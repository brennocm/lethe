package daemon

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"time"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/sensors/egressip"
	"lethe/internal/sensors/hostinfo"
)

// Active checks (NET-011, spec §9.9): one query at the arm, then at a uniformly random interval
// in active_checks.egress_ip.interval. The query runs outside the lock; it only ever leaves
// through the tunnel (bound socket, tunnel resolver) or the Tor SOCKS port.

var (
	errNoActive = errors.New("active checks are off in this session (active_checks.enabled or --no-active)")
	errLeakBusy = errors.New("a DNS leak test is already running; wait for its answer")
)

func (d *Daemon) activeOn(s *session) bool {
	return s.prof.ActiveChecks.Enabled && !s.noActive
}

// activeLoop runs the rounds of session s until ctx ends.
// checkNowGap is the least time between the start of a round and one asked by active.check_now:
// a safe method, so any process of the operator can call it, and it must not become a stream of
// queries to the exit IP services.
const checkNowGap = 15 * time.Second

func (d *Daemon) activeLoop(ctx context.Context, s *session) {
	for {
		started := time.Now()
		d.activeRound(ctx, s)
		ap := s.prof.ActiveChecks.EgressIP
		wait := ap.IntervalMin
		if span := ap.IntervalMax - ap.IntervalMin; span > 0 {
			wait += time.Duration(rand.Int64N(int64(span))) // #nosec G404 -- spreads the queries, not a secret
		}
		select {
		case <-ctx.Done():
			return
		case <-d.cfg.ActiveWake:
		case <-d.wake:
			if rest := d.checkGap - time.Since(started); rest > 0 {
				select {
				case <-ctx.Done():
					return
				case <-time.After(rest):
				}
			}
		case <-time.After(wait):
		}
	}
}

// activePath chooses how the query leaves: Tor's SOCKS port for tor profiles, else the first
// tunnel interface with its DNS servers.
func (d *Daemon) activePathLocked(s *session) (egressip.Path, string) {
	return d.pathLocked(d.snap, s.prof.Egress.Type, s.prof.ActiveChecks.ParsedTunnelDNS)
}

// pathLocked is activePath for a snapshot, an egress type ("" without a profile: the tunnel
// only) and the profile's tunnel DNS servers.
func (d *Daemon) pathLocked(snap discovery.Snapshot, egress string, tunnelDNS []netip.Addr) (egressip.Path, string) {
	if t := egress; t == "tor" || t == "vpn+tor" {
		if snap.Tor != nil {
			for _, sp := range snap.Tor.Socks {
				if ap, err := netip.ParseAddrPort(sp); err == nil {
					return egressip.Path{Socks: ap}, "tor"
				}
			}
		}
		return egressip.Path{}, "tor"
	}
	if len(snap.Tunnels) == 0 {
		return egressip.Path{}, ""
	}
	iface := snap.Tunnels[0].Iface
	var linkDNS []string
	for _, l := range snap.DNS.Resolved.Links {
		if l.Iface == iface {
			linkDNS = append(linkDNS, l.Servers...)
		}
	}
	names := map[int]string{}
	for _, i := range snap.Ifaces {
		names[i.Index] = i.Name
	}
	via := func(a netip.Addr) string {
		r, err := d.cfg.Kernel.RouteGet(a)
		if err != nil {
			return ""
		}
		return names[r.LinkIndex]
	}
	dns := egressip.TunnelDNS(iface, tunnelDNS, linkDNS, snap.DNS.ResolvConf.Nameservers, via)
	return egressip.Path{Tunnel: iface, DNS: dns}, iface
}

func (d *Daemon) activeRound(ctx context.Context, s *session) {
	d.mu.Lock()
	if d.sess != s {
		d.mu.Unlock()
		return
	}
	path, name := d.activePathLocked(s)
	cfg := egressip.Config{Endpoints: s.prof.ActiveChecks.EgressIP.Endpoints, RootCAs: d.cfg.ActiveRootCAs}
	d.mu.Unlock()

	var res egressip.Result
	if name == "" {
		res = egressip.Result{Skipped: egressip.ErrNoPath.Error()}
	} else {
		res = d.cfg.ActiveQuery(ctx, path, cfg)
	}
	if ctx.Err() != nil {
		return
	}
	zones := hostinfo.ZoneCountries(d.cfg.HostRoot)

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess != s {
		return
	}
	want := checks.ExitExpect{Country: s.prof.Egress.ExpectCountry, ASNs: s.prof.Egress.ExpectASN}
	d.conditionLocked("NET-011", checks.NET011{}.Evaluate(res, s.known, d.cfg.Geo, want))
	if !res.Agreed {
		return
	}
	view := ExitView{At: d.cfg.Now().UTC(), Path: name}
	if _, real := s.known.IPs[res.IP.Unmap()]; !real {
		view.IP = res.IP.String()
		view.City, view.PlaceCountry, view.PlaceSource = res.Place.City, res.Place.Country, res.Place.Source
	}
	if d.cfg.Geo != nil {
		if info, ok := d.cfg.Geo.Lookup(res.IP); ok {
			view.Country = info.Country
			if _, real := s.known.ASNs[info.ASN]; !real {
				view.ASN = info.ASN
			}
			tz, loc := s.hostTZ, s.hostLocale // what the machine shows; the profile's when unread
			if tz == "" {
				tz = s.prof.Expect.Timezone
			}
			if loc == "" {
				loc = s.prof.Expect.Locale
			}
			d.conditionGroupLocked("PER-001/country", "PER-001", checks.PER001{}.Country(info.Country, tz, loc, zones))
		}
	}
	s.exit = &view
}

// CheckNow starts a NET-011 round now (the GUI's "check now"). It fails when the session has no
// active checks: the operator turned them off, or the profile did.
func (d *Daemon) CheckNow() error {
	d.mu.Lock()
	s := d.sess
	d.mu.Unlock()
	if s == nil {
		return errState(errNotArmed)
	}
	if !d.activeOn(s) {
		return errState(errNoActive)
	}
	select {
	case d.wake <- struct{}{}:
	default: // a round is already coming
	}
	return nil
}

// DNSLeakTest runs the DNS leak test (spec §9.9): the system resolver resolves the test's names,
// the answer comes through the tunnel or Tor. Addresses that are baseline values are not shown:
// the field that matched is.
func (d *Daemon) DNSLeakTest(ctx context.Context) (contracts.DNSLeakResult, error) {
	d.mu.Lock()
	s := d.sess
	if s == nil {
		return d.quickLeakTestUnlocking(ctx)
	}
	if !d.activeOn(s) {
		d.mu.Unlock()
		return contracts.DNSLeakResult{}, errState(errNoActive)
	}
	if !d.leakBusy.CompareAndSwap(false, true) {
		d.mu.Unlock()
		return contracts.DNSLeakResult{}, errState(errLeakBusy)
	}
	defer d.leakBusy.Store(false)
	path, name := d.activePathLocked(s)
	cfg := egressip.LeakConfig{Config: egressip.Config{RootCAs: d.cfg.ActiveRootCAs}, Lookup: d.cfg.LeakLookup,
		Domain: s.prof.ActiveChecks.DNSLeak.Domain, API: s.prof.ActiveChecks.DNSLeak.API}
	known := s.known
	d.mu.Unlock()
	out := contracts.DNSLeakResult{At: d.cfg.Now().UTC()}
	if name == "" {
		out.Verdict, out.Detail, out.NoTunnel = "skipped", egressip.ErrNoPath.Error(), true
		return out, nil
	}
	res := LeakVerdict(d.cfg.DNSLeak(ctx, path, cfg), known, out.At)
	if res.Verdict != "skipped" {
		d.mu.Lock()
		if d.sess == s {
			d.conditionGroupLocked("DNS-002/leak_test", "DNS-002", checks.DNS002{}.EvaluateLeakTest(res))
		}
		d.mu.Unlock()
	}
	return res, nil
}

// quickLeakTestUnlocking is the DNS leak test without a session (spec §9.9): no profile and no
// baseline, so it discovers the network now, leaves only through a tunnel interface (never the
// bare connection; Tor needs a session with a tor profile), uses the default test service and
// judges against what the machine itself shows: a DNS server configured on an interface outside
// the tunnel is a leak, a server in another country than the exit is suspect. Nothing is
// journaled (there is no session) and no alert is raised. Called with d.mu held; releases it.
func (d *Daemon) quickLeakTestUnlocking(ctx context.Context) (contracts.DNSLeakResult, error) {
	if !d.leakBusy.CompareAndSwap(false, true) {
		d.mu.Unlock()
		return contracts.DNSLeakResult{}, errState(errLeakBusy)
	}
	defer d.leakBusy.Store(false)
	snap := d.discoverLocked(nil)
	findings := quickFindings(snap)
	all := snap
	snap.Tunnels = upTunnels(snap) // a tunnel that is down carries nothing: no path, not a bind error
	path, name := d.pathLocked(snap, "", nil)
	known := checks.Known{Resolvers: outsideResolvers(all, name)}
	cfg := egressip.LeakConfig{Config: egressip.Config{RootCAs: d.cfg.ActiveRootCAs}, Lookup: d.cfg.LeakLookup,
		Domain: egressip.DefaultLeakDomain, API: egressip.DefaultLeakAPI}
	d.mu.Unlock()
	out := contracts.DNSLeakResult{At: d.cfg.Now().UTC(), Quick: true, Findings: findings}
	if name == "" {
		out.Verdict, out.Detail, out.NoTunnel = "skipped", egressip.ErrNoPath.Error(), true
		return out, nil
	}
	res := LeakVerdict(d.cfg.DNSLeak(ctx, path, cfg), known, out.At)
	res.Quick, res.Findings = true, findings
	return res, nil
}

// quickFindings are the route conditions a quick test reports with its answer: IPv6 (NET-003,
// as when the profile expects IPv6, so only a tunnel without IPv6 beside an egress route counts)
// and the effective route (NET-004).
func quickFindings(snap discovery.Snapshot) []contracts.QuickFinding {
	var out []contracts.QuickFinding
	all := append(checks.NET003{}.Evaluate(&snap, true), checks.NET004{}.Evaluate(&snap)...)
	for _, f := range all {
		q := contracts.QuickFinding{Check: f.Check, Severity: string(f.Severity)}
		q.Iface, _ = f.Data["iface"].(string)
		q.Reason, _ = f.Data["reason"].(string)
		if fam, ok := f.Data["family"].(string); ok && q.Reason == "" {
			q.Reason = "route_" + fam // NET-004 names the address family
		}
		out = append(out, q)
	}
	return out
}

// upTunnels are the snapshot's tunnels whose interface is up.
func upTunnels(snap discovery.Snapshot) []discovery.Tunnel {
	up := map[string]bool{}
	for _, i := range snap.Ifaces {
		up[i.Name] = i.Up
	}
	var out []discovery.Tunnel
	for _, t := range snap.Tunnels {
		if up[t.Iface] {
			out = append(out, t)
		}
	}
	return out
}

// outsideResolvers are the DNS servers systemd-resolved has on links that are not tunnels,
// named by their interface (never by address): what a leak would show without a baseline. Every
// tunnel is left out, up or not, not only the one the test leaves through: a second VPN's DNS is
// not the real network.
func outsideResolvers(snap discovery.Snapshot, tunnel string) map[netip.Addr]string {
	tunnels := map[string]bool{tunnel: true, "": true}
	for _, t := range snap.Tunnels {
		tunnels[t.Iface] = true
	}
	out := map[netip.Addr]string{}
	for _, l := range snap.DNS.Resolved.Links {
		if tunnels[l.Iface] {
			continue
		}
		for _, srv := range l.Servers {
			if a, err := netip.ParseAddr(srv); err == nil && !a.IsLoopback() {
				out[a.Unmap()] = l.Iface
			}
		}
	}
	return out
}

// LeakVerdict turns the test's answer into what the operator sees.
func LeakVerdict(r egressip.LeakResult, k checks.Known, at time.Time) contracts.DNSLeakResult {
	out := contracts.DNSLeakResult{At: at, Verdict: "ok"}
	if r.Skipped != "" {
		out.Verdict, out.Detail = "skipped", r.Skipped
		return out
	}
	view := func(s egressip.LeakServer, known map[netip.Addr]string) contracts.DNSLeakServer {
		v := contracts.DNSLeakServer{Country: s.Country, ASN: s.ASN}
		if f, ok := known[s.IP]; ok {
			v.Matched = f
			out.Verdict = "leak"
			return v
		}
		if f, ok := k.IPs[s.IP]; ok {
			v.Matched = f
			out.Verdict = "leak"
			return v
		}
		v.IP = s.IP.String()
		return v
	}
	if r.Exit != nil {
		e := view(*r.Exit, nil)
		out.Exit = &e
	}
	for _, s := range r.DNS {
		v := view(s, k.Resolvers)
		if out.Verdict == "ok" && out.Exit != nil && out.Exit.Country != "" && v.Country != "" && v.Country != out.Exit.Country {
			out.Verdict = "suspect"
		}
		out.DNS = append(out.DNS, v)
	}
	return out
}
