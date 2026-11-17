package daemon

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/netip"
	"time"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/sensors/egressip"
	"lethe/internal/sensors/hostinfo"
)

// Active checks (NET-011, spec §9.9): one query at the arm, then at a uniformly random interval
// in active_checks.egress_ip.interval. The query runs outside the lock; it only ever leaves
// through the tunnel (bound socket, tunnel resolver) or the Tor SOCKS port.

var errNoActive = errors.New("active checks are off in this session (active_checks.enabled or --no-active)")

func (d *Daemon) activeOn(s *session) bool {
	return s.prof.ActiveChecks.Enabled && !s.noActive
}

// activeLoop runs the rounds of session s until ctx ends.
func (d *Daemon) activeLoop(ctx context.Context, s *session) {
	for {
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
		case <-time.After(wait):
		}
	}
}

// activePath chooses how the query leaves: Tor's SOCKS port for tor profiles, else the first
// tunnel interface with its DNS servers.
func (d *Daemon) activePathLocked(s *session) (egressip.Path, string) {
	snap := d.snap
	if t := s.prof.Egress.Type; t == "tor" || t == "vpn+tor" {
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
	dns := egressip.TunnelDNS(iface, s.prof.ActiveChecks.ParsedTunnelDNS, linkDNS, snap.DNS.ResolvConf.Nameservers, via)
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
		d.mu.Unlock()
		return contracts.DNSLeakResult{}, errState(errNotArmed)
	}
	if !d.activeOn(s) {
		d.mu.Unlock()
		return contracts.DNSLeakResult{}, errState(errNoActive)
	}
	path, name := d.activePathLocked(s)
	cfg := egressip.LeakConfig{Config: egressip.Config{RootCAs: d.cfg.ActiveRootCAs}, Lookup: d.cfg.LeakLookup,
		Domain: s.prof.ActiveChecks.DNSLeak.Domain, API: s.prof.ActiveChecks.DNSLeak.API}
	known := s.known
	d.mu.Unlock()
	out := contracts.DNSLeakResult{At: d.cfg.Now().UTC()}
	if name == "" {
		out.Verdict, out.Detail = "skipped", egressip.ErrNoPath.Error()
		return out, nil
	}
	return LeakVerdict(d.cfg.DNSLeak(ctx, path, cfg), known, out.At), nil
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
