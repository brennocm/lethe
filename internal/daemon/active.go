package daemon

import (
	"context"
	"math/rand/v2"
	"net/netip"
	"time"

	"lethe/internal/checks"
	"lethe/internal/sensors/egressip"
	"lethe/internal/sensors/hostinfo"
)

// Active checks (NET-011, spec §9.9): one query at the arm, then at a uniformly random interval
// in active_checks.egress_ip.interval. The query runs outside the lock; it only ever leaves
// through the tunnel (bound socket, tunnel resolver) or the Tor SOCKS port.

// ExitView is the last agreed answer, without the IP (status, GUI header).
type ExitView struct {
	Country string    `json:"country,omitempty"`
	ASN     uint32    `json:"asn,omitempty"`
	At      time.Time `json:"at"`
	Path    string    `json:"path"` // tunnel interface or "tor"
}

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
