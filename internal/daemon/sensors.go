package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/engine"
	"lethe/internal/guard"
	"lethe/internal/sensors/capture"
	"lethe/internal/sensors/netlinkmon"
	"lethe/internal/sensors/nflog"
	"lethe/internal/sensors/sockdiag"
)

const sockScanEvery = 2 * time.Second

// sensorSet is the running sensors of one session.
type sensorSet struct {
	ctx      context.Context
	captures map[string]*capture.Sensor
}

func allowlist(g guard.Config) capture.Allowlist {
	al := capture.Allowlist{LAN: g.LAN}
	for _, e := range g.Endpoints {
		al.Endpoints = append(al.Endpoints, capture.Endpoint{Addr: e.Addr, Proto: e.Proto})
	}
	return al
}

// startSensorsLocked starts capture, netlink, sock_diag and (strict) nflog for d.sess.
func (d *Daemon) startSensorsLocked(snap discovery.Snapshot) {
	s := d.sess
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.sensors = &sensorSet{ctx: ctx, captures: map[string]*capture.Sensor{}}
	now := d.cfg.Now()
	d.syncCapturesLocked(snap)

	s.beats[netlinkmon.SourceID] = now
	links := make(chan netlinkmon.LinkEvent, 64)
	routes := make(chan netlinkmon.RouteChange, 64)
	d.goSensor(s, netlinkmon.SourceID, func() error {
		return (&netlinkmon.Monitor{}).Run(ctx, links, routes, d.beat(s, netlinkmon.SourceID))
	})
	initial, _ := netlinkmon.Links()
	tracker := netlinkmon.NewTracker(initial)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case l := <-links:
				isNew, wasUp := tracker.Apply(l)
				d.onLink(s, l, isNew, wasUp)
			case rc := <-routes:
				d.onRoute(s, rc)
			}
		}
	}()

	if s.guardMode == engine.GuardStrict {
		s.beats[nflog.SourceID] = now
		blocked := make(chan nflog.Blocked, 64)
		d.goSensor(s, nflog.SourceID, func() error { return nflog.Run(ctx, guard.LogGroup, blocked, d.beat(s, nflog.SourceID)) })
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case b := <-blocked:
					d.deliver(s, checks.FromBlocked(b, d.attribute(b.Leak)))
				}
			}
		}()
	}

	s.beats[sockdiag.SourceID] = now
	d.goSensor(s, sockdiag.SourceID, func() error { return d.scanSockets(ctx, s) })

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(d.cfg.DiscoverEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			d.mu.Lock()
			if d.sess == s {
				d.refreshLocked()
			}
			d.mu.Unlock()
		}
	}()
}

// goSensor runs fn until it returns; an error is printed and the missing heartbeats turn the
// state GRAY (SELF-001).
func (d *Daemon) goSensor(s *session, name string, fn func() error) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := fn(); err != nil && s.sensors.ctx.Err() == nil {
			d.mu.Lock()
			_, _ = fmt.Fprintf(d.cfg.Out, "lethe: sensor %s stopped: %v\n", name, err)
			d.mu.Unlock()
		}
	}()
}

// syncCapturesLocked opens a capture sensor on every new capture interface and updates the
// allowlist of the others.
func (d *Daemon) syncCapturesLocked(snap discovery.Snapshot) {
	s := d.sess
	al := allowlist(s.gcfg)
	for _, iface := range snap.CaptureIfaces {
		if c, ok := s.sensors.captures[iface]; ok {
			if err := c.Update(al); err != nil {
				_, _ = fmt.Fprintf(d.cfg.Out, "lethe: capture %s: %v\n", iface, err)
			}
			continue
		}
		c, err := capture.Open(iface, al)
		src := capture.SourceID + ":" + iface
		s.beats[src] = d.cfg.Now()
		if err != nil {
			_, _ = fmt.Fprintf(d.cfg.Out, "lethe: capture %s: %v\n", iface, err)
			continue // no heartbeat: GRAY after 3 s
		}
		s.sensors.captures[iface] = c
		frames := make(chan capture.Frame, 256)
		ctx := s.sensors.ctx
		d.goSensor(s, src, func() error {
			defer func() { _ = c.Close() }()
			return c.Run(ctx, frames, d.beat(s, src))
		})
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case f := <-frames:
					d.deliver(s, checks.FromFrame(f, d.attribute(f.Leak)))
				}
			}
		}()
	}
}

// attribute finds the process behind a leaked packet (sock_diag + /proc, outside the lock).
func (d *Daemon) attribute(l capture.Leak) contracts.Proc {
	proto, src, dst, ok := l.Tuple()
	if !ok {
		return contracts.Proc{}
	}
	socks, err := sockdiag.Dump()
	if err != nil {
		return contracts.Proc{Confidence: contracts.ConfidenceNone}
	}
	owners, _ := sockdiag.Owners(d.cfg.ProcRoot)
	return sockdiag.Attribute(socks, owners, proto, src, dst)
}

func (d *Daemon) scanSockets(ctx context.Context, s *session) error {
	t := time.NewTicker(sockScanEvery)
	defer t.Stop()
	beat := d.beat(s, sockdiag.SourceID)
	for {
		socks, err := sockdiag.Dump()
		if err == nil {
			owners, _ := sockdiag.Owners(d.cfg.ProcRoot)
			d.mu.Lock()
			if d.sess != s {
				d.mu.Unlock()
				return nil
			}
			sc := d.socketScanLocked(socks, owners)
			d.mu.Unlock()
			d.deliver(s, checks.NET010{}.Evaluate(sc)...)
			beat(time.Time{})
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (d *Daemon) socketScanLocked(socks []sockdiag.Sock, owners map[uint32]sockdiag.Owner) checks.SocketScan {
	egress := map[netip.Addr]string{}
	for _, i := range d.snap.Ifaces {
		if i.Class != discovery.ClassEgress && i.Class != discovery.ClassUnknown {
			continue
		}
		for _, a := range i.Addrs {
			if p, err := netip.ParsePrefix(a); err == nil {
				egress[p.Addr()] = i.Name
			}
		}
	}
	g := d.sess.gcfg
	return checks.SocketScan{
		Socks: socks, Owners: owners, EgressAddrs: egress,
		Allowed: func(proto string, dst netip.AddrPort) bool {
			for _, e := range g.Endpoints {
				if e.Addr == dst && protoName(e.Proto) == proto {
					return true
				}
			}
			for _, p := range g.LAN {
				if p.Contains(dst.Addr()) {
					return true
				}
			}
			return false
		},
	}
}

func protoName(p uint8) string {
	if p == 6 {
		return "tcp"
	}
	return "udp"
}

func (d *Daemon) onLink(s *session, l netlinkmon.LinkEvent, isNew, wasUp bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess != s || l.Deleted {
		return
	}
	d.refreshLocked()
	class := discovery.ClassUnknown
	if i, ok := d.snap.Iface(l.Name); ok {
		class = i.Class
	}
	for _, f := range (checks.NET006{}).Evaluate(checks.LinkChange{Name: l.Name, New: isNew, Up: l.Up, WasUp: wasUp, Class: class}) {
		d.findingLocked(f)
	}
}

func (d *Daemon) onRoute(s *session, rc netlinkmon.RouteChange) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess != s {
		return
	}
	d.refreshLocked()
	for _, f := range (checks.NET005{}).Evaluate(rc, &d.snap) {
		d.findingLocked(f)
	}
}

// refreshLocked re-runs the discovery; on a change it updates the guard sets, the capture
// allowlists and the condition checks (spec §7.4).
func (d *Daemon) refreshLocked() {
	s := d.sess
	snap := d.discoverLocked(s.prof)
	old := d.snap
	d.snap = snap
	changed := !slices.Equal(old.Endpoints, snap.Endpoints) || !slices.Equal(old.CaptureIfaces, snap.CaptureIfaces) || len(old.Ifaces) != len(snap.Ifaces)
	if changed {
		oldEgress := s.gcfg.Egress
		s.gcfg = guardConfig(snap, s.prof, s.features)
		d.appendLocked(contracts.Event{Type: contracts.EvDiscoveryChanged, Source: contracts.SourceDaemon, Data: map[string]any{
			"capture_ifaces": len(snap.CaptureIfaces), "endpoints": len(snap.Endpoints), "tunnels": len(snap.Tunnels), "unavailable": toAny(snap.Unavailable),
		}})
		if s.guardMode == engine.GuardStrict && d.eng.Session() == engine.StateArmed {
			d.updateGuardLocked(!slices.Equal(oldEgress, s.gcfg.Egress))
		}
		if s.sensors != nil {
			d.syncCapturesLocked(snap)
		}
	}
	d.evaluateConditionsLocked(snap)
}

// updateGuardLocked refreshes the strict sets, or the whole ruleset when the egress devices
// (netdev chains) changed. Both are single transactions.
func (d *Daemon) updateGuardLocked(full bool) {
	rs, err := guard.Strict(d.sess.gcfg)
	if err == nil {
		var c guard.Conn
		if c, err = d.cfg.NFT(); err == nil {
			if full {
				err = guard.Apply(c, rs)
			} else {
				err = guard.UpdateSets(c, rs)
			}
		}
	}
	if err != nil {
		_, _ = fmt.Fprintf(d.cfg.Out, "lethe: guard update: %v\n", err)
		return
	}
	d.appendLocked(contracts.Event{Type: contracts.EvGuardApplied, Source: contracts.SourceDaemon, Data: map[string]any{
		"mode": "strict", "update": map[bool]string{true: "ruleset", false: "sets"}[full], "endpoints": len(d.sess.gcfg.Endpoints),
	}})
}
