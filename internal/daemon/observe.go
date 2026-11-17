package daemon

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/engine"
	"lethe/internal/platform"
	"lethe/internal/preflight"
	"lethe/internal/response"
	"lethe/internal/sensors/nftmon"
)

// heartbeatTimeout: a source silent for longer is down (SELF-001, SELF-003).
const heartbeatTimeout = 3 * time.Second

// deliver hands one finding of session s to the engine (sensors call it).
func (d *Daemon) deliver(s *session, fs ...checks.Finding) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess != s || s == nil {
		return // session ended while the sensor held the finding
	}
	for _, f := range fs {
		d.findingLocked(f)
	}
}

func (d *Daemon) findingLocked(f checks.Finding) {
	f = checks.NET009{}.Match(f, d.sess.known)
	if d.selftestAbsorbLocked(f) {
		return // caused by the selftest: journaled with selftest: true, responses in dry-run
	}
	ev, err := f.SealedAlert(d.sess.journal.Seal)
	if err != nil {
		ev = f.Alert() // sensitive fields are dropped, never written in clear
	}
	d.alertLocked(ev)
}

// alertLocked runs one check.alert through the engine; new and escalated alerts are journaled
// and their actions executed. Actions run before the journal write: blocking comes first.
func (d *Daemon) alertLocked(ev contracts.Event) {
	dec := d.eng.Observe(ev)
	if dec.DryRun || dec.Alert == nil || (!dec.New && !dec.Escalated) {
		return
	}
	a := dec.Alert
	ev.AlertID, ev.Severity = a.ID, a.Severity
	ev.Actions = nil
	for _, act := range dec.Actions {
		ev.Actions = append(ev.Actions, string(act))
	}
	results := make([]response.Result, 0, len(dec.Actions))
	for _, act := range dec.Actions {
		results = append(results, d.sess.exec.Run(act, ev))
	}
	if a.Severity == contracts.SeverityCritical {
		d.sess.critical++
	}
	out := d.appendLocked(ev)
	d.terminalLocked(out)
	if dec.EnteredPanic {
		d.engagePanicLocked("alert", a.ID, ev)
	}
	for _, r := range results {
		d.appendLocked(r.Event(a.ID))
	}
	if dec.EnteredPanic || d.eng.Color() != d.sess.color {
		d.stateChangedLocked("alert")
	}
}

// conditionLocked feeds the current findings of a condition check and resolves the dedup keys
// that disappeared since the last evaluation.
func (d *Daemon) conditionLocked(check string, fs []checks.Finding) {
	d.conditionGroupLocked(check, check, fs)
}

// conditionGroupLocked is conditionLocked for one of several independent conditions of the same
// check (PER-001's keyboard and its exit country): each group resolves only its own keys.
func (d *Daemon) conditionGroupLocked(group, check string, fs []checks.Finding) {
	prev := d.sess.conditions[group]
	cur := map[string]map[string]any{}
	for _, f := range fs {
		cur[engine.DedupKey(f.Alert())] = f.Data
		d.findingLocked(f)
	}
	keys := make([]string, 0, len(prev))
	for k := range prev {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, still := cur[k]; !still {
			d.eng.Observe(checks.Resolved(check, prev[k]))
		}
	}
	d.sess.conditions[group] = cur
}

func (d *Daemon) evaluateConditionsLocked(snap discovery.Snapshot) {
	for _, n := range preflight.TunnelIfaces(&snap) {
		d.sess.tunnels[n] = true
	}
	d.conditionLocked("NET-003", checks.NET003{}.Evaluate(&snap, d.sess.prof.Expect.IPv6))
	d.conditionLocked("NET-004", checks.NET004{}.Evaluate(&snap))
	d.conditionLocked("TUN-001", checks.TUN001{}.Evaluate(d.tunnelExpectLocked(), &snap))
	d.conditionLocked("TUN-002", checks.TUN002{}.Evaluate(d.sess.tx, &snap, d.cfg.Now()))
	d.conditionLocked("TUN-003", checks.TUN003{}.Evaluate(d.sess.torExpected, &snap))
	d.conditionLocked("TUN-005", checks.TUN005{}.Evaluate(&snap))
	if p := d.sess.prof; p.Egress.Type != "tor" { // tor guards are anywhere by design
		want := checks.GeoExpect{Country: p.Egress.ExpectCountry, ASN: p.Egress.ExpectASN}
		d.conditionLocked("TUN-006", checks.TUN006{}.Evaluate(d.cfg.Geo, want, d.sess.armEndpoints, &snap))
	}
	d.conditionLocked("TUN-007", checks.TUN007{}.Evaluate(&snap))
	if d.sess.nftArm != nil {
		if now, err := d.nftTables(); err == nil {
			d.conditionLocked("TUN-004", checks.TUN004{}.Evaluate(d.sess.nftArm, now))
		}
	}
}

// nftTables snapshots the third-party nftables tables (TUN-004).
func (d *Daemon) nftTables() ([]nftmon.Table, error) {
	c, err := d.cfg.NFT()
	if err != nil {
		return nil, err
	}
	l, ok := c.(nftmon.Lister)
	if !ok {
		return nil, errors.New("nftables connection cannot list rules")
	}
	t, err := nftmon.Snapshot(l)
	if t == nil && err == nil {
		t = []nftmon.Table{}
	}
	return t, err
}

func (d *Daemon) tunnelExpectLocked() checks.TunnelExpect {
	want := checks.TunnelExpect{Require: checks.RequiresTunnel(d.sess.prof.Egress.Type, d.sess.torExpected)}
	for n := range d.sess.tunnels {
		want.Ifaces = append(want.Ifaces, n)
	}
	return want
}

// beat records a heartbeat of source for session s. A paused source (selftest ST-SELF-001)
// loses its heartbeats until the pause ends.
func (d *Daemon) beat(s *session, source string) func(time.Time) {
	return func(time.Time) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.sess == s && s != nil && !d.cfg.Now().Before(s.paused[source]) {
			s.beats[source] = d.cfg.Now()
		}
	}
}

// PauseSensor drops the heartbeats of source for dur, so the state goes GRAY (SELF-001) and
// comes back (selftest ST-SELF-001). The sensor itself keeps running.
func (d *Daemon) PauseSensor(source string, dur time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil {
		return errState(errNotArmed)
	}
	if _, ok := d.sess.beats[source]; !ok {
		return errParams(fmt.Errorf("unknown sensor %q", source))
	}
	d.sess.paused[source] = d.cfg.Now().Add(dur)
	return nil
}

// Tick does the 1 s housekeeping: alert resolution, heartbeats, journal maintenance, color.
func (d *Daemon) Tick() {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.sess
	if s == nil {
		return
	}
	now := d.cfg.Now()
	for _, a := range d.eng.Tick() {
		d.appendLocked(contracts.Event{Type: contracts.EvCheckResolved, Source: contracts.SourceDaemon, Check: a.Check,
			Severity: a.Severity, AlertID: a.ID, Data: map[string]any{"acked": a.Acked, "count": a.Count}})
	}
	srcs := make([]string, 0, len(s.beats))
	for src := range s.beats {
		srcs = append(srcs, src)
	}
	sort.Strings(srcs)
	for _, src := range srcs {
		down := now.Sub(s.beats[src]) > heartbeatTimeout
		if down == s.down[src] {
			continue
		}
		s.down[src] = down
		t := contracts.EvSensorUp
		if down {
			t = contracts.EvSensorDown
		}
		ev := contracts.Event{Type: t, Source: contracts.SourceDaemon, Data: map[string]any{"source": src}}
		d.eng.Observe(ev)
		d.appendLocked(ev)
	}
	d.captureStatsLocked()
	d.clockLocked(now)
	if err := s.journal.Tick(); err != nil {
		_, _ = fmt.Fprintf(d.cfg.Out, "lethe: journal: %v\n", err)
	}
	if d.eng.Color() != s.color {
		d.stateChangedLocked("tick")
	}
}

// terminalLocked prints one alert line. Baseline values are redacted (defense in depth: checks
// already keep them out of event data).
func (d *Daemon) terminalLocked(ev contracts.Event) {
	var parts []string
	for _, k := range []string{"iface", "proto", "dst", "dport", "reason", "subtype"} {
		if v, ok := ev.Data[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	if exe := ev.ProcExe(); exe != "" {
		parts = append(parts, "exe="+exe)
	}
	line := fmt.Sprintf("[%s] %s %s %s", ev.Severity, ev.AlertID, ev.Check, strings.Join(parts, " "))
	if len(ev.Actions) > 0 {
		line += " actions=" + strings.Join(ev.Actions, ",")
	}
	if d.sess != nil && d.sess.base != nil {
		line = d.sess.base.Redact(line)
	}
	line = platform.TermSafe(line)
	if ev.Severity == contracts.SeverityCritical {
		line = "\a" + line
	}
	_, _ = fmt.Fprintln(d.cfg.Out, line)
}
