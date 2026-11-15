package daemon

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/engine"
	"lethe/internal/preflight"
	"lethe/internal/response"
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
	prev := d.sess.conditions[check]
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
	d.sess.conditions[check] = cur
}

func (d *Daemon) evaluateConditionsLocked(snap discovery.Snapshot) {
	for _, n := range preflight.TunnelIfaces(&snap) {
		d.sess.tunnels[n] = true
	}
	d.conditionLocked("NET-003", checks.NET003{}.Evaluate(&snap, d.sess.prof.Expect.IPv6))
	d.conditionLocked("NET-004", checks.NET004{}.Evaluate(&snap))
	d.conditionLocked("TUN-001", checks.TUN001{}.Evaluate(d.tunnelExpectLocked(), &snap))
	d.conditionLocked("TUN-007", checks.TUN007{}.Evaluate(&snap))
}

func (d *Daemon) tunnelExpectLocked() checks.TunnelExpect {
	want := checks.TunnelExpect{Require: checks.RequiresTunnel(d.sess.prof.Egress.Type)}
	for n := range d.sess.tunnels {
		want.Ifaces = append(want.Ifaces, n)
	}
	return want
}

// beat records a heartbeat of source for session s.
func (d *Daemon) beat(s *session, source string) func(time.Time) {
	return func(time.Time) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.sess == s && s != nil {
			s.beats[source] = d.cfg.Now()
		}
	}
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
	if ev.Severity == contracts.SeverityCritical {
		line = "\a" + line
	}
	_, _ = fmt.Fprintln(d.cfg.Out, line)
}
