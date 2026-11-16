package engine

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"lethe/internal/contracts"
)

func newTestEngine(mode GuardMode, state SessionState) (*Engine, *FakeClock) {
	clk := &FakeClock{T: time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)}
	return New(clk, Config{Guard: mode}, state), clk
}

func leak(check string, sev contracts.Severity, dst string) contracts.Event {
	return contracts.Event{
		Type: contracts.EvCheckAlert, Check: check, Severity: sev, Source: contracts.SourceDaemon,
		Data: map[string]any{"iface": "eth0", "dst": dst, "dport": 53, "proc": contracts.Proc{Exe: "/usr/bin/dig"}},
	}
}

func cond(check string, sev contracts.Severity, src contracts.Source) contracts.Event {
	return contracts.Event{Type: contracts.EvCheckAlert, Check: check, Severity: sev, Source: src}
}

func TestDefaultActions_Table(t *testing.T) {
	cases := []struct {
		sev  contracts.Severity
		mode GuardMode
		want []Action
	}{
		{contracts.SeverityInfo, GuardStrict, nil},
		{contracts.SeverityWarning, GuardOff, []Action{ActAlertTray, ActAlertSound}},
		{contracts.SeverityWarning, GuardStrict, []Action{ActAlertTray, ActAlertSound}},
		{contracts.SeverityCritical, GuardOff, []Action{ActAlertFullscreen, ActAlertSound}},
		{contracts.SeverityCritical, GuardReactive, []Action{ActBlockAll, ActKillProcesses, ActAlertFullscreen, ActAlertSound}},
		{contracts.SeverityCritical, GuardStrict, []Action{ActBlockAll, ActKillProcesses, ActAlertFullscreen, ActAlertSound}},
	}
	for _, c := range cases {
		if got := DefaultActions(c.sev, c.mode); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s/%s = %v, want %v", c.sev, c.mode, got, c.want)
		}
	}
}

func TestEffectiveSeverity_NoDowngradeBelowWarning(t *testing.T) {
	info := Override{Severity: contracts.SeverityInfo}
	if got := EffectiveSeverity(contracts.SeverityCritical, info, false); got != contracts.SeverityWarning {
		t.Fatalf("CRITICAL→INFO without allow = %s, want WARNING", got)
	}
	if got := EffectiveSeverity(contracts.SeverityCritical, info, true); got != contracts.SeverityInfo {
		t.Fatalf("with allow = %s", got)
	}
	if got := EffectiveSeverity(contracts.SeverityWarning, Override{Severity: contracts.SeverityCritical}, false); got != contracts.SeverityCritical {
		t.Fatalf("upgrade = %s", got)
	}
	if got := EffectiveSeverity(contracts.SeverityWarning, Override{}, false); got != contracts.SeverityWarning {
		t.Fatalf("no override = %s", got)
	}
}

func TestObserve_DedupWithinOpenAlert(t *testing.T) {
	e, clk := newTestEngine(GuardOff, StateArmed)
	d1 := e.Observe(leak("DNS-001", contracts.SeverityCritical, "192.0.2.53"))
	clk.Advance(2 * time.Second)
	d2 := e.Observe(leak("DNS-001", contracts.SeverityCritical, "192.0.2.53"))
	if !d1.New || d2.New || d2.Alert != d1.Alert || len(d2.Actions) != 0 {
		t.Fatalf("dedup failed: %+v %+v", d1, d2)
	}
	if d1.Alert.Count != 2 || d1.Alert.ID != "A-0001" {
		t.Fatalf("count/id = %d %s", d1.Alert.Count, d1.Alert.ID)
	}
	d3 := e.Observe(leak("DNS-001", contracts.SeverityCritical, "198.51.100.1"))
	if !d3.New || d3.Alert.ID != "A-0002" {
		t.Fatal("different destination must open a new alert")
	}
}

func TestObserve_AckedAlertRecurrenceOpensNew(t *testing.T) {
	e, _ := newTestEngine(GuardOff, StateArmed)
	d1 := e.Observe(leak("NET-001", contracts.SeverityCritical, "192.0.2.1"))
	if _, err := e.Ack(d1.Alert.ID, "investigating", true); err != nil {
		t.Fatal(err)
	}
	d2 := e.Observe(leak("NET-001", contracts.SeverityCritical, "192.0.2.1"))
	if !d2.New || len(d2.Actions) == 0 {
		t.Fatal("a recurring leak after ack must alert again")
	}
}

func TestObserve_AckedConditionStaysInItsAlert(t *testing.T) {
	e, clk := newTestEngine(GuardStrict, StateArmed)
	d1 := e.Observe(cond("NET-004", contracts.SeverityCritical, contracts.SourceDaemon))
	if _, err := e.Ack(d1.Alert.ID, "fixing the route", true); err != nil {
		t.Fatal(err)
	}
	d2 := e.Observe(cond("NET-004", contracts.SeverityCritical, contracts.SourceDaemon))
	if d2.New || d2.Alert != d1.Alert || len(d2.Actions) != 0 {
		t.Fatalf("a still-present condition must stay in its acknowledged alert: %+v", d2)
	}
	e.Observe(contracts.Event{Type: contracts.EvCheckResolved, Check: "NET-004", Source: contracts.SourceDaemon})
	clk.Advance(11 * time.Second)
	if r := e.Tick(); len(r) != 1 || r[0] != d1.Alert {
		t.Fatalf("resolved %v", r)
	}
	if d3 := e.Observe(cond("NET-004", contracts.SeverityCritical, contracts.SourceDaemon)); !d3.New {
		t.Fatal("the condition coming back after resolution is a new alert")
	}
}

func TestObserve_EscalationOnlyUp_AgentCannotLower(t *testing.T) {
	e, _ := newTestEngine(GuardOff, StateArmed)
	d1 := e.Observe(cond("HOST-002", contracts.SeverityWarning, contracts.SourceAgent))
	d2 := e.Observe(cond("HOST-002", contracts.SeverityCritical, contracts.SourceDaemon))
	if !d2.Escalated || d2.Alert != d1.Alert || d1.Alert.Severity != contracts.SeverityCritical {
		t.Fatalf("escalation failed: %+v", d2)
	}
	d3 := e.Observe(cond("HOST-002", contracts.SeverityInfo, contracts.SourceAgent))
	if d3.Alert.Severity != contracts.SeverityCritical || len(d3.Actions) != 0 {
		t.Fatal("severity must never be lowered")
	}
}

func TestObserve_AgentCannotResolve(t *testing.T) {
	e, clk := newTestEngine(GuardOff, StateArmed)
	e.Observe(cond("HOST-003", contracts.SeverityWarning, contracts.SourceDaemon))
	e.Observe(contracts.Event{Type: contracts.EvCheckResolved, Check: "HOST-003", Source: contracts.SourceAgent})
	clk.Advance(time.Minute)
	if len(e.Tick()) != 0 || e.Color() != ColorYellow {
		t.Fatal("agent resolution must be ignored")
	}
}

func TestTick_PointAndConditionResolution(t *testing.T) {
	e, clk := newTestEngine(GuardOff, StateArmed)
	e.Observe(leak("NET-001", contracts.SeverityCritical, "192.0.2.1"))
	e.Observe(cond("TUN-001", contracts.SeverityCritical, contracts.SourceDaemon))
	clk.Advance(9 * time.Second)
	if len(e.Tick()) != 0 {
		t.Fatal("nothing resolves before 10s")
	}
	clk.Advance(time.Second)
	got := e.Tick()
	if len(got) != 1 || got[0].Check != "NET-001" {
		t.Fatalf("point alert should resolve at 10s, got %v", got)
	}
	// condition: resolves only 10s after it clears, and a recurrence resets the timer
	e.Observe(contracts.Event{Type: contracts.EvCheckResolved, Check: "TUN-001", Source: contracts.SourceDaemon})
	clk.Advance(5 * time.Second)
	e.Observe(cond("TUN-001", contracts.SeverityCritical, contracts.SourceDaemon))
	clk.Advance(10 * time.Second)
	if len(e.Tick()) != 0 {
		t.Fatal("condition came back; must not resolve")
	}
	e.Observe(contracts.Event{Type: contracts.EvCheckResolved, Check: "TUN-001", Source: contracts.SourceDaemon})
	clk.Advance(10 * time.Second)
	if got := e.Tick(); len(got) != 1 || got[0].Check != "TUN-001" {
		t.Fatalf("condition should resolve: %v", got)
	}
	if e.Color() != ColorGreen {
		t.Fatalf("color = %s", e.Color())
	}
}

func TestColor_Precedence(t *testing.T) {
	e, _ := newTestEngine(GuardOff, StateArmed)
	if e.Color() != ColorGreen {
		t.Fatal("empty = green")
	}
	e.Observe(cond("NET-005", contracts.SeverityWarning, contracts.SourceDaemon))
	if e.Color() != ColorYellow {
		t.Fatal("warning = yellow")
	}
	e.Observe(contracts.Event{Type: contracts.EvSensorDown, Data: map[string]any{"source": "capture"}})
	if e.Color() != ColorGray || !reflect.DeepEqual(e.Degraded(), []string{"sensor:capture"}) {
		t.Fatal("gray beats yellow")
	}
	e.Observe(cond("TUN-001", contracts.SeverityCritical, contracts.SourceDaemon))
	if e.Color() != ColorRed {
		t.Fatal("red beats gray")
	}
	e2, _ := newTestEngine(GuardOff, StateArmed)
	e2.Observe(contracts.Event{Type: contracts.EvDiscoveryEndpointUnknown})
	if e2.Color() != ColorGray {
		t.Fatal("unknown tunnel endpoint = gray")
	}
	e2.Observe(contracts.Event{Type: contracts.EvDiscoveryEndpointConfirm})
	e2.Observe(contracts.Event{Type: contracts.EvSensorUp, Data: map[string]any{"source": "x"}})
	if e2.Color() != ColorGreen {
		t.Fatal("confirmation clears gray")
	}
}

func TestCriticalInStrict_EntersPanicOnce(t *testing.T) {
	e, _ := newTestEngine(GuardStrict, StateArmed)
	d := e.Observe(leak("NET-001", contracts.SeverityCritical, "192.0.2.1"))
	if !d.EnteredPanic || e.Session() != StatePanic || d.Actions[0] != ActBlockAll {
		t.Fatalf("expected panic: %+v", d)
	}
	d2 := e.Observe(leak("DNS-001", contracts.SeverityCritical, "192.0.2.53"))
	if d2.EnteredPanic {
		t.Fatal("already in panic")
	}
	for _, a := range d2.Actions {
		if a == ActBlockAll {
			t.Fatal("block_all must not repeat while in panic")
		}
	}
}

func TestCriticalInObserver_NoPanic(t *testing.T) {
	e, _ := newTestEngine(GuardOff, StateArmed)
	if d := e.Observe(leak("NET-001", contracts.SeverityCritical, "192.0.2.1")); d.EnteredPanic || e.Session() != StateArmed {
		t.Fatal("observer mode never blocks")
	}
}

func TestSelftestEvents_DryRunOnly(t *testing.T) {
	e, _ := newTestEngine(GuardStrict, StateArmed)
	ev := leak("NET-001", contracts.SeverityCritical, "192.0.2.1")
	ev.Selftest = true
	d := e.Observe(ev)
	if !d.DryRun || d.Alert != nil || e.Session() != StateArmed || len(e.Alerts()) != 0 || len(d.Actions) == 0 {
		t.Fatalf("selftest must be dry-run: %+v", d)
	}
}

func TestOverride_ActionsReplacePlan(t *testing.T) {
	clk := &FakeClock{}
	e := New(clk, Config{Guard: GuardStrict, Overrides: map[string]Override{
		"NET-009": {Severity: contracts.SeverityWarning, Actions: []Action{ActAlertTray}},
	}}, StateArmed)
	d := e.Observe(cond("NET-009", contracts.SeverityCritical, contracts.SourceDaemon))
	if !reflect.DeepEqual(d.Actions, []Action{ActAlertTray}) || d.Alert.Severity != contracts.SeverityWarning {
		t.Fatalf("override not applied: %+v", d)
	}
}

func TestAck_Rules(t *testing.T) {
	e, _ := newTestEngine(GuardOff, StateArmed)
	c := e.Observe(leak("NET-001", contracts.SeverityCritical, "192.0.2.1")).Alert
	w := e.Observe(cond("NET-006", contracts.SeverityWarning, contracts.SourceDaemon)).Alert
	if _, err := e.Ack("A-9999", "x", true); !errors.Is(err, ErrUnknownAlert) {
		t.Fatal(err)
	}
	if _, err := e.Ack(c.ID, "", true); !errors.Is(err, ErrReasonRequired) {
		t.Fatal(err)
	}
	if _, err := e.Ack(c.ID, "reason", false); !errors.Is(err, ErrNotAuthorized) {
		t.Fatal(err)
	}
	if _, err := e.Ack(w.ID, "", false); err != nil {
		t.Fatalf("warning ack needs no auth: %v", err)
	}
	if a, err := e.Ack(c.ID, "reason", true); err != nil || a.State != AlertAcknowledged || !a.Acked {
		t.Fatalf("%+v %v", a, err)
	}
	if e.Color() != ColorRed {
		t.Fatal("an acknowledged but unresolved CRITICAL keeps the color red")
	}
}

func TestUnpanic_Preconditions(t *testing.T) {
	e, clk := newTestEngine(GuardStrict, StateArmed)
	a := e.Observe(leak("NET-001", contracts.SeverityCritical, "192.0.2.1")).Alert
	clk.Advance(time.Minute)
	e.Tick() // resolved, but still unacknowledged
	if err := e.Unpanic(true, false); !errors.Is(err, ErrNotAuthorized) {
		t.Fatal(err)
	}
	if err := e.Unpanic(true, true); !errors.Is(err, ErrUnackedCritical) {
		t.Fatalf("resolved-but-unacked CRITICAL must block unpanic: %v", err)
	}
	if _, err := e.Ack(a.ID, "fixed", true); err != nil {
		t.Fatal(err)
	}
	if err := e.Unpanic(false, true); !errors.Is(err, ErrRecheckFailed) {
		t.Fatal(err)
	}
	if err := e.Unpanic(true, true); err != nil || e.Session() != StateArmed {
		t.Fatalf("unpanic: %v %s", err, e.Session())
	}
	if err := e.Unpanic(true, true); !errors.Is(err, ErrInvalidTransition) {
		t.Fatal("unpanic outside PANIC must fail")
	}
}

func TestArm_ResetsAlerts(t *testing.T) {
	e, _ := newTestEngine(GuardOff, StateArmed)
	e.Observe(leak("NET-001", contracts.SeverityCritical, "192.0.2.1"))
	if _, err := e.Apply(CmdDisarm); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Apply(CmdArmForce); err != nil {
		t.Fatal(err)
	}
	if len(e.Alerts()) != 0 {
		t.Fatal("new session must start without alerts")
	}
	if d := e.Observe(leak("NET-001", contracts.SeverityCritical, "192.0.2.1")); d.Alert.ID != "A-0001" {
		t.Fatal("alert ids restart per session")
	}
}

func TestMalformedSeverity_TreatedAsWarning(t *testing.T) {
	e, _ := newTestEngine(GuardOff, StateArmed)
	d := e.Observe(cond("NET-005", "BOGUS", contracts.SourceDaemon))
	if d.Alert.Severity != contracts.SeverityWarning {
		t.Fatal(d.Alert.Severity)
	}
}

func TestIgnoredEvents(t *testing.T) {
	e, _ := newTestEngine(GuardOff, StateArmed)
	if d := e.Observe(contracts.Event{Type: contracts.EvClockJump}); d.Alert != nil {
		t.Fatal("non-alert events do not open alerts")
	}
	if IsPointCheck("TUN-001") || !IsPointCheck("DNS-001") {
		t.Fatal("point check table broken")
	}
}

func dstN(i int) string { return fmt.Sprintf("198.51.%d.%d", i/256%256, i%256) }

// A long session with many distinct destinations must not grow the alert list without bound.
// Resolved alerts that no longer matter are dropped; an unacknowledged CRITICAL never is.
func TestEngine_AlertListIsBounded(t *testing.T) {
	e, clk := newTestEngine(GuardOff, StateArmed)
	first := e.Observe(leak("NET-001", contracts.SeverityCritical, "192.0.2.1")).Alert
	for i := range 3 * MaxAlerts {
		e.Observe(leak("NET-009", contracts.SeverityWarning, dstN(i)))
		if i%100 == 0 {
			clk.Advance(11 * time.Second)
			e.Tick()
		}
	}
	if n := len(e.Alerts()); n > MaxAlerts {
		t.Fatalf("%d alerts kept, cap %d", n, MaxAlerts)
	}
	if e.Compacted() == 0 {
		t.Fatal("nothing compacted")
	}
	if e.Alert(first.ID) == nil {
		t.Fatal("an unacknowledged CRITICAL was dropped")
	}
}

// When every alert still matters, new keys fold into one overflow alert per check: the leak is
// still counted, the color stays RED and the state turns GRAY-worthy (alert_overflow).
func TestEngine_AlertOverflowFoldsIntoOneAlert(t *testing.T) {
	e, _ := newTestEngine(GuardOff, StateArmed)
	for i := range MaxAlerts + 50 {
		e.Observe(leak("NET-001", contracts.SeverityCritical, dstN(i)))
	}
	if n := len(e.Alerts()); n != MaxAlerts+1 {
		t.Fatalf("%d alerts, want the cap plus one overflow alert", n)
	}
	last := e.Alerts()[MaxAlerts]
	if last.Key != "NET-001|overflow" || last.Count != 50 {
		t.Fatalf("overflow alert %q count %d", last.Key, last.Count)
	}
	if e.Color() != ColorRed {
		t.Fatalf("color %s", e.Color())
	}
	if !reflect.DeepEqual(e.Degraded(), []string{"alert_overflow"}) {
		t.Fatalf("degraded %v", e.Degraded())
	}
}
