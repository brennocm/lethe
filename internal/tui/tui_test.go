package tui

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/golden"
	"github.com/charmbracelet/x/exp/teatest"

	"lethe/internal/contracts"
	"lethe/internal/daemon"
)

var t0 = time.Date(2026, 11, 16, 14, 0, 0, 0, time.UTC)

type fake struct {
	mu       sync.Mutex
	st       daemon.Status
	recent   []contracts.Event
	ch       chan contracts.Event
	panics   int
	acks     []string // id|reason|pass
	selftest []string // full|pass
}

func (f *fake) Status() (daemon.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.st
	st.Alerts = append([]daemon.AlertView{}, f.st.Alerts...) // a copy, as over IPC
	return st, nil
}
func (f *fake) Recent(int) ([]contracts.Event, error) { return f.recent, nil }
func (f *fake) Subscribe(context.Context) (<-chan contracts.Event, error) {
	return f.ch, nil
}
func (f *fake) Panic() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.panics++
	f.st.State, f.st.Color = "PANIC", "RED"
	return nil
}
func (f *fake) Ack(id, reason string, pass []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.acks = append(f.acks, id+"|"+reason+"|"+string(pass))
	for i := range f.st.Alerts {
		if f.st.Alerts[i].ID == id {
			f.st.Alerts[i].Acked, f.st.Alerts[i].State = true, "acknowledged"
		}
	}
	return nil
}
func (f *fake) Selftest(_ context.Context, full bool, pass []byte) (daemon.SelftestResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mode := "quick"
	if full {
		mode = "full"
	}
	f.selftest = append(f.selftest, mode+"|"+string(pass))
	return daemon.SelftestResult{Passed: false, Cases: []daemon.CaseResult{{ID: "ST-NET-001", Result: "PASS"}, {ID: "ST-DNS-001", Result: "FAIL"}}}, nil
}

func (f *fake) snapshot() (int, []string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.panics, append([]string{}, f.acks...), append([]string{}, f.selftest...)
}

func armed() daemon.Status {
	start := t0.Add(-75 * time.Minute)
	return daemon.Status{State: "ARMED", Color: "YELLOW", Session: "s-20261116-1245", Fingerprint: "ed25519:4f2a 9c1b 77de 0a31", Guard: "strict", StartedAt: &start,
		Alerts:  []daemon.AlertView{{ID: "a-2", Check: "HOST-005", Severity: "WARNING", State: "open", Count: 1, FirstSeen: t0, LastSeen: t0}},
		Sensors: []daemon.SensorView{{Source: "capture", Up: true}, {Source: "dbus-system", Up: false}},
		Exit:    &daemon.ExitView{Country: "NL", ASN: 64500, At: t0.Add(-2 * time.Minute), Path: "wg0"},
	}
}

func critical() (daemon.Status, []contracts.Event) {
	st := armed()
	st.Color = "RED"
	st.Alerts = append(st.Alerts, daemon.AlertView{ID: "a-3", Check: "NET-001", Severity: "CRITICAL", State: "open", Count: 2, FirstSeen: t0, LastSeen: t0})
	st.Lockdown = &daemon.Lockdown{What: "toda a rede", Why: "PÂNICO por NET-001", Exit: "lethe unpanic (pede a passphrase)"}
	evs := []contracts.Event{
		{Seq: 7, TS: t0, Type: contracts.EvCheckAlert, Check: "NET-001", Severity: "CRITICAL", AlertID: "a-3",
			Data: map[string]any{"proto": "udp", "dst": "203.0.113.9", "dport": float64(443), "iface": "eth0",
				"proc": map[string]any{"pid": float64(4242), "exe": "/usr/bin/firefox"}}},
		{Seq: 8, TS: t0, Type: contracts.EvResponseExecuted, AlertID: "a-3", Data: map[string]any{"action": "block_all", "ok": true}},
		{Seq: 9, TS: t0, Type: contracts.EvResponseExecuted, AlertID: "a-3", Data: map[string]any{"action": "kill_processes", "ok": false}},
	}
	return st, evs
}

func newModel(f *fake, bell *bytes.Buffer) *Model {
	m := New(f, Options{Lang: "pt-BR", Now: func() time.Time { return t0 }, Loc: time.UTC, Bell: bell, Tick: time.Hour, BellEvery: 10 * time.Second})
	m.w, m.h = 80, 24
	return m
}

// settle applies the startup messages without a terminal.
func settle(m *Model, f *fake) {
	st, _ := f.Status()
	m.Update(statusMsg{st: st})
	m.Update(recentMsg(f.recent))
}

func TestM12_MainScreenGolden(t *testing.T) {
	f := &fake{st: armed(), recent: []contracts.Event{
		{Seq: 1, TS: t0.Add(-75 * time.Minute), Type: contracts.EvSessionStart},
		{Seq: 2, TS: t0, Type: contracts.EvCheckAlert, Check: "HOST-005", Severity: "WARNING", AlertID: "a-2"},
		{Seq: 3, TS: t0, Type: contracts.EvSelftestResult, Severity: "INFO", Selftest: true},
	}}
	m := newModel(f, nil)
	m.opt.Logs = NewLines(10)
	_, _ = m.opt.Logs.Write([]byte("lethe: agente conectado\nparcial"))
	settle(m, f)
	golden.RequireEqual(t, []byte(m.View()))
}

func TestM12_AlertScreenGolden(t *testing.T) {
	st, evs := critical()
	f := &fake{st: st, recent: evs}
	var bell bytes.Buffer
	m := newModel(f, &bell)
	settle(m, f)
	v := m.View()
	golden.RequireEqual(t, []byte(v))
	for _, l := range strings.Split(v, "\n") {
		if !strings.HasPrefix(l, alertBG) {
			t.Fatalf("a line without the red background: %q", l)
		}
	}
	if bell.String() != "" { // the bell is a command: run it
		t.Fatal("bell before the command ran")
	}
}

func TestM12_BellRepeatsUntilAck(t *testing.T) {
	st, evs := critical()
	f := &fake{st: st, recent: evs}
	var bell bytes.Buffer
	now := t0
	m := newModel(f, &bell)
	m.opt.Now = func() time.Time { return now }
	run := func(c tea.Cmd) {
		if c != nil {
			c()
		}
	}
	_, c := m.Update(statusMsg{st: st})
	run(c)
	now = now.Add(5 * time.Second)
	_, c = m.Update(statusMsg{st: st})
	run(c)
	now = now.Add(6 * time.Second)
	_, c = m.Update(statusMsg{st: st})
	run(c)
	if bell.String() != "\a\a" {
		t.Fatalf("bell at once and after ui.sound_repeat: %q", bell.String())
	}
	st.Alerts[1].Acked = true
	now = now.Add(time.Minute)
	_, c = m.Update(statusMsg{st: st})
	run(c)
	if bell.String() != "\a\a" {
		t.Fatal("no bell after the acknowledgement")
	}
}

func start(t *testing.T, f *fake) (*teatest.TestModel, *Model) {
	t.Helper()
	f.ch = make(chan contracts.Event)
	m := New(f, Options{Lang: "pt-BR", Now: func() time.Time { return t0 }, Loc: time.UTC, Tick: 20 * time.Millisecond})
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(80, 24))
	return tm, m
}

func waitFor(t *testing.T, tm *teatest.TestModel, s string) {
	t.Helper()
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool { return bytes.Contains(b, []byte(s)) },
		teatest.WithDuration(3*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
}

func TestM12_AckCriticalNeedsReasonAndPassphrase(t *testing.T) {
	st, evs := critical()
	f := &fake{st: st, recent: evs}
	tm, m := start(t, f)
	waitFor(t, tm, "ALERTA CR")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // Esc does not close the alert
	tm.Type("q")                          // nor does q
	tm.Type("a")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // an empty reason is refused
	tm.Type("falso positivo do lab")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor(t, tm, "Passphrase da baseline")
	tm.Type("correct horse")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor(t, tm, "Alerta reconhecido")
	tm.Type("q")
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
	_, acks, _ := f.snapshot()
	if len(acks) != 1 || acks[0] != "a-3|falso positivo do lab|correct horse" {
		t.Fatalf("%q", acks)
	}
	if m.Result() != Quit || m.pass != nil {
		t.Fatal("q quits without disarming and leaves no passphrase behind")
	}
}

func TestM12_AckWarningWithoutPassphrase(t *testing.T) {
	f := &fake{st: armed()}
	tm, _ := start(t, f)
	waitFor(t, tm, "HOST-005")
	tm.Type("a")
	tm.Type("ok")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor(t, tm, "Alerta reconhecido")
	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
	_, acks, _ := f.snapshot()
	if len(acks) != 1 || acks[0] != "a-2|ok|" {
		t.Fatalf("%q", acks)
	}
}

func TestM12_PanicAsksFirst(t *testing.T) {
	f := &fake{st: armed()}
	tm, m := start(t, f)
	waitFor(t, tm, "ARMED")
	tm.Type("p")
	tm.Type("n")
	tm.Type("p")
	waitFor(t, tm, "Entrar em P")
	tm.Type("s")
	waitFor(t, tm, "lethe unpanic")
	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
	if p, _, _ := f.snapshot(); p != 1 {
		t.Fatalf("panics %d", p)
	}
	if m.Result() != Interrupt {
		t.Fatal("Ctrl-C hands the disarm to the caller")
	}
}

func TestM12_SelftestQuickAndFull(t *testing.T) {
	f := &fake{st: armed()}
	tm, _ := start(t, f)
	waitFor(t, tm, "ARMED")
	tm.Type("s")
	waitFor(t, tm, "[r]")
	tm.Type("r")
	waitFor(t, tm, "ST-DNS-001")
	tm.Type("s")
	tm.Type("c")
	waitFor(t, tm, "Passphrase da baseline")
	tm.Type("pw")
	tm.Send(tea.KeyMsg{Type: tea.KeyBackspace})
	tm.Type("x")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	teatest.WaitFor(t, tm.Output(), func([]byte) bool { _, _, s := f.snapshot(); return len(s) == 2 }, teatest.WithDuration(3*time.Second))
	tm.Type("q")
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
	_, _, runs := f.snapshot()
	if runs[0] != "quick|" || runs[1] != "full|px" {
		t.Fatalf("%q", runs)
	}
}

func TestM12_EventsStreamIn(t *testing.T) {
	f := &fake{st: armed()}
	tm, _ := start(t, f)
	waitFor(t, tm, "ARMED")
	f.ch <- contracts.Event{Seq: 50, TS: t0, Type: contracts.EvCheckAlert, Check: "DNS-004", Severity: "WARNING"}
	waitFor(t, tm, "DNS-004")
	close(f.ch)
	tm.Type("q")
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestM12_SecretWipe(t *testing.T) {
	s := newSecret()
	for _, r := range "pé" {
		s.add(r)
	}
	s.backspace()
	if string(s.bytes()) != "p" {
		t.Fatalf("%q", s.bytes())
	}
	b := s.b
	s.wipe()
	for _, c := range b {
		if c != 0 {
			t.Fatal("not wiped")
		}
	}
}

func TestM12_MergeEventsDedupAndCap(t *testing.T) {
	var a []contracts.Event
	for i := range 250 {
		a = append(a, contracts.Event{Seq: uint64(i)})
	}
	out := mergeEvents(a, a[240:])
	if len(out) != maxEvents || out[0].Seq != 50 || out[len(out)-1].Seq != 249 {
		t.Fatalf("%d %d", len(out), out[0].Seq)
	}
}

// A process name with control sequences (OSC, CSI) must not reach the terminal raw.
func TestM12_DetailsAreTerminalSafe(t *testing.T) {
	m := New(nil, Options{Lang: "pt-BR"})
	m.events = []contracts.Event{{Type: contracts.EvCheckAlert, AlertID: "A-1",
		Data: map[string]any{"proc": map[string]any{"exe": "/tmp/\x1b]0;pwned\x07x", "pid": float64(7)}}}}
	if d := m.details("A-1"); strings.ContainsAny(d, "\x1b\x07") {
		t.Fatalf("control characters reached the view: %q", d)
	}
	l := NewLines(5)
	_, _ = l.Write([]byte("daemon \x1b[2J line\n"))
	if got := l.Last(1)[0]; strings.Contains(got, "\x1b") {
		t.Fatalf("%q", got)
	}
}
