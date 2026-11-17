package gui

import (
	"bytes"
	"context"
	"image/png"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"lethe/internal/contracts"
)

var t0 = time.Date(2026, 11, 16, 14, 0, 0, 0, time.UTC)

func TestMain(m *testing.M) {
	time.Local = time.UTC // the clocks on screen, for the goldens
	os.Exit(m.Run())
}

type fake struct {
	mu       sync.Mutex
	st       contracts.Status
	calls    []string
	reports  []contracts.FullscreenReport
	selftest []string
}

func (f *fake) log(s string) { f.mu.Lock(); f.calls = append(f.calls, s); f.mu.Unlock() }
func (f *fake) Status() (contracts.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := f.st
	st.Alerts = append([]contracts.AlertView{}, f.st.Alerts...)
	return st, nil
}
func (f *fake) Recent(int) ([]contracts.Event, error)                     { return nil, nil }
func (f *fake) Subscribe(context.Context) (<-chan contracts.Event, error) { return nil, os.ErrClosed }
func (f *fake) Heartbeat() error                                          { return nil }
func (f *fake) Panic() error                                              { f.log("panic"); return nil }
func (f *fake) Ack(id, reason string, pass []byte) error {
	f.log("ack " + id + "|" + reason + "|" + string(pass))
	return nil
}
func (f *fake) Selftest(_ context.Context, full bool, pass []byte) (contracts.SelftestResult, error) {
	f.mu.Lock()
	f.selftest = append(f.selftest, map[bool]string{true: "full", false: "quick"}[full]+"|"+string(pass))
	f.mu.Unlock()
	return contracts.SelftestResult{Passed: true}, nil
}
func (f *fake) Disarm(pass []byte) error  { f.log("disarm|" + string(pass)); return nil }
func (f *fake) Unpanic(pass []byte) error { f.log("unpanic|" + string(pass)); return nil }
func (f *fake) Fullscreen(r contracts.FullscreenReport) error {
	f.mu.Lock()
	f.reports = append(f.reports, r)
	f.mu.Unlock()
	return nil
}
func (f *fake) got() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.calls...)
}

// trayApp is the test app with a system tray (the test driver has none).
type trayApp struct {
	fyne.App
	menu *fyne.Menu
	icon fyne.Resource
}

func (a *trayApp) SetSystemTrayMenu(m *fyne.Menu)    { a.menu = m }
func (a *trayApp) SetSystemTrayIcon(r fyne.Resource) { a.icon = r }
func (a *trayApp) SetSystemTrayWindow(fyne.Window)   {}

func armed() contracts.Status {
	start := t0.Add(-75 * time.Minute)
	return contracts.Status{State: "ARMED", Color: "YELLOW", Session: "s-20261116-1245", Fingerprint: "ed25519:4f2a 9c1b", Guard: "strict", StartedAt: &start,
		Alerts: []contracts.AlertView{{ID: "A-0002", Check: "HOST-005", Severity: "WARNING", State: "open", Count: 1, FirstSeen: t0, LastSeen: t0}},
		Exit:   &contracts.ExitView{Country: "NL", ASN: 64500, At: t0.Add(-2 * time.Minute), Path: "wg0"}}
}

func critical() (contracts.Status, []contracts.Event) {
	st := armed()
	st.State, st.Color = "PANIC", "RED"
	st.Alerts = append(st.Alerts, contracts.AlertView{ID: "A-0003", Check: "NET-001", Severity: "CRITICAL", State: "open", Count: 2, FirstSeen: t0, LastSeen: t0})
	st.Lockdown = &contracts.Lockdown{What: "toda a rede", Why: "pânico por NET-001", Exit: "lethe unpanic"}
	return st, []contracts.Event{
		{Seq: 7, TS: t0, Type: contracts.EvCheckAlert, Check: "NET-001", Severity: "CRITICAL", AlertID: "A-0003",
			Data: map[string]any{"proto": "udp", "dst": "203.0.113.9", "dport": float64(443), "iface": "eth0", "proc": map[string]any{"pid": float64(4242), "exe": "/usr/bin/firefox"}}},
		{Seq: 8, TS: t0, Type: contracts.EvResponseExecuted, AlertID: "A-0003", Data: map[string]any{"action": "block_all", "ok": true}},
	}
}

func setup(t *testing.T, st contracts.Status) (*UI, *fake, *trayApp) {
	t.Helper()
	a := &trayApp{App: test.NewTempApp(t)}
	f := &fake{st: st}
	u := New(a, f, Options{Lang: "pt-BR", Now: func() time.Time { return t0 }, X11: true})
	u.Build()
	u.panel.Resize(fyne.NewSize(1000, 720))
	return u, f, a
}

// overlayButton finds a button by text in the window's dialogs.
func overlayButton(t *testing.T, w fyne.Window, text string) *widget.Button {
	t.Helper()
	var found *widget.Button
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		if b, ok := o.(*widget.Button); ok && b.Text == text {
			found = b
		}
		if c, ok := o.(*fyne.Container); ok {
			for _, x := range c.Objects {
				walk(x)
			}
		}
		if wd, ok := o.(fyne.Widget); ok {
			for _, x := range test.WidgetRenderer(wd).Objects() {
				walk(x)
			}
		}
	}
	for _, o := range w.Canvas().Overlays().List() {
		walk(o)
	}
	walk(w.Content())
	if found == nil {
		t.Fatalf("no button %q", text)
	}
	return found
}

func overlaySecret(t *testing.T, w fyne.Window) *SecretEntry {
	t.Helper()
	var found *SecretEntry
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		if s, ok := o.(*SecretEntry); ok {
			found = s
			return
		}
		if c, ok := o.(*fyne.Container); ok {
			for _, x := range c.Objects {
				walk(x)
			}
		}
		if wd, ok := o.(fyne.Widget); ok {
			for _, x := range test.WidgetRenderer(wd).Objects() {
				walk(x)
			}
		}
	}
	for _, o := range w.Canvas().Overlays().List() {
		walk(o)
	}
	walk(w.Content())
	if found == nil {
		t.Fatal("no passphrase entry")
	}
	return found
}

func TestM13_PanelGolden(t *testing.T) {
	u, _, a := setup(t, armed())
	u.Apply(armed(), []contracts.Event{{Seq: 1, TS: t0, Type: contracts.EvCheckAlert, Check: "HOST-005", Severity: "WARNING", AlertID: "A-0002"}})
	test.AssertRendersToMarkup(t, "panel.xml", u.panel.Canvas())
	if u.rows["HOST-005"].Importance != widget.WarningImportance || !strings.Contains(u.rows["HOST-005"].Text, "WARNING ×1") {
		t.Fatalf("%q", u.rows["HOST-005"].Text)
	}
	if u.alertWin != nil {
		t.Fatal("no full-screen alert for a WARNING")
	}
	if a.menu == nil || a.menu.Items[0].Label != "lethe: ARMED · 1" || a.icon == nil {
		t.Fatal("tray")
	}
}

func TestM13_FullscreenAlertOnlyClosesWithAck(t *testing.T) {
	st, evs := critical()
	u, f, _ := setup(t, st)
	u.Apply(st, evs)
	if u.alertWin == nil || !u.alertWin.FullScreen() {
		t.Fatal("a CRITICAL takes the screen")
	}
	test.AssertRendersToMarkup(t, "alert.xml", u.alertWin.Canvas())
	u.alertWin.Close() // the close button is intercepted
	ack := overlayButton(t, u.alertWin, "Reconhecer")
	test.Tap(ack) // no reason, no passphrase: nothing
	pass := overlaySecret(t, u.alertWin)
	test.Type(pass, "correct horse")
	var reason *widget.Entry
	for _, o := range u.alertBody.Objects {
		if e, ok := o.(*widget.Entry); ok {
			reason = e
		}
	}
	test.Type(reason, "falso positivo")
	test.Tap(ack)
	u.wg.Wait()
	calls := f.got()
	if len(calls) != 1 || calls[0] != "ack A-0003|falso positivo|correct horse" {
		t.Fatalf("%q", calls)
	}
	if pass.Len() != 0 {
		t.Fatal("the entry is wiped after the ack")
	}
	if len(f.reports) != 1 || f.reports[0].Result != "shown" || f.reports[0].AlertID != "A-0003" {
		t.Fatalf("%+v", f.reports)
	}
	st.Alerts[1].Acked, st.Alerts[1].State = true, "acknowledged"
	u.Apply(st, nil)
	if u.alertID != "" {
		t.Fatal("the alert window goes after the ack")
	}
	if !u.unpanicBtn.Visible() {
		t.Fatal("PANIC shows the way out")
	}
}

func TestM13_PanicAndDisarm(t *testing.T) {
	u, f, a := setup(t, armed())
	a.menu.Items[2].Action() // tray: Pânico
	test.Tap(overlayButton(t, u.panel, "Yes"))
	u.wg.Wait()
	u.askPassphrase(u.panel, u.t("disarm_ask"), u.be.Disarm)
	test.Type(overlaySecret(t, u.panel), "pw")
	test.Tap(overlayButton(t, u.panel, "Confirmar"))
	u.wg.Wait()
	if c := f.got(); len(c) != 2 || c[0] != "panic" || c[1] != "disarm|pw" {
		t.Fatalf("%q", c)
	}
}

func TestM13_SelftestQuick(t *testing.T) {
	u, f, _ := setup(t, armed())
	u.askSelftest()
	test.Tap(overlayButton(t, u.panel, "Rápido (sem RESP-001)"))
	u.wg.Wait()
	if len(f.selftest) != 1 || f.selftest[0] != "quick|" {
		t.Fatalf("%q", f.selftest)
	}
}

func TestM13_SecretEntry(t *testing.T) {
	test.NewTempApp(t)
	e := NewSecretEntry()
	test.Type(e, "pé")
	e.TypedKey(&fyne.KeyEvent{Name: fyne.KeyBackspace})
	if e.Len() != 1 || e.dots.Text != "• " {
		t.Fatalf("%d %q", e.Len(), e.dots.Text)
	}
	raw := e.buf
	p := e.Take()
	if string(p) != "p" || e.Len() != 0 {
		t.Fatal("take")
	}
	for _, c := range raw {
		if c != 0 {
			t.Fatal("not wiped")
		}
	}
}

func TestM13_TrayIcon(t *testing.T) {
	img, err := png.Decode(bytes.NewReader(TrayIcon("RED", 12).Content()))
	if err != nil {
		t.Fatal(err)
	}
	r, _, _, _ := img.At(6, 32).RGBA()
	if r>>8 != 0xd3 {
		t.Fatalf("not red: %x", r>>8)
	}
}

func TestM13_ViewModel(t *testing.T) {
	st, evs := critical()
	g := Grid(st, "pt-BR")
	var net001 Row
	for _, r := range g["NET"] {
		if r.ID == "NET-001" {
			net001 = r
		}
	}
	if net001.Severity != "CRITICAL" || len(g["SELF"]) == 0 {
		t.Fatalf("%+v", net001)
	}
	if d := Details(evs, "A-0003"); !strings.Contains(d, "udp 203.0.113.9:443") || !strings.Contains(d, "firefox (pid 4242)") {
		t.Fatal(d)
	}
	if a := ActionsTaken(evs, "A-0003", "pt-BR"); len(a) != 1 || a[0] != "Rede bloqueada." {
		t.Fatal(a)
	}
	if len(Filter(evs, "CRITICAL", "")) != 1 || len(Filter(evs, "", "net")) != 1 || OpenCount(st) != 2 {
		t.Fatal("filter")
	}
	if a, _ := AckTarget(st); a.ID != "A-0003" {
		t.Fatal(a)
	}
}
