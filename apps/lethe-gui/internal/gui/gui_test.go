package gui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"lethe/internal/baseline"
	"lethe/internal/contracts"
	"lethe/internal/profile"
	lsetup "lethe/internal/setup"
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
func (f *fake) Disarm(pass []byte) error { f.log("disarm|" + string(pass)); return nil }
func (f *fake) Arm(r ArmRequest) (ArmResult, error) {
	f.log("arm|" + r.Guard + "|" + string(r.Passphrase) + "|" + string(r.Baseline))
	return ArmResult{Session: "s-1"}, nil
}
func (f *fake) CheckNow() error { f.log("check_now"); return nil }
func (f *fake) DNSLeak(context.Context) (contracts.DNSLeakResult, error) {
	f.log("dns")
	return contracts.DNSLeakResult{Verdict: "leak", Exit: &contracts.DNSLeakServer{IP: "203.0.113.9", Country: "NL"},
		DNS: []contracts.DNSLeakServer{{Matched: "baseline.networks[0].resolvers", Country: "BR"}}}, nil
}
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
	st.Lockdown = &contracts.Lockdown{What: "toda a rede", Why: "pânico por NET-001", Exit: "lethe unpanic",
		Ways: []string{contracts.WayAck, contracts.WayUnpanic, contracts.WayDisarm}}
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
		if b, ok := o.(*widget.Button); ok && b.Text == text && found == nil && b.Visible() {
			found = b // the first visible one: dialogs are walked before the window
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
	for _, o := range w.Canvas().Overlays().List() { // a dialog's entry first
		walk(o)
	}
	if found == nil {
		walk(w.Content())
	}
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
	a.menu.Items[2].Action()                      // tray: Pânico
	test.Tap(overlayButton(t, u.panel, "Pânico")) // the dialog names the action, in the panel's language
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

// With no session the panel is the start form: the profile names the baseline, both are read
// as the operator and sent with the passphrase and the protection chosen.
func TestM13_StartSessionFromThePanel(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "baseline.age")
	if err := os.WriteFile(base, []byte("sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	prof := filepath.Join(dir, "lethe", "profile.yaml")
	_ = os.MkdirAll(filepath.Dir(prof), 0o700)
	raw := strings.Replace(string(profile.Template), "~/lethe/baseline.age", base, 1)
	if err := os.WriteFile(prof, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	a := &trayApp{App: test.NewTempApp(t)}
	f := &fake{}
	u := New(a, f, Options{Lang: "pt-BR", Now: func() time.Time { return t0 }, Home: dir})
	u.Build()
	if !u.start.Visible() || u.work.Visible() || u.verdict.Text != "Nenhuma sessão em andamento" {
		t.Fatal("no session: the start form")
	}
	if slices.Contains(u.guardSel.Options, u.t("guard_strict")) || !strings.Contains(u.guardNote.Text, "nenhum selftest") {
		t.Fatalf("strict offered without a selftest: %v %q", u.guardSel.Options, u.guardNote.Text)
	}
	// an approved full selftest in the profile's storage.dir: strict is offered
	p, _, _ := profile.Parse([]byte(raw), dir)
	_ = os.MkdirAll(filepath.Join(p.Storage.Dir, "state"), 0o700)
	st, _ := json.Marshal(contracts.SelftestResult{FinishedAt: t0.Add(-time.Hour), Passed: true, Full: true})
	_ = os.WriteFile(filepath.Join(p.Storage.Dir, "state", "selftest.json"), st, 0o600)
	u.refreshStrict()
	u.guardSel.SetSelected(u.t("guard_strict"))
	test.Type(u.startPass, "pw")
	test.Tap(u.startBtn)
	u.wg.Wait()
	if c := f.got(); len(c) != 1 || c[0] != "arm|strict|pw|sealed" {
		t.Fatalf("%q (flash %q)", c, u.flash.Text)
	}
	if u.startPass.Len() != 0 {
		t.Fatal("the passphrase stays in the entry")
	}
	u.offline = os.ErrNotExist
	u.Apply(contracts.Status{}, nil)
	if u.verdict.Text != "O lethe não está rodando" || !strings.Contains(u.routeNote.Text, "systemctl") || u.start.Visible() {
		t.Fatalf("offline: %q %q", u.verdict.Text, u.routeNote.Text)
	}
}

// The route, the place of the exit and the DNS test, as the operator reads them.
func TestNET011_RouteAndDNSTest(t *testing.T) {
	st := armed()
	st.Exit.IP, st.Exit.City, st.Exit.PlaceCountry, st.Exit.PlaceSource = "203.0.113.9", "Amsterdam", "Netherlands", "am.i.mullvad.net"
	r := RouteOf(st, "pt-BR")
	if r.Tunnel != "wg0" || r.Exit != "203.0.113.9  Amsterdam, Netherlands" || r.Tun != HopOK || r.Out != HopOK ||
		!strings.Contains(r.Note, "am.i.mullvad.net") {
		t.Fatalf("%+v", r)
	}
	st.Alerts = append(st.Alerts, contracts.AlertView{ID: "A-9", Check: "NET-011", Severity: "CRITICAL", State: "open"})
	if r := RouteOf(st, "pt-BR"); r.Out != HopBroken || r.Exit != "seu IP real" {
		t.Fatalf("%+v", r)
	}
	u, f, _ := setup(t, armed())
	u.Apply(armed(), nil)
	u.checkNow()
	u.wg.Wait() // the test driver runs fyne.Do on the caller: one action at a time
	u.askDNS()
	test.Tap(overlayButton(t, u.panel, "Rodar o teste"))
	u.wg.Wait()
	c := f.got()
	slices.Sort(c)
	if len(c) != 2 || c[0] != "check_now" || c[1] != "dns" {
		t.Fatalf("%q", c)
	}
	text, imp := DNSText(contracts.DNSLeakResult{Verdict: "leak", DNS: []contracts.DNSLeakServer{{Matched: "baseline.networks[0].resolvers"}}}, "pt-BR")
	if imp != widget.DangerImportance || !strings.Contains(text, "baseline.networks[0].resolvers") {
		t.Fatalf("%q", text)
	}
}

// In PANIC the block says why and offers both ways out: leave the panic, or end the session
// (passphrase) when the tunnel cannot come back.
func TestAC08_GUIShowsBothWaysOutOfPanic(t *testing.T) {
	st, _ := critical()
	u, f, _ := setup(t, st)
	u.Apply(st, nil)
	if !u.block.Visible() || !u.unpanicBtn.Visible() || !u.endBtn.Visible() || !u.ackWayBtn.Visible() ||
		!strings.Contains(u.blockText.Text, "3. Se o túnel não voltar") || strings.Contains(u.blockText.Text, "lethe unpanic") || u.blockWhat.Text != "toda a rede" {
		t.Fatal("the block and its exits")
	}
	test.Tap(u.endBtn)
	test.Type(overlaySecret(t, u.panel), "pw")
	test.Tap(overlayButton(t, u.panel, "Confirmar"))
	u.wg.Wait()
	if c := f.got(); len(c) != 1 || c[0] != "disarm|pw" {
		t.Fatalf("%q", c)
	}
}

// First use from the panel (spec §15.1): with no profile, even with no daemon, the form fills
// what the machine knows, asks the public IP only on request, refuses differing passphrases and
// writes the profile and the baseline; the start form then names the new profile.
func TestM10_FirstUseFromThePanel(t *testing.T) {
	home := t.TempDir()
	asked := []bool{}
	det := func(_ context.Context, askIP bool) lsetup.Detected {
		asked = append(asked, askIP)
		d := lsetup.Detected{Egress: "wireguard", Network: baseline.Network{GatewayIP: "192.0.2.1", Resolvers: []string{"192.0.2.53"}}}
		if askIP {
			d.Network.PublicIPv4 = "203.0.113.7"
		}
		return d
	}
	a := &trayApp{App: test.NewTempApp(t)}
	u := New(a, &fake{}, Options{Lang: "pt-BR", Now: func() time.Time { return t0 }, Home: home, Detect: det, WorkFactor: 10})
	u.offline = os.ErrNotExist
	u.Build()
	u.wg.Wait()
	f := u.firstForm
	if !f.box.Visible() || u.start.Visible() {
		t.Fatal("no profile: the first-use form, even with the daemon off")
	}
	if len(asked) != 1 || asked[0] || f.gateway.Text != "192.0.2.1" || f.netIP.Text != "" || f.egress.Selected != "wireguard" {
		t.Fatalf("local detection only at start: %v %q %q %q", asked, f.gateway.Text, f.netIP.Text, f.egress.Selected)
	}
	test.Tap(f.detectBtn)
	u.wg.Wait()
	if f.netIP.Text != "203.0.113.7" || len(asked) != 2 || !asked[1] {
		t.Fatalf("the public IP on request: %q %v", f.netIP.Text, asked)
	}
	test.Type(f.pass1, "lab passphrase")
	test.Type(f.pass2, "lab passphrasX")
	test.Tap(f.createBtn)
	u.wg.Wait()
	if lsetup.Exists(filepath.Join(home, "lethe")) || u.flash.Text != u.t("pass_mismatch") || f.pass1.Len() != 0 {
		t.Fatalf("differing passphrases: %q", u.flash.Text)
	}
	test.Type(f.pass1, "lab passphrase")
	test.Type(f.pass2, "lab passphrase")
	test.Tap(f.createBtn)
	u.wg.Wait()
	prof := filepath.Join(home, "lethe", "profile.yaml")
	raw, err := os.ReadFile(prof)
	if err != nil {
		t.Fatalf("%v (flash %q)", err, u.flash.Text)
	}
	p, _, err := profile.Parse(raw, home)
	if err != nil || p.Egress.Type != "wireguard" || p.Guard.Mode != "off" {
		t.Fatalf("%v %+v", err, p.Egress)
	}
	enc, _ := os.ReadFile(p.Baseline.File)
	b, err := baseline.Decrypt(enc, []byte("lab passphrase"))
	if err != nil || b.Networks[0].PublicIPv4 != "203.0.113.7" || b.Networks[0].GatewayIP != "192.0.2.1" {
		t.Fatalf("%v", err)
	}
	if f.box.Visible() || u.profile.Text != prof || !strings.Contains(u.flash.Text, prof) {
		t.Fatalf("after creation the start form names the profile: %q %q", u.profile.Text, u.flash.Text)
	}
	if strings.Contains(u.flash.Text, "203.0.113.7") {
		t.Fatal("a baseline value in the panel")
	}
}

// offBackend is a daemon that does not answer until it is started.
type offBackend struct {
	fake
	up bool
}

func (o *offBackend) Status() (contracts.Status, error) {
	o.mu.Lock()
	up := o.up
	o.mu.Unlock()
	if !up {
		return contracts.Status{}, os.ErrNotExist
	}
	return o.fake.Status()
}

// The panel goes offline when the daemon does not answer and offers to start the service; once
// started, the next poll finds it (spec §16.2, ADR 0015).
func TestM13_StartServiceFromThePanel(t *testing.T) {
	home := t.TempDir() // no ~/lethe yet: the service is started before the first use
	be := &offBackend{}
	started := 0
	a := &trayApp{App: test.NewTempApp(t)}
	u := New(a, be, Options{Lang: "pt-BR", Now: func() time.Time { return t0 }, Home: home,
		StartService: func(context.Context) error {
			started++
			be.mu.Lock()
			be.up = true
			be.mu.Unlock()
			return nil
		}})
	u.Build()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u.poll()
	if u.offline == nil || !u.svcBtn.Visible() || u.verdict.Text != "O lethe não está rodando" || !strings.Contains(u.routeNote.Text, "botão") {
		t.Fatalf("offline: %v %q", u.offline, u.routeNote.Text)
	}
	test.Tap(u.svcBtn)
	u.wg.Wait()
	if fi, err := os.Stat(filepath.Join(home, "lethe")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatal("~/lethe exists before the service starts (its ReadWritePaths)")
	}
	if started != 1 || u.offline != nil || u.svcBtn.Visible() || !u.firstForm.box.Visible() {
		t.Fatalf("after the start: %d %v %q", started, u.offline, u.flash.Text)
	}
	go u.Run(ctx) // Run compiles and keeps polling (main.go starts it)
	cancel()
}

// A block no session owns (a daemon restarted after a crash) shows Release the network; it asks
// for confirmation and then runs the cleanup unit. Offline, the same button is there, because a
// crash in portable mode leaves no daemon to report the block (spec §10.6 item 7, ADR 0015).
func TestM81_ReleaseLeftoverBlockFromThePanel(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, "lethe"), 0o700)
	_ = os.WriteFile(filepath.Join(home, "lethe", "profile.yaml"), profile.Template, 0o600)
	cleaned := 0
	a := &trayApp{App: test.NewTempApp(t)}
	u := New(a, &fake{}, Options{Lang: "pt-BR", Now: func() time.Time { return t0 }, Home: home,
		Cleanup: func(context.Context) error { cleaned++; return nil }})
	u.Build()
	st := contracts.Status{State: "READY", Lockdown: &contracts.Lockdown{What: "a rede está bloqueada", Why: "sobrou", Ways: []string{contracts.WayCleanup}, Tables: []string{"inet lethe"}}}
	u.Apply(st, nil)
	if !u.block.Visible() || !u.cleanBtn.Visible() || u.endBtn.Visible() || !strings.Contains(u.blockText.Text, "Liberar a rede") {
		t.Fatalf("block notice: %q", u.blockText.Text)
	}
	test.Tap(u.cleanBtn)
	test.Tap(overlayButton(t, u.panel, "Cancelar"))
	u.wg.Wait()
	if cleaned != 0 {
		t.Fatal("released without the confirmation")
	}
	test.Tap(u.cleanBtn)
	test.Tap(overlayButton(t, u.panel, "Liberar a rede"))
	u.wg.Wait()
	if cleaned != 1 || u.flash.Text != u.t("cleanup_done") {
		t.Fatalf("%d %q", cleaned, u.flash.Text)
	}
	u.offline = os.ErrNotExist
	u.Apply(contracts.Status{}, nil)
	if !u.cleanOff.Visible() || u.cleanBtn.Visible() {
		t.Fatal("offline: the release stays reachable")
	}
}

// With a baseline already in ~/lethe the form asks for its passphrase, not a new one, and a
// passphrase that does not open it creates nothing.
func TestM10_FirstUseKeepsAnExistingBaseline(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "lethe")
	_ = os.MkdirAll(dir, 0o700)
	b, _ := baseline.New(t0, "test")
	enc, _ := baseline.Encrypt(b, []byte("old passphrase"), 10)
	_ = os.WriteFile(filepath.Join(dir, "baseline.age"), enc, 0o600)
	a := &trayApp{App: test.NewTempApp(t)}
	det := func(context.Context, bool) lsetup.Detected { return lsetup.Detected{} }
	u := New(a, &fake{}, Options{Lang: "pt-BR", Now: func() time.Time { return t0 }, Home: home, Detect: det})
	u.offline = os.ErrNotExist
	u.Build()
	u.wg.Wait()
	f := u.firstForm
	if !f.baseExists {
		t.Fatal("the existing baseline is not seen")
	}
	test.Type(f.pass1, "new passphrase")
	test.Type(f.pass2, "new passphrase")
	test.Tap(f.createBtn)
	u.wg.Wait()
	if lsetup.Exists(dir) || !strings.Contains(u.flash.Text, "não a abre") {
		t.Fatalf("a passphrase that does not open the baseline: %q", u.flash.Text)
	}
	test.Type(f.pass1, "old passphrase")
	test.Type(f.pass2, "old passphrase")
	test.Tap(f.createBtn)
	u.wg.Wait()
	if !lsetup.Exists(dir) {
		t.Fatalf("with its passphrase: %q", u.flash.Text)
	}
}

// overlayEntries lists the plain entries of the window's dialogs, in layout order.
func overlayEntries(w fyne.Window) []*widget.Entry {
	var out []*widget.Entry
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		if e, ok := o.(*widget.Entry); ok {
			out = append(out, e)
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
	return out
}

// Register the current network from the start form: the machine fills gateway and resolvers,
// the public IP comes on request, and the baseline gets the network with its passphrase.
func TestM10_RegisterNetworkFromThePanel(t *testing.T) {
	home := t.TempDir()
	a0 := lsetup.Defaults(home)
	a0.WorkLimit = 10
	a0.Network.PublicIPv4 = "203.0.113.7"
	if _, err := lsetup.Create(a0, home, []byte("lab passphrase"), t0, "test"); err != nil {
		t.Fatal(err)
	}
	det := func(_ context.Context, askIP bool) lsetup.Detected {
		d := lsetup.Detected{Network: lsetup.Network{GatewayIP: "198.51.100.1", Resolvers: []string{"198.51.100.53"}}}
		if askIP {
			d.Network.PublicIPv4 = "198.51.100.20"
		}
		return d
	}
	a := &trayApp{App: test.NewTempApp(t)}
	u := New(a, &fake{}, Options{Lang: "pt-BR", Now: func() time.Time { return t0 }, Home: home, Detect: det, WorkFactor: 10})
	u.Build()
	test.Tap(u.addNetBtn)
	u.wg.Wait()
	es := overlayEntries(u.panel) // name, gateway, ip, resolvers
	if len(es) != 4 || es[1].Text != "198.51.100.1" || es[3].Text != "198.51.100.53" || es[2].Text != "" {
		t.Fatalf("local detection: %d entries", len(es))
	}
	test.Tap(overlayButton(t, u.panel, u.t("detect_ip_btn")))
	u.wg.Wait()
	if es[2].Text != "198.51.100.20" {
		t.Fatalf("public IP on request: %q", es[2].Text)
	}
	test.Type(es[0], "escritório")
	test.Type(overlaySecret(t, u.panel), "lab passphrase")
	test.Tap(overlayButton(t, u.panel, u.t("addnet_save")))
	u.wg.Wait()
	if u.flash.Text != fmt.Sprintf(u.t("addnet_ok"), 2) {
		t.Fatalf("%q", u.flash.Text)
	}
	if strings.Contains(u.flash.Text, "198.51.100") {
		t.Fatal("a baseline value in the panel")
	}
}

// Past sessions from the start form: newest first, a missing report says so, and the text shown
// loses control and bidi characters.
func TestM13_ReportsFromThePanel(t *testing.T) {
	home := t.TempDir()
	a0 := lsetup.Defaults(home)
	a0.WorkLimit = 10
	prof, err := lsetup.Create(a0, home, []byte("lab passphrase"), t0, "test")
	if err != nil {
		t.Fatal(err)
	}
	if l, err := Reports(prof, home); err != nil || len(l) != 0 {
		t.Fatalf("no sessions yet: %v %v", l, err)
	}
	_, _, data := lsetup.Paths(a0.Dir)
	for i, id := range []string{"S-old", "S-new", "S-cut"} {
		dir := filepath.Join(data, "sessions", id)
		_ = os.MkdirAll(dir, 0o750)
		if id != "S-cut" {
			p := filepath.Join(dir, "report.md")
			_ = os.WriteFile(p, []byte("# Relatório "+id+"\x1b[31m\u202e\n"), 0o640)
			_ = os.Chtimes(p, t0.Add(time.Duration(i)*time.Hour), t0.Add(time.Duration(i)*time.Hour))
		}
	}
	l, err := Reports(prof, home)
	if err != nil || len(l) != 3 {
		t.Fatalf("%v %v", l, err)
	}
	ids := []string{}
	for _, r := range l {
		if r.ID != "S-cut" {
			ids = append(ids, r.ID)
		} else if r.Path != "" {
			t.Fatal("a session cut short has no report")
		}
	}
	if strings.Join(ids, ",") != "S-new,S-old" {
		t.Fatalf("newest first: %v", ids)
	}
	first := ""
	for _, r := range l {
		if r.Path != "" && first == "" {
			first = r.Path
		}
	}
	text, err := readReport(first)
	if err != nil || strings.ContainsAny(text, "\x1b\u202e") || !strings.Contains(text, "Relatório") {
		t.Fatalf("%q %v", text, err)
	}
	a := &trayApp{App: test.NewTempApp(t)}
	u := New(a, &fake{}, Options{Lang: "pt-BR", Now: func() time.Time { return t0 }, Home: home})
	u.Build()
	u.showReports()
	if len(u.panel.Canvas().Overlays().List()) == 0 {
		t.Fatalf("no reports dialog (flash %q)", u.flash.Text)
	}
}
