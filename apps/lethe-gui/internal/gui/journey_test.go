package gui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"lethe/internal/baseline"
	"lethe/internal/contracts"
	lsetup "lethe/internal/setup"
)

// The first use goes in the order the operator does it: the real network with the VPN off (it
// does not go on while a tunnel carries the default route), the persona, the passphrase.
func TestM10_FirstUseInSteps(t *testing.T) {
	tunnel := true
	det := func(context.Context, bool) lsetup.Detected {
		return lsetup.Detected{TunnelUp: tunnel, Network: baseline.Network{GatewayIP: "192.0.2.1"}}
	}
	a := &trayApp{App: test.NewTempApp(t)}
	u := New(a, &fake{}, Options{Lang: "en-US", Now: func() time.Time { return t0 }, Home: t.TempDir(), Detect: det})
	u.offline = os.ErrNotExist
	u.Build()
	u.wg.Wait()
	f := u.firstForm
	if f.step != 0 || !f.steps[0].Visible() || f.steps[1].Visible() || !f.tunnelNote.Visible() || !f.next.Disabled() || f.createBtn.Visible() {
		t.Fatal("a tunnel is up: the network step stays, with the reason")
	}
	tunnel = false
	test.Tap(f.detectBtn)
	u.wg.Wait()
	if f.tunnelNote.Visible() || f.next.Disabled() {
		t.Fatal("the VPN is off: the network step goes on")
	}
	test.Tap(f.next)
	if f.step != 1 || !f.steps[1].Visible() || f.steps[0].Visible() || !f.back.Visible() {
		t.Fatal("the persona step")
	}
	test.Tap(f.next)
	if f.step != 2 || f.next.Visible() || !f.createBtn.Visible() || f.stepNames[0].Color != colSage || f.stepNames[2].Color != colGold {
		t.Fatal("the passphrase step ends with Create")
	}
	test.Tap(f.back)
	if f.step != 1 {
		t.Fatal("back")
	}
}

// The connection check on the Overview reports the routes beside the DNS verdict, and a critical
// one makes the answer red even when DNS is fine.
func TestNET004_QuickCheckReportsRoutes(t *testing.T) {
	r := contracts.DNSLeakResult{Verdict: "ok", Quick: true,
		Findings: []contracts.QuickFinding{{Check: "NET-004", Severity: "CRITICAL", Iface: "eth0", Reason: "route_ipv4"}}}
	s, imp := DNSText(r, "en-US")
	if !strings.Contains(s, "Effective route outside the tunnel (eth0), seen by NET-004.") || imp != widget.DangerImportance {
		t.Fatalf("%q %v", s, imp)
	}
	r.Findings = nil
	if s, _ = DNSText(r, "en-US"); !strings.Contains(s, "Routes: IPv4 and IPv6 both go through the tunnel.") {
		t.Fatalf("%q", s)
	}
	u, _, _ := setup(t, contracts.Status{State: "READY", Color: "GRAY"})
	u.Apply(contracts.Status{State: "READY", Color: "GRAY"}, nil)
	if !u.quickBtn.Visible() || !u.quickCard.Visible() {
		t.Fatal("no session: the Overview offers the check")
	}
	u.Apply(armed(), nil)
	if u.quickBtn.Visible() || u.quickCard.Visible() {
		t.Fatal("in a session the route card does that job")
	}
}

func alertEv(seq uint64, check string, sev contracts.Severity, exe string) contracts.Event {
	ev := contracts.Event{Seq: seq, TS: t0.Add(time.Duration(seq) * time.Second), Type: contracts.EvCheckAlert, Check: check, Severity: sev,
		AlertID: fmt.Sprintf("A-%04d", seq)}
	if exe != "" {
		ev.Data = map[string]any{"proc": map[string]any{"exe": exe, "pid": float64(seq)}}
	}
	return ev
}

func view(ev contracts.Event, count int) contracts.AlertView {
	return contracts.AlertView{ID: ev.AlertID, Check: ev.Check, Severity: string(ev.Severity), State: "open", Count: count, LastSeen: ev.TS}
}

// The events page groups the network alerts by program, counting occurrences (the daemon
// journals an alert once and only raises its count); a repeated warning can be hidden on screen
// for the session, a critical one never.
func TestNET001_EventsByProgramAndMute(t *testing.T) {
	evs := []contracts.Event{
		alertEv(1, "NET-002", contracts.SeverityWarning, "/usr/bin/curl"),
		alertEv(2, "NET-001", contracts.SeverityCritical, "/usr/lib/firefox/firefox"),
		alertEv(3, "NET-001", contracts.SeverityCritical, "/usr/lib/firefox/firefox"),
		alertEv(4, "HOST-005", contracts.SeverityWarning, ""),
	}
	alerts := []contracts.AlertView{view(evs[0], 4), view(evs[1], 5), view(evs[2], 1)}
	p := ByProgram(evs, alerts)
	if len(p) != 2 || p[0].Proc != "firefox" || p[0].Outside != 6 || p[1].Proc != "curl" || p[1].Blocked != 4 {
		t.Fatalf("%+v", p)
	}
	if MuteKey(evs[1]) != "" || MuteKey(evs[0]) != "NET-002|curl" {
		t.Fatal("only warnings can be hidden")
	}
	left, n := Unmuted(evs, map[string]bool{"NET-002|curl": true})
	if n != 1 || len(left) != 3 {
		t.Fatalf("%d %d", n, len(left))
	}

	st := armed()
	st.Alerts = append(st.Alerts, alerts...)
	u, _, _ := setup(t, st)
	u.Apply(st, evs)
	u.mute(evs[0])
	u.Apply(st, nil)
	if len(u.shown) != 3 || !u.mutedNote.Visible() || len(u.progRows.Objects) != 2 {
		t.Fatalf("shown %d", len(u.shown))
	}
	for i, r := range u.recent {
		if u.recentRows[i].Visible() && strings.Contains(r.cells[1].Text, "NET-002") {
			t.Fatal("the Overview's recent list hides it too")
		}
	}
	st.Session = "s-other"
	u.Apply(st, nil)
	if len(u.muted) != 0 || u.mutedNote.Visible() {
		t.Fatal("hiding lasts one session")
	}
}

// The guided VPN drop test compares the alerts at its start and at Done: a leak that repeats an
// alert already open is journaled no more, only counted.
func TestTUN001_DropTestVerdict(t *testing.T) {
	leak := alertEv(1, "NET-001", contracts.SeverityCritical, "/usr/bin/curl")
	down := alertEv(2, "TUN-001", contracts.SeverityCritical, "")
	evs := []contracts.Event{leak, down}
	before := []contracts.AlertView{view(leak, 3)}
	cases := []struct {
		after []contracts.AlertView
		want  string
	}{
		{[]contracts.AlertView{view(leak, 3)}, "drop_unseen"},
		{[]contracts.AlertView{view(leak, 3), view(down, 2)}, "drop_ok"},
		{[]contracts.AlertView{view(leak, 5), view(down, 2)}, "drop_leak"},
	}
	for _, c := range cases {
		if r := DropOf(before, c.after, evs); r.Verdict() != c.want {
			t.Fatalf("%+v: %s, want %s", r, r.Verdict(), c.want)
		}
	}
	if r := DropOf(before, cases[2].after, evs); len(r.Procs) != 1 || r.Procs[0] != "curl" || r.Outside != 2 {
		t.Fatalf("%+v", r)
	}
	// with strict protection a drop blocks the network and closes programs: no test
	u, _, _ := setup(t, armed())
	u.Apply(armed(), nil)
	u.askDrop()
	if !strings.Contains(overlayText(u.panel), u.t("drop_needs_observe")) {
		t.Fatal("strict: the test explains why it does not run")
	}
}

// The persona step checks its fields before it goes on, and Create sends the operator back to
// it when they are wrong.
func TestM10_FirstUseValidatesThePersonaStep(t *testing.T) {
	a := &trayApp{App: test.NewTempApp(t)}
	det := func(context.Context, bool) lsetup.Detected { return lsetup.Detected{} }
	u := New(a, &fake{}, Options{Lang: "en-US", Now: func() time.Time { return t0 }, Home: t.TempDir(), Detect: det})
	u.offline = os.ErrNotExist
	u.Build()
	u.wg.Wait()
	f := u.firstForm
	test.Tap(f.next)
	f.country.SetText("Netherlands")
	test.Tap(f.next)
	if f.step != 1 || !strings.Contains(u.flash.Text, "two-letter code") {
		t.Fatalf("step %d, %q", f.step, u.flash.Text)
	}
	f.country.SetText("NL")
	test.Tap(f.next)
	if f.step != 2 || u.flash.Visible() {
		t.Fatalf("step %d", f.step)
	}
}

// The Session page lists the layers of cover: lethe's by their alerts during a session, the
// operator's always as theirs.
func TestM13_LayersOfCover(t *testing.T) {
	u, _, _ := setup(t, contracts.Status{State: "READY", Color: "GRAY"})
	u.Apply(contracts.Status{State: "READY", Color: "GRAY"}, nil)
	idx := map[string]int{}
	for i, l := range Layers {
		idx[l.Key] = i
	}
	if u.layerBadges[idx["layer_net"]].t.Text != "NA SESSÃO" || u.layerBadges[idx["layer_vm"]].t.Text != "VOCÊ" {
		t.Fatal("before a session")
	}
	u.Apply(armed(), nil) // HOST-005 open
	if u.layerBadges[idx["layer_persona"]].t.Text != "AVISO" || u.layerBadges[idx["layer_net"]].t.Text != u.t("badge_ok") {
		t.Fatalf("%q", u.layerBadges[idx["layer_persona"]].t.Text)
	}
}

// overlayText is the text of the labels in the window's dialogs.
func overlayText(w fyne.Window) string {
	var b strings.Builder
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		if l, ok := o.(*widget.Label); ok {
			b.WriteString(l.Text + "\n")
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
	return b.String()
}
