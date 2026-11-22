package gui

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

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
	ev := contracts.Event{Seq: seq, TS: t0.Add(time.Duration(seq) * time.Second), Type: contracts.EvCheckAlert, Check: check, Severity: sev}
	if exe != "" {
		ev.Data = map[string]any{"proc": map[string]any{"exe": exe, "pid": float64(seq)}}
	}
	return ev
}

// The events page groups the network alerts by program; a repeated warning can be hidden on
// screen for the session, a critical one never.
func TestNET001_EventsByProgramAndMute(t *testing.T) {
	evs := []contracts.Event{
		alertEv(1, "NET-002", contracts.SeverityWarning, "/usr/bin/curl"),
		alertEv(2, "NET-001", contracts.SeverityCritical, "/usr/lib/firefox/firefox"),
		alertEv(3, "NET-001", contracts.SeverityCritical, "/usr/lib/firefox/firefox"),
		alertEv(4, "HOST-005", contracts.SeverityWarning, ""),
	}
	p := ByProgram(evs)
	if len(p) != 2 || p[0].Proc != "firefox" || p[0].Outside != 2 || p[0].Worst != "CRITICAL" || p[1].Proc != "curl" || p[1].Blocked != 1 {
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
	u, _, _ := setup(t, st)
	u.Apply(st, evs)
	u.mute(evs[0])
	if len(u.shown) != 3 || !u.mutedNote.Visible() || len(u.progRows.Objects) != 2 {
		t.Fatalf("shown %d", len(u.shown))
	}
	st.Session = "s-other"
	u.Apply(st, nil)
	u.refreshTimeline()
	if len(u.muted) != 0 || u.mutedNote.Visible() {
		t.Fatal("hiding lasts one session")
	}
}

// The guided VPN drop test reads lethe's own events after its start.
func TestTUN001_DropTestVerdict(t *testing.T) {
	before := alertEv(1, "NET-001", contracts.SeverityCritical, "/usr/bin/old")
	down := alertEv(2, "TUN-001", contracts.SeverityCritical, "")
	cases := []struct {
		evs  []contracts.Event
		want string
	}{
		{[]contracts.Event{before}, "drop_unseen"},
		{[]contracts.Event{before, down}, "drop_ok"},
		{[]contracts.Event{before, down, alertEv(3, "NET-002", contracts.SeverityWarning, "/usr/bin/curl")}, "drop_blocked"},
		{[]contracts.Event{before, down, alertEv(3, "DNS-001", contracts.SeverityCritical, "/usr/bin/curl")}, "drop_leak"},
	}
	for _, c := range cases {
		if r := DropOf(c.evs, 1); r.Verdict() != c.want {
			t.Fatalf("%+v: %s, want %s", r, r.Verdict(), c.want)
		}
	}
	if r := DropOf(cases[3].evs, 1); len(r.Procs) != 1 || r.Procs[0] != "curl" || r.Outside != 1 {
		t.Fatalf("%+v", r)
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
