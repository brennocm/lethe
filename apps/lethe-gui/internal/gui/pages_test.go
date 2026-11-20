package gui

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"lethe/internal/contracts"
)

// The panel is a sidebar of pages (ADR 0016): a change of situation brings the page that fits
// it (the panel always opens on the Overview), and the operator's choice stays until then.
func TestM13_PanelPagesFollowTheSituation(t *testing.T) {
	u, _, _ := setup(t, contracts.Status{State: "READY", Color: "GRAY"})
	u.Apply(contracts.Status{State: "READY", Color: "GRAY"}, nil)
	if u.page != "overview" || !u.pages["overview"].Visible() || u.pages["session"].Visible() || u.panicBtn.Visible() {
		t.Fatalf("no session: the overview, no panic button (%q)", u.page)
	}
	test.Tap(u.navs["session"])
	u.Apply(armed(), nil)
	if u.page != "overview" || !u.panicBtn.Visible() || !u.navs["overview"].active || u.navs["session"].active {
		t.Fatalf("a session started: the overview (%q)", u.page)
	}
	test.Tap(u.navs["events"])
	u.Apply(armed(), nil)
	if u.page != "events" || u.pageTitle.Text != "Eventos" {
		t.Fatalf("the operator's page stays while the situation does not change (%q)", u.page)
	}
	if u.exitTop.Text != "NL" || u.timeTop.Text != "01:15:00" || !strings.Contains(u.pill.t.Text, "COM AVISOS") {
		t.Fatalf("top bar and pill: %q %q %q", u.exitTop.Text, u.timeTop.Text, u.pill.t.Text)
	}
}

// The overview's areas count the open alerts of their checks and take the worst severity.
func TestM13_OverviewAreas(t *testing.T) {
	st, evs := critical()
	u, _, _ := setup(t, st)
	u.Apply(st, evs)
	leak, host := u.areas[0], u.areas[3]
	if leak.value.Text != "1" || leak.badge.t.Text != "CRÍTICO" || host.value.Text != "1" || host.badge.t.Text != "AVISO" {
		t.Fatalf("areas: %q %q %q %q", leak.value.Text, leak.badge.t.Text, host.value.Text, host.badge.t.Text)
	}
	if !u.recentRows[0].Visible() || u.recentRows[len(evs)].Visible() {
		t.Fatal("one recent row per event, no empty rows")
	}
	if a := AreaOf(st, "DNS-"); a.Open != 0 || a.Worst != "" {
		t.Fatalf("%+v", a)
	}
}

// The DNS & IP page shows the exit the daemon reported and the last DNS test's servers; a
// server that is a baseline value shows the field it matched, never an address.
func TestNET011_LeaksPage(t *testing.T) {
	st := armed()
	st.Exit.IP, st.Exit.City, st.Exit.PlaceCountry = "203.0.113.9", "Amsterdam", "Netherlands"
	u, _, _ := setup(t, st)
	u.Apply(st, nil)
	if u.idIP.Text != "203.0.113.9" || u.idPlace.Text != "Amsterdam, Netherlands" || u.idASN.Text != "AS64500" || u.idBadge.t.Text != "MASCARADO" {
		t.Fatalf("identity: %q %q %q %q", u.idIP.Text, u.idPlace.Text, u.idASN.Text, u.idBadge.t.Text)
	}
	st.Alerts = append(st.Alerts, contracts.AlertView{ID: "A-9", Check: "NET-011", Severity: "CRITICAL", State: "open"})
	u.Apply(st, nil)
	if u.idIP.Text != "seu IP real" || u.idBadge.t.Text != "EXPOSTO" || u.vectors["exit"].badge.t.Text != "VAZOU" {
		t.Fatalf("a real exit: %q %q", u.idIP.Text, u.idBadge.t.Text)
	}
	u.showDNS(contracts.DNSLeakResult{Verdict: "leak", Exit: &contracts.DNSLeakServer{IP: "203.0.113.9", Country: "NL"},
		DNS: []contracts.DNSLeakServer{{Matched: "baseline.networks[0].resolvers", Country: "BR"}, {IP: "198.51.100.7", Country: "DE"}}}, nil)
	rows := ServerRows(contracts.DNSLeakResult{Exit: &contracts.DNSLeakServer{Country: "NL"},
		DNS: []contracts.DNSLeakServer{{Matched: "baseline.networks[0].resolvers"}, {IP: "198.51.100.7", Country: "DE"}, {IP: "198.51.100.8", Country: "NL"}}}, "pt-BR")
	if len(rows) != 3 || !strings.Contains(rows[0].Server, "baseline.networks[0].resolvers") || rows[0].Tone != toneBad ||
		rows[1].Tone != toneWarn || rows[2].Tone != toneOK {
		t.Fatalf("%+v", rows)
	}
	if len(u.dnsRows.Objects) != 2 || u.dnsBadge.t.Text != "VAZOU" || u.page != "overview" {
		t.Fatalf("dns rows: %d %q", len(u.dnsRows.Objects), u.dnsBadge.t.Text)
	}
	u.Apply(contracts.Status{State: "READY", Color: "GRAY"}, nil)
	if u.leakActs.Visible() || !u.leakNote.Visible() {
		t.Fatal("the tests need a session")
	}
}

// The events table filters by interface and by leaks; the detail explains the check, never
// shows a sealed field's ciphertext and drops control characters from daemon text.
func TestM13_EventsTableAndDetail(t *testing.T) {
	st, evs := critical()
	evs = append(evs, contracts.Event{Seq: 9, TS: t0, Type: contracts.EvCheckAlert, Check: "DNS-001", Severity: "CRITICAL",
		Data: map[string]any{"iface": "wlan0", "dst": "198.51.100.53", "qname": map[string]any{"enc": "s1", "ct": "c2VjcmV0"},
			"proc": map[string]any{"pid": float64(7), "exe": "/usr/bin/evil\x1b[31m\u202e"}}})
	u, _, _ := setup(t, st)
	u.Apply(st, evs)
	if len(u.shown) != 3 || len(u.ifaceSel.Options) != 3 {
		t.Fatalf("all events, interfaces eth0 and wlan0: %d %v", len(u.shown), u.ifaceSel.Options)
	}
	u.ifaceSel.SetSelected("wlan0")
	if len(u.shown) != 1 || u.shown[0].Check != "DNS-001" {
		t.Fatalf("iface filter: %d", len(u.shown))
	}
	u.ifaceSel.SetSelected(u.t("filter_iface_all"))
	u.filter.LeaksOnly = true
	u.refreshTimeline()
	if len(u.shown) != 2 {
		t.Fatalf("leaks only drops the response: %d", len(u.shown))
	}
	r := RowOf(evs[2], "pt-BR")
	if r.Proc != "evil[31m [7]" || r.Status != "VAZOU" || r.Tone != toneBad || r.Proto != "" {
		t.Fatalf("%+v", r)
	}
	fields := EventFields(evs[2], "pt-BR")
	for _, f := range fields {
		if f.Key == "qname" && (f.Value != u.t("ev_sealed") || strings.Contains(f.Value, "c2VjcmV0")) {
			t.Fatalf("a sealed field: %q", f.Value)
		}
		if strings.ContainsAny(f.Value, "\x1b\u202e") {
			t.Fatalf("control characters: %q", f.Value)
		}
	}
	u.showDetail(evs[0])
	if !strings.Contains(labels(u.detail), "o destino viu o seu IP real") || !strings.Contains(labels(u.detail), "Rede bloqueada.") {
		t.Fatalf("detail: %q", labels(u.detail))
	}
}

// The guard page names the session's protection, marks it among the three, and lists the
// default responses of spec §10.4 for it; the selftest runs from it.
func TestM13_GuardPage(t *testing.T) {
	u, f, _ := setup(t, armed())
	u.Apply(armed(), nil)
	if u.guardTitle.Text != "Proteção estrita" || u.modes["strict"].badge.t.Text != "ATUAL" || u.modes["off"].badge.box.Visible() ||
		!strings.Contains(u.respCrit.Text, "Rede bloqueada.") {
		t.Fatalf("guard: %q %q", u.guardTitle.Text, u.respCrit.Text)
	}
	off := armed()
	off.Guard = ""
	u.Apply(off, nil)
	if u.guardTitle.Text != "Só observando" || strings.Contains(u.respCrit.Text, "Rede bloqueada.") {
		t.Fatalf("off: %q %q", u.guardTitle.Text, u.respCrit.Text)
	}
	if w, c := Responses("reactive"); len(w) != 2 || c[0] != "block_all" {
		t.Fatal(w, c)
	}
	u.runSelftest(false, nil)
	u.wg.Wait()
	if len(f.selftest) != 1 || f.selftest[0] != "quick|" || !strings.Contains(u.labOut.Text, "Selftest aprovado") {
		t.Fatalf("%q %q", f.selftest, u.labOut.Text)
	}
}

// The session page shows the session with its fingerprint, or the start form, or offline.
func TestM13_SessionPage(t *testing.T) {
	u, _, _ := setup(t, armed())
	u.Apply(armed(), nil)
	if !u.sessInfo.Visible() || u.start.Visible() || u.sessFP.Text != armed().Fingerprint || u.sessGuard.Text != "proteção estrita" {
		t.Fatalf("session: %q %q", u.sessFP.Text, u.sessGuard.Text)
	}
	if !strings.HasPrefix(u.sessStart.Text, "2026-11-16 12:45:00") {
		t.Fatalf("%q", u.sessStart.Text)
	}
	u.Apply(contracts.Status{State: "READY"}, nil)
	if u.sessInfo.Visible() || !u.start.Visible() {
		t.Fatal("no session: the start form")
	}
	u.offline = errOff{}
	u.Apply(contracts.Status{}, nil)
	if u.start.Visible() || !u.sessOffline.Visible() || u.daemonOn.Text != "lethed fora do ar" || u.page != "overview" {
		t.Fatalf("offline: %q %q", u.daemonOn.Text, u.page)
	}
}

type errOff struct{}

func (errOff) Error() string { return "no daemon" }

// labels joins the label texts under o.
func labels(o fyne.CanvasObject) string {
	var out []string
	var walk func(x fyne.CanvasObject)
	walk = func(x fyne.CanvasObject) {
		switch v := x.(type) {
		case *widget.Label:
			out = append(out, v.Text)
		case *fyne.Container:
			for _, y := range v.Objects {
				walk(y)
			}
		}
	}
	walk(o)
	return strings.Join(out, "\n")
}

// Review fixes (ADR 0016): in PANIC nothing leaves, so the exit identity is blocked, not
// exposed; the open-alerts counter takes the tone of the alerts it counts; event types read in
// the operator's words; a selected row does not stay highlighted while the list moves; with no
// session the guard page lists no responses and says why the selftest is not offered.
func TestM13_PanelReviewFixes(t *testing.T) {
	st, evs := critical()
	u, _, _ := setup(t, st)
	u.Apply(st, evs)
	if u.idBadge.t.Text != "BLOQUEADA" || u.idIP.Text != "nada sai" {
		t.Fatalf("panic identity: %q %q", u.idBadge.t.Text, u.idIP.Text)
	}
	for i := range st.Alerts {
		st.Alerts[i].Acked, st.Alerts[i].State = true, "acknowledged"
	}
	u.Apply(st, nil)
	if u.evStats[2].value.Text != "0" || u.evStats[2].value.Color != colText || OpenWorst(st) != "" {
		t.Fatalf("acknowledged alerts are not open: %q", u.evStats[2].value.Text)
	}
	if TypeName(contracts.EvResponseExecuted, "pt-BR") != "Resposta executada" || TypeName("x.unknown", "pt-BR") != "x.unknown" {
		t.Fatal("event type names")
	}
	u.timeline.Select(0)
	if len(u.detail.Objects) < 2 {
		t.Fatal("the detail shows the selected event")
	}
	u.Apply(contracts.Status{State: "READY"}, nil)
	if u.respCrit.Text != "—" || u.labActs.Visible() || !u.labNote.Visible() {
		t.Fatalf("no session: %q", u.respCrit.Text)
	}
}
