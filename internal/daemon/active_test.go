package daemon

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"lethe/internal/baseline"
	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/geo"
	"lethe/internal/sensors/egressip"
)

func TestNET011_DaemonRound(t *testing.T) {
	f := newFixture(t)
	b, _ := baseline.New(f.clock.Now(), "test")
	b.Networks = []baseline.Network{{Name: "casa", PublicIPv4: "198.51.100.77"}}
	f.base, _ = baseline.Encrypt(b, f.pass, 10)
	f.ident, _ = b.Identity()
	f.d.cfg.Geo = geo.Map{netip.MustParseAddr("203.0.113.9"): {Country: "DE", ASN: 64500}}
	var gotPath egressip.Path
	answer := netip.MustParseAddr("203.0.113.9")
	f.d.cfg.ActiveQuery = func(_ context.Context, p egressip.Path, _ egressip.Config) egressip.Result {
		gotPath = p
		return egressip.Result{Agreed: true, IP: answer, Place: egressip.Place{Country: "Germany", City: "Berlin", Source: "am.i.mullvad.net"}}
	}
	res := f.arm(t, "off")
	f.d.activeRound(context.Background(), f.d.sess)
	if gotPath.Tunnel != "wg0" {
		t.Fatalf("the query must leave through the tunnel: %+v", gotPath)
	}
	if a := alertFor(f.d.Status(), "NET-011"); a == nil || a.Severity != "WARNING" {
		t.Fatalf("country DE vs NL: %+v", f.d.Status().Alerts)
	}
	if st := f.d.Status(); st.Exit == nil || st.Exit.Country != "DE" || st.Exit.Path != "wg0" ||
		st.Exit.IP != "203.0.113.9" || st.Exit.City != "Berlin" || st.Exit.PlaceSource != "am.i.mullvad.net" {
		t.Fatalf("%+v", st.Exit)
	}
	answer = netip.MustParseAddr("198.51.100.77") // the tunnel broke: the real IP
	f.d.activeRound(context.Background(), f.d.sess)
	if a := alertFor(f.d.Status(), "NET-011"); a.Severity != "CRITICAL" {
		t.Fatalf("%+v", a)
	}
	if raw, _ := json.Marshal(f.d.Status()); strings.Contains(string(raw), "198.51.100.77") {
		t.Fatal("a baseline IP in the status")
	}
	_, _ = f.d.Disarm()
	raw, _ := json.Marshal(f.events(t, res.Dir))
	if strings.Contains(string(raw), "198.51.100.77") || !strings.Contains(string(raw), "baseline.networks[0].public_ipv4") {
		t.Fatal("the real IP must be sealed and the match named")
	}
}

func TestNET011_NoActiveSkipsTheLoop(t *testing.T) {
	f := newFixture(t)
	req := f.armReq("off")
	req.NoActive = true
	if _, _, err := f.d.Arm(req); err != nil {
		t.Fatal(err)
	}
	if f.d.activeOn(f.d.sess) {
		t.Fatal("--no-active must turn the queries off")
	}
	_, _ = f.d.Disarm()
}

func TestM13_GUIFullscreenResultOncePerAlert(t *testing.T) {
	f := newFixture(t)
	res := f.arm(t, "off")
	f.d.mu.Lock()
	f.d.findingLocked(checks.Finding{Check: "DNS-004", Severity: contracts.SeverityWarning, Data: map[string]any{"file": "/etc/resolv.conf"}})
	f.d.mu.Unlock()
	a := alertFor(f.d.Status(), "DNS-004")
	if a == nil {
		t.Fatal("no alert")
	}
	for range 3 {
		if err := f.d.FullscreenResult(FullscreenReport{AlertID: a.ID, Result: "shown", LatencyMS: 120}); err != nil {
			t.Fatal(err)
		}
	}
	if f.d.FullscreenResult(FullscreenReport{AlertID: "A-9999", Result: "shown"}) == nil || f.d.FullscreenResult(FullscreenReport{AlertID: a.ID, Result: "shown", LatencyMS: -1}) == nil || f.d.FullscreenResult(FullscreenReport{AlertID: a.ID, Result: "yes"}) == nil {
		t.Fatal("unknown alert and bad latency must be refused")
	}
	_, _ = f.d.Disarm()
	n := 0
	for _, ev := range f.events(t, res.Dir) {
		if ev.Type == contracts.EvResponseExecuted && ev.Data["reported_by"] == "gui" {
			n++
			if ev.Data["fullscreen_result"] != "shown" || ev.Data["action"] != "alert_fullscreen" {
				t.Fatalf("%+v", ev.Data)
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d reports journaled", n)
	}
}

// The DNS leak test: a resolver from the baseline is a leak, shown by the field's name only; a
// resolver in another country than the exit is suspect; check now needs active checks.
func TestNET011_DNSLeakTestVerdicts(t *testing.T) {
	f := newFixture(t)
	b, _ := baseline.New(f.clock.Now(), "test")
	b.Networks = []baseline.Network{{Name: "casa", Resolvers: []string{"198.51.100.53"}}}
	f.base, _ = baseline.Encrypt(b, f.pass, 10)
	f.ident, _ = b.Identity()
	if _, err := f.d.DNSLeakTest(context.Background()); err == nil {
		t.Fatal("no session: the test must be refused")
	}
	answer := egressip.LeakResult{Exit: &egressip.LeakServer{IP: netip.MustParseAddr("203.0.113.9"), Country: "NL"},
		DNS: []egressip.LeakServer{{IP: netip.MustParseAddr("203.0.113.53"), Country: "NL"}}}
	var gotPath egressip.Path
	f.d.cfg.DNSLeak = func(_ context.Context, p egressip.Path, _ egressip.LeakConfig) egressip.LeakResult {
		gotPath = p
		return answer
	}
	f.arm(t, "off")
	r, err := f.d.DNSLeakTest(context.Background())
	if err != nil || r.Verdict != "ok" || gotPath.Tunnel != "wg0" || r.Exit.IP != "203.0.113.9" {
		t.Fatalf("%+v %v %+v", r, err, gotPath)
	}
	answer.DNS = append(answer.DNS, egressip.LeakServer{IP: netip.MustParseAddr("192.0.2.53"), Country: "BR"})
	if r, _ := f.d.DNSLeakTest(context.Background()); r.Verdict != "suspect" {
		t.Fatalf("%+v", r)
	}
	answer.DNS = append(answer.DNS, egressip.LeakServer{IP: netip.MustParseAddr("198.51.100.53"), Country: "BR"})
	r, _ = f.d.DNSLeakTest(context.Background())
	raw, _ := json.Marshal(r)
	if r.Verdict != "leak" || strings.Contains(string(raw), "198.51.100.53") || !strings.Contains(string(raw), "baseline.networks[0].resolvers") {
		t.Fatalf("%s", raw)
	}
	if a := alertFor(f.d.Status(), "DNS-002"); a == nil || a.Severity != "CRITICAL" {
		t.Fatalf("a leak found by the test raises DNS-002: %+v", f.d.Status().Alerts)
	}
	if err := f.d.CheckNow(); err != nil {
		t.Fatal(err)
	}
	if err := f.d.CheckNow(); err != nil {
		t.Fatal("a second request while one waits is not an error")
	}
}
