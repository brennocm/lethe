package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lethe/internal/baseline"
	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/guard"
	"lethe/internal/sensors/capture"
	"lethe/internal/sensors/dbusmon"
	"lethe/internal/sensors/hostinfo"
	"lethe/internal/sensors/nftmon"
	"lethe/internal/sensors/procscan"
)

func alertFor(st Status, check string) *AlertView {
	for _, a := range st.Alerts {
		if a.Check == check {
			return &a
		}
	}
	return nil
}

// withBaseline replaces the fixture baseline with one that knows a hostname and an SSID.
func (f *fixture) withBaseline(t *testing.T) {
	t.Helper()
	b, err := baseline.New(f.clock.Now(), "test")
	if err != nil {
		t.Fatal(err)
	}
	b.Hostname = "estacao-real"
	b.Networks = []baseline.Network{{Name: "casa", SSIDs: []string{"CasaSentinela"}}}
	if f.base, err = baseline.Encrypt(b, f.pass, 10); err != nil {
		t.Fatal(err)
	}
	f.ident, _ = b.Identity()
}

func TestHOST001_DenyListOnArmAndDuringSession(t *testing.T) {
	f := newFixture(t)
	pdir := filepath.Join(f.d.cfg.ProcRoot, "77")
	_ = os.MkdirAll(pdir, 0o755)
	_ = os.WriteFile(filepath.Join(pdir, "comm"), []byte("onedrive\n"), 0o600)
	_ = os.Symlink("/usr/bin/onedrive", filepath.Join(pdir, "exe"))
	_, rep, err := f.d.Arm(f.armReq("off"))
	if err == nil || rep.Result != "FAIL" {
		t.Fatalf("a CRITICAL deny-list process must fail the preflight: %v %s", err, rep.Result)
	}
	_ = os.RemoveAll(pdir)
	f.arm(t, "off")
	f.d.ObserveHost(f.d.sess, hostinfo.State{Procs: []procscan.Process{{PID: 77, Exe: "/usr/bin/onedrive", Comm: "onedrive"}}})
	a := alertFor(f.d.Status(), "HOST-001")
	if a == nil || a.Severity != "CRITICAL" {
		t.Fatalf("status %+v", f.d.Status().Alerts)
	}
	f.d.ObserveHost(f.d.sess, hostinfo.State{})
	f.clock.Advance(11 * time.Second)
	f.d.Tick()
	if a := alertFor(f.d.Status(), "HOST-001"); a.State != "resolved" {
		t.Fatalf("the process is gone: %+v", a)
	}
}

// Agent data raises alerts but never lowers or clears them (principle 9).
func TestM9_AgentNeverLowersOrClears(t *testing.T) {
	f := newFixture(t)
	f.arm(t, "off")
	if err := f.d.AgentReport(AgentFacts{Capture: checks.Capture{Audio: 1}}); err != nil {
		t.Fatal(err)
	}
	if a := alertFor(f.d.Status(), "HOST-002"); a == nil || a.Severity != "WARNING" {
		t.Fatalf("%+v", f.d.Status().Alerts)
	}
	if err := f.d.AgentReport(AgentFacts{}); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(30 * time.Second)
	f.d.Tick()
	if a := alertFor(f.d.Status(), "HOST-002"); a.State == "resolved" {
		t.Fatal("the agent cleared its own alert")
	}
	// a daemon CRITICAL is not lowered by an agent report of the same check
	f.d.mu.Lock()
	f.d.findingLocked(checks.Finding{Check: "HOST-005", Severity: contracts.SeverityCritical, Data: map[string]any{}})
	f.d.mu.Unlock()
	_ = f.d.AgentReport(AgentFacts{Lang: "pt_BR.UTF-8"})
	for _, a := range f.d.Status().Alerts {
		if a.Check == "HOST-005" && a.Severity != "CRITICAL" {
			t.Fatalf("lowered: %+v", a)
		}
	}
	if err := f.d.AgentReport(AgentFacts{Lang: strings.Repeat("x", 100)}); err == nil {
		t.Fatal("oversized field accepted")
	}
	if err := f.d.AgentReport(AgentFacts{Capture: checks.Capture{Video: -1}}); err == nil {
		t.Fatal("negative count accepted")
	}
}

func TestNET007_DaemonWiFiChangeToKnownNetwork(t *testing.T) {
	f := newFixture(t)
	f.withBaseline(t)
	res := f.arm(t, "off")
	cafe := hostinfo.State{BusRead: true, Bus: dbusmon.State{NM: dbusmon.NM{Available: true, WiFi: []dbusmon.WiFi{{Iface: "wlan0", SSID: "Cafe", BSSID: "02:00:00:00:00:01"}}}}}
	f.d.ObserveHost(f.d.sess, cafe)
	if alertFor(f.d.Status(), "NET-007") != nil {
		t.Fatal("the first reading is the reference")
	}
	home := cafe
	home.Bus.NM.WiFi = []dbusmon.WiFi{{Iface: "wlan0", SSID: "CasaSentinela", BSSID: "02:00:00:00:00:02"}}
	f.d.ObserveHost(f.d.sess, home)
	if a := alertFor(f.d.Status(), "NET-007"); a == nil || a.Severity != "CRITICAL" {
		t.Fatalf("%+v", f.d.Status().Alerts)
	}
	_, _ = f.d.Disarm()
	raw, _ := json.Marshal(f.events(t, res.Dir))
	if strings.Contains(string(raw), "CasaSentinela") {
		t.Fatal("the SSID of the baseline reached the journal")
	}
}

func TestNET009_DaemonRaisesOnBaselineHostname(t *testing.T) {
	f := newFixture(t)
	f.withBaseline(t)
	res := f.arm(t, "off")
	leak := capture.Leak{Check: "NET-009", Severity: contracts.SeverityWarning, Proto: "udp", Names: []string{"estacao-real"}}
	f.d.deliver(f.d.sess, checks.FromFrame(capture.Frame{Iface: "eth0", Leak: leak}, contracts.Proc{}))
	if a := alertFor(f.d.Status(), "NET-009"); a == nil || a.Severity != "CRITICAL" {
		t.Fatalf("%+v", f.d.Status().Alerts)
	}
	_, _ = f.d.Disarm()
	raw, _ := json.Marshal(f.events(t, res.Dir))
	if strings.Contains(string(raw), "estacao-real") || !strings.Contains(string(raw), "baseline.hostname") {
		t.Fatalf("journal: the name must be sealed and the match named: %s", raw)
	}
}

func TestSELF005_ClockJumpJournaled(t *testing.T) {
	f := newFixture(t)
	res := f.arm(t, "off")
	f.d.Tick()
	f.d.cfg.Boottime = func() time.Duration { return time.Hour } // the wall clock moves alone
	f.d.Tick()
	f.clock.Advance(10 * time.Second)
	f.d.Tick()
	if a := alertFor(f.d.Status(), "SELF-005"); a == nil || a.Severity != "INFO" {
		t.Fatalf("%+v", f.d.Status().Alerts)
	}
	_, _ = f.d.Disarm()
	if got := strings.Join(types(f.events(t, res.Dir)), ","); !strings.Contains(got, "clock.jump") {
		t.Fatalf("journal %s", got)
	}
}

func TestSELF004_PreflightWarnsWithoutSelftest(t *testing.T) {
	f := newFixture(t)
	res := f.arm(t, "off")
	found := false
	for _, c := range res.Preflight.Checks {
		if c.ID == "SELF-004" && c.Status == "WARN" {
			found = true
		}
	}
	if !found {
		t.Fatalf("preflight %+v", res.Preflight.Checks)
	}
}

// ST-SELF-001: a paused sensor loses its heartbeats, goes GRAY and comes back after the pause.
func TestSELF001_PauseSensorGoesGrayAndBack(t *testing.T) {
	f := newFixture(t)
	f.arm(t, "off")
	s := f.d.sess
	beat := f.d.beat(s, "capture:eth0")
	beat(time.Time{})
	if err := f.d.PauseSensor("capture:eth0", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := f.d.PauseSensor("nope", time.Second); err == nil {
		t.Fatal("unknown sensor accepted")
	}
	for range 4 {
		f.clock.Advance(time.Second)
		beat(time.Time{})
		f.d.Tick()
	}
	if st := f.d.Status(); st.Color != "GRAY" {
		t.Fatalf("paused sensor must turn GRAY: %+v", st)
	}
	f.clock.Advance(2 * time.Second)
	beat(time.Time{})
	f.d.Tick()
	if st := f.d.Status(); st.Color != "GREEN" {
		t.Fatalf("pause over: %+v", st)
	}
	_, _ = f.d.Disarm()
}

// The timerfd watcher ends with the session (it never pins a goroutine).
func TestSELF005_ClockSetLoopEndsWithContext(t *testing.T) {
	f := newFixture(t)
	f.arm(t, "off")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.d.clockSetLoop(ctx, f.d.sess); close(done) }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("clockSetLoop did not stop")
	}
	_, _ = f.d.Disarm()
}

func TestM9_AgentReportSchema(t *testing.T) {
	raw, _ := json.Marshal(AgentFacts{Lang: "pt_BR.UTF-8", Keyboard: "br", Capture: checks.Capture{Audio: 1}})
	if err := contracts.ValidateJSON("agent_report", raw); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{
		`{"capture":{"audio":0,"video":0,"screencast":0},"check":"NET-001"}`,
		`{"capture":{"audio":-1,"video":0,"screencast":0}}`,
		`{"type":"check.alert","check":"HOST-001","severity":"CRITICAL"}`,
	} {
		if contracts.ValidateJSON("agent_report", []byte(bad)) == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// nftmon leaves out exactly the tables the guard creates.
func TestTUN004_OwnTablesMatchTheGuard(t *testing.T) {
	all := guard.All()
	if len(all) != len(nftmon.Own) {
		t.Fatalf("guard %v, nftmon %v", all, nftmon.Own)
	}
	for _, r := range all {
		if !nftmon.Own[r.String()] {
			t.Fatalf("%s is not in nftmon.Own", r)
		}
	}
}
