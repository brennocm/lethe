package checks

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"lethe/internal/baseline"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/sensors/capture"
	"lethe/internal/sensors/dbusmon"
	"lethe/internal/sensors/hostinfo"
	"lethe/internal/sensors/procscan"
)

func known() Known {
	b := &baseline.Baseline{Hostname: "Estacao-Real", Networks: []baseline.Network{{Name: "casa", SSIDs: []string{"CasaSentinela"}}}}
	return KnownFrom(b)
}

// noValue fails if a baseline value leaked into a finding's data.
func noValue(t *testing.T, fs []Finding, values ...string) {
	t.Helper()
	for _, f := range fs {
		b, _ := json.Marshal(f.Data)
		for _, v := range values {
			if strings.Contains(strings.ToLower(string(b)), strings.ToLower(v)) {
				t.Fatalf("%s leaks %q: %s", f.Check, v, b)
			}
		}
	}
}

func TestHOST001_DenyList(t *testing.T) {
	procs := []procscan.Process{{PID: 5, Exe: "/usr/bin/onedrive", Comm: "onedrive", UID: 1000}, {PID: 6, Exe: "/usr/bin/vim", Comm: "vim"}}
	fs := HOST001{}.Evaluate(procs, []DenyRule{{Match: "exe", Value: "onedrive", Severity: contracts.SeverityCritical}})
	f := onlyFinding(t, fs, "HOST-001", contracts.SeverityCritical)
	if f.Data["proc"].(contracts.Proc).PID != 5 || f.Data["rule"] != "exe:onedrive" {
		t.Fatalf("%+v", f.Data)
	}
	ev := f.Alert()
	if ev.ProcExe() != "/usr/bin/onedrive" {
		t.Fatal("the dedup key needs proc.exe")
	}
}

func TestHOST002_CaptureDevices(t *testing.T) {
	procs := []procscan.Process{
		{PID: 1, Exe: "/usr/bin/pipewire", Comm: "pipewire", Devices: []string{"/dev/snd/pcmC0D0c"}},
		{PID: 2, Exe: "/usr/bin/cheese", Comm: "cheese", Devices: []string{"/dev/video0", "/dev/snd/pcmC0D0c"}},
	}
	f := onlyFinding(t, HOST002{}.Evaluate(procs), "HOST-002", contracts.SeverityWarning)
	if f.Data["video"] != 1 || f.Data["audio"] != 1 {
		t.Fatalf("%+v", f.Data)
	}
	if fs := (HOST002{}).FromAgent(Capture{}); fs != nil {
		t.Fatal(fs)
	}
	onlyFinding(t, HOST002{}.FromAgent(Capture{Audio: 1}), "HOST-002", contracts.SeverityWarning)
}

func TestHOST003_RemoteAccess(t *testing.T) {
	procs := []procscan.Process{{PID: 9, Exe: "/usr/bin/anydesk", Comm: "anydesk"}, {PID: 10, Exe: "/usr/bin/ssh", Comm: "ssh"}}
	onlyFinding(t, HOST003{}.Evaluate(procs), "HOST-003", contracts.SeverityWarning)
	onlyFinding(t, HOST003{}.FromAgent(Capture{Screencast: 1}), "HOST-003", contracts.SeverityWarning)
}

func TestHOST004_RealHostname(t *testing.T) {
	fs := HOST004{}.Evaluate("estacao-real", known())
	onlyFinding(t, fs, "HOST-004", contracts.SeverityWarning)
	noValue(t, fs, "estacao")
	if (HOST004{}).Evaluate("persona-box", known()) != nil {
		t.Fatal("other hostname")
	}
}

func TestHOST005_TimezoneLocale(t *testing.T) {
	want := Persona{Timezone: "UTC", Locale: "en_US.UTF-8"}
	if (HOST005{}).Evaluate("Etc/UTC", "en_US.utf8", want) != nil {
		t.Fatal("equivalent values must pass")
	}
	f := onlyFinding(t, HOST005{}.Evaluate("America/Sao_Paulo", "pt_BR.UTF-8", want), "HOST-005", contracts.SeverityWarning)
	noValue(t, []Finding{f}, "sao_paulo", "pt_br")
	onlyFinding(t, HOST005{}.FromAgent("pt_BR.UTF-8", want), "HOST-005", contracts.SeverityWarning)
}

func TestHOST006_RootAndSwap(t *testing.T) {
	yes, no := true, false
	if (HOST006{}).Evaluate(&yes, nil) != nil || (HOST006{}).Evaluate(nil, nil) != nil {
		t.Fatal("encrypted or unknown root must pass")
	}
	onlyFinding(t, HOST006{}.Evaluate(&no, nil), "HOST-006", contracts.SeverityWarning)
	onlyFinding(t, HOST006{}.Evaluate(&yes, []string{"/dev/sda3"}), "HOST-006", contracts.SeverityWarning)
}

func TestHOST007_TimeSync(t *testing.T) {
	onlyFinding(t, HOST007{}.Evaluate([]string{"chrony"}), "HOST-007", contracts.SeverityInfo)
	if (HOST007{}).Evaluate(nil) != nil {
		t.Fatal("no time sync, nothing to say")
	}
}

func nm() dbusmon.NM {
	return dbusmon.NM{Available: true, ConnectivityCheck: true, Connections: []dbusmon.Conn{
		{ID: "CasaSentinela", Type: "802-11-wireless", SSID: "CasaSentinela", Autoconnect: true, SendHostname: true},
		{ID: "op", Type: "802-3-ethernet", DHCPHostname: "estacao-real"},
		{ID: "wg", Type: "wireguard", SendHostname: true},
	}}
}

func TestHOST008_SavedKnownWiFi(t *testing.T) {
	fs := HOST008{}.Evaluate(nm(), known())
	f := onlyFinding(t, fs, "HOST-008", contracts.SeverityWarning)
	if f.Data["connections"] != 1 {
		t.Fatalf("%+v", f.Data)
	}
	noValue(t, fs, "casasentinela")
}

func TestHOST009_GeoClue(t *testing.T) {
	if (HOST009{}).Evaluate(dbusmon.GeoClue{}) != nil {
		t.Fatal("not running")
	}
	onlyFinding(t, HOST009{}.Evaluate(dbusmon.GeoClue{Running: true}), "HOST-009", contracts.SeverityWarning)
}

func TestNET007_WiFiChange(t *testing.T) {
	arm := []dbusmon.WiFi{{Iface: "wlan0", SSID: "Cafe", BSSID: "02:00:00:00:00:01"}}
	if (NET007{}).Evaluate(arm, arm, known()) != nil {
		t.Fatal("no change")
	}
	onlyFinding(t, NET007{}.Evaluate(arm, []dbusmon.WiFi{{Iface: "wlan0", SSID: "Cafe", BSSID: "02:00:00:00:00:02"}}, known()), "NET-007", contracts.SeverityWarning)
	fs := NET007{}.Evaluate(arm, []dbusmon.WiFi{{Iface: "wlan0", SSID: "CasaSentinela", BSSID: "02:00:00:00:00:03"}}, known())
	f := onlyFinding(t, fs, "NET-007", contracts.SeverityCritical)
	if f.Data["matched"] != "baseline.networks[0].ssids" {
		t.Fatalf("%+v", f.Data)
	}
	noValue(t, fs, "casasentinela")
}

func TestNET008_PermanentMAC(t *testing.T) {
	s := &discovery.Snapshot{Ifaces: []discovery.Iface{
		{LinkInfo: discovery.LinkInfo{Name: "wlan0"}, Class: discovery.ClassEgress, Up: true, MAC: "02:AA:00:00:00:01", PermMAC: "02:aa:00:00:00:01"},
		{LinkInfo: discovery.LinkInfo{Name: "eth0"}, Class: discovery.ClassEgress, Up: true, MAC: "02:aa:00:00:00:09", PermMAC: "02:aa:00:00:00:02"},
		{LinkInfo: discovery.LinkInfo{Name: "eth1"}, Class: discovery.ClassEgress, Up: false, MAC: "02:aa:00:00:00:03", PermMAC: "02:aa:00:00:00:03"},
	}}
	f := onlyFinding(t, NET008{}.Evaluate(s), "NET-008", contracts.SeverityWarning)
	if f.Data["iface"] != "wlan0" {
		t.Fatal(f.Data)
	}
}

func TestNET013_ConnectivityCheck(t *testing.T) {
	onlyFinding(t, NET013{}.Evaluate(nm()), "NET-013", contracts.SeverityWarning)
	if (NET013{}).Evaluate(dbusmon.NM{}) != nil {
		t.Fatal("no NetworkManager")
	}
}

func TestNET014_DHCPHostname(t *testing.T) {
	f := onlyFinding(t, NET014{}.Evaluate(nm(), known()), "NET-014", contracts.SeverityWarning)
	if len(f.Data["connections"].([]any)) != 2 || f.Data["matched"] != "baseline.hostname" {
		t.Fatalf("%+v", f.Data)
	}
}

func TestNET009_HostnameMatchesBaseline(t *testing.T) {
	leak := capture.Leak{Check: "NET-009", Severity: contracts.SeverityWarning, Names: []string{"estacao-real [aa:bb]"}}
	f := FromFrame(capture.Frame{Iface: "eth0", Leak: leak}, contracts.Proc{})
	if f.Sensitive["names"] == "" {
		t.Fatal("announced names must be sealed")
	}
	if _, in := f.Data["names"]; in {
		t.Fatal("names must never be in clear data")
	}
	m := NET009{}.Match(f, known())
	if m.Severity != contracts.SeverityCritical || m.Data["matched"] != "baseline.hostname" {
		t.Fatalf("%+v", m)
	}
	other := FromFrame(capture.Frame{Leak: capture.Leak{Check: "NET-009", Severity: contracts.SeverityWarning, Names: []string{"printer"}}}, contracts.Proc{})
	if (NET009{}).Match(other, known()).Severity != contracts.SeverityWarning {
		t.Fatal("other names stay WARNING")
	}
}

func TestPER001_Keyboard(t *testing.T) {
	want := Persona{Keyboard: "us"}
	if (PER001{}).Evaluate("us,br", true, want) != nil || (PER001{}).Evaluate("us(intl)", false, want) != nil {
		t.Fatal("us layouts must pass")
	}
	f := onlyFinding(t, PER001{}.Evaluate("br", true, want), "PER-001", contracts.SeverityWarning)
	if !f.Agent || f.Alert().Source != contracts.SourceAgent {
		t.Fatal("agent findings carry the agent source")
	}
}

func TestPER002_BrowserConfig(t *testing.T) {
	good := hostinfo.Prefs{Found: true, PeerConnection: false}
	bad := hostinfo.Prefs{Found: true, PeerConnection: true, SOCKSProxy: true}
	fs := PER002{}.Evaluate([]hostinfo.Prefs{good, bad, {}}, hostinfo.ChromiumPolicy{Installed: true})
	if len(fs) != 2 || fs[0].Data["profile"] != 1 || len(fs[0].Data["issues"].([]any)) != 2 || fs[1].Data["browser"] != "chromium" {
		t.Fatalf("%+v", fs)
	}
	if (PER002{}).Evaluate(nil, hostinfo.ChromiumPolicy{Installed: true, WebRtcIPHandling: "disable_non_proxied_udp"}) != nil {
		t.Fatal("policy set")
	}
}

func TestPER003_PersonalProfile(t *testing.T) {
	procs := []procscan.Process{
		{PID: 1, Exe: "/usr/lib/firefox/firefox", Cmdline: []string{"/usr/lib/firefox/firefox"}},
		{PID: 2, Exe: "/usr/lib/firefox/firefox", Cmdline: []string{"firefox", "-profile", "/home/op/.mozilla/firefox/x.persona"}},
		{PID: 3, Exe: "/usr/lib/firefox/firefox", Cmdline: []string{"firefox", "-contentproc", "12"}},
		{PID: 4, Exe: "/home/op/tor-browser/Browser/firefox.real", Cmdline: []string{"firefox.real"}},
		{PID: 5, Exe: "/usr/lib/chromium/chromium", Cmdline: []string{"chromium", "--user-data-dir=/home/op/.config/chromium"}},
	}
	fs := PER003{}.Evaluate(procs, []string{"/home/op/.mozilla/firefox/x.persona"})
	if len(fs) != 2 || fs[0].Data["reason"] != "default_profile" || fs[1].Data["reason"] != "profile_not_in_persona" {
		t.Fatalf("%+v", fs)
	}
}

func TestSELF001_SilentSensor(t *testing.T) {
	onlyFinding(t, SELF001{}.Evaluate([]string{"capture:eth0"}), "SELF-001", contracts.SeverityCritical)
}

func TestSELF002_Drops(t *testing.T) {
	if (SELF002{}).Evaluate("eth0", 0) != nil {
		t.Fatal("no drops")
	}
	onlyFinding(t, SELF002{}.Evaluate("eth0", 3), "SELF-002", contracts.SeverityWarning)
}

func TestSELF003_Disconnected(t *testing.T) {
	onlyFinding(t, SELF003{}.Evaluate([]string{"agent"}), "SELF-003", contracts.SeverityWarning)
}

func TestSELF004_Stale(t *testing.T) {
	if f := onlyFinding(t, (SELF004{}).Evaluate(time.Now().Add(-time.Hour), false, true, time.Now()), "SELF-004", contracts.SeverityCritical); f.Data["reason"] != "failed_critical" {
		t.Fatal(f.Data)
	}
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	if f := onlyFinding(t, (SELF004{}).Evaluate(time.Time{}, false, false, now), "SELF-004", contracts.SeverityWarning); f.Data["reason"] != "never_run" {
		t.Fatal(f.Data)
	}
	if f := onlyFinding(t, (SELF004{}).Evaluate(now.Add(-25*time.Hour), true, false, now), "SELF-004", contracts.SeverityWarning); f.Data["reason"] != "stale" {
		t.Fatal(f.Data)
	}
	if f := onlyFinding(t, (SELF004{}).Evaluate(now.Add(-time.Hour), false, false, now), "SELF-004", contracts.SeverityWarning); f.Data["reason"] != "failed" {
		t.Fatal(f.Data)
	}
	if (SELF004{}).Evaluate(now.Add(-time.Hour), true, false, now) != nil {
		t.Fatal("fresh pass")
	}
}

func TestSELF005_ClockJump(t *testing.T) {
	if (SELF005{}).Evaluate(time.Hour, time.Hour+time.Second) != nil {
		t.Fatal("1 s drift is not a jump")
	}
	onlyFinding(t, SELF005{}.Evaluate(time.Hour, time.Hour-5*time.Second), "SELF-005", contracts.SeverityInfo)
}

func TestDNS004_ConfigChanged(t *testing.T) {
	f := onlyFinding(t, DNS004{}.Evaluate("/etc/resolv.conf"), "DNS-004", contracts.SeverityWarning)
	if f.Data["path"] != "/etc/resolv.conf" {
		t.Fatal(f.Data)
	}
	if (DNS004{}).Evaluate("") != nil {
		t.Fatal("no path")
	}
}
