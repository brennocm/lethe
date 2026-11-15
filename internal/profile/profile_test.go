package profile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// specExample is the complete example of spec §13.2.
const specExample = `version: 1
operation:
  id: "OP-2026-117"
  persona: "falcao"
  operator: "agente-07"
egress:
  type: wireguard
  expect_country: NL
  expect_asn: []
  endpoints: []
  tor_control: auto
  tor_cookie: auto
  tor_pt_dns_allow: []
  allow_vpn_client_dns: false
expect:
  timezone: UTC
  locale: en_US.UTF-8
  keyboard: us
  ipv6: false
network:
  allow_lan: false
  allow_dhcp: true
  egress_ifaces: []
  internal_ifaces: []
baseline:
  file: /media/op/vault/baseline.age
guard:
  mode: strict
  panic:
    keep_tunnel: false
    link_down: auto
active_checks:
  enabled: true
  egress_ip:
    interval: [180s, 600s]
    endpoints:
      - https://check.torproject.org/api/ip
      - https://am.i.mullvad.net/json
processes:
  deny:
    - { match: exe,  value: onedrive,         severity: CRITICAL }
    - { match: exe,  value: dropbox,          severity: CRITICAL }
    - { match: exe,  value: telegram-desktop, severity: WARNING }
    - { match: comm, value: Discord,          severity: WARNING }
  kill_on_panic:
    - { match: exe, value: firefox }
    - { match: exe, value: chromium }
    - { match: exe, value: chrome }
    - { match: cgroup, value: "app-*torbrowser*.scope" }
browsers:
  persona_profiles:
    - ~/.mozilla/firefox/xxxx.falcao
overrides:
  NET-009: { severity: WARNING, actions: [alert_tray] }
  HOST-002: { severity: CRITICAL }
overrides_allow_downgrade: false
storage:
  dir: /media/op/vault/lethe
  log_recipients: []
  sensitive_recipients: []
  journald: minimal
ui:
  language: pt-BR
  fullscreen_alerts: true
  sound: true
  sound_repeat: 10s
`

func TestParse_SpecExampleValid(t *testing.T) {
	p, warns, err := Parse([]byte(specExample), "/home/op")
	if err != nil {
		t.Fatal(err)
	}
	if p.Browsers.PersonaProfiles[0] != "/home/op/.mozilla/firefox/xxxx.falcao" {
		t.Fatalf("~ not expanded: %v", p.Browsers.PersonaProfiles)
	}
	if p.ActiveChecks.EgressIP.IntervalMin.Seconds() != 180 || p.UI.SoundRepeatDur.Seconds() != 10 || !*p.Network.AllowDHCP {
		t.Fatalf("durations/defaults: %+v", p.ActiveChecks.EgressIP)
	}
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings %v", warns)
	}
}

func TestTemplate_IsValid(t *testing.T) {
	if _, _, err := Parse(Template, "/home/op"); err != nil {
		t.Fatalf("profile init template must validate: %v", err)
	}
}

func TestParse_Rejects(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"unknown field":   {"ui:\n", "ui:\n  colour: red\n", "colour"},
		"long comm":       {"value: Discord", "value: telegram-desktop", "truncates comm"},
		"bad endpoint":    {"endpoints: []", `endpoints: ["203.0.113.10/udp"]`, "endpoints"},
		"bad guard":       {"mode: strict", "mode: paranoid", "mode"},
		"bad country":     {"expect_country: NL", "expect_country: nl", "expect_country"},
		"relative path":   {"dir: /media/op/vault/lethe", "dir: data/lethe", "absolute"},
		"bad interval":    {"interval: [180s, 600s]", "interval: [600s, 180s]", "interval"},
		"tiny interval":   {"interval: [180s, 600s]", "interval: [5s, 10s]", "interval"},
		"bad override id": {"NET-009:", "NET-9:", "overrides"},
		"bad action":      {"actions: [alert_tray]", "actions: [reboot]", "actions"},
		"bad recipient":   {"log_recipients: []", `log_recipients: ["age1xyz"]`, "log_recipients"},
		"missing storage": {"  dir: /media/op/vault/lethe\n", "", "dir"},
		"duplicate key":   {"  journald: minimal\n", "  journald: minimal\n  journald: none\n", "already defined"},
		"bad version":     {"version: 1", "version: 2", "version"},
		"not yaml":        {"version: 1", "version: [", "YAML"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(specExample, c.from) {
				t.Fatalf("fixture lacks %q", c.from)
			}
			_, _, err := Parse([]byte(strings.Replace(specExample, c.from, c.to, 1)), "/home/op")
			var ve *ValidationError
			if !errors.As(err, &ve) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error mentioning %q, got %v", c.want, err)
			}
		})
	}
}

func TestParse_Warnings(t *testing.T) {
	y := strings.NewReplacer("mode: strict", "mode: off", "allow_lan: false", "allow_lan: true",
		"allow_vpn_client_dns: false", "allow_vpn_client_dns: true",
		"HOST-002: { severity: CRITICAL }", "HOST-002: { severity: INFO }").Replace(specExample)
	_, warns, err := Parse([]byte(y), "/home/op")
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 4 {
		t.Fatalf("want 4 warnings, got %v", warns)
	}
}

func TestParse_EndpointsParsed(t *testing.T) {
	y := strings.Replace(specExample, "endpoints: []", `endpoints: ["203.0.113.10:51820/udp", "[2001:db8::1]:443/tcp"]`, 1)
	p, _, err := Parse([]byte(y), "/home/op")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Egress.ParsedEndpoints) != 2 || p.Egress.ParsedEndpoints[1].Proto != "tcp" || !p.Egress.ParsedEndpoints[1].Addr.Addr().Is6() {
		t.Fatalf("%+v", p.Egress.ParsedEndpoints)
	}
}

func TestExpandPath(t *testing.T) {
	if _, err := ExpandPath("~/x", ""); err == nil {
		t.Fatal("expanded without home")
	}
	if got, _ := ExpandPath("/a/../b", ""); got != "/b" {
		t.Fatal(got)
	}
}

func TestLoad_FileAndSizeLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "op.yaml")
	_ = os.WriteFile(p, []byte(specExample), 0o600)
	if _, _, err := Load(p, "/home/op"); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.yaml")
	_ = os.WriteFile(big, make([]byte, maxProfileSize+10), 0o600)
	if _, _, err := Load(big, "/home/op"); err == nil {
		t.Fatal("oversized profile accepted")
	}
	if _, _, err := Load(filepath.Join(dir, "none"), "/home/op"); err == nil {
		t.Fatal("missing file accepted")
	}
}

func FuzzParseProfile(f *testing.F) {
	f.Add([]byte(specExample))
	f.Add(Template)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = Parse(data, "/home/op")
	})
}

func TestParse_DowngradeAllowedAndPathErrors(t *testing.T) {
	y := strings.NewReplacer("HOST-002: { severity: CRITICAL }", "HOST-002: { severity: INFO }",
		"overrides_allow_downgrade: false", "overrides_allow_downgrade: true",
		"tor_cookie: auto", "tor_cookie: ~/tor/cookie").Replace(specExample)
	p, warns, err := Parse([]byte(y), "/home/op")
	if err != nil || len(warns) != 1 || !strings.Contains(warns[0], "lowers") || p.Egress.TorCookie != "/home/op/tor/cookie" {
		t.Fatalf("%v %v %+v", warns, err, p)
	}
	_, _, err = Parse([]byte(y), "")
	if err == nil || !strings.Contains(err.Error(), "without the operator's home") {
		t.Fatalf("want home error, got %v", err)
	}
	y2 := strings.Replace(specExample, "    - ~/.mozilla/firefox/xxxx.falcao", "    - relative/profile", 1)
	if _, _, err := Parse([]byte(y2), "/home/op"); err == nil {
		t.Fatal("relative browser profile accepted")
	}
}

func TestParse_ActiveChecksNeedTwoEndpoints(t *testing.T) {
	y := strings.Replace(specExample, "      - https://am.i.mullvad.net/json\n", "", 1)
	if _, _, err := Parse([]byte(y), "/home/op"); err == nil || !strings.Contains(err.Error(), "at least 2") {
		t.Fatalf("got %v", err)
	}
}
