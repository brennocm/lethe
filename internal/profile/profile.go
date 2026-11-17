// Package profile loads and validates the operation profile (spec §13).
package profile

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goccy/go-yaml"

	"lethe/internal/contracts"
)

// Template is the commented profile written by `lethe profile init`.
//
//go:embed template.yaml
var Template []byte

const maxProfileSize = 1 << 20

// Bounds of guard.arm_confirm (spec §10.6). Below the minimum a WireGuard keepalive (25 s) may
// not fit; above the maximum the CLI would wait too long for an answer.
const (
	MinArmConfirm = 5 * time.Second
	MaxArmConfirm = 5 * time.Minute
)

// commMax is TASK_COMM_LEN-1: /proc/<pid>/comm is truncated to 15 bytes.
const commMax = 15

type Profile struct {
	Version                 int                 `yaml:"version"`
	Operation               Operation           `yaml:"operation"`
	Egress                  Egress              `yaml:"egress"`
	Expect                  Expect              `yaml:"expect"`
	Network                 Network             `yaml:"network"`
	Baseline                Baseline            `yaml:"baseline"`
	Guard                   Guard               `yaml:"guard"`
	ActiveChecks            ActiveChecks        `yaml:"active_checks"`
	Processes               Processes           `yaml:"processes"`
	Browsers                Browsers            `yaml:"browsers"`
	Overrides               map[string]Override `yaml:"overrides"`
	OverridesAllowDowngrade bool                `yaml:"overrides_allow_downgrade"`
	Storage                 Storage             `yaml:"storage"`
	UI                      UI                  `yaml:"ui"`
}

type Operation struct {
	ID       string `yaml:"id"`
	Persona  string `yaml:"persona"`
	Operator string `yaml:"operator"`
}

type Egress struct {
	Type              string   `yaml:"type"`
	ExpectCountry     string   `yaml:"expect_country"`
	ExpectASN         []uint32 `yaml:"expect_asn"`
	Endpoints         []string `yaml:"endpoints"`
	TorControl        string   `yaml:"tor_control"`
	TorCookie         string   `yaml:"tor_cookie"`
	TorPTDNSAllow     []string `yaml:"tor_pt_dns_allow"`
	AllowVPNClientDNS bool     `yaml:"allow_vpn_client_dns"`

	// ParsedEndpoints is filled by Load from Endpoints.
	ParsedEndpoints []Endpoint `yaml:"-"`
}

// Endpoint is a declared tunnel endpoint.
type Endpoint struct {
	Addr  netip.AddrPort
	Proto string // "udp" | "tcp"
}

type Expect struct {
	Timezone string `yaml:"timezone"`
	Locale   string `yaml:"locale"`
	Keyboard string `yaml:"keyboard"`
	IPv6     bool   `yaml:"ipv6"`
}

type Network struct {
	AllowLAN       bool     `yaml:"allow_lan"`
	AllowDHCP      *bool    `yaml:"allow_dhcp"`
	EgressIfaces   []string `yaml:"egress_ifaces"`
	InternalIfaces []string `yaml:"internal_ifaces"`
}

type Baseline struct {
	File string `yaml:"file"`
}

type Guard struct {
	Mode       string        `yaml:"mode"`
	ArmConfirm string        `yaml:"arm_confirm"`
	Panic      Panic         `yaml:"panic"`
	ArmWindow  time.Duration `yaml:"-"` // parsed arm_confirm (spec §10.6)
}

type Panic struct {
	KeepTunnel bool   `yaml:"keep_tunnel"`
	LinkDown   string `yaml:"link_down"`
}

type ActiveChecks struct {
	Enabled   bool     `yaml:"enabled"`
	EgressIP  EgressIP `yaml:"egress_ip"`
	TunnelDNS []string `yaml:"tunnel_dns"` // DNS servers reached through the tunnel (NET-011)

	// ParsedTunnelDNS is filled by Load.
	ParsedTunnelDNS []netip.Addr `yaml:"-"`
}

type EgressIP struct {
	Interval  []string `yaml:"interval"`
	Endpoints []string `yaml:"endpoints"`

	// IntervalMin/IntervalMax are filled by Load.
	IntervalMin time.Duration `yaml:"-"`
	IntervalMax time.Duration `yaml:"-"`
}

type Processes struct {
	Deny        []Deny    `yaml:"deny"`
	KillOnPanic []Matcher `yaml:"kill_on_panic"`
}

type Matcher struct {
	Match string `yaml:"match"`
	Value string `yaml:"value"`
}

type Deny struct {
	Match    string `yaml:"match"`
	Value    string `yaml:"value"`
	Severity string `yaml:"severity"`
}

type Browsers struct {
	PersonaProfiles []string `yaml:"persona_profiles"`
}

type Override struct {
	Severity string   `yaml:"severity"`
	Actions  []string `yaml:"actions"`
}

type Storage struct {
	Dir                 string   `yaml:"dir"`
	LogRecipients       []string `yaml:"log_recipients"`
	SensitiveRecipients []string `yaml:"sensitive_recipients"`
	Journald            string   `yaml:"journald"`
}

type UI struct {
	Language         string `yaml:"language"`
	FullscreenAlerts *bool  `yaml:"fullscreen_alerts"`
	Sound            *bool  `yaml:"sound"`
	SoundRepeat      string `yaml:"sound_repeat"`

	SoundRepeatDur time.Duration `yaml:"-"`
}

// ValidationError lists every problem found in a profile.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid profile:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// Load reads, validates and normalizes a profile. home expands "~" (the operator's home, not root's).
// Warnings are returned for valid but risky settings (they also surface in preflight).
func Load(path, home string) (*Profile, []string, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-chosen profile
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxProfileSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > maxProfileSize {
		return nil, nil, &ValidationError{Problems: []string{"profile larger than 1 MiB"}}
	}
	return Parse(raw, home)
}

// Parse validates raw YAML against the schema and semantic rules.
func Parse(raw []byte, home string) (*Profile, []string, error) {
	js, err := yaml.YAMLToJSON(raw)
	if err != nil {
		return nil, nil, &ValidationError{Problems: []string{"YAML: " + err.Error()}}
	}
	if err := contracts.ValidateJSON("profile", js); err != nil {
		return nil, nil, &ValidationError{Problems: []string{err.Error()}}
	}
	var p Profile
	if err := yaml.UnmarshalWithOptions(raw, &p, yaml.Strict(), yaml.DisallowUnknownField()); err != nil {
		return nil, nil, &ValidationError{Problems: []string{"YAML: " + err.Error()}}
	}
	p.applyDefaults()
	warns, problems := p.check(home)
	if len(problems) > 0 {
		return nil, warns, &ValidationError{Problems: problems}
	}
	return &p, warns, nil
}

func (p *Profile) applyDefaults() {
	if p.Egress.TorControl == "" {
		p.Egress.TorControl = "auto"
	}
	if p.Egress.TorCookie == "" {
		p.Egress.TorCookie = "auto"
	}
	if p.Network.AllowDHCP == nil {
		t := true
		p.Network.AllowDHCP = &t
	}
	if p.Guard.Panic.LinkDown == "" {
		p.Guard.Panic.LinkDown = "auto"
	}
	if p.Guard.ArmConfirm == "" {
		p.Guard.ArmConfirm = "30s"
	}
	if len(p.ActiveChecks.EgressIP.Interval) == 0 {
		p.ActiveChecks.EgressIP.Interval = []string{"180s", "600s"}
	}
	if len(p.ActiveChecks.EgressIP.Endpoints) == 0 {
		p.ActiveChecks.EgressIP.Endpoints = []string{"https://check.torproject.org/api/ip", "https://am.i.mullvad.net/json"}
	}
	if p.Storage.Journald == "" {
		p.Storage.Journald = "minimal"
	}
	if p.UI.Language == "" {
		p.UI.Language = "pt-BR"
	}
	if p.UI.FullscreenAlerts == nil {
		t := true
		p.UI.FullscreenAlerts = &t
	}
	if p.UI.Sound == nil {
		t := true
		p.UI.Sound = &t
	}
	if p.UI.SoundRepeat == "" {
		p.UI.SoundRepeat = "10s"
	}
}

func (p *Profile) check(home string) (warns, problems []string) {
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	for _, e := range p.Egress.Endpoints {
		addr, proto, _ := strings.Cut(e, "/")
		ap, err := netip.ParseAddrPort(addr)
		if err != nil || ap.Port() == 0 {
			bad("egress.endpoints: %q is not IP:port/proto", e)
			continue
		}
		p.Egress.ParsedEndpoints = append(p.Egress.ParsedEndpoints, Endpoint{Addr: ap, Proto: proto})
	}
	if c := p.Egress.TorControl; c != "auto" {
		if ap, err := netip.ParseAddrPort(c); err != nil || !ap.Addr().Unmap().IsLoopback() {
			bad("egress.tor_control: %q must be auto or a loopback IP:port", c)
		}
	}
	var err error
	if p.ActiveChecks.EgressIP.IntervalMin, err = time.ParseDuration(p.ActiveChecks.EgressIP.Interval[0]); err != nil {
		bad("active_checks.egress_ip.interval: %v", err)
	}
	if p.ActiveChecks.EgressIP.IntervalMax, err = time.ParseDuration(p.ActiveChecks.EgressIP.Interval[1]); err != nil {
		bad("active_checks.egress_ip.interval: %v", err)
	}
	if p.ActiveChecks.EgressIP.IntervalMin < 30*time.Second || p.ActiveChecks.EgressIP.IntervalMax < p.ActiveChecks.EgressIP.IntervalMin {
		bad("active_checks.egress_ip.interval must be [min, max] with 30s <= min <= max")
	}
	for _, v := range p.ActiveChecks.TunnelDNS {
		a, err := netip.ParseAddr(v)
		if err != nil || a.IsLoopback() || a.IsUnspecified() {
			bad("active_checks.tunnel_dns: %q must be the IP of a DNS server in the tunnel (not loopback)", v)
			continue
		}
		p.ActiveChecks.ParsedTunnelDNS = append(p.ActiveChecks.ParsedTunnelDNS, a.Unmap())
	}
	if p.ActiveChecks.Enabled && len(p.ActiveChecks.EgressIP.Endpoints) < 2 {
		bad("active_checks.egress_ip.endpoints needs at least 2 endpoints")
	}
	if p.Guard.ArmWindow, err = time.ParseDuration(p.Guard.ArmConfirm); err != nil {
		bad("guard.arm_confirm: %v", err)
	} else if p.Guard.ArmWindow < 0 || p.Guard.ArmWindow > MaxArmConfirm {
		bad("guard.arm_confirm must be between 0 and %s", MaxArmConfirm)
	} else if p.Guard.ArmWindow > 0 && p.Guard.ArmWindow < MinArmConfirm {
		bad("guard.arm_confirm must be 0 (off) or at least %s", MinArmConfirm)
	}
	if p.UI.SoundRepeatDur, err = time.ParseDuration(p.UI.SoundRepeat); err != nil {
		bad("ui.sound_repeat: %v", err)
	}
	checkComm := func(where string, m, v string) {
		if m == "comm" && len(v) > commMax {
			bad("%s: comm %q has %d characters but /proc truncates comm to %d; use match: exe", where, v, len(v), commMax)
		}
	}
	for i, d := range p.Processes.Deny {
		checkComm(fmt.Sprintf("processes.deny[%d]", i), d.Match, d.Value)
	}
	for i, m := range p.Processes.KillOnPanic {
		checkComm(fmt.Sprintf("processes.kill_on_panic[%d]", i), m.Match, m.Value)
	}
	if p.Guard.Mode == "off" {
		warns = append(warns, "guard.mode is off: leaks are detected but not prevented")
	}
	if p.Guard.Mode == "strict" && p.Guard.ArmWindow == 0 && p.Guard.ArmConfirm != "" {
		warns = append(warns, "guard.arm_confirm is 0: a strict arm is not undone when the tunnel carries no traffic")
	}
	if p.Egress.AllowVPNClientDNS {
		warns = append(warns, "egress.allow_vpn_client_dns lets the VPN client resolve names outside the tunnel")
	}
	if p.Network.AllowLAN {
		warns = append(warns, "network.allow_lan lets traffic reach the local network outside the tunnel")
	}
	for id, ov := range p.Overrides {
		if ov.Severity == "INFO" {
			if p.OverridesAllowDowngrade {
				warns = append(warns, fmt.Sprintf("overrides.%s lowers the severity to INFO", id))
			} else {
				warns = append(warns, fmt.Sprintf("overrides.%s: CRITICAL checks are clamped to WARNING unless overrides_allow_downgrade is true", id))
			}
		}
	}
	expand := func(where string, path *string) {
		if *path == "" {
			return
		}
		x, err := ExpandPath(*path, home)
		if err != nil {
			bad("%s: %v", where, err)
			return
		}
		*path = x
	}
	expand("baseline.file", &p.Baseline.File)
	expand("storage.dir", &p.Storage.Dir)
	if p.Egress.TorCookie != "auto" {
		expand("egress.tor_cookie", &p.Egress.TorCookie)
	}
	for i := range p.Browsers.PersonaProfiles {
		expand(fmt.Sprintf("browsers.persona_profiles[%d]", i), &p.Browsers.PersonaProfiles[i])
	}
	return warns, problems
}

// ExpandPath expands a leading "~/" with home and requires an absolute, clean result.
func ExpandPath(path, home string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		if home == "" {
			return "", errors.New("cannot expand ~ without the operator's home directory")
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~"))
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("path %q must be absolute (or start with ~/)", path)
	}
	return filepath.Clean(path), nil
}
