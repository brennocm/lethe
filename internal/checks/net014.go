package checks

import (
	"strings"

	"lethe/internal/contracts"
	"lethe/internal/sensors/dbusmon"
)

// NET014 is "DHCP sends the hostname" (spec §9.1).
type NET014 struct{}

func (NET014) ID() string { return "NET-014" }

var net014Meta = meta{kind: Preflight, sev: contracts.SeverityWarning, sources: []SourceID{SrcDBus}}

func (NET014) Kind() Kind                          { return net014Meta.Kind() }
func (NET014) DefaultSeverity() contracts.Severity { return net014Meta.DefaultSeverity() }
func (NET014) Sources() []SourceID                 { return net014Meta.Sources() }
func (NET014) SelfTestCases() []string             { return net014Meta.SelfTestCases() }

// Evaluate: WARNING when a NetworkManager connection sends the hostname over DHCP (the default)
// or sets dhcp-hostname to the baseline's hostname.
func (NET014) Evaluate(nm dbusmon.NM, k Known) []Finding {
	var ids []any
	matched := false
	for _, c := range nm.Connections {
		if c.Type == "loopback" || c.Type == "wireguard" || c.Type == "vpn" || c.Type == "tun" {
			continue
		}
		hit := k.Hostname != "" && strings.EqualFold(c.DHCPHostname, k.Hostname)
		if c.SendHostname || hit {
			ids = append(ids, c.ID)
		}
		matched = matched || hit
	}
	if len(ids) == 0 {
		return nil
	}
	d := map[string]any{"connections": ids, "fix": "nmcli connection modify ID ipv4.dhcp-send-hostname no ipv6.dhcp-send-hostname no"}
	if matched {
		d["matched"] = "baseline.hostname"
	}
	return []Finding{{Check: "NET-014", Severity: contracts.SeverityWarning, Data: d}}
}
