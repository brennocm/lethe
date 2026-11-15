package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

// TUN007 is "legacy firewall invisible to lethe" (spec §9.3).
type TUN007 struct{}

func (TUN007) ID() string { return "TUN-007" }

var tun007Meta = meta{kind: Preflight, sev: contracts.SeverityWarning, sources: []SourceID{SrcNetlink}}

func (TUN007) Kind() Kind                          { return tun007Meta.Kind() }
func (TUN007) DefaultSeverity() contracts.Severity { return tun007Meta.DefaultSeverity() }
func (TUN007) Sources() []SourceID                 { return tun007Meta.Sources() }
func (TUN007) SelfTestCases() []string             { return tun007Meta.SelfTestCases() }

// Evaluate: WARNING while iptables-legacy tables are loaded (a kill switch there is invisible
// to TUN-004).
func (TUN007) Evaluate(s *discovery.Snapshot) []Finding {
	if !s.LegacyIPTables {
		return nil
	}
	return []Finding{{Check: "TUN-007", Severity: contracts.SeverityWarning, Data: map[string]any{"reason": "iptables_legacy_tables"}}}
}
