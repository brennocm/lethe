package checks

import (
	"strings"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

// NET008 is "real MAC in use" (spec §9.1).
type NET008 struct{}

func (NET008) ID() string { return "NET-008" }

var net008Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcNetlink}}

func (NET008) Kind() Kind                          { return net008Meta.Kind() }
func (NET008) DefaultSeverity() contracts.Severity { return net008Meta.DefaultSeverity() }
func (NET008) Sources() []SourceID                 { return net008Meta.Sources() }
func (NET008) SelfTestCases() []string             { return net008Meta.SelfTestCases() }

// Evaluate: WARNING for each egress interface that is up with its permanent MAC.
func (NET008) Evaluate(s *discovery.Snapshot) []Finding {
	var out []Finding
	for _, i := range s.Ifaces {
		if i.Class != discovery.ClassEgress || !i.Up || i.PermMAC == "" || !strings.EqualFold(i.MAC, i.PermMAC) {
			continue
		}
		out = append(out, Finding{Check: "NET-008", Severity: contracts.SeverityWarning, Data: map[string]any{"iface": i.Name}})
	}
	return out
}
