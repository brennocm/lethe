package checks

import (
	"lethe/internal/contracts"
)

// SELF002 is "capture packet loss" (spec §9.6).
type SELF002 struct{}

func (SELF002) ID() string { return "SELF-002" }

var self002Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcCapture}, st: []string{"ST-SELF-002"}}

func (SELF002) Kind() Kind                          { return self002Meta.Kind() }
func (SELF002) DefaultSeverity() contracts.Severity { return self002Meta.DefaultSeverity() }
func (SELF002) Sources() []SourceID                 { return self002Meta.Sources() }
func (SELF002) SelfTestCases() []string             { return self002Meta.SelfTestCases() }

// Evaluate: WARNING when the capture socket of iface dropped packets in the last interval.
func (SELF002) Evaluate(iface string, drops uint32) []Finding {
	if drops == 0 {
		return nil
	}
	return []Finding{{Check: "SELF-002", Severity: contracts.SeverityWarning, Data: map[string]any{"iface": iface, "drops": int(drops)}}}
}
