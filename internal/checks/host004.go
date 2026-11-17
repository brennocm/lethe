package checks

import (
	"strings"

	"lethe/internal/contracts"
)

// HOST004 is "real hostname" (spec §9.4).
type HOST004 struct{}

func (HOST004) ID() string { return "HOST-004" }

var host004Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcHostinfo}}

func (HOST004) Kind() Kind                          { return host004Meta.Kind() }
func (HOST004) DefaultSeverity() contracts.Severity { return host004Meta.DefaultSeverity() }
func (HOST004) Sources() []SourceID                 { return host004Meta.Sources() }
func (HOST004) SelfTestCases() []string             { return host004Meta.SelfTestCases() }

// Evaluate: WARNING when the current hostname is the baseline's.
func (HOST004) Evaluate(hostname string, k Known) []Finding {
	if hostname == "" || k.Hostname == "" || !strings.EqualFold(hostname, k.Hostname) {
		return nil
	}
	return []Finding{{Check: "HOST-004", Severity: contracts.SeverityWarning, Data: map[string]any{"matched": "baseline.hostname"}}}
}
