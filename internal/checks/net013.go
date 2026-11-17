package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/sensors/dbusmon"
)

// NET013 is "interface-bound connectivity check" (spec §9.1).
type NET013 struct{}

func (NET013) ID() string { return "NET-013" }

var net013Meta = meta{kind: Preflight, sev: contracts.SeverityWarning, sources: []SourceID{SrcDBus}}

func (NET013) Kind() Kind                          { return net013Meta.Kind() }
func (NET013) DefaultSeverity() contracts.Severity { return net013Meta.DefaultSeverity() }
func (NET013) Sources() []SourceID                 { return net013Meta.Sources() }
func (NET013) SelfTestCases() []string             { return net013Meta.SelfTestCases() }

// Evaluate: WARNING when NetworkManager runs its connectivity check, which binds to the
// interface and may leave outside the tunnel.
func (NET013) Evaluate(nm dbusmon.NM) []Finding {
	if !nm.Available || !nm.ConnectivityCheck {
		return nil
	}
	return []Finding{{Check: "NET-013", Severity: contracts.SeverityWarning, Data: map[string]any{"fix": "connectivity.enabled=false (NetworkManager.conf)"}}}
}
