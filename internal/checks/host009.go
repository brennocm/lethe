package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/sensors/dbusmon"
)

// HOST009 is "geolocation service active" (spec §9.4).
type HOST009 struct{}

func (HOST009) ID() string { return "HOST-009" }

var host009Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcDBus}}

func (HOST009) Kind() Kind                          { return host009Meta.Kind() }
func (HOST009) DefaultSeverity() contracts.Severity { return host009Meta.DefaultSeverity() }
func (HOST009) Sources() []SourceID                 { return host009Meta.Sources() }
func (HOST009) SelfTestCases() []string             { return host009Meta.SelfTestCases() }

// Evaluate: WARNING while GeoClue runs: it sends the nearby BSSIDs to a location service, which
// reveals the physical position even through the tunnel.
func (HOST009) Evaluate(g dbusmon.GeoClue) []Finding {
	if !g.Running {
		return nil
	}
	return []Finding{{Check: "HOST-009", Severity: contracts.SeverityWarning, Data: map[string]any{"in_use": g.InUse}}}
}
