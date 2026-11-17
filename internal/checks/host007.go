package checks

import (
	"lethe/internal/contracts"
)

// HOST007 is "time synchronization" (spec §9.4).
type HOST007 struct{}

func (HOST007) ID() string { return "HOST-007" }

var host007Meta = meta{kind: Preflight, sev: contracts.SeverityInfo, sources: []SourceID{SrcHostinfo}}

func (HOST007) Kind() Kind                          { return host007Meta.Kind() }
func (HOST007) DefaultSeverity() contracts.Severity { return host007Meta.DefaultSeverity() }
func (HOST007) Sources() []SourceID                 { return host007Meta.Sources() }
func (HOST007) SelfTestCases() []string             { return host007Meta.SelfTestCases() }

// Evaluate: INFO naming the configured time synchronization daemons (their traffic is already
// covered by NET-001; this records the configuration).
func (HOST007) Evaluate(daemons []string) []Finding {
	if len(daemons) == 0 {
		return nil
	}
	ds := make([]any, 0, len(daemons))
	for _, d := range daemons {
		ds = append(ds, d)
	}
	return []Finding{{Check: "HOST-007", Severity: contracts.SeverityInfo, Data: map[string]any{"daemons": ds}}}
}
