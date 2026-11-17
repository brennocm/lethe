package checks

import (
	"lethe/internal/contracts"
)

// SELF001 is "sensor stopped" (spec §9.6): a source without heartbeat for more than 3 s turns the state GRAY. The daemon tracks the heartbeats; the engine handles sensor.down.
type SELF001 struct{}

func (SELF001) ID() string { return "SELF-001" }

var self001Meta = meta{kind: Passive, sev: contracts.SeverityCritical, sources: []SourceID{SrcIPC}, st: []string{"ST-SELF-001"}}

func (SELF001) Kind() Kind                          { return self001Meta.Kind() }
func (SELF001) DefaultSeverity() contracts.Severity { return self001Meta.DefaultSeverity() }
func (SELF001) Sources() []SourceID                 { return self001Meta.Sources() }
func (SELF001) SelfTestCases() []string             { return self001Meta.SelfTestCases() }

// Evaluate: one finding per source that is down.
func (SELF001) Evaluate(down []string) []Finding {
	var out []Finding
	for _, s := range down {
		out = append(out, Finding{Check: "SELF-001", Severity: contracts.SeverityCritical, Data: map[string]any{"source": s}})
	}
	return out
}
