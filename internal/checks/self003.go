package checks

import (
	"lethe/internal/contracts"
)

// SELF003 is "session agent or GUI disconnected" (spec §9.6).
type SELF003 struct{}

func (SELF003) ID() string { return "SELF-003" }

var self003Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcAgent}}

func (SELF003) Kind() Kind                          { return self003Meta.Kind() }
func (SELF003) DefaultSeverity() contracts.Severity { return self003Meta.DefaultSeverity() }
func (SELF003) Sources() []SourceID                 { return self003Meta.Sources() }
func (SELF003) SelfTestCases() []string             { return self003Meta.SelfTestCases() }

// Evaluate: WARNING per IPC peer (agent, gui) without heartbeat.
func (SELF003) Evaluate(silent []string) []Finding {
	var out []Finding
	for _, p := range silent {
		out = append(out, Finding{Check: "SELF-003", Severity: contracts.SeverityWarning, Data: map[string]any{"peer": p}})
	}
	return out
}
