package checks

import (
	"path/filepath"

	"lethe/internal/contracts"
	"lethe/internal/sensors/procscan"
)

// HOST001 is "process from the deny list" (spec §9.4).
type HOST001 struct{}

func (HOST001) ID() string { return "HOST-001" }

var host001Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcProcscan}, st: []string{"ST-HOST-001"}}

func (HOST001) Kind() Kind                          { return host001Meta.Kind() }
func (HOST001) DefaultSeverity() contracts.Severity { return host001Meta.DefaultSeverity() }
func (HOST001) Sources() []SourceID                 { return host001Meta.Sources() }
func (HOST001) SelfTestCases() []string             { return host001Meta.SelfTestCases() }

// DenyRule is one processes.deny entry of the profile.
type DenyRule struct {
	Match, Value string
	Severity     contracts.Severity
}

// Evaluate: one finding per running process that matches a deny rule, with the rule's severity.
func (HOST001) Evaluate(procs []procscan.Process, rules []DenyRule) []Finding {
	var out []Finding
	for _, p := range procs {
		for _, r := range rules {
			if !(procscan.Matcher{Match: r.Match, Value: r.Value}).Matches(p) {
				continue
			}
			sev := r.Severity
			if !sev.Valid() {
				sev = contracts.SeverityWarning
			}
			out = append(out, Finding{Check: "HOST-001", Severity: sev, Data: map[string]any{
				"proc": procOf(p), "rule": r.Match + ":" + r.Value,
			}})
			break
		}
	}
	return out
}

// procOf is the event form of a scanned process (matched by /proc, so confidence is high).
func procOf(p procscan.Process) contracts.Proc {
	exe := p.Exe
	if exe == "" {
		exe = filepath.Base(p.Comm)
	}
	return contracts.Proc{PID: p.PID, Exe: exe, Comm: p.Comm, UID: p.UID, Confidence: contracts.ConfidenceHigh}
}
