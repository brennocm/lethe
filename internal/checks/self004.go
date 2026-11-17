package checks

import (
	"time"

	"lethe/internal/contracts"
)

// SELF004 is "selftest out of date" (spec §9.6).
type SELF004 struct{}

func (SELF004) ID() string { return "SELF-004" }

var self004Meta = meta{kind: Preflight, sev: contracts.SeverityWarning, sources: []SourceID{SrcHostinfo}}

func (SELF004) Kind() Kind                          { return self004Meta.Kind() }
func (SELF004) DefaultSeverity() contracts.Severity { return self004Meta.DefaultSeverity() }
func (SELF004) Sources() []SourceID                 { return self004Meta.Sources() }
func (SELF004) SelfTestCases() []string             { return self004Meta.SelfTestCases() }

// SelftestMaxAge is how old the last selftest may be.
const SelftestMaxAge = 24 * time.Hour

// Evaluate: WARNING when the last selftest on this machine is older than 24 h or never ran,
// and when it did not pass.
func (SELF004) Evaluate(last time.Time, passed bool, now time.Time) []Finding {
	switch {
	case last.IsZero():
		return []Finding{{Check: "SELF-004", Severity: contracts.SeverityWarning, Data: map[string]any{"reason": "never_run", "fix": "lethe selftest"}}}
	case now.Sub(last) > SelftestMaxAge:
		return []Finding{{Check: "SELF-004", Severity: contracts.SeverityWarning, Data: map[string]any{"reason": "stale", "age_h": int(now.Sub(last).Hours()), "fix": "lethe selftest"}}}
	case !passed:
		return []Finding{{Check: "SELF-004", Severity: contracts.SeverityWarning, Data: map[string]any{"reason": "failed", "fix": "lethe selftest"}}}
	}
	return nil
}
