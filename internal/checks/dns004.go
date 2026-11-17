package checks

import "lethe/internal/contracts"

// DNS004 is "DNS configuration changed" (spec §9.2).
type DNS004 struct{}

func (DNS004) ID() string { return "DNS-004" }

var dns004Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcFSWatch}, st: []string{"ST-DNS-004"}}

func (DNS004) Kind() Kind                          { return dns004Meta.Kind() }
func (DNS004) DefaultSeverity() contracts.Severity { return dns004Meta.DefaultSeverity() }
func (DNS004) Sources() []SourceID                 { return dns004Meta.Sources() }
func (DNS004) SelfTestCases() []string             { return dns004Meta.SelfTestCases() }

// Evaluate: WARNING for a change of a watched DNS file (resolv.conf, its symlink target). The
// discovery refresh that follows re-evaluates DNS-001's allowlist and the tunnel checks.
func (DNS004) Evaluate(path string) []Finding {
	if path == "" {
		return nil
	}
	return []Finding{{Check: "DNS-004", Severity: contracts.SeverityWarning, Data: map[string]any{"path": path}}}
}
