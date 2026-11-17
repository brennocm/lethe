package checks

import (
	"strings"

	"lethe/internal/contracts"
)

// PER001 is "geographic coherence" (spec §9.5).
type PER001 struct{}

func (PER001) ID() string { return "PER-001" }

var per001Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcAgent, SrcDBus}}

func (PER001) Kind() Kind                          { return per001Meta.Kind() }
func (PER001) DefaultSeverity() contracts.Severity { return per001Meta.DefaultSeverity() }
func (PER001) Sources() []SourceID                 { return per001Meta.Sources() }
func (PER001) SelfTestCases() []string             { return per001Meta.SelfTestCases() }

// Evaluate compares the keyboard layout of the session (agent; locale1 as the fallback) with
// expect.keyboard. The exit country × timezone part arrives with the active checks (M11).
func (PER001) Evaluate(keyboard string, fromAgent bool, want Persona) []Finding {
	if want.Keyboard == "" || keyboard == "" || sameLayout(keyboard, want.Keyboard) {
		return nil
	}
	d := map[string]any{"mismatch": []any{"keyboard"}, "expected_keyboard": want.Keyboard}
	return []Finding{{Check: "PER-001", Severity: contracts.SeverityWarning, Agent: fromAgent, Data: d}}
}

// sameLayout: "us" matches "us" and "us,br" (the first layout is the active default).
func sameLayout(have, want string) bool {
	first, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(have)), ",")
	first, _, _ = strings.Cut(first, "(") // us(intl)
	return first == strings.ToLower(strings.TrimSpace(want))
}
