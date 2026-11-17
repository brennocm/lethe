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
// expect.keyboard. Country gives the exit country × timezone × locale part.
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

// Country compares the exit country (NET-011, offline geo) with the country of the timezone
// (zone1970.tab) and the territory of the locale (pt_BR → BR). A timezone shared by several
// countries matches any of them. Unknown parts are not compared.
func (PER001) Country(exit string, timezone, locale string, zoneCountries map[string][]string) []Finding {
	exit = strings.ToUpper(exit)
	if exit == "" {
		return nil
	}
	var mismatch []any
	if cs, ok := zoneCountries[timezone]; ok && len(cs) > 0 {
		match := false
		for _, c := range cs {
			if strings.EqualFold(c, exit) {
				match = true
			}
		}
		if !match {
			mismatch = append(mismatch, "timezone")
		}
	}
	if t := localeTerritory(locale); t != "" && t != exit {
		mismatch = append(mismatch, "locale")
	}
	if len(mismatch) == 0 {
		return nil
	}
	return []Finding{{Check: "PER-001", Severity: contracts.SeverityWarning, Data: map[string]any{
		"mismatch": mismatch, "exit_country": exit}}}
}

// localeTerritory is the territory of a POSIX locale: "pt_BR.UTF-8@x" → "BR".
func localeTerritory(l string) string {
	l, _, _ = strings.Cut(l, ".")
	l, _, _ = strings.Cut(l, "@")
	if _, t, ok := strings.Cut(l, "_"); ok && len(t) == 2 {
		return strings.ToUpper(t)
	}
	return ""
}
