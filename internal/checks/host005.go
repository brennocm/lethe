package checks

import (
	"strings"

	"lethe/internal/contracts"
)

// HOST005 is "timezone and locale outside the profile" (spec §9.4).
type HOST005 struct{}

func (HOST005) ID() string { return "HOST-005" }

var host005Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcHostinfo}}

func (HOST005) Kind() Kind                          { return host005Meta.Kind() }
func (HOST005) DefaultSeverity() contracts.Severity { return host005Meta.DefaultSeverity() }
func (HOST005) Sources() []SourceID                 { return host005Meta.Sources() }
func (HOST005) SelfTestCases() []string             { return host005Meta.SelfTestCases() }

// Persona is the expect section of the profile.
type Persona struct {
	Timezone, Locale, Keyboard string
}

// Evaluate: WARNING listing which of timezone and locale differ from the profile. Only the
// expected values are reported: the actual ones may be the operator's real ones.
func (HOST005) Evaluate(timezone, locale string, want Persona) []Finding {
	var mismatch []any
	if want.Timezone != "" && timezone != "" && !sameZone(timezone, want.Timezone) {
		mismatch = append(mismatch, "timezone")
	}
	if want.Locale != "" && locale != "" && !sameLocale(locale, want.Locale) {
		mismatch = append(mismatch, "locale")
	}
	if len(mismatch) == 0 {
		return nil
	}
	return []Finding{{Check: "HOST-005", Severity: contracts.SeverityWarning, Data: map[string]any{
		"mismatch": mismatch, "expected_timezone": want.Timezone, "expected_locale": want.Locale,
	}}}
}

// FromAgent: WARNING when the session language differs from the profile.
func (HOST005) FromAgent(lang string, want Persona) []Finding {
	if want.Locale == "" || lang == "" || sameLocale(lang, want.Locale) {
		return nil
	}
	return []Finding{{Check: "HOST-005", Severity: contracts.SeverityWarning, Agent: true, Data: map[string]any{
		"mismatch": []any{"session_locale"}, "expected_locale": want.Locale,
	}}}
}

// sameLocale compares language_TERRITORY and ignores the codeset (pt_BR.UTF-8 = pt_BR.utf8).
func sameLocale(a, b string) bool {
	norm := func(s string) string {
		s, _, _ = strings.Cut(s, ".")
		s, _, _ = strings.Cut(s, "@")
		return strings.ToLower(s)
	}
	return norm(a) == norm(b)
}

// sameZone treats UTC aliases as equal.
func sameZone(a, b string) bool {
	utc := map[string]bool{"UTC": true, "Etc/UTC": true, "Etc/Universal": true, "Universal": true, "Zulu": true, "Etc/Zulu": true}
	return a == b || (utc[a] && utc[b])
}
