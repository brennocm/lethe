package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/sensors/dbusmon"
)

// HOST008 is "saved Wi-Fi networks with autoconnect" (spec §9.4).
type HOST008 struct{}

func (HOST008) ID() string { return "HOST-008" }

var host008Meta = meta{kind: Preflight, sev: contracts.SeverityWarning, sources: []SourceID{SrcDBus}}

func (HOST008) Kind() Kind                          { return host008Meta.Kind() }
func (HOST008) DefaultSeverity() contracts.Severity { return host008Meta.DefaultSeverity() }
func (HOST008) Sources() []SourceID                 { return host008Meta.Sources() }
func (HOST008) SelfTestCases() []string             { return host008Meta.SelfTestCases() }

// Evaluate: WARNING when NetworkManager would join a known network of the baseline by itself.
// Only the matched baseline fields are reported, never the SSID or the connection name.
func (HOST008) Evaluate(nm dbusmon.NM, k Known) []Finding {
	var matched []any
	n := 0
	for _, c := range nm.Connections {
		if field, ok := k.SSIDs[c.SSID]; ok && c.SSID != "" && c.Autoconnect {
			n++
			matched = appendUnique(matched, field)
		}
	}
	if n == 0 {
		return nil
	}
	return []Finding{{Check: "HOST-008", Severity: contracts.SeverityWarning, Data: map[string]any{"connections": n, "matched": matched}}}
}

func appendUnique(xs []any, x string) []any {
	for _, y := range xs {
		if y == x {
			return xs
		}
	}
	return append(xs, x)
}
