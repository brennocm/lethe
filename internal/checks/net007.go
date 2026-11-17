package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/sensors/dbusmon"
)

// NET007 is "Wi-Fi network change" (spec §9.1).
type NET007 struct{}

func (NET007) ID() string { return "NET-007" }

var net007Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcDBus}}

func (NET007) Kind() Kind                          { return net007Meta.Kind() }
func (NET007) DefaultSeverity() contracts.Severity { return net007Meta.DefaultSeverity() }
func (NET007) Sources() []SourceID                 { return net007Meta.Sources() }
func (NET007) SelfTestCases() []string             { return net007Meta.SelfTestCases() }

// Evaluate: per wireless interface, WARNING when the SSID or BSSID differs from the arm, and
// CRITICAL when the new SSID is a known network of the baseline.
func (NET007) Evaluate(atArm, now []dbusmon.WiFi, k Known) []Finding {
	before := map[string]dbusmon.WiFi{}
	for _, w := range atArm {
		before[w.Iface] = w
	}
	var out []Finding
	for _, w := range now {
		b, seen := before[w.Iface]
		if seen && b.SSID == w.SSID && b.BSSID == w.BSSID {
			continue
		}
		d := map[string]any{"iface": w.Iface, "ssid_changed": !seen || b.SSID != w.SSID}
		sev := contracts.SeverityWarning
		if field, ok := k.SSIDs[w.SSID]; ok && w.SSID != "" {
			sev = contracts.SeverityCritical
			d["matched"] = field
		}
		out = append(out, Finding{Check: "NET-007", Severity: sev, Data: d})
	}
	return out
}
