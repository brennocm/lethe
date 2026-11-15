package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/sensors/capture"
)

// NET001 is "traffic outside the tunnel" (spec §8, §9.1): every frame the capture filter
// delivers. FromFrame also produces DNS-001, NET-009 and NET-012 (subclassifications, §8.3).
type NET001 struct{}

func (NET001) ID() string { return "NET-001" }

var net001Meta = meta{kind: Passive, sev: contracts.SeverityCritical, sources: []SourceID{SrcCapture}, st: []string{"ST-NET-001", "ST-NET-003"}}

func (NET001) Kind() Kind                          { return net001Meta.Kind() }
func (NET001) DefaultSeverity() contracts.Severity { return net001Meta.DefaultSeverity() }
func (NET001) Sources() []SourceID                 { return net001Meta.Sources() }
func (NET001) SelfTestCases() []string             { return net001Meta.SelfTestCases() }

// FromFrame turns a delivered frame plus its attribution (NET-010) into a finding.
func FromFrame(f capture.Frame, proc contracts.Proc) Finding {
	d := f.Leak.Data()
	d["iface"] = f.Iface
	if proc.Confidence != "" {
		d["proc"] = proc
	}
	out := Finding{Check: f.Leak.Check, Severity: f.Leak.Severity, Data: d}
	if f.Leak.QName != "" {
		out.Sensitive = map[string]string{"qname": f.Leak.QName}
	}
	return out
}
