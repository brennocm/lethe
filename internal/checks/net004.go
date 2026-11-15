package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

// NET004 is "effective route outside the tunnel" (spec §9.1): the route the kernel picks for
// 192.0.2.1 and 2001:db8::1 (no mark) must leave through a tunnel interface.
type NET004 struct{}

func (NET004) ID() string { return "NET-004" }

var net004Meta = meta{kind: Passive, sev: contracts.SeverityCritical, sources: []SourceID{SrcNetlink}}

func (NET004) Kind() Kind                          { return net004Meta.Kind() }
func (NET004) DefaultSeverity() contracts.Severity { return net004Meta.DefaultSeverity() }
func (NET004) Sources() []SourceID                 { return net004Meta.Sources() }
func (NET004) SelfTestCases() []string             { return net004Meta.SelfTestCases() }

// Evaluate reports each probe whose route exists and is not through a tunnel. A missing
// route (unreachable) is not a leak.
func (NET004) Evaluate(s *discovery.Snapshot) []Finding {
	var out []Finding
	for _, p := range []struct {
		family string
		r      *discovery.Route
	}{{"ipv4", s.Routes.ProbeV4}, {"ipv6", s.Routes.ProbeV6}} {
		if p.r == nil || p.r.Class == discovery.ClassTunnel {
			continue
		}
		out = append(out, Finding{Check: "NET-004", Severity: contracts.SeverityCritical,
			Data: map[string]any{"iface": p.r.Iface, "family": p.family, "class": string(p.r.Class)}})
	}
	return out
}
