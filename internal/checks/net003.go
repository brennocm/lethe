package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

// NET003 is "IPv6 outside the tunnel" (spec §9.1).
type NET003 struct{}

func (NET003) ID() string { return "NET-003" }

var net003Meta = meta{kind: Passive, sev: contracts.SeverityCritical, sources: []SourceID{SrcNetlink}, st: []string{"ST-NET-003"}}

func (NET003) Kind() Kind                          { return net003Meta.Kind() }
func (NET003) DefaultSeverity() contracts.Severity { return net003Meta.DefaultSeverity() }
func (NET003) Sources() []SourceID                 { return net003Meta.Sources() }
func (NET003) SelfTestCases() []string             { return net003Meta.SelfTestCases() }

func leaky(c discovery.Class) bool { return c == discovery.ClassEgress || c == discovery.ClassUnknown }

// Evaluate: CRITICAL for a default v6 route on an egress interface when the profile does not
// expect IPv6 or the tunnel has no default v6 route; WARNING for a global v6 address on an
// egress interface without such a route. One finding per interface.
func (NET003) Evaluate(s *discovery.Snapshot, expectIPv6 bool) []Finding {
	tunnelV6 := false
	for _, r := range s.Routes.DefaultV6 {
		if r.Class == discovery.ClassTunnel {
			tunnelV6 = true
		}
	}
	var out []Finding
	routed := map[string]bool{}
	for _, r := range s.Routes.DefaultV6 {
		if !leaky(r.Class) || routed[r.Iface] {
			continue
		}
		routed[r.Iface] = true
		if expectIPv6 && tunnelV6 {
			continue // the tunnel carries v6; the effective route is NET-004's business
		}
		reason := "default_route_ipv6_not_expected"
		if expectIPv6 {
			reason = "default_route_tunnel_without_ipv6"
		}
		out = append(out, Finding{Check: "NET-003", Severity: contracts.SeverityCritical,
			Data: map[string]any{"iface": r.Iface, "reason": reason}})
	}
	for _, i := range s.Ifaces {
		if !leaky(i.Class) || routed[i.Name] || i.IPv6Disabled || len(i.GlobalV6) == 0 {
			continue
		}
		out = append(out, Finding{Check: "NET-003", Severity: contracts.SeverityWarning,
			Data: map[string]any{"iface": i.Name, "reason": "global_address_without_route"}})
	}
	return out
}
