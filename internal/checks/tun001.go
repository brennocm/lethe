package checks

import (
	"sort"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

// TUN001 is "tunnel missing or down" (spec §9.3).
type TUN001 struct{}

func (TUN001) ID() string { return "TUN-001" }

var tun001Meta = meta{kind: Passive, sev: contracts.SeverityCritical, sources: []SourceID{SrcNetlink}}

func (TUN001) Kind() Kind                          { return tun001Meta.Kind() }
func (TUN001) DefaultSeverity() contracts.Severity { return tun001Meta.DefaultSeverity() }
func (TUN001) Sources() []SourceID                 { return tun001Meta.Sources() }
func (TUN001) SelfTestCases() []string             { return tun001Meta.SelfTestCases() }

// TunnelExpect says which tunnels must be present.
type TunnelExpect struct {
	Ifaces  []string // tunnels seen since arm (the set only grows within a session)
	Require bool     // egress.type needs a tunnel interface (everything but tor)
}

// RequiresTunnel reports whether egress.type needs a tunnel interface: everything but tor, and
// "auto" only when tor is not in use.
func RequiresTunnel(egressType string, torInUse bool) bool {
	return egressType != "tor" && (egressType != "auto" || !torInUse)
}

// Evaluate: CRITICAL for every expected tunnel that is gone, down or without carrier, and for a
// session that needs a tunnel and has none.
func (TUN001) Evaluate(want TunnelExpect, s *discovery.Snapshot) []Finding {
	var out []Finding
	names := append([]string(nil), want.Ifaces...)
	sort.Strings(names)
	for _, n := range names {
		reason := ""
		switch i, ok := s.Iface(n); {
		case !ok:
			reason = "missing"
		case !i.Up:
			reason = "down"
		case !i.Running:
			reason = "not_running"
		}
		if reason != "" {
			out = append(out, Finding{Check: "TUN-001", Severity: contracts.SeverityCritical, Data: map[string]any{"iface": n, "reason": reason}})
		}
	}
	if len(names) == 0 && want.Require {
		out = append(out, Finding{Check: "TUN-001", Severity: contracts.SeverityCritical, Data: map[string]any{"reason": "no_tunnel"}})
	}
	return out
}
