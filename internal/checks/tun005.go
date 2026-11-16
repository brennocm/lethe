package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

// TUN005 is "split tunneling active" (spec §9.3).
type TUN005 struct{}

func (TUN005) ID() string { return "TUN-005" }

var tun005Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcNetlink}}

func (TUN005) Kind() Kind                          { return tun005Meta.Kind() }
func (TUN005) DefaultSeverity() contracts.Severity { return tun005Meta.DefaultSeverity() }
func (TUN005) Sources() []SourceID                 { return tun005Meta.Sources() }
func (TUN005) SelfTestCases() []string             { return tun005Meta.SelfTestCases() }

// Evaluate: WARNING for each policy rule that sends marked or per-UID traffic to a table whose
// default route is not a tunnel, and for each populated exclusion cgroup. Inverted rules ("not fwmark", wg-quick) and the tunnels' own
// transport marks are the normal full-tunnel setup and are left alone.
func (TUN005) Evaluate(s *discovery.Snapshot) []Finding {
	tunnelTable := map[int]bool{}
	for _, r := range append(append([]discovery.Route{}, s.Routes.DefaultV4...), s.Routes.DefaultV6...) {
		if r.Class == discovery.ClassTunnel {
			tunnelTable[r.Table] = true
		}
	}
	ownMark := map[uint32]bool{}
	for _, t := range s.Tunnels {
		if t.FwMark > 0 {
			ownMark[uint32(t.FwMark)] = true // #nosec G115 -- fwmark is u32
		}
	}
	var out []Finding
	for _, r := range s.Routes.Rules {
		if r.Invert || tunnelTable[r.Table] {
			continue
		}
		reason := ""
		switch {
		case r.UIDRange:
			reason = "uid_exclusion"
		case r.Mark != 0 && !ownMark[r.Mark]:
			reason = "fwmark_exclusion"
		default:
			continue
		}
		out = append(out, Finding{Check: "TUN-005", Severity: contracts.SeverityWarning,
			Data: map[string]any{"reason": reason, "family": r.Family, "table": r.Table, "priority": r.Priority}})
	}
	// Processes inside an exclusion cgroup leave outside the tunnel (net_cls classid marks, or a
	// client's own cgroup v2 matched by its nftables rules).
	for _, c := range s.Exclusions {
		out = append(out, Finding{Check: "TUN-005", Severity: contracts.SeverityWarning,
			Data: map[string]any{"reason": "cgroup_exclusion", "cgroup": c.Path, "cgroup_version": c.Version, "procs": c.Procs}})
	}
	return out
}
