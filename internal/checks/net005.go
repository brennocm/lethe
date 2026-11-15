package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/sensors/netlinkmon"
)

// NET005 is "route or policy routing change" (spec §9.1).
type NET005 struct{}

func (NET005) ID() string { return "NET-005" }

var net005Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcNetlink}}

func (NET005) Kind() Kind                          { return net005Meta.Kind() }
func (NET005) DefaultSeverity() contracts.Severity { return net005Meta.DefaultSeverity() }
func (NET005) Sources() []SourceID                 { return net005Meta.Sources() }
func (NET005) SelfTestCases() []string             { return net005Meta.SelfTestCases() }

// RouteChange is the netlinkmon event NET-005 evaluates.
type RouteChange = netlinkmon.RouteChange

const (
	tableLocal = 255 // kernel-managed local/broadcast routes (follow address changes)
)

// Evaluate ignores changes in the tunnel's own tables, on tunnel interfaces, in the local
// table, and rules keyed on a tunnel fwmark; anything else is a WARNING.
func (NET005) Evaluate(c RouteChange, s *discovery.Snapshot) []Finding {
	if c.Table == tableLocal {
		return nil
	}
	for _, t := range s.Tunnels {
		if t.FwMark != 0 && (c.Table == t.FwMark || (c.Kind == "rule" && c.Mark == uint32(t.FwMark))) { // #nosec G115 -- fwmark is u32 in the kernel
			return nil
		}
	}
	if c.Kind == "route" {
		if i, ok := s.Iface(c.Iface); ok && (i.Class == discovery.ClassTunnel || i.Class == discovery.ClassLoopback) {
			return nil
		}
	}
	d := map[string]any{"kind": c.Kind, "op": c.Op, "family": c.Family, "table": c.Table}
	if c.Kind == "route" {
		d["iface"], d["dst"] = c.Iface, c.Dst
	}
	return []Finding{{Check: "NET-005", Severity: contracts.SeverityWarning, Data: d}}
}
