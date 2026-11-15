package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/sensors/nftmon"
)

// TUN004 is "kill switch changed" (spec §9.3).
type TUN004 struct{}

func (TUN004) ID() string { return "TUN-004" }

var tun004Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcNFTMon}, st: []string{"ST-TUN-004"}}

func (TUN004) Kind() Kind                          { return tun004Meta.Kind() }
func (TUN004) DefaultSeverity() contracts.Severity { return tun004Meta.DefaultSeverity() }
func (TUN004) Sources() []SourceID                 { return tun004Meta.Sources() }
func (TUN004) SelfTestCases() []string             { return tun004Meta.SelfTestCases() }

// Evaluate compares the third-party tables with the snapshot taken at arm: a table added,
// changed or removed is WARNING; a removed table that dropped in the output hook (a kill switch)
// is CRITICAL. Only table names go in the data, never rule contents.
func (TUN004) Evaluate(atArm, now []nftmon.Table) []Finding {
	cur := map[string]nftmon.Table{}
	for _, t := range now {
		cur[t.Name] = t
	}
	was := map[string]bool{}
	var out []Finding
	add := func(sev contracts.Severity, name, reason string) {
		out = append(out, Finding{Check: "TUN-004", Severity: sev, Data: map[string]any{"table": name, "reason": reason}})
	}
	for _, b := range atArm {
		was[b.Name] = true
		c, ok := cur[b.Name]
		switch {
		case !ok && b.OutputDrop:
			add(contracts.SeverityCritical, b.Name, "killswitch_removed")
		case !ok:
			add(contracts.SeverityWarning, b.Name, "removed")
		case c.Hash != b.Hash:
			add(contracts.SeverityWarning, b.Name, "changed")
		}
	}
	for _, c := range now {
		if !was[c.Name] {
			add(contracts.SeverityWarning, c.Name, "added")
		}
	}
	return out
}
