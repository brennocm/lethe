package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

// NET006 is "new interface or link up" (spec §9.1).
type NET006 struct{}

func (NET006) ID() string { return "NET-006" }

var net006Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcNetlink}, st: []string{"ST-NET-006"}}

func (NET006) Kind() Kind                          { return net006Meta.Kind() }
func (NET006) DefaultSeverity() contracts.Severity { return net006Meta.DefaultSeverity() }
func (NET006) Sources() []SourceID                 { return net006Meta.Sources() }
func (NET006) SelfTestCases() []string             { return net006Meta.SelfTestCases() }

// LinkChange is one RTM_NEWLINK seen by netlinkmon, already classified (§7.2).
type LinkChange struct {
	Name  string
	New   bool // first time this ifindex is seen in the session
	Up    bool
	WasUp bool
	Class discovery.Class
}

// Evaluate: a new link or a down→up transition is WARNING on egress/unknown, INFO otherwise.
func (NET006) Evaluate(c LinkChange) []Finding {
	cameUp := c.Up && !c.WasUp
	if c.Class == discovery.ClassLoopback || (!c.New && !cameUp) {
		return nil
	}
	sev := contracts.SeverityInfo
	if leaky(c.Class) {
		sev = contracts.SeverityWarning
	}
	event := "link_up"
	if c.New {
		event = "new_link"
	}
	return []Finding{{Check: "NET-006", Severity: sev,
		Data: map[string]any{"iface": c.Name, "class": string(c.Class), "event": event}}}
}
