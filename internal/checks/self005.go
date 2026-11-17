package checks

import (
	"time"

	"lethe/internal/contracts"
)

// SELF005 is "clock changed" (spec §9.6).
type SELF005 struct{}

func (SELF005) ID() string { return "SELF-005" }

var self005Meta = meta{kind: Passive, sev: contracts.SeverityInfo, sources: []SourceID{SrcClock}}

func (SELF005) Kind() Kind                          { return self005Meta.Kind() }
func (SELF005) DefaultSeverity() contracts.Severity { return self005Meta.DefaultSeverity() }
func (SELF005) Sources() []SourceID                 { return self005Meta.Sources() }
func (SELF005) SelfTestCases() []string             { return self005Meta.SelfTestCases() }

// ClockJump is the threshold between CLOCK_REALTIME and CLOCK_BOOTTIME.
const ClockJump = 2 * time.Second

// Evaluate compares two readings of (realtime − boottime): a difference above 2 s means the
// wall clock was set.
func (SELF005) Evaluate(prevOffset, offset time.Duration) []Finding {
	jump := offset - prevOffset
	if jump < ClockJump && jump > -ClockJump {
		return nil
	}
	return []Finding{{Check: "SELF-005", Severity: contracts.SeverityInfo, Data: map[string]any{"jump_ms": jump.Milliseconds()}}}
}
