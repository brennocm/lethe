package engine

import "lethe/internal/contracts"

// GuardMode is the nftables guard submode (spec §11.1).
type GuardMode string

const (
	GuardOff      GuardMode = "off"
	GuardReactive GuardMode = "reactive"
	GuardStrict   GuardMode = "strict"
)

// Action is a response action (spec §10.3).
type Action string

const (
	ActAlertTray       Action = "alert_tray"
	ActAlertSound      Action = "alert_sound"
	ActAlertFullscreen Action = "alert_fullscreen"
	ActBlockAll        Action = "block_all"
	ActKillProcesses   Action = "kill_processes"
	ActKillOffender    Action = "kill_offender"
	ActLinkDown        Action = "link_down"
	ActLockScreen      Action = "lock_screen"
)

// Override changes the severity and/or actions of one check (profile "overrides").
type Override struct {
	Severity contracts.Severity // empty = keep the check's severity
	Actions  []Action           // nil = default plan for the severity; empty slice = no actions
}

// DefaultActions is the response table of spec §10.4.
func DefaultActions(sev contracts.Severity, mode GuardMode) []Action {
	switch sev {
	case contracts.SeverityWarning:
		return []Action{ActAlertTray, ActAlertSound}
	case contracts.SeverityCritical:
		if mode == GuardReactive || mode == GuardStrict {
			return []Action{ActBlockAll, ActKillProcesses, ActAlertFullscreen, ActAlertSound}
		}
		return []Action{ActAlertFullscreen, ActAlertSound}
	default:
		return nil
	}
}

// EffectiveSeverity applies an override to the severity a check emitted. A check that emits
// CRITICAL can never be lowered below WARNING unless allowDowngrade is set (spec §5.4).
func EffectiveSeverity(emitted contracts.Severity, ov Override, allowDowngrade bool) contracts.Severity {
	if !ov.Severity.Valid() {
		return emitted
	}
	if emitted == contracts.SeverityCritical && !allowDowngrade && ov.Severity.Rank() < contracts.SeverityWarning.Rank() {
		return contracts.SeverityWarning
	}
	return ov.Severity
}

func planFor(sev contracts.Severity, mode GuardMode, ov Override) []Action {
	if ov.Actions != nil {
		return append([]Action(nil), ov.Actions...)
	}
	return DefaultActions(sev, mode)
}
