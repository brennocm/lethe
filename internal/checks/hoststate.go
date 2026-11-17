package checks

import (
	"time"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/profile"
	"lethe/internal/sensors/hostinfo"
)

// HostInput is what EvaluateHost needs besides the host state.
type HostInput struct {
	State           hostinfo.State
	Snapshot        *discovery.Snapshot
	Deny            []DenyRule
	Persona         Persona
	PersonaProfiles []string
	Known           Known
	Now             time.Time
	// AgentKeyboard is the layout the session agent reported ("" = none: use the system's).
	AgentKeyboard string
}

// HostChecks are the checks EvaluateHost answers, in report order.
var HostChecks = []string{
	"NET-008", "NET-013", "NET-014",
	"HOST-001", "HOST-002", "HOST-003", "HOST-004", "HOST-005", "HOST-006", "HOST-007", "HOST-008", "HOST-009",
	"PER-001", "PER-002", "PER-003", "SELF-004",
}

// EvaluateHost runs every host-level check over one reading. Checks whose source was not read
// (no system bus) are absent from the result, so they are neither reported nor resolved.
func EvaluateHost(in HostInput) map[string][]Finding {
	st := in.State
	out := map[string][]Finding{
		"HOST-001": HOST001{}.Evaluate(st.Procs, in.Deny),
		"HOST-002": HOST002{}.Evaluate(st.Procs),
		"HOST-003": HOST003{}.Evaluate(st.Procs),
		"HOST-004": HOST004{}.Evaluate(st.Facts.Hostname, in.Known),
		"HOST-005": HOST005{}.Evaluate(st.Timezone(), st.Locale(), in.Persona),
		"HOST-006": HOST006{}.Evaluate(st.Facts.RootEncrypted, st.Facts.PlainSwap),
		"HOST-007": HOST007{}.Evaluate(st.Facts.TimeSync),
		"PER-002":  PER002{}.Evaluate(st.Prefs, st.Chromium),
		"PER-003":  PER003{}.Evaluate(st.Procs, in.PersonaProfiles),
		"SELF-004": SELF004{}.Evaluate(st.Selftest.FinishedAt, st.Selftest.Passed, st.Selftest.Critical, in.Now),
	}
	if in.AgentKeyboard == "" {
		out["PER-001"] = PER001{}.Evaluate(st.Keyboard(), false, in.Persona)
	}
	if in.Snapshot != nil {
		out["NET-008"] = NET008{}.Evaluate(in.Snapshot)
	}
	if st.BusRead {
		out["NET-013"] = NET013{}.Evaluate(st.Bus.NM)
		out["NET-014"] = NET014{}.Evaluate(st.Bus.NM, in.Known)
		out["HOST-008"] = HOST008{}.Evaluate(st.Bus.NM, in.Known)
		out["HOST-009"] = HOST009{}.Evaluate(st.Bus.GeoClue)
	}
	return out
}

// HostRules takes the host-check settings of a profile into a HostInput (nil = defaults).
func HostRules(p *profile.Profile, in HostInput) HostInput {
	if p == nil {
		return in
	}
	for _, d := range p.Processes.Deny {
		in.Deny = append(in.Deny, DenyRule{Match: d.Match, Value: d.Value, Severity: contracts.Severity(d.Severity)})
	}
	in.Persona = Persona{Timezone: p.Expect.Timezone, Locale: p.Expect.Locale, Keyboard: p.Expect.Keyboard}
	in.PersonaProfiles = p.Browsers.PersonaProfiles
	return in
}
