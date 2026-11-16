package engine

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"lethe/internal/contracts"
)

// Color is the global state while armed (spec §6.1).
type Color string

const (
	ColorGreen  Color = "GREEN"
	ColorYellow Color = "YELLOW"
	ColorRed    Color = "RED"
	ColorGray   Color = "GRAY"
)

// Config is the part of the profile the engine needs.
type Config struct {
	Guard          GuardMode
	Overrides      map[string]Override
	AllowDowngrade bool
}

// Decision is what the engine concluded from one event.
type Decision struct {
	Alert        *Alert   // alert opened or updated (nil if the event did not touch an alert)
	New          bool     // a new alert was opened
	Escalated    bool     // an existing alert's severity was raised
	Actions      []Action // responses to execute now (empty when deduplicated)
	DryRun       bool     // selftest: report the plan, execute nothing
	EnteredPanic bool     // the session moved to PANIC because of this event
}

// Errors returned by engine operations.
var (
	ErrUnknownAlert    = errors.New("unknown alert")
	ErrReasonRequired  = errors.New("a reason is required to acknowledge a CRITICAL alert")
	ErrNotAuthorized   = errors.New("this action requires passphrase authorization")
	ErrUnackedCritical = errors.New("unacknowledged CRITICAL alerts remain")
	ErrRecheckFailed   = errors.New("state re-check did not pass")
)

// Engine is not safe for concurrent use; the daemon serializes calls through one goroutine.
type Engine struct {
	clock   Clock
	cfg     Config
	session SessionState
	alerts  []*Alert
	nextID  int
	// compacted counts resolved alerts dropped to keep the list bounded (MaxAlerts)
	compacted int
	down      map[string]bool // sensor sources currently down
	degrade   map[string]bool // other visibility gaps (e.g. "tunnel_unknown")
}

// New creates an engine in the given initial session state.
func New(clock Clock, cfg Config, initial SessionState) *Engine {
	if cfg.Guard == "" {
		cfg.Guard = GuardOff
	}
	return &Engine{clock: clock, cfg: cfg, session: initial, nextID: 1, down: map[string]bool{}, degrade: map[string]bool{}}
}

// Session returns the current session state.
func (e *Engine) Session() SessionState { return e.session }

// Apply runs a session command that has no extra preconditions (everything except unpanic).
func (e *Engine) Apply(cmd Command) (SessionState, error) {
	if cmd == CmdUnpanic {
		return e.session, errors.New("use Unpanic for the unpanic command")
	}
	to, err := Next(e.session, cmd)
	if err != nil {
		return e.session, err
	}
	if cmd == CmdArm || cmd == CmdArmForce {
		e.alerts, e.nextID, e.compacted = nil, 1, 0 // a new session starts with a clean alert list
		delete(e.degrade, "alert_overflow")
	}
	e.session = to
	return to, nil
}

// Unpanic leaves PANIC only when every CRITICAL alert of the session was acknowledged, the state
// re-check passed and the caller proved the passphrase (spec §10.5).
func (e *Engine) Unpanic(recheckPassed, authorized bool) error {
	if _, err := Next(e.session, CmdUnpanic); err != nil {
		return err
	}
	if !authorized {
		return ErrNotAuthorized
	}
	for _, a := range e.alerts {
		if a.Severity == contracts.SeverityCritical && !a.Acked {
			return fmt.Errorf("%w: %s (%s)", ErrUnackedCritical, a.ID, a.Check)
		}
	}
	if !recheckPassed {
		return ErrRecheckFailed
	}
	e.session = StateArmed
	return nil
}

// Observe feeds one event to the engine.
func (e *Engine) Observe(ev contracts.Event) Decision {
	switch ev.Type {
	case contracts.EvCheckAlert:
		return e.observeAlert(ev)
	case contracts.EvCheckResolved:
		e.observeResolved(ev)
	case contracts.EvSensorDown:
		if s := ev.Str("source"); s != "" {
			e.down[s] = true
		}
	case contracts.EvSensorUp:
		delete(e.down, ev.Str("source"))
	case contracts.EvDiscoveryEndpointUnknown:
		e.degrade["tunnel_unknown"] = true
	case contracts.EvDiscoveryEndpointConfirm, contracts.EvDiscoveryEndpointChanged, contracts.EvDiscoveryEndpointLearned:
		delete(e.degrade, "tunnel_unknown")
	}
	return Decision{}
}

func (e *Engine) observeAlert(ev contracts.Event) Decision {
	ov := e.cfg.Overrides[ev.Check]
	sev := EffectiveSeverity(ev.Severity, ov, e.cfg.AllowDowngrade)
	if !sev.Valid() {
		sev = contracts.SeverityWarning // malformed severity: fail toward attention
	}
	if ev.Selftest || ev.Source == contracts.SourceSelftest {
		return Decision{Actions: planFor(sev, e.cfg.Guard, ov), DryRun: true}
	}
	now := e.clock.Now()
	key := DedupKey(ev)

	if a := e.findOpen(key); a != nil {
		a.Count++
		a.LastSeen = now
		a.clearSince = time.Time{}
		if sev.Rank() <= a.Severity.Rank() {
			return Decision{Alert: a} // deduplicated: no new actions
		}
		a.Severity = sev // only ever raised, never lowered (principle 9)
		return e.withActions(Decision{Alert: a, Escalated: true}, sev, ov)
	}

	if !e.makeRoom() {
		// Full of alerts that still matter: every new key of this check joins one overflow
		// alert, so a flood of distinct destinations still counts and still raises the color.
		key = ev.Check + "|overflow"
		e.degrade["alert_overflow"] = true
		if a := e.findOpen(key); a != nil {
			a.Count++
			a.LastSeen = now
			if sev.Rank() <= a.Severity.Rank() {
				return Decision{Alert: a}
			}
			a.Severity = sev
			return e.withActions(Decision{Alert: a, Escalated: true}, sev, ov)
		}
	}
	a := &Alert{
		ID: formatAlertID(e.nextID), Check: ev.Check, Severity: sev, Key: key, State: AlertOpen,
		Count: 1, FirstSeen: now, LastSeen: now, Source: ev.Source,
	}
	e.nextID++
	e.alerts = append(e.alerts, a)
	return e.withActions(Decision{Alert: a, New: true}, sev, ov)
}

// MaxAlerts bounds the alert list of one session. Distinct destinations each open an alert, so
// without a bound a long session could grow without limit. Past the cap, each check gets at most
// one overflow alert, so the list never exceeds MaxAlerts plus the number of checks.
const MaxAlerts = 1024

// makeRoom keeps the list under MaxAlerts by dropping the oldest alerts that no longer matter:
// resolved and either acknowledged or below CRITICAL. A resolved CRITICAL that was never
// acknowledged still blocks unpanic, so it is kept. It reports whether a new alert fits.
func (e *Engine) makeRoom() bool {
	if len(e.alerts) < MaxAlerts {
		return true
	}
	kept := e.alerts[:0]
	excess := len(e.alerts) - MaxAlerts + 1
	for _, a := range e.alerts {
		if excess > 0 && a.State == AlertResolved && (a.Acked || a.Severity != contracts.SeverityCritical) {
			excess--
			e.compacted++
			continue
		}
		kept = append(kept, a)
	}
	for i := len(kept); i < len(e.alerts); i++ {
		e.alerts[i] = nil
	}
	e.alerts = kept
	return len(e.alerts) < MaxAlerts
}

// Compacted is the number of resolved alerts dropped from the list by makeRoom.
func (e *Engine) Compacted() int { return e.compacted }

func (e *Engine) withActions(d Decision, sev contracts.Severity, ov Override) Decision {
	acts := planFor(sev, e.cfg.Guard, ov)
	hasBlock := false
	for _, a := range acts {
		if a == ActBlockAll {
			hasBlock = true
		}
	}
	switch {
	case hasBlock && e.session == StateArmed:
		e.session = StatePanic
		d.EnteredPanic = true
	case hasBlock && e.session == StatePanic:
		acts = without(acts, ActBlockAll) // already blocked
	}
	d.Actions = acts
	return d
}

func without(acts []Action, drop Action) []Action {
	out := acts[:0:0]
	for _, a := range acts {
		if a != drop {
			out = append(out, a)
		}
	}
	return out
}

// findOpen returns the alert that absorbs a new occurrence of key. A point check that recurs
// after its ack opens a new alert: the operator must see a repeated leak again. A condition that
// is still present after its ack is the same condition, so it stays in the acknowledged alert
// until it resolves.
func (e *Engine) findOpen(key string) *Alert {
	for i := len(e.alerts) - 1; i >= 0; i-- {
		a := e.alerts[i]
		if a.Key != key {
			continue
		}
		if a.State == AlertOpen || (a.State == AlertAcknowledged && !IsPointCheck(a.Check)) {
			return a
		}
	}
	return nil
}

func (e *Engine) observeResolved(ev contracts.Event) {
	if ev.Source == contracts.SourceAgent {
		return // low-trust source may raise, never clear (principle 9)
	}
	now := e.clock.Now()
	byKey := len(ev.Data) > 0
	key := DedupKey(ev)
	for _, a := range e.alerts {
		if a.Check != ev.Check || !a.Unresolved() || IsPointCheck(a.Check) {
			continue
		}
		if byKey && a.Key != key {
			continue
		}
		if a.clearSince.IsZero() {
			a.clearSince = now
		}
	}
}

// Tick resolves alerts whose resolution window elapsed and returns them.
func (e *Engine) Tick() []*Alert {
	now := e.clock.Now()
	var resolved []*Alert
	for _, a := range e.alerts {
		if !a.Unresolved() {
			continue
		}
		point := IsPointCheck(a.Check) && now.Sub(a.LastSeen) >= resolveWindow
		cond := !IsPointCheck(a.Check) && !a.clearSince.IsZero() && now.Sub(a.clearSince) >= resolveWindow
		if point || cond {
			a.State, a.ResolvedAt = AlertResolved, now
			resolved = append(resolved, a)
		}
	}
	return resolved
}

// Ack acknowledges an alert. CRITICAL alerts need a reason and passphrase authorization.
func (e *Engine) Ack(id, reason string, authorized bool) (*Alert, error) {
	a := e.Alert(id)
	if a == nil {
		return nil, fmt.Errorf("%w: %s", ErrUnknownAlert, id)
	}
	if a.Severity == contracts.SeverityCritical {
		if reason == "" {
			return nil, ErrReasonRequired
		}
		if !authorized {
			return nil, ErrNotAuthorized
		}
	}
	a.Acked, a.AckReason = true, reason
	if a.State == AlertOpen {
		a.State = AlertAcknowledged
	}
	return a, nil
}

// Alert returns the alert with this ID, or nil.
func (e *Engine) Alert(id string) *Alert {
	for _, a := range e.alerts {
		if a.ID == id {
			return a
		}
	}
	return nil
}

// Alerts returns every alert of the session, oldest first.
func (e *Engine) Alerts() []*Alert { return append([]*Alert(nil), e.alerts...) }

// Degraded lists the current visibility gaps (sensor sources down and other reasons), sorted.
func (e *Engine) Degraded() []string {
	var out []string
	for s := range e.down {
		out = append(out, "sensor:"+s)
	}
	for r := range e.degrade {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// Color computes the global color: RED > GRAY > YELLOW > GREEN.
func (e *Engine) Color() Color {
	var crit, warn bool
	for _, a := range e.alerts {
		if !a.Unresolved() {
			continue
		}
		switch a.Severity {
		case contracts.SeverityCritical:
			crit = true
		case contracts.SeverityWarning:
			warn = true
		}
	}
	switch {
	case crit:
		return ColorRed
	case len(e.down) > 0 || len(e.degrade) > 0:
		return ColorGray
	case warn:
		return ColorYellow
	default:
		return ColorGreen
	}
}
