// Package response executes the response actions of spec §10.3. Network and process actions
// run in the daemon; alert_* actions are delegated to the agent/GUI through IPC events.
package response

import (
	"errors"
	"fmt"
	"syscall"
	"time"

	"lethe/internal/contracts"
	"lethe/internal/engine"
	"lethe/internal/guard"
	"lethe/internal/sensors/procscan"
)

// Result is one executed action; it becomes a response.executed event.
type Result struct {
	Action    engine.Action
	OK        bool
	Err       string
	Latency   time.Duration
	Count     int  // processes killed / links downed
	Delegated bool // alert_*: handed to the agent/GUI
}

// Event builds the response.executed event for r (data has no baseline values).
func (r Result) Event(alertID string) contracts.Event {
	d := map[string]any{"action": string(r.Action), "ok": r.OK, "latency_ms": float64(r.Latency.Microseconds()) / 1000}
	if r.Err != "" {
		d["error"] = r.Err
	}
	if r.Count > 0 {
		d["count"] = r.Count
	}
	if r.Delegated {
		d["delegated"] = true
	}
	return contracts.Event{V: 1, Type: contracts.EvResponseExecuted, Source: contracts.SourceDaemon, AlertID: alertID, Data: d}
}

// Env is what the executor touches; every field is injectable for tests.
type Env struct {
	Guard       func() (guard.Conn, error)
	GuardConfig func() guard.Config
	ProcRoot    string
	KillOnPanic []procscan.Matcher
	Egress      func() []string
	LinkDown    func(iface string) error
	LockScreen  func() error
	Kill        func(pid int) error // default: SIGKILL
	Protected   map[int]bool        // never killed (self, agent, pid 1)
	Now         func() time.Time
	// LinkDownMode is guard.panic.link_down: auto | always | never.
	LinkDownMode string
}

// Executor runs actions.
type Executor struct{ env Env }

// New builds an executor.
func New(env Env) *Executor {
	if env.Kill == nil {
		env.Kill = func(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Protected == nil {
		env.Protected = map[int]bool{}
	}
	env.Protected[1] = true
	return &Executor{env: env}
}

// Run executes a for the event ev (ev carries the attributed process for kill_offender).
func (x *Executor) Run(a engine.Action, ev contracts.Event) Result {
	start := x.env.Now()
	r := Result{Action: a}
	var err error
	switch a {
	case engine.ActAlertTray, engine.ActAlertSound, engine.ActAlertFullscreen:
		r.Delegated = true
	case engine.ActBlockAll:
		err = x.blockAll(&r)
	case engine.ActKillProcesses:
		r.Count, err = x.killMatching()
	case engine.ActKillOffender:
		r.Count, err = x.killOffender(ev)
	case engine.ActLinkDown:
		r.Count, err = x.linkDown()
	case engine.ActLockScreen:
		if x.env.LockScreen == nil {
			err = errors.New("lock_screen unavailable")
		} else {
			err = x.env.LockScreen()
		}
	default:
		err = fmt.Errorf("unknown action %q", a)
	}
	r.Latency = x.env.Now().Sub(start)
	r.OK = err == nil
	if err != nil {
		r.Err = err.Error()
	}
	return r
}

// BlockAll applies the panic tables (and link_down when the L2 layer is missing, or always).
func (x *Executor) blockAll(r *Result) error {
	cfg := x.env.GuardConfig()
	rs, err := guard.Panic(cfg)
	if err != nil {
		return err
	}
	c, err := x.env.Guard()
	if err != nil {
		return err
	}
	applyErr := guard.Apply(c, rs)
	if x.env.LinkDownMode == "always" || (x.env.LinkDownMode != "never" && !cfg.L2) {
		n, lerr := x.linkDown()
		r.Count = n
		applyErr = errors.Join(applyErr, lerr)
	}
	return applyErr
}

func (x *Executor) killMatching() (int, error) {
	if len(x.env.KillOnPanic) == 0 {
		return 0, nil
	}
	ps, err := procscan.List(x.env.ProcRoot)
	if err != nil {
		return 0, err
	}
	n := 0
	var errs []error
	for _, p := range ps {
		if x.env.Protected[p.PID] {
			continue
		}
		for _, m := range x.env.KillOnPanic {
			if m.Matches(p) {
				if err := x.env.Kill(p.PID); err != nil && !errors.Is(err, syscall.ESRCH) {
					errs = append(errs, fmt.Errorf("pid %d: %w", p.PID, err))
				} else {
					n++
				}
				break
			}
		}
	}
	return n, errors.Join(errs...)
}

func (x *Executor) killOffender(ev contracts.Event) (int, error) {
	var p contracts.Proc
	switch v := ev.Data["proc"].(type) {
	case contracts.Proc:
		p = v
	case *contracts.Proc:
		if v != nil {
			p = *v
		}
	}
	if p.Confidence != contracts.ConfidenceHigh || p.PID <= 0 {
		return 0, errors.New("no process attributed with high confidence")
	}
	if x.env.Protected[p.PID] {
		return 0, fmt.Errorf("pid %d is protected", p.PID)
	}
	if err := x.env.Kill(p.PID); err != nil {
		return 0, err
	}
	return 1, nil
}

func (x *Executor) linkDown() (int, error) {
	if x.env.LinkDown == nil || x.env.Egress == nil {
		return 0, errors.New("link_down unavailable")
	}
	n := 0
	var errs []error
	for _, i := range x.env.Egress() {
		if err := x.env.LinkDown(i); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", i, err))
			continue
		}
		n++
	}
	return n, errors.Join(errs...)
}
