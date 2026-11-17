// Package response executes the response actions of spec §10.3. Network and process actions
// run in the daemon; alert_* actions are delegated to the agent/GUI through IPC events.
package response

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

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
	// KillUID is the only UID whose processes may be killed: the operator's. Root's and the
	// system services' processes are never killed (a leak by them is contained by the block, and
	// in service mode the profile, which names what to kill, comes from a non-root operator).
	KillUID int
	// Kill sends SIGKILL to pid if it still runs exe and belongs to uid. Default: KillVerified.
	Kill      func(pid int, exe string, uid int) error
	Protected map[int]bool // never killed (self, agent, pid 1)
	Now       func() time.Time
	// LinkDownMode is guard.panic.link_down: auto | always | never.
	LinkDownMode string
}

// Executor runs actions.
type Executor struct{ env Env }

// New builds an executor.
func New(env Env) *Executor {
	if env.Kill == nil {
		procRoot := env.ProcRoot
		if procRoot == "" {
			procRoot = "/proc"
		}
		env.Kill = func(pid int, exe string, uid int) error { return KillVerified(procRoot, pid, exe, uid) }
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
		if x.env.Protected[p.PID] || p.UID != x.env.KillUID {
			continue
		}
		for _, m := range x.env.KillOnPanic {
			if m.Matches(p) {
				if err := x.env.Kill(p.PID, p.Exe, p.UID); err != nil && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, ErrPIDReused) {
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
	if p.UID != x.env.KillUID {
		return 0, fmt.Errorf("pid %d belongs to uid %d, not the operator: not killed (the block contains it)", p.PID, p.UID)
	}
	if err := x.env.Kill(p.PID, p.Exe, p.UID); err != nil {
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

// ErrPIDReused: the pid now runs another executable (or belongs to another user) than the one
// attributed or matched.
var ErrPIDReused = errors.New("pid now belongs to another executable or user; not killed")

// KillVerified kills pid only if it still runs exe and its real UID is uid. Between the
// attribution (or the /proc scan) and the kill the process may have exited and its pid been
// reused; the root daemon must not SIGKILL a bystander. A pidfd pins the process, so the checks
// and the signal see the same one.
func KillVerified(procRoot string, pid int, exe string, uid int) error {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if got, err := realUID(procRoot, pid); err != nil {
		return err
	} else if got != uid {
		return ErrPIDReused
	}
	if exe != "" {
		cur, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
		if err != nil {
			return err
		}
		if strings.TrimSuffix(cur, " (deleted)") != strings.TrimSuffix(exe, " (deleted)") {
			return ErrPIDReused
		}
	}
	return unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
}

// realUID reads the real UID of pid from /proc/<pid>/status.
func realUID(procRoot string, pid int) (int, error) {
	b, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status")) // #nosec G304 -- procfs
	if err != nil {
		return -1, err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
			if f := strings.Fields(rest); len(f) > 0 {
				return strconv.Atoi(f[0])
			}
		}
	}
	return -1, errors.New("no Uid line in status")
}
