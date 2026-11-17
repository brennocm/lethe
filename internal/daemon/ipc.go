package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"lethe/internal/contracts"
	"lethe/internal/ipc"
	"lethe/internal/privsep"

	"golang.org/x/sys/unix"
)

// Status snapshots the daemon state.
func (d *Daemon) Status() Status {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := Status{State: string(d.eng.Session()), Color: string(d.colorLocked()), Alerts: []AlertView{}, Degraded: []string{}, Sensors: []SensorView{}, Agent: d.agent != nil}
	s := d.sess
	if s == nil {
		st.Lockdown = LeftoverLockdown(d.leftoverLocked(), true)
		return st
	}
	t := s.startedAt.UTC()
	st.Session, st.Fingerprint, st.Guard, st.StartedAt, st.AuthSalt = s.id, s.journal.Fingerprint(), string(s.guardMode), &t, s.salt
	for _, a := range d.eng.Alerts() {
		st.Alerts = append(st.Alerts, AlertView{ID: a.ID, Check: a.Check, Severity: string(a.Severity), State: string(a.State),
			Count: a.Count, FirstSeen: a.FirstSeen.UTC(), LastSeen: a.LastSeen.UTC(), Acked: a.Acked})
	}
	st.Degraded = append(st.Degraded, d.eng.Degraded()...)
	for src := range s.beats {
		st.Sensors = append(st.Sensors, SensorView{Source: src, Up: !s.down[src]})
	}
	sortSensors(st.Sensors)
	st.Confirming = s.confirming
	st.Lockdown = d.lockdownLocked()
	st.Exit = s.exit
	return st
}

// The IPC answers live in contracts (the GUI imports only contracts and ipc).
type (
	Status          = contracts.Status
	AlertView       = contracts.AlertView
	SensorView      = contracts.SensorView
	ExitView        = contracts.ExitView
	Lockdown        = contracts.Lockdown
	QueryParams     = contracts.QueryParams
	DisarmResult    = contracts.DisarmResult
	SelftestRequest = contracts.SelftestRequest
	CaseResult      = contracts.CaseResult
	SelftestResult  = contracts.SelftestResult
)

func sortSensors(v []SensorView) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j].Source < v[j-1].Source; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

func decode(c *ipc.Call, v any) error {
	if len(c.Req.Params) == 0 {
		return nil
	}
	if err := json.Unmarshal(c.Req.Params, v); err != nil {
		return errParams(err)
	}
	return nil
}

func matchQuery(q QueryParams, ev contracts.Event) bool {
	if q.Severity == "" {
		return true
	}
	return ev.Severity.Valid() && ev.Severity.Rank() >= contracts.Severity(q.Severity).Rank()
}

func (d *Daemon) routes() {
	h := d.srv.Handle
	h("auth.challenge", func(*ipc.Call) (any, error) {
		d.mu.Lock()
		s := d.sess
		d.mu.Unlock()
		if s == nil {
			return nil, errState(errNotArmed)
		}
		n, err := s.auth.Challenge()
		return map[string]any{"nonce": n}, err
	})
	h("status.get", func(*ipc.Call) (any, error) { return d.Status(), nil })
	h("discovery.get", func(*ipc.Call) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.sess == nil {
			return d.discoverLocked(nil), nil
		}
		return d.snap, nil
	})
	h("events.query", func(c *ipc.Call) (any, error) {
		var q QueryParams
		if err := decode(c, &q); err != nil {
			return nil, err
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		out := []contracts.Event{}
		for _, ev := range d.recent {
			if matchQuery(q, ev) {
				out = append(out, ev)
			}
		}
		if q.Limit > 0 && len(out) > q.Limit {
			out = out[len(out)-q.Limit:]
		}
		return out, nil
	})
	h("events.subscribe", func(c *ipc.Call) (any, error) {
		var q QueryParams
		if err := decode(c, &q); err != nil {
			return nil, err
		}
		ch := make(chan contracts.Event, 256)
		d.mu.Lock()
		id := d.nextSub
		d.nextSub++
		d.subs[id] = ch
		d.mu.Unlock()
		go func() {
			defer func() {
				d.mu.Lock()
				delete(d.subs, id)
				d.mu.Unlock()
			}()
			for {
				select {
				case <-c.Ctx.Done():
					return
				case ev := <-ch:
					if matchQuery(q, ev) && c.Notify(ev) != nil {
						return
					}
				}
			}
		}()
		return map[string]any{"subscribed": true}, nil
	})
	h("heartbeat", func(c *ipc.Call) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		role := "gui"
		if c.Peer.Agent {
			role = "agent"
		}
		if d.sess != nil && role == "agent" {
			d.sess.beats["agent"] = d.cfg.Now()
		}
		d.lastBeat[role] = d.cfg.Now()
		return map[string]any{"state": string(d.eng.Session()), "color": string(d.colorLocked())}, nil
	})
	h("panic.engage", func(*ipc.Call) (any, error) {
		return map[string]any{"ok": true}, d.Panic("manual")
	})
	h("alert.ack", func(c *ipc.Call) (any, error) {
		var p struct {
			ID     string `json:"id"`
			Reason string `json:"reason"`
		}
		if err := decode(c, &p); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, d.Ack(p.ID, p.Reason, c.Authorize)
	})
	h("gui.fullscreen_result", func(c *ipc.Call) (any, error) {
		var r FullscreenReport
		if err := decode(c, &r); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, d.FullscreenResult(r)
	})
	h("agent.report", func(c *ipc.Call) (any, error) {
		if err := contracts.ValidateJSON("agent_report", c.Req.Params); err != nil {
			return nil, errParams(err) // facts only: no check IDs, no severities (ADR 0009)
		}
		var f AgentFacts
		if err := decode(c, &f); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true}, d.AgentReport(f)
	})
	h("session.arm", func(c *ipc.Call) (any, error) {
		var req ArmRequest
		err := decode(c, &req)
		wipe(c.Req.Params) // the passphrase travelled base64-encoded in params
		if err != nil {
			return nil, err
		}
		res, rep, err := d.Arm(req)
		if errors.Is(err, ErrPreflight) || (err != nil && rep.Result != "") {
			return nil, &ipc.Error{Code: ipc.CodeState, Message: fmt.Sprintf("%v (preflight %s)", err, rep.Result)}
		}
		return res, err
	})
	h("selftest.run", func(c *ipc.Call) (any, error) {
		var r SelftestRequest
		if err := decode(c, &r); err != nil {
			return nil, err
		}
		return d.RunSelftest(c.Ctx, r, c.Authorize)
	})
	h("session.disarm", func(*ipc.Call) (any, error) { return d.Disarm() })
	h("active.check_now", func(*ipc.Call) (any, error) { return map[string]any{"ok": true}, d.CheckNow() })
	h("dns.leak_test", func(c *ipc.Call) (any, error) { return d.DNSLeakTest(c.Ctx) })
	h("panic.release", func(*ipc.Call) (any, error) { return d.Unpanic() })
	h("discovery.confirm_endpoint", func(c *ipc.Call) (any, error) { // sensitive: the server checks the proof
		var p struct {
			Endpoint string `json:"endpoint"`
		}
		if err := decode(c, &p); err != nil {
			return nil, err
		}
		return d.ConfirmEndpoint(p.Endpoint)
	})
}

// agentProc is the session agent spawned by the daemon (portable mode).
type agentProc struct {
	pid  int
	proc *os.Process
}

// isAgent tells whether the peer pid is the session agent. The agent is lethe itself run as the
// operator, so its executable must be the daemon's own file. In portable mode it must also be the
// child the daemon spawned and still alive; in service mode (no spawned agent, a user unit) the
// executable is the identity. The agent is a low-trust source either way (principle 9): a copy of
// lethe started by the operator's other processes gains nothing beyond what the agent may do.
func (d *Daemon) isAgent(pid int) bool {
	d.mu.Lock()
	a, spawned := d.agent, d.cfg.Agent != nil
	d.mu.Unlock()
	if spawned && (a == nil || a.pid != pid) {
		return false
	}
	return sameExe(d.cfg.ProcRoot, pid)
}

// sameExe reports whether /proc/<pid>/exe is the same file as the running daemon.
func sameExe(procRoot string, pid int) bool {
	peer, err := os.Stat(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return false
	}
	self, err := os.Stat("/proc/self/exe")
	return err == nil && os.SameFile(peer, self)
}

// spawnAgentLocked starts the agent as the operator (setuid before the capabilities drop).
func (d *Daemon) spawnAgentLocked() error {
	o := privsep.SpawnOptions{Env: d.cfg.AgentEnv, Stdout: d.cfg.Out, Stderr: d.cfg.Out}
	if isRoot() && d.cfg.Operator.UID != 0 {
		o.Cred = &privsep.Credential{UID: d.cfg.Operator.UID, GID: d.cfg.Operator.GID}
	}
	cmd, err := privsep.Spawn(d.cfg.Agent, o)
	if err != nil {
		return err
	}
	a := &agentProc{pid: cmd.Process.Pid, proc: cmd.Process}
	d.agent = a
	if d.sess != nil {
		d.sess.beats["agent"] = d.cfg.Now()
		d.sess.protected[a.pid] = true
	}
	go func() {
		// Wait for the exit without reaping it: while the zombie exists, its PID cannot be reused,
		// so the agent role and the kill protection go away before another process can take it.
		var info unix.Siginfo
		for unix.Waitid(unix.P_PID, a.pid, &info, unix.WEXITED|unix.WNOWAIT, nil) == unix.EINTR {
		}
		d.mu.Lock()
		if d.agent == a {
			d.agent = nil
		}
		if d.sess != nil {
			delete(d.sess.protected, a.pid)
		}
		d.mu.Unlock()
		_ = cmd.Wait()
	}()
	return nil
}

// Close stops the agent.
func (d *Daemon) Close() {
	d.mu.Lock()
	a := d.agent
	d.mu.Unlock()
	if a != nil {
		_ = a.proc.Kill()
	}
}
