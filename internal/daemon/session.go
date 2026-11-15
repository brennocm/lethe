package daemon

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
	"github.com/godbus/dbus/v5"
	"github.com/google/nftables"
	"golang.org/x/sys/unix"

	"lethe/internal/baseline"
	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/engine"
	"lethe/internal/guard"
	"lethe/internal/ipc"
	"lethe/internal/journal"
	"lethe/internal/preflight"
	"lethe/internal/privsep"
	"lethe/internal/profile"
	"lethe/internal/report"
	"lethe/internal/response"
	"lethe/internal/sensors/procscan"
)

// ArmRequest is session.arm. The CLI reads the profile and the baseline as the operator and
// sends their bytes, so the daemon never opens a path chosen by a peer. Decrypting the baseline
// with Passphrase is the proof that authorizes the call (ADR 0006).
type ArmRequest struct {
	Profile    []byte             `json:"profile"`
	Baseline   []byte             `json:"baseline"`
	Passphrase []byte             `json:"passphrase"`
	Guard      string             `json:"guard,omitempty"` // overrides guard.mode
	Force      bool               `json:"force,omitempty"`
	Reason     string             `json:"reason,omitempty"`
	Manual     []preflight.Answer `json:"manual,omitempty"` // nil = checklist not asked
}

// ArmResult is returned by a successful arm.
type ArmResult struct {
	Session     string           `json:"session"`
	Fingerprint string           `json:"fingerprint"`
	Guard       string           `json:"guard"`
	Preflight   preflight.Report `json:"preflight"`
	Dir         string           `json:"dir"`
}

// ErrPreflight is returned when the preflight fails and the arm was not forced.
var ErrPreflight = errors.New("preflight failed (use --force --reason to arm anyway)")

const (
	armFailLimit  = 5
	armFailWindow = 5 * time.Minute
	saltSize      = 16
)

// Arm runs the preflight, opens the journal, applies the guard and starts the sensors.
// Passphrase is wiped before returning.
func (d *Daemon) Arm(req ArmRequest) (ArmResult, preflight.Report, error) {
	defer wipe(req.Passphrase)
	d.mu.Lock()
	defer d.mu.Unlock()
	var rep preflight.Report
	if st := d.eng.Session(); st != engine.StateReady && st != engine.StateVerified {
		return ArmResult{}, rep, errState(fmt.Errorf("cannot arm in %s", st))
	}
	now := d.cfg.Now()
	if d.armLockedOut(now) {
		return ArmResult{}, rep, errAuth("too many wrong passphrases; arm is locked for 5 minutes")
	}
	if req.Force && req.Reason == "" {
		return ArmResult{}, rep, errParams(errors.New("--force needs --reason"))
	}
	prof, warns, err := profile.Parse(req.Profile, d.cfg.Operator.Home)
	if err != nil {
		return ArmResult{}, rep, errParams(err)
	}
	mode := engine.GuardMode(prof.Guard.Mode)
	if req.Guard != "" {
		mode = engine.GuardMode(req.Guard)
	}
	switch mode {
	case engine.GuardOff, engine.GuardReactive, engine.GuardStrict:
	case "":
		mode = engine.GuardOff
	default:
		return ArmResult{}, rep, errParams(fmt.Errorf("guard mode %q", mode))
	}
	if prof.Storage.Dir == "" {
		return ArmResult{}, rep, errParams(errors.New("profile: storage.dir is required to arm"))
	}
	base, err := baseline.Decrypt(req.Baseline, req.Passphrase)
	if err != nil {
		d.armFails = append(d.armFails, now)
		return ArmResult{}, rep, errAuth(baseline.ErrWrongPassphrase.Error())
	}
	d.armFails = nil

	snap := d.discoverLocked(prof)
	rep = preflight.Run(preflight.Input{Snapshot: &snap, Profile: prof, Warnings: warns, Manual: req.Manual})
	cmd := engine.CmdArm
	if rep.Result == preflight.Fail {
		if _, err := d.eng.Apply(engine.CmdPreflightFail); err != nil {
			return ArmResult{}, rep, errState(err)
		}
		if !req.Force {
			return ArmResult{}, rep, errState(ErrPreflight)
		}
		cmd = engine.CmdArmForce
	} else if _, err := d.eng.Apply(engine.CmdPreflightPass); err != nil {
		return ArmResult{}, rep, errState(err)
	}
	if req.Force {
		cmd = engine.CmdArmForce
	}

	s, err := d.openSession(prof, base, mode, req.Passphrase, now)
	if err != nil {
		return ArmResult{}, rep, err
	}
	d.sess = s
	d.snap = snap
	ov := map[string]engine.Override{}
	for id, o := range prof.Overrides {
		e := engine.Override{Severity: contracts.Severity(o.Severity)}
		if o.Actions != nil {
			e.Actions = []engine.Action{}
			for _, a := range o.Actions {
				e.Actions = append(e.Actions, engine.Action(a))
			}
		}
		ov[id] = e
	}
	d.eng = engine.New(clock{d.cfg.Now}, engine.Config{Guard: mode, Overrides: ov, AllowDowngrade: prof.OverridesAllowDowngrade}, d.eng.Session())
	if _, err := d.eng.Apply(cmd); err != nil {
		d.abortLocked(err)
		return ArmResult{}, rep, errState(err)
	}
	for _, a := range rep.Manual {
		d.appendLocked(contracts.Event{Type: contracts.EvPreflightManualItem, Source: contracts.SourceOperator, Data: map[string]any{"id": a.ID, "ok": a.OK}})
	}
	d.appendLocked(contracts.Event{Type: contracts.EvPreflightResult, Source: contracts.SourceDaemon, Data: preflightData(rep)})
	if req.Force {
		d.appendLocked(contracts.Event{Type: contracts.EvOperatorForce, Source: contracts.SourceOperator, Data: map[string]any{"command": "arm", "reason": req.Reason, "preflight": rep.Result}})
	}
	if err := d.applyGuardLocked(snap); err != nil {
		d.abortLocked(err)
		return ArmResult{}, rep, err
	}
	if d.cfg.Sensors {
		d.startSensorsLocked(snap)
	}
	d.evaluateConditionsLocked(snap)
	if len(d.cfg.Agent) > 0 && d.agent == nil {
		if err := d.spawnAgentLocked(); err != nil {
			_, _ = fmt.Fprintf(d.cfg.Out, "lethe: agent: %v (alerts only on this terminal)\n", err)
		}
	}
	d.sess.color = ""
	d.stateChangedLocked("arm")
	if d.cfg.HardenAfterArm && !d.hardened {
		if err := privsep.Harden(); err != nil {
			d.abortLocked(err)
			return ArmResult{}, rep, fmt.Errorf("drop privileges: %w", err)
		}
		d.hardened = true
	}
	return ArmResult{Session: s.id, Fingerprint: s.journal.Fingerprint(), Guard: string(mode), Preflight: rep, Dir: s.dir()}, rep, nil
}

func (d *Daemon) armLockedOut(now time.Time) bool {
	n := 0
	for _, t := range d.armFails {
		if now.Sub(t) < armFailWindow {
			n++
		}
	}
	return n >= armFailLimit
}

func preflightData(r preflight.Report) map[string]any {
	cs := []any{}
	for _, c := range r.Checks {
		cs = append(cs, map[string]any{"id": c.ID, "status": c.Status})
	}
	return map[string]any{"result": r.Result, "checks": cs, "warnings": len(r.Warnings), "manual_skipped": r.ManualSkipped}
}

func (s *session) dir() string { return filepath.Join(s.prof.Storage.Dir, "sessions", s.id) }

// openSession derives the IPC key, opens the journal and builds the executor.
func (d *Daemon) openSession(prof *profile.Profile, base *baseline.Baseline, mode engine.GuardMode, pass []byte, now time.Time) (*session, error) {
	id, err := newUUID()
	if err != nil {
		return nil, err
	}
	s := &session{id: id, prof: prof, base: base, guardMode: mode, startedAt: now,
		beats: map[string]time.Time{}, down: map[string]bool{}, conditions: map[string]map[string]map[string]any{}}
	recips, err := recipients(prof.Storage.LogRecipients, base)
	if err != nil {
		return nil, errParams(err)
	}
	sens := recips
	if len(prof.Storage.SensitiveRecipients) > 0 {
		if sens, err = recipients(prof.Storage.SensitiveRecipients, base); err != nil {
			return nil, errParams(err)
		}
	}
	s.salt = make([]byte, saltSize)
	if _, err := rand.Read(s.salt); err != nil {
		return nil, err
	}
	key, err := ipc.DeriveKey(pass, s.salt)
	if err != nil {
		return nil, err
	}
	if err := d.sessionsDir(prof.Storage.Dir); err != nil {
		wipe(key)
		return nil, err
	}
	gid := -1
	if isRoot() {
		gid = d.cfg.Operator.GID
	}
	w, err := journal.Open(journal.Config{
		Dir: s.dir(), Session: id, Recipients: recips, SensitiveRecipients: sens,
		Now: d.cfg.Now, Mono: d.cfg.Mono, ReaderGID: gid,
		StartData: map[string]any{
			"tool_version": d.cfg.ToolVersion, "guard": string(mode), "operation": prof.Operation.ID,
			"auth_salt": base64.StdEncoding.EncodeToString(s.salt),
		},
	})
	if err != nil {
		wipe(key)
		return nil, err
	}
	s.journal = w
	s.auth = ipc.NewAuthenticator(key, d.cfg.Now, d.authLimit) // owns key; Close wipes it
	d.srv.SetAuthenticator(s.auth)
	s.exec = response.New(d.executorEnv(s))
	return s, nil
}

// sessionsDir creates storage.dir/sessions; as root it is root:operator 02750 so the operator
// can read sessions after the capabilities are dropped.
func (d *Daemon) sessionsDir(storage string) error {
	dir := filepath.Join(storage, "sessions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("storage: %w", err)
	}
	if isRoot() && d.cfg.Operator.GID > 0 {
		if err := os.Chown(dir, -1, d.cfg.Operator.GID); err != nil {
			return fmt.Errorf("storage: %w", err)
		}
		if err := os.Chmod(dir, 0o750|os.ModeSetgid); err != nil { // #nosec G302 -- operator group reads sessions
			return fmt.Errorf("storage: %w", err)
		}
	}
	return nil
}

func recipients(keys []string, base *baseline.Baseline) ([]age.Recipient, error) {
	if len(keys) == 0 {
		id, err := base.Identity()
		if err != nil {
			return nil, err
		}
		return []age.Recipient{id.Recipient()}, nil
	}
	var out []age.Recipient
	for _, k := range keys {
		r, err := age.ParseX25519Recipient(k)
		if err != nil {
			return nil, fmt.Errorf("storage recipient: %w", err)
		}
		out = append(out, r)
	}
	return out, nil
}

func (d *Daemon) executorEnv(s *session) response.Env {
	var kill []procscan.Matcher
	for _, m := range s.prof.Processes.KillOnPanic {
		kill = append(kill, procscan.Matcher{Match: m.Match, Value: m.Value})
	}
	s.protected = map[int]bool{os.Getpid(): true}
	if d.agent != nil {
		s.protected[d.agent.pid] = true
	}
	uid := uint32(d.cfg.Operator.UID) // #nosec G115 -- uids are u32
	return response.Env{
		Guard:       d.cfg.NFT,
		GuardConfig: func() guard.Config { return s.gcfg }, // runs under d.mu
		ProcRoot:    d.cfg.ProcRoot,
		KillOnPanic: kill,
		Egress:      func() []string { return s.gcfg.Egress },
		LinkDown:    response.NetlinkLinkDown,
		LockScreen: func() error {
			c, err := dbus.ConnectSystemBus()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			return response.LockScreen(response.SystemLogin1{Conn: c}, uid)
		},
		Protected:    s.protected,
		Now:          d.cfg.Now,
		LinkDownMode: s.prof.Guard.Panic.LinkDown,
	}
}

func (d *Daemon) discoverLocked(prof *profile.Profile) discovery.Snapshot {
	opt := discovery.Options{Now: d.cfg.Now(), Resolved: d.cfg.Resolved}
	if prof != nil {
		opt.Overrides = discovery.Overrides{Egress: prof.Network.EgressIfaces, Internal: prof.Network.InternalIfaces}
		for _, e := range prof.Egress.ParsedEndpoints {
			opt.ProfileEndpoints = append(opt.ProfileEndpoints, discovery.Endpoint{Addr: e.Addr, Proto: e.Proto})
		}
	}
	return discovery.Discover(d.cfg.Kernel, opt)
}

// guardConfig derives the nftables configuration from the discovery and the profile.
func guardConfig(snap discovery.Snapshot, prof *profile.Profile, f guard.Features) guard.Config {
	cfg := guard.Config{KeepTunnel: prof.Guard.Panic.KeepTunnel}
	tun := map[string]bool{}
	for _, t := range snap.Tunnels {
		tun[t.Iface] = true
		if cfg.WGMark == 0 && t.FwMark > 0 {
			cfg.WGMark = uint32(t.FwMark) // #nosec G115 -- fwmark is u32
		}
	}
	for _, i := range snap.Ifaces {
		switch i.Class {
		case discovery.ClassTunnel:
			tun[i.Name] = true
		case discovery.ClassInternal:
			cfg.Internal = append(cfg.Internal, i.Name)
		case discovery.ClassEgress:
			cfg.Egress = append(cfg.Egress, i.Name)
			if prof.Network.AllowLAN {
				for _, a := range i.Addrs {
					if p, err := netip.ParsePrefix(a); err == nil && p.Addr().IsPrivate() {
						cfg.LAN = append(cfg.LAN, p.Masked())
					}
				}
			}
		}
	}
	for n := range tun {
		cfg.Tunnels = append(cfg.Tunnels, n)
	}
	for _, e := range snap.ParsedEndpoints() {
		proto := uint8(unix.IPPROTO_UDP)
		if e.Proto == "tcp" {
			proto = unix.IPPROTO_TCP
		}
		cfg.Endpoints = append(cfg.Endpoints, guard.Endpoint{Addr: e.Addr, Proto: proto})
	}
	cfg.L2 = f.L2 && len(cfg.Egress) > 0
	return cfg
}

// applyGuardLocked probes the kernel and, in strict mode, installs the strict tables.
func (d *Daemon) applyGuardLocked(snap discovery.Snapshot) error {
	s := d.sess
	if s.guardMode == engine.GuardOff {
		s.gcfg = guardConfig(snap, s.prof, guard.Features{})
		return nil
	}
	c, err := d.cfg.NFT()
	if err != nil {
		return fmt.Errorf("guard: %w", err)
	}
	if s.features, err = guard.Probe(c); err != nil {
		return fmt.Errorf("guard: probe: %w", err)
	}
	s.gcfg = guardConfig(snap, s.prof, s.features)
	if s.guardMode != engine.GuardStrict {
		return nil
	}
	rs, err := guard.Strict(s.gcfg)
	if err != nil {
		return err
	}
	if err := guard.Apply(c, rs); err != nil {
		return fmt.Errorf("guard: apply strict: %w", err)
	}
	d.appendLocked(contracts.Event{Type: contracts.EvGuardApplied, Source: contracts.SourceDaemon, Data: map[string]any{
		"mode": "strict", "l2": s.gcfg.L2, "tables": tableNames(rs), "endpoints": len(s.gcfg.Endpoints),
	}})
	return nil
}

func tableNames(rs guard.Ruleset) []any {
	var out []any
	for _, t := range rs.Tables {
		out = append(out, guard.FamilyName(t.Family)+" "+t.Name)
	}
	return out
}

// abortLocked undoes a half-done arm: no guard left behind, journal closed with the reason.
func (d *Daemon) abortLocked(cause error) {
	d.endLocked("arm_failed: "+cause.Error(), false)
	d.eng = engine.New(clock{d.cfg.Now}, engine.Config{}, engine.StateReady)
}

// endLocked stops the sensors, removes the guard (unless keepGuard) and closes the journal.
func (d *Daemon) endLocked(reason string, keepGuard bool) {
	s := d.sess
	if s == nil {
		return
	}
	if cancel := s.cancel; cancel != nil {
		// Sensors take d.mu to deliver: release it while they drain. With d.sess nil they drop
		// what they still hold, and the engine state (still ARMED/PANIC) refuses a new arm.
		s.cancel, d.sess = nil, nil
		cancel()
		d.mu.Unlock()
		s.wg.Wait()
		d.mu.Lock()
		d.sess = s
	}
	if !keepGuard && s.guardMode != engine.GuardOff {
		if c, err := d.cfg.NFT(); err == nil {
			if err := guard.Remove(c, guard.All()...); err == nil {
				d.appendLocked(contracts.Event{Type: contracts.EvGuardRemoved, Source: contracts.SourceDaemon, Data: map[string]any{"reason": "disarm"}})
			} else {
				_, _ = fmt.Fprintf(d.cfg.Out, "lethe: guard: %v (run lethe cleanup)\n", err)
			}
		}
	}
	unacked := 0
	for _, a := range d.eng.Alerts() {
		if a.Severity == contracts.SeverityCritical && !a.Acked {
			unacked++
		}
	}
	_ = s.journal.Close(map[string]any{"reason": reason, "alerts": len(d.eng.Alerts()), "critical": s.critical, "unacked_critical": unacked, "guard_kept": keepGuard})
	d.writeReport(s)
	s.auth.Close()
	d.srv.SetAuthenticator(nil)
	d.sess = nil
	if d.cfg.ExitAfterSession {
		d.endOnce.Do(func() { close(d.ended) })
	}
	d.publishLocked(contracts.Event{Type: contracts.EvStateChanged, Source: contracts.SourceDaemon, Data: map[string]any{"state": string(engine.StateReady), "reason": reason}})
}

// DisarmResult summarizes a closed session.
type DisarmResult struct {
	Session  string `json:"session"`
	Dir      string `json:"dir"`
	Critical int    `json:"critical"`
}

// Disarm closes an ARMED session (PANIC needs unpanic first, spec §6.1).
func (d *Daemon) Disarm() (DisarmResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil {
		return DisarmResult{}, errState(errNotArmed)
	}
	if _, err := engine.Next(d.eng.Session(), engine.CmdDisarm); err != nil {
		return DisarmResult{}, errState(err)
	}
	r := DisarmResult{Session: d.sess.id, Dir: d.sess.dir(), Critical: d.sess.critical}
	d.endLocked("disarm", false)
	if _, err := d.eng.Apply(engine.CmdDisarm); err != nil {
		return r, errState(err)
	}
	return r, nil
}

// Panic engages block_all and kill_processes manually (no passphrase needed, spec §10.5).
func (d *Daemon) Panic(cause string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil {
		return errState(errNotArmed)
	}
	was := d.eng.Session()
	if _, err := d.eng.Apply(engine.CmdPanic); err != nil {
		return errState(err)
	}
	if was == engine.StatePanic {
		return nil // already blocked
	}
	d.engagePanicLocked(cause, "", contracts.Event{})
	return nil
}

func (d *Daemon) engagePanicLocked(cause, alertID string, ev contracts.Event) {
	data := map[string]any{"cause": cause}
	if ev.Check != "" {
		data["check"] = ev.Check
	}
	d.appendLocked(contracts.Event{Type: contracts.EvPanicEngaged, Source: contracts.SourceDaemon, AlertID: alertID, Data: data})
	if alertID != "" {
		return // the alert's own action plan carries block_all and kill_processes
	}
	for _, a := range []engine.Action{engine.ActBlockAll, engine.ActKillProcesses} {
		d.appendLocked(d.sess.exec.Run(a, ev).Event(""))
	}
	d.stateChangedLocked("panic")
}

// Unpanic leaves PANIC after re-checking the local state (spec §10.5). The caller proved the
// passphrase (panic.release is sensitive).
func (d *Daemon) Unpanic() (map[string]any, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil {
		return nil, errState(errNotArmed)
	}
	snap := d.discoverLocked(d.sess.prof)
	failed := []any{}
	for _, f := range append(checks.NET003{}.Evaluate(&snap, d.sess.prof.Expect.IPv6), checks.NET004{}.Evaluate(&snap)...) {
		if f.Severity == contracts.SeverityCritical {
			failed = append(failed, f.Check)
		}
	}
	if err := d.eng.Unpanic(len(failed) == 0, true); err != nil {
		return map[string]any{"recheck_failed": failed}, errState(err)
	}
	d.snap = snap
	if err := d.releaseGuardLocked(snap); err != nil {
		// Still blocked: go back to PANIC rather than claim the network is in strict mode.
		_, _ = d.eng.Apply(engine.CmdPanic)
		return nil, err
	}
	d.appendLocked(contracts.Event{Type: contracts.EvPanicReleased, Source: contracts.SourceOperator, Data: map[string]any{"recheck": []any{"NET-003", "NET-004"}}})
	d.stateChangedLocked("unpanic")
	return map[string]any{"state": string(d.eng.Session())}, nil
}

// releaseGuardLocked reapplies strict before removing the panic tables, so there is never a
// moment without a guard (fail-closed ordering). In reactive mode it removes the panic tables.
func (d *Daemon) releaseGuardLocked(snap discovery.Snapshot) error {
	s := d.sess
	c, err := d.cfg.NFT()
	if err != nil {
		return err
	}
	s.gcfg = guardConfig(snap, s.prof, s.features)
	panicRefs := []guard.TableRef{{Family: nftables.TableFamilyINet, Name: guard.TablePanic}}
	if s.guardMode == engine.GuardStrict {
		rs, err := guard.Strict(s.gcfg)
		if err != nil {
			return err
		}
		if err := guard.Apply(c, rs); err != nil {
			return fmt.Errorf("guard: reapply strict: %w", err)
		}
	} else {
		panicRefs = append(panicRefs, guard.TableRef{Family: nftables.TableFamilyNetdev, Name: guard.TableL2})
	}
	return guard.Remove(c, panicRefs...)
}

// Ack acknowledges an alert; authorize is called only for CRITICAL (spec §10.2).
func (d *Daemon) Ack(id, reason string, authorize func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil {
		return errState(errNotArmed)
	}
	a := d.eng.Alert(id)
	if a == nil {
		return errParams(fmt.Errorf("unknown alert %s", id))
	}
	authorized := false
	if a.Severity == contracts.SeverityCritical {
		if err := authorize(); err != nil {
			return errAuth(err.Error())
		}
		authorized = true
	}
	if _, err := d.eng.Ack(id, reason, authorized); err != nil {
		return errState(err)
	}
	d.appendLocked(contracts.Event{Type: contracts.EvAlertAck, Source: contracts.SourceOperator, AlertID: id, Check: "", Data: map[string]any{"reason": reason, "check": a.Check}})
	d.stateChangedLocked("ack")
	return nil
}

// authLimit is the Authenticator's 5-failures callback: enter panic (spec §17.3).
func (d *Daemon) authLimit() {
	go func() { _ = d.Panic("auth_failures") }() // called from inside Verify; avoid re-entrancy
}

func (d *Daemon) stateChangedLocked(reason string) {
	if d.sess == nil {
		return
	}
	c := d.eng.Color()
	d.sess.color = c
	d.appendLocked(contracts.Event{Type: contracts.EvStateChanged, Source: contracts.SourceDaemon, Data: map[string]any{
		"state": string(d.eng.Session()), "color": string(c), "reason": reason, "degraded": toAny(d.eng.Degraded()),
	}})
}

func toAny(xs []string) []any {
	out := make([]any, 0, len(xs))
	for _, x := range xs {
		out = append(out, x)
	}
	return out
}

// writeReport verifies the closed journal and writes report.md next to it (spec §6.2, step 7).
// With institutional log_recipients the daemon cannot read the journal: `lethe report` with
// that key produces the report instead.
func (d *Daemon) writeReport(s *session) {
	if len(s.prof.Storage.LogRecipients) > 0 {
		return
	}
	fail := func(err error) { _, _ = fmt.Fprintf(d.cfg.Out, "lethe: report: %v (use lethe report)\n", err) }
	id, err := s.base.Identity()
	if err != nil {
		fail(err)
		return
	}
	js, err := journal.Read(s.dir(), []age.Identity{id})
	if err != nil {
		fail(err)
		return
	}
	res, err := journal.Verify(js, s.journal.Fingerprint())
	if err != nil {
		fail(err)
		return
	}
	r, err := report.Build(js, res, report.Options{})
	if err != nil {
		fail(err)
		return
	}
	f, err := os.OpenFile(filepath.Join(s.dir(), "report.md"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640) // #nosec G302 G304 -- operator group reads it
	if err != nil {
		fail(err)
		return
	}
	err = report.WriteMarkdown(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fail(err)
	}
}
