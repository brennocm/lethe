package daemon

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
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
	"lethe/internal/platform"
	"lethe/internal/preflight"
	"lethe/internal/privsep"
	"lethe/internal/profile"
	"lethe/internal/report"
	"lethe/internal/response"
	"lethe/internal/sensors/dbusmon"
	"lethe/internal/sensors/procscan"
	"lethe/internal/sensors/sockdiag"
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
	Manual     []preflight.Answer `json:"manual,omitempty"`    // nil = checklist not asked
	NoActive   bool               `json:"no_active,omitempty"` // no NET-011 queries this session
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

// ErrForceTunnel refuses --force over a tunnel failure with a guard that blocks (spec §10.6
// item 1): the guard would cut the network as soon as it was applied.
var ErrForceTunnel = errors.New("preflight failed and --force does not apply: with this guard the network would be cut because the tunnel is not working; connect the tunnel, or arm with --guard off to only observe")

const (
	armFailLimit  = 5
	armFailWindow = 5 * time.Minute
	saltSize      = 16
)

// Arm runs the preflight, opens the journal, applies the guard and starts the sensors. In strict
// mode with guard.arm_confirm it then waits for the tunnel to prove it works (spec §10.6) and
// undoes the arm without that proof. Passphrase is wiped before returning.
func (d *Daemon) Arm(req ArmRequest) (ArmResult, preflight.Report, error) {
	res, rep, s, err := d.arm(req)
	if err != nil || s == nil {
		return res, rep, err
	}
	if err := d.confirmArm(s); err != nil {
		return ArmResult{}, rep, err
	}
	return res, rep, nil
}

// tunnelFails lists the tunnel checks that failed in the preflight: with strict or reactive
// they mean the guard would cut the network at once, so --force cannot override them.
func tunnelFails(rep preflight.Report) []string {
	var out []string
	for _, c := range rep.Checks {
		if c.Status == preflight.Fail && (c.ID == "TUN-001" || c.ID == "TUN-003" || c.ID == "TUN-008") {
			out = append(out, c.ID)
		}
	}
	return out
}

// arm does everything up to the confirmation. It returns the session to confirm, or nil.
func (d *Daemon) arm(req ArmRequest) (ArmResult, preflight.Report, *session, error) {
	defer wipe(req.Passphrase)
	d.mu.Lock()
	defer d.mu.Unlock()
	res, rep, err := d.armLocked(req)
	if err != nil {
		return res, rep, nil, err
	}
	s := d.sess
	if !s.confirming {
		return res, rep, nil, nil
	}
	return res, rep, s, nil
}

func (d *Daemon) armLocked(req ArmRequest) (ArmResult, preflight.Report, error) {
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
	if left := d.leftoverLocked(); len(left) > 0 {
		// a session over a block it does not own would say "protection off" with the network dead
		return ArmResult{}, rep, errState(fmt.Errorf("the network is blocked by tables left over from a previous session (%s): release the network first (Release the network in the panel, or sudo lethe cleanup)", strings.Join(left, ", ")))
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

	d.closeTorLocked() // a new profile may name another control port
	snap := d.discoverLocked(prof)
	known := checks.KnownFrom(base)
	col := d.collector(&session{prof: prof})
	host := col.Collect()
	rep = preflight.Run(preflight.Input{Snapshot: &snap, Profile: prof, Guard: string(mode), Warnings: warns, Manual: req.Manual,
		Host: &host, Known: known, Now: now})
	if mode == engine.GuardStrict && len(checks.TUN008{}.Evaluate(string(mode), &snap)) > 0 {
		d.closeTorLocked()
		return ArmResult{}, rep, errParams(errors.New("TUN-008: snowflake and meek bridges cannot be followed by the strict guard; arm with --guard off (observer)"))
	}
	cmd := engine.CmdArm
	if rep.Result == preflight.Fail {
		if _, err := d.eng.Apply(engine.CmdPreflightFail); err != nil {
			return ArmResult{}, rep, errState(err)
		}
		if !req.Force {
			d.closeTorLocked()
			return ArmResult{}, rep, errState(ErrPreflight)
		}
		if ids := tunnelFails(rep); len(ids) > 0 && mode != engine.GuardOff {
			d.closeTorLocked()
			return ArmResult{}, rep, errState(fmt.Errorf("%w: %s", ErrForceTunnel, strings.Join(ids, ", ")))
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
	s.known = known
	s.noActive = req.NoActive
	if host.BusRead {
		s.armWiFi = append([]dbusmon.WiFi{}, host.Bus.NM.WiFi...)
	}
	s.torExpected = checks.TorExpected(prof.Egress.Type, &snap)
	s.armEndpoints = map[string]bool{}
	for _, e := range snap.Endpoints {
		s.armEndpoints[e] = true
	}
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
	if t, err := d.nftTables(); err == nil {
		d.sess.nftArm = t
	} else {
		_, _ = fmt.Fprintf(d.cfg.Out, "lethe: TUN-004 unavailable: %v\n", err)
	}
	if err := d.applyGuardLocked(snap); err != nil {
		d.abortLocked(err)
		return ArmResult{}, rep, err
	}
	if d.cfg.Sensors {
		d.startSensorsLocked(snap)
	}
	d.endpointEventsLocked(discovery.Snapshot{}, snap)
	d.evaluateConditionsLocked(snap)
	if len(d.cfg.Agent) > 0 && d.agent == nil {
		if err := d.spawnAgentLocked(); err != nil {
			_, _ = fmt.Fprintf(d.cfg.Out, "lethe: agent: %v (alerts only on this terminal)\n", err)
		}
	}
	d.sess.color = ""
	d.sess.confirming = mode == engine.GuardStrict && prof.Guard.ArmWindow > 0
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
	recent := d.armFails[:0] // only the window counts; older failures are dropped
	for _, t := range d.armFails {
		if now.Sub(t) < armFailWindow {
			recent = append(recent, t)
		}
	}
	d.armFails = recent
	return len(recent) >= armFailLimit
}

func preflightData(r preflight.Report) map[string]any {
	cs := []any{}
	for _, c := range r.Checks {
		cs = append(cs, map[string]any{"id": c.ID, "status": c.Status})
	}
	return map[string]any{"result": r.Result, "checks": cs, "warnings": len(r.Warnings), "manual_skipped": r.ManualSkipped}
}

// dir is the session directory as the operator sees it (results, messages).
func (s *session) dir() string { return filepath.Join(s.prof.Storage.Dir, "sessions", s.id) }

// ioDir is the same directory through its open descriptor: every read and write of the daemon
// goes through it, so swapping a path component (the operator owns storage.dir) cannot redirect
// what root writes.
func (s *session) ioDir() string { return platform.FDPath(s.dirF) }

// openSession derives the IPC key, opens the journal and builds the executor.
func (d *Daemon) openSession(prof *profile.Profile, base *baseline.Baseline, mode engine.GuardMode, pass []byte, now time.Time) (*session, error) {
	id, err := newUUID()
	if err != nil {
		return nil, err
	}
	s := &session{id: id, prof: prof, base: base, guardMode: mode, startedAt: now,
		beats: map[string]time.Time{}, paused: map[string]time.Time{}, fullscreen: map[string]bool{}, down: map[string]bool{}, conditions: map[string]map[string]map[string]any{}, tunnels: map[string]bool{}, tx: checks.NewTxTracker()}
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
	if s.dirF, err = d.sessionDir(prof.Storage.Dir, id); err != nil {
		wipe(key)
		return nil, err
	}
	// storage.dir/state gets its owner while the daemon still holds CAP_CHOWN (see stateDir)
	sd, err := d.stateDir(s)
	if err != nil {
		wipe(key)
		_ = s.dirF.Close()
		return nil, err
	}
	_ = sd.Close()
	gid := -1
	if isRoot() {
		gid = d.cfg.Operator.GID
	}
	w, err := journal.Open(journal.Config{
		Dir: s.ioDir(), Session: id, Recipients: recips, SensitiveRecipients: sens,
		Now: d.cfg.Now, Mono: d.cfg.Mono, ReaderGID: gid,
		StartData: map[string]any{
			"tool_version": d.cfg.ToolVersion, "guard": string(mode), "operation": prof.Operation.ID,
			"auth_salt": base64.StdEncoding.EncodeToString(s.salt),
		},
	})
	if err != nil {
		wipe(key)
		_ = s.dirF.Close()
		return nil, err
	}
	s.journal = w
	s.auth = ipc.NewAuthenticator(key, d.cfg.Now, d.authLimit) // owns key; Close wipes it
	d.srv.SetAuthenticator(s.auth)
	s.exec = response.New(d.executorEnv(s))
	return s, nil
}

// sessionDir creates storage.dir/sessions/<id> and returns it open. As root, sessions is
// root:operator 02750 so the operator can read sessions after the capabilities are dropped. Both
// levels are created and changed through descriptors that never follow a symlink (the operator
// owns storage.dir; a planted sessions -> /etc must not get chowned).
func (d *Daemon) sessionDir(storage, id string) (*os.File, error) {
	if err := os.MkdirAll(storage, 0o700); err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	st, err := os.Open(storage) // #nosec G304 -- operator-chosen storage.dir (may itself be a symlink)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	defer func() { _ = st.Close() }()
	sessions, err := platform.MkdirAt(st, "sessions", 0o700)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	defer func() { _ = sessions.Close() }()
	if isRoot() && d.cfg.Operator.GID > 0 {
		if err := platform.SecureDir(sessions, -1, d.cfg.Operator.GID, 0o2750); err != nil {
			return nil, fmt.Errorf("storage: %w", err)
		}
	}
	dir, err := platform.MkdirAt(sessions, id, 0o700)
	if err != nil {
		return nil, fmt.Errorf("storage: %w", err)
	}
	return dir, nil
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
		KillUID:     d.cfg.Operator.UID,
		Egress:      func() []string { return s.gcfg.Egress },
		LinkDown:    response.RecordedLinkDown(response.LinkStore{Dir: d.cfg.LinkDir}),
		LockScreen: func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			c, err := dbus.ConnectSystemBus(dbus.WithContext(ctx))
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
	opt := discovery.Options{Now: d.cfg.Now(), Resolved: d.cfg.Resolved, Cgroups: d.cfg.Cgroups}
	if d.cfg.Sockets != nil {
		// Under the lock, discovery reads the last scan of the socket sensor; only a pass with no
		// scan yet (the arm) dumps the sockets itself.
		opt.Sockets = func() ([]sockdiag.Sock, map[uint32]sockdiag.Owner, error) {
			if d.sess != nil && d.sess.socks != nil {
				return d.sess.socks, d.sess.owners, nil
			}
			return d.cfg.Sockets()
		}
	}
	if prof != nil && checks.TorQueried(prof.Egress.Type) {
		if d.tor == nil {
			newTor := d.cfg.Tor
			if newTor == nil {
				newTor = func(addr, cookie string) discovery.TorSource {
					return discovery.NewTorControl(addr, cookie, d.cfg.Operator.UID)
				}
			}
			d.tor = newAsyncTor(newTor(prof.Egress.TorControl, prof.Egress.TorCookie))
		}
		opt.Tor, opt.TorRequired = d.tor, checks.TorRequired(prof.Egress.Type)
	}
	if prof != nil {
		opt.Overrides = discovery.Overrides{Egress: prof.Network.EgressIfaces, Internal: prof.Network.InternalIfaces}
		for _, e := range prof.Egress.ParsedEndpoints {
			opt.ProfileEndpoints = append(opt.ProfileEndpoints, discovery.Endpoint{Addr: e.Addr, Proto: e.Proto})
		}
	}
	if d.sess != nil {
		opt.ProfileEndpoints = append(opt.ProfileEndpoints, d.sess.learned...)
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
	for _, c := range snap.VPNClients {
		if c.CgroupID != 0 {
			cfg.VPN = &guard.Cgroup{Path: c.Cgroup, Level: c.CgroupLevel, ID: c.CgroupID, DNS: prof.Egress.AllowVPNClientDNS}
			break
		}
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
				data := map[string]any{"reason": removalReason(reason)}
				if up := d.restoreLinksLocked(); len(up) > 0 {
					data["links_up"] = up
				}
				d.appendLocked(contracts.Event{Type: contracts.EvGuardRemoved, Source: contracts.SourceDaemon, Data: data})
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
	_ = s.dirF.Close()
	s.auth.Close()
	d.srv.SetAuthenticator(nil)
	d.closeTorLocked()
	d.sess = nil
	if d.cfg.ExitAfterSession {
		d.endOnce.Do(func() { close(d.ended) })
	}
	d.publishLocked(contracts.Event{Type: contracts.EvStateChanged, Source: contracts.SourceDaemon, Data: map[string]any{"state": string(engine.StateReady), "reason": reason}})
}

// removalReason names why the guard left: the session end reason, or disarm.
func removalReason(end string) string {
	switch end {
	case "arm_unconfirmed", "daemon_stopped", "ipc_failed", "disarm_in_panic":
		return end
	}
	if strings.HasPrefix(end, "arm_failed") {
		return "arm_failed"
	}
	return "disarm"
}

// Disarm closes the session (passphrase proved by the caller). From PANIC it also lifts the
// block: it is the operator's way out when the unpanic re-check cannot pass, because the panic
// blocks the very tunnel that would have to come back (spec §10.6 item 10). It is journaled as
// disarm_in_panic, with the unacknowledged CRITICALs counted in session.end.
func (d *Daemon) Disarm() (DisarmResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil {
		return DisarmResult{}, errState(errNotArmed)
	}
	if _, err := engine.Next(d.eng.Session(), engine.CmdDisarm); err != nil {
		return DisarmResult{}, errState(err)
	}
	inPanic := d.eng.Session() == engine.StatePanic
	r := DisarmResult{Session: d.sess.id, Dir: d.sess.dir(), Critical: d.sess.critical, InPanic: inPanic}
	reason := "disarm"
	if inPanic {
		reason = "disarm_in_panic"
	}
	d.endLocked(reason, false)
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
	d.sess.panic = panicCause{cause: cause, alert: alertID, check: ev.Check}
	defer d.printLockdownLocked() // after blocking: the explanation never delays it
	d.appendLocked(contracts.Event{Type: contracts.EvPanicEngaged, Source: contracts.SourceDaemon, AlertID: alertID, Data: data})
	if alertID != "" {
		return // the alert's own action plan carries block_all and kill_processes
	}
	for _, a := range []engine.Action{engine.ActBlockAll, engine.ActKillProcesses} {
		d.appendLocked(d.sess.exec.Run(a, ev).Event(""))
	}
	d.stateChangedLocked("panic")
}

func (d *Daemon) printLockdownLocked() {
	if l := d.lockdownLocked(); l != nil {
		_, _ = fmt.Fprintf(d.cfg.Out, "lethe: %s\n", l)
	}
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
	recheck := append(checks.NET003{}.Evaluate(&snap, d.sess.prof.Expect.IPv6), checks.NET004{}.Evaluate(&snap)...)
	recheck = append(recheck, checks.TUN001{}.Evaluate(d.tunnelExpectLocked(), &snap)...)
	recheck = append(recheck, checks.TUN003{}.Evaluate(d.sess.torExpected, &snap)...)
	recheck = append(recheck, checks.DNS002{}.Evaluate(&snap, d.sess.known)...)
	for _, f := range recheck {
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
	d.sess.panic = panicCause{}
	data := map[string]any{"recheck": []any{"NET-003", "NET-004", "DNS-002", "TUN-001", "TUN-003"}}
	if up := d.restoreLinksLocked(); len(up) > 0 {
		data["links_up"] = up
	}
	d.appendLocked(contracts.Event{Type: contracts.EvPanicReleased, Source: contracts.SourceOperator, Data: data})
	d.stateChangedLocked("unpanic")
	return map[string]any{"state": string(d.eng.Session())}, nil
}

// restoreLinksLocked brings back up the links panic set down (link_down). Leaving the panic must
// give the network back: without this the operator would leave PANIC with every egress link
// still down and nothing in lethe to undo it. A link that fails stays recorded, and the message
// names `sudo lethe cleanup`, which retries.
func (d *Daemon) restoreLinksLocked() []any {
	up, err := response.LinkStore{Dir: d.cfg.LinkDir}.Restore(response.NetlinkLinkUp)
	if err != nil {
		_, _ = fmt.Fprintf(d.cfg.Out, "lethe: interfaces taken down by the panic did not come back: %v\n  how to get out: sudo lethe cleanup (tries again), or bring them up in the network manager\n", err)
	}
	out := make([]any, 0, len(up))
	for _, l := range up {
		out = append(out, l)
	}
	return out
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

// authLimit is the Authenticator's 5-failures callback (spec §17.3). It is called from inside
// Verify, so the work runs on its own goroutine.
func (d *Daemon) authLimit() { go d.authFailures() }

// authFailures opens SELF-006. Under strict and reactive its CRITICAL plan engages the panic;
// under off the sensitive methods are locked for 5 minutes and the network is left alone
// (spec §10.6 item 3).
func (d *Daemon) authFailures() {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.sess
	if s == nil {
		return
	}
	var locked time.Duration
	if s.guardMode == engine.GuardOff {
		locked = ipc.FailWindow
		s.auth.LockFor(locked)
		_, _ = fmt.Fprintf(d.cfg.Out, "lethe: 5 wrong passphrases: sensitive actions locked for %s (the network was not blocked)\n", locked)
	}
	d.findingLocked(checks.SELF006{}.Finding(ipc.FailLimit, ipc.FailWindow.Seconds(), locked.Seconds()))
}

func (d *Daemon) stateChangedLocked(reason string) { d.stateChangedWithLocked(reason, nil) }

// stateChangedWithLocked journals state.changed with extra fields. While the arm is being
// confirmed nothing is announced: ARMED is said only after the proof (spec §10.6).
func (d *Daemon) stateChangedWithLocked(reason string, extra map[string]any) {
	if d.sess == nil || (d.sess.confirming && d.eng.Session() == engine.StateArmed) {
		return
	}
	c := d.eng.Color()
	d.sess.color = c
	data := map[string]any{"state": string(d.eng.Session()), "color": string(c), "reason": reason, "degraded": toAny(d.eng.Degraded())}
	for k, v := range extra {
		data[k] = v
	}
	d.appendLocked(contracts.Event{Type: contracts.EvStateChanged, Source: contracts.SourceDaemon, Data: data})
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
	js, err := journal.Read(s.ioDir(), []age.Identity{id})
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
	f, err := os.OpenFile(filepath.Join(s.ioDir(), "report.md"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640) // #nosec G302 G304 -- operator group reads it
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

// closeTorLocked drops the tor control client (it is rebuilt from the next profile).
func (d *Daemon) closeTorLocked() {
	if c, ok := d.tor.(io.Closer); ok {
		_ = c.Close()
	}
	d.tor = nil
}
