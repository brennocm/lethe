//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"lethe/internal/baseline"
	"lethe/internal/cli"
	"lethe/internal/contracts"
	"lethe/internal/daemon"
	"lethe/internal/guard"
	"lethe/internal/ipc"
	"lethe/internal/journal"
	"lethe/internal/platform"
	"lethe/internal/preflight"
	"lethe/internal/privsep"
	"lethe/internal/profile"
	"lethe/test/netlab"
)

// TestMain lets the test binary act as the lethe CLI when the daemon re-executes
// /proc/self/exe (agent) or when a test runs `lethe run` in a child process.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && (os.Args[1] == "agent" || os.Args[1] == "selftest-deny") {
		os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
	}
	if args := os.Getenv("LETHE_E2E_CLI"); args != "" {
		os.Exit(cli.Execute(strings.Split(args, "\x1f"), os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

type session struct {
	dir, profile, baseline, socket string
	pass                           []byte
	ident                          *age.X25519Identity
	env                            []string // extra environment of the CLI child
}

// newSession writes a strict profile for the lab and an encrypted baseline.
func newSession(t *testing.T) *session {
	t.Helper()
	home := t.TempDir()
	s := &session{dir: home, profile: filepath.Join(home, "op.yaml"), baseline: filepath.Join(home, "baseline.age"),
		socket: filepath.Join(home, "run", "lethe.sock"), pass: []byte("lab passphrase")}
	b, err := baseline.New(time.Now(), "e2e")
	if err != nil {
		t.Fatal(err)
	}
	s.ident, _ = b.Identity()
	ct, err := baseline.Encrypt(b, s.pass, 10)
	if err != nil {
		t.Fatal(err)
	}
	prof := strings.NewReplacer(
		"egress_ifaces: []", "egress_ifaces: ["+netlab.DUTEgress+"]",
		"file: ~/lethe/baseline.age", "file: "+s.baseline,
		"dir: ~/lethe/data", "dir: "+filepath.Join(home, "data"),
		"mode: off ", "mode: strict ", // the lab exercises the guard; the template starts in off
		"active_checks:\n  enabled: true", "active_checks:\n  enabled: false", // no exit-IP queries (NET-011 has its own e2e)
		"keep_tunnel: true ", "keep_tunnel: false ", // the full-block panic (keep_tunnel has its own e2e)
	).Replace(string(profile.Template))
	if err := os.WriteFile(s.profile, []byte(prof), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.baseline, ct, 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *session) armRequest(t *testing.T) daemon.ArmRequest {
	t.Helper()
	raw, _ := os.ReadFile(s.profile)
	base, _ := os.ReadFile(s.baseline)
	var man []preflight.Answer
	for _, it := range preflight.Manual {
		man = append(man, preflight.Answer{ID: it.ID, OK: true})
	}
	return daemon.ArmRequest{Profile: raw, Baseline: base, Passphrase: append([]byte(nil), s.pass...), Manual: man}
}

func dialWait(t *testing.T, path string) *ipc.Client {
	t.Helper()
	for range 300 {
		if c, err := ipc.Dial(path, time.Second); err == nil {
			t.Cleanup(func() { _ = c.Close() })
			return c
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s did not come up", path)
	return nil
}

func proof(t *testing.T, c *ipc.Client, pass []byte, method string, params any) *ipc.Auth {
	t.Helper()
	var st daemon.Status
	if err := c.Call("status.get", nil, nil, &st); err != nil {
		t.Fatal(err)
	}
	key, err := ipc.DeriveKey(pass, st.AuthSalt)
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.Prove(key, method, params)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func ipcCode(err error) int {
	var ie *ipc.Error
	if errors.As(err, &ie) {
		return ie.Code
	}
	return 0
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timeout waiting for %s", what)
}

// probeLeakRoute sends 192.0.2.0/24 out of the egress link: NET-004 becomes CRITICAL.
func probeLeakRoute(t *testing.T, add bool) {
	t.Helper()
	eg, err := netlink.LinkByName(netlab.DUTEgress)
	if err != nil {
		t.Fatal(err)
	}
	_, dst, _ := net.ParseCIDR("192.0.2.0/24")
	r := &netlink.Route{LinkIndex: eg.Attrs().Index, Dst: dst, Gw: net.ParseIP("10.0.0.1")}
	if add {
		err = netlink.RouteAdd(r)
	} else {
		err = netlink.RouteDel(r)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// startArmed runs an in-process daemon with live sensors and arms it in strict mode over IPC.
func startArmed(t *testing.T, s *session) (*daemon.Daemon, *ipc.Client, daemon.ArmResult) {
	t.Helper()
	d, c, out := startDaemon(t, s)
	var res daemon.ArmResult
	if err := c.Call("session.arm", s.armRequest(t), nil, &res); err != nil {
		t.Fatalf("arm: %v\n%s", err, out.String())
	}
	return d, c, res
}

// startDaemon runs an in-process daemon with live sensors, not armed.
func startDaemon(t *testing.T, s *session) (*daemon.Daemon, *ipc.Client, *syncBuffer) {
	t.Helper()
	out := &syncBuffer{}
	d := daemon.New(daemon.Config{
		Operator: platform.Operator{UID: os.Getuid(), GID: os.Getgid(), Home: s.dir}, SocketPath: s.socket,
		ToolVersion: "e2e", Sensors: true, Out: out, DiscoverEvery: 300 * time.Millisecond,
		LinkDir: filepath.Join(s.dir, "linkstate"), // /run is the host's, read-only in the user namespace
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		c, _ := guardConn()
		_, _ = guard.Cleanup(c)
		if t.Failed() {
			t.Logf("daemon output:\n%s", out.String())
		}
	})
	c := dialWait(t, s.socket)
	_ = c.SetDeadline(time.Now().Add(time.Minute))
	return d, c, out
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func alertOf(d *daemon.Daemon, check string) *daemon.AlertView {
	for _, a := range d.Status().Alerts {
		if a.Check == check {
			return &a
		}
	}
	return nil
}

// TestE2E_AC04_DaemonTunnelDown: strict; the tunnel goes down and traffic is generated:
// TUN-001 CRITICAL, NET-002 journaled, and the ISP sees nothing but link control frames.
func TestE2E_AC04_DaemonTunnelDown(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	s := newSession(t)
	d, _, _ := startArmed(t, s)
	sn := lab.Sniff(t)
	start := time.Now()
	lab.SetTunnel(t, false)
	for range 5 {
		sendUDP(t, "192.0.2.1:9", false, []byte("tunnel is down"))
		sendUDP(t, "192.0.2.1:9", true, []byte("bound to egress"))
		time.Sleep(50 * time.Millisecond)
	}
	waitFor(t, "TUN-001 CRITICAL and NET-002", func() bool {
		a, b := alertOf(d, "TUN-001"), alertOf(d, "NET-002")
		return a != nil && a.Severity == "CRITICAL" && b != nil
	})
	time.Sleep(2500 * time.Millisecond)
	for _, f := range sn.Since(start) {
		if !netlab.IsLinkControl(f.Data) {
			t.Fatalf("leaked frame % x", f.Data[:min(48, len(f.Data))])
		}
	}
}

// TestE2E_AC05_EndpointChange: strict; the client switches to the server's second address.
// The allowlist follows within 1 s, the tunnel comes back, no CRITICAL and at most one NET-002.
func TestE2E_AC05_EndpointChange(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	echo := lab.TunnelEcho(t)
	s := newSession(t)
	d, _, _ := startArmed(t, s)
	if !echo() {
		t.Fatal("no round trip through the tunnel before the change: test is not measuring anything")
	}
	sn := lab.Sniff(t)
	changed := time.Now()
	lab.SetEndpoint(t, "198.18.0.3")
	waitFor(t, "allowlist with the new endpoint", func() bool { return strings.Contains(dump(t), "c6120003") }) // 198.18.0.3 in the endpoint set
	if dt := time.Since(changed); dt > time.Second+300*time.Millisecond {                                       // 1 s poll + dump latency
		t.Fatalf("allowlist updated after %s (> 1 s)", dt)
	}
	waitFor(t, "tunnel traffic to the new endpoint", func() bool {
		sendUDP(t, "10.200.0.1:9", false, []byte("via new endpoint"))
		for _, f := range sn.Since(changed) {
			if netlab.UDPTo(f.Data, net.ParseIP("198.18.0.3"), netlab.WGPort) {
				return true
			}
		}
		return false
	})
	waitFor(t, "round trip through the tunnel after the change", echo)
	time.Sleep(time.Second)
	st := d.Status()
	blocked := 0
	for _, a := range st.Alerts {
		if a.Severity == "CRITICAL" {
			t.Fatalf("CRITICAL during an endpoint change: %+v", a)
		}
		if a.Check == "NET-002" {
			blocked += a.Count
		}
	}
	if blocked > 1 {
		t.Fatalf("%d NET-002 (want at most 1)", blocked)
	}
	if st.Color == "RED" || st.Color == "GRAY" {
		t.Fatalf("status %+v", st)
	}
}

// TestE2E_AC06_KillSwitchRemoved: a third-party kill switch (inet killswitch, drop in output)
// exists at arm and is deleted during the session: TUN-004 CRITICAL.
func TestE2E_AC06_KillSwitchRemoved(t *testing.T) {
	netlab.New(t, true)
	c := nft(t)
	ks := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: "killswitch"})
	accept := nftables.ChainPolicyAccept
	out := c.AddChain(&nftables.Chain{Name: "out", Table: ks, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &accept})
	c.AddRule(&nftables.Rule{Table: ks, Chain: out, Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0, 9}},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}})
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c := nft(t); c.DelTable(ks); _ = c.Flush() })
	s := newSession(t)
	d, _, _ := startArmed(t, s)
	time.Sleep(time.Second)
	if a := alertOf(d, "TUN-004"); a != nil {
		t.Fatalf("TUN-004 before any change: %+v", a)
	}
	c = nft(t)
	c.DelTable(ks)
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "TUN-004 CRITICAL", func() bool {
		a := alertOf(d, "TUN-004")
		return a != nil && a.Severity == "CRITICAL"
	})
}

// TestE2E_AC08_DaemonPanicUnpanic drives the real daemon (strict guard, live sensors) over IPC:
// lethe panic blocks everything within 200 ms; unpanic is refused without the passphrase, with an
// unacknowledged CRITICAL and with a failing re-check, and succeeds with everything.
func TestE2E_AC08_DaemonPanicUnpanic(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	s := newSession(t)
	d, c, res := startArmed(t, s)
	if res.Guard != "strict" || res.Preflight.Result == preflight.Fail {
		t.Fatalf("arm result %+v", res)
	}
	if !strings.Contains(dump(t), "table inet lethe ") {
		t.Fatalf("strict table not applied:\n%s", dump(t))
	}

	sn := lab.Sniff(t)
	t0 := time.Now()
	if err := c.Call("panic.engage", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	applied := time.Now()
	if dt := applied.Sub(t0); dt > 200*time.Millisecond {
		t.Fatalf("lethe panic took %s (> 200 ms)", dt)
	}
	for range 5 {
		sendUDP(t, "10.200.0.1:9", false, []byte("tunnel during panic"))
		sendUDP(t, "192.0.2.1:9", true, []byte("egress during panic"))
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(2500 * time.Millisecond) // a WireGuard keepalive (2 s) would show up here
	if fs := sn.Since(applied); len(fs) != 0 {
		t.Fatalf("%d frames left during panic", len(fs))
	}

	// A CRITICAL while in PANIC: the route to the probe address now leaves via the egress link.
	probeLeakRoute(t, true)
	var alertID string
	waitFor(t, "NET-004 alert", func() bool {
		st := d.Status()
		for _, a := range st.Alerts {
			if a.Check == "NET-004" {
				alertID = a.ID
				return true
			}
		}
		return false
	})
	if err := c.Call("panic.release", nil, nil, nil); ipcCode(err) != ipc.CodeAuth {
		t.Fatalf("unpanic without passphrase: %v", err)
	}
	if err := c.Call("panic.release", nil, proof(t, c, s.pass, "panic.release", nil), nil); err == nil || !strings.Contains(err.Error(), "unacknowledged") {
		t.Fatalf("unpanic with an unacked CRITICAL: %v", err)
	}
	ack := map[string]string{"id": alertID, "reason": "lab"}
	if err := c.Call("alert.ack", ack, nil, nil); ipcCode(err) != ipc.CodeAuth {
		t.Fatalf("CRITICAL ack without passphrase: %v", err)
	}
	if err := c.Call("alert.ack", ack, proof(t, c, s.pass, "alert.ack", ack), nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Call("panic.release", nil, proof(t, c, s.pass, "panic.release", nil), nil); err == nil || !strings.Contains(err.Error(), "re-check") {
		t.Fatalf("unpanic with NET-004 failing: %v", err)
	}
	probeLeakRoute(t, false)
	if err := c.Call("panic.release", nil, proof(t, c, s.pass, "panic.release", nil), nil); err != nil {
		t.Fatalf("unpanic: %v", err)
	}
	if dm := dump(t); strings.Contains(dm, guard.TablePanic) || !strings.Contains(dm, "table inet lethe ") {
		t.Fatalf("after unpanic:\n%s", dm)
	}
	released := time.Now()
	sendUDP(t, "10.200.0.1:9", false, []byte("after"))
	waitFor(t, "tunnel traffic after unpanic", func() bool {
		for _, f := range sn.Since(released) {
			if netlab.UDPTo(f.Data, net.ParseIP("198.18.0.2"), netlab.WGPort) {
				return true
			}
		}
		return false
	})

	var dr daemon.DisarmResult
	if err := c.Call("session.disarm", nil, proof(t, c, s.pass, "session.disarm", nil), &dr); err != nil {
		t.Fatal(err)
	}
	if dm := dump(t); strings.Contains(dm, "lethe") {
		t.Fatalf("tables left after disarm:\n%s", dm)
	}
	js, err := journal.Read(res.Dir, []age.Identity{s.ident})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Verify(js, res.Fingerprint); err != nil {
		t.Fatalf("verify: %v", err)
	}
	var seen []string
	for _, ev := range js.Events {
		seen = append(seen, string(ev.Type))
	}
	all := strings.Join(seen, ",")
	for _, want := range []contracts.EventType{contracts.EvGuardApplied, contracts.EvPanicEngaged, contracts.EvIPCDenied,
		contracts.EvAlertAck, contracts.EvPanicReleased, contracts.EvGuardRemoved, contracts.EvSessionEnd} {
		if !strings.Contains(all, string(want)) {
			t.Fatalf("journal lacks %s: %s", want, all)
		}
	}
}

// TestE2E_M7_RunCLI runs `lethe run` in a child process: it arms in strict mode, spawns the
// agent, drops the capabilities on every thread and disarms cleanly on SIGTERM.
func TestE2E_M7_RunCLI(t *testing.T) {
	netlab.New(t, true)
	s := newSession(t)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pw.Write(append(append([]byte(nil), s.pass...), '\n'))
	_ = pw.Close()
	var out bytes.Buffer
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "LETHE_SOCKET="+s.socket,
		"LETHE_E2E_CLI="+strings.Join([]string{"run", "-p", s.profile, "--no-manual", "--passphrase-fd", "3"}, "\x1f"))
	cmd.ExtraFiles = []*os.File{pr}
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = pr.Close()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		c, _ := guardConn()
		_, _ = guard.Cleanup(c)
	})
	c := dialWait(t, s.socket)
	var st daemon.Status
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("status %+v caps %v\n%s", st, hardened(cmd.Process.Pid), out.String())
		}
	})
	waitFor(t, "ARMED with agent and dropped capabilities", func() bool {
		if err := c.Call("status.get", nil, nil, &st); err != nil {
			return false
		}
		return st.State == "ARMED" && st.Agent && hardened(cmd.Process.Pid) == nil
	})
	if err := hardened(cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Impressão digital") {
		t.Fatalf("fingerprint not shown:\n%s", out.String())
	}
	_ = cmd.Process.Signal(os.Interrupt)
	errc := make(chan error, 1)
	go func() { errc <- cmd.Wait() }()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("run exited with %v:\n%s", err, out.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("run did not exit:\n%s", out.String())
	}
	if dm := dump(t); strings.Contains(dm, "lethe") {
		t.Fatalf("tables left after run:\n%s", dm)
	}
}

// hardened checks the §19.3 capability sets on every thread of pid.
func hardened(pid int) error {
	tasks, _ := filepath.Glob(filepath.Join("/proc", strconv.Itoa(pid), "task", "*", "status"))
	if len(tasks) == 0 {
		return errors.New("no threads")
	}
	for _, p := range tasks {
		st, err := privsep.ReadStatus(p)
		if err != nil {
			continue
		}
		if st.Eff != privsep.KeepMask() || st.Prm != privsep.KeepMask() || st.Bnd != privsep.KeepMask() || st.Inh != 0 || st.Amb != 0 || !st.NoNewPrivs {
			return fmt.Errorf("%s: %+v", p, st)
		}
	}
	return nil
}

func guardConn() (guard.Conn, error) { return nftConn() }

func nftConn() (guard.Conn, error) { return nftables.New() }
