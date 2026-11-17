//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"filippo.io/age"

	"lethe/internal/cli"
	"lethe/internal/contracts"
	"lethe/internal/daemon"
	"lethe/internal/guard"
	"lethe/internal/ipc"
	"lethe/internal/journal"
	"lethe/test/netlab"
)

func (s *session) edit(t *testing.T, from, to string) {
	t.Helper()
	raw, err := os.ReadFile(s.profile)
	if err != nil || !bytes.Contains(raw, []byte(from)) {
		t.Fatalf("profile lacks %q: %v", from, err)
	}
	if err := os.WriteFile(s.profile, bytes.Replace(raw, []byte(from), []byte(to), 1), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s *session) onlySession(t *testing.T) []contracts.Event {
	t.Helper()
	dirs, _ := filepath.Glob(filepath.Join(s.dir, "data", "sessions", "*"))
	if len(dirs) != 1 {
		t.Fatalf("sessions %v", dirs)
	}
	js, err := journal.Read(dirs[0], []age.Identity{s.ident})
	if err != nil {
		t.Fatal(err)
	}
	return js.Events
}

// runCLI starts `lethe <args>` in a child process with the passphrase on fd 3.
func runCLI(t *testing.T, s *session, out *syncBuffer, args ...string) *exec.Cmd {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pw.Write(append(append([]byte(nil), s.pass...), '\n'))
	_ = pw.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "LETHE_SOCKET="+s.socket, "LETHE_E2E_CLI="+strings.Join(append(args, "--passphrase-fd", "3"), "\x1f"))
	cmd.Env = append(cmd.Env, s.env...)
	cmd.ExtraFiles = []*os.File{pr}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = pr.Close()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		c, _ := guardConn()
		_, _ = guard.Cleanup(c)
	})
	return cmd
}

func exitOf(t *testing.T, cmd *exec.Cmd, out *syncBuffer) int {
	t.Helper()
	errc := make(chan error, 1)
	go func() { errc <- cmd.Wait() }()
	select {
	case err := <-errc:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		if err != nil {
			t.Fatal(err)
		}
		return 0
	case <-time.After(60 * time.Second):
		t.Fatalf("lethe did not exit:\n%s", out.String())
	}
	return -1
}

// TestE2E_AC16_ArmUndoneWhenTunnelCarriesNothing: strict, the WireGuard server is stopped. The
// arm is undone within guard.arm_confirm, no lethe table is left, exit 6 names the cause and the
// log closes with arm_unconfirmed.
func TestE2E_AC16_ArmUndoneWhenTunnelCarriesNothing(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	lab.StopServer(t)
	s := newSession(t)
	s.edit(t, "arm_confirm: 30s", "arm_confirm: 5s")
	out := &syncBuffer{}
	start := time.Now()
	cmd := runCLI(t, s, out, "run", "-p", s.profile, "--no-manual")
	if code := exitOf(t, cmd, out); code != cli.ExitArmUnconfirmed {
		t.Fatalf("exit %d, want %d:\n%s", code, cli.ExitArmUnconfirmed, out.String())
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Fatalf("took %s", took)
	}
	if !strings.Contains(out.String(), "PersistentKeepalive") || !strings.Contains(out.String(), "desfeito") {
		t.Fatalf("the cause is not explained:\n%s", out.String())
	}
	if d := dump(t); strings.Contains(d, "lethe") {
		t.Fatalf("tables left:\n%s", d)
	}
	evs := s.onlySession(t)
	last := evs[len(evs)-1]
	if last.Type != contracts.EvSessionEnd || last.Data["reason"] != "arm_unconfirmed" {
		t.Fatalf("last event %s %v", last.Type, last.Data)
	}
}

// TestE2E_AC17_ForceRefusedWithoutTunnel: strict without tunnel; run --force --reason x is
// refused with exit 2 and the --guard off hint; no table is applied.
func TestE2E_AC17_ForceRefusedWithoutTunnel(t *testing.T) {
	lab := netlab.New(t, true)
	lab.SetTunnel(t, false)
	s := newSession(t)
	out := &syncBuffer{}
	cmd := runCLI(t, s, out, "run", "-p", s.profile, "--no-manual", "--force", "--reason", "x")
	if code := exitOf(t, cmd, out); code != cli.ExitPreflightFailed {
		t.Fatalf("exit %d, want %d:\n%s", code, cli.ExitPreflightFailed, out.String())
	}
	if !strings.Contains(out.String(), "--guard off") || !strings.Contains(out.String(), "TUN-001") {
		t.Fatalf("no hint:\n%s", out.String())
	}
	if d := dump(t); strings.Contains(d, "lethe") {
		t.Fatalf("tables applied:\n%s", d)
	}
}

// TestE2E_AC18_ObserverBadProofsAndLeftoverStatus: off with 5 wrong proofs opens SELF-006
// without any table; a strict daemon killed with -9 leaves its tables, and status as root
// points to sudo lethe cleanup.
func TestE2E_AC18_ObserverBadProofsAndLeftoverStatus(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)

	s := newSession(t)
	s.edit(t, "mode: strict ", "mode: off ")
	d, c, out := startDaemon(t, s)
	if err := c.Call("session.arm", s.armRequest(t), nil, nil); err != nil {
		t.Fatal(err)
	}
	bad := bytes.Repeat([]byte{7}, 32)
	for range ipc.FailLimit {
		p, err := c.Prove(bad, "session.disarm", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Call("session.disarm", nil, p, nil)
	}
	waitFor(t, "SELF-006 CRITICAL", func() bool {
		a := alertOf(d, "SELF-006")
		return a != nil && a.Severity == "CRITICAL"
	})
	if st := d.Status(); st.State != "ARMED" || st.Lockdown != nil {
		t.Fatalf("observer must not block: %+v\n%s", st, out.String())
	}
	if dm := dump(t); strings.Contains(dm, "lethe") {
		t.Fatalf("tables applied in off:\n%s", dm)
	}
	if err := c.Call("session.disarm", nil, proof(t, c, s.pass, "session.disarm", nil), nil); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("sensitive methods must be locked: %v", err)
	}

	s2 := newSession(t)
	cout := &syncBuffer{}
	cmd := runCLI(t, s2, cout, "run", "-p", s2.profile, "--no-manual")
	c2 := dialWait(t, s2.socket)
	waitFor(t, "strict ARMED", func() bool {
		var st daemon.Status
		return c2.Call("status.get", nil, nil, &st) == nil && st.State == "ARMED" && !st.Confirming
	})
	_ = cmd.Process.Signal(syscall.SIGKILL)
	_, _ = cmd.Process.Wait()
	t.Setenv("LETHE_SOCKET", s2.socket)
	var sout, serr bytes.Buffer
	if code := cli.Execute([]string{"status", "--json"}, &sout, &serr); code != cli.ExitDaemonDown {
		t.Fatalf("status exit %d: %s", code, serr.String())
	}
	var st daemon.Status
	if err := json.Unmarshal(sout.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Lockdown == nil || !strings.Contains(st.Lockdown.Exit, "sudo lethe cleanup") || len(st.Lockdown.Tables) == 0 {
		t.Fatalf("status %s", sout.String())
	}
	if err := contracts.ValidateJSON("status", sout.Bytes()); err != nil {
		t.Fatal(err)
	}
}
