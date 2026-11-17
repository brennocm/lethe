//go:build e2e

package e2e

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"lethe/internal/cli"
	"lethe/internal/contracts"
	"lethe/internal/daemon"
	"lethe/test/netlab"
)

// kmsg reads the kernel log from the moment it is opened (seccomp writes audit type=1326 there).
type kmsg struct{ fd int }

func openKmsg(t *testing.T) *kmsg {
	t.Helper()
	fd, err := unix.Open("/dev/kmsg", unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no kernel log to read the seccomp records from: %v", err)
	}
	if _, err := unix.Seek(fd, 0, unix.SEEK_END); err != nil {
		t.Skipf("kmsg seek: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return &kmsg{fd: fd}
}

var seccompRec = regexp.MustCompile(`type=1326 .* pid=(\d+) .* syscall=(\d+) .* code=(0x[0-9a-f]+)`)

// records returns "syscall code" for every seccomp record of the given pids (nil: every pid;
// under WSL2 the kernel logs pids of another namespace, so the tests take every record).
func (k *kmsg) records(pids map[int]bool) []string {
	var out []string
	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(k.fd, buf)
		if errors.Is(err, unix.EPIPE) { // overwritten records: keep reading
			continue
		}
		if err != nil || n <= 0 {
			break
		}
		m := seccompRec.FindStringSubmatch(string(buf[:n]))
		if m == nil {
			continue
		}
		pid, _ := strconv.Atoi(m[1])
		if pids == nil || pids[pid] {
			out = append(out, m[2]+" "+m[3])
		}
	}
	sort.Strings(out)
	return out
}

// TestE2E_M14_SeccompEnforce: `lethe run` in a child, strict, hardened with the phase-2
// allowlist in enforce (LETHE_SECCOMP=log turns this test into the survey that built the list:
// it then prints the syscalls the allowlist lacks). The session goes through the full selftest,
// panic, a CRITICAL and its acknowledgement, unpanic and the disarm; the daemon survives all of it and leaves no seccomp record and no table.
func TestE2E_M14_SeccompEnforce(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	km := openKmsg(t)
	s := newSession(t)
	out := &syncBuffer{}
	cmd := runCLI(t, s, out, "run", "-p", s.profile, "--no-manual")
	c := dialWait(t, s.socket)
	var st daemon.Status
	status := func() daemon.Status {
		st = daemon.Status{}
		_ = c.Call("status.get", nil, nil, &st)
		return st
	}
	alive := func() {
		t.Helper()
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("the daemon died (seccomp %v):\n%s", km.records(nil), out.String())
		}
	}
	waitFor(t, "ARMED, hardened, confirmed", func() bool {
		st := status()
		return st.State == "ARMED" && !st.Confirming && hardened(cmd.Process.Pid) == nil
	})
	raw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
	if !strings.Contains(string(raw), "Seccomp:\t2") {
		t.Fatal("no seccomp filter on the daemon")
	}

	sreq := daemon.SelftestRequest{Resp: true}
	_ = c.SetDeadline(time.Now().Add(3 * time.Minute))
	var res daemon.SelftestResult
	if err := c.Call("selftest.run", sreq, proof(t, c, s.pass, "selftest.run", sreq), &res); err != nil {
		t.Fatalf("selftest: %v\n%s", err, out.String())
	}
	alive()
	if !res.Full || len(res.Cases) < 10 {
		t.Fatalf("not the full selftest: %+v", res)
	}
	for _, r := range res.Cases {
		if r.Result == daemon.CaseFail {
			t.Errorf("selftest %s: %s", r.ID, r.Reason)
		}
	}

	// a CRITICAL in panic (as AC-08): the probe route leaves via the egress link, then goes
	if err := c.Call("panic.engage", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	probeLeakRoute(t, true)
	var id string
	waitFor(t, "NET-004", func() bool {
		for _, a := range status().Alerts {
			if a.Check == "NET-004" && !a.Acked {
				id = a.ID
			}
		}
		return id != ""
	})
	ack := map[string]string{"id": id, "reason": "lab"}
	if err := c.Call("alert.ack", ack, proof(t, c, s.pass, "alert.ack", ack), nil); err != nil {
		t.Fatal(err)
	}
	probeLeakRoute(t, false)
	alive()

	var relErr error
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("last unpanic: %v; status %+v; seccomp %v", relErr, st, km.records(nil))
		}
	})
	waitFor(t, "panic released", func() bool {
		relErr = c.Call("panic.release", nil, proof(t, c, s.pass, "panic.release", nil), nil)
		return relErr == nil
	})
	alive()

	_ = cmd.Process.Signal(os.Interrupt)
	// the NET-004 of the panic makes it a session with a CRITICAL
	if code := exitOf(t, cmd, out); code != cli.ExitSessionCritical {
		t.Fatalf("run exited %d:\n%s", code, out.String())
	}
	if recs := km.records(nil); len(recs) > 0 {
		t.Errorf("seccomp records (syscall code): %v", recs)
	}
	if dm := dump(t); strings.Contains(dm, "lethe") {
		t.Fatalf("tables left:\n%s", dm)
	}
}

// TestE2E_M14_SeccompActiveAndDNSLeak: the active checks under the enforcing filter. NET-011
// rounds (at the arm and on check_now) leave through the tunnel with the tunnel's resolver, and
// the DNS leak test resolves names through the system resolver, then fetches the result through
// the tunnel. The daemon survives and leaves no seccomp record.
func TestE2E_M14_SeccompActiveAndDNSLeak(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	exitServices(t, lab)
	km := openKmsg(t)
	s := newSession(t)
	ca := filepath.Join(s.dir, "ca.pem")
	if err := os.WriteFile(ca, exitCA, 0o600); err != nil {
		t.Fatal(err)
	}
	s.env = []string{"SSL_CERT_FILE=" + ca} // Go's system roots: the lab's CA only
	raw, _ := os.ReadFile(s.profile)
	prof := strings.NewReplacer(
		"active_checks:\n  enabled: false", "active_checks:\n  enabled: true",
		"https://check.torproject.org/api/ip", "https://"+exitNames[0]+"/json",
		"https://am.i.mullvad.net/json", "https://"+exitNames[1]+"/",
		"tunnel_dns: []", "tunnel_dns: ["+exitSrv+"]",
		"domain: bash.ws", "domain: "+leakDomain,
		"api: https://bash.ws/dnsleak/test/%s?json", "api: https://"+exitNames[0]+"/dnsleak/test/%s",
	).Replace(string(raw))
	if err := os.WriteFile(s.profile, []byte(prof), 0o600); err != nil {
		t.Fatal(err)
	}
	out := &syncBuffer{}
	cmd := runCLI(t, s, out, "run", "-p", s.profile, "--no-manual")
	c := dialWait(t, s.socket)
	status := func() daemon.Status {
		var st daemon.Status
		_ = c.Call("status.get", nil, nil, &st)
		return st
	}
	alive := func() {
		t.Helper()
		if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
			t.Fatalf("the daemon died (seccomp %v):\n%s", km.records(nil), out.String())
		}
	}
	waitFor(t, "ARMED, hardened, confirmed", func() bool {
		st := status()
		return st.State == "ARMED" && !st.Confirming && hardened(cmd.Process.Pid) == nil
	})
	for deadline := time.Now().Add(45 * time.Second); status().Exit == nil; time.Sleep(100 * time.Millisecond) {
		if time.Now().After(deadline) {
			var evs []contracts.Event
			_ = c.Call("events.query", map[string]any{"limit": 50}, nil, &evs)
			for _, ev := range evs {
				if ev.Check == "NET-011" || ev.Type == contracts.EvSensorDown {
					t.Logf("%s %s %v", ev.Type, ev.Check, ev.Data)
				}
			}
			t.Fatalf("no NET-011 round through the tunnel:\n%s", out.String())
		}
	}
	if e := status().Exit; e.IP != exitIP || e.Path != netlab.DUTTunnel {
		t.Fatalf("exit %+v", e)
	}
	if err := c.Call("active.check_now", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	var res contracts.DNSLeakResult
	if err := c.Call("dns.leak_test", nil, nil, &res); err != nil {
		t.Fatalf("dns.leak_test: %v\n%s", err, out.String())
	}
	if res.Verdict == "" {
		t.Fatalf("%+v", res)
	}
	t.Logf("DNS leak test in the lab: %s %s", res.Verdict, res.Detail)
	alive()
	if recs := km.records(nil); len(recs) != 0 {
		t.Fatalf("seccomp records (syscall code): %v", recs)
	}
}
