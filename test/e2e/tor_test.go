//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/test/netlab"
)

// TestE2E_AC07_TorDiscoveryAndStop: the system tor runs in ns "dut" with a ControlPort and cookie
// authentication, configured with a bridge in ns "vpn" (the lab has no internet, so tor never
// bootstraps). Discovery lists the bridge address; once tor is stopped, TUN-003 is CRITICAL.
// SKIP without a tor binary; docs/runbooks/ac07-tor.md is the manual procedure.
func TestE2E_AC07_TorDiscoveryAndStop(t *testing.T) {
	bin, err := exec.LookPath("tor")
	if err != nil {
		t.Skip("no tor binary; run docs/runbooks/ac07-tor.md by hand")
	}
	lab := netlab.New(t, false)
	dir := t.TempDir()
	cookie := filepath.Join(dir, "control_auth_cookie")
	torrc := filepath.Join(dir, "torrc")
	conf := fmt.Sprintf(`DataDirectory %s
SocksPort 0
ControlPort 127.0.0.1:9051
CookieAuthentication 1
CookieAuthFile %s
UseBridges 1
Bridge 198.18.0.2:9001
Log notice stderr
`, filepath.Join(dir, "data"), cookie)
	if err := os.WriteFile(torrc, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-f", torrc)
	cmd.Stderr = os.Stderr
	if err := lab.In(lab.DUT, cmd.Start); err != nil {
		t.Fatal(err)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	tc := discovery.NewTorControl("127.0.0.1:9051", cookie)
	defer func() { _ = tc.Close() }()
	discover := func() discovery.Snapshot {
		var s discovery.Snapshot
		_ = lab.In(lab.DUT, func() error {
			s = discovery.Discover(discovery.NetlinkKernel{}, discovery.Options{
				Overrides: discovery.Overrides{Egress: []string{netlab.DUTEgress}}, Now: time.Now(), Tor: tc, TorRequired: true,
			})
			return nil
		})
		return s
	}

	var s discovery.Snapshot
	deadline := time.Now().Add(15 * time.Second)
	for {
		s = discover()
		if s.Tor != nil && s.Tor.Reachable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("tor control never answered: %+v", s.Tor)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !s.Tor.UseBridges || len(s.Tor.Bridges) != 1 || s.Tor.Bridges[0].Addr != "198.18.0.2:9001" ||
		!slices.Contains(s.Endpoints, "198.18.0.2:9001/tcp") {
		t.Fatalf("bridge not discovered: tor %+v endpoints %v", s.Tor, s.Endpoints)
	}
	if err := contracts.Validate("discover", s); err != nil {
		t.Fatal(err)
	}

	_ = cmd.Process.Signal(os.Interrupt)
	_ = cmd.Process.Signal(os.Interrupt) // tor waits ShutdownWaitLength after the first one
	_ = cmd.Wait()
	stopped = true
	s = discover()
	fs := checks.TUN003{}.Evaluate(true, &s)
	if len(fs) != 1 || fs[0].Severity != contracts.SeverityCritical || fs[0].Data["reason"] != "control_unreachable" {
		t.Fatalf("after stopping tor: %+v (tor %+v)", fs, s.Tor)
	}
}
