//go:build e2e

package e2e

import (
	"encoding/hex"
	"net"
	"os"
	"testing"
	"time"

	"lethe/internal/cli"
	"lethe/internal/daemon"
	"lethe/test/netlab"
)

// TestE2E_AC12_NoTrafficOfItsOwn: with the active checks off (the e2e profile), a whole hardened
// session (arm in strict, the arm confirmation, an idle stretch, panic, unpanic, disarm) puts
// nothing on the "internet" link besides link control (ARP, DHCP, NDP) and the WireGuard
// datagrams to the server: no DNS, no NTP, no HTTP, no reports home.
func TestE2E_AC12_NoTrafficOfItsOwn(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	sn := lab.Sniff(t)
	start := time.Now()
	s := newSession(t)
	out := &syncBuffer{}
	cmd := runCLI(t, s, out, "run", "-p", s.profile, "--no-manual")
	c := dialWait(t, s.socket)
	waitFor(t, "ARMED and confirmed", func() bool {
		var st daemon.Status
		return c.Call("status.get", nil, nil, &st) == nil && st.State == "ARMED" && !st.Confirming
	})
	time.Sleep(10 * time.Second) // sensors, housekeeping, journal checkpoints
	if err := c.Call("panic.engage", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Call("panic.release", nil, proof(t, c, s.pass, "panic.release", nil), nil); err != nil {
		t.Fatalf("unpanic: %v", err)
	}
	time.Sleep(2 * time.Second)
	_ = cmd.Process.Signal(os.Interrupt)
	if code := exitOf(t, cmd, out); code != cli.ExitOK {
		t.Fatalf("run exited %d:\n%s", code, out.String())
	}
	wg := net.ParseIP("198.18.0.2")
	n := 0
	for _, f := range sn.Since(start) {
		n++
		if netlab.IsLinkControl(f.Data) || netlab.UDPTo(f.Data, wg, netlab.WGPort) {
			continue
		}
		t.Errorf("frame of lethe's own on the internet link at %s:\n%s", f.At.Format(time.StampMilli), hex.Dump(f.Data[:min(len(f.Data), 64)]))
	}
	if n == 0 {
		t.Fatal("the sniffer saw nothing at all (not even the tunnel): it is not looking")
	}
}
