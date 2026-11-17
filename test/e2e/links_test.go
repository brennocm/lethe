//go:build e2e

package e2e

import (
	"net"
	"strings"
	"testing"
	"time"

	"lethe/test/netlab"
)

// TestE2E_M14_PanicLinksComeBack: with guard.panic.link_down: always the panic sets the egress
// link down; unpanic must bring it back up, or the operator leaves PANIC with no network and
// nothing in lethe to undo it.
func TestE2E_M14_PanicLinksComeBack(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	s := newSession(t)
	s.edit(t, "link_down: auto", "link_down: always")
	d, c, _ := startArmed(t, s)
	up := func() bool {
		ifi, err := net.InterfaceByName(netlab.DUTEgress)
		return err == nil && ifi.Flags&net.FlagUp != 0
	}
	if err := c.Call("panic.engage", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "egress link down", func() bool { return !up() })
	// the link going down opens real CRITICALs (NET-004, TUN-001…): acknowledge them first
	waitFor(t, "unpanic", func() bool {
		for _, a := range d.Status().Alerts {
			if a.Severity == "CRITICAL" && !a.Acked {
				ack := map[string]string{"id": a.ID, "reason": "lab"}
				_ = c.Call("alert.ack", ack, proof(t, c, s.pass, "alert.ack", ack), nil)
			}
		}
		err := c.Call("panic.release", nil, proof(t, c, s.pass, "panic.release", nil), nil)
		if err != nil && strings.Contains(err.Error(), "re-check") && !up() {
			t.Fatalf("the re-check fails because the link is still down: %v", err)
		}
		return err == nil
	})
	if !up() {
		t.Fatal("the egress link stayed down after unpanic")
	}
}
