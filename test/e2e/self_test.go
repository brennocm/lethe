//go:build e2e

package e2e

import (
	"net"
	"testing"
	"time"

	"lethe/test/netlab"
)

// TestE2E_SELF001_PausedSensorGoesGray: a live capture sensor that stops beating turns the
// state GRAY within 3 s and back once it beats again (ST-SELF-001).
func TestE2E_SELF001_PausedSensorGoesGray(t *testing.T) {
	lab := netlab.New(t, true)
	defer lab.Close()
	lab.WaitHandshake(t, 10*time.Second)
	s := newSession(t)
	d, c, out := startDaemon(t, s)
	req := s.armRequest(t)
	req.Guard = "off"
	if err := c.Call("session.arm", req, nil, nil); err != nil {
		t.Fatalf("arm: %v\n%s", err, out.String())
	}
	// the lab host's own timezone may raise HOST-005 (YELLOW): only GRAY matters here
	notGray := func() bool { st := d.Status(); return st.Color != "GRAY" && len(st.Degraded) == 0 }
	waitFor(t, "not gray", notGray)
	if err := d.PauseSensor("capture:"+netlab.DUTEgress, 4*time.Second); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	waitFor(t, "gray", func() bool { return d.Status().Color == "GRAY" })
	if el := time.Since(start); el > 4*time.Second {
		t.Fatalf("GRAY after %v", el)
	}
	defer func() {
		if t.Failed() {
			t.Logf("status %+v", d.Status())
		}
	}()
	waitFor(t, "out of gray", notGray)
}

// TestE2E_SELF002_CaptureDrops: with the minimum receive buffer, a burst of 2000 leak packets
// overflows the capture socket and SELF-002 reports the drops (ST-SELF-002).
func TestE2E_SELF002_CaptureDrops(t *testing.T) {
	lab := netlab.New(t, true)
	defer lab.Close()
	lab.WaitHandshake(t, 10*time.Second)
	s := newSession(t)
	d, c, out := startDaemon(t, s)
	req := s.armRequest(t)
	req.Guard = "off" // strict would drop the burst before AF_PACKET sees it
	if err := c.Call("session.arm", req, nil, nil); err != nil {
		t.Fatalf("arm: %v\n%s", err, out.String())
	}
	if err := d.ShrinkCapture(netlab.DUTEgress, 1); err != nil {
		t.Fatal(err)
	}
	dl := net.Dialer{Control: bindEgress}
	u, err := dl.Dial("udp", "192.0.2.77:9")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = u.Close() }()
	payload := make([]byte, 1200)
	for range 2000 {
		_, _ = u.Write(payload)
	}
	waitFor(t, "SELF-002", func() bool { return alertOf(d, "SELF-002") != nil })
	if a := alertOf(d, "SELF-002"); a.Severity != "WARNING" {
		t.Fatalf("%+v", a)
	}
}
