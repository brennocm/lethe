//go:build e2e

package e2e

import (
	"testing"
	"time"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/test/netlab"
)

func TestE2E_M4_DiscoveryOnNetlab(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	var s discovery.Snapshot
	_ = lab.In(lab.DUT, func() error {
		s = discovery.Discover(discovery.NetlinkKernel{}, discovery.Options{
			Overrides: discovery.Overrides{Egress: []string{netlab.DUTEgress}}, Now: time.Now(),
		})
		return nil
	})
	eg, ok := s.Iface(netlab.DUTEgress)
	if !ok || eg.Class != discovery.ClassEgress {
		t.Fatalf("egress: %+v", eg)
	}
	wg, ok := s.Iface(netlab.DUTTunnel)
	if !ok || wg.Class != discovery.ClassTunnel || !wg.Up {
		t.Fatalf("tunnel: %+v", wg)
	}
	if len(s.Endpoints) != 1 || s.Endpoints[0] != "198.18.0.2:51820/udp" {
		t.Fatalf("endpoints %v", s.Endpoints)
	}
	if len(s.CaptureIfaces) != 1 || s.CaptureIfaces[0] != netlab.DUTEgress {
		t.Fatalf("capture %v", s.CaptureIfaces)
	}
	if s.Routes.ProbeV4 == nil || s.Routes.ProbeV4.Iface != netlab.DUTTunnel || s.Routes.ProbeV4.Class != discovery.ClassTunnel {
		t.Fatalf("probe v4 should go through the tunnel: %+v", s.Routes.ProbeV4)
	}
	if len(s.Tunnels) != 1 || s.Tunnels[0].Kind != "wireguard" || s.Tunnels[0].Peers[0].LastHandshake.IsZero() {
		t.Fatalf("tunnels %+v", s.Tunnels)
	}
	if err := contracts.Validate("discover", s); err != nil {
		t.Fatal(err)
	}
}

func TestE2E_M4_TunnelDownRouteFallsBackToEgress(t *testing.T) {
	lab := netlab.New(t, false) // no tunnel: default route via the egress link
	var s discovery.Snapshot
	_ = lab.In(lab.DUT, func() error {
		s = discovery.Discover(discovery.NetlinkKernel{}, discovery.Options{Overrides: discovery.Overrides{Egress: []string{netlab.DUTEgress}}})
		return nil
	})
	if s.Routes.ProbeV4 == nil || s.Routes.ProbeV4.Class != discovery.ClassEgress {
		t.Fatalf("probe v4 = %+v", s.Routes.ProbeV4)
	}
	if len(s.Endpoints) != 0 {
		t.Fatalf("endpoints %v", s.Endpoints)
	}
}
