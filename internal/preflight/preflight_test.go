package preflight

import (
	"testing"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

func allYes() []Answer {
	var a []Answer
	for _, it := range Manual {
		a = append(a, Answer{ID: it.ID, OK: true})
	}
	return a
}

func tunnelSnap() *discovery.Snapshot {
	return &discovery.Snapshot{
		Ifaces:  []discovery.Iface{{LinkInfo: discovery.LinkInfo{Name: "wg0"}, Class: discovery.ClassTunnel, Up: true, Running: true}},
		Tunnels: []discovery.Tunnel{{Iface: "wg0", Kind: "wireguard"}},
		Routes: discovery.Routes{
			ProbeV4: &discovery.Route{Dst: "192.0.2.1", Iface: "wg0", Class: discovery.ClassTunnel},
		},
	}
}

func TestPreflight_PassWhenRoutedThroughTunnel(t *testing.T) {
	r := Run(Input{Snapshot: tunnelSnap(), Manual: allYes()})
	if r.Result != Pass {
		t.Fatalf("got %+v", r)
	}
	if err := contracts.Validate("preflight", r); err != nil {
		t.Fatal(err)
	}
}

func TestNET004_PreflightFailsOnEgressRoute(t *testing.T) {
	s := tunnelSnap()
	s.Routes.ProbeV4 = &discovery.Route{Dst: "192.0.2.1", Iface: "eth0", Class: discovery.ClassEgress}
	r := Run(Input{Snapshot: s, Manual: allYes()})
	if r.Result != Fail || r.Checks[1].ID != "NET-004" || r.Checks[1].Status != Fail {
		t.Fatalf("got %+v", r)
	}
}

func TestPreflight_ManualAnswers(t *testing.T) {
	no := allYes()
	no[2].OK = false
	if r := Run(Input{Snapshot: tunnelSnap(), Manual: no}); r.Result != Fail {
		t.Fatalf("a negative answer must fail: %+v", r)
	}
	if r := Run(Input{Snapshot: tunnelSnap(), Manual: allYes()[:2]}); r.Result != Fail {
		t.Fatalf("a missing answer must fail: %+v", r)
	}
	if r := Run(Input{Snapshot: tunnelSnap()}); r.Result != Warn || !r.ManualSkipped {
		t.Fatalf("skipped checklist must warn: %+v", r)
	}
}

func TestPreflight_WarningsAndGaps(t *testing.T) {
	s := tunnelSnap()
	s.Unavailable = []string{"wgctrl"}
	r := Run(Input{Snapshot: s, Manual: allYes(), Warnings: []string{"guard.mode is off"}})
	if r.Result != Warn || len(r.Warnings) != 2 {
		t.Fatalf("got %+v", r)
	}
}

func TestTUN001_PreflightNeedsATunnel(t *testing.T) {
	s := tunnelSnap()
	s.Tunnels, s.Ifaces = nil, nil
	r := Run(Input{Snapshot: s, Manual: allYes()})
	if r.Result != Fail || r.Checks[2].ID != "TUN-001" || r.Checks[2].Status != Fail {
		t.Fatalf("got %+v", r)
	}
}

func TestTUN007_PreflightWarns(t *testing.T) {
	s := tunnelSnap()
	s.LegacyIPTables = true
	if r := Run(Input{Snapshot: s, Manual: allYes()}); r.Result != Warn || r.Checks[3].Status != Warn {
		t.Fatalf("got %+v", r)
	}
}
