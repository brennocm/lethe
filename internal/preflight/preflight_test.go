package preflight

import (
	"testing"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/profile"
)

func allYes() []Answer {
	var a []Answer
	for _, it := range Manual {
		a = append(a, Answer{ID: it.ID, OK: true})
	}
	return a
}

func status(r Report, id string) string {
	for _, c := range r.Checks {
		if c.ID == id {
			return c.Status
		}
	}
	return "missing"
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
	if r.Result != Fail || status(r, "NET-004") != Fail {
		t.Fatalf("got %+v", r)
	}
}

func TestTUN003_PreflightTor(t *testing.T) {
	p := profile.Profile{}
	p.Egress.Type = "tor"
	s := &discovery.Snapshot{Tor: &discovery.TorState{Reachable: true, Bootstrap: 40}}
	r := Run(Input{Snapshot: s, Profile: &p, Manual: allYes()})
	if r.Result != Fail || status(r, "TUN-003") != Fail || status(r, "TUN-001") != Pass {
		t.Fatalf("tor-only session bootstrapping: %+v", r)
	}
	s.Tor.Bootstrap, s.Tor.CircuitEstablished = 100, true
	if r := Run(Input{Snapshot: s, Profile: &p, Manual: allYes()}); r.Result != Pass {
		t.Fatalf("healthy tor: %+v", r)
	}
	// auto with tor answering: tor is in use, so no tunnel interface is needed.
	p.Egress.Type = "auto"
	if r := Run(Input{Snapshot: s, Profile: &p, Manual: allYes()}); status(r, "TUN-001") != Pass || status(r, "TUN-003") != Pass {
		t.Fatalf("auto with tor: %+v", r)
	}
	s.Tor.Reachable = false
	if r := Run(Input{Snapshot: s, Profile: &p, Manual: allYes()}); status(r, "TUN-001") != Fail || status(r, "TUN-003") != Pass {
		t.Fatalf("auto without tor needs a tunnel: %+v", r)
	}
}

func TestTUN008_PreflightStrictWithSnowflake(t *testing.T) {
	p := profile.Profile{}
	p.Egress.Type, p.Guard.Mode = "tor", "strict"
	s := &discovery.Snapshot{Tor: &discovery.TorState{Reachable: true, Bootstrap: 100, CircuitEstablished: true, UseBridges: true, Transports: []string{"snowflake"}}}
	if r := Run(Input{Snapshot: s, Profile: &p, Manual: allYes()}); status(r, "TUN-008") != Fail {
		t.Fatalf("strict: %+v", r)
	}
	if r := Run(Input{Snapshot: s, Profile: &p, Guard: "off", Manual: allYes()}); r.Result != Pass {
		t.Fatalf("observer mode with snowflake: %+v", r)
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
	if r.Result != Fail || status(r, "TUN-001") != Fail {
		t.Fatalf("got %+v", r)
	}
}

func TestTUN007_PreflightWarns(t *testing.T) {
	s := tunnelSnap()
	s.LegacyIPTables = true
	if r := Run(Input{Snapshot: s, Manual: allYes()}); r.Result != Warn || status(r, "TUN-007") != Warn {
		t.Fatalf("got %+v", r)
	}
}

func TestTUN005_PreflightWarns(t *testing.T) {
	s := tunnelSnap()
	s.Routes.Rules = []discovery.Rule{{Family: "ipv4", Priority: 100, Table: 254, Mark: 0x6d6f6c65}}
	if r := Run(Input{Snapshot: s, Manual: allYes()}); r.Result != Warn || status(r, "TUN-005") != Warn {
		t.Fatalf("got %+v", r)
	}
}
