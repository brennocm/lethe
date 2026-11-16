package checks

import (
	"fmt"
	"testing"
	"time"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/sensors/nftmon"
)

func reasons(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Data["reason"].(string))
	}
	return out
}

func TestTUN001_Evaluate(t *testing.T) {
	s := snap()
	s.Ifaces[2].Up, s.Ifaces[2].Running = true, true
	want := TunnelExpect{Ifaces: []string{"wg0"}, Require: true}
	if fs := (TUN001{}).Evaluate(want, s); len(fs) != 0 {
		t.Fatalf("healthy tunnel: %v", fs)
	}
	s.Ifaces[2].Running = false
	if got := reasons((TUN001{}).Evaluate(want, s)); len(got) != 1 || got[0] != "not_running" {
		t.Fatalf("got %v", got)
	}
	s.Ifaces[2].Up = false
	if got := reasons((TUN001{}).Evaluate(want, s)); got[0] != "down" {
		t.Fatalf("got %v", got)
	}
	s.Ifaces = s.Ifaces[:2]
	if got := reasons((TUN001{}).Evaluate(want, s)); got[0] != "missing" {
		t.Fatalf("got %v", got)
	}
	if got := reasons((TUN001{}).Evaluate(TunnelExpect{Require: true}, s)); len(got) != 1 || got[0] != "no_tunnel" {
		t.Fatalf("got %v", got)
	}
	if fs := (TUN001{}).Evaluate(TunnelExpect{}, s); len(fs) != 0 {
		t.Fatalf("tor sessions need no tunnel interface: %v", fs)
	}
	if RequiresTunnel("tor", false) || !RequiresTunnel("auto", false) || RequiresTunnel("auto", true) || !RequiresTunnel("vpn+tor", true) {
		t.Fatal("RequiresTunnel")
	}
}

func TestTUN007_Evaluate(t *testing.T) {
	s := &discovery.Snapshot{}
	if fs := (TUN007{}).Evaluate(s); len(fs) != 0 {
		t.Fatal(fs)
	}
	s.LegacyIPTables = true
	if fs := (TUN007{}).Evaluate(s); len(fs) != 1 || fs[0].Severity != "WARNING" {
		t.Fatal(fs)
	}
}

func TestTUN004_Evaluate(t *testing.T) {
	arm := []nftmon.Table{{Name: "inet killswitch", Hash: "a", OutputDrop: true}, {Name: "inet fw", Hash: "b"}}
	if fs := (TUN004{}).Evaluate(arm, arm); len(fs) != 0 {
		t.Fatal(fs)
	}
	now := []nftmon.Table{{Name: "inet fw", Hash: "c"}, {Name: "ip nat", Hash: "d"}}
	fs := (TUN004{}).Evaluate(arm, now)
	got := map[string]string{}
	for _, f := range fs {
		got[f.Data["reason"].(string)] = string(f.Severity)
	}
	want := map[string]string{"killswitch_removed": "CRITICAL", "changed": "WARNING", "added": "WARNING"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: got %q want %q (%v)", k, got[k], v, got)
		}
	}
	if fs := (TUN004{}).Evaluate([]nftmon.Table{{Name: "inet fw"}}, nil); len(fs) != 1 || fs[0].Severity != "WARNING" {
		t.Fatalf("removing a table without output drop is WARNING: %v", fs)
	}
}

func TestTUN002_Evaluate(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	s := snap()
	s.Tunnels[0].Peers = []discovery.WGPeer{{Endpoint: "198.51.100.7:51820", TxBytes: 100, LastHandshake: now.Add(-200 * time.Second)}}
	tr := NewTxTracker()
	if fs := (TUN002{}).Evaluate(tr, s, now); len(fs) != 0 {
		t.Fatal("first sample has no tx history")
	}
	s.Tunnels[0].Peers[0].TxBytes = 200
	if fs := (TUN002{}).Evaluate(tr, s, now.Add(time.Second)); len(fs) != 1 {
		t.Fatalf("tx grew with a 200 s old handshake: %v", fs)
	}
	if fs := (TUN002{}).Evaluate(tr, s, now.Add(12*time.Second)); len(fs) != 0 {
		t.Fatalf("no tx in the last 10 s: %v", fs)
	}
	s.Tunnels[0].Peers[0].TxBytes = 300
	s.Tunnels[0].Peers[0].LastHandshake = now
	if fs := (TUN002{}).Evaluate(tr, s, now.Add(13*time.Second)); len(fs) != 0 {
		t.Fatalf("fresh handshake: %v", fs)
	}
}

func TestTUN005_Evaluate(t *testing.T) {
	s := snap()
	s.Routes.Rules = []discovery.Rule{
		{Family: "ipv4", Priority: 32764, Table: 254},                              // main: plain
		{Family: "ipv4", Priority: 32765, Table: 51820, Mark: 51820, Invert: true}, // wg-quick
		{Family: "ipv4", Priority: 100, Table: 254, Mark: 51820},                   // tunnel's own transport mark
		{Family: "ipv4", Priority: 200, Table: 254, Mark: 0x6d6f6c65},              // excluded app
		{Family: "ipv6", Priority: 300, Table: 254, UIDRange: true},                // excluded user
		{Family: "ipv4", Priority: 400, Table: 51820, Mark: 7},                     // into the tunnel table
	}
	got := reasons((TUN005{}).Evaluate(s))
	if len(got) != 2 || got[0] != "fwmark_exclusion" || got[1] != "uid_exclusion" {
		t.Fatalf("got %v", got)
	}
}

func TestTUN003_Evaluate(t *testing.T) {
	s := snap()
	if fs := (TUN003{}).Evaluate(false, s); len(fs) != 0 {
		t.Fatal("tor not expected")
	}
	cases := []struct {
		tor  *discovery.TorState
		want string
	}{
		{nil, "control_unreachable"},
		{&discovery.TorState{}, "control_unreachable"},
		{&discovery.TorState{Reachable: true, Bootstrap: 85}, "bootstrap"},
		{&discovery.TorState{Reachable: true, Bootstrap: 100}, "no_circuit"},
	}
	for _, c := range cases {
		s.Tor = c.tor
		f := onlyFinding(t, (TUN003{}).Evaluate(true, s), "TUN-003", contracts.SeverityCritical)
		if f.Data["reason"] != c.want {
			t.Errorf("%+v: got %v", c.tor, f.Data)
		}
	}
	s.Tor = &discovery.TorState{Reachable: true, Bootstrap: 100, CircuitEstablished: true}
	if fs := (TUN003{}).Evaluate(true, s); len(fs) != 0 {
		t.Fatalf("healthy tor: %v", fs)
	}
	if !TorRequired("vpn+tor") || TorRequired("auto") || !TorQueried("auto") || TorQueried("wireguard") {
		t.Fatal("egress.type mapping")
	}
}

func TestTUN008_Evaluate(t *testing.T) {
	s := snap()
	s.Tor = &discovery.TorState{Reachable: true, UseBridges: true, Transports: []string{"obfs4", "snowflake", "webtunnel"}}
	f := onlyFinding(t, (TUN008{}).Evaluate("strict", s), "TUN-008", contracts.SeverityCritical)
	if f.Data["transport"] != "snowflake" {
		t.Fatalf("%v", f.Data)
	}
	if fs := (TUN008{}).Evaluate("reactive", s); len(fs) != 0 {
		t.Fatal("only the strict guard cannot follow dynamic transports")
	}
	s.Tor.UseBridges = false
	if fs := (TUN008{}).Evaluate("strict", s); len(fs) != 0 {
		t.Fatal("bridges configured but not in use")
	}
}

func TestTUN002_TrackerForgetsGonePeers(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	s := snap()
	tr := NewTxTracker()
	for i := range 50 {
		s.Tunnels[0].Peers = []discovery.WGPeer{{Endpoint: fmt.Sprintf("198.51.100.%d:51820", i), TxBytes: int64(i)}}
		(TUN002{}).Evaluate(tr, s, now)
	}
	if len(tr.last) != 1 || len(tr.grew) > 1 {
		t.Fatalf("tracker keeps %d peers", len(tr.last))
	}
}
