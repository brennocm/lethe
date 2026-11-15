package checks

import (
	"testing"

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
	if RequiresTunnel("tor") || !RequiresTunnel("auto") || !RequiresTunnel("vpn+tor") {
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
