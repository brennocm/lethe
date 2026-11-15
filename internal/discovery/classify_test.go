package discovery

import (
	"reflect"
	"testing"
)

func TestClassify_Topologies(t *testing.T) {
	links := []LinkInfo{
		{Index: 1, Name: "lo", Type: "device"},
		{Index: 2, Name: "enp3s0", Type: "device", HasDevice: true},
		{Index: 3, Name: "wlp2s0", Type: "device", HasDevice: true},
		{Index: 4, Name: "wg0", Type: "wireguard"},
		{Index: 5, Name: "tun0", Type: "tuntap"},
		{Index: 6, Name: "enp3s0.10", Type: "vlan", ParentIndex: 2},
		{Index: 7, Name: "br0", Type: "bridge"},
		{Index: 8, Name: "vnet0", Type: "tuntap", MasterIndex: 7},
		{Index: 9, Name: "docker0", Type: "bridge"},
		{Index: 10, Name: "veth1a", Type: "veth", MasterIndex: 9},
		{Index: 11, Name: "dummy0", Type: "dummy"},
		{Index: 12, Name: "bond0", Type: "bond"},
		{Index: 13, Name: "enp4s0", Type: "device", HasDevice: true, MasterIndex: 12},
		{Index: 14, Name: "br-lan", Type: "bridge"},
		{Index: 15, Name: "enp5s0", Type: "device", HasDevice: true, MasterIndex: 14},
		{Index: 16, Name: "vxlan0", Type: "vxlan"},
		{Index: 17, Name: "mv0", Type: "macvlan", ParentIndex: 9},
		{Index: 18, Name: "ppp0", Type: "ppp"},
		{Index: 19, Name: "proton0", Type: "tuntap"},
		{Index: 20, Name: "mullvad-wg", Type: "unknownkind"},
		{Index: 21, Name: "bond1", Type: "bond"},
		{Index: 22, Name: "lethe-st0", Type: "dummy"},
		{Index: 23, Name: "veth-test", Type: "veth"},
	}
	got := Classify(links, Overrides{Egress: []string{"veth-test"}})
	want := map[string]Class{
		"lo": ClassLoopback, "enp3s0": ClassEgress, "wlp2s0": ClassEgress, "wg0": ClassTunnel, "tun0": ClassTunnel,
		"enp3s0.10": ClassEgress, "br0": ClassInternal, "vnet0": ClassInternal, "docker0": ClassInternal, "veth1a": ClassInternal,
		"dummy0": ClassInternal, "bond0": ClassEgress, "enp4s0": ClassEgress, "br-lan": ClassEgress, "enp5s0": ClassEgress,
		"vxlan0": ClassUnknown, "mv0": ClassInternal, "ppp0": ClassEgress, "proton0": ClassTunnel, "mullvad-wg": ClassTunnel,
		"bond1": ClassUnknown, "lethe-st0": ClassInternal, "veth-test": ClassEgress,
	}
	for name, c := range want {
		if got[name] != c {
			t.Errorf("%s = %s, want %s", name, got[name], c)
		}
	}
	capture := CaptureIfaces(links, got, Overrides{Egress: []string{"veth-test"}})
	if !reflect.DeepEqual(capture, []string{"enp3s0", "enp4s0", "enp5s0", "veth-test", "wlp2s0"}) {
		t.Fatalf("capture = %v", capture)
	}
}

func TestClassify_InternalOverrideAndCycles(t *testing.T) {
	links := []LinkInfo{
		{Index: 2, Name: "eth0", Type: "device", HasDevice: true},
		{Index: 3, Name: "v1", Type: "vlan", ParentIndex: 4},
		{Index: 4, Name: "v2", Type: "vlan", ParentIndex: 3}, // pathological cycle
	}
	got := Classify(links, Overrides{Internal: []string{"eth0"}})
	if got["eth0"] != ClassInternal {
		t.Fatal("internal override ignored")
	}
	if got["v1"] != ClassUnknown && got["v1"] != ClassInternal {
		t.Fatalf("cycle produced %s", got["v1"])
	}
}

// TestClassify_NewUnknownIsFailClosed documents principle 1: an unknown kind is never internal.
func TestClassify_NewUnknownIsFailClosed(t *testing.T) {
	got := Classify([]LinkInfo{{Index: 9, Name: "weird0", Type: "geneve"}}, Overrides{})
	if got["weird0"] != ClassUnknown {
		t.Fatal(got["weird0"])
	}
}
