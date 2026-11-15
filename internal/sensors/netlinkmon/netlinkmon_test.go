package netlinkmon

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestNET006_Tracker(t *testing.T) {
	tr := NewTracker([]LinkEvent{{Index: 1, Name: "lo", Up: true}, {Index: 2, Name: "eth0", Up: false}})
	if n, w := tr.Apply(LinkEvent{Index: 2, Name: "eth0", Up: true}); n || w {
		t.Fatalf("eth0 up: new=%v wasUp=%v", n, w)
	}
	if n, w := tr.Apply(LinkEvent{Index: 2, Name: "eth0", Up: true}); n || !w {
		t.Fatalf("eth0 repeat: new=%v wasUp=%v", n, w)
	}
	if n, _ := tr.Apply(LinkEvent{Index: 9, Name: "usb0"}); !n {
		t.Fatal("usb0 must be new")
	}
	if n, w := tr.Apply(LinkEvent{Index: 9, Name: "usb0", Deleted: true}); n || w {
		t.Fatal("delete")
	}
	if n, _ := tr.Apply(LinkEvent{Index: 9, Name: "usb0"}); !n {
		t.Fatal("re-added link is new again")
	}
}

func TestNET005_RouteChange(t *testing.T) {
	_, dst, _ := net.ParseCIDR("192.0.2.0/24")
	_, zero, _ := net.ParseCIDR("0.0.0.0/0")
	cases := []struct {
		u    netlink.RouteUpdate
		want RouteChange
	}{
		{netlink.RouteUpdate{Type: unix.RTM_NEWROUTE, Route: netlink.Route{Family: unix.AF_INET, Table: 254}},
			RouteChange{Kind: "route", Op: "new", Family: "ipv4", Table: 254, Iface: "eth0", Dst: "default"}},
		{netlink.RouteUpdate{Type: unix.RTM_NEWROUTE, Route: netlink.Route{Family: unix.AF_INET, Table: 254, Dst: zero}},
			RouteChange{Kind: "route", Op: "new", Family: "ipv4", Table: 254, Iface: "eth0", Dst: "default"}},
		{netlink.RouteUpdate{Type: unix.RTM_DELROUTE, Route: netlink.Route{Family: unix.AF_INET6, Table: 100, Dst: dst}},
			RouteChange{Kind: "route", Op: "del", Family: "ipv6", Table: 100, Iface: "eth0", Dst: "192.0.2.0/24"}},
	}
	for _, c := range cases {
		if got := routeChange(c.u, "eth0"); got != c.want {
			t.Fatalf("got %+v want %+v", got, c.want)
		}
	}
}

func TestNET005_DiffRules(t *testing.T) {
	a := rule{Family: unix.AF_INET, Priority: 0, Table: 255}
	b := rule{Family: unix.AF_INET, Priority: 32765, Table: 51820, Mark: 51820, Invert: true}
	c := rule{Family: unix.AF_INET6, Priority: 100, Table: 7}
	got := diffRules(map[rule]bool{a: true, b: true}, map[rule]bool{a: true, c: true})
	want := []RouteChange{
		{Kind: "rule", Op: "del", Family: "ipv4", Table: 51820, Mark: 51820},
		{Kind: "rule", Op: "new", Family: "ipv6", Table: 7},
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v", got)
	}
}
