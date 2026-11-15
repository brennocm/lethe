//go:build e2e

package e2e

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/sensors/netlinkmon"
	"lethe/test/netlab"
)

// TestE2E_ST_NET006_DummyLinkAndRoutes covers ST-NET-006 and the NET-005 sources.
func TestE2E_ST_NET006_DummyLinkAndRoutes(t *testing.T) {
	lab := netlab.New(t, false)
	initial, err := netlinkmon.Links()
	if err != nil {
		t.Fatal(err)
	}
	tr := netlinkmon.NewTracker(initial)
	links := make(chan netlinkmon.LinkEvent, 64)
	routes := make(chan netlinkmon.RouteChange, 64)
	beats := make(chan time.Time, 64)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var m netlinkmon.Monitor
	go func() {
		done <- m.Run(ctx, links, routes, func(ts time.Time) {
			select {
			case beats <- ts:
			default:
			}
		})
	}()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("monitor: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond) // subscriptions in place

	const name = "lethe-st0"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(lab.In(lab.DUT, func() error {
		return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}})
	}))
	defer func() {
		_ = lab.In(lab.DUT, func() error {
			if l, err := netlink.LinkByName(name); err == nil {
				return netlink.LinkDel(l)
			}
			return nil
		})
	}()
	var sawNew bool
	timeout := time.After(3 * time.Second)
	for !sawNew {
		select {
		case ev := <-links:
			if ev.Name != name {
				continue
			}
			isNew, wasUp := tr.Apply(ev)
			fs := (checks.NET006{}).Evaluate(checks.LinkChange{Name: ev.Name, New: isNew, Up: ev.Up, WasUp: wasUp, Class: discovery.ClassUnknown})
			if !isNew || len(fs) != 1 || fs[0].Severity != contracts.SeverityWarning {
				t.Fatalf("new=%v findings=%+v", isNew, fs)
			}
			sawNew = true
		case <-timeout:
			t.Fatal("no RTM_NEWLINK for the dummy link")
		}
	}

	must(lab.In(lab.DUT, func() error {
		l, err := netlink.LinkByName(name)
		if err != nil {
			return err
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return err
		}
		_, dst, _ := net.ParseCIDR("192.0.2.0/24")
		return netlink.RouteAdd(&netlink.Route{LinkIndex: l.Attrs().Index, Dst: dst, Table: 100})
	}))
	rule := netlink.NewRule()
	rule.Table, rule.Priority = 100, 1234
	_, rsrc, _ := net.ParseCIDR("10.99.0.0/16")
	rule.Src = rsrc
	must(lab.In(lab.DUT, func() error { return netlink.RuleAdd(rule) }))

	snap := &discovery.Snapshot{}
	var sawRoute, sawRule bool
	timeout = time.After(4 * time.Second)
	for !sawRoute || !sawRule {
		select {
		case c := <-routes:
			fs := (checks.NET005{}).Evaluate(c, snap)
			switch {
			case c.Kind == "route" && c.Table == 100 && c.Dst == "192.0.2.0/24" && c.Iface == name && c.Op == "new":
				sawRoute = len(fs) == 1
			case c.Kind == "rule" && c.Table == 100 && c.Op == "new":
				sawRule = len(fs) == 1
			}
		case <-timeout:
			t.Fatalf("route=%v rule=%v", sawRoute, sawRule)
		}
	}
	select {
	case <-beats:
	case <-time.After(2 * time.Second):
		t.Fatal("no heartbeat from netlinkmon")
	}
}
