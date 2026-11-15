//go:build e2e

// Package netlab builds the spec §23.2 test topology out of network namespaces:
//
//	"dut" (the namespace the test process already runs in, created by scripts/e2e.sh)
//	  ltx0 (veth, declared egress)  <->  ns "isp": isp0 10.0.0.1, uplink to ns "vpn"
//	  ltwg0 (WireGuard client)            ns "vpn": 198.18.0.2, WireGuard server ltwgs0
//
// The isp namespace blackholes the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
// 203.0.113.0/24, 2001:db8::/32) so nothing a test sends can go anywhere.
//
// Safety: New refuses to run in the host network namespace.
package netlab

import (
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Interface and address plan.
const (
	DUTEgress   = "ltx0"
	DUTTunnel   = "ltwg0"
	ISPDown     = "isp0"
	ISPUp       = "isp1"
	VPNUp       = "vpn0"
	VPNTunnel   = "ltwgs0"
	DUTAddr     = "10.0.0.2/24"
	ISPDownAddr = "10.0.0.1/24"
	ISPUpAddr   = "198.18.0.1/24"
	VPNAddr     = "198.18.0.2/24"
	VPNAltAddr  = "198.18.0.3/24" // second server address (endpoint change, AC-05)
	WGClient    = "10.200.0.2/24"
	WGServer    = "10.200.0.1/24"
	WGPort      = 51820
	// EgressMetric is the metric of the egress default route while the tunnel is up.
	EgressMetric = 1000
)

// Lab is one topology. Close releases the namespaces.
type Lab struct {
	DUT, ISP, VPN netns.NsHandle
	mu            sync.Mutex
}

// AssertNotHostNamespace aborts unless the process runs in a fresh network namespace.
func AssertNotHostNamespace() error {
	self, err1 := os.Readlink("/proc/self/ns/net")
	host, err2 := os.Readlink("/proc/1/ns/net")
	if err1 == nil && err2 == nil {
		if self == host {
			return errors.New("netlab: refusing to run in the host network namespace (use mise run e2e)")
		}
		return nil
	}
	// /proc/1 is not readable from a user namespace: require a fresh namespace instead.
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("netlab: list links: %w", err)
	}
	for _, l := range links {
		if n := l.Attrs().Name; n != "lo" && !strings.HasPrefix(n, "lt") {
			return fmt.Errorf("netlab: namespace has interface %q; refusing to touch what may be the host (use mise run e2e)", n)
		}
	}
	return nil
}

// New builds the topology. withWG adds the WireGuard tunnel and makes it the default route.
func New(t testing.TB, withWG bool) *Lab {
	t.Helper()
	if err := AssertNotHostNamespace(); err != nil {
		t.Fatal(err)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	dut, err := netns.Get()
	if err != nil {
		t.Fatal(err)
	}
	l := &Lab{DUT: dut}
	t.Cleanup(l.Close)
	if l.ISP, err = netns.New(); err != nil {
		t.Fatalf("netns isp: %v", err)
	}
	if l.VPN, err = netns.New(); err != nil {
		t.Fatalf("netns vpn: %v", err)
	}
	if err := netns.Set(dut); err != nil {
		t.Fatal(err)
	}
	must(t, l.In(l.DUT, func() error { return setUp("lo") }))
	must(t, l.In(l.ISP, func() error { return setUp("lo") }))
	must(t, l.In(l.VPN, func() error { return setUp("lo") }))
	must(t, l.vethPair(DUTEgress, l.DUT, ISPDown, l.ISP))
	must(t, l.vethPair(ISPUp, l.ISP, VPNUp, l.VPN))
	must(t, l.In(l.DUT, func() error {
		return errors.Join(addAddr(DUTEgress, DUTAddr), setUp(DUTEgress), defaultVia("10.0.0.1"))
	}))
	must(t, l.In(l.ISP, func() error {
		return errors.Join(addAddr(ISPDown, ISPDownAddr), setUp(ISPDown), addAddr(ISPUp, ISPUpAddr), setUp(ISPUp),
			sysctl("net/ipv4/ip_forward", "1"), blackholes())
	}))
	must(t, l.In(l.VPN, func() error {
		return errors.Join(addAddr(VPNUp, VPNAddr), addAddr(VPNUp, VPNAltAddr), setUp(VPNUp), defaultVia("198.18.0.1"))
	}))
	if withWG {
		must(t, l.wireguard())
	}
	return l
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// In runs fn with the calling OS thread switched into ns.
func (l *Lab) In(ns netns.NsHandle, fn func() error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := netns.Get()
	if err != nil {
		return err
	}
	defer func() { _ = netns.Set(orig); _ = orig.Close() }()
	if err := netns.Set(ns); err != nil {
		return err
	}
	return fn()
}

// Close releases the extra namespaces (their interfaces disappear with them).
func (l *Lab) Close() {
	for _, h := range []netns.NsHandle{l.ISP, l.VPN} {
		if h.IsOpen() {
			_ = h.Close()
		}
	}
	_ = l.In(l.DUT, func() error {
		for _, n := range []string{DUTEgress, DUTTunnel} {
			if link, err := netlink.LinkByName(n); err == nil {
				_ = netlink.LinkDel(link)
			}
		}
		return nil
	})
}

func (l *Lab) vethPair(a string, nsA netns.NsHandle, b string, nsB netns.NsHandle) error {
	return l.In(nsA, func() error {
		veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: a}, PeerName: b}
		if err := netlink.LinkAdd(veth); err != nil {
			return fmt.Errorf("veth %s/%s: %w", a, b, err)
		}
		peer, err := netlink.LinkByName(b)
		if err != nil {
			return err
		}
		return netlink.LinkSetNsFd(peer, int(nsB))
	})
}

func (l *Lab) wireguard() error {
	cliKey, _ := wgtypes.GeneratePrivateKey()
	srvKey, _ := wgtypes.GeneratePrivateKey()
	port := WGPort
	keepalive := 2 * time.Second
	_, all, _ := net.ParseCIDR("0.0.0.0/0")
	_, cliNet, _ := net.ParseCIDR("10.200.0.2/32")
	err := l.In(l.VPN, func() error {
		if err := addWG(VPNTunnel); err != nil {
			return err
		}
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		if err := c.ConfigureDevice(VPNTunnel, wgtypes.Config{PrivateKey: &srvKey, ListenPort: &port,
			Peers: []wgtypes.PeerConfig{{PublicKey: cliKey.PublicKey(), AllowedIPs: []net.IPNet{*cliNet}}}}); err != nil {
			return err
		}
		return errors.Join(addAddr(VPNTunnel, WGServer), setUp(VPNTunnel))
	})
	if err != nil {
		return fmt.Errorf("wireguard server: %w", err)
	}
	return l.In(l.DUT, func() error {
		if err := addWG(DUTTunnel); err != nil {
			return err
		}
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		ep := &net.UDPAddr{IP: net.ParseIP("198.18.0.2"), Port: WGPort}
		if err := c.ConfigureDevice(DUTTunnel, wgtypes.Config{PrivateKey: &cliKey,
			Peers: []wgtypes.PeerConfig{{PublicKey: srvKey.PublicKey(), Endpoint: ep, AllowedIPs: []net.IPNet{*all}, PersistentKeepaliveInterval: &keepalive}}}); err != nil {
			return err
		}
		if err := errors.Join(addAddr(DUTTunnel, WGClient), setUp(DUTTunnel)); err != nil {
			return err
		}
		// endpoint via the egress link, everything else through the tunnel
		eg, err := netlink.LinkByName(DUTEgress)
		if err != nil {
			return err
		}
		_, host, _ := net.ParseCIDR("198.18.0.0/24")
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: eg.Attrs().Index, Dst: host, Gw: net.ParseIP("10.0.0.1")}); err != nil {
			return fmt.Errorf("endpoint route: %w", err)
		}
		wg, err := netlink.LinkByName(DUTTunnel)
		if err != nil {
			return err
		}
		// Like NetworkManager with a VPN up: the egress default stays, with a worse metric, so a
		// socket bound to the egress (SO_BINDTODEVICE) still leaks, which is what the sensor sees.
		if err := netlink.RouteDel(&netlink.Route{Dst: nil, Gw: net.ParseIP("10.0.0.1"), LinkIndex: eg.Attrs().Index}); err != nil {
			return fmt.Errorf("drop egress default: %w", err)
		}
		if err := netlink.RouteAdd(&netlink.Route{LinkIndex: eg.Attrs().Index, Gw: net.ParseIP("10.0.0.1"), Priority: EgressMetric}); err != nil {
			return fmt.Errorf("egress default with metric: %w", err)
		}
		_, def4, _ := net.ParseCIDR("0.0.0.0/0")
		return netlink.RouteAdd(&netlink.Route{LinkIndex: wg.Attrs().Index, Dst: def4, Scope: netlink.SCOPE_LINK})
	})
}

func addWG(name string) error {
	if err := netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: name}, LinkType: "wireguard"}); err != nil {
		return fmt.Errorf("create wireguard %s (kernel module missing?): %w", name, err)
	}
	return nil
}

func setUp(name string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	return netlink.LinkSetUp(l)
}

func addAddr(name, cidr string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	a, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	return netlink.AddrAdd(l, a)
}

func defaultVia(gw string) error {
	return netlink.RouteAdd(&netlink.Route{Gw: net.ParseIP(gw)})
}

func blackholes() error {
	var errs []error
	for _, c := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, dst, _ := net.ParseCIDR(c)
		errs = append(errs, netlink.RouteAdd(&netlink.Route{Dst: dst, Type: 6 /* RTN_BLACKHOLE */}))
	}
	return errors.Join(errs...)
}

func sysctl(key, val string) error {
	return os.WriteFile("/proc/sys/"+key, []byte(val), 0o600)
}

// WaitHandshake waits until the client tunnel completed a WireGuard handshake.
func (l *Lab) WaitHandshake(t testing.TB, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var ok bool
		_ = l.In(l.DUT, func() error {
			c, err := wgctrl.New()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			d, err := c.Device(DUTTunnel)
			if err == nil && len(d.Peers) > 0 && !d.Peers[0].LastHandshakeTime.IsZero() {
				ok = true
			}
			return nil
		})
		if ok {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("netlab: WireGuard handshake did not complete")
}

// IPv6 plan for EgressIPv6 (inside 2001:db8::/32, blackholed beyond the isp namespace).
const (
	DUTAddr6 = "2001:db8:1::2/64"
	ISPAddr6 = "2001:db8:1::1/64"
)

// EgressIPv6 gives the egress link a global IPv6 address and a default v6 route through it,
// while the tunnel stays v4-only (AC-03, ST-NET-003). Addresses skip DAD (IFA_F_NODAD).
func (l *Lab) EgressIPv6(t testing.TB) {
	t.Helper()
	must(t, l.In(l.ISP, func() error {
		return errors.Join(addAddrNoDAD(ISPDown, ISPAddr6), sysctl("net/ipv6/conf/all/forwarding", "1"))
	}))
	must(t, l.In(l.DUT, func() error {
		if err := addAddrNoDAD(DUTEgress, DUTAddr6); err != nil {
			return err
		}
		eg, err := netlink.LinkByName(DUTEgress)
		if err != nil {
			return err
		}
		_, def6, _ := net.ParseCIDR("::/0")
		return netlink.RouteAdd(&netlink.Route{LinkIndex: eg.Attrs().Index, Dst: def6, Gw: net.ParseIP("2001:db8:1::1")})
	}))
}

func addAddrNoDAD(name, cidr string) error {
	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	a, err := netlink.ParseAddr(cidr)
	if err != nil {
		return err
	}
	a.Flags = 0x02 // IFA_F_NODAD
	return netlink.AddrAdd(l, a)
}
