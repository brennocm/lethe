package discovery

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
)

// KernelLink is a link as read from the kernel.
type KernelLink struct {
	LinkInfo
	Up      bool
	Running bool
	MAC     string
	PermMAC string
	Addrs   []netip.Prefix
}

// RawRoute is a route as read from the kernel.
type RawRoute struct {
	Dst       netip.Prefix // invalid prefix = default route
	Gateway   netip.Addr
	LinkIndex int
	Table     int
}

// WGDevice is a WireGuard device read with wgctrl.
type WGDevice struct {
	Name   string
	FwMark int
	Peers  []WGPeerRaw
}

// WGPeerRaw is one WireGuard peer.
type WGPeerRaw struct {
	Endpoint netip.AddrPort
	Stats    WGPeer
}

// Kernel is the kernel state discovery reads. NetlinkKernel is the real one.
type Kernel interface {
	Links() ([]KernelLink, error)
	DefaultRoutes(family int) ([]RawRoute, error)
	RouteGet(dst netip.Addr) (RawRoute, error)
	WireGuard() ([]WGDevice, error)
	IPv6Disabled(iface string) bool
	LegacyIPTables() bool
}

// NetlinkKernel reads the current network namespace. Root is "/" except in tests.
type NetlinkKernel struct{ Root string }

func (k NetlinkKernel) path(p string) string { return filepath.Join(k.rootOr(), p) }

func (k NetlinkKernel) rootOr() string {
	if k.Root == "" {
		return "/"
	}
	return k.Root
}

// Links lists every link with its addresses.
func (k NetlinkKernel) Links() ([]KernelLink, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}
	out := make([]KernelLink, 0, len(links))
	for _, l := range links {
		a := l.Attrs()
		kl := KernelLink{
			LinkInfo: LinkInfo{Index: a.Index, Name: a.Name, Type: l.Type(), ParentIndex: a.ParentIndex, MasterIndex: a.MasterIndex},
			Up:       a.Flags&net.FlagUp != 0,
			Running:  a.RawFlags&unix.IFF_RUNNING != 0,
		}
		if _, err := os.Stat(k.path("sys/class/net/" + a.Name + "/device")); err == nil {
			kl.HasDevice = true
		}
		if len(a.HardwareAddr) > 0 {
			kl.MAC = a.HardwareAddr.String()
		}
		if len(a.PermHWAddr) > 0 {
			kl.PermMAC = a.PermHWAddr.String()
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
		if err == nil {
			for _, ad := range addrs {
				if p, ok := prefixOf(ad.IPNet); ok {
					kl.Addrs = append(kl.Addrs, p)
				}
			}
		}
		out = append(out, kl)
	}
	return out, nil
}

func prefixOf(n *net.IPNet) (netip.Prefix, bool) {
	if n == nil {
		return netip.Prefix{}, false
	}
	a, ok := netip.AddrFromSlice(n.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), ones), true
}

// DefaultRoutes lists default routes of a family in every table.
func (k NetlinkKernel) DefaultRoutes(family int) ([]RawRoute, error) {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	var out []RawRoute
	for _, r := range routes {
		if r.Dst != nil {
			if ones, _ := r.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		if r.Type != unix.RTN_UNICAST {
			continue
		}
		out = append(out, toRaw(r))
	}
	return out, nil
}

func toRaw(r netlink.Route) RawRoute {
	rr := RawRoute{LinkIndex: r.LinkIndex, Table: r.Table}
	if p, ok := prefixOf(r.Dst); ok {
		rr.Dst = p
	}
	if g, ok := netip.AddrFromSlice(r.Gw); ok {
		rr.Gateway = g.Unmap()
	}
	return rr
}

// RouteGet asks the kernel which route a packet to dst would take (ip route get).
func (k NetlinkKernel) RouteGet(dst netip.Addr) (RawRoute, error) {
	routes, err := netlink.RouteGet(dst.AsSlice())
	if err != nil {
		return RawRoute{}, err
	}
	if len(routes) == 0 {
		return RawRoute{}, errors.New("no route")
	}
	return toRaw(routes[0]), nil
}

// WireGuard lists WireGuard devices and peers.
func (k NetlinkKernel) WireGuard() ([]WGDevice, error) {
	c, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()
	devs, err := c.Devices()
	if err != nil {
		return nil, err
	}
	out := make([]WGDevice, 0, len(devs))
	for _, d := range devs {
		wd := WGDevice{Name: d.Name, FwMark: d.FirewallMark}
		for _, p := range d.Peers {
			pr := WGPeerRaw{Stats: WGPeer{LastHandshake: p.LastHandshakeTime, TxBytes: p.TransmitBytes, RxBytes: p.ReceiveBytes}}
			if p.Endpoint != nil {
				if a, ok := netip.AddrFromSlice(p.Endpoint.IP); ok {
					pr.Endpoint = netip.AddrPortFrom(a.Unmap(), uint16(p.Endpoint.Port)) // #nosec G115 -- UDP port
				}
			}
			wd.Peers = append(wd.Peers, pr)
		}
		out = append(out, wd)
	}
	return out, nil
}

// IPv6Disabled reads net.ipv6.conf.<iface>.disable_ipv6 (per network namespace).
func (k NetlinkKernel) IPv6Disabled(iface string) bool {
	raw, err := os.ReadFile(k.path("proc/sys/net/ipv6/conf/" + iface + "/disable_ipv6")) // #nosec G304 -- fixed procfs path
	if err != nil {
		return true // no IPv6 support at all
	}
	return strings.TrimSpace(string(raw)) == "1"
}

// LegacyIPTables reports iptables-legacy tables loaded in the kernel (TUN-007).
func (k NetlinkKernel) LegacyIPTables() bool {
	for _, f := range []string{"proc/net/ip_tables_names", "proc/net/ip6_tables_names"} {
		if raw, err := os.ReadFile(k.path(f)); err == nil && strings.TrimSpace(string(raw)) != "" { // #nosec G304 -- fixed procfs path
			return true
		}
	}
	return false
}
