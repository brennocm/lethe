package discovery

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Snapshot is everything discovery knows at one instant (lethe discover --json, schema: discover).
type Snapshot struct {
	TakenAt        time.Time `json:"taken_at"`
	Ifaces         []Iface   `json:"ifaces"`
	CaptureIfaces  []string  `json:"capture_ifaces"`
	Tunnels        []Tunnel  `json:"tunnels"`
	Endpoints      []string  `json:"endpoints"` // "ip:port/proto", sorted
	Routes         Routes    `json:"routes"`
	DNS            DNS       `json:"dns"`
	LegacyIPTables bool      `json:"legacy_iptables"`
	Unavailable    []string  `json:"unavailable"` // sources that could not be read (visibility gaps)
}

// Iface is one interface with its class.
type Iface struct {
	LinkInfo
	Class        Class    `json:"class"`
	Up           bool     `json:"up"`
	Running      bool     `json:"running"`
	MAC          string   `json:"mac,omitempty"`
	PermMAC      string   `json:"perm_mac,omitempty"`
	Addrs        []string `json:"addrs"`
	GlobalV6     []string `json:"global_v6"`
	IPv6Disabled bool     `json:"ipv6_disabled"`
}

// Tunnel is one tunnel interface and what is known about its peers.
type Tunnel struct {
	Iface  string   `json:"iface"`
	Kind   string   `json:"kind"` // wireguard | tun | generic
	FwMark int      `json:"fwmark,omitempty"`
	Peers  []WGPeer `json:"peers,omitempty"`
}

// WGPeer is a WireGuard peer.
type WGPeer struct {
	Endpoint      string    `json:"endpoint,omitempty"`
	LastHandshake time.Time `json:"last_handshake"`
	TxBytes       int64     `json:"tx_bytes"`
	RxBytes       int64     `json:"rx_bytes"`
}

// Routes summarizes default routes and the effective route of the test destinations (NET-004).
type Routes struct {
	DefaultV4 []Route `json:"default_v4"`
	DefaultV6 []Route `json:"default_v6"`
	ProbeV4   *Route  `json:"probe_v4,omitempty"` // route to 192.0.2.1
	ProbeV6   *Route  `json:"probe_v6,omitempty"` // route to 2001:db8::1
}

// Route is one route with the class of its output interface.
type Route struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gateway,omitempty"`
	Iface   string `json:"iface"`
	Class   Class  `json:"class"`
	Table   int    `json:"table"`
}

// Probe destinations for NET-004 (RFC 5737 / RFC 3849: never routed on the internet).
var (
	ProbeV4 = netip.MustParseAddr("192.0.2.1")
	ProbeV6 = netip.MustParseAddr("2001:db8::1")
)

// DNS is the effective resolver configuration.
type DNS struct {
	ResolvConf ResolvConf `json:"resolv_conf"`
	Resolved   Resolved   `json:"resolved"`
}

// ResolvConf is /etc/resolv.conf after following symlinks.
type ResolvConf struct {
	Path        string   `json:"path"`
	Target      string   `json:"target,omitempty"`
	Nameservers []string `json:"nameservers"`
	Stub        bool     `json:"stub"` // points at the systemd-resolved stub (127.0.0.53/54)
}

// Resolved is systemd-resolved state read over D-Bus.
type Resolved struct {
	Available bool           `json:"available"`
	Links     []ResolvedLink `json:"links"`
}

// ResolvedLink is per-link DNS from systemd-resolved.
type ResolvedLink struct {
	Iface        string   `json:"iface"`
	Servers      []string `json:"servers"`
	DefaultRoute bool     `json:"default_route"`
	Domains      []string `json:"domains"`
}

// Endpoint is a tunnel endpoint (IP, protocol, port).
type Endpoint struct {
	Addr  netip.AddrPort
	Proto string // udp | tcp
}

func (e Endpoint) String() string { return e.Addr.String() + "/" + e.Proto }

// ParseEndpoint parses "ip:port/proto".
func ParseEndpoint(s string) (Endpoint, error) {
	addr, proto, ok := strings.Cut(s, "/")
	if !ok || (proto != "udp" && proto != "tcp") {
		return Endpoint{}, fmt.Errorf("endpoint %q: want ip:port/udp|tcp", s)
	}
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || ap.Port() == 0 {
		return Endpoint{}, fmt.Errorf("endpoint %q: bad address", s)
	}
	return Endpoint{Addr: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), Proto: proto}, nil
}

// Iface returns the interface with this name.
func (s Snapshot) Iface(name string) (Iface, bool) {
	for _, i := range s.Ifaces {
		if i.Name == name {
			return i, true
		}
	}
	return Iface{}, false
}

// ParsedEndpoints returns the endpoints as values.
func (s Snapshot) ParsedEndpoints() []Endpoint {
	var out []Endpoint
	for _, e := range s.Endpoints {
		if ep, err := ParseEndpoint(e); err == nil {
			out = append(out, ep)
		}
	}
	return out
}
