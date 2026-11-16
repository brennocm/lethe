package discovery

import (
	"net/netip"
	"testing"

	"lethe/internal/sensors/sockdiag"
)

var (
	vpnOwners = map[uint32]sockdiag.Owner{
		10: {PID: 500, Exe: "/usr/sbin/openvpn", UID: 0},
		11: {PID: 500, Exe: "/usr/sbin/openvpn", UID: 0},
		20: {PID: 900, Exe: "/usr/bin/firefox", UID: 1000},
		30: {PID: 700, Exe: "/usr/sbin/NetworkManager", UID: 0},
	}
	vpnSocks = []sockdiag.Sock{
		// openvpn over TCP, connected to its server
		{Proto: "tcp", Local: netip.MustParseAddrPort("10.0.0.2:40000"), Remote: netip.MustParseAddrPort("203.0.113.9:443"), Inode: 10},
		// openvpn over UDP: unconnected, bound to 1194
		{Proto: "udp", Local: netip.MustParseAddrPort("0.0.0.0:1194"), Inode: 11},
		// the browser
		{Proto: "tcp", Local: netip.MustParseAddrPort("10.0.0.2:50000"), Remote: netip.MustParseAddrPort("192.0.2.80:443"), Inode: 20},
		{Proto: "udp", Local: netip.MustParseAddrPort("0.0.0.0:5353"), Inode: 20},
		// NetworkManager is not a VPN client, even though openvpn may run in its cgroup
		{Proto: "tcp", Local: netip.MustParseAddrPort("10.0.0.2:41000"), Remote: netip.MustParseAddrPort("192.0.2.10:80"), Inode: 30},
		// management socket on loopback
		{Proto: "tcp", Local: netip.MustParseAddrPort("127.0.0.1:7505"), Remote: netip.MustParseAddrPort("127.0.0.1:41234"), Inode: 10},
	}
)

func TestTUN001_VPNScanFindsClientAndEndpoints(t *testing.T) {
	cg := func(pid int) (string, uint64, uint32, bool) {
		if pid == 500 {
			return "system.slice/openvpn-client@work.service", 4242, 2, true
		}
		return "", 0, 0, false
	}
	outside := func(a netip.Addr) bool { return a != netip.MustParseAddr("198.18.0.1") }
	clients, eps := vpnScan(vpnSocks, vpnOwners, cg, outside)
	if len(clients) != 1 || clients[0].PID != 500 || clients[0].CgroupID != 4242 || clients[0].CgroupLevel != 2 {
		t.Fatalf("clients %+v", clients)
	}
	if len(eps) != 1 || eps[0].String() != "203.0.113.9:443/tcp" {
		t.Fatalf("endpoints %v", eps)
	}
	// a remote reached through the tunnel itself (the client's API) is not an endpoint
	routed := append([]sockdiag.Sock{}, vpnSocks...)
	routed = append(routed, sockdiag.Sock{Proto: "tcp", Local: netip.MustParseAddrPort("10.8.0.2:42000"), Remote: netip.MustParseAddrPort("198.18.0.1:443"), Inode: 10})
	if _, eps := vpnScan(routed, vpnOwners, cg, outside); len(eps) != 1 {
		t.Fatalf("tunnel-routed remote counted: %v", eps)
	}
}

func TestNET002_LearnBlocked(t *testing.T) {
	clients := []VPNClient{{PID: 500, Exe: "/usr/sbin/openvpn"}}
	cases := []struct {
		name     string
		proto    string
		src, dst string
		socks    []sockdiag.Sock
		want     string
	}{
		{"udp client to a new server", "udp", "10.0.0.2:1194", "198.51.100.20:1194", vpnSocks, "198.51.100.20:1194/udp"},
		{"tcp exact tuple", "tcp", "10.0.0.2:40000", "203.0.113.9:443", vpnSocks, "203.0.113.9:443/tcp"},
		{"browser is never learned", "tcp", "10.0.0.2:50000", "192.0.2.80:443", vpnSocks, ""},
		{"mdns from the browser", "udp", "10.0.0.2:5353", "198.51.100.1:5353", vpnSocks, ""},
		{"NetworkManager is not the client", "tcp", "10.0.0.2:41000", "192.0.2.10:80", vpnSocks, ""},
		{"no socket", "udp", "10.0.0.2:9999", "198.51.100.20:1194", vpnSocks, ""},
		{"ambiguous port", "udp", "10.0.0.2:1194", "198.51.100.20:1194",
			append(append([]sockdiag.Sock{}, vpnSocks...), sockdiag.Sock{Proto: "udp", Local: netip.MustParseAddrPort("10.0.0.2:1194"), Inode: 20}), ""},
		{"broadcast", "udp", "10.0.0.2:1194", "255.255.255.255:1194", vpnSocks, ""},
		{"icmp", "icmp", "10.0.0.2:0", "198.51.100.20:0", vpnSocks, ""},
	}
	for _, c := range cases {
		e, ok := LearnBlocked(c.proto, netip.MustParseAddrPort(c.src), netip.MustParseAddrPort(c.dst), c.socks, vpnOwners, clients)
		got := ""
		if ok {
			got = e.String()
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	// the process must be a client of this discovery, not merely named like one
	if _, ok := LearnBlocked("udp", netip.MustParseAddrPort("10.0.0.2:1194"), netip.MustParseAddrPort("198.51.100.20:1194"), vpnSocks, vpnOwners, nil); ok {
		t.Fatal("learned without a discovered client")
	}
}
