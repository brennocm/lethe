package discovery

import (
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"lethe/internal/sensors/sockdiag"
)

// VPNClient is a running VPN client process found by its sockets (spec §4.3, §7.1).
type VPNClient struct {
	PID         int    `json:"pid"`
	Exe         string `json:"exe"`
	UID         int    `json:"uid"`
	Cgroup      string `json:"cgroup,omitempty"`       // cgroup v2 path, relative to the mount
	CgroupID    uint64 `json:"cgroup_id,omitempty"`    // what nftables "socket cgroupv2" compares
	CgroupLevel uint32 `json:"cgroup_level,omitempty"` // path depth
}

// vpnClientNames are the executables of the VPN clients lethe knows (basename).
var vpnClientNames = map[string]bool{
	"openvpn": true, "openconnect": true, "openfortivpn": true, "vpnc": true,
	"charon": true, "charon-systemd": true, // strongSwan IKE daemon
	"mullvad-daemon": true, "nordvpnd": true, "expressvpnd": true, "ivpn-service": true,
	"pia-daemon": true, "warp-svc": true,
}

// IsVPNClient reports whether exe is a known VPN client.
func IsVPNClient(exe string) bool {
	return vpnClientNames[filepath.Base(strings.TrimSuffix(exe, " (deleted)"))]
}

// SocketSource lists the sockets of the namespace and their owners (sock_diag + /proc).
type SocketSource func() ([]sockdiag.Sock, map[uint32]sockdiag.Owner, error)

// CgroupResolver returns the cgroup v2 path, ID and depth of a process.
type CgroupResolver func(pid int) (path string, id uint64, level uint32, ok bool)

// SystemSockets is the SocketSource of the running system.
func SystemSockets(procRoot string) SocketSource {
	return func() ([]sockdiag.Sock, map[uint32]sockdiag.Owner, error) {
		socks, err := sockdiag.Dump()
		if err != nil {
			return nil, nil, err
		}
		owners, err := sockdiag.Owners(procRoot)
		return socks, owners, err
	}
}

// SystemCgroups resolves cgroups through /proc/<pid>/cgroup and the cgroup v2 mount. The ID of a
// cgroup v2 is the inode number of its directory.
func SystemCgroups(procRoot, cgroupRoot string) CgroupResolver {
	return func(pid int) (string, uint64, uint32, bool) {
		raw, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cgroup")) // #nosec G304 -- procfs path
		if err != nil {
			return "", 0, 0, false
		}
		for line := range strings.SplitSeq(string(raw), "\n") {
			p, ok := strings.CutPrefix(line, "0::/")
			if !ok || p == "" {
				continue
			}
			fi, err := os.Stat(filepath.Join(cgroupRoot, p))
			if err != nil {
				return "", 0, 0, false
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				return "", 0, 0, false
			}
			return p, st.Ino, uint32(strings.Count(p, "/") + 1), true // #nosec G115 -- small depth
		}
		return "", 0, 0, false
	}
}

// vpnScan finds the VPN client processes and the remote ends of their connected sockets. A
// remote end counts as an endpoint only when it is routed outside the tunnel (outside(addr)):
// what a client sends through its own tunnel (its API, for instance) is not an endpoint.
func vpnScan(socks []sockdiag.Sock, owners map[uint32]sockdiag.Owner, cgroupOf CgroupResolver, outside func(netip.Addr) bool) ([]VPNClient, []Endpoint) {
	clients := map[int]*VPNClient{}
	var eps []Endpoint
	seen := map[string]bool{}
	for _, s := range socks {
		o, ok := owners[s.Inode]
		if !ok || !IsVPNClient(o.Exe) {
			continue
		}
		if _, ok := clients[o.PID]; !ok {
			c := &VPNClient{PID: o.PID, Exe: o.Exe, UID: o.UID}
			if cgroupOf != nil {
				c.Cgroup, c.CgroupID, c.CgroupLevel, _ = cgroupOf(o.PID)
			}
			clients[o.PID] = c
		}
		a := s.Remote.Addr().Unmap()
		if !s.Remote.IsValid() || s.Remote.Port() == 0 || a.IsUnspecified() || a.IsLoopback() ||
			a.IsLinkLocalUnicast() || a.IsMulticast() || !outside(a) {
			continue
		}
		e := Endpoint{Addr: netip.AddrPortFrom(a, s.Remote.Port()), Proto: s.Proto}
		if !seen[e.String()] {
			seen[e.String()] = true
			eps = append(eps, e)
		}
	}
	out := make([]VPNClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, eps
}

// LearnBlocked returns the endpoint a packet blocked by the strict guard was heading to, when the
// socket that sent it belongs to one of the discovered VPN clients (spec §7.4). The socket must
// be known exactly: the connected socket with this 5-tuple, or the only unconnected UDP socket
// bound to the source port (OpenVPN over UDP does not connect its socket). Anything less
// certain stays blocked.
func LearnBlocked(proto string, src, dst netip.AddrPort, socks []sockdiag.Sock, owners map[uint32]sockdiag.Owner, clients []VPNClient) (Endpoint, bool) {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	a := dst.Addr()
	if (proto != "udp" && proto != "tcp") || dst.Port() == 0 || !a.IsValid() || a.IsUnspecified() || a.IsLoopback() ||
		a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return Endpoint{}, false
	}
	var exact, loose *sockdiag.Sock
	looseN := 0
	for i := range socks {
		s := &socks[i]
		if s.Proto != proto || s.Local.Port() != src.Port() {
			continue
		}
		local := s.Local.Addr().Unmap()
		if local != src.Addr() && !local.IsUnspecified() {
			continue
		}
		if s.Remote.IsValid() && s.Remote.Port() != 0 {
			r := netip.AddrPortFrom(s.Remote.Addr().Unmap(), s.Remote.Port())
			if r == dst && local == src.Addr() {
				exact = s
			}
			continue
		}
		looseN++
		loose = s
	}
	sock := exact
	if sock == nil && proto == "udp" && looseN == 1 {
		sock = loose
	}
	if sock == nil {
		return Endpoint{}, false
	}
	o, ok := owners[sock.Inode]
	if !ok || !IsVPNClient(o.Exe) {
		return Endpoint{}, false
	}
	for _, c := range clients {
		if c.PID == o.PID {
			return Endpoint{Addr: dst, Proto: proto}, true
		}
	}
	return Endpoint{}, false
}
