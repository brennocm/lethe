// Package sockdiag lists TCP/UDP sockets via NETLINK_SOCK_DIAG and maps them to processes
// through /proc/*/fd (NET-010, spec §9.1).
package sockdiag

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"lethe/internal/contracts"
)

// SourceID of this sensor (spec §9.7).
const SourceID = "sockdiag"

// Sock is one kernel socket.
type Sock struct {
	Proto  string // tcp | udp
	Local  netip.AddrPort
	Remote netip.AddrPort // zero port/unspecified addr for unconnected UDP and listeners
	UID    uint32
	Inode  uint32
}

// Owner is the process holding a socket inode.
type Owner struct {
	PID  int
	Exe  string
	Comm string
	UID  int
}

// Dump lists every TCP and UDP socket, v4 and v6, in the current network namespace.
func Dump() ([]Sock, error) {
	var out []Sock
	for _, fam := range []uint8{unix.AF_INET, unix.AF_INET6} {
		for _, proto := range []string{"tcp", "udp"} {
			var (
				ss  []*netlink.Socket
				err error
			)
			if proto == "tcp" {
				ss, err = netlink.SocketDiagTCP(fam)
			} else {
				ss, err = netlink.SocketDiagUDP(fam)
			}
			if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
				return nil, fmt.Errorf("sock_diag %s/%d: %w", proto, fam, err)
			}
			for _, s := range ss {
				out = append(out, Sock{
					Proto:  proto,
					Local:  addrPort(s.ID.Source, s.ID.SourcePort),
					Remote: addrPort(s.ID.Destination, s.ID.DestinationPort),
					UID:    s.UID,
					Inode:  s.INode,
				})
			}
		}
	}
	return out, nil
}

func addrPort(ip net.IP, port uint16) netip.AddrPort {
	a, _ := netip.AddrFromSlice(ip)
	return netip.AddrPortFrom(a.Unmap(), port)
}

// Owners maps socket inodes to processes by scanning <procRoot>/*/fd. Processes that vanish or
// cannot be read are skipped (best effort; attribution then degrades to "none").
func Owners(procRoot string) (map[uint32]Owner, error) {
	ents, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, fmt.Errorf("scan %s: %w", procRoot, err)
	}
	out := map[uint32]Owner{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if err != nil {
			continue
		}
		var owner *Owner
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil {
				continue
			}
			ino, ok := socketInode(link)
			if !ok {
				continue
			}
			if owner == nil {
				o := readOwner(dir, pid)
				owner = &o
			}
			if _, dup := out[ino]; !dup { // shared after fork: the first (lowest) PID wins
				out[ino] = *owner
			}
		}
	}
	return out, nil
}

func socketInode(link string) (uint32, bool) {
	s, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0, false
	}
	s, ok = strings.CutSuffix(s, "]")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil
}

func readOwner(dir string, pid int) Owner {
	o := Owner{PID: pid, UID: -1}
	o.Exe, _ = os.Readlink(filepath.Join(dir, "exe"))
	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil { // #nosec G304 -- under procRoot
		o.Comm = strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile(filepath.Join(dir, "status")); err == nil { // #nosec G304 -- under procRoot
		for line := range strings.SplitSeq(string(b), "\n") {
			if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
				if f := strings.Fields(rest); len(f) > 0 {
					if uid, err := strconv.Atoi(f[0]); err == nil {
						o.UID = uid
					}
				}
				break
			}
		}
	}
	return o
}

// Attribute finds the process behind a packet (spec §9.1, NET-010): high = exact 5-tuple,
// low = same protocol and local port only (unconnected UDP, wildcard bind), none otherwise.
func Attribute(socks []Sock, owners map[uint32]Owner, proto string, src, dst netip.AddrPort) contracts.Proc {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	var low *Sock
	for i := range socks {
		s := &socks[i]
		if s.Proto != proto || s.Local.Port() != src.Port() || (s.Local.Addr().Is4() && !src.Addr().Is4()) {
			continue // a v4 socket never sends v6; a v6 socket may send v4 (dual-stack)
		}
		if s.Remote == dst && (s.Local.Addr() == src.Addr()) {
			return proc(*s, owners, contracts.ConfidenceHigh)
		}
		localOK := s.Local.Addr() == src.Addr() || s.Local.Addr().IsUnspecified()
		remoteOK := s.Remote.Port() == 0 || s.Remote == dst
		if localOK && remoteOK && low == nil {
			low = s
		}
	}
	if low != nil {
		return proc(*low, owners, contracts.ConfidenceLow)
	}
	return contracts.Proc{PID: 0, UID: -1, Confidence: contracts.ConfidenceNone}
}

func proc(s Sock, owners map[uint32]Owner, c contracts.Confidence) contracts.Proc {
	o, ok := owners[s.Inode]
	if !ok {
		// socket known but no process found (exited, or in another pid ns): keep the UID
		return contracts.Proc{UID: int(s.UID), Confidence: contracts.ConfidenceLow}
	}
	return contracts.Proc{PID: o.PID, Exe: o.Exe, Comm: o.Comm, UID: o.UID, Confidence: c}
}
