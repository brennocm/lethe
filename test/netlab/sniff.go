//go:build e2e

package netlab

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"antrea.io/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Sniffer records every frame the isp namespace receives on isp0: what left the DUT's egress.
type Sniffer struct {
	mu     sync.Mutex
	closed bool
	frames []Frame
	conn   *packet.Conn
	done   chan struct{}
}

// Frame is one sniffed frame.
type Frame struct {
	At   time.Time
	Data []byte
}

// Sniff starts the external sniffer of the spec ("o sniffer externo", §23.2).
func (l *Lab) Sniff(t testing.TB) *Sniffer {
	t.Helper()
	notOutgoing, err := bpf.Assemble([]bpf.Instruction{
		bpf.LoadExtension{Num: bpf.ExtType},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.PACKET_OUTGOING, SkipTrue: 1},
		bpf.RetConstant{Val: 2048},
		bpf.RetConstant{Val: 0},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := &Sniffer{done: make(chan struct{})}
	must(t, l.In(l.ISP, func() error {
		ifi, err := net.InterfaceByName(ISPDown)
		if err != nil {
			return err
		}
		s.conn, err = packet.Listen(ifi, packet.Raw, unix.ETH_P_ALL, &packet.Config{Filter: notOutgoing})
		return err
	}))
	go func() {
		defer close(s.done)
		buf := make([]byte, 2048)
		for {
			n, _, err := s.conn.ReadFrom(buf)
			if err != nil {
				s.mu.Lock()
				closed := s.closed
				s.mu.Unlock()
				if !closed && !errors.Is(err, os.ErrClosed) && !errors.Is(err, net.ErrClosed) {
					t.Errorf("sniffer: %v", err)
				}
				return
			}
			s.mu.Lock()
			s.frames = append(s.frames, Frame{At: time.Now(), Data: append([]byte(nil), buf[:n]...)})
			s.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		_ = s.conn.Close()
		<-s.done
	})
	return s
}

// Since returns the frames received at or after ts.
func (s *Sniffer) Since(ts time.Time) []Frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Frame
	for _, f := range s.frames {
		if !f.At.Before(ts) {
			out = append(out, f)
		}
	}
	return out
}

// IsLinkControl reports ARP, DHCP (v4/v6), NDP and MLD: what AC-04 tolerates on the wire.
func IsLinkControl(f []byte) bool {
	if len(f) < 14 {
		return false
	}
	switch binary.BigEndian.Uint16(f[12:14]) {
	case unix.ETH_P_ARP:
		return true
	case unix.ETH_P_IP:
		p := f[14:]
		if len(p) < 28 || p[9] != unix.IPPROTO_UDP {
			return false
		}
		ihl := int(p[0]&0x0f) * 4
		return len(p) >= ihl+4 && binary.BigEndian.Uint16(p[ihl:]) == 68 && binary.BigEndian.Uint16(p[ihl+2:]) == 67
	case unix.ETH_P_IPV6:
		p := f[14:]
		if len(p) < 41 {
			return false
		}
		switch p[6] {
		case unix.IPPROTO_ICMPV6:
			t := p[40]
			return t == 133 || t == 135 || t == 136 || t == 143
		case 0: // hop-by-hop (MLD reports carry router alert)
			return len(p) > 48 && p[40] == unix.IPPROTO_ICMPV6 && p[48] == 143
		case unix.IPPROTO_UDP:
			return len(p) >= 44 && binary.BigEndian.Uint16(p[40:]) == 546 && binary.BigEndian.Uint16(p[42:]) == 547
		}
	}
	return false
}

// UDPTo reports whether f is an IPv4 UDP datagram to dst:port.
func UDPTo(f []byte, dst net.IP, port uint16) bool {
	if len(f) < 14+28 || binary.BigEndian.Uint16(f[12:14]) != unix.ETH_P_IP {
		return false
	}
	p := f[14:]
	ihl := int(p[0]&0x0f) * 4
	return p[9] == unix.IPPROTO_UDP && net.IP(p[16:20]).Equal(dst) && len(p) >= ihl+4 && binary.BigEndian.Uint16(p[ihl+2:]) == port
}

// SetTunnel sets the DUT's WireGuard link up or down (AC-04).
func (l *Lab) SetTunnel(t testing.TB, up bool) {
	t.Helper()
	must(t, l.In(l.DUT, func() error {
		if up {
			return setUp(DUTTunnel)
		}
		return setDown(DUTTunnel)
	}))
}

// StopServer stops the WireGuard server and resets the DUT's peer, so the client has no
// handshake and receives nothing through the tunnel (AC-16: a tunnel that does not work).
func (l *Lab) StopServer(t testing.TB) {
	t.Helper()
	must(t, l.In(l.VPN, func() error { return setDown(VPNTunnel) }))
	must(t, l.In(l.DUT, func() error {
		c, err := wgctrl.New()
		if err != nil {
			return err
		}
		defer func() { _ = c.Close() }()
		d, err := c.Device(DUTTunnel)
		if err != nil || len(d.Peers) == 0 {
			return fmt.Errorf("netlab: no wireguard peer: %w", err)
		}
		p := d.Peers[0]
		keepalive := p.PersistentKeepaliveInterval
		return c.ConfigureDevice(DUTTunnel, wgtypes.Config{ReplacePeers: true, Peers: []wgtypes.PeerConfig{{
			PublicKey: p.PublicKey, Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs, PersistentKeepaliveInterval: &keepalive,
		}}})
	}))
}
