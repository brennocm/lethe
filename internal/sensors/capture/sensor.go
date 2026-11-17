package capture

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"antrea.io/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// SourceID of this sensor (spec §9.7).
const SourceID = "capture"

// heartbeatEvery bounds how long Run goes without calling the heartbeat (SELF-001 needs < 3 s).
const heartbeatEvery = 500 * time.Millisecond

// Frame is one delivered, classified frame.
type Frame struct {
	Iface string
	At    time.Time
	Leak  Leak
}

// Stats are the counters since the previous call (PACKET_STATISTICS resets on read; SELF-002).
type Stats struct {
	Packets uint32
	Drops   uint32
}

// Sensor is one AF_PACKET socket bound to one egress interface (spec §8.1).
type Sensor struct {
	iface string
	mu    sync.Mutex
	conn  *packet.Conn
}

// Open binds a socket to iface with a drop-all filter, drains it, then installs the real one.
func Open(iface string, al Allowlist) (*Sensor, error) {
	prog, err := assemble(al)
	if err != nil {
		return nil, err
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("capture %s: %w", iface, err)
	}
	drop, err := bpf.Assemble(DropAll())
	if err != nil {
		return nil, err
	}
	conn, err := packet.Listen(ifi, packet.Raw, unix.ETH_P_ALL, &packet.Config{Filter: drop})
	if err != nil {
		return nil, fmt.Errorf("capture %s: %w", iface, err)
	}
	s := &Sensor{iface: iface, conn: conn}
	if err := s.drain(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := conn.SetBPF(prog); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("capture %s: attach filter: %w", iface, err)
	}
	return s, nil
}

func assemble(al Allowlist) ([]bpf.RawInstruction, error) {
	ins, err := Build(al, true)
	if err != nil {
		return nil, err
	}
	return bpf.Assemble(ins)
}

// drain discards whatever was queued before the drop-all filter took effect.
func (s *Sensor) drain() error {
	buf := make([]byte, Snaplen)
	for {
		if err := s.conn.SetReadDeadline(time.Now().Add(time.Millisecond)); err != nil {
			return err
		}
		if _, _, err := s.conn.ReadFrom(buf); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				return s.conn.SetReadDeadline(time.Time{})
			}
			return fmt.Errorf("capture %s: drain: %w", s.iface, err)
		}
	}
}

// Update replaces the filter atomically (SO_ATTACH_FILTER swaps the program).
func (s *Sensor) Update(al Allowlist) error {
	prog, err := assemble(al)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.conn.SetBPF(prog); err != nil {
		return fmt.Errorf("capture %s: update filter: %w", s.iface, err)
	}
	return nil
}

// SetReadBuffer sets SO_RCVBUF (the selftest shrinks it to force drops, ST-SELF-002).
func (s *Sensor) SetReadBuffer(n int) error {
	rc, err := s.conn.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, n) // #nosec G115 -- fd fits in int
	}); err != nil {
		return err
	}
	return serr
}

// ReadBuffer reads SO_RCVBUF (the kernel reports twice the requested size; pass it back as is).
func (s *Sensor) ReadBuffer() (int, error) {
	rc, err := s.conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var serr error
	if err := rc.Control(func(fd uintptr) {
		n, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF) // #nosec G115 -- fd fits in int
	}); err != nil {
		return 0, err
	}
	return n / 2, serr
}

// Stats reads and resets the kernel counters.
func (s *Sensor) Stats() (Stats, error) {
	st, err := s.conn.Stats()
	if err != nil {
		return Stats{}, fmt.Errorf("capture %s: stats: %w", s.iface, err)
	}
	return Stats{Packets: st.Packets, Drops: st.Drops}, nil
}

// Run reads frames until ctx ends, sending each classified frame to out and calling beat at
// least every 500 ms while the socket is healthy.
func (s *Sensor) Run(ctx context.Context, out chan<- Frame, beat func(time.Time)) error {
	rc, err := s.conn.SyscallConn()
	if err != nil {
		return err
	}
	buf := make([]byte, Snaplen)
	for ctx.Err() == nil {
		if err := s.conn.SetReadDeadline(time.Now().Add(heartbeatEvery)); err != nil {
			return err
		}
		var (
			n    int
			rerr error
		)
		err := rc.Read(func(fd uintptr) bool {
			// MSG_TRUNC: the return value is the length on the wire, not the snaplen.
			n, _, rerr = unix.Recvfrom(int(fd), buf, unix.MSG_TRUNC)
			return !errors.Is(rerr, unix.EAGAIN)
		})
		now := time.Now()
		switch {
		case errors.Is(err, os.ErrDeadlineExceeded):
			beat(now)
			continue
		case err != nil:
			return fmt.Errorf("capture %s: read: %w", s.iface, err)
		case rerr != nil:
			return fmt.Errorf("capture %s: recv: %w", s.iface, rerr)
		}
		beat(now)
		captured := min(n, len(buf))
		f := Frame{Iface: s.iface, At: now, Leak: Classify(buf[:captured], n)}
		select {
		case out <- f:
		case <-ctx.Done():
		}
	}
	return nil
}

// Close releases the socket.
func (s *Sensor) Close() error { return s.conn.Close() }
