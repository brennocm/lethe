package discovery

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"time"

	"lethe/internal/discovery/torctl"
	"lethe/internal/sensors/sockdiag"
)

// TorSource answers tor's state (TorControl in production).
type TorSource interface {
	Status() (torctl.Status, error)
}

// TorState is what the snapshot keeps from tor (spec §7.5).
type TorState struct {
	Reachable          bool        `json:"reachable"` // control port answered and authenticated
	Version            string      `json:"version,omitempty"`
	Bootstrap          int         `json:"bootstrap"`
	CircuitEstablished bool        `json:"circuit_established"`
	UseBridges         bool        `json:"use_bridges"`
	Transports         []string    `json:"transports"`
	Guards             []string    `json:"guards"` // ip:port
	Bridges            []TorBridge `json:"bridges"`
}

// TorBridge is one configured bridge.
type TorBridge struct {
	Transport string `json:"transport,omitempty"`
	Addr      string `json:"addr,omitempty"`
}

// torState queries the source and adds the guards (and, with UseBridges, the bridge addresses)
// to the endpoints as TCP. A failure leaves Reachable false; the caller records the gap.
func torState(src TorSource, endpoints map[string]bool) (*TorState, bool) {
	ts := &TorState{Transports: []string{}, Guards: []string{}, Bridges: []TorBridge{}}
	st, err := src.Status()
	if err != nil {
		return ts, false
	}
	ts.Reachable, ts.Version, ts.Bootstrap, ts.CircuitEstablished, ts.UseBridges = true, st.Version, st.Bootstrap, st.CircuitEstablished, st.UseBridges
	ts.Transports = append(ts.Transports, st.Transports()...)
	add := func(ap netip.AddrPort) {
		if ap.IsValid() && ap.Port() != 0 {
			endpoints[Endpoint{Addr: ap, Proto: "tcp"}.String()] = true
		}
	}
	for _, g := range st.Guards {
		ts.Guards = append(ts.Guards, g.String())
		add(g)
	}
	for _, b := range st.Bridges {
		tb := TorBridge{Transport: b.Transport}
		if b.Addr.IsValid() {
			tb.Addr = b.Addr.String()
		}
		ts.Bridges = append(ts.Bridges, tb)
		if st.UseBridges {
			add(b.Addr)
		}
	}
	return ts, true
}

// TorPeer identifies the process holding the server end of a local TCP connection.
type TorPeer func(local, remote netip.AddrPort) (uid int, exe string, err error)

// TorControl keeps one authenticated control connection, reconnecting on the next Status after
// a failure. Changed fires (coalesced) on every CIRC, STATUS_CLIENT or GUARD event.
//
// Whatever answers on the control port decides which addresses the guard lets through, and any
// local user can listen on 127.0.0.1:9051 when tor is not running. So before authenticating, the
// server end must belong to a process whose executable is named tor, running as the operator (Tor
// Browser) or as a system user (uid < 1000). Its cookie must be owned by that same uid.
type TorControl struct {
	Addr        string // egress.tor_control
	Cookie      string // egress.tor_cookie
	OperatorUID int
	Timeout     time.Duration
	Peer        TorPeer // nil = sock_diag + /proc

	mu      sync.Mutex
	conn    *torctl.Conn
	changed chan struct{}
	once    sync.Once
}

// NewTorControl returns a client for the profile's control settings; it connects lazily.
func NewTorControl(addr, cookie string, operatorUID int) *TorControl {
	return &TorControl{Addr: addr, Cookie: cookie, OperatorUID: operatorUID, Timeout: 2 * time.Second}
}

// ErrUntrustedTor: the control port is held by something that is not tor run by a trusted user.
var ErrUntrustedTor = errors.New("tor control: the port is not held by tor running as a system user or the operator")

const systemUIDMax = 999

// trustedTor is the server identity rule of TorControl.
func trustedTor(uid int, exe string, operator int) bool {
	return filepath.Base(exe) == "tor" && uid >= 0 && (uid == operator || uid <= systemUIDMax)
}

// sockdiagPeer finds the server-side socket of the connection and the process that owns it.
func sockdiagPeer(local, remote netip.AddrPort) (int, string, error) {
	socks, err := sockdiag.Dump()
	if err != nil {
		return 0, "", err
	}
	for _, s := range socks {
		if s.Proto == "tcp" && s.Local == remote && s.Remote == local {
			owners, err := sockdiag.Owners("/proc")
			if err != nil {
				return 0, "", err
			}
			o, ok := owners[s.Inode]
			if !ok {
				return 0, "", errors.New("tor control: no process owns the server socket")
			}
			return int(s.UID), o.Exe, nil
		}
	}
	return 0, "", errors.New("tor control: server socket not found")
}

func addrPortOf(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		ap := t.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}

// Changed is signalled when tor reports a circuit, status or guard event, or lost events.
func (t *TorControl) Changed() <-chan struct{} {
	t.once.Do(func() { t.changed = make(chan struct{}, 1) })
	return t.changed
}

func (t *TorControl) notify() {
	select {
	case t.changed <- struct{}{}:
	default:
	}
}

// Status implements TorSource.
func (t *TorControl) Status() (torctl.Status, error) {
	t.Changed()
	t.mu.Lock()
	defer t.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), t.Timeout)
	defer cancel()
	if t.conn == nil {
		c, err := t.connect(ctx)
		if err != nil {
			return torctl.Status{}, err
		}
		t.conn = c
	}
	st, err := t.conn.Status(ctx)
	if err != nil {
		_ = t.conn.Close()
		t.conn = nil
	}
	return st, err
}

func (t *TorControl) connect(ctx context.Context) (*torctl.Conn, error) {
	c, err := torctl.Dial(ctx, t.Addr)
	if err != nil {
		return nil, err
	}
	peer := t.Peer
	if peer == nil {
		peer = sockdiagPeer
	}
	uid, exe, err := peer(addrPortOf(c.LocalAddr()), addrPortOf(c.RemoteAddr()))
	if err == nil && !trustedTor(uid, exe, t.OperatorUID) {
		err = ErrUntrustedTor
	}
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if err := c.Authenticate(ctx, t.Cookie, uint32(uid)); err != nil { // #nosec G115 -- checked >= 0
		_ = c.Close()
		return nil, err
	}
	if err := c.SetEvents(ctx, "CIRC", "STATUS_CLIENT", "GUARD"); err != nil {
		_ = c.Close()
		return nil, err
	}
	go func() {
		for range c.Events() {
			t.notify()
		}
		// Closed by tor (not by us): the next pass sees it. Our own closes stay silent, or a
		// failing Status would reconnect in a loop.
		t.mu.Lock()
		remote := t.conn == c
		t.mu.Unlock()
		if remote {
			t.notify()
		}
	}()
	return c, nil
}

// Close ends the connection.
func (t *TorControl) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.conn == nil {
		return nil
	}
	err := t.conn.Close()
	t.conn = nil
	return err
}
