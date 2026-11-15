package discovery

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"lethe/internal/discovery/torctl"
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

// TorControl keeps one authenticated control connection, reconnecting on the next Status after
// a failure. Changed fires (coalesced) on every CIRC, STATUS_CLIENT or GUARD event.
type TorControl struct {
	Addr    string // egress.tor_control
	Cookie  string // egress.tor_cookie
	Timeout time.Duration

	mu      sync.Mutex
	conn    *torctl.Conn
	changed chan struct{}
	once    sync.Once
}

// NewTorControl returns a client for the profile's control settings; it connects lazily.
func NewTorControl(addr, cookie string) *TorControl {
	return &TorControl{Addr: addr, Cookie: cookie, Timeout: 2 * time.Second}
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
	if err := c.Authenticate(ctx, t.Cookie); err != nil {
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
