// Package torctl is a minimal client for the Tor control protocol (control-spec.txt): replies,
// GETINFO/GETCONF, SAFECOOKIE authentication and asynchronous events. Spec §7.5 asks for it to be
// ours and dependency-free. Everything the server sends is untrusted: lines and replies are
// bounded, and the cookie is never sent before the server proves it knows it.
package torctl

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	maxLine     = 64 << 10 // one line
	maxReply    = 4 << 20  // one reply (circuit-status on a busy client stays far below)
	eventBuffer = 256
	codeAsync   = 650
)

// DefaultPorts are tried in order by "auto": the system tor, then Tor Browser.
var DefaultPorts = []uint16{9051, 9151}

// Line is one reply line; Data holds the dot-encoded block of a "NNN+" line.
type Line struct {
	Code int
	Text string
	Data []string
}

// Reply is a full reply: every line up to the "NNN " end line.
type Reply struct{ Lines []Line }

// Code is the status of the end line.
func (r Reply) Code() int { return r.Lines[len(r.Lines)-1].Code }

// Err turns a non-2xx reply into an error carrying the code (never the server text verbatim
// beyond one line, which goes to the journal only through the caller).
func (r Reply) Err() error {
	if c := r.Code(); c < 200 || c > 299 {
		return &ReplyError{Code: c, Text: r.Lines[len(r.Lines)-1].Text}
	}
	return nil
}

// ReplyError is a non-2xx reply.
type ReplyError struct {
	Code int
	Text string
}

func (e *ReplyError) Error() string { return fmt.Sprintf("tor control: %d %s", e.Code, e.Text) }

// Event is one asynchronous (650) reply. Type is its first word (CIRC, STATUS_CLIENT, GUARD...).
type Event struct {
	Type  string
	Reply Reply
}

// Conn is a control connection. Commands are serialized; events arrive on Events().
type Conn struct {
	c       net.Conn
	mu      sync.Mutex
	replies chan Reply
	events  chan Event
	lost    atomic.Bool
	done    chan struct{}
	errMu   sync.Mutex
	err     error
}

// ErrNotLoopback: the control port must be local. Talking to a remote one would itself be
// traffic outside the tunnel.
var ErrNotLoopback = errors.New("tor control: address is not loopback")

// Dial connects to addr ("auto" tries 127.0.0.1 on DefaultPorts).
func Dial(ctx context.Context, addr string) (*Conn, error) {
	var cands []netip.AddrPort
	if addr == "auto" {
		for _, p := range DefaultPorts {
			cands = append(cands, netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), p))
		}
	} else {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, fmt.Errorf("tor control: %w", err)
		}
		cands = append(cands, ap)
	}
	var d net.Dialer
	var last error
	for _, ap := range cands {
		if !ap.Addr().Unmap().IsLoopback() {
			return nil, ErrNotLoopback
		}
		c, err := d.DialContext(ctx, "tcp", ap.String())
		if err != nil {
			last = err
			continue
		}
		return New(c), nil
	}
	return nil, fmt.Errorf("tor control: %w", last)
}

// New wraps an established connection and starts reading from it.
func New(c net.Conn) *Conn {
	cn := &Conn{c: c, replies: make(chan Reply, 1), events: make(chan Event, eventBuffer), done: make(chan struct{})}
	go cn.read()
	return cn
}

// Events delivers asynchronous events. It is closed when the connection ends.
func (c *Conn) Events() <-chan Event { return c.events }

// LostEvents reports (and clears) whether events were dropped because nobody read them; the
// caller should then refresh its full state.
func (c *Conn) LostEvents() bool { return c.lost.Swap(false) }

// Done is closed when the connection ends; Err says why.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err is the reason the connection ended (nil while open).
func (c *Conn) Err() error {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	return c.err
}

// Close ends the connection.
func (c *Conn) Close() error { return c.c.Close() }

func (c *Conn) fail(err error) {
	c.errMu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.errMu.Unlock()
}

func (c *Conn) read() {
	defer close(c.done)
	defer close(c.events)
	defer func() { _ = c.c.Close() }()
	r := bufio.NewReaderSize(c.c, 4096)
	for {
		rep, err := readReply(r)
		if err != nil {
			c.fail(err)
			return
		}
		if rep.Code() == codeAsync {
			typ, _, _ := strings.Cut(rep.Lines[0].Text, " ")
			select {
			case c.events <- Event{Type: typ, Reply: rep}:
			default:
				c.lost.Store(true)
			}
			continue
		}
		select {
		case c.replies <- rep:
		default:
			c.fail(errors.New("tor control: unsolicited reply"))
			return
		}
	}
}

// Command sends one command line and waits for its reply. A cancelled context closes the
// connection, since the reply would otherwise desynchronize the stream.
func (c *Conn) Command(ctx context.Context, line string) (Reply, error) {
	if strings.ContainsAny(line, "\r\n") {
		return Reply{}, errors.New("tor control: newline in command")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.c.Write([]byte(line + "\r\n")); err != nil {
		return Reply{}, fmt.Errorf("tor control: %w", err)
	}
	select {
	case rep := <-c.replies:
		return rep, nil
	case <-c.done:
		if err := c.Err(); err != nil {
			return Reply{}, err
		}
		return Reply{}, errors.New("tor control: connection closed")
	case <-ctx.Done():
		_ = c.c.Close()
		return Reply{}, ctx.Err()
	}
}

// readLine reads one CRLF (or LF) terminated line of at most maxLine bytes.
func readLine(r *bufio.Reader) (string, error) {
	var b []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(b)+len(chunk) > maxLine+2 {
			return "", errors.New("tor control: line too long")
		}
		b = append(b, chunk...)
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return "", err
		}
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

func readReply(r *bufio.Reader) (Reply, error) {
	var rep Reply
	size := 0
	for {
		s, err := readLine(r)
		if err != nil {
			return Reply{}, err
		}
		size += len(s)
		if len(s) < 4 {
			return Reply{}, errors.New("tor control: short line")
		}
		code, err := strconv.Atoi(s[:3])
		if err != nil || code < 100 || code > 999 {
			return Reply{}, errors.New("tor control: bad status code")
		}
		if len(rep.Lines) > 0 && rep.Lines[0].Code != code {
			return Reply{}, errors.New("tor control: mixed status codes in one reply")
		}
		ln := Line{Code: code, Text: s[4:]}
		sep := s[3]
		if sep == '+' {
			for {
				d, err := readLine(r)
				if err != nil {
					return Reply{}, err
				}
				size += len(d)
				if size > maxReply {
					return Reply{}, errors.New("tor control: reply too large")
				}
				if d == "." {
					break
				}
				ln.Data = append(ln.Data, strings.TrimPrefix(d, "."))
			}
		}
		if size > maxReply {
			return Reply{}, errors.New("tor control: reply too large")
		}
		rep.Lines = append(rep.Lines, ln)
		switch sep {
		case ' ':
			return rep, nil
		case '-', '+':
		default:
			return Reply{}, errors.New("tor control: bad line separator")
		}
	}
}
