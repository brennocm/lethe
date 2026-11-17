package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"lethe/internal/platform"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// Peer is the authenticated other end of a connection (SO_PEERCRED).
type Peer struct {
	UID, GID, PID int
	Agent         bool // the session agent spawned by this daemon
}

// Call is one request being handled.
type Call struct {
	Ctx    context.Context
	Peer   Peer
	Conn   uint64 // the connection, unique for the server's life (binds challenges to it)
	Req    Request
	notify func(any) error
	auth   *Authenticator
	authed bool
}

// Authorize checks the passphrase proof attached to the request (once per call). Handlers of
// conditionally sensitive methods (alert.ack on a CRITICAL) call it themselves.
func (c *Call) Authorize() error {
	if c.authed {
		return nil
	}
	if c.auth == nil {
		return ErrNoProof
	}
	if err := c.auth.Verify(c.Conn, c.Req.Method, c.Req.Params, c.Req.Auth); err != nil {
		return err
	}
	c.authed = true
	return nil
}

// Notify pushes a notification on this connection (events.subscribe).
func (c *Call) Notify(params any) error {
	return c.notify(Notification{JSONRPC: "2.0", Method: "event", Params: params})
}

// Handler serves one method. A returned *Error is sent as is; other errors become CodeInternal.
type Handler func(*Call) (any, error)

// Server dispatches requests to handlers after the peer and class checks.
type Server struct {
	OperatorUID int
	IsAgent     func(pid int) bool
	// Denied is called for every refused peer or call (the daemon journals ipc.denied).
	Denied func(p Peer, method, reason string)
	// SelfAuthorized methods prove the passphrase themselves (session.arm decrypts the baseline).
	SelfAuthorized map[string]bool

	mu       sync.Mutex
	conns    atomic.Uint64
	auth     *Authenticator
	handlers map[string]Handler
	wg       sync.WaitGroup
}

// Handle registers h for method (which must be in Methods).
func (s *Server) Handle(method string, h Handler) {
	if _, ok := Methods[method]; !ok {
		panic("ipc: unknown method " + method)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handlers == nil {
		s.handlers = map[string]Handler{}
	}
	s.handlers[method] = h
}

// SetAuthenticator installs (or clears, with nil) the proof checker of the current session.
func (s *Server) SetAuthenticator(a *Authenticator) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auth = a
}

// Listen creates the socket at path: directory 0700 and socket 0600, both owned by uid/gid.
// A stale socket is replaced; anything else at path is an error. The directory may sit in a
// place the operator owns (/run/user/<uid>), so it is created and changed through a descriptor
// opened without following symlinks, and the socket is checked and chowned relative to it.
func Listen(path string, uid, gid int) (*net.UnixListener, error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	parent, err := os.Open(filepath.Dir(dir)) // #nosec G304 -- fixed runtime directory
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	d, err := platform.MkdirAt(parent, filepath.Base(dir), 0o700)
	_ = parent.Close()
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	defer func() { _ = d.Close() }()
	root := os.Geteuid() == 0
	owner, group := -1, -1
	if root {
		owner, group = uid, gid
	}
	if err := platform.SecureDir(d, owner, group, 0o700); err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	dfd := int(d.Fd()) // #nosec G115 -- fd
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
			return nil, fmt.Errorf("ipc: %s exists and is not a socket", path)
		}
		if err := unix.Unlinkat(dfd, base, 0); err != nil {
			return nil, fmt.Errorf("ipc: %w", err)
		}
	}
	old := unix.Umask(0o177)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	unix.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("ipc: %w", err)
	}
	l.SetUnlinkOnClose(true)
	// The socket must have landed in the directory we secured (not in one swapped in meanwhile).
	if err := unix.Fstatat(dfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		_ = l.Close()
		return nil, fmt.Errorf("ipc: %s changed while the socket was created", dir)
	}
	if root {
		if err := unix.Fchownat(dfd, base, uid, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			_ = l.Close()
			return nil, fmt.Errorf("ipc: %w", err)
		}
	}
	return l, nil
}

// Serve accepts connections until ctx ends.
func (s *Server) Serve(ctx context.Context, l *net.UnixListener) error {
	go func() { <-ctx.Done(); _ = l.Close() }()
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				s.wg.Wait()
				return nil
			}
			return fmt.Errorf("ipc: accept: %w", err)
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(ctx, c)
		}()
	}
}

// PeerCred reads SO_PEERCRED of a Unix connection.
func PeerCred(c *net.UnixConn) (Peer, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var (
		cred *unix.Ucred
		cerr error
	)
	if err := rc.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return Peer{}, err
	}
	if cerr != nil {
		return Peer{}, cerr
	}
	return Peer{UID: int(cred.Uid), GID: int(cred.Gid), PID: int(cred.Pid)}, nil
}

func (s *Server) denied(p Peer, method, reason string) {
	if s.Denied != nil {
		s.Denied(p, method, reason)
	}
}

// Allowed is the peer policy: the operator's UID and root only (spec §17.1).
func (s *Server) Allowed(p Peer) bool { return p.UID == 0 || p.UID == s.OperatorUID }

func (s *Server) serveConn(ctx context.Context, c *net.UnixConn) {
	defer func() { _ = c.Close() }()
	p, err := PeerCred(c)
	if err != nil {
		s.denied(Peer{UID: -1, GID: -1}, "", "no peer credentials")
		return
	}
	if !s.Allowed(p) {
		s.denied(p, "", "uid not allowed")
		return
	}
	if s.IsAgent != nil {
		p.Agent = s.IsAgent(p.PID)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { <-ctx.Done(); _ = c.Close() }()
	var wmu sync.Mutex
	enc := json.NewEncoder(c)
	write := func(v any) error {
		wmu.Lock()
		defer wmu.Unlock()
		return enc.Encode(v)
	}
	r := bufio.NewReaderSize(c, MaxMessage)
	conn := s.conns.Add(1)
	for {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			s.denied(p, "", "message over 64 KiB")
			_ = write(Response{JSONRPC: "2.0", Error: &Error{Code: CodeInvalidRequest, Message: ErrTooLarge.Error()}})
			return
		}
		if err != nil {
			return
		}
		line = append([]byte(nil), bytes.TrimRight(line, "\r\n")...)
		if len(line) == 0 {
			continue
		}
		resp := s.dispatch(ctx, p, conn, line, write)
		if err := write(resp); err != nil {
			return
		}
	}
}

func (s *Server) dispatch(ctx context.Context, p Peer, conn uint64, line []byte, write func(any) error) Response {
	req, perr := DecodeRequest(line)
	var id *uint64
	if perr == nil || req.ID != 0 {
		v := req.ID
		id = &v
	}
	if perr != nil {
		return Response{JSONRPC: "2.0", ID: id, Error: perr}
	}
	class := Methods[req.Method]
	s.mu.Lock()
	h := s.handlers[req.Method]
	auth := s.auth
	s.mu.Unlock()
	fail := func(code int, msg string) Response {
		return Response{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: msg}}
	}
	if h == nil {
		return fail(CodeMethodNotFound, "method not available")
	}
	if class == ClassAgent && !p.Agent {
		s.denied(p, req.Method, "not the session agent")
		return fail(CodeDenied, "only the session agent may call this method")
	}
	call := &Call{Ctx: ctx, Peer: p, Conn: conn, Req: req, notify: write, auth: auth}
	if class == ClassSensitive && !s.SelfAuthorized[req.Method] {
		if err := call.Authorize(); err != nil {
			s.denied(p, req.Method, err.Error())
			return fail(CodeAuth, err.Error())
		}
	}
	res, err := h(call)
	if err != nil {
		var ie *Error
		if errors.As(err, &ie) {
			if ie.Code == CodeAuth {
				s.denied(p, req.Method, ie.Message)
			}
			return fail(ie.Code, ie.Message)
		}
		return fail(CodeInternal, err.Error())
	}
	raw, err := json.Marshal(res)
	if err != nil {
		return fail(CodeInternal, "cannot encode result")
	}
	return Response{JSONRPC: "2.0", ID: id, Result: raw}
}
