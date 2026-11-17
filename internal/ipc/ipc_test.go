package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lethe/internal/contracts"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type fixture struct {
	srv     *Server
	path    string
	key     []byte
	clk     *clock
	denied  []string
	mu      sync.Mutex
	tripped int
}

func newFixture(t *testing.T, operator int) *fixture {
	t.Helper()
	f := &fixture{clk: &clock{t: time.Unix(1_700_000_000, 0)}}
	f.key = []byte("0123456789abcdef0123456789abcdef")
	f.srv = &Server{OperatorUID: operator, SelfAuthorized: map[string]bool{"session.arm": true},
		IsAgent: func(pid int) bool { return false },
		Denied: func(p Peer, m, r string) {
			f.mu.Lock()
			f.denied = append(f.denied, m+":"+r)
			f.mu.Unlock()
		}}
	auth := NewAuthenticator(append([]byte(nil), f.key...), f.clk.now, func() { f.mu.Lock(); f.tripped++; f.mu.Unlock() })
	t.Cleanup(auth.Close)
	f.srv.SetAuthenticator(auth)
	f.srv.Handle("auth.challenge", func(c *Call) (any, error) {
		n, err := auth.Challenge(c.Conn)
		return map[string][]byte{"nonce": n}, err
	})
	f.srv.Handle("status.get", func(c *Call) (any, error) { return map[string]any{"uid": c.Peer.UID}, nil })
	f.srv.Handle("panic.release", func(c *Call) (any, error) { return map[string]bool{"released": true}, nil })
	f.srv.Handle("session.arm", func(c *Call) (any, error) { return "armed", nil })
	f.srv.Handle("agent.report", func(c *Call) (any, error) { return "ok", nil })
	f.srv.Handle("alert.ack", func(c *Call) (any, error) {
		var p struct{ Critical bool }
		_ = json.Unmarshal(c.Req.Params, &p)
		if p.Critical {
			if err := c.Authorize(); err != nil {
				return nil, &Error{Code: CodeAuth, Message: err.Error()}
			}
		}
		return "acked", nil
	})
	f.srv.Handle("events.subscribe", func(c *Call) (any, error) {
		_ = c.Notify(map[string]string{"type": "state.changed"})
		return "subscribed", nil
	})
	f.srv.Handle("heartbeat", func(c *Call) (any, error) { return nil, errors.New("boom") })
	f.path = filepath.Join(t.TempDir(), "run", "lethe.sock")
	l, err := Listen(f.path, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.srv.Serve(ctx, l) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return f
}

func (f *fixture) dial(t *testing.T) *Client {
	t.Helper()
	c, err := Dial(f.path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	return c
}

func code(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

func TestIPC_SocketPermissions(t *testing.T) {
	f := newFixture(t, os.Getuid())
	fi, err := os.Stat(f.path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(f.path))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(f.path), "plain"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(filepath.Dir(f.path), "plain"), 0, 0); err == nil {
		t.Fatal("must refuse to replace a regular file")
	}
}

// The socket directory sits where the operator can write (/run/user/<uid>): a planted symlink
// must not make the daemon (root) chmod/chown its target.
func TestIPC_SocketDirSymlinkRefused(t *testing.T) {
	rt := t.TempDir()
	target := t.TempDir()
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(rt, "lethe")); err != nil {
		t.Fatal(err)
	}
	if l, err := Listen(filepath.Join(rt, "lethe", "lethe.sock"), os.Getuid(), os.Getgid()); err == nil {
		_ = l.Close()
		t.Fatal("followed a symlinked socket directory")
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o755 {
		t.Fatalf("target mode changed to %v", fi.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(target, "lethe.sock")); err == nil {
		t.Fatal("socket created in the symlink target")
	}
}

func TestIPC_ReadAndSensitive(t *testing.T) {
	f := newFixture(t, os.Getuid())
	c := f.dial(t)
	var st map[string]int
	if err := c.Call("status.get", nil, nil, &st); err != nil || st["uid"] != os.Getuid() {
		t.Fatalf("%v %v", st, err)
	}
	// sensitive without proof
	if err := c.Call("panic.release", map[string]any{}, nil, nil); code(err) != CodeAuth {
		t.Fatalf("no proof: %v", err)
	}
	// with a proof under the wrong key
	bad, err := c.Prove([]byte("wrong-key-wrong-key-wrong-key-00"), "panic.release", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Call("panic.release", map[string]any{}, bad, nil); code(err) != CodeAuth {
		t.Fatalf("wrong key: %v", err)
	}
	// proof for other params
	other, _ := c.Prove(f.key, "panic.release", map[string]any{"x": 1})
	if err := c.Call("panic.release", map[string]any{}, other, nil); code(err) != CodeAuth {
		t.Fatalf("params not covered: %v", err)
	}
	good, _ := c.Prove(f.key, "panic.release", map[string]any{})
	var res map[string]bool
	if err := c.Call("panic.release", map[string]any{}, good, &res); err != nil || !res["released"] {
		t.Fatalf("good proof: %v %v", res, err)
	}
	if err := c.Call("panic.release", map[string]any{}, good, nil); code(err) != CodeAuth {
		t.Fatalf("nonce reuse: %v", err)
	}
	// session.arm proves itself (baseline decryption)
	if err := c.Call("session.arm", map[string]any{}, nil, nil); err != nil {
		t.Fatal(err)
	}
	// conditional: ack of a WARNING is safe, of a CRITICAL is sensitive
	if err := c.Call("alert.ack", map[string]any{"critical": false}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Call("alert.ack", map[string]any{"critical": true}, nil, nil); code(err) != CodeAuth {
		t.Fatalf("critical ack: %v", err)
	}
	proof, _ := c.Prove(f.key, "alert.ack", map[string]any{"critical": true})
	if err := c.Call("alert.ack", map[string]any{"critical": true}, proof, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Call("agent.report", map[string]any{}, nil, nil); code(err) != CodeDenied {
		t.Fatalf("agent-only: %v", err)
	}
	if err := c.Call("heartbeat", nil, nil, nil); code(err) != CodeInternal {
		t.Fatalf("handler error: %v", err)
	}
	if err := c.Call("events.query", nil, nil, nil); code(err) != CodeMethodNotFound {
		t.Fatalf("unregistered: %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.denied) < 5 {
		t.Fatalf("denials not reported: %v", f.denied)
	}
}

func TestIPC_NonceExpiresAndFailureBudgetPanics(t *testing.T) {
	f := newFixture(t, os.Getuid())
	c := f.dial(t)
	p, _ := c.Prove(f.key, "panic.release", map[string]any{})
	f.clk.add(31 * time.Second)
	if err := c.Call("panic.release", map[string]any{}, p, nil); code(err) != CodeAuth {
		t.Fatalf("expired: %v", err)
	}
	// client errors (no proof, expired nonce) are refused but are no passphrase guess
	for range 10 {
		_ = c.Call("panic.release", map[string]any{}, nil, nil)
	}
	wrong := make([]byte, 32)
	guess := func() {
		p, _ := c.Prove(wrong, "panic.release", map[string]any{})
		_ = c.Call("panic.release", map[string]any{}, p, nil)
	}
	f.mu.Lock()
	tripped := f.tripped
	f.mu.Unlock()
	if tripped != 0 {
		t.Fatalf("missing proofs engaged panic (%d)", tripped)
	}
	for range 5 {
		guess()
	}
	f.mu.Lock()
	tripped = f.tripped
	f.mu.Unlock()
	if tripped != 1 {
		t.Fatalf("5 wrong passphrases within 5 min must engage panic once, got %d", tripped)
	}
	// failures spread beyond the window do not trip
	for range 4 {
		guess()
		f.clk.add(2 * time.Minute)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tripped != 1 {
		t.Fatalf("tripped=%d", f.tripped)
	}
}

func TestAC14_OtherUIDRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always an allowed peer")
	}
	f := newFixture(t, os.Getuid()+4242)
	c := f.dial(t)
	if err := c.Call("status.get", nil, nil, nil); err == nil {
		t.Fatal("a peer with another UID must be refused")
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := len(f.denied)
		f.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("ipc.denied not reported")
}

func TestIPC_OversizedMessageClosesConnection(t *testing.T) {
	f := newFixture(t, os.Getuid())
	conn, err := net.Dial("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		_, _ = conn.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"status.get","params":{"x":"` + strings.Repeat("a", MaxMessage) + `"}}` + "\n"))
	}()
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if !strings.Contains(string(buf[:n]), "64 KiB") {
		t.Fatalf("reply %q", buf[:n])
	}
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("connection must be closed")
	}
}

func TestIPC_Notifications(t *testing.T) {
	f := newFixture(t, os.Getuid())
	c := f.dial(t)
	var got json.RawMessage
	c.OnNotify = func(p json.RawMessage) { got = p }
	if err := c.Call("events.subscribe", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "state.changed") {
		t.Fatalf("notification %s", got)
	}
}

func TestIPC_DecodeRequest(t *testing.T) {
	cases := map[string]int{
		`{"jsonrpc":"2.0","id":1,"method":"status.get"}`:                                      0,
		`{"jsonrpc":"2.0","id":1,"method":"status.get","extra":1}`:                            CodeParse,
		`{"jsonrpc":"1.0","id":1,"method":"status.get"}`:                                      CodeInvalidRequest,
		`{"jsonrpc":"2.0","id":1,"method":"rm.rf"}`:                                           CodeMethodNotFound,
		`{"jsonrpc":"2.0","id":1,"method":"status.get","params":[1]}`:                         CodeInvalidParams,
		`{"jsonrpc":"2.0","id":1,"method":"status.get","auth":{"nonce":"AA==","mac":"AA=="}}`: CodeInvalidRequest,
		`{"jsonrpc":"2.0","id":1,"method":"status.get"} {}`:                                   CodeParse,
		`not json`: CodeParse,
	}
	for in, want := range cases {
		_, err := DecodeRequest([]byte(in))
		got := 0
		if err != nil {
			got = err.Code
		}
		if got != want {
			t.Fatalf("%s: code %d, want %d", in, got, want)
		}
	}
	if _, err := DecodeRequest(make([]byte, MaxMessage+1)); err == nil {
		t.Fatal("oversized")
	}
}

func TestIPC_MessagesMatchContract(t *testing.T) {
	id := uint64(3)
	n := make([]byte, NonceSize)
	mac, _ := MAC(make([]byte, 32), n, "panic.release", nil)
	msgs := []any{
		Request{JSONRPC: "2.0", ID: 3, Method: "panic.release", Params: json.RawMessage(`{}`), Auth: &Auth{Nonce: n, MAC: mac}},
		Response{JSONRPC: "2.0", ID: &id, Result: json.RawMessage(`{"ok":true}`)},
		Response{JSONRPC: "2.0", ID: &id, Error: &Error{Code: CodeAuth, Message: "x"}},
		Notification{JSONRPC: "2.0", Method: "event", Params: map[string]any{"type": "check.alert"}},
	}
	for _, m := range msgs {
		if err := contracts.Validate("ipc", m); err != nil {
			t.Fatalf("%T: %v", m, err)
		}
	}
	for m := range Methods {
		raw, _ := json.Marshal(Request{JSONRPC: "2.0", ID: 1, Method: m})
		if err := contracts.ValidateJSON("ipc", raw); err != nil {
			t.Fatalf("method %s not in the schema: %v", m, err)
		}
	}
}

func TestIPC_DeriveKey(t *testing.T) {
	k1, err := DeriveKey([]byte("pw"), []byte("salt-salt-salt-1"))
	if err != nil || len(k1) != 32 {
		t.Fatal(err)
	}
	k2, _ := DeriveKey([]byte("pw"), []byte("salt-salt-salt-2"))
	if string(k1) == string(k2) {
		t.Fatal("salt must change the key")
	}
	if _, err := MAC(k1, nil, "m", json.RawMessage(`{bad`)); err == nil {
		t.Fatal("invalid params must not MAC")
	}
}

func FuzzDecodeRequest(f *testing.F) {
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"status.get","params":{}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":2,"method":"panic.release","params":{"a":[1,2]},"auth":{"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRequest(b)
		if err == nil {
			if _, ok := Methods[r.Method]; !ok || r.JSONRPC != "2.0" {
				t.Fatalf("accepted invalid request %+v", r)
			}
		}
	})
}

// Requests are capped at 64 KiB, but answers grow with the session (every alert, the recent
// events): a busy session must not break status.get or events.query on the client.
func TestIPC_LargeResponsesReachTheClient(t *testing.T) {
	f := newFixture(t, os.Getuid())
	big := strings.Repeat("x", 3*MaxMessage)
	f.srv.Handle("events.query", func(*Call) (any, error) { return []string{big}, nil })
	c := f.dial(t)
	var out []string
	if err := c.Call("events.query", nil, nil, &out); err != nil || len(out) != 1 || len(out[0]) != len(big) {
		t.Fatalf("err=%v len=%d", err, len(out))
	}
	var st map[string]int
	if err := c.Call("status.get", nil, nil, &st); err != nil {
		t.Fatalf("connection unusable after a large answer: %v", err)
	}
}

// A listener that is not root (an impostor of the operator's UID in /run/user/<uid>/lethe)
// never receives a byte from DialDaemon: the passphrase of session.arm stays home.
func TestAC14_ClientRefusesNonRootListener(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: every listener here is root")
	}
	path := filepath.Join(t.TempDir(), "fake.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	got := make(chan int, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			got <- -1
			return
		}
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := c.Read(make([]byte, 64))
		got <- n
		_ = c.Close()
	}()
	if _, err := DialDaemon(path, time.Second); !errors.Is(err, ErrNotDaemon) {
		t.Fatalf("err = %v", err)
	}
	if n := <-got; n > 0 {
		t.Fatalf("the impostor read %d bytes", n)
	}
}

// A connection that hoards challenges evicts only its own: another connection still gets a
// nonce and proves (the GUI keeps its way out of a panic), and a proof made on one connection's
// nonce is refused on another's.
func TestSELF006_ChallengesBoundToTheirConnection(t *testing.T) {
	f := newFixture(t, os.Getuid())
	hog := f.dial(t)
	var first []byte
	for i := 0; i < 200; i++ {
		var ch struct{ Nonce []byte }
		if err := hog.Call("auth.challenge", nil, nil, &ch); err != nil {
			t.Fatalf("challenge %d: %v", i, err)
		}
		if i == 0 {
			first = ch.Nonce
		}
	}
	gui := f.dial(t)
	proof, err := gui.Prove(f.key, "panic.release", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gui.Call("panic.release", map[string]any{}, proof, nil); err != nil {
		t.Fatalf("the other connection cannot prove: %v", err)
	}
	// a proof over the hog's nonce, sent on the GUI's connection, is refused without counting
	mac, _ := MAC(f.key, first, "panic.release", json.RawMessage(`{}`))
	if err := gui.Call("panic.release", map[string]any{}, &Auth{Nonce: first, MAC: mac}, nil); err == nil {
		t.Fatal("a nonce of another connection was accepted")
	}
}
