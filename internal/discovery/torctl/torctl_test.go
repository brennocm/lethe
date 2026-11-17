package torctl

import (
	"bufio"
	"context"
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeTor answers control commands from a handler; it returns the raw reply text to send.
type fakeTor struct {
	t       *testing.T
	handle  func(cmd string) string
	srv     net.Conn
	gotCmds chan string
}

func newFake(t *testing.T, handle func(cmd string) string) (*Conn, *fakeTor) {
	t.Helper()
	a, b := net.Pipe()
	f := &fakeTor{t: t, handle: handle, srv: b, gotCmds: make(chan string, 64)}
	go func() {
		r := bufio.NewReader(b)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.TrimRight(line, "\r\n")
			f.gotCmds <- cmd
			if _, err := b.Write([]byte(f.handle(cmd))); err != nil {
				return
			}
		}
	}()
	c := New(a)
	t.Cleanup(func() { c.Close(); b.Close() })
	return c, f
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestTorctl_ReplyParsing(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("250-a=1\r\n250+b=\r\nline1\r\n..dotted\r\n.\r\n250 OK\r\n"))
	rep, err := readReply(r)
	if err != nil || len(rep.Lines) != 3 || rep.Lines[1].Data[1] != ".dotted" || rep.Code() != 250 {
		t.Fatalf("%+v %v", rep, err)
	}
	for name, in := range map[string]string{
		"mixed codes": "250-a\r\n251 b\r\n",
		"bad sep":     "250*x\r\n",
		"short":       "25\r\n",
		"not digits":  "2x0 OK\r\n",
		"long line":   "250 " + strings.Repeat("x", maxLine+10) + "\r\n",
	} {
		if _, err := readReply(bufio.NewReader(strings.NewReader(in))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	big := "250+x=\r\n" + strings.Repeat(strings.Repeat("y", 1000)+"\r\n", maxReply/1000+2) + ".\r\n250 OK\r\n"
	if _, err := readReply(bufio.NewReader(strings.NewReader(big))); err == nil {
		t.Error("oversized reply accepted")
	}
}

func TestTorctl_DialRefusesRemote(t *testing.T) {
	if _, err := Dial(ctx(t), "198.51.100.1:9051"); !errors.Is(err, ErrNotLoopback) {
		t.Fatalf("got %v", err)
	}
}

func TestTorctl_ParseKV(t *testing.T) {
	kv := parseKV(`METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/run/tor/a \"b\"\\c" X=1`)
	if kv["METHODS"] != "COOKIE,SAFECOOKIE" || kv["COOKIEFILE"] != `/run/tor/a "b"\c` || kv["X"] != "1" {
		t.Fatalf("%v", kv)
	}
}

func writeCookie(t *testing.T, n int) (string, []byte) {
	t.Helper()
	cookie := make([]byte, n)
	for i := range cookie {
		cookie[i] = byte(i + 1)
	}
	p := filepath.Join(t.TempDir(), "control_auth_cookie")
	if err := os.WriteFile(p, cookie, 0o600); err != nil {
		t.Fatal(err)
	}
	return p, cookie
}

// safeCookieServer implements the server side of SAFECOOKIE; lie makes it send a bad server hash.
func safeCookieServer(cookiePath string, cookie []byte, lie bool, authed *bool) func(string) string {
	sn := make([]byte, nonceLen)
	for i := range sn {
		sn[i] = 0xA0
	}
	var msg []byte
	return func(cmd string) string {
		switch {
		case cmd == "PROTOCOLINFO 1":
			return "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"" + cookiePath + "\"\r\n250-VERSION Tor=\"0.4.8.13\"\r\n250 OK\r\n"
		case strings.HasPrefix(cmd, "AUTHCHALLENGE SAFECOOKIE "):
			cn, _ := hex.DecodeString(strings.TrimPrefix(cmd, "AUTHCHALLENGE SAFECOOKIE "))
			msg = append(append(append([]byte{}, cookie...), cn...), sn...)
			sh := mac(serverKey, msg)
			if lie {
				sh[0] ^= 1
			}
			return "250 AUTHCHALLENGE SERVERHASH=" + hex.EncodeToString(sh) + " SERVERNONCE=" + hex.EncodeToString(sn) + "\r\n"
		case strings.HasPrefix(cmd, "AUTHENTICATE "):
			got, _ := hex.DecodeString(strings.TrimPrefix(cmd, "AUTHENTICATE "))
			if hmac.Equal(got, mac(clientKey, msg)) {
				*authed = true
				return "250 OK\r\n"
			}
			return "515 Authentication failed\r\n"
		}
		return "510 Unrecognized command\r\n"
	}
}

func TestTorctl_SafeCookie(t *testing.T) {
	path, cookie := writeCookie(t, cookieLen)
	var authed bool
	c, _ := newFake(t, safeCookieServer(path, cookie, false, &authed))
	if err := c.Authenticate(ctx(t), "auto", me()); err != nil || !authed {
		t.Fatalf("auth: %v authed=%v", err, authed)
	}
}

func TestTorctl_SafeCookieServerMustProveCookie(t *testing.T) {
	path, cookie := writeCookie(t, cookieLen)
	var authed bool
	c, f := newFake(t, safeCookieServer(path, cookie, true, &authed))
	if err := c.Authenticate(ctx(t), path, me()); !errors.Is(err, ErrServerHash) {
		t.Fatalf("got %v", err)
	}
	close(f.gotCmds)
	for cmd := range f.gotCmds {
		if strings.HasPrefix(cmd, "AUTHENTICATE") {
			t.Fatal("client answered a server that failed its proof")
		}
	}
}

func TestTorctl_CookieSizeAndMethods(t *testing.T) {
	path, cookie := writeCookie(t, cookieLen+1)
	var authed bool
	c, _ := newFake(t, safeCookieServer(path, cookie, false, &authed))
	if err := c.Authenticate(ctx(t), path, me()); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("33-byte cookie: %v", err)
	}
	for _, methods := range []string{"COOKIE", "HASHEDPASSWORD", ""} {
		c, _ := newFake(t, func(string) string {
			return "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=" + methods + "\r\n250 OK\r\n"
		})
		if err := c.Authenticate(ctx(t), "auto", me()); !errors.Is(err, ErrNoUsableAuth) {
			t.Errorf("methods %q: %v", methods, err)
		}
	}
}

func TestTorctl_NullAuthRefused(t *testing.T) {
	c, _ := newFake(t, func(cmd string) string {
		if cmd == "PROTOCOLINFO 1" {
			return "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=NULL\r\n250 OK\r\n"
		}
		return "250 OK\r\n"
	})
	if err := c.Authenticate(ctx(t), "auto", me()); !errors.Is(err, ErrNoUsableAuth) {
		t.Fatalf("NULL auth would trust whoever holds the port: %v", err)
	}
}

func TestTorctl_CookieOwnership(t *testing.T) {
	path, cookie := writeCookie(t, cookieLen)
	var authed bool
	c, _ := newFake(t, safeCookieServer(path, cookie, false, &authed))
	if err := c.Authenticate(ctx(t), path, me()+1); !errors.Is(err, ErrCookieOwner) {
		t.Fatalf("cookie of another uid: %v", err)
	}
	if err := os.Chmod(path, 0o620); err != nil {
		t.Fatal(err)
	}
	c, _ = newFake(t, safeCookieServer(path, cookie, false, &authed))
	if err := c.Authenticate(ctx(t), path, me()); !errors.Is(err, ErrCookieOwner) || authed {
		t.Fatalf("group-writable cookie: %v", err)
	}
}

func me() uint32 { return uint32(os.Getuid()) }

const (
	fpA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	fpC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
)

func statusServer(bridges string, useBridges string, events bool) func(string) string {
	return func(cmd string) string {
		switch cmd {
		case "GETINFO version status/bootstrap-phase status/circuit-established circuit-status":
			reply := "250-version=0.4.8.13\r\n" +
				"250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n" +
				"250-status/circuit-established=1\r\n" +
				"250+circuit-status=\r\n" +
				"1 BUILT $" + fpA + "~guard1,$" + fpC + "~mid PURPOSE=GENERAL\r\n" +
				"2 LAUNCHED $" + fpC + "~mid\r\n" +
				".\r\n250 OK\r\n"
			if events {
				reply = "650 CIRC 3 BUILT $" + fpA + "~guard1\r\n" + reply
			}
			return reply
		case "GETINFO entry-guards":
			return "250+entry-guards=\r\n$" + fpA + "~guard1 up\r\n$" + fpB + "=guard2 down\r\n.\r\n250 OK\r\n"
		case "GETCONF UseBridges":
			return "250 UseBridges=" + useBridges + "\r\n"
		case "GETCONF Bridge":
			return bridges
		case "GETINFO ns/id/" + fpA:
			return "250+ns/id/" + fpA + "=\r\nr guard1 qqqq rrrr 2026-11-15 10:00:00 203.0.113.9 9001 0\r\na [2001:db8::9]:9001\r\ns Fast Guard Running Stable Valid\r\n.\r\n250 OK\r\n"
		}
		return "552 Unrecognized key\r\n"
	}
}

func TestTorctl_Status(t *testing.T) {
	c, _ := newFake(t, statusServer("250 Bridge\r\n", "0", true))
	st, err := c.Status(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:9001"), netip.MustParseAddrPort("[2001:db8::9]:9001")}
	if st.Bootstrap != 100 || !st.CircuitEstablished || st.Version != "0.4.8.13" || len(st.Guards) != 2 ||
		st.Guards[0] != want[0] || st.Guards[1] != want[1] || st.UseBridges || len(st.Bridges) != 0 {
		t.Fatalf("%+v", st)
	}
	select {
	case ev := <-c.Events():
		if ev.Type != "CIRC" {
			t.Fatalf("event %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
}

func TestTorctl_Bridges(t *testing.T) {
	c, _ := newFake(t, statusServer(
		"250-Bridge=obfs4 198.51.100.4:443 "+fpB+" cert=xyz iat-mode=0\r\n"+
			"250-Bridge=198.51.100.5:9001\r\n"+
			"250 Bridge=snowflake 192.0.2.3:80 "+fpC+" url=https://snowflake.example/\r\n", "1", false))
	st, err := c.Status(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if !st.UseBridges || len(st.Bridges) != 3 || st.Bridges[0] != (Bridge{"obfs4", netip.MustParseAddrPort("198.51.100.4:443")}) ||
		st.Bridges[1].Transport != "" || st.Bridges[2].Transport != "snowflake" {
		t.Fatalf("%+v", st.Bridges)
	}
	if tr := st.Transports(); len(tr) != 2 || tr[0] != "obfs4" || tr[1] != "snowflake" {
		t.Fatalf("transports %v", tr)
	}
}

func TestTorctl_LostEvents(t *testing.T) {
	flood := strings.Repeat("650 STATUS_CLIENT NOTICE CIRCUIT_ESTABLISHED\r\n", eventBuffer+5)
	c, _ := newFake(t, func(string) string { return flood + "250 OK\r\n" })
	if err := c.SetEvents(ctx(t), "CIRC", "STATUS_CLIENT", "GUARD"); err != nil {
		t.Fatal(err)
	}
	if !c.LostEvents() || c.LostEvents() {
		t.Fatal("overflow must be reported once")
	}
}

func TestTorctl_ClosedConnection(t *testing.T) {
	c, f := newFake(t, func(string) string { return "" })
	f.srv.Close()
	<-c.Done()
	if _, err := c.Command(ctx(t), "GETINFO version"); err == nil {
		t.Fatal("command on a closed connection")
	}
	if _, ok := <-c.Events(); ok {
		t.Fatal("events channel stays open")
	}
}

func TestTorctl_RejectsInjection(t *testing.T) {
	c, _ := newFake(t, func(string) string { return "250 OK\r\n" })
	if _, err := c.GetInfo(ctx(t), "version\r\nSIGNAL HALT"); err == nil {
		t.Fatal("newline in key")
	}
	if _, err := c.GetConf(ctx(t), "Bridge SIGNAL"); err == nil {
		t.Fatal("space in key")
	}
}

func TestNET011_ParseSocksListeners(t *testing.T) {
	got := ParseListeners(`"127.0.0.1:9050" "unix:/run/tor/socks" "[::1]:9150"`)
	if len(got) != 2 || got[0].String() != "127.0.0.1:9050" || got[1].String() != "[::1]:9150" {
		t.Fatal(got)
	}
}
