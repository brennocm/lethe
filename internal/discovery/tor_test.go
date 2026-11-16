package discovery

import (
	"bufio"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestTorctl_TrustedServer(t *testing.T) {
	cases := []struct {
		uid  int
		exe  string
		want bool
	}{
		{110, "/usr/bin/tor", true},                                     // debian-tor
		{1000, "/home/op/tor-browser/Browser/TorBrowser/Tor/tor", true}, // operator's Tor Browser
		{1001, "/usr/bin/tor", false},                                   // another login user
		{110, "/usr/bin/python3", false},                                // a system user, but not tor
		{1000, "/tmp/torx", false},
		{-1, "/usr/bin/tor", false},
	}
	for _, c := range cases {
		if got := trustedTor(c.uid, c.exe, 1000); got != c.want {
			t.Errorf("uid %d exe %s: got %v", c.uid, c.exe, got)
		}
	}
}

// A process that is not tor holds the control port: lethe must not even send PROTOCOLINFO.
func TestTorctl_UntrustedServerNotQueried(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		line, _ := bufio.NewReader(c).ReadString('\n')
		got <- line
	}()
	tc := NewTorControl(l.Addr().String(), "auto", 1000)
	tc.Peer = func(local, remote netip.AddrPort) (int, string, error) {
		if remote.String() != l.Addr().String() || !local.Addr().IsLoopback() {
			t.Errorf("peer lookup with %v -> %v", local, remote)
		}
		return 1001, "/usr/bin/nc", nil
	}
	if _, err := tc.Status(); !errors.Is(err, ErrUntrustedTor) {
		t.Fatalf("got %v", err)
	}
	if line := <-got; strings.TrimSpace(line) != "" {
		t.Fatalf("sent %q to an untrusted server", line)
	}
}
