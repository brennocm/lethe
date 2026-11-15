package sockdiag

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"lethe/internal/contracts"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

var socks = []Sock{
	{Proto: "tcp", Local: ap("10.0.0.2:40000"), Remote: ap("198.51.100.1:443"), Inode: 11, UID: 1000},
	{Proto: "udp", Local: ap("0.0.0.0:40001"), Remote: ap("0.0.0.0:0"), Inode: 12, UID: 1000},
	{Proto: "tcp", Local: ap("10.0.0.2:40002"), Remote: ap("198.51.100.1:443"), Inode: 99, UID: 1001},
	{Proto: "udp", Local: ap("[::]:40003"), Remote: ap("[::]:0"), Inode: 13, UID: 0},
}

var owners = map[uint32]Owner{
	11: {PID: 4121, Exe: "/usr/bin/curl", Comm: "curl", UID: 1000},
	12: {PID: 4200, Exe: "/usr/bin/nc", Comm: "nc", UID: 1000},
	13: {PID: 1, Exe: "/usr/lib/systemd/systemd", Comm: "systemd", UID: 0},
}

func TestNET010_Attribute(t *testing.T) {
	cases := []struct {
		name     string
		proto    string
		src, dst string
		pid      int
		conf     contracts.Confidence
	}{
		{"exact tcp", "tcp", "10.0.0.2:40000", "198.51.100.1:443", 4121, contracts.ConfidenceHigh},
		{"tcp other dst only local port", "tcp", "10.0.0.2:40000", "198.51.100.2:443", 0, contracts.ConfidenceNone},
		{"unconnected udp", "udp", "10.0.0.2:40001", "192.0.2.1:9", 4200, contracts.ConfidenceLow},
		{"wrong proto", "udp", "10.0.0.2:40000", "198.51.100.1:443", 0, contracts.ConfidenceNone},
		{"socket without process", "tcp", "10.0.0.2:40002", "198.51.100.1:443", 0, contracts.ConfidenceLow},
		{"v4 packet from dual-stack wildcard", "udp", "[::ffff:10.0.0.2]:40003", "192.0.2.1:9", 1, contracts.ConfidenceLow},
		{"v6 wildcard", "udp", "[2001:db8:1::2]:40003", "[2001:db8::1]:9", 1, contracts.ConfidenceLow},
		{"nothing", "tcp", "10.0.0.2:1", "192.0.2.1:2", 0, contracts.ConfidenceNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Attribute(socks, owners, c.proto, ap(c.src), ap(c.dst))
			if p.PID != c.pid || p.Confidence != c.conf {
				t.Fatalf("got %+v", p)
			}
		})
	}
	if p := Attribute(socks, owners, "tcp", ap("10.0.0.2:40002"), ap("198.51.100.1:443")); p.UID != 1001 {
		t.Fatalf("uid of orphan socket: %+v", p)
	}
}

func TestNET010_OwnersFromProcFixture(t *testing.T) {
	root := t.TempDir()
	mk := func(pid string, links map[string]string, exe, comm, status string) {
		fd := filepath.Join(root, pid, "fd")
		if err := os.MkdirAll(fd, 0o755); err != nil {
			t.Fatal(err)
		}
		for n, target := range links {
			if err := os.Symlink(target, filepath.Join(fd, n)); err != nil {
				t.Fatal(err)
			}
		}
		if exe != "" {
			if err := os.Symlink(exe, filepath.Join(root, pid, "exe")); err != nil {
				t.Fatal(err)
			}
		}
		_ = os.WriteFile(filepath.Join(root, pid, "comm"), []byte(comm+"\n"), 0o644)
		_ = os.WriteFile(filepath.Join(root, pid, "status"), []byte(status), 0o644)
	}
	mk("4121", map[string]string{"0": "/dev/null", "3": "socket:[11]", "4": "pipe:[5]"}, "/usr/bin/curl", "curl", "Name:\tcurl\nUid:\t1000\t1000\t1000\t1000\n")
	mk("4122", map[string]string{"3": "socket:[11]", "5": "socket:[77]"}, "/usr/bin/curl", "curl", "Uid:\t1000\t1000\t1000\t1000\n")
	mk("4300", map[string]string{"1": "socket:[notanumber]"}, "", "x", "")
	if err := os.MkdirAll(filepath.Join(root, "self"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Owners(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[11].PID != 4121 || got[11].Exe != "/usr/bin/curl" || got[11].UID != 1000 || got[11].Comm != "curl" || got[77].PID != 4122 {
		t.Fatalf("owners=%+v", got)
	}
	if _, err := Owners(filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing proc root must fail")
	}
}
