package procscan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHOST001_Matcher(t *testing.T) {
	ff := Process{PID: 10, Exe: "/usr/lib/firefox/firefox", Comm: "GeckoMain", Cgroup: "/user.slice/user-1000.slice/app-org.mozilla.firefox-123.scope"}
	tb := Process{PID: 11, Exe: "/home/x/tor-browser/Browser/firefox.real", Comm: "firefox.real", Cgroup: "/user.slice/app-torbrowser-9.scope"}
	cases := []struct {
		m    Matcher
		p    Process
		want bool
	}{
		{Matcher{"exe", "firefox"}, ff, true},
		{Matcher{"exe", "/usr/lib/firefox/firefox"}, ff, true},
		{Matcher{"exe", "/usr/bin/firefox"}, ff, false},
		{Matcher{"exe", "firefox"}, tb, false},
		{Matcher{"exe", "firefox"}, Process{Exe: "/usr/lib/firefox/firefox (deleted)"}, true},
		{Matcher{"exe", "firefox"}, Process{Comm: "firefox"}, false},
		{Matcher{"comm", "GeckoMain"}, ff, true},
		{Matcher{"cgroup", "app-*torbrowser*.scope"}, tb, true},
		{Matcher{"cgroup", "app-*torbrowser*.scope"}, ff, false},
		{Matcher{"pid", "10"}, ff, false},
	}
	for _, c := range cases {
		if got := c.m.Matches(c.p); got != c.want {
			t.Fatalf("%+v on %+v: %v", c.m, c.p, got)
		}
	}
}

func TestHOST001_ListFixture(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "42")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink("/usr/bin/curl", filepath.Join(d, "exe"))
	_ = os.WriteFile(filepath.Join(d, "comm"), []byte("curl\n"), 0o644)
	_ = os.WriteFile(filepath.Join(d, "cgroup"), []byte("0::/user.slice/x.scope\n"), 0o644)
	_ = os.WriteFile(filepath.Join(d, "status"), []byte("Name:\tcurl\nUid:\t1000\t1000\t1000\t1000\n"), 0o644)
	_ = os.MkdirAll(filepath.Join(root, "43"), 0o755) // vanished: no comm
	_ = os.MkdirAll(filepath.Join(root, "self"), 0o755)
	ps, err := List(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 1 || ps[0].Exe != "/usr/bin/curl" || ps[0].Cgroup != "/user.slice/x.scope" || ps[0].UID != 1000 {
		t.Fatalf("%+v", ps)
	}
	if _, err := List(filepath.Join(root, "nope")); err == nil {
		t.Fatal("missing root")
	}
}
