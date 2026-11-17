package fswatch

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// An atomic replacement through rename (how resolv.conf changes) is seen, as is a write to the
// symlink's target.
func TestDNS004_WatchDirectoryAndTarget(t *testing.T) {
	dir := t.TempDir()
	run := filepath.Join(dir, "run")
	_ = os.Mkdir(run, 0o755)
	target := filepath.Join(run, "stub-resolv.conf")
	_ = os.WriteFile(target, []byte("nameserver 127.0.0.53\n"), 0o600)
	link := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	w, err := New(link)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 16)
	go func() { _ = w.Run(ctx, func(c Change) { got <- c.Path }, nil) }()
	time.Sleep(50 * time.Millisecond)

	_ = os.WriteFile(filepath.Join(dir, "unrelated"), []byte("x"), 0o600)
	tmp := filepath.Join(dir, ".resolv.tmp")
	_ = os.Symlink(target, tmp)
	if err := os.Rename(tmp, link); err != nil {
		t.Fatal(err)
	}
	expect(t, got, link)
	_ = os.WriteFile(target, []byte("nameserver 192.0.2.53\n"), 0o600)
	expect(t, got, target)
}

func expect(t *testing.T, got chan string, want string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case p := <-got:
			if p == want {
				return
			}
			if filepath.Base(p) == "unrelated" {
				t.Fatal("a file outside the set was reported")
			}
		case <-deadline:
			t.Fatalf("no change for %s", want)
		}
	}
}

func TestDNS004_NothingToWatch(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "missing", "resolv.conf")); err == nil {
		t.Fatal("a missing directory gives no watch")
	}
}
