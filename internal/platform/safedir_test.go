package platform

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSELF001_WriteFileAtNeverFollowsSymlinks: root writes storage.dir/state, which the operator
// owns. A planted temporary-name symlink must be replaced, never written through, and the
// target must stay intact.
func TestSELF001_WriteFileAtNeverFollowsSymlinks(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("intact"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{".selftest.json.tmp", "selftest.json"} {
		if err := os.Symlink(victim, filepath.Join(state, link)); err != nil {
			t.Fatal(err)
		}
	}
	d, err := OpenDir(state, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if err := WriteFileAt(d, "selftest.json", []byte("new"), 0o600, -1, -1); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "intact" {
		t.Fatalf("the symlink target was written: %q", b)
	}
	fi, err := os.Lstat(filepath.Join(state, "selftest.json"))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("selftest.json is not a regular file: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "selftest.json")); string(b) != "new" {
		t.Fatalf("content %q", b)
	}
	if _, err := os.Lstat(filepath.Join(state, ".selftest.json.tmp")); !os.IsNotExist(err) {
		t.Fatal("temporary file left behind")
	}
	if err := WriteFileAt(d, "../x", nil, 0o600, -1, -1); err == nil {
		t.Fatal("a name with a slash was accepted")
	}
}

// TestSELF001_MkdirAtRefusesSymlinkedDir: state -> /etc must not be opened as the state dir.
func TestSELF001_MkdirAtRefusesSymlinkedDir(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "state")); err != nil {
		t.Fatal(err)
	}
	d, err := OpenDir(root, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if _, err := MkdirAt(d, "state", 0o700); err == nil {
		t.Fatal("a symlinked state directory was accepted")
	}
}
