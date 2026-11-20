package platform

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
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

// TestSELF004_EnsureDirChangesOnlyWhatDiffers: a directory already right needs no chown, so a
// daemon without CAP_CHOWN can reopen storage.dir/state; a wrong mode is still fixed.
func TestSELF004_EnsureDirChangesOnlyWhatDiffers(t *testing.T) {
	parent, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Close() }()
	d, err := MkdirAt(parent, "state", 0o700)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(d.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	// same owner and group: no chown, only the mode changes
	if err := EnsureDir(d, int(st.Uid), int(st.Gid), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstat(int(d.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode&0o7777 != 0o750 {
		t.Fatalf("mode %o", st.Mode&0o7777)
	}
	if err := EnsureDir(d, int(st.Uid), int(st.Gid), 0o750); err != nil {
		t.Fatalf("already right: %v", err)
	}
	if os.Geteuid() != 0 { // a foreign owner needs CAP_CHOWN: the error is reported, not hidden
		if err := EnsureDir(d, int(st.Uid)+1, -1, 0o750); err == nil {
			t.Fatal("chown to another uid without CAP_CHOWN succeeded")
		}
	}
}
