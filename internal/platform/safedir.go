package platform

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// The daemon runs as root but creates directories inside places the operator owns
// (/run/user/<uid>, storage.dir). Path-based chown/chmod there would follow a symlink the operator's
// processes planted (sessions -> /etc). These helpers work on directory descriptors opened with
// O_NOFOLLOW, so a later rename or swap of the path cannot redirect what root changes.

// ErrNotDir: the name exists and is not a directory (a symlink included).
var ErrNotDir = errors.New("exists and is not a directory (symlinks are refused)")

// MkdirAt creates name inside parent (if missing) with mode perm and opens it without following
// a symlink.
func MkdirAt(parent *os.File, name string, perm uint32) (*os.File, error) {
	if name == "" || name == "." || name == ".." || containsSlash(name) {
		return nil, fmt.Errorf("bad directory name %q", name)
	}
	pfd := int(parent.Fd()) // #nosec G115 -- fd
	if err := unix.Mkdirat(pfd, name, perm); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, &os.PathError{Op: "mkdir", Path: parent.Name() + "/" + name, Err: err}
	}
	fd, err := unix.Openat(pfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("%s/%s %w", parent.Name(), name, ErrNotDir)
		}
		return nil, &os.PathError{Op: "open", Path: parent.Name() + "/" + name, Err: err}
	}
	return os.NewFile(uintptr(fd), parent.Name()+"/"+name), nil // #nosec G115 -- fd from openat(2)
}

// SecureDir sets the owner (-1 keeps it) and the mode (permission, setgid and sticky bits) of
// an open directory.
func SecureDir(d *os.File, uid, gid int, mode uint32) error {
	fd := int(d.Fd()) // #nosec G115 -- fd
	if uid >= 0 || gid >= 0 {
		if err := unix.Fchown(fd, uid, gid); err != nil {
			return &os.PathError{Op: "chown", Path: d.Name(), Err: err}
		}
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return &os.PathError{Op: "chmod", Path: d.Name(), Err: err}
	}
	return nil
}

// FDPath names an open directory through /proc/self/fd: paths under it resolve to that inode no
// matter what happens to the original path.
func FDPath(d *os.File) string { return "/proc/self/fd/" + strconv.Itoa(int(d.Fd())) } // #nosec G115

func containsSlash(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return true
		}
	}
	return false
}
