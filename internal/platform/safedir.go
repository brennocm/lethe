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

// SecureDir sets the mode (permission, setgid and sticky bits) and the owner (-1 keeps it) of
// an open directory. The mode goes first, while the caller still owns the directory: the
// service daemon is root without CAP_FOWNER, so once it has handed the directory to the
// operator it may no longer chmod it (ADR 0019). chown(2) keeps a directory's setgid bit.
func SecureDir(d *os.File, uid, gid int, mode uint32) error {
	fd := int(d.Fd()) // #nosec G115 -- fd
	if err := unix.Fchmod(fd, mode); err != nil {
		return &os.PathError{Op: "chmod", Path: d.Name(), Err: err}
	}
	if uid >= 0 || gid >= 0 {
		if err := unix.Fchown(fd, uid, gid); err != nil {
			return &os.PathError{Op: "chown", Path: d.Name(), Err: err}
		}
	}
	return nil
}

// EnsureDir is SecureDir that changes only what differs: an owner, group or mode already in
// place costs no chown/chmod, so a process without CAP_CHOWN can open a directory prepared
// earlier.
func EnsureDir(d *os.File, uid, gid int, mode uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(int(d.Fd()), &st); err != nil { // #nosec G115 -- fd
		return &os.PathError{Op: "stat", Path: d.Name(), Err: err}
	}
	if uid >= 0 && st.Uid == uint32(uid) { // #nosec G115 -- uid >= 0
		uid = -1
	}
	if gid >= 0 && st.Gid == uint32(gid) { // #nosec G115 -- gid >= 0
		gid = -1
	}
	const bits = 0o7777
	if uid < 0 && gid < 0 && st.Mode&bits == mode&bits {
		return nil
	}
	return SecureDir(d, uid, gid, mode)
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

// OpenDir opens path as a directory, creating it (mode perm) when missing. The path itself may be
// a symlink the operator chose (storage.dir); what is created inside goes through MkdirAt.
func OpenDir(path string, perm uint32) (*os.File, error) {
	if err := os.MkdirAll(path, os.FileMode(perm)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil // #nosec G115 -- fd from open(2)
}

// WriteFileAt replaces name inside dir atomically, never following a symlink: a temporary file
// is created with O_EXCL|O_NOFOLLOW (a planted .name.tmp -> /etc/shadow is removed, not
// written through), owned by uid/gid when they are >= 0, set to mode perm, synced and renamed
// over name. Root writes into storage.dir/state only through this.
func WriteFileAt(dir *os.File, name string, data []byte, perm uint32, uid, gid int) error {
	if name == "" || name == "." || name == ".." || containsSlash(name) {
		return fmt.Errorf("bad file name %q", name)
	}
	dfd := int(dir.Fd()) // #nosec G115 -- fd
	tmp := "." + name + ".tmp"
	if err := unix.Unlinkat(dfd, tmp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "unlink", Path: dir.Name() + "/" + tmp, Err: err}
	}
	fd, err := unix.Openat(dfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, perm)
	if err != nil {
		return &os.PathError{Op: "create", Path: dir.Name() + "/" + tmp, Err: err}
	}
	f := os.NewFile(uintptr(fd), dir.Name()+"/"+tmp) // #nosec G115 -- fd from openat(2)
	_, err = f.Write(data)
	if err == nil { // perm as given, whatever the umask (the service units run with 0077)
		err = unix.Fchmod(fd, perm) // before the chown: without CAP_FOWNER root may not chmod what it gave away
	}
	if err == nil && (uid >= 0 || gid >= 0) {
		err = unix.Fchown(fd, uid, gid)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = unix.Renameat(dfd, tmp, dfd, name)
	}
	if err != nil {
		_ = unix.Unlinkat(dfd, tmp, 0)
		return fmt.Errorf("write %s/%s: %w", dir.Name(), name, err)
	}
	return nil
}
