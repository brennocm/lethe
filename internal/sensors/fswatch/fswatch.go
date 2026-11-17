// Package fswatch watches the DNS configuration with inotify (DNS-004, spec §9.2). The
// directory is watched, not the file: /etc/resolv.conf is usually a symlink replaced atomically,
// and a watch on the file itself loses every replacement. The symlink target's directory is
// watched as well.
package fswatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SourceID of this sensor.
const SourceID = "fswatch"

// Change is one modification of a watched file.
type Change struct {
	Path string
	At   time.Time
}

const mask = unix.IN_CLOSE_WRITE | unix.IN_MOVED_TO | unix.IN_MOVED_FROM | unix.IN_CREATE | unix.IN_DELETE |
	unix.IN_ATTRIB | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF

// Watcher reports changes to a set of files.
type Watcher struct {
	f     *os.File
	dirs  map[int]string  // watch descriptor -> directory
	files map[string]bool // the files whose changes count
}

// New watches files (and, for a symlink, its target): each file's directory gets one watch.
func New(files ...string) (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("fswatch: %w", err)
	}
	w := &Watcher{f: os.NewFile(uintptr(fd), "inotify"), dirs: map[int]string{}, files: map[string]bool{}}
	for _, p := range Targets(files...) {
		w.files[p] = true
		dir := filepath.Dir(p)
		if w.has(dir) {
			continue
		}
		wd, err := unix.InotifyAddWatch(fd, dir, mask)
		if err != nil {
			continue // a missing directory is not an error: nothing to watch there
		}
		w.dirs[wd] = dir
	}
	if len(w.dirs) == 0 {
		_ = w.f.Close()
		return nil, errors.New("fswatch: no directory could be watched")
	}
	return w, nil
}

func (w *Watcher) has(dir string) bool {
	for _, d := range w.dirs {
		if d == dir {
			return true
		}
	}
	return false
}

// Targets expands each path with its symlink target (one level of resolution, then the final
// one), deduplicated and sorted.
func Targets(files ...string) []string {
	set := map[string]bool{}
	for _, p := range files {
		p = filepath.Clean(p)
		set[p] = true
		if t, err := os.Readlink(p); err == nil {
			if !filepath.IsAbs(t) {
				t = filepath.Join(filepath.Dir(p), t)
			}
			set[filepath.Clean(t)] = true
		}
		if t, err := filepath.EvalSymlinks(p); err == nil {
			set[t] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Run reads events until ctx ends and calls on for every change of a watched file. beat is
// called at least every 500 ms while the watch is healthy (SELF-001).
func (w *Watcher) Run(ctx context.Context, on func(Change), beat func(time.Time)) error {
	go func() { <-ctx.Done(); _ = w.f.Close() }()
	buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))
	for {
		_ = w.f.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := w.f.Read(buf)
		if beat != nil {
			beat(time.Now())
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue
			}
			return fmt.Errorf("fswatch: %w", err)
		}
		for _, c := range w.parse(buf[:n]) {
			on(c)
		}
	}
}

func (w *Watcher) parse(b []byte) []Change {
	var out []Change
	seen := map[string]bool{}
	for off := 0; off+unix.SizeofInotifyEvent <= len(b); {
		ev := (*unix.InotifyEvent)(unsafe.Pointer(&b[off])) // #nosec G103 -- kernel ABI layout
		nameLen := int(ev.Len)
		start := off + unix.SizeofInotifyEvent
		if start+nameLen > len(b) {
			break
		}
		name := string(trimNUL(b[start : start+nameLen]))
		off = start + nameLen
		dir, ok := w.dirs[int(ev.Wd)]
		if !ok {
			continue
		}
		p := dir
		if name != "" {
			p = filepath.Join(dir, name)
		}
		if (w.files[p] || ev.Mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0) && !seen[p] {
			seen[p] = true
			out = append(out, Change{Path: p, At: time.Now()})
		}
	}
	return out
}

func trimNUL(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}

// Close stops the watch.
func (w *Watcher) Close() error { return w.f.Close() }
