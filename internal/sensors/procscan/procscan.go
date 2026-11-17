// Package procscan lists processes from /proc and matches them against profile rules
// (processes.kill_on_panic, processes.deny). Processes are matched by exe, never by a
// truncated comm unless the rule asks for comm explicitly.
package procscan

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// SourceID of this sensor (spec §9.7).
const SourceID = "procscan"

// Process is one /proc entry.
type Process struct {
	PID    int
	Exe    string // readlink exe; "" for kernel threads or unreadable
	Comm   string
	Cgroup string // cgroup v2 path ("0::/user.slice/…")
	UID    int
	// Filled by Scan with Detail: the command line (NUL-split, at most maxCmdline bytes) and the
	// capture devices the process holds open (/dev/video*, /dev/snd/pcmC*D*c).
	Cmdline []string
	Devices []string
}

// maxCmdline bounds what is read of /proc/<pid>/cmdline.
const maxCmdline = 16 << 10

// Detail asks Scan for the command line and the open capture devices (HOST-002, PER-003).
type Detail struct {
	Cmdline bool
	Devices bool
}

// IsCaptureDevice reports whether a /proc/<pid>/fd target is a camera or a capture PCM.
func IsCaptureDevice(target string) bool {
	if strings.HasPrefix(target, "/dev/video") {
		return true
	}
	if rest, ok := strings.CutPrefix(target, "/dev/snd/pcmC"); ok {
		return strings.HasSuffix(rest, "c") && strings.Contains(rest, "D")
	}
	return false
}

// Matcher is one profile rule: match ∈ exe | comm | cgroup.
type Matcher struct {
	Match string
	Value string
}

// Matches reports whether p matches m. exe: a value with "/" compares the full path, otherwise
// the basename; comm: exact; cgroup: glob (path.Match) against any path component.
func (m Matcher) Matches(p Process) bool {
	switch m.Match {
	case "exe":
		if p.Exe == "" {
			return false
		}
		exe := strings.TrimSuffix(p.Exe, " (deleted)")
		if strings.Contains(m.Value, "/") {
			return exe == m.Value
		}
		return filepath.Base(exe) == m.Value
	case "comm":
		return p.Comm == m.Value
	case "cgroup":
		for _, c := range strings.Split(p.Cgroup, "/") {
			if ok, _ := path.Match(m.Value, c); ok {
				return true
			}
		}
	}
	return false
}

// List scans root (normally /proc). Vanished or unreadable processes are skipped.
func List(root string) ([]Process, error) { return Scan(root, Detail{}) }

// Scan is List with the optional details.
func Scan(root string, det Detail) ([]Process, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("procscan: %w", err)
	}
	var out []Process
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(root, e.Name())
		p := Process{PID: pid, UID: -1}
		p.Exe, _ = os.Readlink(filepath.Join(dir, "exe"))
		if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil { // #nosec G304 -- under root
			p.Comm = strings.TrimSpace(string(b))
		} else {
			continue // gone
		}
		if b, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil { // #nosec G304 -- under root
			for line := range strings.SplitSeq(string(b), "\n") {
				if rest, ok := strings.CutPrefix(line, "0::"); ok {
					p.Cgroup = rest
				}
			}
		}
		if b, err := os.ReadFile(filepath.Join(dir, "status")); err == nil { // #nosec G304 -- under root
			for line := range strings.SplitSeq(string(b), "\n") {
				if rest, ok := strings.CutPrefix(line, "Uid:"); ok {
					if f := strings.Fields(rest); len(f) > 0 {
						p.UID, _ = strconv.Atoi(f[0])
					}
					break
				}
			}
		}
		if det.Cmdline {
			p.Cmdline = readCmdline(filepath.Join(dir, "cmdline"))
		}
		if det.Devices {
			p.Devices = captureDevices(filepath.Join(dir, "fd"))
		}
		out = append(out, p)
	}
	return out, nil
}

func readCmdline(path string) []string {
	f, err := os.Open(path) // #nosec G304 -- under root
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, maxCmdline)
	n, _ := f.Read(buf)
	var out []string
	for _, a := range strings.Split(strings.TrimRight(string(buf[:n]), "\x00"), "\x00") {
		if a != "" {
			out = append(out, a)
		}
	}
	return out
}

func captureDevices(fdDir string) []string {
	ents, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range ents {
		t, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err == nil && IsCaptureDevice(t) && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}
