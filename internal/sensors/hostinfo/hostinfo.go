// Package hostinfo reads host facts from files and sysfs (spec §9.4): hostname, timezone,
// locale, console keyboard, disk and swap encryption and time synchronization. Every path is
// relative to Root so tests run on fixtures. Reads are bounded and never follow a path chosen by
// an unprivileged user.
package hostinfo

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SourceID of this sensor.
const SourceID = "hostinfo"

const maxFile = 64 << 10

// Facts is one reading.
type Facts struct {
	Hostname string `json:"hostname"`
	Timezone string `json:"timezone"` // IANA name; "" when unknown
	Locale   string `json:"locale"`   // system LANG
	Keyboard string `json:"keyboard"` // console/X11 layout of the system configuration
	// RootEncrypted: nil = could not tell (no sysfs), else whether / sits on dm-crypt.
	RootEncrypted *bool `json:"root_encrypted,omitempty"`
	// PlainSwap lists active swap devices that are neither dm-crypt nor zram.
	PlainSwap []string `json:"plain_swap"`
	// TimeSync lists the time synchronization daemons configured on the host.
	TimeSync []string `json:"time_sync"`
}

// Reader reads Facts under Root ("/" in production).
type Reader struct{ Root string }

func (r Reader) path(p string) string {
	root := r.Root
	if root == "" {
		root = "/"
	}
	return filepath.Join(root, p)
}

func (r Reader) read(p string) []byte {
	f, err := os.Open(r.path(p)) // #nosec G304 -- fixed system paths under Root
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	b, _ := io.ReadAll(io.LimitReader(f, maxFile))
	return b
}

// Read collects every fact; a missing source leaves its field empty.
func (r Reader) Read() Facts {
	f := Facts{PlainSwap: []string{}, TimeSync: []string{}}
	f.Hostname = strings.TrimSpace(string(r.read("proc/sys/kernel/hostname")))
	if f.Hostname == "" {
		f.Hostname = strings.TrimSpace(string(r.read("etc/hostname")))
	}
	f.Timezone = r.timezone()
	f.Locale = firstNonEmpty(kv(r.read("etc/locale.conf"), "LANG"), kv(r.read("etc/default/locale"), "LANG"))
	f.Keyboard = firstNonEmpty(kv(r.read("etc/default/keyboard"), "XKBLAYOUT"), kv(r.read("etc/vconsole.conf"), "XKBLAYOUT"),
		kv(r.read("etc/vconsole.conf"), "KEYMAP"), x11Layout(r.read("etc/X11/xorg.conf.d/00-keyboard.conf")))
	f.RootEncrypted = r.rootEncrypted()
	f.PlainSwap = r.plainSwap()
	f.TimeSync = r.timeSync()
	return f
}

// timezone is the zone /etc/localtime links to, or /etc/timezone.
func (r Reader) timezone() string {
	if t, err := os.Readlink(r.path("etc/localtime")); err == nil {
		if _, zone, ok := strings.Cut(t, "zoneinfo/"); ok {
			return zone
		}
	}
	return strings.TrimSpace(string(r.read("etc/timezone")))
}

// kv reads KEY=value (shell style, optional quotes) from a config file.
func kv(b []byte, key string) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, key+"="); ok {
			return strings.Trim(rest, `"'`)
		}
	}
	return ""
}

// x11Layout reads Option "XkbLayout" "us" from an xorg.conf.d snippet (localectl writes it).
func x11Layout(b []byte) string {
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "Option" && strings.Trim(f[1], `"`) == "XkbLayout" {
			return strings.Trim(f[2], `"`)
		}
	}
	return ""
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

// rootEncrypted finds the device of / in mountinfo and walks its slaves looking for dm-crypt.
func (r Reader) rootEncrypted() *bool {
	dev := ""
	for line := range strings.SplitSeq(string(r.read("proc/self/mountinfo")), "\n") {
		f := strings.Fields(line)
		if len(f) > 4 && f[4] == "/" {
			dev = f[2] // major:minor
		}
	}
	if dev == "" {
		return nil
	}
	sys := r.path("sys/dev/block/" + dev)
	if _, err := os.Stat(sys); err != nil {
		return nil
	}
	enc := r.cryptBelow(sys, 0)
	return &enc
}

// cryptBelow reports whether the block device at sys, or anything it is stacked on, is dm-crypt.
func (r Reader) cryptBelow(sys string, depth int) bool {
	if depth > 8 {
		return false
	}
	if b, err := os.ReadFile(filepath.Join(sys, "dm", "uuid")); err == nil && strings.HasPrefix(string(b), "CRYPT-") { // #nosec G304 -- sysfs
		return true
	}
	slaves, _ := os.ReadDir(filepath.Join(sys, "slaves"))
	for _, s := range slaves {
		if r.cryptBelow(filepath.Join(sys, "slaves", s.Name()), depth+1) {
			return true
		}
	}
	// a partition's parent holds no dm info; a dm device on a partition lists it in slaves
	return false
}

// plainSwap lists active swap devices that are neither zram nor on dm-crypt.
func (r Reader) plainSwap() []string {
	out := []string{}
	lines := strings.Split(string(r.read("proc/swaps")), "\n")
	for _, line := range lines[min(1, len(lines)):] {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		name := f[0]
		base := filepath.Base(name)
		if strings.HasPrefix(base, "zram") {
			continue
		}
		if f[1] == "partition" {
			if sys := r.path("sys/class/block/" + base); r.cryptBelow(sys, 0) {
				continue
			}
		}
		// a swap file lives on a filesystem: encrypted when / is (the common layout)
		if f[1] == "file" {
			if e := r.rootEncrypted(); e != nil && *e {
				continue
			}
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// timeSync lists configured synchronization daemons (enabled units or their config files).
func (r Reader) timeSync() []string {
	out := []string{}
	units := map[string][]string{
		"systemd-timesyncd": {"etc/systemd/system/sysinit.target.wants/systemd-timesyncd.service", "etc/systemd/system/multi-user.target.wants/systemd-timesyncd.service"},
		"chrony":            {"etc/chrony.conf", "etc/chrony/chrony.conf"},
		"ntpd":              {"etc/ntp.conf", "etc/ntpsec/ntp.conf"},
	}
	for name, paths := range units {
		for _, p := range paths {
			if _, err := os.Lstat(r.path(p)); err == nil {
				out = append(out, name)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
