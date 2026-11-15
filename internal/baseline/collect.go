package baseline

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// Local holds identity facts read from the local system (no network access).
type Local struct {
	Hostname string
	Username string
	Timezone string
	Locale   string
}

// CollectLocal reads hostname, the operator's username (SUDO_USER when run via sudo),
// timezone (/etc/localtime) and locale (LANG/LC_ALL). Root is the filesystem root, for tests.
func CollectLocal(root string, env func(string) string) Local {
	var l Local
	if raw, err := os.ReadFile(filepath.Join(root, "etc/hostname")); err == nil { // #nosec G304 -- fixed path under root
		l.Hostname = strings.TrimSpace(string(raw))
	}
	if l.Hostname == "" && root == "/" {
		l.Hostname, _ = os.Hostname()
	}
	l.Username = env("SUDO_USER")
	if l.Username == "" {
		if u, err := user.Current(); err == nil {
			l.Username = u.Username
		}
	}
	if target, err := os.Readlink(filepath.Join(root, "etc/localtime")); err == nil {
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			l.Timezone = target[i+len("zoneinfo/"):]
		}
	}
	if l.Timezone == "" {
		if raw, err := os.ReadFile(filepath.Join(root, "etc/timezone")); err == nil { // #nosec G304 -- fixed path under root
			l.Timezone = strings.TrimSpace(string(raw))
		}
	}
	for _, k := range []string{"LC_ALL", "LANG"} {
		if v := env(k); v != "" {
			l.Locale = v
			break
		}
	}
	return l
}

// Apply copies local facts into the baseline.
func (l Local) Apply(b *Baseline) {
	b.Hostname, b.Username, b.Timezone, b.Locale = l.Hostname, l.Username, l.Timezone, l.Locale
}
