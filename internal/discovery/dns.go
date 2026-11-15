package discovery

import (
	"bufio"
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// ReadResolvConf parses the resolv.conf at path (normally /etc/resolv.conf), following symlinks.
func ReadResolvConf(path string) (ResolvConf, error) {
	rc := ResolvConf{Path: path, Nameservers: []string{}}
	if target, err := filepath.EvalSymlinks(path); err == nil && target != path {
		rc.Target = target
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- fixed system path (or a test fixture)
	if err != nil {
		return rc, err
	}
	rc.Nameservers = parseNameservers(raw)
	for _, ns := range rc.Nameservers {
		if ns == "127.0.0.53" || ns == "127.0.0.54" {
			rc.Stub = true
		}
	}
	return rc, nil
}

func parseNameservers(raw []byte) []string {
	out := []string{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			addr := f[1]
			if i := strings.IndexByte(addr, '%'); i >= 0 {
				addr = addr[:i] // drop zone of link-local IPv6
			}
			if a, err := netip.ParseAddr(addr); err == nil {
				out = append(out, a.String())
			}
		}
	}
	return out
}

// ResolvedClient reads systemd-resolved state. The D-Bus implementation lives in dbus_resolved.go.
type ResolvedClient interface {
	Links(names map[int]string) ([]ResolvedLink, error)
}
