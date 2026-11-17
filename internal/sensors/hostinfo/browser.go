package hostinfo

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Prefs are the privacy-relevant preferences of one Firefox or Tor Browser profile (PER-002).
// A missing preference keeps Firefox's default.
type Prefs struct {
	Dir                string `json:"-"`
	Found              bool   `json:"found"`
	PeerConnection     bool   `json:"peerconnection"`       // media.peerconnection.enabled (default true)
	DefaultAddressOnly bool   `json:"default_address_only"` // media.peerconnection.ice.default_address_only
	TRRMode            int    `json:"trr_mode"`             // network.trr.mode
	SOCKSProxy         bool   `json:"socks_proxy"`          // network.proxy.type = 1 with a socks host
	SOCKSRemoteDNS     bool   `json:"socks_remote_dns"`     // network.proxy.socks_remote_dns
}

var prefLine = regexp.MustCompile(`^\s*user_pref\(\s*"([^"]+)"\s*,\s*(.+?)\s*\)\s*;`)

// BrowserPrefs reads prefs.js then user.js (user.js wins, as in Firefox) of a profile directory.
// Files are opened without following a symlink at the last component and read up to 4 MiB.
func BrowserPrefs(dir string) Prefs {
	p := Prefs{Dir: dir, PeerConnection: true}
	vals := map[string]string{}
	for _, name := range []string{"prefs.js", "user.js"} {
		b := readNoFollow(filepath.Join(dir, name), 4<<20)
		if b == nil {
			continue
		}
		p.Found = true
		for line := range strings.SplitSeq(string(b), "\n") {
			if m := prefLine.FindStringSubmatch(line); m != nil {
				vals[m[1]] = strings.Trim(m[2], `"`)
			}
		}
	}
	if v, ok := vals["media.peerconnection.enabled"]; ok {
		p.PeerConnection = v != "false"
	}
	p.DefaultAddressOnly = vals["media.peerconnection.ice.default_address_only"] == "true"
	if v, ok := vals["network.trr.mode"]; ok {
		for _, c := range v {
			if c >= '0' && c <= '9' {
				p.TRRMode = p.TRRMode*10 + int(c-'0')
			}
		}
	}
	p.SOCKSProxy = vals["network.proxy.type"] == "1" && vals["network.proxy.socks"] != ""
	p.SOCKSRemoteDNS = vals["network.proxy.socks_remote_dns"] == "true"
	return p
}

// ChromiumPolicy is the WebRtcIPHandling policy of Chromium and Chrome ("" = not set).
type ChromiumPolicy struct {
	Installed        bool   `json:"installed"`
	WebRtcIPHandling string `json:"webrtc_ip_handling"`
}

// Chromium reads the managed policies of Chromium and Google Chrome.
func (r Reader) Chromium() ChromiumPolicy {
	var c ChromiumPolicy
	for _, bin := range []string{"usr/bin/chromium", "usr/bin/chromium-browser", "usr/bin/google-chrome", "usr/bin/google-chrome-stable", "opt/google/chrome/chrome"} {
		if _, err := os.Stat(r.path(bin)); err == nil {
			c.Installed = true
		}
	}
	var files []string
	for _, d := range []string{"etc/chromium/policies/managed", "etc/opt/chrome/policies/managed"} {
		m, _ := filepath.Glob(filepath.Join(r.path(d), "*.json"))
		files = append(files, m...)
	}
	sort.Strings(files)
	for _, f := range files {
		var pol map[string]any
		if json.Unmarshal(readNoFollow(f, 1<<20), &pol) != nil {
			continue
		}
		if v, ok := pol["WebRtcIPHandling"].(string); ok {
			c.WebRtcIPHandling = v
		}
	}
	return c
}

func readNoFollow(path string, limit int64) []byte {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(path) // #nosec G304 -- profile paths from the operator's profile; regular files only
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	b, _ := io.ReadAll(io.LimitReader(f, limit))
	return b
}
