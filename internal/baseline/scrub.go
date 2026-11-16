package baseline

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// field is one baseline value with the name events may carry instead (spec §12.1).
type field struct {
	name  string // "baseline.networks[0].resolvers"
	value string
	exact bool // IPs and MACs: whole-value match after normalization; text: substring
}

func normIP(s string) (string, bool) {
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap().String(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap().String(), true
	}
	return "", false
}

func normMAC(s string) (string, bool) {
	if m, err := net.ParseMAC(s); err == nil {
		return m.String(), true
	}
	return "", false
}

func (b *Baseline) fields() []field {
	var out []field
	ip := func(name, v string) {
		if n, ok := normIP(v); ok {
			out = append(out, field{name, n, true})
		}
	}
	mac := func(name, v string) {
		if n, ok := normMAC(v); ok {
			out = append(out, field{name, n, true})
		}
	}
	text := func(name, v string) {
		if v = strings.TrimSpace(v); len(v) >= 3 {
			out = append(out, field{name, asciiLower(v), false})
		}
	}
	for _, m := range b.PermMACs {
		mac("baseline.perm_macs", m)
	}
	text("baseline.hostname", b.Hostname)
	text("baseline.username", b.Username)
	for i, n := range b.Networks {
		p := fmt.Sprintf("baseline.networks[%d].", i)
		ip(p+"public_ipv4", n.PublicIPv4)
		ip(p+"public_ipv6", n.PublicIPv6)
		ip(p+"gateway_ip", n.GatewayIP)
		mac(p+"gateway_mac", n.GatewayMAC)
		for _, r := range n.Resolvers {
			ip(p+"resolvers", r)
		}
		text(p+"provider", n.Provider)
		for _, s := range n.SSIDs {
			text(p+"ssids", s)
		}
	}
	// Longer text first, so a value that contains another is replaced whole.
	sort.SliceStable(out, func(i, j int) bool { return len(out[i].value) > len(out[j].value) })
	return out
}

// Scrub returns a copy of event data with every baseline value replaced by "[baseline]" and the
// names of the matched fields in "matched" (comma-separated). IPs and MACs match whole values
// (an "ip:port" too) after normalization; hostname, username, provider and SSIDs match as
// case-insensitive substrings (an exe under /home/<username> included). Sealed fields are left
// alone. The copy goes through JSON, so typed values (contracts.Proc) become plain maps.
func (b *Baseline) Scrub(data map[string]any) (map[string]any, error) {
	if len(data) == 0 {
		return data, nil
	}
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var cp map[string]any
	if err := json.Unmarshal(raw, &cp); err != nil {
		return nil, err
	}
	fs := b.fields()
	matched := map[string]bool{}
	var walk func(v any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case map[string]any:
			if t["enc"] == "s1" {
				return t // sealed field: ciphertext, never rewritten
			}
			for k, x := range t {
				t[k] = walk(x)
			}
			return t
		case []any:
			for i, x := range t {
				t[i] = walk(x)
			}
			return t
		case string:
			return scrubString(t, fs, matched)
		}
		return v
	}
	cp = walk(cp).(map[string]any)
	if len(matched) > 0 {
		names := make([]string, 0, len(matched))
		for n := range matched {
			names = append(names, n)
		}
		sort.Strings(names)
		cp["matched"] = strings.Join(names, ",")
	}
	return cp, nil
}

func scrubString(s string, fs []field, matched map[string]bool) string {
	nIP, isIP := normIP(s)
	nMAC, isMAC := normMAC(s)
	whole := false
	for _, f := range fs {
		if f.exact && ((isIP && nIP == f.value) || (isMAC && nMAC == f.value)) {
			matched[f.name] = true // every field holding this value is named
			whole = true
		}
	}
	if whole {
		return "[baseline]"
	}
	for _, f := range fs {
		if f.exact {
			continue
		}
		s = replaceFold(s, f, matched)
	}
	return s
}

// replaceFold replaces every ASCII-case-insensitive occurrence of f.value in s.
func replaceFold(s string, f field, matched map[string]bool) string {
	lower := asciiLower(s)
	if !strings.Contains(lower, f.value) {
		return s
	}
	var out strings.Builder
	for {
		i := strings.Index(lower, f.value)
		if i < 0 {
			break
		}
		out.WriteString(s[:i])
		out.WriteString("[baseline]")
		s, lower = s[i+len(f.value):], lower[i+len(f.value):]
	}
	out.WriteString(s)
	matched[f.name] = true
	return out.String()
}

// asciiLower lowers A-Z only, so byte offsets stay aligned with the original.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
