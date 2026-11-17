package torctl

import (
	"context"
	"errors"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Bridge is one Bridge line of the configuration.
type Bridge struct {
	Transport string         // "" for a plain bridge
	Addr      netip.AddrPort // invalid if the line has no parseable address
}

// Status is what discovery needs from tor (spec §7.5).
type Status struct {
	Version            string
	Bootstrap          int // 0..100
	CircuitEstablished bool
	UseBridges         bool
	Bridges            []Bridge
	Guards             []netip.AddrPort // first hops of built circuits and live entry guards, sorted
	Socks              []netip.AddrPort // TCP SOCKS listeners (NET-011 asks through them, socks5h)
}

// Transports returns the distinct pluggable transports of the configured bridges (only when
// UseBridges is on).
func (s Status) Transports() []string {
	if !s.UseBridges {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, b := range s.Bridges {
		if b.Transport != "" && !seen[b.Transport] {
			seen[b.Transport] = true
			out = append(out, b.Transport)
		}
	}
	sort.Strings(out)
	return out
}

// GetInfo returns the values of the keys. A key the server does not know is an error.
func (c *Conn) GetInfo(ctx context.Context, keys ...string) (map[string]string, error) {
	for _, k := range keys {
		if !validKey(k) {
			return nil, errors.New("tor control: bad GETINFO key")
		}
	}
	rep, err := c.Command(ctx, "GETINFO "+strings.Join(keys, " "))
	if err != nil {
		return nil, err
	}
	if err := rep.Err(); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, l := range rep.Lines {
		k, v, ok := strings.Cut(l.Text, "=")
		if !ok {
			continue // the final "OK"
		}
		if l.Data != nil {
			v = strings.Join(l.Data, "\n")
		}
		out[k] = v
	}
	return out, nil
}

// GetConf returns every value of one option (an unset option yields none).
func (c *Conn) GetConf(ctx context.Context, key string) ([]string, error) {
	if !validKey(key) {
		return nil, errors.New("tor control: bad GETCONF key")
	}
	rep, err := c.Command(ctx, "GETCONF "+key)
	if err != nil {
		return nil, err
	}
	if err := rep.Err(); err != nil {
		return nil, err
	}
	var out []string
	for _, l := range rep.Lines {
		if _, v, ok := strings.Cut(l.Text, "="); ok {
			out = append(out, v)
		}
	}
	return out, nil
}

// SetEvents subscribes to asynchronous events (replacing any previous subscription).
func (c *Conn) SetEvents(ctx context.Context, events ...string) error {
	for _, e := range events {
		if !validKey(e) {
			return errors.New("tor control: bad event name")
		}
	}
	return c.ok(ctx, strings.TrimSpace("SETEVENTS "+strings.Join(events, " ")))
}

var keyRE = regexp.MustCompile(`^[A-Za-z0-9_/.\-]+$`)

func validKey(k string) bool { return len(k) <= 128 && keyRE.MatchString(k) }

var fpRE = regexp.MustCompile(`^\$?([0-9A-Fa-f]{40})`)

// Status queries bootstrap, circuits, guards and bridges. Each guard fingerprint is resolved
// through ns/id/<fp>; one that is not in the consensus (a bridge) is covered by the Bridge lines.
func (c *Conn) Status(ctx context.Context) (Status, error) {
	info, err := c.GetInfo(ctx, "version", "status/bootstrap-phase", "status/circuit-established", "circuit-status")
	if err != nil {
		return Status{}, err
	}
	st := Status{Version: info["version"], CircuitEstablished: info["status/circuit-established"] == "1"}
	if p, err := strconv.Atoi(parseKV(info["status/bootstrap-phase"])["PROGRESS"]); err == nil && p >= 0 && p <= 100 {
		st.Bootstrap = p
	}
	fps := map[string]bool{}
	for _, line := range strings.Split(info["circuit-status"], "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || (f[1] != "BUILT" && f[1] != "EXTENDED") {
			continue
		}
		first, _, _ := strings.Cut(f[2], ",")
		if m := fpRE.FindStringSubmatch(first); m != nil {
			fps[strings.ToUpper(m[1])] = true
		}
	}
	// entry-guards is deprecated in newer tor; its absence is not an error.
	if eg, err := c.GetInfo(ctx, "entry-guards"); err == nil {
		for _, line := range strings.Split(eg["entry-guards"], "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[1] == "up" {
				if m := fpRE.FindStringSubmatch(f[0]); m != nil {
					fps[strings.ToUpper(m[1])] = true
				}
			}
		}
	} else if !isUnrecognized(err) {
		return Status{}, err
	}
	use, err := c.GetConf(ctx, "UseBridges")
	if err != nil {
		return Status{}, err
	}
	st.UseBridges = len(use) > 0 && use[0] == "1"
	lines, err := c.GetConf(ctx, "Bridge")
	if err != nil {
		return Status{}, err
	}
	for _, l := range lines {
		st.Bridges = append(st.Bridges, ParseBridge(l))
	}
	guards := map[netip.AddrPort]bool{}
	for fp := range fps {
		ns, err := c.GetInfo(ctx, "ns/id/"+fp)
		if err != nil {
			if isUnrecognized(err) {
				continue
			}
			return Status{}, err
		}
		for _, ap := range parseNS(ns["ns/id/"+fp]) {
			guards[ap] = true
		}
	}
	for ap := range guards {
		st.Guards = append(st.Guards, ap)
	}
	sort.Slice(st.Guards, func(i, j int) bool { return st.Guards[i].Compare(st.Guards[j]) < 0 })
	if li, err := c.GetInfo(ctx, "net/listeners/socks"); err == nil {
		st.Socks = ParseListeners(li["net/listeners/socks"])
	} else if !isUnrecognized(err) {
		return Status{}, err
	}
	return st, nil
}

// isUnrecognized is tor's 552 (unrecognized key or entity).
func isUnrecognized(err error) bool {
	var re *ReplyError
	return errors.As(err, &re) && re.Code == 552
}

// ParseBridge parses a Bridge line: "[transport] IP:ORPort [fingerprint] [k=v...]".
func ParseBridge(line string) Bridge {
	f := strings.Fields(line)
	if len(f) == 0 {
		return Bridge{}
	}
	if ap, err := netip.ParseAddrPort(f[0]); err == nil {
		return Bridge{Addr: unmap(ap)}
	}
	b := Bridge{Transport: strings.ToLower(f[0])}
	if len(f) > 1 {
		if ap, err := netip.ParseAddrPort(f[1]); err == nil {
			b.Addr = unmap(ap)
		}
	}
	return b
}

// parseNS extracts the ORPorts of a router status entry: the "r" line (IPv4) and "a" lines.
func parseNS(doc string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, line := range strings.Split(doc, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) >= 8 && f[0] == "r":
			a, err1 := netip.ParseAddr(f[6])
			p, err2 := strconv.ParseUint(f[7], 10, 16)
			if err1 == nil && err2 == nil && p > 0 {
				out = append(out, netip.AddrPortFrom(a.Unmap(), uint16(p)))
			}
		case len(f) >= 2 && f[0] == "a":
			if ap, err := netip.ParseAddrPort(f[1]); err == nil && ap.Port() > 0 {
				out = append(out, unmap(ap))
			}
		}
	}
	return out
}

func unmap(ap netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) }

// ParseListeners reads a net/listeners/* value: quoted addresses separated by spaces; unix
// sockets are left out.
func ParseListeners(v string) []netip.AddrPort {
	var out []netip.AddrPort
	for _, f := range strings.Fields(v) {
		f = strings.Trim(f, `"`)
		if ap, err := netip.ParseAddrPort(f); err == nil {
			out = append(out, ap)
		}
	}
	return out
}
