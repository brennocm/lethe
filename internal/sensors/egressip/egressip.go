// Package egressip asks public "what is my IP" services which address the traffic leaves with
// (NET-011, spec §9.9). The query never uses the system path: for a VPN the socket is bound to the
// tunnel interface and names are resolved by a resolver of its own, also bound to the tunnel,
// that asks the tunnel's DNS; for Tor it goes through the SOCKS port with remote resolution
// (socks5h). Without a DNS server known in the tunnel the check is skipped, never answered by
// the system resolver. Requests carry a common browser User-Agent and nothing that names lethe.
package egressip

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
	"unicode"

	"golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
)

// SourceID of this sensor.
const SourceID = "egressip"

// UserAgent is a common browser string: the query must not become a signature that links
// personas.
const UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"

// Path is how the query leaves.
type Path struct {
	Tunnel string                                                            // VPN: tunnel interface (SO_BINDTODEVICE)
	DNS    []netip.Addr                                                      // VPN: resolvers reached through the tunnel
	Socks  netip.AddrPort                                                    // Tor: SOCKS listener (socks5h)
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error) // tests: replaces the dialer
}

// Config is the request side.
type Config struct {
	Endpoints []string       // https URLs (active_checks.egress_ip.endpoints)
	RootCAs   *x509.CertPool // nil = the system roots
	Timeout   time.Duration  // per endpoint (default 15 s)
	Pick      func(n int) []int
}

// Answer is one endpoint's reply.
type Answer struct {
	Endpoint string
	IP       netip.Addr
	Place    Place
	Err      error
}

// Place is where an endpoint says the address is (am.i.mullvad.net answers country and city).
// It is the endpoint's claim, untrusted: shown to the operator with its source, never used to
// decide an alert (the country of NET-011 comes from the offline database).
type Place struct {
	Country string
	City    string
	Source  string // endpoint host
}

// Result of one round. Skipped explains why there is no result (no tunnel DNS, too few
// endpoints); Agreed is false when the endpoints disagree or failed.
type Result struct {
	IP      netip.Addr
	Place   Place // the first endpoint that said where the address is
	Agreed  bool
	Skipped string
	Answers []Answer
}

// Errors that skip the round.
var (
	ErrNoTunnelDNS = errors.New("no DNS server known in the tunnel")
	ErrFewEnds     = errors.New("active_checks.egress_ip.endpoints needs at least two endpoints")
	ErrNoPath      = errors.New("no tunnel interface and no Tor SOCKS port")
)

// Query asks two endpoints, chosen at random, through p.
func Query(ctx context.Context, p Path, cfg Config) Result {
	if len(cfg.Endpoints) < 2 {
		return Result{Skipped: ErrFewEnds.Error()}
	}
	client, err := clientFor(p, cfg)
	if err != nil {
		return Result{Skipped: err.Error()}
	}
	pick := cfg.Pick
	if pick == nil {
		pick = func(n int) []int { return rand.Perm(n)[:2] } // #nosec G404 -- only spreads the queries
	}
	res := Result{}
	for _, i := range pick(len(cfg.Endpoints)) {
		ep := cfg.Endpoints[i]
		ip, place, err := ask(ctx, client, ep)
		res.Answers = append(res.Answers, Answer{Endpoint: ep, IP: ip, Place: place, Err: err})
	}
	a, b := res.Answers[0], res.Answers[1]
	if a.Err == nil && b.Err == nil && a.IP == b.IP {
		res.IP, res.Agreed = a.IP, true
		for _, x := range res.Answers {
			if x.Place.Country != "" || x.Place.City != "" {
				res.Place = x.Place
				break
			}
		}
	}
	return res
}

func clientFor(p Path, cfg Config) (*http.Client, error) {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	tr := &http.Transport{
		Proxy:               nil, // never an environment proxy
		TLSClientConfig:     &tls.Config{RootCAs: cfg.RootCAs, MinVersion: tls.VersionTLS12},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: timeout,
		MaxIdleConns:        0,
	}
	switch {
	case p.Dial != nil:
		tr.DialContext = p.Dial
	case p.Socks.IsValid():
		d, err := proxy.SOCKS5("tcp", p.Socks.String(), nil, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, err
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("socks dialer without context")
		}
		tr.DialContext = cd.DialContext // the host name goes to tor as is: remote resolution
	case p.Tunnel != "":
		if len(p.DNS) == 0 {
			return nil, ErrNoTunnelDNS
		}
		tr.DialContext = (&net.Dialer{Timeout: timeout, Control: bindTo(p.Tunnel), Resolver: tunnelResolver(p.Tunnel, p.DNS, timeout)}).DialContext
	default:
		return nil, ErrNoPath
	}
	return &http.Client{Transport: tr, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

func bindTo(iface string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) { serr = unix.BindToDevice(int(fd), iface) }); err != nil { // #nosec G115
			return err
		}
		return serr
	}
}

// tunnelResolver asks only the tunnel's DNS servers, from sockets bound to the tunnel. The
// address the Go resolver passes (from resolv.conf) is ignored.
func tunnelResolver(iface string, servers []netip.Addr, timeout time.Duration) *net.Resolver {
	next := 0
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		srv := servers[next%len(servers)]
		next++
		d := net.Dialer{Timeout: timeout, Control: bindTo(iface)}
		if !strings.HasPrefix(network, "tcp") {
			network = "udp"
		}
		return d.DialContext(ctx, network, netip.AddrPortFrom(srv, 53).String())
	}}
}

func ask(ctx context.Context, c *http.Client, endpoint string) (netip.Addr, Place, error) {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return netip.Addr{}, Place{}, fmt.Errorf("endpoint %q is not an https URL", endpoint)
	}
	body, err := get(ctx, c, endpoint)
	if err != nil {
		return netip.Addr{}, Place{}, err
	}
	ip, err := ParseIP(body)
	if err != nil {
		return netip.Addr{}, Place{}, err
	}
	p := ParsePlace(body)
	if p.Country != "" || p.City != "" {
		p.Source = u.Host
	}
	return ip, p, nil
}

// get fetches endpoint (https, at most 64 KiB of answer) with a browser User-Agent.
func get(ctx context.Context, c *http.Client, endpoint string) ([]byte, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", u.Host, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<10))
}

// ParsePlace reads country and city from a JSON answer (country or country_name, city). The
// text is cleaned: printable characters only, at most 64 of them.
func ParsePlace(body []byte) Place {
	var obj map[string]any
	if json.Unmarshal(body, &obj) != nil {
		return Place{}
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if s, ok := obj[k].(string); ok {
				if c := Clean(s); c != "" {
					return c
				}
			}
		}
		return ""
	}
	return Place{Country: str("country", "country_name"), City: str("city")}
}

// Clean keeps the printable characters of s (no control or format characters, which could
// reorder or hide text on the operator's screen) and cuts it at 64.
func Clean(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range strings.TrimSpace(s) {
		if n == 64 {
			break
		}
		if !unicode.IsPrint(r) {
			continue
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimSpace(b.String())
}

// ParseIP reads the address from a JSON object (ip, IP, query, origin) or from plain text.
func ParseIP(body []byte) (netip.Addr, error) {
	var obj map[string]any
	if json.Unmarshal(body, &obj) == nil {
		for _, k := range []string{"ip", "IP", "query", "origin"} {
			if s, ok := obj[k].(string); ok {
				if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
					return a.Unmap(), nil
				}
			}
		}
		return netip.Addr{}, errors.New("no address in the JSON answer")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil {
		return netip.Addr{}, errors.New("the answer is not an address")
	}
	return a.Unmap(), nil
}

// TunnelDNS lists the resolvers NET-011 may ask through tunnel: the profile's
// (active_checks.tunnel_dns), systemd-resolved's servers of that link, and the resolv.conf
// nameservers whose route leaves through it. Loopback stubs are never used: behind them is the
// system resolver.
func TunnelDNS(tunnel string, profile []netip.Addr, resolvedLink []string, resolvConf []string, via func(netip.Addr) string) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(a netip.Addr) {
		a = a.Unmap()
		if a.IsValid() && !a.IsLoopback() && !a.IsUnspecified() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, a := range profile {
		add(a)
	}
	for _, s := range resolvedLink {
		if a, err := netip.ParseAddr(s); err == nil {
			add(a)
		}
	}
	for _, s := range resolvConf {
		if a, err := netip.ParseAddr(s); err == nil && via != nil && via(a) == tunnel {
			add(a)
		}
	}
	return out
}
