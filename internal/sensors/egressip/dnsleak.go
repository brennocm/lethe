package egressip

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"
)

// DNS leak test (spec §9.9, operator-requested only). The names i.ID.<domain> are resolved the
// way every program on the machine resolves them, through the system resolver: that is the path
// being tested. The servers that asked the test's authoritative DNS are then fetched from the
// API through the same path as NET-011 (the tunnel or Tor), never through the system path.

// LeakConfig is the test's side.
type LeakConfig struct {
	Domain string                                       // names are N.ID.Domain (bash.ws)
	API    string                                       // https URL with one %s for the ID
	Lookup func(ctx context.Context, host string) error // nil = the system resolver
	ID     func() (string, error)                       // nil = 7 random digits
	Names  int                                          // names resolved (default 10)
	Config Config                                       // RootCAs and timeout of the API fetch
	Sleep  func(ctx context.Context, d time.Duration)   // nil = a real wait before the fetch
	Wait   time.Duration                                // before the fetch (default 2 s)
}

// LeakServer is one address in the API's answer.
type LeakServer struct {
	IP          netip.Addr
	Country     string // ISO code, cleaned
	CountryName string
	ASN         string
}

// LeakResult is one test.
type LeakResult struct {
	Exit    *LeakServer
	DNS     []LeakServer
	Skipped string
}

// DefaultLeakDomain and DefaultLeakAPI are bash.ws's free test.
const (
	DefaultLeakDomain = "bash.ws"
	DefaultLeakAPI    = "https://bash.ws/dnsleak/test/%s?json"
)

// Errors of the test's API.
var (
	ErrLeakAPI  = errors.New("the DNS leak test answered something unexpected")
	ErrLeakNone = errors.New("no lookup reached the test (the system resolver answered nothing or nothing left the machine)")
)

// DNSLeak runs the test.
func DNSLeak(ctx context.Context, p Path, cfg LeakConfig) LeakResult {
	if cfg.Domain == "" {
		cfg.Domain = DefaultLeakDomain
	}
	if cfg.API == "" {
		cfg.API = DefaultLeakAPI
	}
	if cfg.Names <= 0 {
		cfg.Names = 10
	}
	if cfg.Wait == 0 {
		cfg.Wait = 2 * time.Second
	}
	if cfg.ID == nil {
		cfg.ID = randomID
	}
	if cfg.Lookup == nil {
		cfg.Lookup = systemLookup
	}
	if cfg.Sleep == nil {
		cfg.Sleep = func(ctx context.Context, d time.Duration) {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		}
	}
	client, err := clientFor(p, cfg.Config) // fails closed: no tunnel path, no fetch
	if err != nil {
		return LeakResult{Skipped: err.Error()}
	}
	id, err := cfg.ID()
	if err != nil {
		return LeakResult{Skipped: err.Error()}
	}
	for i := 1; i <= cfg.Names; i++ {
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_ = cfg.Lookup(lctx, fmt.Sprintf("%d.%s.%s", i, id, cfg.Domain)) // the answer does not matter, the asking does
		cancel()
	}
	cfg.Sleep(ctx, cfg.Wait)
	if ctx.Err() != nil {
		return LeakResult{Skipped: ctx.Err().Error()}
	}
	body, err := get(ctx, client, fmt.Sprintf(cfg.API, id))
	if err != nil {
		return LeakResult{Skipped: err.Error()}
	}
	res, err := ParseLeak(body)
	if err != nil {
		return LeakResult{Skipped: err.Error()}
	}
	return res
}

// ParseLeak reads the API's JSON (format checked against bash.ws on 2026-11-17): a list of
// {ip, country (lowercase ISO), country_name, asn ("AS64500 Name"), org, type} where type is ip
// (the address the web sees), dns (a resolver) or conclusion (text in ip, ignored); or
// {"error": "..."} when no lookup arrived.
func ParseLeak(body []byte) (LeakResult, error) {
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		// no name reached the test's DNS: {"error":"No DNS servers found. Try again..."}
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			return LeakResult{}, fmt.Errorf("%w: %s", ErrLeakNone, Clean(e.Error))
		}
		return LeakResult{}, ErrLeakAPI
	}
	var res LeakResult
	for _, r := range rows {
		typ, _ := r["type"].(string)
		if typ != "ip" && typ != "dns" {
			continue
		}
		s, _ := r["ip"].(string)
		ip, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			continue
		}
		srv := LeakServer{IP: ip.Unmap(), Country: strings.ToUpper(field(r, "country")), CountryName: field(r, "country_name"), ASN: field(r, "asn")}
		if typ == "ip" {
			if res.Exit == nil {
				res.Exit = &srv
			}
			continue
		}
		if len(res.DNS) < 32 {
			res.DNS = append(res.DNS, srv)
		}
	}
	if res.Exit == nil && len(res.DNS) == 0 {
		return LeakResult{}, ErrLeakAPI
	}
	return res, nil
}

// field reads a string value; the API writes false for "unknown".
func field(r map[string]any, k string) string {
	switch v := r[k].(type) {
	case string:
		return Clean(v)
	case float64:
		return fmt.Sprintf("%.0f", v)
	}
	return ""
}

func randomID() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(9_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprint(n.Int64() + 1_000_000), nil
}

func systemLookup(ctx context.Context, host string) error {
	_, err := net.DefaultResolver.LookupHost(ctx, host)
	return err
}
