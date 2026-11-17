package egressip

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func servers(t *testing.T, bodies map[string]string) (Path, Config, *[]http.Header) {
	t.Helper()
	var mu sync.Mutex
	var seen []http.Header
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Clone())
		mu.Unlock()
		_, _ = w.Write([]byte(bodies[r.URL.Path]))
	}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	addr := srv.Listener.Addr().String()
	p := Path{Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr) // every name lands on the test server
	}}
	var eps []string
	for path := range bodies {
		eps = append(eps, "https://example.com"+path)
	}
	return p, Config{Endpoints: eps, RootCAs: pool, Pick: func(int) []int { return []int{0, 1} }}, &seen
}

func TestNET011_TwoEndpointsAgree(t *testing.T) {
	p, cfg, seen := servers(t, map[string]string{"/a": `{"IsTor":true,"IP":"203.0.113.9"}`, "/b": "203.0.113.9\n"})
	r := Query(context.Background(), p, cfg)
	if !r.Agreed || r.IP != netip.MustParseAddr("203.0.113.9") {
		t.Fatalf("%+v", r)
	}
	for _, h := range *seen {
		if h.Get("User-Agent") != UserAgent || strings.Contains(strings.ToLower(h.Get("User-Agent")), "lethe") {
			t.Fatalf("headers %v", h)
		}
	}
}

func TestNET011_DisagreementGivesNoResult(t *testing.T) {
	p, cfg, _ := servers(t, map[string]string{"/a": `{"ip":"203.0.113.9"}`, "/b": `{"ip":"198.51.100.1"}`})
	if r := Query(context.Background(), p, cfg); r.Agreed {
		t.Fatalf("%+v", r)
	}
}

func TestNET011_Skips(t *testing.T) {
	if r := Query(context.Background(), Path{Tunnel: "wg0"}, Config{Endpoints: []string{"https://a", "https://b"}}); r.Skipped != ErrNoTunnelDNS.Error() {
		t.Fatalf("no tunnel DNS must skip: %+v", r)
	}
	if r := Query(context.Background(), Path{Tunnel: "wg0"}, Config{Endpoints: []string{"https://a"}}); r.Skipped == "" {
		t.Fatal("one endpoint must skip")
	}
	if r := Query(context.Background(), Path{}, Config{Endpoints: []string{"https://a", "https://b"}}); r.Skipped == "" {
		t.Fatal("no path must skip")
	}
}

func TestNET011_ParseIP(t *testing.T) {
	for in, want := range map[string]string{`{"ip":"::ffff:192.0.2.1"}`: "192.0.2.1", " 2001:db8::1 \n": "2001:db8::1", `{"origin":"198.51.100.4"}`: "198.51.100.4"} {
		got, err := ParseIP([]byte(in))
		if err != nil || got.String() != want {
			t.Fatalf("%s: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{`{"x":1}`, "<html>", ""} {
		if _, err := ParseIP([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestNET011_TunnelDNS(t *testing.T) {
	via := func(a netip.Addr) string {
		if a.String() == "10.64.0.1" {
			return "wg0"
		}
		return "eth0"
	}
	got := TunnelDNS("wg0", []netip.Addr{netip.MustParseAddr("10.2.0.1")}, []string{"10.2.0.1", "127.0.0.53"},
		[]string{"127.0.0.53", "10.64.0.1", "192.168.1.1"}, via)
	if len(got) != 2 || got[0].String() != "10.2.0.1" || got[1].String() != "10.64.0.1" {
		t.Fatal(got)
	}
}

// The place an endpoint claims is kept with its source, cleaned of control characters.
func TestNET011_PlaceFromTheEndpoint(t *testing.T) {
	p, cfg, _ := servers(t, map[string]string{
		"/a": `{"IsTor":false,"IP":"203.0.113.9"}`,
		"/b": `{"ip":"203.0.113.9","country":"Netherlands","city":"Amster\u202edam\u0007"}`,
	})
	r := Query(context.Background(), p, cfg)
	if !r.Agreed || r.Place.Country != "Netherlands" || r.Place.City != "Amsterdam" || r.Place.Source != "example.com" {
		t.Fatalf("%+v", r.Place)
	}
	if got := Clean(strings.Repeat("x", 100)); len(got) != 64 {
		t.Fatalf("not cut: %d", len(got))
	}
}

// The test resolves names through the given lookup (the system path) and fetches the result
// through the tunnel path; resolvers and the exit come from the answer.
func TestNET011_DNSLeakTest(t *testing.T) {
	// the shape bash.ws answers (addresses replaced by documentation ones)
	body := `[{"ip":"203.0.113.9","country":"nl","country_name":"Netherlands","asn":"AS64500 Example","org":"Example","type":"ip"},
		{"ip":"198.51.100.53","country":"br","country_name":"Brazil","asn":"","org":"","type":"dns"},
		{"ip":"DNS may be leaking.","country":"","country_name":"","asn":"","org":"","type":"conclusion"}]`
	p, cfg, _ := servers(t, map[string]string{"/dnsleak/test/1234567": body, "/unused": ""})
	var asked []string
	res := DNSLeak(context.Background(), p, LeakConfig{
		API: "https://example.com/dnsleak/test/%s", Config: cfg,
		ID:     func() (string, error) { return "1234567", nil },
		Lookup: func(_ context.Context, h string) error { asked = append(asked, h); return nil },
		Sleep:  func(context.Context, time.Duration) {},
	})
	if res.Skipped != "" || res.Exit == nil || res.Exit.Country != "NL" || len(res.DNS) != 1 || res.DNS[0].Country != "BR" || res.DNS[0].ASN != "" {
		t.Fatalf("%+v", res)
	}
	if len(asked) != 10 || asked[0] != "1.1234567.bash.ws" {
		t.Fatalf("asked %v", asked)
	}
	// no tunnel path: no fetch through the system, the test is skipped
	if r := DNSLeak(context.Background(), Path{}, LeakConfig{Lookup: func(context.Context, string) error {
		t.Fatal("names resolved without a path to fetch the answer")
		return nil
	}}); r.Skipped == "" {
		t.Fatal("must skip")
	}
	if _, err := ParseLeak([]byte(`{"oops":1}`)); !errors.Is(err, ErrLeakAPI) {
		t.Fatal("bad answer accepted")
	}
	if _, err := ParseLeak([]byte(`{"error":"No DNS servers found. Try again..."}`)); !errors.Is(err, ErrLeakNone) || !strings.Contains(err.Error(), "No DNS servers") {
		t.Fatalf("the API's own error: %v", err)
	}
}
