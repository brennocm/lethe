package checks

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

func dnsSnap(links []discovery.ResolvedLink, resolv []string) *discovery.Snapshot {
	s := &discovery.Snapshot{CaptureIfaces: []string{"eth0"}, Tunnels: []discovery.Tunnel{{Iface: "wg0"}}}
	s.DNS.Resolved.Links = links
	s.DNS.ResolvConf.Nameservers = resolv
	return s
}

// The provider's resolver behind the stub (resolved) or in resolv.conf is CRITICAL, named by
// the baseline field; the address never appears.
func TestDNS002_BaselineResolverInUse(t *testing.T) {
	k := Known{Resolvers: map[netip.Addr]string{netip.MustParseAddr("198.51.100.53"): "baseline.networks[0].resolvers"}}
	if fs := (DNS002{}).Evaluate(dnsSnap([]discovery.ResolvedLink{{Iface: "wg0", Servers: []string{"10.64.0.1"}}}, []string{"127.0.0.53"}), k); len(fs) != 0 {
		t.Fatalf("the tunnel's DNS: %+v", fs)
	}
	fs := (DNS002{}).Evaluate(dnsSnap([]discovery.ResolvedLink{{Iface: "eth0", Servers: []string{"198.51.100.53"}}}, []string{"198.51.100.53"}), k)
	if len(fs) != 2 || fs[0].Severity != contracts.SeverityCritical {
		t.Fatalf("%+v", fs)
	}
	raw, _ := json.Marshal(fs)
	if strings.Contains(string(raw), "198.51.100.53") || !strings.Contains(string(raw), "baseline.networks[0].resolvers") {
		t.Fatalf("%s", raw)
	}
	leak := contracts.DNSLeakResult{Verdict: "leak", DNS: []contracts.DNSLeakServer{{Matched: "baseline.networks[0].resolvers"}, {IP: "203.0.113.53"}}}
	if fs := (DNS002{}).EvaluateLeakTest(leak); len(fs) != 1 || fs[0].Data["source"] != "dns_leak_test" {
		t.Fatalf("%+v", fs)
	}
	if fs := (DNS002{}).EvaluateLeakTest(contracts.DNSLeakResult{Verdict: "skipped"}); fs != nil {
		t.Fatal("a skipped test says nothing")
	}
}

// A physical link with DNS and DefaultRoute is a WARNING unless the tunnel claims "~.".
func TestDNS003_DefaultRouteWithoutCatchAll(t *testing.T) {
	eth := discovery.ResolvedLink{Iface: "eth0", Servers: []string{"192.0.2.1"}, DefaultRoute: true}
	if fs := (DNS003{}).Evaluate(dnsSnap([]discovery.ResolvedLink{eth, {Iface: "wg0", Servers: []string{"10.64.0.1"}}}, nil)); len(fs) != 1 || fs[0].Data["iface"] != "eth0" {
		t.Fatalf("%+v", fs)
	}
	if fs := (DNS003{}).Evaluate(dnsSnap([]discovery.ResolvedLink{eth, {Iface: "wg0", Domains: []string{"~."}}}, nil)); len(fs) != 0 {
		t.Fatalf("~. on the tunnel: %+v", fs)
	}
	eth.DefaultRoute = false
	if fs := (DNS003{}).Evaluate(dnsSnap([]discovery.ResolvedLink{eth}, nil)); len(fs) != 0 {
		t.Fatalf("no DefaultRoute: %+v", fs)
	}
}
