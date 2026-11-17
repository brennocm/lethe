package checks

import (
	"net/netip"
	"sort"
	"strings"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

// DNS002 is "the provider's resolver is configured" (spec §9.2): a DNS server the machine
// actually uses (behind the 127.0.0.53 stub: systemd-resolved's servers per link; or a
// nameserver of resolv.conf) is one of the baseline's resolvers, the real connection's.
type DNS002 struct{}

func (DNS002) ID() string { return "DNS-002" }

var dns002Meta = meta{kind: Preflight, sev: contracts.SeverityCritical, sources: []SourceID{SrcDBus, SrcEgressIP}}

func (DNS002) Kind() Kind                          { return dns002Meta.Kind() }
func (DNS002) DefaultSeverity() contracts.Severity { return dns002Meta.DefaultSeverity() }
func (DNS002) Sources() []SourceID                 { return dns002Meta.Sources() }
func (DNS002) SelfTestCases() []string             { return dns002Meta.SelfTestCases() }

// Evaluate: CRITICAL for each effective resolver that is in the baseline, named by the baseline
// field and the link (never the address).
func (DNS002) Evaluate(s *discovery.Snapshot, k Known) []Finding {
	type hit struct{ field, iface, source string }
	seen := map[hit]bool{}
	add := func(v, iface, source string) {
		a, err := netip.ParseAddr(strings.TrimSpace(v))
		if err != nil {
			return
		}
		if f, ok := k.Resolvers[a.Unmap()]; ok {
			seen[hit{f, iface, source}] = true
		}
	}
	for _, l := range s.DNS.Resolved.Links {
		for _, v := range l.Servers {
			add(v, l.Iface, "resolved")
		}
	}
	for _, v := range s.DNS.ResolvConf.Nameservers {
		add(v, "", "resolv.conf")
	}
	hits := make([]hit, 0, len(seen))
	for h := range seen {
		hits = append(hits, h)
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].field+hits[i].iface < hits[j].field+hits[j].iface })
	var out []Finding
	for _, h := range hits {
		d := map[string]any{"matched": h.field, "source": h.source}
		if h.iface != "" {
			d["iface"] = h.iface
		}
		out = append(out, Finding{Check: "DNS-002", Severity: contracts.SeverityCritical, Data: d})
	}
	return out
}

// EvaluateLeakTest: CRITICAL for each resolver the DNS leak test saw that is in the baseline
// (the test answers the field, never the address).
func (DNS002) EvaluateLeakTest(r contracts.DNSLeakResult) []Finding {
	if r.Verdict == "skipped" {
		return nil
	}
	var out []Finding
	for _, s := range r.DNS {
		if s.Matched != "" {
			out = append(out, Finding{Check: "DNS-002", Severity: contracts.SeverityCritical,
				Data: map[string]any{"matched": s.Matched, "source": "dns_leak_test"}})
		}
	}
	return out
}

// DNS003 is "resolver on a physical link with DefaultRoute" (spec §9.2): systemd-resolved may
// send any name to a DNS server of a physical egress (DefaultRoute=yes) and no tunnel link
// claims every domain with "~.".
type DNS003 struct{}

func (DNS003) ID() string { return "DNS-003" }

var dns003Meta = meta{kind: Preflight, sev: contracts.SeverityWarning, sources: []SourceID{SrcDBus}}

func (DNS003) Kind() Kind                          { return dns003Meta.Kind() }
func (DNS003) DefaultSeverity() contracts.Severity { return dns003Meta.DefaultSeverity() }
func (DNS003) Sources() []SourceID                 { return dns003Meta.Sources() }
func (DNS003) SelfTestCases() []string             { return dns003Meta.SelfTestCases() }

// Evaluate: WARNING for each egress link with DNS servers and DefaultRoute when no tunnel link
// has the "~." routing domain.
func (DNS003) Evaluate(s *discovery.Snapshot) []Finding {
	tunnels := map[string]bool{}
	for _, t := range s.Tunnels {
		tunnels[t.Iface] = true
	}
	for _, l := range s.DNS.Resolved.Links {
		if tunnels[l.Iface] {
			for _, d := range l.Domains {
				if d == "~." {
					return nil // every name goes to the tunnel's DNS first
				}
			}
		}
	}
	egress := map[string]bool{}
	for _, e := range s.CaptureIfaces {
		egress[e] = true
	}
	var out []Finding
	for _, l := range s.DNS.Resolved.Links {
		if egress[l.Iface] && l.DefaultRoute && len(l.Servers) > 0 {
			out = append(out, Finding{Check: "DNS-003", Severity: contracts.SeverityWarning,
				Data: map[string]any{"iface": l.Iface, "reason": "default_route_without_tunnel_catch_all"}})
		}
	}
	return out
}
