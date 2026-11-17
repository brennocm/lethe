package checks

import (
	"strings"

	"lethe/internal/contracts"
)

// NET009 is LAN broadcast with identifiers (mDNS, LLMNR, NetBIOS, SSDP), classified by the
// capture sensor (§8.3). The announced names travel sealed (Sensitive["names"]); Match compares
// them with the baseline and raises the finding to CRITICAL on a hit.
type NET009 struct{}

func (NET009) ID() string { return "NET-009" }

var net009Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcCapture}}

func (NET009) Kind() Kind                          { return net009Meta.Kind() }
func (NET009) DefaultSeverity() contracts.Severity { return net009Meta.DefaultSeverity() }
func (NET009) Sources() []SourceID                 { return net009Meta.Sources() }
func (NET009) SelfTestCases() []string             { return net009Meta.SelfTestCases() }

// Match raises a NET-009 finding to CRITICAL when one of its announced names is the baseline's
// hostname (alone, or as the first label or the start of a service instance name).
func (NET009) Match(f Finding, k Known) Finding {
	if f.Check != "NET-009" || k.Hostname == "" || f.Sensitive["names"] == "" {
		return f
	}
	host := strings.ToLower(k.Hostname)
	for _, n := range strings.Split(f.Sensitive["names"], "\n") {
		first, _, _ := strings.Cut(n, ".")
		if n == host || first == host || strings.HasPrefix(n, host+" ") {
			f.Severity = contracts.SeverityCritical
			f.Data["matched"] = "baseline.hostname"
			return f
		}
	}
	return f
}
