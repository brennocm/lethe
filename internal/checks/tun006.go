package checks

import (
	"slices"
	"strings"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/geo"
)

// TUN006 is "unexpected endpoint" (spec §9.3).
type TUN006 struct{}

func (TUN006) ID() string { return "TUN-006" }

var tun006Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcWgctrl, SrcNetlink}}

func (TUN006) Kind() Kind                          { return tun006Meta.Kind() }
func (TUN006) DefaultSeverity() contracts.Severity { return tun006Meta.DefaultSeverity() }
func (TUN006) Sources() []SourceID                 { return tun006Meta.Sources() }
func (TUN006) SelfTestCases() []string             { return tun006Meta.SelfTestCases() }

// GeoExpect is egress.expect_country and egress.expect_asn.
type GeoExpect struct {
	Country string
	ASN     []uint32
}

// Evaluate: WARNING for each endpoint that appeared after the arm (not in armed) and sits outside
// the expected country or ASNs. Without a database (db nil) or without expectations, nothing is
// reported. An endpoint missing from the database is reported as unknown: a provider would not
// normally run its servers on unrouted space.
func (TUN006) Evaluate(db geo.DB, want GeoExpect, armed map[string]bool, s *discovery.Snapshot) []Finding {
	if db == nil || (want.Country == "" && len(want.ASN) == 0) {
		return nil
	}
	var out []Finding
	for _, e := range s.ParsedEndpoints() {
		if armed[e.String()] {
			continue
		}
		data := map[string]any{"dst": e.Addr.Addr().String(), "dport": int(e.Addr.Port()), "proto": e.Proto}
		info, ok := db.Lookup(e.Addr.Addr())
		switch {
		case !ok:
			data["reason"] = "unknown_location"
		case want.Country != "" && !strings.EqualFold(info.Country, want.Country):
			data["reason"], data["country"] = "country", info.Country
		case len(want.ASN) > 0 && !slices.Contains(want.ASN, info.ASN):
			data["reason"], data["asn"] = "asn", int(info.ASN)
		default:
			continue
		}
		out = append(out, Finding{Check: "TUN-006", Severity: contracts.SeverityWarning, Data: data})
	}
	return out
}
