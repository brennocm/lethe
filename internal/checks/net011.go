package checks

import (
	"slices"
	"strings"

	"lethe/internal/contracts"
	"lethe/internal/geo"
	"lethe/internal/sensors/egressip"
)

// NET011 is "exit IP (active check)" (spec §9.1, §9.9).
type NET011 struct{}

func (NET011) ID() string { return "NET-011" }

var net011Meta = meta{kind: Active, sev: contracts.SeverityCritical, sources: []SourceID{SrcEgressIP}}

func (NET011) Kind() Kind                          { return net011Meta.Kind() }
func (NET011) DefaultSeverity() contracts.Severity { return net011Meta.DefaultSeverity() }
func (NET011) Sources() []SourceID                 { return net011Meta.Sources() }
func (NET011) SelfTestCases() []string             { return net011Meta.SelfTestCases() }

// ExitExpect is what the profile expects of the exit.
type ExitExpect struct {
	Country string
	ASNs    []uint32
}

// Evaluate: CRITICAL when the exit IP or its ASN is in the baseline (the real connection);
// WARNING when the country or the ASN differs from the profile, when the round was skipped (no
// DNS in the tunnel) or when the endpoints did not agree. The exit IP is sealed, never written
// in the clear: it may be the baseline's. The country comes from the offline database only.
func (NET011) Evaluate(r egressip.Result, k Known, db geo.DB, want ExitExpect) []Finding {
	w := func(d map[string]any) []Finding {
		return []Finding{{Check: "NET-011", Severity: contracts.SeverityWarning, Data: d}}
	}
	switch {
	case r.Skipped != "":
		return w(map[string]any{"reason": "skipped", "detail": r.Skipped})
	case !r.Agreed:
		var errs []any
		for _, a := range r.Answers {
			if a.Err != nil {
				errs = append(errs, a.Err.Error())
			}
		}
		d := map[string]any{"reason": "no_agreement"}
		if len(errs) > 0 {
			d["errors"] = errs
		}
		return w(d)
	}
	sealed := map[string]string{"exit_ip": r.IP.String()}
	if field, ok := k.IPs[r.IP.Unmap()]; ok {
		return []Finding{{Check: "NET-011", Severity: contracts.SeverityCritical, Sensitive: sealed,
			Data: map[string]any{"reason": "real_ip", "matched": field}}}
	}
	if db == nil {
		return nil // nothing to compare the country with (no geo database in this build)
	}
	info, ok := db.Lookup(r.IP)
	if !ok {
		return nil
	}
	if field, ok := k.ASNs[info.ASN]; ok && info.ASN != 0 {
		return []Finding{{Check: "NET-011", Severity: contracts.SeverityCritical, Sensitive: sealed,
			Data: map[string]any{"reason": "real_asn", "matched": field}}}
	}
	var out []Finding
	if want.Country != "" && info.Country != "" && !strings.EqualFold(info.Country, want.Country) {
		out = append(out, Finding{Check: "NET-011", Severity: contracts.SeverityWarning, Sensitive: sealed,
			Data: map[string]any{"reason": "country", "country": info.Country, "expected_country": strings.ToUpper(want.Country)}})
	}
	if len(want.ASNs) > 0 && info.ASN != 0 && !slices.Contains(want.ASNs, info.ASN) {
		out = append(out, Finding{Check: "NET-011", Severity: contracts.SeverityWarning, Sensitive: sealed,
			Data: map[string]any{"reason": "asn", "asn": int(info.ASN)}})
	}
	return out
}
