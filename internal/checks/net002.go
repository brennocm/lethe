package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/sensors/nflog"
)

// NET002 is "blocked leak (attempt)" in strict mode (spec §9.1): WARNING, the guard worked.
type NET002 struct{}

func (NET002) ID() string { return "NET-002" }

var net002Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcNFLog}, st: []string{"ST-NET-002"}}

func (NET002) Kind() Kind                          { return net002Meta.Kind() }
func (NET002) DefaultSeverity() contracts.Severity { return net002Meta.DefaultSeverity() }
func (NET002) Sources() []SourceID                 { return net002Meta.Sources() }
func (NET002) SelfTestCases() []string             { return net002Meta.SelfTestCases() }

// FromBlocked builds the NET-002 finding. A DNS attempt keeps its qname sealed, like DNS-001.
func FromBlocked(b nflog.Blocked, proc contracts.Proc) Finding {
	d := b.Leak.Data()
	d["iface"] = b.OutIface
	d["chain"] = b.Prefix
	d["uid"] = b.UID
	if b.Leak.Check != "NET-001" {
		d["class"] = b.Leak.Check // what it would have been (DNS-001, NET-012…)
	}
	if proc.Confidence != "" {
		d["proc"] = proc
	}
	f := Finding{Check: "NET-002", Severity: contracts.SeverityWarning, Data: d}
	if b.Leak.QName != "" {
		f.Sensitive = map[string]string{"qname": b.Leak.QName}
	}
	return f
}
