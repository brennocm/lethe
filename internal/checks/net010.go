package checks

import (
	"net/netip"

	"lethe/internal/contracts"
	"lethe/internal/sensors/sockdiag"
)

// NET010 is process and socket attribution on the physical interface (spec §9.1). It enriches
// NET-001/002 (sockdiag.Attribute) and, on its own, warns about connected sockets bound to an
// egress address whose destination is outside the allowlist with no packet seen yet.
type NET010 struct{}

func (NET010) ID() string { return "NET-010" }

var net010Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcSockdiag}, st: []string{"ST-NET-010"}}

func (NET010) Kind() Kind                          { return net010Meta.Kind() }
func (NET010) DefaultSeverity() contracts.Severity { return net010Meta.DefaultSeverity() }
func (NET010) Sources() []SourceID                 { return net010Meta.Sources() }
func (NET010) SelfTestCases() []string             { return net010Meta.SelfTestCases() }

// SocketScan is one sock_diag pass with its context.
type SocketScan struct {
	Socks       []sockdiag.Sock
	Owners      map[uint32]sockdiag.Owner
	EgressAddrs map[netip.Addr]string                       // local address → egress interface
	Allowed     func(proto string, dst netip.AddrPort) bool // endpoints + LAN (if allow_lan)
	Seen        func(proto string, src, dst netip.AddrPort) bool
}

// Evaluate returns one WARNING per offending socket.
func (NET010) Evaluate(sc SocketScan) []Finding {
	var out []Finding
	for _, s := range sc.Socks {
		iface, ok := sc.EgressAddrs[s.Local.Addr()]
		if !ok || s.Remote.Port() == 0 || !s.Remote.Addr().IsValid() || s.Remote.Addr().IsUnspecified() {
			continue
		}
		if sc.Allowed(s.Proto, s.Remote) || (sc.Seen != nil && sc.Seen(s.Proto, s.Local, s.Remote)) {
			continue
		}
		p := contracts.Proc{UID: int(s.UID), Confidence: contracts.ConfidenceLow}
		if o, ok := sc.Owners[s.Inode]; ok {
			p = contracts.Proc{PID: o.PID, Exe: o.Exe, Comm: o.Comm, UID: o.UID, Confidence: contracts.ConfidenceHigh}
		}
		out = append(out, Finding{Check: "NET-010", Severity: contracts.SeverityWarning, Data: map[string]any{
			"iface": iface, "proto": s.Proto, "dst": s.Remote.Addr().String(), "dport": int(s.Remote.Port()), "proc": p,
		}})
	}
	return out
}
