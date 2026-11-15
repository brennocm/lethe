package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

// TUN003 is "Tor without bootstrap or circuit" (spec §9.3).
type TUN003 struct{}

func (TUN003) ID() string { return "TUN-003" }

var tun003Meta = meta{kind: Passive, sev: contracts.SeverityCritical, sources: []SourceID{SrcTorctl}}

func (TUN003) Kind() Kind                          { return tun003Meta.Kind() }
func (TUN003) DefaultSeverity() contracts.Severity { return tun003Meta.DefaultSeverity() }
func (TUN003) Sources() []SourceID                 { return tun003Meta.Sources() }
func (TUN003) SelfTestCases() []string             { return tun003Meta.SelfTestCases() }

// TorRequired reports whether egress.type needs tor; "auto" needs it only if tor answered at arm.
func TorRequired(egressType string) bool { return egressType == "tor" || egressType == "vpn+tor" }

// TorQueried reports whether discovery should ask tor at all for this egress.type.
func TorQueried(egressType string) bool { return TorRequired(egressType) || egressType == "auto" }

// TorExpected reports whether this session depends on tor: always for tor and vpn+tor, and for
// "auto" when the control port answered at arm.
func TorExpected(egressType string, s *discovery.Snapshot) bool {
	return TorRequired(egressType) || (egressType == "auto" && s.Tor != nil && s.Tor.Reachable)
}

// Evaluate: CRITICAL when tor is expected and its control port does not answer, the bootstrap is
// below 100 or no circuit is established.
func (TUN003) Evaluate(expected bool, s *discovery.Snapshot) []Finding {
	if !expected {
		return nil
	}
	data := map[string]any{}
	switch t := s.Tor; {
	case t == nil || !t.Reachable:
		data["reason"] = "control_unreachable"
	case t.Bootstrap < 100:
		data["reason"], data["progress"] = "bootstrap", t.Bootstrap
	case !t.CircuitEstablished:
		data["reason"] = "no_circuit"
	default:
		return nil
	}
	return []Finding{{Check: "TUN-003", Severity: contracts.SeverityCritical, Data: data}}
}
