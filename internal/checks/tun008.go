package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

// TUN008 is "unsupported pluggable transport" (spec §9.3, §7.5).
type TUN008 struct{}

func (TUN008) ID() string { return "TUN-008" }

var tun008Meta = meta{kind: Preflight, sev: contracts.SeverityCritical, sources: []SourceID{SrcTorctl}}

func (TUN008) Kind() Kind                          { return tun008Meta.Kind() }
func (TUN008) DefaultSeverity() contracts.Severity { return tun008Meta.DefaultSeverity() }
func (TUN008) Sources() []SourceID                 { return tun008Meta.Sources() }
func (TUN008) SelfTestCases() []string             { return tun008Meta.SelfTestCases() }

// dynamicTransports reach CDNs and WebRTC peers that no allowlist can name in advance.
var dynamicTransports = map[string]bool{"snowflake": true, "meek": true, "meek_lite": true}

// Evaluate: CRITICAL for each bridge transport with dynamic destinations when the guard is strict.
// Only observer mode supports them in v1.
func (TUN008) Evaluate(guardMode string, s *discovery.Snapshot) []Finding {
	if guardMode != "strict" || s.Tor == nil || !s.Tor.UseBridges {
		return nil
	}
	var out []Finding
	for _, t := range s.Tor.Transports {
		if dynamicTransports[t] {
			out = append(out, Finding{Check: "TUN-008", Severity: contracts.SeverityCritical, Data: map[string]any{"transport": t}})
		}
	}
	return out
}
