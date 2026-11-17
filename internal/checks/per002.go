package checks

import (
	"lethe/internal/contracts"
	"lethe/internal/sensors/hostinfo"
)

// PER002 is "browser configuration" (spec §9.5).
type PER002 struct{}

func (PER002) ID() string { return "PER-002" }

var per002Meta = meta{kind: Preflight, sev: contracts.SeverityWarning, sources: []SourceID{SrcHostinfo}}

func (PER002) Kind() Kind                          { return per002Meta.Kind() }
func (PER002) DefaultSeverity() contracts.Severity { return per002Meta.DefaultSeverity() }
func (PER002) Sources() []SourceID                 { return per002Meta.Sources() }
func (PER002) SelfTestCases() []string             { return per002Meta.SelfTestCases() }

// Evaluate: WARNING per persona profile whose WebRTC may expose local addresses or whose SOCKS
// proxy resolves names locally, and for Chromium installed without a WebRtcIPHandling policy.
func (PER002) Evaluate(profiles []hostinfo.Prefs, chromium hostinfo.ChromiumPolicy) []Finding {
	var out []Finding
	for i, p := range profiles {
		if !p.Found {
			continue
		}
		var issues []any
		if p.PeerConnection && !p.DefaultAddressOnly {
			issues = append(issues, "webrtc")
		}
		if p.SOCKSProxy && !p.SOCKSRemoteDNS {
			issues = append(issues, "socks_local_dns")
		}
		if len(issues) > 0 {
			out = append(out, Finding{Check: "PER-002", Severity: contracts.SeverityWarning, Data: map[string]any{
				"browser": "firefox", "profile": i, "issues": issues,
			}})
		}
	}
	switch chromium.WebRtcIPHandling {
	case "disable_non_proxied_udp", "default_public_interface_only":
	default:
		if chromium.Installed {
			out = append(out, Finding{Check: "PER-002", Severity: contracts.SeverityWarning, Data: map[string]any{
				"browser": "chromium", "issues": []any{"webrtc"}, "fix": "policy WebRtcIPHandling=disable_non_proxied_udp",
			}})
		}
	}
	return out
}
