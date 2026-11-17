package checks

import (
	"path/filepath"
	"strings"

	"lethe/internal/contracts"
	"lethe/internal/sensors/procscan"
)

// PER003 is "personal browser profile" (spec §9.5).
type PER003 struct{}

func (PER003) ID() string { return "PER-003" }

var per003Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcProcscan}}

func (PER003) Kind() Kind                          { return per003Meta.Kind() }
func (PER003) DefaultSeverity() contracts.Severity { return per003Meta.DefaultSeverity() }
func (PER003) Sources() []SourceID                 { return per003Meta.Sources() }
func (PER003) SelfTestCases() []string             { return per003Meta.SelfTestCases() }

var browsers = map[string]bool{"firefox": true, "firefox-esr": true, "firefox-bin": true, "chromium": true, "chromium-browser": true, "chrome": true, "google-chrome": true, "brave": true}

// Evaluate: WARNING for each browser main process running a profile that is not one of
// browsers.persona_profiles, or the default profile. Tor Browser keeps its own profile and is
// not reported.
func (PER003) Evaluate(procs []procscan.Process, persona []string) []Finding {
	allowed := map[string]bool{}
	for _, p := range persona {
		allowed[filepath.Clean(p)] = true
	}
	var out []Finding
	for _, p := range procs {
		exe := strings.TrimSuffix(p.Exe, " (deleted)")
		if !browsers[filepath.Base(exe)] || isTorBrowser(exe) || isChildProcess(p.Cmdline) {
			continue
		}
		prof := profileArg(p.Cmdline)
		if prof != "" && allowed[filepath.Clean(prof)] {
			continue
		}
		reason := "default_profile"
		if prof != "" {
			reason = "profile_not_in_persona"
		}
		out = append(out, Finding{Check: "PER-003", Severity: contracts.SeverityWarning, Data: map[string]any{"proc": procOf(p), "reason": reason}})
	}
	return out
}

func isTorBrowser(exe string) bool {
	l := strings.ToLower(exe)
	return strings.Contains(l, "tor-browser") || strings.Contains(l, "torbrowser")
}

// isChildProcess: content and GPU processes repeat the parent's arguments; only the main one counts.
func isChildProcess(args []string) bool {
	for _, a := range args {
		if a == "-contentproc" || strings.HasPrefix(a, "--type=") {
			return true
		}
	}
	return false
}

// profileArg returns the profile directory of a browser command line ("" = default profile).
func profileArg(args []string) string {
	for i, a := range args {
		switch {
		case (a == "-profile" || a == "--profile") && i+1 < len(args):
			return args[i+1]
		case strings.HasPrefix(a, "--user-data-dir="):
			return strings.TrimPrefix(a, "--user-data-dir=")
		case strings.HasPrefix(a, "--profile="):
			return strings.TrimPrefix(a, "--profile=")
		case (a == "-P" || a == "--P") && i+1 < len(args):
			return "name:" + args[i+1]
		}
	}
	return ""
}
