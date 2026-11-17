package checks

import (
	"path/filepath"
	"strings"

	"lethe/internal/contracts"
	"lethe/internal/sensors/procscan"
)

// HOST003 is "screen sharing or remote access" (spec §9.4).
type HOST003 struct{}

func (HOST003) ID() string { return "HOST-003" }

var host003Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcProcscan}}

func (HOST003) Kind() Kind                          { return host003Meta.Kind() }
func (HOST003) DefaultSeverity() contracts.Severity { return host003Meta.DefaultSeverity() }
func (HOST003) Sources() []SourceID                 { return host003Meta.Sources() }
func (HOST003) SelfTestCases() []string             { return host003Meta.SelfTestCases() }

// remoteAccess are the executables of known remote access and screen sharing servers.
var remoteAccess = map[string]bool{
	"anydesk": true, "teamviewer": true, "teamviewerd": true, "TeamViewer": true, "rustdesk": true,
	"x11vnc": true, "Xvnc": true, "vncserver": true, "x0vncserver": true, "krfb": true, "wayvnc": true,
	"gnome-remote-desktop-daemon": true, "xrdp": true, "xrdp-sesman": true, "chrome-remote-desktop-host": true,
	"remoting_me2me_host": true, "meshagent": true, "sunshine": true,
}

// Evaluate: WARNING for each running remote access server.
func (HOST003) Evaluate(procs []procscan.Process) []Finding {
	var out []Finding
	for _, p := range procs {
		name := filepath.Base(strings.TrimSuffix(p.Exe, " (deleted)"))
		if !remoteAccess[name] && !remoteAccess[p.Comm] {
			continue
		}
		out = append(out, Finding{Check: "HOST-003", Severity: contracts.SeverityWarning, Data: map[string]any{"proc": procOf(p)}})
	}
	return out
}

// FromAgent: WARNING while the agent sees screencast streams (xdg portal sessions in PipeWire).
func (HOST003) FromAgent(c Capture) []Finding {
	if c.Screencast == 0 {
		return nil
	}
	return []Finding{{Check: "HOST-003", Severity: contracts.SeverityWarning, Agent: true, Data: map[string]any{"screencasts": c.Screencast}}}
}
