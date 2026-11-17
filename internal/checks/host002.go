package checks

import (
	"path/filepath"

	"lethe/internal/contracts"
	"lethe/internal/sensors/procscan"
)

// HOST002 is "camera or microphone in use" (spec §9.4).
type HOST002 struct{}

func (HOST002) ID() string { return "HOST-002" }

var host002Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcProcscan}}

func (HOST002) Kind() Kind                          { return host002Meta.Kind() }
func (HOST002) DefaultSeverity() contracts.Severity { return host002Meta.DefaultSeverity() }
func (HOST002) Sources() []SourceID                 { return host002Meta.Sources() }
func (HOST002) SelfTestCases() []string             { return host002Meta.SelfTestCases() }

// audioServers hold the capture devices on behalf of their clients: the agent sees those
// clients as PipeWire streams instead.
var audioServers = map[string]bool{"pipewire": true, "pipewire-pulse": true, "wireplumber": true, "pulseaudio": true, "jackd": true, "jackdbus": true}

// Capture is what the session agent saw in PipeWire (low trust: it may raise, never clear).
type Capture struct {
	Audio      int `json:"audio"`
	Video      int `json:"video"`
	Screencast int `json:"screencast"`
}

// Evaluate: WARNING for each process holding a camera or a capture PCM open (daemon view).
func (HOST002) Evaluate(procs []procscan.Process) []Finding {
	var out []Finding
	for _, p := range procs {
		if len(p.Devices) == 0 || audioServers[filepath.Base(p.Exe)] || audioServers[p.Comm] {
			continue
		}
		video, audio := 0, 0
		for _, d := range p.Devices {
			if filepath.Dir(d) == "/dev" {
				video++
			} else {
				audio++
			}
		}
		out = append(out, Finding{Check: "HOST-002", Severity: contracts.SeverityWarning, Data: map[string]any{
			"proc": procOf(p), "video": video, "audio": audio,
		}})
	}
	return out
}

// FromAgent: WARNING when the agent reports capture streams (camera or microphone).
func (HOST002) FromAgent(c Capture) []Finding {
	if c.Audio == 0 && c.Video == 0 {
		return nil
	}
	return []Finding{{Check: "HOST-002", Severity: contracts.SeverityWarning, Agent: true, Data: map[string]any{
		"audio_streams": c.Audio, "video_streams": c.Video,
	}}}
}
