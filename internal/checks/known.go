package checks

import (
	"fmt"
	"strings"

	"lethe/internal/baseline"
)

// Known is the part of the baseline the host checks compare with. The values stay in memory:
// findings carry only the name of the matched field (spec §12.1).
type Known struct {
	Hostname string
	SSIDs    map[string]string // SSID → "baseline.networks[i].ssids"
}

// KnownFrom extracts Known from a decrypted baseline (nil = nothing known).
func KnownFrom(b *baseline.Baseline) Known {
	k := Known{SSIDs: map[string]string{}}
	if b == nil {
		return k
	}
	k.Hostname = strings.TrimSpace(b.Hostname)
	for i, n := range b.Networks {
		for _, s := range n.SSIDs {
			if s != "" {
				k.SSIDs[s] = fmt.Sprintf("baseline.networks[%d].ssids", i)
			}
		}
	}
	return k
}
