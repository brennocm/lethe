package checks

import (
	"fmt"
	"net/netip"
	"strings"

	"lethe/internal/baseline"
)

// Known is the part of the baseline the host checks compare with. The values stay in memory:
// findings carry only the name of the matched field (spec §12.1).
type Known struct {
	Hostname string
	SSIDs    map[string]string     // SSID → "baseline.networks[i].ssids"
	IPs      map[netip.Addr]string // public IP → "baseline.networks[i].public_ipv4|6" (NET-011)
	ASNs     map[uint32]string     // ASN → "baseline.networks[i].asn"
	// Resolvers: DNS server → "baseline.networks[i].resolvers" (the DNS leak test).
	Resolvers map[netip.Addr]string
}

// KnownFrom extracts Known from a decrypted baseline (nil = nothing known).
func KnownFrom(b *baseline.Baseline) Known {
	k := Known{SSIDs: map[string]string{}, IPs: map[netip.Addr]string{}, ASNs: map[uint32]string{}, Resolvers: map[netip.Addr]string{}}
	if b == nil {
		return k
	}
	k.Hostname = strings.TrimSpace(b.Hostname)
	for i, n := range b.Networks {
		for field, v := range map[string]string{"public_ipv4": n.PublicIPv4, "public_ipv6": n.PublicIPv6} {
			if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
				k.IPs[a.Unmap()] = fmt.Sprintf("baseline.networks[%d].%s", i, field)
			}
		}
		if n.ASN != 0 {
			k.ASNs[n.ASN] = fmt.Sprintf("baseline.networks[%d].asn", i)
		}
		for _, r := range n.Resolvers {
			if a, err := netip.ParseAddr(strings.TrimSpace(r)); err == nil {
				k.Resolvers[a.Unmap()] = fmt.Sprintf("baseline.networks[%d].resolvers", i)
			}
		}
		for _, s := range n.SSIDs {
			if s != "" {
				k.SSIDs[s] = fmt.Sprintf("baseline.networks[%d].ssids", i)
			}
		}
	}
	return k
}
