// Package discovery finds the tunnel, its endpoints, the egress interfaces and the effective DNS
// (spec §7). Classification is pure; kernel access is behind small interfaces for tests.
package discovery

import (
	"sort"
	"strings"
)

// Class is the role of an interface (spec §7.2). Exactly one per interface.
type Class string

const (
	ClassLoopback Class = "loopback"
	ClassTunnel   Class = "tunnel"
	ClassEgress   Class = "egress"
	ClassInternal Class = "internal"
	ClassUnknown  Class = "unknown" // treated as egress by the guard and the sensor (fail-closed)
)

// LinkInfo is the minimum the classifier needs about one link.
type LinkInfo struct {
	Index       int    `json:"index"`
	Name        string `json:"name"`
	Type        string `json:"type"` // netlink link kind: device, veth, bridge, vlan, wireguard, tuntap, ...
	HasDevice   bool   `json:"has_device"`
	ParentIndex int    `json:"parent_index,omitempty"` // IFLA_LINK (vlan, macvlan, ipvlan)
	MasterIndex int    `json:"master_index,omitempty"` // IFLA_MASTER (bridge or bond port)
}

// Overrides come from profile network.egress_ifaces / internal_ifaces.
type Overrides struct {
	Egress   []string
	Internal []string
}

var tunnelTypes = map[string]bool{"wireguard": true, "tuntap": true, "tun": true, "tap": true}

var tunnelPrefixes = []string{"wg", "tun", "tap", "proton", "mullvad", "nordlynx", "tailscale", "ivpn", "pvpn"}

// stackedTypes inherit the class of their parent (IFLA_LINK).
var stackedTypes = map[string]bool{"vlan": true, "macvlan": true, "ipvlan": true, "macvtap": true}

// aggregateTypes are egress when any of their ports is egress.
var aggregateTypes = map[string]bool{"bridge": true, "bond": true, "team": true}

// internalTypes never reach hardware on their own.
var internalTypes = map[string]bool{"tuntap": true, "veth": true, "dummy": true, "ifb": true, "nlmon": true, "bridge": true}

// pppTypes carry the provider session itself (PPPoE): egress even without a device.
var pppTypes = map[string]bool{"ppp": true}

// Classify assigns a class to every link following the order of spec §7.2.
func Classify(links []LinkInfo, ov Overrides) map[string]Class {
	byIndex := map[int]LinkInfo{}
	for _, l := range links {
		byIndex[l.Index] = l
	}
	egressOv, internalOv := set(ov.Egress), set(ov.Internal)
	out := map[string]Class{}
	var memo map[int]Class
	var classOf func(l LinkInfo, depth int) Class
	classOf = func(l LinkInfo, depth int) Class {
		if c, ok := memo[l.Index]; ok {
			return c
		}
		c := ClassUnknown
		switch {
		case l.Name == "lo" || l.Type == "loopback":
			c = ClassLoopback
		case egressOv[l.Name]:
			c = ClassEgress
		case internalOv[l.Name]:
			c = ClassInternal
		case isTunnel(l):
			c = ClassTunnel
		case l.HasDevice || pppTypes[l.Type]:
			c = ClassEgress
		case stackedTypes[l.Type] && depth < 8:
			if p, ok := byIndex[l.ParentIndex]; ok {
				if pc := classOf(p, depth+1); pc == ClassEgress || pc == ClassUnknown {
					c = pc
				} else {
					c = ClassInternal
				}
			}
		case aggregateTypes[l.Type] && depth < 8:
			c = ClassInternal
			for _, port := range links {
				if port.MasterIndex == l.Index && port.Index != l.Index {
					if pc := classOf(port, depth+1); pc == ClassEgress || pc == ClassUnknown {
						c = ClassEgress
						break
					}
				}
			}
			if l.Type != "bridge" && c == ClassInternal {
				c = ClassUnknown // an empty bond/team may get a hardware port at any moment
			}
		case internalTypes[l.Type]:
			c = ClassInternal
		}
		memo[l.Index] = c
		return c
	}
	memo = map[int]Class{}
	for _, l := range links {
		out[l.Name] = classOf(l, 0)
	}
	return out
}

func isTunnel(l LinkInfo) bool {
	if l.MasterIndex != 0 {
		return false // a tap enslaved to a bridge is a VM port, not a tunnel
	}
	if tunnelTypes[l.Type] {
		return true
	}
	if l.HasDevice {
		return false
	}
	for _, p := range tunnelPrefixes {
		if strings.HasPrefix(l.Name, p) && l.Type != "veth" && l.Type != "bridge" && l.Type != "dummy" {
			return true
		}
	}
	return false
}

// CaptureIfaces returns the hardware egress leaves the capture sensor binds to (spec §7.2):
// egress links with a device, plus egress overrides (veth in tests). Sorted for determinism.
func CaptureIfaces(links []LinkInfo, classes map[string]Class, ov Overrides) []string {
	egressOv := set(ov.Egress)
	var out []string
	for _, l := range links {
		if classes[l.Name] == ClassEgress && (l.HasDevice || egressOv[l.Name]) {
			out = append(out, l.Name)
		}
	}
	sort.Strings(out)
	return out
}

func set(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}
