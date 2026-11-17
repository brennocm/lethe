package capture

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"lethe/internal/contracts"
)

// Check IDs produced by the classifier (spec §8.3).
const (
	CheckNET001 = "NET-001"
	CheckNET009 = "NET-009"
	CheckNET012 = "NET-012"
	CheckDNS001 = "DNS-001"
)

const stunMagic = 0x2112A442

// Leak is one delivered frame, classified. QName is sensitive: the daemon seals it (§14.4)
// and it never goes to Data().
type Leak struct {
	Check     string
	Severity  contracts.Severity
	Subtype   string // ipv6 | dot | doq | l2 | fragment | ""
	Proto     string // tcp | udp | icmp | icmpv6 | ip:<n> | ether:0x<type>
	Src, Dst  netip.Addr
	Sport     uint16
	Dport     uint16
	Len       int // original length on the wire
	QName     string
	Names     []string // hostnames announced by a NET-009 broadcast (sensitive, like QName)
	hasPorts  bool
	EtherType uint16
}

// Data is the non-sensitive event payload (spec §8.3); the daemon adds iface and proc.
func (l Leak) Data() map[string]any {
	d := map[string]any{"proto": l.Proto, "len": l.Len}
	if l.Src.IsValid() {
		d["src"] = l.Src.String()
		d["dst"] = l.Dst.String()
	}
	if l.hasPorts {
		d["sport"] = int(l.Sport)
		d["dport"] = int(l.Dport)
	}
	if l.Subtype != "" {
		d["subtype"] = l.Subtype
	}
	return d
}

// Tuple returns the 5-tuple for NET-010 attribution (ok=false without ports).
func (l Leak) Tuple() (proto string, src, dst netip.AddrPort, ok bool) {
	if !l.hasPorts || (l.Proto != "tcp" && l.Proto != "udp") {
		return "", netip.AddrPort{}, netip.AddrPort{}, false
	}
	return l.Proto, netip.AddrPortFrom(l.Src, l.Sport), netip.AddrPortFrom(l.Dst, l.Dport), true
}

// Classify decodes a frame delivered by the filter. Everything the filter delivers is a leak:
// a frame that cannot be decoded is still NET-001 (fail-closed), never dropped.
func Classify(frame []byte, wireLen int) Leak {
	l := Leak{Check: CheckNET001, Severity: contracts.SeverityCritical, Len: wireLen}
	if len(frame) < 14 {
		l.Proto, l.Subtype = "ether:?", "l2"
		return l
	}
	return classifyL3(binary.BigEndian.Uint16(frame[12:14]), frame[14:], wireLen)
}

// ClassifyIP classifies a packet that starts at the IP header (NFLOG payloads, NET-002).
func ClassifyIP(pkt []byte, wireLen int) Leak {
	et := uint16(0)
	if len(pkt) > 0 {
		switch pkt[0] >> 4 {
		case 4:
			et = etherIPv4
		case 6:
			et = etherIPv6
		}
	}
	if et == 0 {
		return Leak{Check: CheckNET001, Severity: contracts.SeverityCritical, Len: wireLen, Proto: "ip:?"}
	}
	return classifyL3(et, pkt, wireLen)
}

func classifyL3(etherType uint16, p []byte, wireLen int) Leak {
	l := Leak{Check: CheckNET001, Severity: contracts.SeverityCritical, Len: wireLen, EtherType: etherType}
	var (
		proto   uint8
		l4      []byte
		isV6    bool
		decoded bool
	)
	switch l.EtherType {
	case etherIPv4:
		proto, l4, decoded = l.ipv4(p)
	case etherIPv6:
		isV6 = true
		proto, l4, decoded = l.ipv6(p)
	default:
		l.Proto, l.Subtype = fmt.Sprintf("ether:0x%04x", l.EtherType), "l2"
		return l
	}
	if !decoded {
		if isV6 {
			l.Subtype = "ipv6"
		}
		if l.Proto == "" {
			l.Proto = "ip:?"
		}
		return l
	}
	l.Proto = protoName(proto, isV6)
	payload := l.ports(proto, l4)
	l.classify(proto, payload)
	if l.Check == CheckNET001 && isV6 && l.Subtype == "" {
		l.Subtype = "ipv6"
	}
	return l
}

func (l *Leak) ipv4(p []byte) (uint8, []byte, bool) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return 0, nil, false
	}
	ihl := int(p[0]&0x0f) * 4
	l.Src = netip.AddrFrom4([4]byte(p[12:16]))
	l.Dst = netip.AddrFrom4([4]byte(p[16:20]))
	proto := p[9]
	l.Proto = protoName(proto, false)
	if ihl < 20 || len(p) < ihl {
		return proto, nil, false
	}
	if binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
		l.Subtype = "fragment"
		return proto, nil, false
	}
	return proto, p[ihl:], true
}

func (l *Leak) ipv6(p []byte) (uint8, []byte, bool) {
	if len(p) < 40 || p[0]>>4 != 6 {
		return 0, nil, false
	}
	l.Src = netip.AddrFrom16([16]byte(p[8:24]))
	l.Dst = netip.AddrFrom16([16]byte(p[24:40]))
	next, rest := p[6], p[40:]
	for range 8 { // bounded walk of extension headers
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(rest) < 8 {
				return next, nil, false
			}
			hl := (int(rest[1]) + 1) * 8
			if len(rest) < hl {
				return next, nil, false
			}
			next, rest = rest[0], rest[hl:]
		case 44: // fragment
			if len(rest) < 8 {
				return next, nil, false
			}
			if binary.BigEndian.Uint16(rest[2:4])&0xfff8 != 0 {
				l.Proto = protoName(rest[0], true)
				return rest[0], nil, false
			}
			next, rest = rest[0], rest[8:]
		default:
			return next, rest, true
		}
	}
	return next, nil, false
}

func (l *Leak) ports(proto uint8, l4 []byte) []byte {
	switch proto {
	case protoTCP:
		if len(l4) < 20 {
			return nil
		}
		l.Sport, l.Dport, l.hasPorts = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4]), true
		off := int(l4[12]>>4) * 4
		if off < 20 || len(l4) < off {
			return nil
		}
		return l4[off:]
	case protoUDP:
		if len(l4) < 8 {
			return nil
		}
		l.Sport, l.Dport, l.hasPorts = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4]), true
		return l4[8:]
	}
	return nil
}

func (l *Leak) classify(proto uint8, payload []byte) {
	if !l.hasPorts {
		return
	}
	switch {
	case l.Dport == 53:
		l.Check = CheckDNS001
		l.QName = qname(proto, payload)
	case l.Dport == 853:
		l.Check = CheckDNS001
		l.Subtype = map[uint8]string{protoTCP: "dot", protoUDP: "doq"}[proto]
	case l.Dport == 3478 || l.Dport == 5349 || (l.Dport >= 19302 && l.Dport <= 19309) || isSTUN(proto, payload):
		l.Check = CheckNET012
	case l.Dport == 5353 || l.Dport == 5355 || l.Dport == 137 || l.Dport == 138 || l.Dport == 1900:
		l.Check, l.Severity = CheckNET009, contracts.SeverityWarning
		l.Names = announcedNames(l.Dport, payload)
	}
}

func isSTUN(proto uint8, p []byte) bool {
	return proto == protoUDP && len(p) >= 20 && p[0]&0xc0 == 0 && binary.BigEndian.Uint32(p[4:8]) == stunMagic
}

// qname returns the first question name, "" if the payload is not a decodable query.
func qname(proto uint8, p []byte) string {
	if proto == protoTCP {
		if len(p) < 2 {
			return ""
		}
		p = p[2:]
	}
	var d layers.DNS
	if err := d.DecodeFromBytes(p, gopacket.NilDecodeFeedback); err != nil || len(d.Questions) == 0 {
		return ""
	}
	return strings.ToValidUTF8(string(d.Questions[0].Name), "�")
}

func protoName(p uint8, v6 bool) string {
	switch {
	case p == protoTCP:
		return "tcp"
	case p == protoUDP:
		return "udp"
	case p == 1 && !v6:
		return "icmp"
	case p == protoICMPv6 && v6:
		return "icmpv6"
	default:
		return fmt.Sprintf("ip:%d", p)
	}
}
