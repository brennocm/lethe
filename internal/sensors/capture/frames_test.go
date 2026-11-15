package capture

import (
	"encoding/binary"
	"net/netip"
)

// Hand-built frames, independent from the decoder under test.

func eth(etherType uint16, payload []byte) []byte {
	f := make([]byte, 14, 14+len(payload))
	copy(f[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(f[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(f[12:], etherType)
	return append(f, payload...)
}

func l4(proto uint8, sport, dport uint16, body []byte) []byte {
	if proto == protoTCP {
		h := make([]byte, 20)
		binary.BigEndian.PutUint16(h[0:], sport)
		binary.BigEndian.PutUint16(h[2:], dport)
		h[12] = 5 << 4
		h[13] = 0x02 // SYN
		return append(h, body...)
	}
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(body)))
	return append(h, body...)
}

func ip4(src, dst string, proto uint8, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(payload)))
	h[8] = 64
	h[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(h[12:16], s[:])
	copy(h[16:20], d[:])
	return eth(etherIPv4, append(h, payload...))
}

// ip4opts is an IPv4 header with 4 bytes of options (IHL=6) to exercise LoadMemShift.
func ip4opts(src, dst string, proto uint8, payload []byte) []byte {
	f := ip4(src, dst, proto, nil)
	hdr := append([]byte{}, f[14:34]...)
	hdr[0] = 0x46
	hdr = append(hdr, 1, 1, 1, 0) // NOP NOP NOP EOL
	binary.BigEndian.PutUint16(hdr[2:], uint16(24+len(payload)))
	return eth(etherIPv4, append(hdr, payload...))
}

func frag4(src, dst string, proto uint8, offset uint16) []byte {
	f := ip4(src, dst, proto, []byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0})
	binary.BigEndian.PutUint16(f[14+6:], offset)
	return f
}

func ip6(src, dst string, next uint8, payload []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(payload)))
	h[6] = next
	h[7] = 64
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(h[8:24], s[:])
	copy(h[24:40], d[:])
	return eth(etherIPv6, append(h, payload...))
}

func icmp6(typ uint8) []byte { return []byte{typ, 0, 0, 0, 0, 0, 0, 0} }

func dnsQuery(name string) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			q = append(q, byte(i-start))
			q = append(q, name[start:i]...)
			start = i + 1
		}
	}
	return append(q, 0, 0, 1, 0, 1)
}

func stunBinding() []byte {
	m := make([]byte, 20)
	binary.BigEndian.PutUint16(m[0:], 0x0001)
	binary.BigEndian.PutUint32(m[4:], 0x2112A442)
	copy(m[8:], "lethe-txn-id")
	return m
}
