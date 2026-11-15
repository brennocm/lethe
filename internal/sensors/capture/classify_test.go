package capture

import (
	"encoding/binary"
	"testing"

	"lethe/internal/contracts"
)

const me4, me6 = "10.0.0.2", "2001:db8:1::2"

func TestNET001_ClassifyTable(t *testing.T) {
	tcpDNS := append([]byte{0, 0}, dnsQuery("tcp.example.test")...)
	binary.BigEndian.PutUint16(tcpDNS, uint16(len(tcpDNS)-2))
	cases := []struct {
		name    string
		frame   []byte
		check   string
		sev     contracts.Severity
		subtype string
		proto   string
		qname   string
	}{
		{"udp leak", ip4(me4, "192.0.2.1", protoUDP, l4(protoUDP, 40000, 9, nil)), CheckNET001, contracts.SeverityCritical, "", "udp", ""},
		{"tcp syn", ip4(me4, "198.51.100.1", protoTCP, l4(protoTCP, 40000, 443, nil)), CheckNET001, contracts.SeverityCritical, "", "tcp", ""},
		{"icmp", ip4(me4, "192.0.2.1", 1, []byte{8, 0, 0, 0}), CheckNET001, contracts.SeverityCritical, "", "icmp", ""},
		{"dns udp", ip4(me4, "192.0.2.53", protoUDP, l4(protoUDP, 40000, 53, dnsQuery("leak.example.test"))), CheckDNS001, contracts.SeverityCritical, "", "udp", "leak.example.test"},
		{"dns tcp", ip4(me4, "192.0.2.53", protoTCP, append(l4(protoTCP, 40000, 53, nil), tcpDNS...)), CheckDNS001, contracts.SeverityCritical, "", "tcp", "tcp.example.test"},
		{"dns tcp syn", ip4(me4, "192.0.2.53", protoTCP, l4(protoTCP, 40000, 53, nil)), CheckDNS001, contracts.SeverityCritical, "", "tcp", ""},
		{"dns garbage", ip4(me4, "192.0.2.53", protoUDP, l4(protoUDP, 40000, 53, []byte{1, 2, 3})), CheckDNS001, contracts.SeverityCritical, "", "udp", ""},
		{"dot", ip4(me4, "192.0.2.53", protoTCP, l4(protoTCP, 40000, 853, nil)), CheckDNS001, contracts.SeverityCritical, "dot", "tcp", ""},
		{"doq", ip4(me4, "192.0.2.53", protoUDP, l4(protoUDP, 40000, 853, nil)), CheckDNS001, contracts.SeverityCritical, "doq", "udp", ""},
		{"stun port", ip4(me4, "203.0.113.1", protoUDP, l4(protoUDP, 40000, 3478, nil)), CheckNET012, contracts.SeverityCritical, "", "udp", ""},
		{"stun google range", ip4(me4, "203.0.113.1", protoUDP, l4(protoUDP, 40000, 19305, nil)), CheckNET012, contracts.SeverityCritical, "", "udp", ""},
		{"stun cookie on odd port", ip4(me4, "203.0.113.1", protoUDP, l4(protoUDP, 40000, 40001, stunBinding())), CheckNET012, contracts.SeverityCritical, "", "udp", ""},
		{"mdns", ip4(me4, "224.0.0.251", protoUDP, l4(protoUDP, 5353, 5353, nil)), CheckNET009, contracts.SeverityWarning, "", "udp", ""},
		{"llmnr", ip4(me4, "224.0.0.252", protoUDP, l4(protoUDP, 40000, 5355, nil)), CheckNET009, contracts.SeverityWarning, "", "udp", ""},
		{"ssdp", ip4(me4, "239.255.255.250", protoUDP, l4(protoUDP, 40000, 1900, nil)), CheckNET009, contracts.SeverityWarning, "", "udp", ""},
		{"netbios", ip4(me4, "10.0.0.255", protoUDP, l4(protoUDP, 137, 137, nil)), CheckNET009, contracts.SeverityWarning, "", "udp", ""},
		{"v6 udp", ip6(me6, "2001:db8::1", protoUDP, l4(protoUDP, 40000, 9, nil)), CheckNET001, contracts.SeverityCritical, "ipv6", "udp", ""},
		{"v6 dns stays DNS-001", ip6(me6, "2001:db8::53", protoUDP, l4(protoUDP, 40000, 53, dnsQuery("six.example.test"))), CheckDNS001, contracts.SeverityCritical, "", "udp", "six.example.test"},
		{"v6 hop-by-hop then udp", ip6(me6, "2001:db8::1", 0, append([]byte{protoUDP, 0, 0, 0, 0, 0, 0, 0}, l4(protoUDP, 1, 53, nil)...)), CheckDNS001, contracts.SeverityCritical, "", "udp", ""},
		{"v6 later fragment", ip6(me6, "2001:db8::1", 44, []byte{protoUDP, 0, 0x05, 0x00, 0, 0, 0, 1}), CheckNET001, contracts.SeverityCritical, "ipv6", "udp", ""},
		{"v4 later fragment", frag4(me4, "192.0.2.1", protoUDP, 0x00b9), CheckNET001, contracts.SeverityCritical, "fragment", "udp", ""},
		{"lldp", eth(0x88cc, make([]byte, 16)), CheckNET001, contracts.SeverityCritical, "l2", "ether:0x88cc", ""},
		{"runt", []byte{1, 2}, CheckNET001, contracts.SeverityCritical, "l2", "ether:?", ""},
		{"truncated ipv4", eth(etherIPv4, []byte{0x45, 0}), CheckNET001, contracts.SeverityCritical, "", "ip:?", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := Classify(c.frame, len(c.frame))
			if l.Check != c.check || l.Severity != c.sev || l.Subtype != c.subtype || l.Proto != c.proto || l.QName != c.qname {
				t.Fatalf("got check=%s sev=%s subtype=%q proto=%s qname=%q", l.Check, l.Severity, l.Subtype, l.Proto, l.QName)
			}
		})
	}
}

func TestDNS001_QNameNeverInData(t *testing.T) {
	f := ip4(me4, "192.0.2.53", protoUDP, l4(protoUDP, 40000, 53, dnsQuery("sentinel-qname.example.test")))
	l := Classify(f, len(f))
	if l.QName == "" {
		t.Fatal("qname not decoded")
	}
	for k, v := range l.Data() {
		if s, ok := v.(string); ok && s == l.QName {
			t.Fatalf("qname leaked into data[%s]", k)
		}
	}
	want := map[string]any{"proto": "udp", "len": len(f), "src": me4, "dst": "192.0.2.53", "sport": 40000, "dport": 53}
	got := l.Data()
	if len(got) != len(want) {
		t.Fatalf("data=%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("data[%s]=%v, want %v", k, got[k], v)
		}
	}
}

func TestNET010_LeakTuple(t *testing.T) {
	f := ip4(me4, "198.51.100.1", protoTCP, l4(protoTCP, 40000, 443, nil))
	proto, src, dst, ok := Classify(f, len(f)).Tuple()
	if !ok || proto != "tcp" || src.String() != "10.0.0.2:40000" || dst.String() != "198.51.100.1:443" {
		t.Fatalf("%v %s %s %s", ok, proto, src, dst)
	}
	icmp := ip4(me4, "192.0.2.1", 1, []byte{8, 0, 0, 0})
	if _, _, _, ok := Classify(icmp, len(icmp)).Tuple(); ok {
		t.Fatal("icmp has no tuple")
	}
}

func FuzzClassify(f *testing.F) {
	f.Add(ip4(me4, "192.0.2.53", protoUDP, l4(protoUDP, 1, 53, dnsQuery("a.example.test"))))
	f.Add(ip6(me6, "2001:db8::1", 0, append([]byte{protoUDP, 0, 0, 0, 0, 0, 0, 0}, l4(protoUDP, 1, 9, nil)...)))
	f.Add(ip4(me4, "203.0.113.1", protoUDP, l4(protoUDP, 1, 2, stunBinding())))
	f.Add(eth(0x88cc, nil))
	f.Fuzz(func(t *testing.T, frame []byte) {
		l := Classify(frame, len(frame))
		if l.Check == "" || !l.Severity.Valid() || l.Proto == "" {
			t.Fatalf("incomplete leak %+v", l)
		}
		_ = l.Data()
	})
}

func TestNET012_STUNOnlyByPortOrCookie(t *testing.T) {
	notSTUN := stunBinding()
	notSTUN[4] ^= 0xff // wrong magic cookie, odd port: plain NET-001
	f := ip4(me4, "203.0.113.1", protoUDP, l4(protoUDP, 40000, 40001, notSTUN))
	if l := Classify(f, len(f)); l.Check != CheckNET001 {
		t.Fatalf("got %s", l.Check)
	}
	tcp := ip4(me4, "203.0.113.1", protoTCP, l4(protoTCP, 40000, 40001, stunBinding()))
	if l := Classify(tcp, len(tcp)); l.Check != CheckNET001 {
		t.Fatalf("cookie only counts on UDP, got %s", l.Check)
	}
	turnTLS := ip4(me4, "203.0.113.1", protoTCP, l4(protoTCP, 40000, 5349, nil))
	if l := Classify(turnTLS, len(turnTLS)); l.Check != CheckNET012 || l.Severity != contracts.SeverityCritical {
		t.Fatalf("got %s %s", l.Check, l.Severity)
	}
}

func TestNET009_LANBroadcastIsWarning(t *testing.T) {
	for _, port := range []uint16{5353, 5355, 137, 138, 1900} {
		f := ip4(me4, "224.0.0.251", protoUDP, l4(protoUDP, 40000, port, nil))
		if l := Classify(f, len(f)); l.Check != CheckNET009 || l.Severity != contracts.SeverityWarning {
			t.Fatalf("port %d: %s %s", port, l.Check, l.Severity)
		}
	}
	// DNS wins over the NET-009 ports (first match, §8.3)
	f := ip4(me4, "224.0.0.251", protoUDP, l4(protoUDP, 5353, 53, nil))
	if l := Classify(f, len(f)); l.Check != CheckDNS001 {
		t.Fatalf("got %s", l.Check)
	}
}
