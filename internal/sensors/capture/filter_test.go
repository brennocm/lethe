package capture

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"golang.org/x/net/bpf"
)

func vm(t *testing.T, al Allowlist) *bpf.VM {
	t.Helper()
	prog, err := Build(al, false)
	if err != nil {
		t.Fatal(err)
	}
	v, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func delivered(t *testing.T, v *bpf.VM, frame []byte) bool {
	t.Helper()
	n, err := v.Run(frame)
	if err != nil {
		t.Fatal(err)
	}
	return n > 0
}

var testAllow = Allowlist{
	Endpoints: []Endpoint{
		{Addr: netip.MustParseAddrPort("198.18.0.2:51820"), Proto: protoUDP},
		{Addr: netip.MustParseAddrPort("[2001:db8:ffff::2]:51820"), Proto: protoUDP},
		{Addr: netip.MustParseAddrPort("198.18.0.9:443"), Proto: protoTCP},
	},
	LAN: []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("fd00:1:2::/48"),
		netip.MustParsePrefix("fd99::/16"),
	},
}

func TestNET001_FilterAllowlist(t *testing.T) {
	v := vm(t, testAllow)
	const me4, me6 = "10.0.0.2", "2001:db8:1::2"
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"arp", eth(etherARP, make([]byte, 28)), false},
		{"eapol", eth(etherEAPOL, make([]byte, 8)), false},
		{"lldp other L2 delivered", eth(0x88cc, make([]byte, 16)), true},
		{"dhcpv4", ip4("0.0.0.0", "255.255.255.255", protoUDP, l4(protoUDP, 68, 67, nil)), false},
		{"udp 68 to non-67", ip4(me4, "192.0.2.1", protoUDP, l4(protoUDP, 68, 53, nil)), true},
		{"wg endpoint", ip4(me4, "198.18.0.2", protoUDP, l4(protoUDP, 40000, 51820, nil)), false},
		{"wg endpoint with ip options", ip4opts(me4, "198.18.0.2", protoUDP, l4(protoUDP, 40000, 51820, nil)), false},
		{"endpoint ip, wrong port", ip4(me4, "198.18.0.2", protoUDP, l4(protoUDP, 40000, 51821, nil)), true},
		{"endpoint ip, wrong proto", ip4(me4, "198.18.0.2", protoTCP, l4(protoTCP, 40000, 51820, nil)), true},
		{"endpoint ip, wrong port, ip options", ip4opts(me4, "198.18.0.2", protoUDP, l4(protoUDP, 40000, 9, nil)), true},
		{"tcp endpoint", ip4(me4, "198.18.0.9", protoTCP, l4(protoTCP, 40000, 443, nil)), false},
		{"non-first fragment to endpoint", frag4(me4, "198.18.0.2", protoUDP, 0x00b9), false},
		{"non-first fragment elsewhere", frag4(me4, "192.0.2.1", protoUDP, 0x00b9), true},
		{"leak v4", ip4(me4, "192.0.2.1", protoUDP, l4(protoUDP, 40000, 9, nil)), true},
		{"dns leak", ip4(me4, "192.0.2.53", protoUDP, l4(protoUDP, 40000, 53, dnsQuery("example.test"))), true},
		{"lan v4", ip4(me4, "10.0.0.1", protoTCP, l4(protoTCP, 40000, 22, nil)), false},
		{"just outside lan v4", ip4(me4, "10.0.1.1", protoTCP, l4(protoTCP, 40000, 22, nil)), true},
		{"ndp rs", ip6("fe80::1", "ff02::2", protoICMPv6, icmp6(133)), false},
		{"ndp ns", ip6("fe80::1", "ff02::1:ff00:1", protoICMPv6, icmp6(135)), false},
		{"ndp na", ip6("fe80::1", "fe80::2", protoICMPv6, icmp6(136)), false},
		{"mldv2", ip6("fe80::1", "ff02::16", protoICMPv6, icmp6(143)), false},
		{"icmpv6 echo delivered", ip6(me6, "2001:db8::1", protoICMPv6, icmp6(128)), true},
		{"dhcpv6", ip6("fe80::1", "ff02::1:2", protoUDP, l4(protoUDP, 546, 547, nil)), false},
		{"v6 wg endpoint", ip6(me6, "2001:db8:ffff::2", protoUDP, l4(protoUDP, 40000, 51820, nil)), false},
		{"v6 endpoint, wrong port", ip6(me6, "2001:db8:ffff::2", protoUDP, l4(protoUDP, 40000, 1, nil)), true},
		{"v6 near endpoint", ip6(me6, "2001:db8:ffff::3", protoUDP, l4(protoUDP, 40000, 51820, nil)), true},
		{"leak v6", ip6(me6, "2001:db8::1", protoUDP, l4(protoUDP, 40000, 9, nil)), true},
		{"lan v6 /48", ip6(me6, "fd00:1:2:3::1", protoTCP, l4(protoTCP, 40000, 22, nil)), false},
		{"outside lan v6 /48", ip6(me6, "fd00:1:3::1", protoTCP, l4(protoTCP, 40000, 22, nil)), true},
		{"lan v6 /16", ip6(me6, "fd99:abcd::1", protoTCP, l4(protoTCP, 40000, 22, nil)), false},
		{"truncated frame", []byte{1, 2, 3}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := delivered(t, v, c.frame); got != c.want {
				t.Fatalf("delivered=%v, want %v", got, c.want)
			}
		})
	}
}

func TestNET001_FilterEmptyAllowlistDeliversLeaks(t *testing.T) {
	v := vm(t, Allowlist{})
	if !delivered(t, v, ip4("10.0.0.2", "10.0.0.1", protoTCP, l4(protoTCP, 1, 22, nil))) {
		t.Fatal("without allow_lan the LAN is a leak")
	}
	if delivered(t, v, eth(etherARP, make([]byte, 28))) {
		t.Fatal("ARP must always be dropped")
	}
}

func TestNET001_FilterSnaplen(t *testing.T) {
	v := vm(t, Allowlist{})
	big := ip4("10.0.0.2", "192.0.2.1", protoUDP, l4(protoUDP, 1, 9, make([]byte, 1400)))
	n, err := v.Run(big)
	if err != nil || n != Snaplen {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestNET001_FilterLimits(t *testing.T) {
	var al Allowlist
	for i := range MaxEndpoints {
		al.Endpoints = append(al.Endpoints, Endpoint{Addr: netip.AddrPortFrom(netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i+1)), 51820), Proto: protoUDP})
	}
	prog, err := Build(al, true)
	if err != nil {
		t.Fatalf("256 endpoints must fit: %v", err)
	}
	if len(prog) > maxInstructions {
		t.Fatalf("program has %d instructions", len(prog))
	}
	if _, err := bpf.Assemble(prog); err != nil {
		t.Fatal(err)
	}
	al.Endpoints = append(al.Endpoints, al.Endpoints[0])
	if _, err := Build(al, true); !errors.Is(err, ErrTooManyEndpoints) {
		t.Fatalf("257 endpoints: err=%v", err)
	}
}

func TestNET001_FilterPktTypePrefix(t *testing.T) {
	prog, err := Build(testAllow, true)
	if err != nil {
		t.Fatal(err)
	}
	ext, ok := prog[0].(bpf.LoadExtension)
	if !ok || ext.Num != bpf.ExtType {
		t.Fatalf("first instruction must load SKF_AD_PKTTYPE, got %#v", prog[0])
	}
	if j, ok := prog[1].(bpf.JumpIf); !ok || j.Val != pktOutgoing {
		t.Fatalf("second instruction must compare with PACKET_OUTGOING, got %#v", prog[1])
	}
	if _, err := bpf.Assemble(DropAll()); err != nil {
		t.Fatal(err)
	}
}
