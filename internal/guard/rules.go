package guard

import (
	"encoding/binary"
	"fmt"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Registers: legacy reg 1 (128 bit) is NFT_REG32_00..03; concatenations continue in 32-bit
// registers after the previous field, exactly as nft compiles them.
const (
	reg1    = 1
	reg3200 = 8 // NFT_REG32_00
)

// l3 knows how a family tests for IPv4/IPv6: inet uses meta nfproto, netdev/bridge the
// ethertype (meta protocol).
type l3 struct{ family nftables.TableFamily }

func (f l3) is(v6 bool) []expr.Any {
	if f.family == nftables.TableFamilyINet {
		p := byte(unix.NFPROTO_IPV4)
		if v6 {
			p = unix.NFPROTO_IPV6
		}
		return []expr.Any{
			&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: reg1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{p}},
		}
	}
	et := uint16(unix.ETH_P_IP)
	if v6 {
		et = unix.ETH_P_IPV6
	}
	return metaProtocol(et)
}

func metaProtocol(ethertype uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyPROTOCOL, Register: reg1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: binaryutil.BigEndian.PutUint16(ethertype)},
	}
}

func ipWord(v6 bool) string {
	if v6 {
		return "ip6"
	}
	return "ip"
}

// IfName pads an interface name to IFNAMSIZ, as the kernel compares it.
func IfName(n string) []byte {
	b := make([]byte, unix.IFNAMSIZ)
	copy(b, n+"\x00")
	return b
}

func verdict(k expr.VerdictKind) *expr.Verdict { return &expr.Verdict{Kind: k} }

func accept() *expr.Verdict { return verdict(expr.VerdictAccept) }

func join(parts ...[]expr.Any) []expr.Any {
	var out []expr.Any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func lookup(s *Set, reg uint32) *expr.Lookup {
	return &expr.Lookup{SourceRegister: reg, SetName: s.Name} // SetID bound at apply time
}

func ruleIfAccept(dir, name string) Rule {
	key := expr.MetaKeyOIFNAME
	if dir == "iifname" {
		key = expr.MetaKeyIIFNAME
	}
	return Rule{Text: fmt.Sprintf("%s %q accept", dir, name), Exprs: []expr.Any{
		&expr.Meta{Key: key, Register: reg1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: IfName(name)},
		accept(),
	}}
}

func ruleIfSetAccept(dir string, s *Set) Rule {
	key := expr.MetaKeyOIFNAME
	if dir == "iifname" {
		key = expr.MetaKeyIIFNAME
	}
	return Rule{Text: fmt.Sprintf("%s @%s accept", dir, s.Name), Exprs: []expr.Any{
		&expr.Meta{Key: key, Register: reg1}, lookup(s, reg1), accept(),
	}}
}

func ruleMarkAccept(mark uint32) Rule {
	return Rule{Text: fmt.Sprintf("meta mark 0x%08x accept", mark), Exprs: []expr.Any{
		&expr.Meta{Key: expr.MetaKeyMARK, Register: reg1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: binaryutil.NativeEndian.PutUint32(mark)},
		accept(),
	}}
}

// endpointMatch loads "<ip> daddr|saddr . meta l4proto . th dport|sport" and looks it up in s.
func endpointMatch(f l3, s *Set, v6, source bool) []expr.Any {
	off, addrLen, next := uint32(16), uint32(4), uint32(reg3200+1)
	if v6 {
		off, addrLen, next = 24, 16, reg3200+4
	}
	portOff := uint32(2)
	if source {
		off -= addrLen
		portOff = 0
	}
	return join(f.is(v6), []expr.Any{
		&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: addrLen},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: next},
		&expr.Payload{DestRegister: next + 1, Base: expr.PayloadBaseTransportHeader, Offset: portOff, Len: 2},
		lookup(s, reg1),
	})
}

func ruleEndpointsAccept(f l3, s *Set, v6, source bool) Rule {
	dir, port := "daddr", "dport"
	if source {
		dir, port = "saddr", "sport"
	}
	return Rule{Text: fmt.Sprintf("%s %s . meta l4proto . th %s @%s accept", ipWord(v6), dir, port, s.Name),
		Exprs: append(endpointMatch(f, s, v6, source), accept())}
}

func ruleSkuidEndpointsAccept(f l3, uid uint32, s *Set, v6 bool) Rule {
	r := ruleEndpointsAccept(f, s, v6, false)
	r.Text = fmt.Sprintf("meta skuid %d ", uid) + r.Text
	r.Exprs = append([]expr.Any{
		&expr.Meta{Key: expr.MetaKeySKUID, Register: reg1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: binaryutil.NativeEndian.PutUint32(uid)},
	}, r.Exprs...)
	return r
}

func ruleCgroupAccept(id uint64, level uint32, path string) Rule {
	return Rule{Text: fmt.Sprintf("socket cgroupv2 level %d %q accept # id %d", level, path, id), Exprs: []expr.Any{
		&expr.Socket{Key: expr.SocketKeyCgroupv2, Level: level, Register: reg1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: binaryutil.NativeEndian.PutUint64(id)},
		accept(),
	}}
}

func udpPorts(sport, dport uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: reg1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: binaryutil.BigEndian.PutUint16(sport)},
		&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: binaryutil.BigEndian.PutUint16(dport)},
	}
}

func ruleDHCPAccept(f l3, v6 bool) Rule {
	sport, dport := uint16(68), uint16(67)
	if v6 {
		sport, dport = 546, 547
	}
	text := fmt.Sprintf("udp sport %d udp dport %d accept", sport, dport)
	if f.family != nftables.TableFamilyINet {
		text = fmt.Sprintf("meta protocol %s %s", ipWord(v6), text)
	}
	return Rule{Text: text, Exprs: join(f.is(v6), udpPorts(sport, dport), []expr.Any{accept()})}
}

var icmp6Names = map[byte]string{133: "nd-router-solicit", 135: "nd-neighbor-solicit", 136: "nd-neighbor-advert", 143: "mld2-listener-report"}

// rulesICMPv6Link accepts NDP and MLDv2 (one rule per type; same semantics as the set form).
func rulesICMPv6Link(f l3) []Rule {
	var out []Rule
	for _, t := range []byte{133, 135, 136, 143} {
		out = append(out, Rule{Text: fmt.Sprintf("icmpv6 type %s accept", icmp6Names[t]), Exprs: join(f.is(true), []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: reg1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{unix.IPPROTO_ICMPV6}},
			&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{t}},
			accept(),
		})})
	}
	return out
}

func ruleDaddrSetAccept(f l3, s *Set, v6 bool) Rule {
	off, n := uint32(16), uint32(4)
	if v6 {
		off, n = 24, 16
	}
	return Rule{Text: fmt.Sprintf("%s daddr @%s accept", ipWord(v6), s.Name), Exprs: join(f.is(v6), []expr.Any{
		&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: n},
		lookup(s, reg1), accept(),
	})}
}

func ruleEtherAccept(ethertype uint16, name string) Rule {
	return Rule{Text: fmt.Sprintf("meta protocol %s accept", name), Exprs: append(metaProtocol(ethertype), accept())}
}

// LogGroup is the NFLOG group read by the NET-002 sensor.
const LogGroup = 4242

func ruleLimitLog(prefix string) Rule {
	return Rule{Text: fmt.Sprintf("limit rate 100/second burst 200 packets log group %d prefix %q", LogGroup, prefix), Exprs: []expr.Any{
		&expr.Limit{Type: expr.LimitTypePkts, Rate: 100, Unit: expr.LimitTimeSecond, Burst: 200},
		&expr.Log{Key: 1<<unix.NFTA_LOG_GROUP | 1<<unix.NFTA_LOG_PREFIX, Group: LogGroup, Data: []byte(prefix)},
	}}
}

func ruleDrop() Rule { return Rule{Text: "drop", Exprs: []expr.Any{verdict(expr.VerdictDrop)}} }

// prefixRule prepends an oifname @set match (bridge chain: only frames towards egress ports).
func prefixOifSet(s *Set, r Rule) Rule {
	r.Text = fmt.Sprintf("oifname @%s %s", s.Name, r.Text)
	r.Exprs = append([]expr.Any{&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: reg1}, lookup(s, reg1)}, r.Exprs...)
	return r
}

func be16(v uint16) []byte { return binary.BigEndian.AppendUint16(nil, v) }
