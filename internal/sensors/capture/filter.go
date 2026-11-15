// Package capture is the NET-001 sensor (spec §8): one AF_PACKET socket per hardware egress
// interface with a kernel cBPF filter that delivers only outgoing frames that are NOT allowed.
package capture

import (
	"errors"
	"fmt"
	"net/netip"

	"golang.org/x/net/bpf"
)

// Snaplen is how much of each delivered frame reaches user space (IP + L4 + DNS/STUN header).
const Snaplen = 512

// MaxEndpoints bounds the cBPF program (4096 instructions); beyond it the sensor goes GRAY.
const MaxEndpoints = 256

// maxInstructions is BPF_MAXINSNS (linux/bpf_common.h).
const maxInstructions = 4096

// ErrTooManyEndpoints is returned when the allowlist cannot fit a cBPF program.
var ErrTooManyEndpoints = errors.New("allowlist exceeds the cBPF limit")

// Endpoint is an allowed destination (IP, L4 protocol, port).
type Endpoint struct {
	Addr  netip.AddrPort
	Proto uint8 // 6 = TCP, 17 = UDP
}

// Allowlist is what may leave an egress interface (spec §1.3, §8.1).
type Allowlist struct {
	Endpoints []Endpoint
	LAN       []netip.Prefix // only when network.allow_lan
}

const (
	ethTypeOff = 12
	ip4Base    = 14
	ip6Base    = 14

	etherARP   = 0x0806
	etherEAPOL = 0x888e
	etherIPv4  = 0x0800
	etherIPv6  = 0x86dd

	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58

	pktOutgoing = 4 // PACKET_OUTGOING (linux/if_packet.h)
)

// asm is a tiny assembler: conditional jumps are local (8-bit), long jumps use labels + ja.
type asm struct {
	ins    []bpf.Instruction
	labels map[string]int
	fixups map[int]string // index of a ja → target label
}

func newAsm() *asm { return &asm{labels: map[string]int{}, fixups: map[int]string{}} }

func (a *asm) add(i ...bpf.Instruction) { a.ins = append(a.ins, i...) }
func (a *asm) label(name string)        { a.labels[name] = len(a.ins) }
func (a *asm) jump(label string) {
	a.fixups[len(a.ins)] = label
	a.add(bpf.Jump{})
}
func (a *asm) drop()    { a.add(bpf.RetConstant{Val: 0}) }
func (a *asm) deliver() { a.add(bpf.RetConstant{Val: Snaplen}) }

func (a *asm) assemble() ([]bpf.Instruction, error) {
	for at, name := range a.fixups {
		target, ok := a.labels[name]
		if !ok {
			return nil, fmt.Errorf("bpf: undefined label %s", name)
		}
		a.ins[at] = bpf.Jump{Skip: uint32(target - at - 1)} // #nosec G115 -- forward jump, program < 4096
	}
	if len(a.ins) > maxInstructions {
		return nil, ErrTooManyEndpoints
	}
	return a.ins, nil
}

// ifEq emits "if A == v { body }" where body is a few instructions (local skip < 256).
func (a *asm) ifEq(v uint32, body ...bpf.Instruction) {
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: v, SkipFalse: uint8(len(body))}) // #nosec G115 -- small bodies
	a.add(body...)
}

// Build generates the filter. withPktType=false omits the PACKET_OUTGOING check, which the
// x/net/bpf VM cannot execute; only tests use that.
func Build(al Allowlist, withPktType bool) ([]bpf.Instruction, error) {
	if len(al.Endpoints) > MaxEndpoints {
		return nil, ErrTooManyEndpoints
	}
	a := newAsm()
	if withPktType {
		a.add(bpf.LoadExtension{Num: bpf.ExtType})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: pktOutgoing, SkipTrue: 1})
		a.drop()
	}
	a.add(bpf.LoadAbsolute{Off: ethTypeOff, Size: 2})
	a.ifEq(etherARP, bpf.RetConstant{Val: 0})
	a.ifEq(etherEAPOL, bpf.RetConstant{Val: 0})
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherIPv6, SkipFalse: 1})
	a.jump("v6")
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: etherIPv4, SkipTrue: 1})
	a.deliver() // any other L2 protocol: user space decides (fail toward visibility)

	// ---- IPv4 ----
	a.add(bpf.LoadMemShift{Off: ip4Base}) // X = IHL*4
	// DHCPv4 client → server (udp 68 → 67)
	a.add(bpf.LoadAbsolute{Off: ip4Base + 9, Size: 1})
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoUDP, SkipFalse: 5})
	a.add(bpf.LoadIndirect{Off: ip4Base, Size: 2})
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 68, SkipFalse: 3})
	a.add(bpf.LoadIndirect{Off: ip4Base + 2, Size: 2})
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 67, SkipFalse: 1})
	a.drop()
	for _, e := range al.Endpoints {
		if !e.Addr.Addr().Is4() {
			continue
		}
		ip := e.Addr.Addr().As4()
		// dst == ip && proto == P && (fragment || dport == port) → drop
		a.add(bpf.LoadAbsolute{Off: ip4Base + 16, Size: 4})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(ip[:]), SkipFalse: 8})
		a.add(bpf.LoadAbsolute{Off: ip4Base + 9, Size: 1})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(e.Proto), SkipFalse: 6})
		a.add(bpf.LoadAbsolute{Off: ip4Base + 6, Size: 2})
		a.add(bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: 0x1fff, SkipFalse: 1}) // non-first fragment: no ports
		a.drop()
		a.add(bpf.LoadIndirect{Off: ip4Base + 2, Size: 2})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(e.Addr.Port()), SkipFalse: 1})
		a.drop()
	}
	for _, p := range al.LAN {
		if !p.Addr().Is4() {
			continue
		}
		ip := p.Masked().Addr().As4()
		a.add(bpf.LoadAbsolute{Off: ip4Base + 16, Size: 4})
		a.add(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: mask4(p.Bits())})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(ip[:]), SkipFalse: 1})
		a.drop()
	}
	a.deliver()

	// ---- IPv6 (no extension-header walking: anything unusual is delivered) ----
	a.label("v6")
	a.add(bpf.LoadAbsolute{Off: ip6Base + 6, Size: 1}) // next header
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoICMPv6, SkipFalse: 6})
	a.add(bpf.LoadAbsolute{Off: ip6Base + 40, Size: 1}) // ICMPv6 type: RS 133, NS 135, NA 136, MLDv2 143
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 133, SkipTrue: 3})
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 135, SkipTrue: 2})
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 136, SkipTrue: 1})
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 143, SkipFalse: 1})
	a.drop()
	// DHCPv6 client → server (udp 546 → 547)
	a.add(bpf.LoadAbsolute{Off: ip6Base + 6, Size: 1})
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: protoUDP, SkipFalse: 5})
	a.add(bpf.LoadAbsolute{Off: ip6Base + 40, Size: 2})
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 546, SkipFalse: 3})
	a.add(bpf.LoadAbsolute{Off: ip6Base + 42, Size: 2})
	a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: 547, SkipFalse: 1})
	a.drop()
	for _, e := range al.Endpoints {
		if !e.Addr.Addr().Is6() {
			continue
		}
		ip := e.Addr.Addr().As16()
		// 4 words of dst, next header, dport
		a.add(bpf.LoadAbsolute{Off: ip6Base + 24, Size: 4})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(ip[0:4]), SkipFalse: 11})
		a.add(bpf.LoadAbsolute{Off: ip6Base + 28, Size: 4})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(ip[4:8]), SkipFalse: 9})
		a.add(bpf.LoadAbsolute{Off: ip6Base + 32, Size: 4})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(ip[8:12]), SkipFalse: 7})
		a.add(bpf.LoadAbsolute{Off: ip6Base + 36, Size: 4})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(ip[12:16]), SkipFalse: 5})
		a.add(bpf.LoadAbsolute{Off: ip6Base + 6, Size: 1})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(e.Proto), SkipFalse: 3})
		a.add(bpf.LoadAbsolute{Off: ip6Base + 42, Size: 2})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(e.Addr.Port()), SkipFalse: 1})
		a.drop()
	}
	for _, p := range al.LAN {
		if !p.Addr().Is6() || p.Bits() > 64 { // longer prefixes: delivered, user space decides
			continue
		}
		ip := p.Masked().Addr().As16()
		bits := p.Bits()
		// compare the first 1-2 words under the mask (prefixes up to /64)
		w0mask := mask4(min(bits, 32))
		a.add(bpf.LoadAbsolute{Off: ip6Base + 24, Size: 4})
		a.add(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: w0mask})
		if bits <= 32 {
			a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(ip[0:4]), SkipFalse: 1})
			a.drop()
			continue
		}
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(ip[0:4]), SkipFalse: 4})
		a.add(bpf.LoadAbsolute{Off: ip6Base + 28, Size: 4})
		a.add(bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: mask4(bits - 32)})
		a.add(bpf.JumpIf{Cond: bpf.JumpEqual, Val: be32(ip[4:8]), SkipFalse: 1})
		a.drop()
	}
	a.deliver()
	return a.assemble()
}

// DropAll is attached before bind so no frame is processed before the real filter (spec §8.1).
func DropAll() []bpf.Instruction { return []bpf.Instruction{bpf.RetConstant{Val: 0}} }

func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func mask4(bits int) uint32 {
	if bits <= 0 {
		return 0
	}
	if bits >= 32 {
		return 0xffffffff
	}
	return ^uint32(0) << (32 - bits)
}
