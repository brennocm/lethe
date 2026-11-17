package guard

import (
	"fmt"
	"net/netip"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Exception is a temporary accept for one selftest flow (spec §18.1): the exact 5-tuple of the
// test, to a documentation destination, from root. It goes first in the output chain and in the
// L2 chains and lives for one selftest case.
type Exception struct {
	Proto uint8 // unix.IPPROTO_UDP | unix.IPPROTO_TCP
	Sport uint16
	Dst   netip.AddrPort
}

// documentation are the only destinations an exception may open (RFC 5737, RFC 3849): they are
// not routed on the internet, so an exception can never let a real leak out.
var documentation = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("2001:db8::/32"),
}

// IsDocumentation reports whether a is in a documentation range.
func IsDocumentation(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range documentation {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (e Exception) check() error {
	if !IsDocumentation(e.Dst.Addr()) {
		return fmt.Errorf("guard: selftest exception to %s refused: not a documentation address", e.Dst.Addr())
	}
	if e.Proto != unix.IPPROTO_UDP && e.Proto != unix.IPPROTO_TCP {
		return fmt.Errorf("guard: selftest exception: protocol %d", e.Proto)
	}
	if e.Sport == 0 || e.Dst.Port() == 0 {
		return fmt.Errorf("guard: selftest exception needs both ports")
	}
	return nil
}

// rule is "[meta skuid 0] ip daddr X meta l4proto P th sport S th dport D accept".
func (e Exception) rule(f l3, withUID bool) Rule {
	a := e.Dst.Addr().Unmap()
	v6 := a.Is6()
	off := uint32(16)
	if v6 {
		off = 24
	}
	name := map[uint8]string{unix.IPPROTO_TCP: "tcp", unix.IPPROTO_UDP: "udp"}[e.Proto]
	text := fmt.Sprintf("%s daddr %s meta l4proto %s th sport %d th dport %d accept # selftest", ipWord(v6), a, name, e.Sport, e.Dst.Port())
	var ex []expr.Any
	if withUID {
		text = "meta skuid 0 " + text
		ex = append(ex, &expr.Meta{Key: expr.MetaKeySKUID, Register: reg1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: binaryutil.NativeEndian.PutUint32(0)})
	}
	ex = append(ex, f.is(v6)...)
	ex = append(ex,
		&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseNetworkHeader, Offset: off, Len: uint32(len(a.AsSlice()))},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: a.AsSlice()},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: reg1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: []byte{e.Proto}},
		&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: be16(e.Sport)},
		&expr.Payload{DestRegister: reg1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: reg1, Data: be16(e.Dst.Port())},
		accept(),
	)
	return Rule{Text: text, Exprs: ex}
}

// exceptionRules validates and renders the exceptions of cfg for one family.
func exceptionRules(cfg Config, f l3, withUID bool) ([]Rule, error) {
	var out []Rule
	for _, e := range cfg.Exceptions {
		if err := e.check(); err != nil {
			return nil, err
		}
		out = append(out, e.rule(f, withUID))
	}
	return out, nil
}
