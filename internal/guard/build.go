package guard

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Endpoint is an allowed destination (IP, L4 protocol, port).
type Endpoint struct {
	Addr  netip.AddrPort
	Proto uint8 // unix.IPPROTO_TCP | unix.IPPROTO_UDP
}

// Cgroup is the VPN client's cgroup (spec §11.2). ID changes when the service restarts.
//
// The cgroup is never accepted as a whole: with NetworkManager the client runs in
// NetworkManager.service, whose own traffic (the connectivity check, for one) would then leave
// outside the tunnel. The client reaches its servers through the endpoint sets like everyone
// else (learned through NFLOG, spec §7.4); the cgroup only opens DNS, and only with
// egress.allow_vpn_client_dns.
type Cgroup struct {
	Path  string
	Level uint32
	ID    uint64
	DNS   bool // egress.allow_vpn_client_dns
}

// Config is everything the generator needs (from discovery and the profile).
type Config struct {
	Tunnels    []string // class tunnel
	Internal   []string // class internal
	Egress     []string // hardware egress interfaces (netdev egress chains, §11.5)
	Endpoints  []Endpoint
	LAN        []netip.Prefix // only with network.allow_lan
	WGMark     uint32         // 0 = none discovered
	VPN        *Cgroup        // OpenVPN/generic client (M8)
	TorUID     *uint32        // tor running under its own UID (M8)
	Bridges    map[string][]string
	L2         bool // kernel has the netdev egress hook (>= 5.16)
	KeepTunnel bool
}

// ErrNoEgress: a netdev chain needs at least one device; the generator never guesses.
var ErrNoEgress = errors.New("guard: L2 layer requested without egress interfaces")

func newSets(cfg Config, withInternal, withLAN bool) (map[string]*Set, error) {
	ifSet := func(name string, names []string) *Set {
		s := &Set{Name: name, TypeText: "ifname", Key: nftables.TypeIFName}
		for _, n := range sorted(names) {
			s.Elems = append(s.Elems, Elem{Text: fmt.Sprintf("%q", n), Key: IfName(n)})
		}
		return s
	}
	k4, err := nftables.ConcatSetType(nftables.TypeIPAddr, nftables.TypeInetProto, nftables.TypeInetService)
	if err != nil {
		return nil, err
	}
	k6, err := nftables.ConcatSetType(nftables.TypeIP6Addr, nftables.TypeInetProto, nftables.TypeInetService)
	if err != nil {
		return nil, err
	}
	sets := map[string]*Set{
		"tunnel_ifaces": ifSet("tunnel_ifaces", cfg.Tunnels),
		"endpoints4":    {Name: "endpoints4", TypeText: "ipv4_addr . inet_proto . inet_service", Key: k4, Concat: true},
		"endpoints6":    {Name: "endpoints6", TypeText: "ipv6_addr . inet_proto . inet_service", Key: k6, Concat: true},
	}
	if withInternal {
		sets["internal_ifaces"] = ifSet("internal_ifaces", cfg.Internal)
	}
	for _, e := range cfg.Endpoints {
		if e.Proto != unix.IPPROTO_TCP && e.Proto != unix.IPPROTO_UDP {
			return nil, fmt.Errorf("guard: endpoint %s: protocol %d is not tcp/udp", e.Addr, e.Proto)
		}
		a := e.Addr.Addr().Unmap()
		name := map[uint8]string{unix.IPPROTO_TCP: "tcp", unix.IPPROTO_UDP: "udp"}[e.Proto]
		pad := []byte{e.Proto, 0, 0, 0}
		port := append(be16(e.Addr.Port()), 0, 0)
		set := sets["endpoints4"]
		if a.Is6() {
			set = sets["endpoints6"]
		}
		set.Elems = append(set.Elems, Elem{
			Text: fmt.Sprintf("%s . %s . %d", a, name, e.Addr.Port()),
			Key:  append(append(a.AsSlice(), pad...), port...),
		})
	}
	if withLAN {
		lan4 := &Set{Name: "lan4", TypeText: "ipv4_addr", Key: nftables.TypeIPAddr, Interval: true}
		lan6 := &Set{Name: "lan6", TypeText: "ipv6_addr", Key: nftables.TypeIP6Addr, Interval: true}
		for _, p := range cfg.LAN {
			p = p.Masked()
			if p.Bits() == 0 {
				return nil, fmt.Errorf("guard: LAN prefix %s would allow everything", p)
			}
			end, ok := lastAddr(p)
			if !ok {
				return nil, fmt.Errorf("guard: LAN prefix %s reaches the end of the address space", p)
			}
			s := lan4
			if p.Addr().Is6() {
				s = lan6
			}
			s.Elems = append(s.Elems, Elem{Text: p.String(), Key: p.Addr().AsSlice(), End: end.Next().AsSlice()})
		}
		sets["lan4"], sets["lan6"] = lan4, lan6
	}
	return sets, nil
}

// lastAddr is the last address of p; ok=false when p ends at the top of the address space
// (the exclusive interval end would overflow).
func lastAddr(p netip.Prefix) (netip.Addr, bool) {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	last, _ := netip.AddrFromSlice(b)
	return last, last.Next().IsValid()
}

func sorted(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func ordered(sets map[string]*Set, names ...string) []*Set {
	var out []*Set
	for _, n := range names {
		if s, ok := sets[n]; ok {
			out = append(out, s)
		}
	}
	return out
}

func hook(h *nftables.ChainHook, text string) (*nftables.ChainHook, string) { return h, text }

// allowRules are the egress exceptions shared by inet output, the L2 chains and keep_tunnel panic.
func allowRules(f l3, cfg Config, sets map[string]*Set, withLAN bool) []Rule {
	var rs []Rule
	if cfg.WGMark != 0 {
		rs = append(rs, ruleMarkAccept(cfg.WGMark))
	}
	if cfg.VPN != nil && cfg.VPN.DNS && f.family == nftables.TableFamilyINet {
		rs = append(rs, ruleCgroupDNSAccept(*cfg.VPN, unix.IPPROTO_UDP), ruleCgroupDNSAccept(*cfg.VPN, unix.IPPROTO_TCP))
	}
	if cfg.TorUID != nil {
		rs = append(rs, ruleSkuidEndpointsAccept(f, *cfg.TorUID, sets["endpoints4"], false),
			ruleSkuidEndpointsAccept(f, *cfg.TorUID, sets["endpoints6"], true))
	}
	rs = append(rs,
		ruleEndpointsAccept(f, sets["endpoints4"], false, false),
		ruleEndpointsAccept(f, sets["endpoints6"], true, false),
		ruleDHCPAccept(f, false), ruleDHCPAccept(f, true))
	rs = append(rs, rulesICMPv6Link(f)...)
	if withLAN {
		rs = append(rs, ruleDaddrSetAccept(f, sets["lan4"], false), ruleDaddrSetAccept(f, sets["lan6"], true))
	}
	return rs
}

const (
	prioStrict = -10  // filter - 10
	prioPanic  = -20  // filter - 20
	prioL2     = -500 // netdev egress
	prioBridge = -210 // bridge filter (-200) - 10
)

// Strict builds the strict-mode tables (§11.3, §11.5, bridge note).
func Strict(cfg Config) (Ruleset, error) {
	withLAN := len(cfg.LAN) > 0
	sets, err := newSets(cfg, true, withLAN)
	if err != nil {
		return Ruleset{}, err
	}
	f := l3{nftables.TableFamilyINet}
	out := []Rule{ruleIfAccept("oifname", "lo"), ruleIfSetAccept("oifname", sets["tunnel_ifaces"]), ruleIfSetAccept("oifname", sets["internal_ifaces"])}
	out = append(out, allowRules(f, cfg, sets, withLAN)...)
	out = append(out, ruleLimitLog("LETHE-BLOCK "), ruleDrop())
	fwd := []Rule{ruleIfSetAccept("oifname", sets["tunnel_ifaces"]), ruleIfSetAccept("oifname", sets["internal_ifaces"]),
		ruleLimitLog("LETHE-FWD "), ruleDrop()}
	h, ht := hook(nftables.ChainHookOutput, "output")
	hf, hft := hook(nftables.ChainHookForward, "forward")
	inet := &Table{Family: nftables.TableFamilyINet, Name: TableStrict,
		Sets: ordered(sets, "tunnel_ifaces", "internal_ifaces", "endpoints4", "endpoints6", "lan4", "lan6"),
		Chains: []*Chain{
			{Name: "output", Hook: h, HookText: ht, Priority: prioStrict, Policy: nftables.ChainPolicyDrop, Rules: out},
			{Name: "forward", Hook: hf, HookText: hft, Priority: prioStrict, Policy: nftables.ChainPolicyAccept, Rules: fwd},
		}}
	rs := Ruleset{Tables: []*Table{inet}}
	if cfg.L2 {
		t, err := l2Table(cfg, false)
		if err != nil {
			return Ruleset{}, err
		}
		rs.Tables = append(rs.Tables, t)
	}
	if bt := bridgeTable(cfg); bt != nil {
		rs.Tables = append(rs.Tables, bt)
	}
	return rs, nil
}

// l2Table is netdev lethe_l2: one egress chain per hardware egress interface. Non-IP frames
// other than ARP/EAPOL are dropped (§11.5); IP frames get the same allowlist as inet output,
// because AF_PACKET senders never traversed it (ADR 0005). In panic: policy drop, no rules,
// unless keep_tunnel.
func l2Table(cfg Config, panic bool) (*Table, error) {
	if len(cfg.Egress) == 0 {
		return nil, ErrNoEgress
	}
	withLAN := len(cfg.LAN) > 0 && !panic
	sets, err := newSets(cfg, false, withLAN)
	if err != nil {
		return nil, err
	}
	f := l3{nftables.TableFamilyNetdev}
	var rules []Rule
	policy := nftables.ChainPolicyAccept
	switch {
	case panic && !cfg.KeepTunnel:
		policy = nftables.ChainPolicyDrop
	default:
		rules = append(rules, ruleEtherAccept(unix.ETH_P_ARP, "arp"))
		if !panic {
			rules = append(rules, ruleEtherAccept(0x888e, "0x888e"))
		}
		rules = append(rules, allowRules(f, cfg, sets, withLAN)...)
		rules = append(rules, ruleLimitLog("LETHE-L2 "), ruleDrop())
	}
	t := &Table{Family: nftables.TableFamilyNetdev, Name: TableL2, Sets: ordered(sets, "endpoints4", "endpoints6", "lan4", "lan6")}
	if policy == nftables.ChainPolicyDrop {
		t.Sets = nil
	}
	for _, dev := range sorted(cfg.Egress) {
		h, ht := hook(nftables.ChainHookEgress, "egress")
		t.Chains = append(t.Chains, &Chain{Name: "egress_" + dev, Hook: h, HookText: ht, Priority: prioL2, Policy: policy, Device: dev, Rules: rules})
	}
	return t, nil
}

// bridgeTable drops IP frames bridged towards egress ports, except ARP and DHCP.
func bridgeTable(cfg Config) *Table {
	var ports []string
	for _, ps := range cfg.Bridges {
		ports = append(ports, ps...)
	}
	if len(ports) == 0 {
		return nil
	}
	s := &Set{Name: "egress_ports", TypeText: "ifname", Key: nftables.TypeIFName}
	for _, p := range sorted(ports) {
		s.Elems = append(s.Elems, Elem{Text: fmt.Sprintf("%q", p), Key: IfName(p)})
	}
	f := l3{nftables.TableFamilyBridge}
	rules := []Rule{
		ruleEtherAccept(unix.ETH_P_ARP, "arp"),
		prefixOifSet(s, ruleDHCPAccept(f, false)),
		prefixOifSet(s, ruleDHCPAccept(f, true)),
		prefixOifSet(s, ruleLimitLog("LETHE-BR ")),
	}
	for _, v6 := range []bool{false, true} {
		rules = append(rules, prefixOifSet(s, Rule{Text: fmt.Sprintf("meta protocol %s drop", ipWord(v6)),
			Exprs: append(f.is(v6), verdict(expr.VerdictDrop))}))
	}
	h, ht := hook(nftables.ChainHookForward, "forward")
	return &Table{Family: nftables.TableFamilyBridge, Name: TableBridge, Sets: []*Set{s},
		Chains: []*Chain{{Name: "forward", Hook: h, HookText: ht, Priority: prioBridge, Policy: nftables.ChainPolicyAccept, Rules: rules}}}
}

// Panic builds block_all (§11.4): inet lethe_panic plus netdev lethe_l2 at policy drop (when
// the kernel has the egress hook). keep_tunnel keeps the tunnel and its transport only.
func Panic(cfg Config) (Ruleset, error) {
	f := l3{nftables.TableFamilyINet}
	ho, hot := hook(nftables.ChainHookOutput, "output")
	hf, hft := hook(nftables.ChainHookForward, "forward")
	hi, hit := hook(nftables.ChainHookInput, "input")
	out := []Rule{ruleIfAccept("oifname", "lo")}
	in := []Rule{ruleIfAccept("iifname", "lo")}
	t := &Table{Family: nftables.TableFamilyINet, Name: TablePanic}
	if cfg.KeepTunnel {
		sets, err := newSets(cfg, false, false)
		if err != nil {
			return Ruleset{}, err
		}
		t.Sets = ordered(sets, "tunnel_ifaces", "endpoints4", "endpoints6")
		out = append(out, ruleIfSetAccept("oifname", sets["tunnel_ifaces"]))
		out = append(out, allowRules(f, Config{WGMark: cfg.WGMark, VPN: cfg.VPN, TorUID: cfg.TorUID}, sets, false)...)
		in = append(in, ruleIfSetAccept("iifname", sets["tunnel_ifaces"]),
			ruleEndpointsAccept(f, sets["endpoints4"], false, true), ruleEndpointsAccept(f, sets["endpoints6"], true, true))
	}
	t.Chains = []*Chain{
		{Name: "output", Hook: ho, HookText: hot, Priority: prioPanic, Policy: nftables.ChainPolicyDrop, Rules: out},
		{Name: "forward", Hook: hf, HookText: hft, Priority: prioPanic, Policy: nftables.ChainPolicyDrop},
		{Name: "input", Hook: hi, HookText: hit, Priority: prioPanic, Policy: nftables.ChainPolicyDrop, Rules: in},
	}
	rs := Ruleset{Tables: []*Table{t}}
	if cfg.L2 {
		l2, err := l2Table(cfg, true)
		if err != nil {
			return Ruleset{}, err
		}
		rs.Tables = append(rs.Tables, l2)
	}
	return rs, nil
}
