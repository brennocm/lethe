package checks

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"lethe/internal/i18n"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/sensors/capture"
	"lethe/internal/sensors/nflog"
	"lethe/internal/sensors/sockdiag"
)

func snap() *discovery.Snapshot {
	return &discovery.Snapshot{
		Ifaces: []discovery.Iface{
			{LinkInfo: discovery.LinkInfo{Name: "lo"}, Class: discovery.ClassLoopback},
			{LinkInfo: discovery.LinkInfo{Name: "eth0"}, Class: discovery.ClassEgress},
			{LinkInfo: discovery.LinkInfo{Name: "wg0"}, Class: discovery.ClassTunnel},
			{LinkInfo: discovery.LinkInfo{Name: "virbr0"}, Class: discovery.ClassInternal, GlobalV6: []string{"2001:db8:5::1"}},
		},
		Tunnels: []discovery.Tunnel{{Iface: "wg0", Kind: "wireguard", FwMark: 51820}},
		Routes: discovery.Routes{
			DefaultV4: []discovery.Route{{Dst: "default", Iface: "wg0", Class: discovery.ClassTunnel, Table: 51820}},
			ProbeV4:   &discovery.Route{Dst: "192.0.2.1", Iface: "wg0", Class: discovery.ClassTunnel},
		},
	}
}

func onlyFinding(t *testing.T, fs []Finding, check string, sev contracts.Severity) Finding {
	t.Helper()
	if len(fs) != 1 || fs[0].Check != check || fs[0].Severity != sev {
		t.Fatalf("findings=%+v", fs)
	}
	return fs[0]
}

func TestRegistryUniqueAndConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Registry() {
		if seen[c.ID()] {
			t.Fatalf("duplicate %s", c.ID())
		}
		seen[c.ID()] = true
		if !c.DefaultSeverity().Valid() || c.Kind() == 0 || len(c.Sources()) == 0 {
			t.Fatalf("%s: incomplete metadata", c.ID())
		}
		_ = c.SelfTestCases()
	}
	if c, ok := ByID("NET-001"); !ok || c.DefaultSeverity() != contracts.SeverityCritical {
		t.Fatal("NET-001 not registered as CRITICAL")
	}
	if _, ok := ByID("NET-999"); ok {
		t.Fatal("unknown id found")
	}
}

func TestNET001_FromFrame(t *testing.T) {
	leak := capture.Leak{Check: "DNS-001", Severity: contracts.SeverityCritical, Proto: "udp", QName: "secret.example.test"}
	f := FromFrame(capture.Frame{Iface: "eth0", At: time.Unix(0, 0), Leak: leak}, contracts.Proc{PID: 7, Exe: "/usr/bin/dig", Confidence: contracts.ConfidenceHigh})
	if f.Check != "DNS-001" || f.Data["iface"] != "eth0" || f.Sensitive["qname"] != "secret.example.test" {
		t.Fatalf("%+v", f)
	}
	for k, v := range f.Data {
		if v == "secret.example.test" {
			t.Fatalf("qname in data[%s]", k)
		}
	}
	ev := f.Alert()
	if ev.Type != contracts.EvCheckAlert || ev.ProcExe() != "/usr/bin/dig" || ev.Source != contracts.SourceDaemon {
		t.Fatalf("%+v", ev)
	}
	if r := Resolved("NET-003", nil); r.Type != contracts.EvCheckResolved {
		t.Fatal(r)
	}
	plain := FromFrame(capture.Frame{Iface: "eth0", Leak: capture.Leak{Check: "NET-001", Severity: contracts.SeverityCritical}}, contracts.Proc{})
	if _, ok := plain.Data["proc"]; ok || plain.Sensitive != nil {
		t.Fatalf("%+v", plain)
	}
}

func TestNET003_Evaluate(t *testing.T) {
	s := snap()
	if fs := (NET003{}).Evaluate(s, false); len(fs) != 0 {
		t.Fatalf("clean snapshot: %+v", fs)
	}
	s.Routes.DefaultV6 = []discovery.Route{{Dst: "default", Iface: "eth0", Class: discovery.ClassEgress}}
	f := onlyFinding(t, (NET003{}).Evaluate(s, false), "NET-003", contracts.SeverityCritical)
	if f.Data["iface"] != "eth0" || f.Data["reason"] != "default_route_ipv6_not_expected" {
		t.Fatalf("%+v", f)
	}
	f = onlyFinding(t, (NET003{}).Evaluate(s, true), "NET-003", contracts.SeverityCritical)
	if f.Data["reason"] != "default_route_tunnel_without_ipv6" {
		t.Fatalf("%+v", f)
	}
	s.Routes.DefaultV6 = append(s.Routes.DefaultV6, discovery.Route{Dst: "default", Iface: "wg0", Class: discovery.ClassTunnel})
	if fs := (NET003{}).Evaluate(s, true); len(fs) != 0 {
		t.Fatalf("tunnel carries v6 and v6 is expected: %+v", fs)
	}
	s.Routes.DefaultV6 = nil
	s.Ifaces[1].GlobalV6 = []string{"2001:db8:1::2"}
	f = onlyFinding(t, (NET003{}).Evaluate(s, false), "NET-003", contracts.SeverityWarning)
	if f.Data["reason"] != "global_address_without_route" {
		t.Fatalf("%+v", f)
	}
	s.Ifaces[1].IPv6Disabled = true
	if fs := (NET003{}).Evaluate(s, false); len(fs) != 0 {
		t.Fatalf("v6 disabled: %+v", fs)
	}
}

func TestNET004_Evaluate(t *testing.T) {
	s := snap()
	if fs := (NET004{}).Evaluate(s); len(fs) != 0 {
		t.Fatalf("%+v", fs)
	}
	s.Routes.ProbeV4 = &discovery.Route{Dst: "192.0.2.1", Iface: "eth0", Class: discovery.ClassEgress}
	s.Routes.ProbeV6 = &discovery.Route{Dst: "2001:db8::1", Iface: "eth1", Class: discovery.ClassUnknown}
	fs := (NET004{}).Evaluate(s)
	if len(fs) != 2 || fs[0].Data["family"] != "ipv4" || fs[1].Data["class"] != "unknown" || fs[1].Severity != contracts.SeverityCritical {
		t.Fatalf("%+v", fs)
	}
}

func TestNET005_Evaluate(t *testing.T) {
	s := snap()
	ignored := []RouteChange{
		{Kind: "route", Op: "new", Table: 51820, Iface: "eth0", Dst: "default"},
		{Kind: "route", Op: "new", Table: 254, Iface: "wg0", Dst: "10.200.0.0/24"},
		{Kind: "route", Op: "new", Table: 255, Iface: "eth0", Dst: "10.0.0.2"},
		{Kind: "rule", Op: "new", Table: 254, Mark: 51820},
		{Kind: "rule", Op: "del", Table: 51820},
	}
	for _, c := range ignored {
		if fs := (NET005{}).Evaluate(c, s); len(fs) != 0 {
			t.Fatalf("%+v → %+v", c, fs)
		}
	}
	f := onlyFinding(t, (NET005{}).Evaluate(RouteChange{Kind: "route", Op: "new", Family: "ipv4", Table: 254, Iface: "eth0", Dst: "default"}, s), "NET-005", contracts.SeverityWarning)
	if f.Data["iface"] != "eth0" || f.Data["dst"] != "default" || f.Data["op"] != "new" {
		t.Fatalf("%+v", f)
	}
	f = onlyFinding(t, (NET005{}).Evaluate(RouteChange{Kind: "rule", Op: "new", Family: "ipv4", Table: 100}, s), "NET-005", contracts.SeverityWarning)
	if _, ok := f.Data["iface"]; ok {
		t.Fatalf("rule has no iface: %+v", f)
	}
}

func TestNET006_Evaluate(t *testing.T) {
	cases := []struct {
		c    LinkChange
		sev  contracts.Severity
		none bool
	}{
		{LinkChange{Name: "usb0", New: true, Class: discovery.ClassEgress}, contracts.SeverityWarning, false},
		{LinkChange{Name: "x0", New: true, Class: discovery.ClassUnknown}, contracts.SeverityWarning, false},
		{LinkChange{Name: "eth0", Up: true, WasUp: false, Class: discovery.ClassEgress}, contracts.SeverityWarning, false},
		{LinkChange{Name: "veth1", New: true, Class: discovery.ClassInternal}, contracts.SeverityInfo, false},
		{LinkChange{Name: "wg0", Up: true, Class: discovery.ClassTunnel}, contracts.SeverityInfo, false},
		{LinkChange{Name: "eth0", Up: true, WasUp: true, Class: discovery.ClassEgress}, "", true},
		{LinkChange{Name: "eth0", Up: false, WasUp: true, Class: discovery.ClassEgress}, "", true},
		{LinkChange{Name: "lo", New: true, Class: discovery.ClassLoopback}, "", true},
	}
	for _, c := range cases {
		fs := (NET006{}).Evaluate(c.c)
		if c.none {
			if len(fs) != 0 {
				t.Fatalf("%+v → %+v", c.c, fs)
			}
			continue
		}
		onlyFinding(t, fs, "NET-006", c.sev)
	}
}

func TestNET010_SocketScan(t *testing.T) {
	ap := netip.MustParseAddrPort
	sc := SocketScan{
		Socks: []sockdiag.Sock{
			{Proto: "tcp", Local: ap("10.0.0.2:40000"), Remote: ap("198.51.100.1:443"), Inode: 1},   // leak, owner known
			{Proto: "udp", Local: ap("10.0.0.2:40001"), Remote: ap("198.18.0.2:51820"), Inode: 2},   // allowed endpoint
			{Proto: "tcp", Local: ap("10.200.0.2:40002"), Remote: ap("198.51.100.1:443"), Inode: 3}, // tunnel address
			{Proto: "udp", Local: ap("10.0.0.2:5353"), Remote: ap("0.0.0.0:0"), Inode: 4},           // unconnected
			{Proto: "tcp", Local: ap("10.0.0.2:40003"), Remote: ap("198.51.100.2:80"), Inode: 5, UID: 1001},
			{Proto: "tcp", Local: ap("10.0.0.2:40004"), Remote: ap("198.51.100.3:80"), Inode: 6}, // already seen
		},
		Owners:      map[uint32]sockdiag.Owner{1: {PID: 10, Exe: "/usr/bin/curl", UID: 1000}},
		EgressAddrs: map[netip.Addr]string{netip.MustParseAddr("10.0.0.2"): "eth0"},
		Allowed:     func(_ string, d netip.AddrPort) bool { return d == ap("198.18.0.2:51820") },
		Seen:        func(_ string, _, d netip.AddrPort) bool { return d == ap("198.51.100.3:80") },
	}
	fs := (NET010{}).Evaluate(sc)
	if len(fs) != 2 {
		t.Fatalf("%+v", fs)
	}
	if p := fs[0].Data["proc"].(contracts.Proc); p.PID != 10 || p.Confidence != contracts.ConfidenceHigh || fs[0].Data["dport"] != 443 {
		t.Fatalf("%+v", fs[0])
	}
	if p := fs[1].Data["proc"].(contracts.Proc); p.PID != 0 || p.UID != 1001 || p.Confidence != contracts.ConfidenceLow {
		t.Fatalf("%+v", fs[1])
	}
}

func TestDNS001_SealedAlert(t *testing.T) {
	f := Finding{Check: "DNS-001", Severity: contracts.SeverityCritical, Data: map[string]any{"iface": "eth0"},
		Sensitive: map[string]string{"qname": "q.example.test"}}
	ev, err := f.SealedAlert(func(s string) (map[string]any, error) { return map[string]any{"enc": "s1", "ct": "x" + s[:1]}, nil })
	if err != nil {
		t.Fatal(err)
	}
	if m, ok := ev.Data["qname"].(map[string]any); !ok || m["enc"] != "s1" {
		t.Fatalf("%+v", ev.Data)
	}
	if _, ok := f.Data["qname"]; ok {
		t.Fatal("SealedAlert mutated the finding")
	}
	ev, _ = f.SealedAlert(nil)
	if _, ok := ev.Data["qname"]; ok {
		t.Fatal("without a sealer the qname must be dropped")
	}
	if _, err := f.SealedAlert(func(string) (map[string]any, error) { return nil, errors.New("boom") }); err == nil {
		t.Fatal("seal error must propagate")
	}
	plain := Finding{Check: "NET-001", Severity: contracts.SeverityCritical, Data: map[string]any{"iface": "eth0"}}
	if ev, err := plain.SealedAlert(nil); err != nil || ev.Data["iface"] != "eth0" {
		t.Fatal(err)
	}
}

func TestNET002_FromBlocked(t *testing.T) {
	b := nflog.Blocked{Prefix: "LETHE-BLOCK ", UID: 1000, OutIface: "eth0",
		Leak: capture.Leak{Check: "DNS-001", Severity: contracts.SeverityCritical, Proto: "udp", QName: "b.example.test"}}
	f := FromBlocked(b, contracts.Proc{})
	if f.Check != "NET-002" || f.Severity != contracts.SeverityWarning || f.Data["uid"] != 1000 || f.Data["class"] != "DNS-001" || f.Sensitive["qname"] != "b.example.test" {
		t.Fatalf("%+v", f)
	}
	if _, ok := f.Data["proc"]; ok {
		t.Fatal("no proc without attribution")
	}
	b.Leak = capture.Leak{Check: "NET-001", Severity: contracts.SeverityCritical, Proto: "tcp"}
	f = FromBlocked(b, contracts.Proc{PID: 1, Confidence: contracts.ConfidenceHigh})
	if _, ok := f.Data["class"]; ok || f.Sensitive != nil || f.Data["proc"] == nil {
		t.Fatalf("%+v", f)
	}
}

func TestSELF006_Finding(t *testing.T) {
	f := SELF006{}.Finding(5, 300, 300)
	if f.Check != "SELF-006" || f.Severity != contracts.SeverityCritical || f.Data["locked_s"] != 300.0 {
		t.Fatalf("%+v", f)
	}
}

func TestM9_EveryCheckHasATitle(t *testing.T) {
	for _, c := range Registry() {
		if Title(c.ID(), "pt-BR") == c.ID() || Title(c.ID(), "en-US") == c.ID() {
			t.Fatalf("%s has no title", c.ID())
		}
	}
	if Title("XXX-000", "pt-BR") != "XXX-000" {
		t.Fatal("unknown id")
	}
	// The other way round too: a text for a check that does not exist would put it on the GUI
	// grid as "ok" while nothing watches it (fail-silent, principle 1).
	reg := map[string]bool{}
	for _, c := range Registry() {
		reg[c.ID()] = true
	}
	for _, id := range i18n.CheckIDs() {
		if !reg[id] {
			t.Errorf("internal/i18n has %s, which is not in the registry", id)
		}
	}
	for _, c := range Registry() {
		for _, l := range i18n.Langs {
			if tx := i18n.CheckText(l, c.ID()); tx.Meaning == "" || tx.Todo == "" {
				t.Fatalf("%s has no meaning or todo in %s (internal/i18n)", c.ID(), l)
			}
		}
	}
}
