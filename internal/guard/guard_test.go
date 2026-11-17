package guard

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

var update = flag.Bool("update", false, "rewrite golden files")

func fullConfig() Config {
	tor := uint32(108)
	return Config{
		Tunnels:  []string{"wg0", "tun0"},
		Internal: []string{"virbr0", "docker0"},
		Egress:   []string{"wlp2s0", "enp0s31f6"},
		Endpoints: []Endpoint{
			{Addr: netip.MustParseAddrPort("198.51.100.7:51820"), Proto: unix.IPPROTO_UDP},
			{Addr: netip.MustParseAddrPort("[2001:db8::7]:51820"), Proto: unix.IPPROTO_UDP},
			{Addr: netip.MustParseAddrPort("203.0.113.9:443"), Proto: unix.IPPROTO_TCP},
		},
		LAN:     []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fd00:1::/64")},
		WGMark:  0xca6c,
		VPN:     &Cgroup{Path: "system.slice/openvpn-client@work.service", Level: 2, ID: 4242, DNS: true},
		TorUID:  &tor,
		Bridges: map[string][]string{"br0": {"enp0s31f6"}},
		L2:      true,
	}
}

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if string(want) != got {
		t.Fatalf("%s differs from golden:\n%s", name, got)
	}
}

func TestGuard_StrictGolden(t *testing.T) {
	rs, err := Strict(fullConfig())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "strict.nft.golden", rs.Render())
	min, err := Strict(Config{Tunnels: []string{"wg0"}, Endpoints: []Endpoint{{Addr: netip.MustParseAddrPort("198.51.100.7:51820"), Proto: unix.IPPROTO_UDP}}})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "strict-minimal.nft.golden", min.Render())
}

func TestGuard_PanicGolden(t *testing.T) {
	rs, err := Panic(fullConfig())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "panic.nft.golden", rs.Render())
	cfg := fullConfig()
	cfg.KeepTunnel = true
	rs, err = Panic(cfg)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "panic-keep-tunnel.nft.golden", rs.Render())
}

func TestGuard_GeneratorRejects(t *testing.T) {
	if _, err := Strict(Config{L2: true}); !errors.Is(err, ErrNoEgress) {
		t.Fatalf("L2 without egress: %v", err)
	}
	if _, err := Strict(Config{Endpoints: []Endpoint{{Addr: netip.MustParseAddrPort("192.0.2.1:1"), Proto: 1}}}); err == nil {
		t.Fatal("icmp endpoint accepted")
	}
	if _, err := Strict(Config{LAN: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}); err == nil {
		t.Fatal("/0 LAN accepted")
	}
	if _, err := Strict(Config{LAN: []netip.Prefix{netip.MustParsePrefix("255.255.255.0/24")}}); err == nil {
		t.Fatal("prefix at the top of the space accepted")
	}
}

func TestGuard_SetEncoding(t *testing.T) {
	rs, err := Strict(fullConfig())
	if err != nil {
		t.Fatal(err)
	}
	inet := rs.Find(nftables.TableFamilyINet, TableStrict)
	e4 := inet.Set("endpoints4")
	var udp []byte
	for _, e := range e4.Elems {
		if strings.HasPrefix(e.Text, "198.51.100.7") {
			udp = e.Key
		}
	}
	want := []byte{198, 51, 100, 7, unix.IPPROTO_UDP, 0, 0, 0, 0xca, 0x6c, 0, 0}
	if string(udp) != string(want) {
		t.Fatalf("endpoint key % x, want % x", udp, want)
	}
	if e4.Key.Bytes != 12 {
		t.Fatalf("concat key length %d", e4.Key.Bytes)
	}
	lan := inet.Set("lan4").Elems[0]
	if string(lan.Key) != string([]byte{192, 168, 1, 0}) || string(lan.End) != string([]byte{192, 168, 2, 0}) {
		t.Fatalf("interval % x .. % x", lan.Key, lan.End)
	}
	if n := IfName("wg0"); len(n) != unix.IFNAMSIZ || n[3] != 0 {
		t.Fatalf("ifname % x", n)
	}
	if rs.Find(nftables.TableFamilyIPv4, "x") != nil || inet.Set("nope") != nil {
		t.Fatal("find")
	}
}

// fakeConn records the transaction.
type fakeConn struct {
	ops      []string
	tables   []*nftables.Table
	flushes  int
	flushErr error
	rules    []*nftables.Rule
	sets     map[string]*nftables.Set
}

func (f *fakeConn) AddTable(t *nftables.Table) *nftables.Table {
	f.ops = append(f.ops, "add "+t.Name)
	return t
}
func (f *fakeConn) DelTable(t *nftables.Table) { f.ops = append(f.ops, "del "+t.Name) }
func (f *fakeConn) AddSet(s *nftables.Set, _ []nftables.SetElement) error {
	if f.sets == nil {
		f.sets = map[string]*nftables.Set{}
	}
	s.ID = uint32(len(f.sets) + 100)
	f.sets[s.Table.Name+"/"+s.Name] = s
	f.ops = append(f.ops, "set "+s.Name)
	return nil
}
func (f *fakeConn) FlushSet(s *nftables.Set) { f.ops = append(f.ops, "flushset "+s.Name) }
func (f *fakeConn) SetAddElements(s *nftables.Set, el []nftables.SetElement) error {
	f.ops = append(f.ops, "elems "+s.Name)
	return nil
}
func (f *fakeConn) AddChain(c *nftables.Chain) *nftables.Chain {
	f.ops = append(f.ops, "chain "+c.Name)
	return c
}
func (f *fakeConn) AddRule(r *nftables.Rule) *nftables.Rule { f.rules = append(f.rules, r); return r }
func (f *fakeConn) ListTables() ([]*nftables.Table, error)  { return f.tables, nil }
func (f *fakeConn) Flush() error                            { f.flushes++; return f.flushErr }

func TestGuard_ApplyIsOneTransaction(t *testing.T) {
	rs, err := Strict(fullConfig())
	if err != nil {
		t.Fatal(err)
	}
	c := &fakeConn{}
	if err := Apply(c, rs); err != nil {
		t.Fatal(err)
	}
	if c.flushes != 1 {
		t.Fatalf("flushes=%d", c.flushes)
	}
	if strings.Join(c.ops[:3], ",") != "add lethe,del lethe,add lethe" {
		t.Fatalf("ops %v", c.ops)
	}
	for _, r := range c.rules {
		for _, e := range r.Exprs {
			if l, ok := e.(*expr.Lookup); ok && l.SetID == 0 {
				t.Fatalf("lookup %s not bound to a set ID", l.SetName)
			}
		}
	}
	bad := Ruleset{Tables: []*Table{{Family: nftables.TableFamilyINet, Name: "killswitch"}}}
	if err := Apply(&fakeConn{}, bad); err == nil {
		t.Fatal("must refuse foreign tables")
	}
	undefined := Ruleset{Tables: []*Table{{Family: nftables.TableFamilyINet, Name: "lethe", Chains: []*Chain{{Name: "x", Rules: []Rule{{Exprs: []expr.Any{&expr.Lookup{SetName: "ghost"}}}}}}}}}
	if err := Apply(&fakeConn{}, undefined); err == nil {
		t.Fatal("undefined set accepted")
	}
	if err := Apply(&fakeConn{flushErr: errors.New("EPERM")}, rs); err == nil {
		t.Fatal("flush error swallowed")
	}
	c = &fakeConn{}
	if err := UpdateSets(c, rs); err != nil || c.flushes != 1 {
		t.Fatalf("update: %v flushes %d", err, c.flushes)
	}
}

func TestGuard_CleanupOnlyLetheTables(t *testing.T) {
	c := &fakeConn{tables: []*nftables.Table{
		{Family: nftables.TableFamilyINet, Name: "lethe"},
		{Family: nftables.TableFamilyINet, Name: "killswitch"},
		{Family: nftables.TableFamilyNetdev, Name: "lethe_l2"},
		{Family: nftables.TableFamilyIPv4, Name: "filter"},
		{Family: nftables.TableFamilyINet, Name: "lethe_selftest"},
	}}
	got, err := Cleanup(c)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range got {
		names = append(names, r.Name)
	}
	if strings.Join(names, ",") != "lethe,lethe_selftest,lethe_l2" || c.flushes != 1 {
		t.Fatalf("removed %v flushes %d", names, c.flushes)
	}
	for _, op := range c.ops {
		if strings.Contains(op, "killswitch") || strings.Contains(op, "filter") {
			t.Fatalf("touched a foreign table: %v", c.ops)
		}
	}
	empty := &fakeConn{tables: []*nftables.Table{{Family: nftables.TableFamilyIPv4, Name: "filter"}}}
	if got, err := Cleanup(empty); err != nil || got != nil || empty.flushes != 0 {
		t.Fatal("nothing to clean must be a no-op")
	}
	if err := Remove(&fakeConn{}, TableRef{nftables.TableFamilyINet, "killswitch"}); err == nil {
		t.Fatal("Remove must refuse foreign names")
	}
	if len(All()) != 4 {
		t.Fatal("All")
	}
}

func TestGuard_CgroupID(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "system.slice", "openvpn.service")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cg, err := CgroupID(root, dir)
	if err != nil {
		t.Fatal(err)
	}
	if cg.Level != 2 || cg.Path != "system.slice/openvpn.service" || cg.ID == 0 {
		t.Fatalf("%+v", cg)
	}
	// a restart recreates the directory: new ID (the rule must be regenerated, §11.2)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := CgroupID(root, "/elsewhere"); err == nil {
		t.Fatal("outside root accepted")
	}
	if _, err := CgroupID(root, filepath.Join(root, "missing")); err == nil {
		t.Fatal("missing accepted")
	}
}

func TestGuard_WatchCgroupSeesRestart(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "system.slice", "openvpn.service")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	cg, err := CgroupID(root, dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan bool, 8)
	ids := make(chan uint64, 8)
	go WatchCgroup(ctx, root, dir, 5*time.Millisecond, cg, func(c Cgroup, ok bool) { events <- ok; ids <- c.ID })
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if ok := <-events; ok {
		t.Fatal("removal must be reported as gone")
	}
	<-ids
	// hold a file in the parent so the recreated dir cannot reuse the old inode number
	if err := os.WriteFile(filepath.Join(root, "system.slice", "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if ok := <-events; !ok {
		t.Fatal("recreation must be reported")
	}
	if id := <-ids; id == 0 {
		t.Fatal("new id")
	}
}

type probeConn struct {
	fakeConn
	results []error
}

func (p *probeConn) Flush() error {
	err := p.results[0]
	p.results = p.results[1:]
	return err
}

func TestGuard_Probe(t *testing.T) {
	f, err := Probe(&probeConn{results: []error{errors.New("netlink receive: no such file or directory"), nil, errors.New("operation not supported")}})
	if err != nil || f.SocketCgroup || !f.L2 || f.Bridge {
		t.Fatalf("%+v %v", f, err)
	}
	if _, err := Probe(&probeConn{results: []error{fmt.Errorf("wrapped: %w", syscall.EPERM)}}); err == nil {
		t.Fatal("permission errors must surface")
	}
	if _, err := Probe(&probeConn{results: []error{nil, fmt.Errorf("x: %w", syscall.EPERM)}}); err == nil {
		t.Fatal("permission errors must surface (L2)")
	}
	if _, err := Probe(&probeConn{results: []error{nil, nil, fmt.Errorf("x: %w", syscall.EPERM)}}); err == nil {
		t.Fatal("permission errors must surface (bridge)")
	}
}

// ST-NET-001 in strict: the exception is first, carries skuid 0 in inet (not at netdev), and
// only documentation destinations are accepted.
func TestAC11_SelftestException(t *testing.T) {
	c := fullConfig()
	c.Exceptions = []Exception{{Proto: unix.IPPROTO_UDP, Sport: 40001, Dst: netip.MustParseAddrPort("192.0.2.1:9")}}
	rs, err := Strict(c)
	if err != nil {
		t.Fatal(err)
	}
	out := rs.Find(nftables.TableFamilyINet, TableStrict).Chains[0].Rules[0].Text
	if out != "meta skuid 0 ip daddr 192.0.2.1 meta l4proto udp th sport 40001 th dport 9 accept # selftest" {
		t.Fatal(out)
	}
	l2 := rs.Find(nftables.TableFamilyNetdev, TableL2).Chains[0].Rules[0].Text
	if l2 != "ip daddr 192.0.2.1 meta l4proto udp th sport 40001 th dport 9 accept # selftest" {
		t.Fatal(l2)
	}
	for _, bad := range []Exception{
		{Proto: unix.IPPROTO_UDP, Sport: 1, Dst: netip.MustParseAddrPort("8.8.8.8:53")},
		{Proto: unix.IPPROTO_ICMP, Sport: 1, Dst: netip.MustParseAddrPort("192.0.2.1:9")},
		{Proto: unix.IPPROTO_UDP, Dst: netip.MustParseAddrPort("192.0.2.1:9")},
	} {
		c.Exceptions = []Exception{bad}
		if _, err := Strict(c); err == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	p, _ := Panic(fullConfig())
	if strings.Contains(p.Render(), "selftest") {
		t.Fatal("panic never carries exceptions")
	}
}
