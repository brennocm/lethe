package daemon

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/google/nftables"

	"lethe/internal/baseline"
	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/engine"
	"lethe/internal/guard"
	"lethe/internal/ipc"
	"lethe/internal/journal"
	"lethe/internal/platform"
	"lethe/internal/preflight"
	"lethe/internal/profile"
)

// fakeKernel: wg0 (tunnel) carries the default route; eth0 is the egress device.
type fakeKernel struct {
	mu      sync.Mutex
	probeV4 int // link index the probe route uses
}

func (k *fakeKernel) Links() ([]discovery.KernelLink, error) {
	return []discovery.KernelLink{
		{LinkInfo: discovery.LinkInfo{Index: 1, Name: "lo", Type: "device"}, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{LinkInfo: discovery.LinkInfo{Index: 2, Name: "eth0", Type: "device", HasDevice: true}, Up: true, Running: true, Addrs: []netip.Prefix{netip.MustParsePrefix("203.0.113.10/24")}},
		{LinkInfo: discovery.LinkInfo{Index: 3, Name: "wg0", Type: "wireguard"}, Up: true, Running: true, Addrs: []netip.Prefix{netip.MustParsePrefix("10.66.0.2/32")}},
	}, nil
}

func (k *fakeKernel) DefaultRoutes(family int) ([]discovery.RawRoute, error) {
	if family == 10 {
		return nil, nil
	}
	return []discovery.RawRoute{{LinkIndex: 3, Table: 254}}, nil
}

func (k *fakeKernel) RouteGet(dst netip.Addr) (discovery.RawRoute, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if dst.Is6() {
		return discovery.RawRoute{}, errors.New("unreachable")
	}
	return discovery.RawRoute{LinkIndex: k.probeV4, Table: 254}, nil
}

func (k *fakeKernel) setProbe(idx int) { k.mu.Lock(); k.probeV4 = idx; k.mu.Unlock() }

func (k *fakeKernel) WireGuard() ([]discovery.WGDevice, error) {
	return []discovery.WGDevice{{Name: "wg0", Peers: []discovery.WGPeerRaw{{Endpoint: netip.MustParseAddrPort("198.51.100.7:51820")}}}}, nil
}
func (k *fakeKernel) IPv6Disabled(string) bool { return true }
func (k *fakeKernel) LegacyIPTables() bool     { return false }

// fakeNFT records the tables present after each flush.
type fakeNFT struct {
	mu      sync.Mutex
	tables  map[string]*nftables.Table
	pending []func()
}

func key(t *nftables.Table) string { return guard.FamilyName(t.Family) + " " + t.Name }

func (f *fakeNFT) AddTable(t *nftables.Table) *nftables.Table {
	f.pending = append(f.pending, func() { f.tables[key(t)] = t })
	return t
}
func (f *fakeNFT) DelTable(t *nftables.Table) {
	f.pending = append(f.pending, func() { delete(f.tables, key(t)) })
}
func (f *fakeNFT) AddSet(*nftables.Set, []nftables.SetElement) error         { return nil }
func (f *fakeNFT) FlushSet(*nftables.Set)                                    {}
func (f *fakeNFT) SetAddElements(*nftables.Set, []nftables.SetElement) error { return nil }
func (f *fakeNFT) AddChain(c *nftables.Chain) *nftables.Chain                { return c }
func (f *fakeNFT) AddRule(r *nftables.Rule) *nftables.Rule                   { return r }
func (f *fakeNFT) ListTables() ([]*nftables.Table, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*nftables.Table
	for _, t := range f.tables {
		out = append(out, t)
	}
	return out, nil
}
func (f *fakeNFT) Flush() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.pending {
		p()
	}
	f.pending = nil
	return nil
}
func (f *fakeNFT) has(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.tables[name]
	return ok
}

type fixture struct {
	d       *Daemon
	k       *fakeKernel
	nft     *fakeNFT
	clock   *engine.FakeClock
	home    string
	pass    []byte
	base    []byte
	prof    []byte
	ident   *age.X25519Identity
	out     *syncBuf
	sockDir string
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	home := t.TempDir()
	clk := &engine.FakeClock{T: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	b, err := baseline.New(clk.T, "test")
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("correct horse battery")
	ct, err := baseline.Encrypt(b, pass, 10)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := b.Identity()
	f := &fixture{k: &fakeKernel{probeV4: 3}, nft: &fakeNFT{tables: map[string]*nftables.Table{}}, clock: clk, home: home,
		pass: pass, base: ct, prof: profile.Template, ident: id, out: &syncBuf{}}
	f.sockDir = filepath.Join(home, "run")
	var mono int64
	f.d = New(Config{
		Operator:   platform.Operator{UID: os.Getuid(), GID: os.Getgid(), Home: home},
		SocketPath: filepath.Join(f.sockDir, "lethe.sock"),
		Now:        func() time.Time { return clk.Now() },
		Mono:       func() int64 { mono++; return mono },
		Kernel:     f.k,
		NFT:        func() (guard.Conn, error) { return f.nft, nil },
		ProcRoot:   t.TempDir(),
		Out:        f.out,
	})
	return f
}

func allYes() []preflight.Answer {
	var a []preflight.Answer
	for _, it := range preflight.Manual {
		a = append(a, preflight.Answer{ID: it.ID, OK: true})
	}
	return a
}

func (f *fixture) armReq(mode string) ArmRequest {
	return ArmRequest{Profile: f.prof, Baseline: f.base, Passphrase: append([]byte(nil), f.pass...), Guard: mode, Manual: allYes()}
}

func (f *fixture) arm(t *testing.T, mode string) ArmResult {
	t.Helper()
	res, _, err := f.d.Arm(f.armReq(mode))
	if err != nil {
		t.Fatalf("arm: %v", err)
	}
	return res
}

func (f *fixture) events(t *testing.T, dir string) []contracts.Event {
	t.Helper()
	s, err := journal.Read(dir, []age.Identity{f.ident})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Verify(s, ""); err != nil {
		t.Fatalf("verify: %v", err)
	}
	return s.Events
}

func types(evs []contracts.Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, string(e.Type))
	}
	return out
}

func leak() checks.Finding {
	return checks.Finding{Check: "NET-001", Severity: contracts.SeverityCritical,
		Data: map[string]any{"iface": "eth0", "proto": "udp", "dst": "192.0.2.9", "dport": 53, "len": 60}}
}

func TestM7_ArmObserveDisarm(t *testing.T) {
	f := newFixture(t)
	res := f.arm(t, "off")
	if st, c := f.d.State(); st != engine.StateArmed || c != engine.ColorGreen {
		t.Fatalf("state %s %s", st, c)
	}
	f.d.deliver(f.d.sess, leak())
	f.d.deliver(f.d.sess, leak()) // deduplicated
	st := f.d.Status()
	if st.Color != "RED" || len(st.Alerts) != 1 || st.Alerts[0].Count != 2 || st.Alerts[0].ID != "A-0001" {
		t.Fatalf("status %+v", st)
	}
	if err := contracts.Validate("status", st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), "[CRITICAL] A-0001 NET-001") {
		t.Fatalf("terminal: %q", f.out.String())
	}
	dr, err := f.d.Disarm()
	if err != nil || dr.Critical != 1 {
		t.Fatalf("disarm %+v %v", dr, err)
	}
	evs := f.events(t, res.Dir)
	got := strings.Join(types(evs), ",")
	for _, want := range []string{"session.start", "preflight.manual_item", "preflight.result", "check.alert", "response.executed", "session.end"} {
		if !strings.Contains(got, want) {
			t.Fatalf("journal lacks %s: %s", want, got)
		}
	}
	if n := strings.Count(got, "check.alert"); n != 1 {
		t.Fatalf("%d check.alert in journal, want 1 (dedup)", n)
	}
	if st, _ := f.d.State(); st != engine.StateReady {
		t.Fatalf("after disarm: %s", st)
	}
}

func TestM7_WrongPassphraseLocksArm(t *testing.T) {
	f := newFixture(t)
	for i := range armFailLimit {
		req := f.armReq("off")
		req.Passphrase = []byte("wrong")
		_, _, err := f.d.Arm(req)
		var ie *ipc.Error
		if !errors.As(err, &ie) || ie.Code != ipc.CodeAuth {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if _, _, err := f.d.Arm(f.armReq("off")); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("arm must be locked out after %d failures: %v", armFailLimit, err)
	}
	f.clock.Advance(armFailWindow)
	f.arm(t, "off")
}

func TestM7_PreflightFailBlocksArmUnlessForced(t *testing.T) {
	f := newFixture(t)
	f.k.setProbe(2) // the probe route leaves via eth0: NET-004 CRITICAL
	_, rep, err := f.d.Arm(f.armReq("off"))
	if err == nil {
		t.Fatal("arm must fail")
	}
	if rep.Result != preflight.Fail || !strings.Contains(err.Error(), "preflight failed") {
		t.Fatalf("got %v %+v", err, rep)
	}
	req := f.armReq("off")
	req.Force = true
	if _, _, err := f.d.Arm(req); err == nil {
		t.Fatal("--force without --reason must be refused")
	}
	req = f.armReq("off")
	req.Force, req.Reason = true, "test"
	res, _, err := f.d.Arm(req)
	if err != nil {
		t.Fatal(err)
	}
	if st := f.d.Status(); st.Color != "RED" || st.Alerts[0].Check != "NET-004" {
		t.Fatalf("status %+v", st)
	}
	_, _ = f.d.Disarm()
	if got := strings.Join(types(f.events(t, res.Dir)), ","); !strings.Contains(got, "operator.force") {
		t.Fatalf("force not journaled: %s", got)
	}
}

func TestAC08_ReactivePanicAndUnpanic(t *testing.T) {
	f := newFixture(t)
	res := f.arm(t, "reactive")
	f.d.deliver(f.d.sess, leak())
	if st, _ := f.d.State(); st != engine.StatePanic {
		t.Fatalf("CRITICAL in reactive must panic, got %s", st)
	}
	if !f.nft.has("inet lethe_panic") {
		t.Fatal("panic table not applied")
	}
	if _, err := f.d.Disarm(); err == nil {
		t.Fatal("disarm from PANIC must be refused")
	}
	if _, err := f.d.Unpanic(); err == nil || !strings.Contains(err.Error(), "unacknowledged") {
		t.Fatalf("unpanic with an unacked CRITICAL: %v", err)
	}
	if err := f.d.Ack("A-0001", "test", func() error { return errors.New("no proof") }); err == nil {
		t.Fatal("CRITICAL ack without proof must fail")
	}
	if err := f.d.Ack("A-0001", "test", func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	f.k.setProbe(2)
	if _, err := f.d.Unpanic(); err == nil || !strings.Contains(err.Error(), "re-check") {
		t.Fatalf("unpanic with NET-004 failing: %v", err)
	}
	f.k.setProbe(3)
	if _, err := f.d.Unpanic(); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.d.State(); st != engine.StateArmed || f.nft.has("inet lethe_panic") {
		t.Fatalf("after unpanic: %s, panic table %v", st, f.nft.has("inet lethe_panic"))
	}
	if _, err := f.d.Disarm(); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(types(f.events(t, res.Dir)), ",")
	for _, want := range []string{"panic.engaged", "alert.ack", "panic.released"} {
		if !strings.Contains(got, want) {
			t.Fatalf("journal lacks %s: %s", want, got)
		}
	}
}

func TestAC08_StrictUnpanicRestoresStrict(t *testing.T) {
	f := newFixture(t)
	f.arm(t, "strict")
	if !f.nft.has("inet lethe") {
		t.Fatal("strict table missing")
	}
	if err := f.d.Panic("manual"); err != nil {
		t.Fatal(err)
	}
	if !f.nft.has("inet lethe_panic") {
		t.Fatal("panic table missing")
	}
	if _, err := f.d.Unpanic(); err != nil { // manual panic: no CRITICAL to ack
		t.Fatal(err)
	}
	if !f.nft.has("inet lethe") || f.nft.has("inet lethe_panic") {
		t.Fatal("unpanic must leave strict and remove panic")
	}
	if _, err := f.d.Disarm(); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"inet lethe", "inet lethe_panic", "netdev lethe_l2"} {
		if f.nft.has(n) {
			t.Fatalf("%s left after disarm", n)
		}
	}
}

func TestSELF001_SensorHeartbeat(t *testing.T) {
	f := newFixture(t)
	f.arm(t, "off")
	s := f.d.sess
	f.d.beat(s, "capture:eth0")(time.Time{})
	f.d.Tick()
	if st := f.d.Status(); st.Color != "GREEN" {
		t.Fatalf("color %s", st.Color)
	}
	f.clock.Advance(4 * time.Second)
	f.d.Tick()
	if st := f.d.Status(); st.Color != "GRAY" || len(st.Degraded) != 1 {
		t.Fatalf("silent sensor must turn GRAY: %+v", st)
	}
	f.d.beat(s, "capture:eth0")(time.Time{})
	f.d.Tick()
	if st := f.d.Status(); st.Color != "GREEN" {
		t.Fatalf("recovered sensor: %+v", st)
	}
	_, _ = f.d.Disarm()
}

func TestM7_ConditionResolves(t *testing.T) {
	f := newFixture(t)
	f.k.setProbe(2)
	req := f.armReq("off")
	req.Force, req.Reason = true, "test"
	if _, _, err := f.d.Arm(req); err != nil {
		t.Fatal(err)
	}
	f.k.setProbe(3)
	f.d.mu.Lock()
	f.d.refreshLocked()
	f.d.mu.Unlock()
	f.clock.Advance(11 * time.Second)
	f.d.Tick()
	if st := f.d.Status(); st.Alerts[0].State != "resolved" || st.Color != "GREEN" {
		t.Fatalf("status %+v", st)
	}
	_, _ = f.d.Disarm()
}

func (f *fixture) serve(t *testing.T) *ipc.Client {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.d.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	path := filepath.Join(f.sockDir, "lethe.sock")
	for range 200 {
		if c, err := ipc.Dial(path, time.Second); err == nil {
			t.Cleanup(func() { _ = c.Close() })
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("daemon socket did not come up")
	return nil
}

func TestM7_IPCSensitiveNeedsProof(t *testing.T) {
	f := newFixture(t)
	c := f.serve(t)
	var res ArmResult
	if err := c.Call("session.arm", f.armReq("off"), nil, &res); err != nil {
		t.Fatalf("arm over IPC: %v", err)
	}
	var st Status
	if err := c.Call("status.get", nil, nil, &st); err != nil || st.State != "ARMED" || len(st.AuthSalt) != saltSize {
		t.Fatalf("status %+v %v", st, err)
	}
	var ie *ipc.Error
	if err := c.Call("session.disarm", nil, nil, nil); !errors.As(err, &ie) || ie.Code != ipc.CodeAuth {
		t.Fatalf("disarm without proof: %v", err)
	}
	key, err := ipc.DeriveKey(f.pass, st.AuthSalt)
	if err != nil {
		t.Fatal(err)
	}
	f.d.deliver(f.d.sess, leak())
	ack := map[string]string{"id": "A-0001", "reason": "test"}
	if err := c.Call("alert.ack", ack, nil, nil); !errors.As(err, &ie) || ie.Code != ipc.CodeAuth {
		t.Fatalf("CRITICAL ack without proof: %v", err)
	}
	proof, err := c.Prove(key, "alert.ack", ack)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Call("alert.ack", ack, proof, nil); err != nil {
		t.Fatalf("CRITICAL ack with proof: %v", err)
	}
	proof, _ = c.Prove(key, "session.disarm", nil)
	var dr DisarmResult
	if err := c.Call("session.disarm", nil, proof, &dr); err != nil || dr.Session != res.Session {
		t.Fatalf("disarm with proof: %+v %v", dr, err)
	}
	got := strings.Join(types(f.events(t, res.Dir)), ",")
	if strings.Count(got, "ipc.denied") < 2 {
		t.Fatalf("denials not journaled: %s", got)
	}
}

func TestM7_FiveBadProofsPanic(t *testing.T) {
	f := newFixture(t)
	c := f.serve(t)
	if err := c.Call("session.arm", f.armReq("reactive"), nil, nil); err != nil {
		t.Fatal(err)
	}
	bad := []byte("0123456789abcdef0123456789abcdef")
	for range 5 {
		proof, err := c.Prove(bad, "panic.release", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Call("panic.release", nil, proof, nil)
	}
	for range 200 {
		if st, _ := f.d.State(); st == engine.StatePanic {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("5 failed proofs must engage panic")
}
