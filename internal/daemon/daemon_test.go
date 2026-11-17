package daemon

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"lethe/internal/geo"

	"lethe/internal/sensors/capture"
	"lethe/internal/sensors/nflog"
	"lethe/internal/sensors/sockdiag"

	"filippo.io/age"
	"github.com/google/nftables"

	"lethe/internal/baseline"
	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/discovery/torctl"
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
	mu       sync.Mutex
	probeV4  int // link index the probe route uses
	endpoint string
	now      func() time.Time // the peer's last handshake (nil or stale = no handshake)
	stale    bool
	rx       uint64 // wg0 received bytes
	wgDown   bool
}

func (k *fakeKernel) Links() ([]discovery.KernelLink, error) {
	return []discovery.KernelLink{
		{LinkInfo: discovery.LinkInfo{Index: 1, Name: "lo", Type: "device"}, Up: true, Addrs: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/8")}},
		{LinkInfo: discovery.LinkInfo{Index: 2, Name: "eth0", Type: "device", HasDevice: true}, Up: true, Running: true, Addrs: []netip.Prefix{netip.MustParsePrefix("203.0.113.10/24")}},
		{LinkInfo: discovery.LinkInfo{Index: 3, Name: "wg0", Type: "wireguard"}, Up: !k.down(), Running: !k.down(), Addrs: []netip.Prefix{netip.MustParsePrefix("10.66.0.2/32")}, RxBytes: k.rxBytes()},
	}, nil
}

func (k *fakeKernel) rxBytes() uint64 { k.mu.Lock(); defer k.mu.Unlock(); return k.rx }
func (k *fakeKernel) down() bool      { k.mu.Lock(); defer k.mu.Unlock(); return k.wgDown }

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
	k.mu.Lock()
	defer k.mu.Unlock()
	var peer discovery.WGPeerRaw
	if k.endpoint != "none" {
		peer.Endpoint = netip.MustParseAddrPort("198.51.100.7:51820")
		if k.endpoint != "" {
			peer.Endpoint = netip.MustParseAddrPort(k.endpoint)
		}
	}
	if k.now != nil && !k.stale {
		peer.Stats.LastHandshake = k.now()
	}
	return []discovery.WGDevice{{Name: "wg0", Peers: []discovery.WGPeerRaw{peer}}}, nil
}

func (k *fakeKernel) setEndpoint(e string)     { k.mu.Lock(); k.endpoint = e; k.mu.Unlock() }
func (k *fakeKernel) IPv6Disabled(string) bool { return true }
func (k *fakeKernel) Rules() ([]discovery.Rule, error) {
	return []discovery.Rule{{Family: "ipv4", Priority: 0, Table: 255}, {Family: "ipv4", Priority: 32766, Table: 254}}, nil
}
func (k *fakeKernel) LegacyIPTables() bool { return false }

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

// fakeTor is a tor control port; the zero value does not answer.
type fakeTor struct {
	mu      sync.Mutex
	st      torctl.Status
	up      bool
	changed chan struct{}
}

func (t *fakeTor) Status() (torctl.Status, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.up {
		return torctl.Status{}, errors.New("connection refused")
	}
	return t.st, nil
}

func (t *fakeTor) Changed() <-chan struct{} { return t.changed }

func (t *fakeTor) set(up bool, st torctl.Status) {
	t.mu.Lock()
	t.up, t.st = up, st
	t.mu.Unlock()
	select {
	case t.changed <- struct{}{}:
	default:
	}
}

type fixture struct {
	tor     *fakeTor
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
	f := &fixture{k: &fakeKernel{probeV4: 3, now: clk.Now}, nft: &fakeNFT{tables: map[string]*nftables.Table{}}, clock: clk, home: home,
		pass: pass, base: ct, prof: profile.Template, ident: id, out: &syncBuf{}, tor: &fakeTor{changed: make(chan struct{}, 1)}}
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
		Tor:        func(string, string) discovery.TorSource { return f.tor },
		Sleep:      clk.Advance,
		HostRoot:   t.TempDir(),
		Boottime:   func() time.Duration { return clk.Now().Sub(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)) },
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
	rep, err := os.ReadFile(filepath.Join(res.Dir, "report.md"))
	if err != nil || !strings.Contains(string(rep), "NET-001") {
		t.Fatalf("report.md: %v\n%s", err, rep)
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

// The operator's way out of a PANIC whose re-check cannot pass (the panic blocks the tunnel that
// would have to come back): disarm with the passphrase lifts every table, the journal says so.
func TestAC08_DisarmFromPanicLiftsTheBlock(t *testing.T) {
	f := newFixture(t)
	res := f.arm(t, "strict")
	f.d.deliver(f.d.sess, leak())
	if st, _ := f.d.State(); st != engine.StatePanic {
		t.Fatalf("got %s", st)
	}
	f.k.setProbe(2) // the re-check fails: unpanic is impossible
	if _, err := f.d.Unpanic(); err == nil {
		t.Fatal("unpanic must still need the re-check")
	}
	r, err := f.d.Disarm()
	if err != nil || !r.InPanic {
		t.Fatalf("%+v %v", r, err)
	}
	if st, _ := f.d.State(); st != engine.StateReady || f.nft.has("inet lethe_panic") || f.nft.has("inet lethe") {
		t.Fatalf("after disarm in panic: %s, tables left", st)
	}
	evs := f.events(t, res.Dir)
	last := evs[len(evs)-1]
	if last.Type != "session.end" || last.Data["reason"] != "disarm_in_panic" {
		t.Fatalf("journal end: %+v", last)
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

func TestM8_EndpointUnknownAndChanged(t *testing.T) {
	f := newFixture(t)
	f.k.setEndpoint("none")
	res := f.arm(t, "off")
	if st := f.d.Status(); st.Color != "GRAY" || len(st.Degraded) != 1 || st.Degraded[0] != "tunnel_unknown" {
		t.Fatalf("a tunnel without a known endpoint must be GRAY: %+v", st)
	}
	f.k.setEndpoint("")
	f.d.mu.Lock()
	f.d.refreshLocked()
	f.d.mu.Unlock()
	if st := f.d.Status(); st.Color != "GREEN" {
		t.Fatalf("endpoint found: %+v", st)
	}
	f.k.setEndpoint("198.51.100.8:51820")
	f.d.mu.Lock()
	f.d.refreshLocked()
	f.d.mu.Unlock()
	_, _ = f.d.Disarm()
	got := strings.Join(types(f.events(t, res.Dir)), ",")
	if strings.Count(got, "discovery.endpoint_changed") != 2 || !strings.Contains(got, "discovery.endpoint_unknown") {
		t.Fatalf("journal: %s", got)
	}
}

func healthyTor() torctl.Status {
	return torctl.Status{Bootstrap: 100, CircuitEstablished: true, Guards: []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:9001")}}
}

func TestTUN003_TorStopsDuringSession(t *testing.T) {
	f := newFixture(t)
	f.prof = regexp.MustCompile(`(?m)^(\s+type:) auto`).ReplaceAll(f.prof, []byte("$1 tor"))
	f.tor.up, f.tor.st = true, healthyTor()
	res := f.arm(t, "off")
	if st := f.d.Status(); st.Color != "GREEN" {
		t.Fatalf("healthy tor: %+v", st)
	}
	f.tor.set(false, torctl.Status{})
	// Tor is read from a cache refreshed in the background (discovery never waits on the control
	// port under d.mu): the stop shows up on a pass after the refresh.
	var st Status
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		f.d.mu.Lock()
		f.d.refreshLocked()
		f.d.mu.Unlock()
		if st = f.d.Status(); st.Color == "RED" {
			break
		}
	}
	if st.Color != "RED" || len(st.Alerts) != 1 || st.Alerts[0].Check != "TUN-003" {
		t.Fatalf("tor stopped: %+v", st)
	}
	_, _ = f.d.Disarm()
	evs := f.events(t, res.Dir)
	found := false
	for _, e := range evs {
		if e.Check == "TUN-003" && e.Data["reason"] == "control_unreachable" {
			found = true
		}
	}
	if !found {
		t.Fatalf("journal: %v", types(evs))
	}
}

func TestTUN008_StrictArmRefusedWithSnowflake(t *testing.T) {
	f := newFixture(t)
	f.prof = regexp.MustCompile(`(?m)^(\s+type:) auto`).ReplaceAll(f.prof, []byte("$1 tor"))
	st := healthyTor()
	st.UseBridges, st.Bridges = true, []torctl.Bridge{{Transport: "snowflake", Addr: netip.MustParseAddrPort("192.0.2.3:80")}}
	f.tor.up, f.tor.st = true, st
	req := f.armReq("strict")
	req.Force, req.Reason = true, "test"
	if _, _, err := f.d.Arm(req); err == nil || !strings.Contains(err.Error(), "TUN-008") {
		t.Fatalf("strict arm with snowflake: %v", err)
	}
	f.arm(t, "off")
	_, _ = f.d.Disarm()
}

// storage.dir belongs to the operator: a planted "sessions" symlink must make arm fail without
// touching its target (as root, the daemon would otherwise chown and chmod it).
func TestM8_SessionsSymlinkRefused(t *testing.T) {
	f := newFixture(t)
	storage := filepath.Join(f.home, "lethe", "data")
	if err := os.MkdirAll(storage, 0o700); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(storage, "sessions")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.d.Arm(f.armReq("off")); err == nil {
		t.Fatal("armed through a symlinked sessions directory")
	}
	entries, _ := os.ReadDir(target)
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o755 || len(entries) != 0 {
		t.Fatalf("target touched: mode %v, %d entries", fi.Mode().Perm(), len(entries))
	}
}

// A leak to a baseline resolver (the home router) and an exe under the operator's home must reach
// the journal by field name only (spec §12.1).
func TestM8_AlertDataScrubbedOfBaselineValues(t *testing.T) {
	f := newFixture(t)
	b, err := baseline.New(f.clock.T, "test")
	if err != nil {
		t.Fatal(err)
	}
	b.Username = "operador"
	b.Networks = []baseline.Network{{Name: "casa", Resolvers: []string{"192.168.1.1"}}}
	if f.base, err = baseline.Encrypt(b, f.pass, 10); err != nil {
		t.Fatal(err)
	}
	if f.ident, err = b.Identity(); err != nil {
		t.Fatal(err)
	}
	res := f.arm(t, "off")
	f.d.deliver(f.d.sess, checks.Finding{Check: "DNS-001", Severity: contracts.SeverityCritical, Data: map[string]any{
		"iface": "eth0", "proto": "udp", "dst": "192.168.1.1", "dport": 53,
		"proc": contracts.Proc{PID: 42, Exe: "/home/operador/bin/dig", Confidence: contracts.ConfidenceHigh},
	}})
	_, _ = f.d.Disarm()
	found := false
	for _, ev := range f.events(t, res.Dir) {
		found = found || ev.Check == "DNS-001"
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "192.168.1.1") || strings.Contains(string(raw), "operador") {
			t.Fatalf("baseline value in the journal: %s", raw)
		}
		if ev.Check == "DNS-001" && ev.Data["matched"] != "baseline.networks[0].resolvers,baseline.username" {
			t.Fatalf("matched = %v", ev.Data["matched"])
		}
	}
	if !found {
		t.Fatal("the alert was not journaled")
	}
}

// The agent role follows the executable, not only the PID: a process of the operator that is not
// lethe never becomes the agent, even if it inherits a PID the daemon once knew.
func TestSELF003_AgentIdentifiedByExecutable(t *testing.T) {
	f := newFixture(t)
	proc := f.d.cfg.ProcRoot
	link := func(pid int, target string) {
		dir := filepath.Join(proc, strconv.Itoa(pid))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "exe")); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.Readlink("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	link(4100, self)
	link(4200, "/bin/sh")

	// service mode: no spawned agent, the executable is the identity
	if !f.d.isAgent(4100) || f.d.isAgent(4200) || f.d.isAgent(4300) {
		t.Fatal("service mode: identity must follow the executable")
	}
	// portable mode: only the spawned child, and only with the daemon's executable
	f.d.cfg.Agent = []string{"agent"}
	f.d.agent = &agentProc{pid: 4200}
	if f.d.isAgent(4200) || f.d.isAgent(4100) {
		t.Fatal("portable mode: a different executable or PID must not be the agent")
	}
	f.d.agent = &agentProc{pid: 4100}
	if !f.d.isAgent(4100) {
		t.Fatal("portable mode: the spawned lethe child is the agent")
	}
	f.d.agent = nil
	if f.d.isAgent(4100) {
		t.Fatal("portable mode: a dead agent's PID must not keep the role")
	}
}

// udp4 builds an IPv4/UDP packet (the NFLOG payload).
func udp4(src, dst netip.AddrPort) []byte {
	p := make([]byte, 28)
	p[0], p[9] = 0x45, 17
	binary.BigEndian.PutUint16(p[2:], 28)
	s4, d4 := src.Addr().As4(), dst.Addr().As4()
	copy(p[12:], s4[:])
	copy(p[16:], d4[:])
	binary.BigEndian.PutUint16(p[20:], src.Port())
	binary.BigEndian.PutUint16(p[22:], dst.Port())
	binary.BigEndian.PutUint16(p[24:], 8)
	return p
}

// An OpenVPN client that moves to a new server is learned from its blocked packet (spec §7.4);
// the browser's blocked packet is never learned.
func TestNET002_StrictLearnsVPNClientEndpoint(t *testing.T) {
	f := newFixture(t)
	socks := []sockdiag.Sock{
		{Proto: "udp", Local: netip.MustParseAddrPort("0.0.0.0:1194"), Inode: 11},
		{Proto: "tcp", Local: netip.MustParseAddrPort("10.0.0.2:50000"), Remote: netip.MustParseAddrPort("192.0.2.80:443"), Inode: 20},
	}
	owners := map[uint32]sockdiag.Owner{11: {PID: 500, Exe: "/usr/sbin/openvpn"}, 20: {PID: 900, Exe: "/usr/bin/firefox"}}
	f.d.cfg.Sockets = func() ([]sockdiag.Sock, map[uint32]sockdiag.Owner, error) { return socks, owners, nil }
	f.d.cfg.Cgroups = func(pid int) (string, uint64, uint32, bool) {
		return "system.slice/openvpn-client@work.service", 4242, 2, pid == 500
	}
	res := f.arm(t, "strict")
	if c := f.d.snap.VPNClients; len(c) != 1 || c[0].PID != 500 {
		t.Fatalf("vpn clients %+v", c)
	}
	if v := f.d.sess.gcfg.VPN; v == nil || v.ID != 4242 || v.DNS {
		t.Fatalf("guard cgroup %+v", v)
	}
	blocked := func(src, dst string) nflog.Blocked {
		pkt := udp4(netip.MustParseAddrPort(src), netip.MustParseAddrPort(dst))
		return nflog.Blocked{Prefix: "LETHE-BLOCK ", Leak: capture.ClassifyIP(pkt, len(pkt))}
	}
	f.d.learnBlocked(f.d.sess, blocked("10.0.0.2:1194", "198.51.100.20:1194"))
	f.d.learnBlocked(f.d.sess, blocked("10.0.0.2:5353", "198.51.100.21:5353")) // no VPN socket
	if !slices.Contains(f.d.snap.Endpoints, "198.51.100.20:1194/udp") || slices.Contains(f.d.snap.Endpoints, "198.51.100.21:5353/udp") {
		t.Fatalf("endpoints %v", f.d.snap.Endpoints)
	}
	// the operator confirms another one (sensitive at the IPC layer)
	if _, err := f.d.ConfirmEndpoint("203.0.113.44:443/tcp"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.ConfirmEndpoint("127.0.0.1:53/udp"); err == nil {
		t.Fatal("loopback endpoint accepted")
	}
	if !slices.Contains(f.d.snap.Endpoints, "203.0.113.44:443/tcp") {
		t.Fatalf("confirmed endpoint missing: %v", f.d.snap.Endpoints)
	}
	_, _ = f.d.Disarm()
	got := strings.Join(types(f.events(t, res.Dir)), ",")
	if !strings.Contains(got, "discovery.endpoint_learned") || !strings.Contains(got, "discovery.endpoint_confirmed") {
		t.Fatalf("journal: %s", got)
	}
}

// With allow_vpn_client_dns the cgroup rule opens DNS only; without it, no cgroup rule at all.
func TestNET002_VPNClientDNSOnlyWithProfileFlag(t *testing.T) {
	f := newFixture(t)
	f.prof = regexp.MustCompile(`allow_vpn_client_dns: false`).ReplaceAll(f.prof, []byte("allow_vpn_client_dns: true"))
	f.d.cfg.Sockets = func() ([]sockdiag.Sock, map[uint32]sockdiag.Owner, error) {
		return []sockdiag.Sock{{Proto: "udp", Local: netip.MustParseAddrPort("0.0.0.0:1194"), Inode: 11}},
			map[uint32]sockdiag.Owner{11: {PID: 500, Exe: "/usr/sbin/openvpn"}}, nil
	}
	f.d.cfg.Cgroups = func(int) (string, uint64, uint32, bool) { return "system.slice/openvpn.service", 7, 2, true }
	f.arm(t, "strict")
	if v := f.d.sess.gcfg.VPN; v == nil || !v.DNS {
		t.Fatalf("guard cgroup %+v", v)
	}
	_, _ = f.d.Disarm()
}

// A WireGuard endpoint that moves to another country during the session is TUN-006 (WARNING).
func TestTUN006_EndpointMovesAbroad(t *testing.T) {
	f := newFixture(t)
	f.d.cfg.Geo = geo.Map{
		netip.MustParseAddr("198.51.100.7"): {Country: "NL", ASN: 64500},
		netip.MustParseAddr("198.51.100.8"): {Country: "US", ASN: 64501},
	}
	f.arm(t, "off")
	f.k.setEndpoint("198.51.100.8:51820")
	f.d.mu.Lock()
	f.d.refreshLocked()
	f.d.mu.Unlock()
	st := f.d.Status()
	if st.Color != "YELLOW" || len(st.Alerts) != 1 || st.Alerts[0].Check != "TUN-006" {
		t.Fatalf("%+v", st)
	}
	_, _ = f.d.Disarm()
}
