package daemon

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lethe/internal/checks"
	"lethe/internal/contracts"
)

// fakeOps answers every case at once, as the sensors would.
type fakeOps struct {
	d        *Daemon
	noAnswer bool
	dummies  []string
}

func qnameOf(q []byte) string {
	var parts []string
	for i := 12; i < len(q) && q[i] != 0; {
		n := int(q[i])
		parts = append(parts, string(q[i+1:i+1+n]))
		i += 1 + n
	}
	return strings.Join(parts, ".")
}

func (o *fakeOps) UDP(iface string, dst netip.AddrPort, payload []byte, count int, before func(uint16) error) (uint16, error) {
	if before != nil {
		if err := before(40001); err != nil {
			return 0, err
		}
	}
	if o.noAnswer {
		return 40001, nil
	}
	f := checks.Finding{Check: "NET-001", Severity: contracts.SeverityCritical, Data: map[string]any{
		"iface": iface, "proto": "udp", "dst": dst.Addr().String(), "dport": int(dst.Port()), "sport": 40001}}
	switch dst.Port() {
	case 53:
		f.Check, f.Sensitive = "DNS-001", map[string]string{"qname": qnameOf(payload)}
	case 3478:
		f.Check = "NET-012"
	}
	o.d.deliver(o.d.sess, f)
	return 40001, nil
}

func (o *fakeOps) SYN(string, netip.AddrPort, func(uint16) error) (func(), error) {
	return func() {}, nil
}

func (o *fakeOps) AddDummy(name string) error {
	o.dummies = append(o.dummies, name)
	o.d.deliver(o.d.sess, checks.Finding{Check: "NET-006", Severity: contracts.SeverityWarning, Data: map[string]any{"iface": name}})
	return nil
}
func (o *fakeOps) DelDummy(string) error           { return nil }
func (o *fakeOps) AddTable(string) error           { return nil }
func (o *fakeOps) DelTable(string) error           { return nil }
func (o *fakeOps) SpawnDeny() (int, func(), error) { return 0, func() {}, nil }

func TestAC11_SelftestFindingsAreDryRun(t *testing.T) {
	f := newFixture(t)
	ops := &fakeOps{d: f.d}
	f.d.cfg.SelftestOps = ops
	res := f.arm(t, "off")
	out, err := f.d.RunSelftest(context.Background(), SelftestRequest{Cases: []string{STNet001, STNet002, STNet006, STNet012, STDNS001, Resp001}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range out.Cases {
		got[c.ID] = c.Result
	}
	want := map[string]string{STNet001: CasePass, STNet002: CaseSkip, STNet006: CasePass, STNet012: CasePass, STDNS001: CasePass, Resp001: CaseSkip}
	for id, r := range want {
		if got[id] != r {
			t.Fatalf("%s = %s, want %s (%+v)", id, got[id], r, out.Cases)
		}
	}
	if !out.Passed || out.Full {
		t.Fatalf("%+v", out)
	}
	if st := f.d.Status(); len(st.Alerts) != 0 {
		t.Fatalf("selftest findings opened real alerts: %+v", st.Alerts)
	}
	if _, err := os.Stat(filepath.Join(f.home, "lethe", "data", "state", "selftest.json")); err == nil {
		t.Fatal("a partial run must not update selftest.json")
	}
	_, _ = f.d.Disarm()
	evs := f.events(t, res.Dir)
	n, result := 0, false
	for _, ev := range evs {
		if ev.Type == contracts.EvCheckAlert {
			if !ev.Selftest || ev.Data["dry_run"] != true {
				t.Fatalf("not a selftest event: %+v", ev)
			}
			n++
		}
		if ev.Type == contracts.EvSelftestResult {
			result = true
		}
	}
	if n != 4 || !result {
		t.Fatalf("alerts %d, result %v", n, result)
	}
	raw, _ := json.Marshal(evs)
	if strings.Contains(string(raw), "lethe-st-") && !strings.Contains(string(raw), "sealed") {
		t.Fatal("the test qname must be sealed")
	}
}

// A case that is never seen fails; ST-NET-001 failing makes the result critical, and a full run
// writes selftest.json for SELF-004.
func TestSELF004_FullSelftestRecorded(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the case timeouts")
	}
	f := newFixture(t)
	f.d.cfg.SelftestOps = &fakeOps{d: f.d, noAnswer: true}
	f.arm(t, "off")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // every case gives up at once
	out, err := f.d.RunSelftest(ctx, SelftestRequest{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out.Passed || !out.Critical || !out.Full {
		t.Fatalf("%+v", out)
	}
	dir := filepath.Join(f.d.sess.prof.Storage.Dir, "state")
	raw, err := os.ReadFile(filepath.Join(dir, "selftest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rec SelftestResult
	if json.Unmarshal(raw, &rec) != nil || !rec.Critical {
		t.Fatalf("%s", raw)
	}
	_, _ = f.d.Disarm()
}

func TestAC11_SelftestRefusals(t *testing.T) {
	f := newFixture(t)
	if _, err := f.d.RunSelftest(context.Background(), SelftestRequest{}, nil); err == nil {
		t.Fatal("no session")
	}
	f.arm(t, "off")
	if _, err := f.d.RunSelftest(context.Background(), SelftestRequest{Cases: []string{"ST-XXX-000"}}, nil); err == nil {
		t.Fatal("unknown case")
	}
	denied := func() error { return os.ErrPermission }
	if _, err := f.d.RunSelftest(context.Background(), SelftestRequest{Cases: []string{Resp001}, Resp: true}, denied); err == nil {
		t.Fatal("RESP-001 without the passphrase proof")
	}
	_, _ = f.d.Disarm()
}
