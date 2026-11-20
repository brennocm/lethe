package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"

	"lethe/internal/contracts"
	"lethe/internal/engine"
	"lethe/internal/ipc"
)

func latestSessionDir(t *testing.T, f *fixture) string {
	t.Helper()
	root := filepath.Join(f.home, "lethe", "data", "sessions")
	ents, err := os.ReadDir(root)
	if err != nil || len(ents) == 0 {
		t.Fatalf("no session dir: %v", err)
	}
	return filepath.Join(root, ents[len(ents)-1].Name())
}

func endReason(t *testing.T, evs []contracts.Event) string {
	t.Helper()
	for _, e := range evs {
		if e.Type == contracts.EvSessionEnd {
			r, _ := e.Data["reason"].(string)
			return r
		}
	}
	t.Fatal("no session.end")
	return ""
}

func (f *fixture) leftoverTables() []string {
	f.nft.mu.Lock()
	defer f.nft.mu.Unlock()
	var out []string
	for k := range f.nft.tables {
		out = append(out, k)
	}
	return out
}

// Strict arm without any proof from the tunnel is undone inside guard.arm_confirm.
func TestAC16_StrictArmUndoneWithoutProof(t *testing.T) {
	f := newFixture(t)
	f.k.stale = true
	start := f.clock.Now()
	_, _, err := f.d.Arm(f.armReq("strict"))
	var ie *ipc.Error
	if !errors.As(err, &ie) || ie.Code != ipc.CodeArmUnconfirmed || !strings.Contains(ie.Message, "PersistentKeepalive") {
		t.Fatalf("want arm_unconfirmed with the cause, got %v", err)
	}
	if waited := f.clock.Now().Sub(start); waited < 30*time.Second || waited > 31*time.Second {
		t.Fatalf("waited %s, want the 30 s window", waited)
	}
	if left := f.leftoverTables(); len(left) != 0 {
		t.Fatalf("tables left behind: %v", left)
	}
	if st, _ := f.d.State(); st != engine.StateReady {
		t.Fatalf("state %s", st)
	}
	dir := latestSessionDir(t, f)
	evs := f.events(t, dir)
	if r := endReason(t, evs); r != "arm_unconfirmed" {
		t.Fatalf("session.end reason %q", r)
	}
	for _, e := range evs {
		if e.Type == contracts.EvGuardRemoved && e.Data["reason"] != "arm_unconfirmed" {
			t.Fatalf("guard.removed %v", e.Data)
		}
		if e.Type == contracts.EvStateChanged && e.Data["state"] == "ARMED" {
			t.Fatal("ARMED was announced without proof")
		}
	}
	f.k.stale = false
	f.arm(t, "strict") // the operator fixes the tunnel and arms again
}

func TestM81_ArmConfirmedByTunnelRx(t *testing.T) {
	f := newFixture(t)
	f.k.stale = true
	f.d.cfg.Sleep = func(d time.Duration) {
		f.clock.Advance(d)
		f.k.mu.Lock()
		f.k.rx += 1500
		f.k.mu.Unlock()
	}
	res := f.arm(t, "strict")
	st := f.d.Status()
	if st.State != "ARMED" || st.Confirming {
		t.Fatalf("status %+v", st)
	}
	_, _ = f.d.Disarm()
	found := false
	for _, e := range f.events(t, res.Dir) {
		if e.Type == contracts.EvStateChanged && e.Data["proof"] == proofRx {
			found = true
		}
	}
	if !found {
		t.Fatal("the proof is not journaled")
	}
}

func TestM81_ArmConfirmZeroSkipsTheWindow(t *testing.T) {
	f := newFixture(t)
	f.k.stale = true
	f.prof = []byte(strings.Replace(string(f.prof), "arm_confirm: 30s", "arm_confirm: 0s", 1))
	start := f.clock.Now()
	f.arm(t, "strict")
	if !f.clock.Now().Equal(start) {
		t.Fatal("arm_confirm 0 must not wait")
	}
}

// --force never arms a blocking guard over a tunnel failure; under off it still works.
func TestAC17_ForceRefusedWhenTunnelFails(t *testing.T) {
	f := newFixture(t)
	f.k.wgDown = true
	for _, mode := range []string{"strict", "reactive"} {
		req := f.armReq(mode)
		req.Force, req.Reason = true, "x"
		_, rep, err := f.d.Arm(req)
		if err == nil || !strings.Contains(err.Error(), "preflight failed") ||
			!strings.Contains(err.Error(), "--guard off") || !strings.Contains(err.Error(), "TUN-001") {
			t.Fatalf("%s: %v (%s)", mode, err, rep.Result)
		}
		if left := f.leftoverTables(); len(left) != 0 {
			t.Fatalf("%s: tables applied: %v", mode, left)
		}
	}
	req := f.armReq("off")
	req.Force, req.Reason = true, "observer only"
	if _, _, err := f.d.Arm(req); err != nil {
		t.Fatalf("off + --force must arm: %v", err)
	}
}

// Five wrong proofs under off: SELF-006 CRITICAL, sensitive methods locked, network untouched.
func TestSELF006_AC18_OffBadProofsLockWithoutBlocking(t *testing.T) {
	f := newFixture(t)
	c := f.serve(t)
	if err := c.Call("session.arm", f.armReq("off"), nil, nil); err != nil {
		t.Fatal(err)
	}
	bad := []byte("0123456789abcdef0123456789abcdef")
	for range ipc.FailLimit {
		proof, err := c.Prove(bad, "session.disarm", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Call("session.disarm", nil, proof, nil)
	}
	var st Status
	for range 200 {
		st = f.d.Status()
		if len(st.Alerts) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(st.Alerts) != 1 || st.Alerts[0].Check != "SELF-006" || st.Alerts[0].Severity != "CRITICAL" {
		t.Fatalf("alerts %+v", st.Alerts)
	}
	if st.State != "ARMED" {
		t.Fatalf("state %s: off must not panic", st.State)
	}
	if left := f.leftoverTables(); len(left) != 0 {
		t.Fatalf("tables applied: %v", left)
	}
	key, err := ipc.DeriveKey(f.pass, f.d.sess.salt)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := c.Prove(key, "session.disarm", nil)
	if err := c.Call("session.disarm", nil, proof, nil); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("a right proof during the lock must be refused: %v", err)
	}
	if st.Lockdown != nil {
		t.Fatalf("nothing is blocked, lockdown %+v", st.Lockdown)
	}
	f.clock.Advance(ipc.FailWindow)
	proof, _ = c.Prove(key, "session.disarm", nil)
	if err := c.Call("session.disarm", nil, proof, nil); err != nil {
		t.Fatalf("after 5 min the right proof works: %v", err)
	}
}

// Every block says what, why and how to get out (spec §10.6 item 5).
func TestM81_LockdownExplainsPanicAndStrictWithoutTunnel(t *testing.T) {
	f := newFixture(t)
	f.arm(t, "strict")
	if st := f.d.Status(); st.Lockdown != nil {
		t.Fatalf("armed and healthy: lockdown %+v", st.Lockdown)
	}
	f.k.mu.Lock()
	f.k.wgDown = true
	f.k.mu.Unlock()
	f.d.mu.Lock()
	f.d.refreshLocked()
	f.d.mu.Unlock()
	st := f.d.Status()
	if st.Lockdown == nil || !strings.Contains(st.Lockdown.What, "without a tunnel") || !strings.Contains(st.Lockdown.Exit, "lethe disarm") {
		// strict + TUN-001 CRITICAL engages the panic: that lockdown names unpanic instead
		if st.Lockdown == nil || !strings.Contains(st.Lockdown.What, "panic") || !strings.Contains(st.Lockdown.Why, "TUN-001") ||
			!strings.Contains(st.Lockdown.Exit, "lethe ack") || !strings.Contains(st.Lockdown.Exit, "lethe unpanic") {
			t.Fatalf("lockdown %+v", st.Lockdown)
		}
	}
	if err := contracts.Validate("status", st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.out.String(), "how to get out") {
		t.Fatalf("the terminal must show the way out: %q", f.out.String())
	}
}

func TestM81_LockdownManualPanic(t *testing.T) {
	f := newFixture(t)
	f.arm(t, "reactive")
	if err := f.d.Panic("operator"); err != nil {
		t.Fatal(err)
	}
	l := f.d.Status().Lockdown
	if l == nil || !strings.Contains(l.Why, "lethe panic") || !strings.HasPrefix(l.Exit, "lethe unpanic") {
		t.Fatalf("lockdown %+v", l)
	}
	// the ways out as actions for the GUI: leave the panic, or end the session
	if strings.Join(l.Ways, ",") != "unpanic,disarm" {
		t.Fatalf("ways %v", l.Ways)
	}
}

func TestM81_LeftoverLockdown(t *testing.T) {
	if LeftoverLockdown(nil, false) != nil {
		t.Fatal("no tables, no lockdown")
	}
	l := LeftoverLockdown([]string{"inet lethe"}, false)
	if !strings.Contains(l.Exit, "sudo lethe cleanup") || len(l.Tables) != 1 || len(l.Ways) != 1 || l.Ways[0] != "cleanup" {
		t.Fatalf("%+v", l)
	}
}

// A daemon that starts over tables a dead one left (service mode restarts it) says the network
// is blocked and how to release it, and refuses to arm on top of the block.
func TestM81_RestartedDaemonReportsLeftovers(t *testing.T) {
	f := newFixture(t)
	if l := f.d.Status().Lockdown; l != nil {
		t.Fatalf("no tables: %+v", l)
	}
	f.nft.mu.Lock()
	f.nft.tables["inet lethe"] = &nftables.Table{Family: nftables.TableFamilyINet, Name: "lethe"}
	f.nft.tables["inet other"] = &nftables.Table{Family: nftables.TableFamilyINet, Name: "other"}
	f.nft.mu.Unlock()
	l := f.d.Status().Lockdown
	if l == nil || strings.Join(l.Tables, ",") != "inet lethe" || l.Ways[0] != "cleanup" || !strings.Contains(l.Why, "this daemon has no session") {
		t.Fatalf("%+v", l)
	}
	if _, _, err := f.d.Arm(f.armReq("off")); err == nil || !strings.Contains(err.Error(), "release the network first") {
		t.Fatalf("arm over a leftover block: %v", err)
	}
}
