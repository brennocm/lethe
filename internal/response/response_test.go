package response

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/google/nftables"

	"lethe/internal/contracts"
	"lethe/internal/engine"
	"lethe/internal/guard"
	"lethe/internal/sensors/procscan"
)

type nullConn struct {
	tables  []string
	flushed int
	err     error
}

func (n *nullConn) AddTable(t *nftables.Table) *nftables.Table {
	n.tables = append(n.tables, t.Name)
	return t
}
func (n *nullConn) DelTable(*nftables.Table)                                  {}
func (n *nullConn) AddSet(*nftables.Set, []nftables.SetElement) error         { return nil }
func (n *nullConn) FlushSet(*nftables.Set)                                    {}
func (n *nullConn) SetAddElements(*nftables.Set, []nftables.SetElement) error { return nil }
func (n *nullConn) AddChain(c *nftables.Chain) *nftables.Chain                { return c }
func (n *nullConn) AddRule(r *nftables.Rule) *nftables.Rule                   { return r }
func (n *nullConn) ListTables() ([]*nftables.Table, error)                    { return nil, nil }
func (n *nullConn) Flush() error                                              { n.flushed++; return n.err }

func procFixture(t *testing.T, procs map[int]string) string {
	root := t.TempDir()
	for pid, exe := range procs {
		d := filepath.Join(root, strconv.Itoa(pid))
		_ = os.MkdirAll(d, 0o755)
		_ = os.Symlink(exe, filepath.Join(d, "exe"))
		_ = os.WriteFile(filepath.Join(d, "comm"), []byte(filepath.Base(exe)+"\n"), 0o644)
	}
	return root
}

type tick struct{ t time.Time }

func (k *tick) now() time.Time { k.t = k.t.Add(3 * time.Millisecond); return k.t }

func TestRESP_BlockAll(t *testing.T) {
	c := &nullConn{}
	var downs []string
	x := New(Env{
		Guard:       func() (guard.Conn, error) { return c, nil },
		GuardConfig: func() guard.Config { return guard.Config{Egress: []string{"eth0"}, L2: true} },
		Egress:      func() []string { return []string{"eth0"} },
		LinkDown:    func(i string) error { downs = append(downs, i); return nil },
		Now:         (&tick{}).now, LinkDownMode: "auto",
	})
	r := x.Run(engine.ActBlockAll, contracts.Event{})
	if !r.OK || c.flushed != 1 || len(downs) != 0 || r.Latency != 3*time.Millisecond {
		t.Fatalf("%+v flushed=%d downs=%v", r, c.flushed, downs)
	}
	// no L2 layer: auto falls back to link_down too
	x.env.GuardConfig = func() guard.Config { return guard.Config{Egress: []string{"eth0"}} }
	r = x.Run(engine.ActBlockAll, contracts.Event{})
	if !r.OK || len(downs) != 1 || r.Count != 1 {
		t.Fatalf("%+v downs=%v", r, downs)
	}
	x.env.LinkDownMode = "never"
	downs = nil
	x.Run(engine.ActBlockAll, contracts.Event{})
	if len(downs) != 0 {
		t.Fatal("never means never")
	}
	c.err = errors.New("EPERM")
	if r := x.Run(engine.ActBlockAll, contracts.Event{}); r.OK || r.Err == "" {
		t.Fatalf("%+v", r)
	}
	ev := r.Event("A-0001")
	if ev.Type != contracts.EvResponseExecuted || ev.AlertID != "A-0001" || ev.Data["action"] != "block_all" {
		t.Fatalf("%+v", ev)
	}
}

func TestRESP_KillProcesses(t *testing.T) {
	root := procFixture(t, map[int]string{100: "/usr/lib/firefox/firefox", 101: "/usr/bin/bash", 102: "/usr/bin/chromium", 1: "/usr/lib/systemd/systemd", 103: "/usr/lib/firefox/firefox"})
	var killed []int
	x := New(Env{ProcRoot: root, KillOnPanic: []procscan.Matcher{{Match: "exe", Value: "firefox"}, {Match: "exe", Value: "chromium"}, {Match: "exe", Value: "systemd"}},
		Protected: map[int]bool{103: true},
		Kill: func(pid int) error {
			if pid == 102 {
				return syscall.ESRCH // already gone: not an error
			}
			killed = append(killed, pid)
			return nil
		}})
	r := x.Run(engine.ActKillProcesses, contracts.Event{})
	if !r.OK || r.Count != 2 || len(killed) != 1 || killed[0] != 100 {
		t.Fatalf("%+v killed=%v", r, killed)
	}
	x.env.Kill = func(int) error { return syscall.EPERM }
	if r := x.Run(engine.ActKillProcesses, contracts.Event{}); r.OK {
		t.Fatal("EPERM must fail")
	}
	if r := New(Env{}).Run(engine.ActKillProcesses, contracts.Event{}); !r.OK || r.Count != 0 {
		t.Fatal("empty list is a no-op")
	}
}

func TestRESP_KillOffenderOnlyWithHighConfidence(t *testing.T) {
	var killed []int
	x := New(Env{Kill: func(pid int) error { killed = append(killed, pid); return nil }, Protected: map[int]bool{77: true}})
	ev := func(p contracts.Proc) contracts.Event { return contracts.Event{Data: map[string]any{"proc": p}} }
	if r := x.Run(engine.ActKillOffender, ev(contracts.Proc{PID: 50, Confidence: contracts.ConfidenceLow})); r.OK {
		t.Fatal("low confidence must not kill")
	}
	if r := x.Run(engine.ActKillOffender, ev(contracts.Proc{PID: 77, Confidence: contracts.ConfidenceHigh})); r.OK {
		t.Fatal("protected pid")
	}
	if r := x.Run(engine.ActKillOffender, ev(contracts.Proc{PID: 1, Confidence: contracts.ConfidenceHigh})); r.OK {
		t.Fatal("pid 1")
	}
	p := &contracts.Proc{PID: 51, Confidence: contracts.ConfidenceHigh}
	if r := x.Run(engine.ActKillOffender, contracts.Event{Data: map[string]any{"proc": p}}); !r.OK || len(killed) != 1 || killed[0] != 51 {
		t.Fatalf("%+v %v", r, killed)
	}
}

type fakeLogin1 struct {
	paths  map[uint32][]dbus.ObjectPath
	locked []dbus.ObjectPath
}

func (f *fakeLogin1) SessionsOf(uid uint32) ([]dbus.ObjectPath, error) { return f.paths[uid], nil }
func (f *fakeLogin1) Lock(p dbus.ObjectPath) error                     { f.locked = append(f.locked, p); return nil }

func TestRESP_LockScreenAndDelegation(t *testing.T) {
	l := &fakeLogin1{paths: map[uint32][]dbus.ObjectPath{1000: {"/org/freedesktop/login1/session/_32"}}}
	if err := LockScreen(l, 1000); err != nil || len(l.locked) != 1 {
		t.Fatal(err)
	}
	if err := LockScreen(l, 1001); err == nil {
		t.Fatal("no session must fail")
	}
	x := New(Env{LockScreen: func() error { return LockScreen(l, 1000) }})
	if r := x.Run(engine.ActLockScreen, contracts.Event{}); !r.OK {
		t.Fatal(r.Err)
	}
	if r := New(Env{}).Run(engine.ActLockScreen, contracts.Event{}); r.OK {
		t.Fatal("unavailable lock")
	}
	for _, a := range []engine.Action{engine.ActAlertTray, engine.ActAlertSound, engine.ActAlertFullscreen} {
		if r := x.Run(a, contracts.Event{}); !r.OK || !r.Delegated || r.Event("").Data["delegated"] != true {
			t.Fatalf("%s: %+v", a, r)
		}
	}
	if r := x.Run("rm_rf", contracts.Event{}); r.OK {
		t.Fatal("unknown action")
	}
	if r := New(Env{}).Run(engine.ActLinkDown, contracts.Event{}); r.OK {
		t.Fatal("link_down unavailable")
	}
	x = New(Env{Egress: func() []string { return []string{"a", "b"} }, LinkDown: func(i string) error {
		if i == "b" {
			return errors.New("busy")
		}
		return nil
	}})
	if r := x.Run(engine.ActLinkDown, contracts.Event{}); r.OK || r.Count != 1 {
		t.Fatalf("%+v", r)
	}
}
