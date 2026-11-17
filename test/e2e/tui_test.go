//go:build e2e

package e2e

import (
	"bytes"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

	"lethe/internal/tui"
	"lethe/test/netlab"
)

// TestE2E_M12_TUIOverIPC: the TUI against an armed daemon through the real socket. The tunnel
// drops, TUN-001 CRITICAL takes the screen, a wrong passphrase is refused and the right one
// acknowledges it.
func TestE2E_M12_TUIOverIPC(t *testing.T) {
	lab := netlab.New(t, true)
	lab.WaitHandshake(t, 10*time.Second)
	s := newSession(t)
	d, _, _ := startArmed(t, s)
	m := tui.New(tui.IPC{Socket: s.socket}, tui.Options{Lang: "pt-BR", Tick: 100 * time.Millisecond})
	tm := teatest.NewTestModel(t, m, teatest.WithInitialTermSize(100, 30))
	see := func(what string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool { return bytes.Contains(b, []byte(what)) },
			teatest.WithDuration(15*time.Second), teatest.WithCheckInterval(50*time.Millisecond))
	}
	see("ARMED")
	lab.SetTunnel(t, false)
	see("ALERTA CR")
	ack := func(pass string) {
		tm.Type("a")
		tm.Type("teste do laboratório")
		tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
		tm.Type(pass)
		tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	}
	ack("senha errada")
	see("rejected")
	if a := alertOf(d, "TUN-001"); a == nil || a.Acked {
		t.Fatalf("a wrong passphrase must not acknowledge: %+v", a)
	}
	// a acknowledges the oldest open CRITICAL first (NET-004 when the tunnel route goes, then
	// TUN-001): repeat until every CRITICAL is acknowledged and the screen is back.
	openCritical := func() int {
		n := 0
		for _, a := range d.Status().Alerts {
			if a.Severity == "CRITICAL" && !a.Acked && a.State == "open" {
				n++
			}
		}
		return n
	}
	for i := 0; openCritical() > 0 && i < 5; i++ {
		ack(string(s.pass))
		see("Alerta reconhecido")
		time.Sleep(300 * time.Millisecond)
	}
	if a := alertOf(d, "TUN-001"); a == nil || !a.Acked {
		t.Fatalf("TUN-001 not acknowledged: %+v", a)
	}
	time.Sleep(500 * time.Millisecond)
	tm.Type("q")
	tm.WaitFinished(t, teatest.WithFinalTimeout(5*time.Second))
	if v := tm.FinalModel(t).View(); !strings.Contains(v, "a reconhecer · s selftest") {
		t.Fatalf("back to the main screen after the acknowledgements:\n%s", v)
	}
}
