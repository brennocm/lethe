package daemon

import (
	"errors"
	"fmt"
	"time"

	"lethe/internal/discovery"
	"lethe/internal/engine"
	"lethe/internal/ipc"
)

// Arm confirmation (spec §10.6 item 2): after the strict tables are applied, the tunnel has
// guard.arm_confirm to prove, with local evidence only, that it carries traffic.

// handshakeFresh is how recent a WireGuard handshake must be to count as proof (WireGuard
// rekeys every 120 s, so a live tunnel always has one younger than 180 s).
const handshakeFresh = 180 * time.Second

// Proofs a tunnel can give.
const (
	proofHandshake = "wireguard_handshake"
	proofRx        = "tunnel_rx"
	proofTor       = "tor_circuit"
)

// ErrArmUnconfirmed is returned when the tunnel gave no proof inside the window (exit code 6).
var ErrArmUnconfirmed = errors.New("arm undone: the tunnel did not prove it carries traffic with the guard on")

// armProof looks for evidence that the tunnel works: a fresh WireGuard handshake, received bytes
// rising on a tunnel interface since the arm, or an established tor circuit.
func armProof(before, now discovery.Snapshot, at time.Time) (string, bool) {
	for _, t := range now.Tunnels {
		for _, p := range t.Peers {
			if !p.LastHandshake.IsZero() && at.Sub(p.LastHandshake) < handshakeFresh {
				return proofHandshake, true
			}
		}
	}
	for _, i := range now.Ifaces {
		if i.Class != discovery.ClassTunnel {
			continue
		}
		if b, ok := before.Iface(i.Name); ok && i.RxBytes > b.RxBytes {
			return proofRx, true
		}
	}
	if now.Tor != nil && now.Tor.CircuitEstablished {
		return proofTor, true
	}
	return "", false
}

// missingProof explains, in the operator's language, what did not happen and what to try.
func missingProof(now discovery.Snapshot, window time.Duration) string {
	wg := false
	for _, t := range now.Tunnels {
		if t.Kind == "wireguard" {
			wg = true
		}
	}
	switch {
	case now.Tor != nil && !wg:
		return fmt.Sprintf("o tor não estabeleceu um circuito em %s; confira o bootstrap do tor e arme de novo", window)
	case wg:
		return fmt.Sprintf("nenhum handshake WireGuard nem tráfego recebido pelo túnel em %s; abra uma página ou ative o PersistentKeepalive e arme de novo", window)
	}
	return fmt.Sprintf("nenhum tráfego recebido pelo túnel em %s; abra uma página ou ative o keepalive do cliente VPN e arme de novo", window)
}

// confirmArm waits for the proof without holding d.mu (sensors and IPC keep working, the session
// is already protected). Without proof the guard is removed and the session ends with
// arm_unconfirmed. A panic during the window ends the wait and keeps the block (fail-closed).
func (d *Daemon) confirmArm(s *session) error {
	window := s.prof.Guard.ArmWindow
	d.mu.Lock()
	before := d.snap
	d.mu.Unlock()
	for waited := time.Duration(0); ; waited += d.cfg.ArmConfirmPoll {
		d.mu.Lock()
		if d.sess != s {
			d.mu.Unlock()
			return errState(errors.New("the session ended during the arm confirmation"))
		}
		if d.eng.Session() != engine.StateArmed {
			s.confirming = false
			d.mu.Unlock()
			return nil
		}
		snap := d.discoverLocked(s.prof)
		if proof, ok := armProof(before, snap, d.cfg.Now()); ok {
			s.confirming = false
			d.sess.color = ""
			d.stateChangedWithLocked("arm", map[string]any{"proof": proof})
			d.mu.Unlock()
			return nil
		}
		if waited >= window {
			why := missingProof(snap, window)
			_, _ = fmt.Fprintf(d.cfg.Out, "lethe: arm desfeito: %s\n", why)
			d.endLocked("arm_unconfirmed", false)
			d.eng = engine.New(clock{d.cfg.Now}, engine.Config{}, engine.StateReady)
			d.mu.Unlock()
			return &ipc.Error{Code: ipc.CodeArmUnconfirmed, Message: ErrArmUnconfirmed.Error() + ": " + why}
		}
		d.mu.Unlock()
		d.cfg.Sleep(d.cfg.ArmConfirmPoll)
	}
}
