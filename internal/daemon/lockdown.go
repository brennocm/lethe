package daemon

import (
	"fmt"
	"sort"
	"strings"

	"lethe/internal/contracts"
	"lethe/internal/engine"
	"lethe/internal/guard"
)

// panicCause records why the session entered PANIC (for the lockdown explanation).
type panicCause struct {
	cause string // alert | operator | auth_failures
	alert string
	check string
}

// LeftoverLockdown describes lethe* tables that no session owns (spec §10.6 item 6): found with
// no daemon running (lethe status), or by a daemon that started after another one died (service
// mode restarts it) and has no session yet.
func LeftoverLockdown(tables []string, daemonUp bool) *Lockdown {
	if len(tables) == 0 {
		return nil
	}
	why := "no lethe daemon is running (it crashed, was killed with kill -9, or the session was interrupted); the block stays on purpose, so nothing leaks"
	if daemonUp {
		why = "the previous session ended without releasing the network (the daemon crashed, was killed, or the machine lost power) and this daemon has no session; the block stays on purpose, so nothing leaks"
	}
	return &Lockdown{
		What:   "the network is blocked by leftover lethe tables: " + strings.Join(tables, ", "),
		Why:    why,
		Exit:   "Release the network in the panel (asks for the administrator password), or sudo lethe cleanup (removes only the lethe* tables), or reboot the machine",
		Ways:   []string{contracts.WayCleanup},
		Tables: tables,
	}
}

// leftoverLocked lists the lethe* tables present while no session owns them (nil on error: the
// status then says nothing rather than something false).
func (d *Daemon) leftoverLocked() []string {
	c, err := d.cfg.NFT()
	if err != nil {
		return nil
	}
	refs, err := guard.Leftovers(c)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.String())
	}
	return out
}

// lockdownLocked describes the current block, or nil when lethe blocks nothing.
func (d *Daemon) lockdownLocked() *Lockdown {
	s := d.sess
	if s == nil {
		return nil
	}
	unacked := []string{}
	var tunnel []string
	for _, a := range d.eng.Alerts() {
		if a.Severity == contracts.SeverityCritical && !a.Acked {
			unacked = append(unacked, a.ID)
		}
		if a.State != engine.AlertResolved && (a.Check == "TUN-001" || a.Check == "TUN-003") {
			tunnel = append(tunnel, fmt.Sprintf("%s (%s)", a.ID, a.Check))
		}
	}
	sort.Strings(unacked)
	switch {
	case d.eng.Session() == engine.StatePanic:
		why := "panic requested by the operator (lethe panic)"
		switch s.panic.cause {
		case "alert":
			why = fmt.Sprintf("alert %s (%s) triggered the panic", s.panic.alert, s.panic.check)
			if s.panic.check == "SELF-006" {
				why += ": 5 wrong passphrases in 5 minutes"
			}
		case "auth_failures":
			why = "5 wrong passphrases in 5 minutes (SELF-006)"
		}
		exit := "lethe unpanic (asks for the passphrase and checks the tunnel, routes and IPv6 before releasing)"
		ways := []string{contracts.WayUnpanic, contracts.WayDisarm}
		if len(unacked) > 0 {
			ways = []string{contracts.WayAck, contracts.WayUnpanic, contracts.WayDisarm}
			exit = fmt.Sprintf("acknowledge the CRITICAL alerts with lethe ack ID --reason \"...\" (%s), then run lethe unpanic", strings.Join(unacked, ", "))
		}
		return &Lockdown{What: "the network is blocked: panic", Why: why,
			Exit: exit + "; if the tunnel does not come back: lethe disarm ends the session and releases the network (asks for the passphrase); if lethe does not answer: sudo lethe cleanup, or reboot the machine",
			Ways: ways}
	case s.guardMode == engine.GuardStrict && s.confirming:
		return &Lockdown{What: "strict guard applied: only the tunnel passes while it proves it works",
			Why:  fmt.Sprintf("arm waits up to %s for a handshake or traffic through the tunnel", s.prof.Guard.ArmWindow),
			Exit: "nothing to do: without the proof lethe undoes the block by itself; open a web page to speed it up",
			Ways: []string{contracts.WayWait}}
	case s.guardMode == engine.GuardStrict && len(tunnel) > 0:
		return &Lockdown{What: "the network is blocked: strict guard without a tunnel",
			Why:  "the tunnel went down (" + strings.Join(tunnel, ", ") + "); in strict only the tunnel passes, so nothing leaves through the physical network",
			Exit: "reconnect the tunnel (the network comes back by itself), or lethe disarm to end the session and release the network",
			Ways: []string{contracts.WayReconnect, contracts.WayDisarm}}
	}
	return nil
}
