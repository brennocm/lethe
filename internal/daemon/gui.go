package daemon

import (
	"fmt"

	"lethe/internal/contracts"
	"lethe/internal/engine"
)

// FullscreenReport is gui.fullscreen_result (contracts).
type FullscreenReport = contracts.FullscreenReport

// FullscreenResult journals r.
func (d *Daemon) FullscreenResult(r FullscreenReport) error {
	if r.Result != "focused" && r.Result != "shown" && r.Result != "failed" {
		return errParams(fmt.Errorf("result %q: focused, shown or failed", r.Result))
	}
	if r.LatencyMS < 0 || r.LatencyMS > 600_000 {
		return errParams(fmt.Errorf("latency_ms %v out of range", r.LatencyMS))
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.sess
	if s == nil {
		return errState(errNotArmed)
	}
	if d.eng.Alert(r.AlertID) == nil {
		return errParams(fmt.Errorf("unknown alert %s", r.AlertID))
	}
	if s.fullscreen[r.AlertID] {
		return nil // one report per alert: a peer cannot flood the journal
	}
	s.fullscreen[r.AlertID] = true
	d.appendLocked(contracts.Event{Type: contracts.EvResponseExecuted, Source: contracts.SourceDaemon, AlertID: r.AlertID,
		Data: map[string]any{"action": string(engine.ActAlertFullscreen), "ok": r.Result != "failed", "latency_ms": r.LatencyMS,
			"fullscreen_result": r.Result, "reported_by": "gui"}})
	return nil
}
