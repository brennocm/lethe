package checks

import (
	"time"

	"lethe/internal/contracts"
	"lethe/internal/discovery"
)

// TUN002 is "stale WireGuard handshake" (spec §9.3).
type TUN002 struct{}

func (TUN002) ID() string { return "TUN-002" }

var tun002Meta = meta{kind: Passive, sev: contracts.SeverityWarning, sources: []SourceID{SrcWgctrl}}

func (TUN002) Kind() Kind                          { return tun002Meta.Kind() }
func (TUN002) DefaultSeverity() contracts.Severity { return tun002Meta.DefaultSeverity() }
func (TUN002) Sources() []SourceID                 { return tun002Meta.Sources() }
func (TUN002) SelfTestCases() []string             { return tun002Meta.SelfTestCases() }

const (
	txWindow        = 10 * time.Second
	rejectAfterTime = 180 * time.Second // WireGuard REJECT_AFTER_TIME
)

// TxTracker remembers when each peer's tx_bytes last grew. The caller owns it across passes.
type TxTracker struct {
	last map[string]int64
	grew map[string]time.Time
}

// NewTxTracker returns an empty tracker.
func NewTxTracker() *TxTracker {
	return &TxTracker{last: map[string]int64{}, grew: map[string]time.Time{}}
}

// Evaluate: WARNING for a peer that sent in the last 10 s while its last handshake is older than
// 180 s (or never happened): packets go into a tunnel that no longer answers.
func (TUN002) Evaluate(tr *TxTracker, s *discovery.Snapshot, now time.Time) []Finding {
	var out []Finding
	seenNow := map[string]bool{}
	defer func() { // forget peers that are gone (endpoint changes would otherwise pile up)
		for k := range tr.last {
			if !seenNow[k] {
				delete(tr.last, k)
				delete(tr.grew, k)
			}
		}
	}()
	for _, t := range s.Tunnels {
		for _, p := range t.Peers {
			key := t.Iface + "|" + p.Endpoint
			seenNow[key] = true
			prev, seen := tr.last[key]
			if seen && p.TxBytes > prev {
				tr.grew[key] = now
			}
			tr.last[key] = p.TxBytes
			g, ok := tr.grew[key]
			if !ok || now.Sub(g) > txWindow {
				continue
			}
			if !p.LastHandshake.IsZero() && now.Sub(p.LastHandshake) <= rejectAfterTime {
				continue
			}
			out = append(out, Finding{Check: "TUN-002", Severity: contracts.SeverityWarning,
				Data: map[string]any{"iface": t.Iface, "reason": "handshake_stale"}})
		}
	}
	return out
}
