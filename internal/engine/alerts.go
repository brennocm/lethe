package engine

import (
	"fmt"
	"strconv"
	"time"

	"lethe/internal/contracts"
)

// AlertState is the alert lifecycle (spec §10.2).
type AlertState string

const (
	AlertOpen         AlertState = "open"
	AlertAcknowledged AlertState = "acknowledged"
	AlertResolved     AlertState = "resolved"
)

const (
	dedupWindow   = 5 * time.Second
	resolveWindow = 10 * time.Second
)

// pointChecks are one-shot detections, auto-resolved after resolveWindow without recurrence.
// Every other check is a condition, resolved after its condition has been clear for resolveWindow.
var pointChecks = map[string]bool{
	"NET-001": true, "NET-002": true, "NET-009": true, "NET-012": true, "DNS-001": true,
}

// IsPointCheck reports whether check is a one-shot detection (vs. a condition).
func IsPointCheck(check string) bool { return pointChecks[check] }

// Alert is one deduplicated alert.
type Alert struct {
	ID         string
	Check      string
	Severity   contracts.Severity
	Key        string
	State      AlertState
	Count      int
	FirstSeen  time.Time
	LastSeen   time.Time
	ResolvedAt time.Time
	AckReason  string
	Acked      bool // stays true after resolution, for unpanic and the report
	Source     contracts.Source
	clearSince time.Time
}

// Unresolved reports whether the alert still counts for the global color.
func (a *Alert) Unresolved() bool { return a.State != AlertResolved }

// DedupKey is (check, iface, dst, dport, proc.exe) (spec §10.2).
func DedupKey(ev contracts.Event) string {
	return ev.Check + "|" + ev.Str("iface") + "|" + ev.Str("dst") + "|" + strconv.Itoa(ev.Int("dport")) + "|" + ev.ProcExe()
}

func formatAlertID(n int) string { return fmt.Sprintf("A-%04d", n) }
