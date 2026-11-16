// Package checks holds one file per check (spec §9) and the static registry. Checks turn
// sensor observations into findings; they never act (no guard, no responses).
package checks

import (
	"fmt"

	"lethe/internal/contracts"
)

// Kind of check (spec §5.4).
type Kind uint8

const (
	Passive Kind = iota + 1
	Active
	Preflight
)

// SourceID names a sensor (spec §9.7). If a source is down, its checks go GRAY.
type SourceID string

const (
	SrcCapture  SourceID = "capture"
	SrcNFLog    SourceID = "nflog"
	SrcNetlink  SourceID = "netlink"
	SrcSockdiag SourceID = "sockdiag"
	SrcWgctrl   SourceID = "wgctrl"
	SrcNFTMon   SourceID = "nftmon"
	SrcTorctl   SourceID = "torctl"
	SrcIPC      SourceID = "ipc" // the daemon's own IPC server (proof failures)
)

// Check is the static metadata every check exposes. Behaviour lives in per-check functions,
// called by the daemon with the sensor data they need (pure where possible).
type Check interface {
	ID() string
	Kind() Kind
	DefaultSeverity() contracts.Severity
	Sources() []SourceID
	SelfTestCases() []string
}

// Finding is what a check reports. Sensitive values (qname…) go in Sensitive; the daemon seals
// them into the journal (§14.4) and never copies them into Data.
type Finding struct {
	Check     string
	Severity  contracts.Severity
	Data      map[string]any
	Sensitive map[string]string
}

// Alert builds the check.alert event (seq, ts, session and chain are filled downstream).
func (f Finding) Alert() contracts.Event {
	return contracts.Event{
		V: 1, Type: contracts.EvCheckAlert, Check: f.Check, Severity: f.Severity,
		Source: contracts.SourceDaemon, Data: f.Data,
	}
}

// Resolved builds the check.resolved event for a condition that cleared.
func Resolved(check string, data map[string]any) contracts.Event {
	return contracts.Event{V: 1, Type: contracts.EvCheckResolved, Check: check, Source: contracts.SourceDaemon, Data: data}
}

// meta is the shared implementation of Check.
type meta struct {
	kind    Kind
	sev     contracts.Severity
	sources []SourceID
	st      []string
}

func (m meta) Kind() Kind                          { return m.kind }
func (m meta) DefaultSeverity() contracts.Severity { return m.sev }
func (m meta) Sources() []SourceID                 { return append([]SourceID(nil), m.sources...) }
func (m meta) SelfTestCases() []string             { return append([]string(nil), m.st...) }

// SealedAlert builds the check.alert event with every sensitive value sealed by seal
// (journal.Writer.Seal). Without a sealer the sensitive values are dropped, never copied.
func (f Finding) SealedAlert(seal func(string) (map[string]any, error)) (contracts.Event, error) {
	ev := f.Alert()
	if len(f.Sensitive) == 0 {
		return ev, nil
	}
	data := make(map[string]any, len(f.Data)+len(f.Sensitive))
	for k, v := range f.Data {
		data[k] = v
	}
	if seal != nil {
		for k, v := range f.Sensitive {
			s, err := seal(v)
			if err != nil {
				return contracts.Event{}, fmt.Errorf("seal %s: %w", k, err)
			}
			data[k] = s
		}
	}
	ev.Data = data
	return ev, nil
}
