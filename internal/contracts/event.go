package contracts

import "time"

// Severity levels (spec §10.1).
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarning  Severity = "WARNING"
	SeverityCritical Severity = "CRITICAL"
)

// Rank orders severities: INFO < WARNING < CRITICAL. Unknown severities rank lowest.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// Valid reports whether s is one of the three defined levels.
func (s Severity) Valid() bool { return s.Rank() > 0 }

// EventType is the closed list of event types (spec §14.1). Adding one requires a spec change.
type EventType string

const (
	EvSessionStart             EventType = "session.start"
	EvSessionEnd               EventType = "session.end"
	EvSessionCheckpoint        EventType = "session.checkpoint"
	EvStateChanged             EventType = "state.changed"
	EvDiscoveryChanged         EventType = "discovery.changed"
	EvDiscoveryEndpointChanged EventType = "discovery.endpoint_changed"
	EvDiscoveryEndpointLearned EventType = "discovery.endpoint_learned"
	EvDiscoveryEndpointUnknown EventType = "discovery.endpoint_unknown"
	EvDiscoveryEndpointConfirm EventType = "discovery.endpoint_confirmed"
	EvPreflightResult          EventType = "preflight.result"
	EvPreflightManualItem      EventType = "preflight.manual_item"
	EvCheckAlert               EventType = "check.alert"
	EvCheckResolved            EventType = "check.resolved"
	EvAlertAck                 EventType = "alert.ack"
	EvResponseExecuted         EventType = "response.executed"
	EvGuardApplied             EventType = "guard.applied"
	EvGuardRemoved             EventType = "guard.removed"
	EvGuardBypassDetected      EventType = "guard.bypass_detected"
	EvPanicEngaged             EventType = "panic.engaged"
	EvPanicReleased            EventType = "panic.released"
	EvSelftestResult           EventType = "selftest.result"
	EvOperatorForce            EventType = "operator.force"
	EvSensorDown               EventType = "sensor.down"
	EvSensorUp                 EventType = "sensor.up"
	EvClockJump                EventType = "clock.jump"
	EvIPCDenied                EventType = "ipc.denied"
)

// EventTypes returns the closed list, in spec order.
func EventTypes() []EventType {
	return []EventType{
		EvSessionStart, EvSessionEnd, EvSessionCheckpoint, EvStateChanged, EvDiscoveryChanged,
		EvDiscoveryEndpointChanged, EvDiscoveryEndpointLearned, EvDiscoveryEndpointUnknown,
		EvDiscoveryEndpointConfirm, EvPreflightResult, EvPreflightManualItem, EvCheckAlert,
		EvCheckResolved, EvAlertAck, EvResponseExecuted, EvGuardApplied, EvGuardRemoved,
		EvGuardBypassDetected, EvPanicEngaged, EvPanicReleased, EvSelftestResult, EvOperatorForce,
		EvSensorDown, EvSensorUp, EvClockJump, EvIPCDenied,
	}
}

// Source identifies who produced an event. Agent data is low-trust (spec principle 9).
type Source string

const (
	SourceDaemon   Source = "daemon"
	SourceAgent    Source = "agent"
	SourceOperator Source = "operator"
	SourceSelftest Source = "selftest"
)

// Confidence of process attribution (NET-010).
type Confidence string

const (
	ConfidenceHigh Confidence = "high"
	ConfidenceLow  Confidence = "low"
	ConfidenceNone Confidence = "none"
)

// Proc is the process attributed to a network event.
type Proc struct {
	PID        int        `json:"pid"`
	Exe        string     `json:"exe,omitempty"`
	Comm       string     `json:"comm,omitempty"`
	UID        int        `json:"uid"`
	Confidence Confidence `json:"confidence"`
}

// Event is one journal record (spec §14.1). Seq, Prev and Hash are filled by the journal.
type Event struct {
	V        int            `json:"v"`
	Seq      uint64         `json:"seq"`
	TS       time.Time      `json:"ts"`
	MonoNS   int64          `json:"mono_ns"`
	Session  string         `json:"session"`
	Type     EventType      `json:"type"`
	Check    string         `json:"check,omitempty"`
	Severity Severity       `json:"severity,omitempty"`
	Source   Source         `json:"source"`
	Selftest bool           `json:"selftest,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
	AlertID  string         `json:"alert_id,omitempty"`
	Actions  []string       `json:"actions,omitempty"`
	Prev     string         `json:"prev,omitempty"`
	Hash     string         `json:"hash,omitempty"`
}

// Str returns Data[key] as a string ("" if absent or not a string).
func (e Event) Str(key string) string {
	s, _ := e.Data[key].(string)
	return s
}

// Int returns Data[key] as an int (accepts int, int64, float64 from JSON).
func (e Event) Int(key string) int {
	switch v := e.Data[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

// ProcExe returns the attributed executable, if any.
func (e Event) ProcExe() string {
	switch p := e.Data["proc"].(type) {
	case Proc:
		return p.Exe
	case *Proc:
		if p != nil {
			return p.Exe
		}
	case map[string]any:
		s, _ := p["exe"].(string)
		return s
	}
	return ""
}
