package contracts

import (
	"fmt"
	"time"
)

// The IPC answers the interfaces read (status.get, selftest.run, session.disarm). They live
// here, not in the daemon, because the GUI module may import only contracts and ipc (spec
// §20.3); internal/daemon aliases them.

// Status is status.get and `lethe status --json` (schema: status).
type Status struct {
	State       string       `json:"state"`
	Color       string       `json:"color"`
	Session     string       `json:"session,omitempty"`
	Fingerprint string       `json:"fingerprint,omitempty"`
	Guard       string       `json:"guard,omitempty"`
	StartedAt   *time.Time   `json:"started_at,omitempty"`
	AuthSalt    []byte       `json:"auth_salt,omitempty"` // for K = scrypt(passphrase, salt), spec §17.3
	Alerts      []AlertView  `json:"alerts"`
	Degraded    []string     `json:"degraded"`
	Sensors     []SensorView `json:"sensors"`
	Agent       bool         `json:"agent"`
	Confirming  bool         `json:"confirming,omitempty"` // strict arm waiting for the tunnel's proof
	Lockdown    *Lockdown    `json:"lockdown,omitempty"`   // what lethe blocks, why and how to get out
	Exit        *ExitView    `json:"exit,omitempty"`       // last agreed exit check (NET-011), never the IP
}

// AlertView is one alert in the status.
type AlertView struct {
	ID        string    `json:"id"`
	Check     string    `json:"check"`
	Severity  string    `json:"severity"`
	State     string    `json:"state"`
	Count     int       `json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Acked     bool      `json:"acked"`
}

// SensorView is one heartbeat source.
type SensorView struct {
	Source string `json:"source"`
	Up     bool   `json:"up"`
}

// ExitView is the last agreed exit check, without the IP (status, GUI header).
type ExitView struct {
	Country string    `json:"country,omitempty"`
	ASN     uint32    `json:"asn,omitempty"`
	At      time.Time `json:"at"`
	Path    string    `json:"path"` // tunnel interface or "tor"
}

// Lockdown explains a network blocked by lethe in three parts (spec §10.6 item 5): what is
// blocked, why (cause and alert, never a baseline value) and the exact way out.
type Lockdown struct {
	What   string   `json:"what"`
	Why    string   `json:"why"`
	Exit   string   `json:"exit"`
	Tables []string `json:"tables,omitempty"` // leftover lethe* tables (status without a daemon)
}

// String is the human form used on the terminal and in error messages.
func (l Lockdown) String() string {
	return fmt.Sprintf("%s\n  por quê: %s\n  como sair: %s", l.What, l.Why, l.Exit)
}

// QueryParams filters events.query and events.subscribe.
type QueryParams struct {
	Severity string `json:"severity,omitempty"` // minimum severity
	Limit    int    `json:"limit,omitempty"`
}

// DisarmResult is session.disarm.
type DisarmResult struct {
	Session  string `json:"session"`
	Dir      string `json:"dir"`
	Critical int    `json:"critical"`
}

// SelftestCases is every case of spec §18.2, in run order; Resp001 is the one that cuts the
// network and needs the passphrase.
var SelftestCases = []string{"ST-NET-001", "ST-NET-002", "ST-NET-003", "ST-NET-006", "ST-NET-010", "ST-NET-012",
	"ST-DNS-001", "ST-DNS-004", "ST-TUN-004", "ST-HOST-001", "ST-SELF-001", "ST-SELF-002", Resp001}

// Resp001 is the response selftest case.
const Resp001 = "RESP-001"

// Selftest case results.
const (
	CasePass = "pass"
	CaseFail = "fail"
	CaseSkip = "skip"
)

// SelftestRequest is selftest.run. RESP-001 runs only when Resp is true (a sensitive call).
type SelftestRequest struct {
	Cases []string `json:"cases,omitempty"` // empty = all
	Resp  bool     `json:"resp,omitempty"`  // the operator confirmed RESP-001 (it cuts the network ~1 s)
}

// CaseResult is one row of the result table.
type CaseResult struct {
	ID        string  `json:"id"`
	Result    string  `json:"result"`
	LatencyMS float64 `json:"latency_ms,omitempty"`
	Reason    string  `json:"reason,omitempty"`
}

// SelftestResult is the table written to the journal and to storage.dir/state/selftest.json.
type SelftestResult struct {
	FinishedAt time.Time    `json:"finished_at"`
	Guard      string       `json:"guard"`
	Passed     bool         `json:"passed"`
	Critical   bool         `json:"critical"`
	Full       bool         `json:"full"` // every case was asked (only a full run updates SELF-004)
	Cases      []CaseResult `json:"cases"`
}

// FullscreenReport is gui.fullscreen_result (spec §16.4): what the GUI's full-screen alert
// achieved ("focused", "shown" when the toolkit cannot tell whether the compositor gave it focus,
// "failed") and how long it took to show. It is journaled as response.executed of the
// alert_fullscreen action, reported_by gui. The GUI is a low-trust peer (same UID as the
// browser): the report only adds a record, once per alert, and changes no state.
type FullscreenReport struct {
	AlertID   string  `json:"alert_id"`
	Result    string  `json:"result"`
	LatencyMS float64 `json:"latency_ms"`
}
