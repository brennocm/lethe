package checks

import "lethe/internal/contracts"

// SELF006 is "passphrase attempts" (spec §9.6): 5 wrong proofs in 5 minutes on sensitive
// methods. The response depends on the guard (spec §10.6 item 3): panic under strict and
// reactive, a 5-minute lock of the sensitive methods (no network block) under off.
type SELF006 struct{}

func (SELF006) ID() string { return "SELF-006" }

var self006Meta = meta{kind: Passive, sev: contracts.SeverityCritical, sources: []SourceID{SrcIPC}}

func (SELF006) Kind() Kind                          { return self006Meta.Kind() }
func (SELF006) DefaultSeverity() contracts.Severity { return self006Meta.DefaultSeverity() }
func (SELF006) Sources() []SourceID                 { return self006Meta.Sources() }
func (SELF006) SelfTestCases() []string             { return self006Meta.SelfTestCases() }

// Finding reports the exhausted budget. locked is how long the sensitive methods stay refused
// (0 when the guard panics instead).
func (SELF006) Finding(failures int, window, locked float64) Finding {
	return Finding{Check: "SELF-006", Severity: contracts.SeverityCritical, Data: map[string]any{
		"failures": failures, "window_s": window, "locked_s": locked,
	}}
}
