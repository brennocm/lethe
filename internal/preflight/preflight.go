// Package preflight runs the pre-arm verification of spec §9.8: the automatic state checks over
// a discovery snapshot, the profile warnings and the operator's manual checklist.
package preflight

import (
	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/profile"
)

// Result of a preflight (or of one check in it).
const (
	Pass = "PASS"
	Warn = "WARN"
	Fail = "FAIL"
)

// Item is one question of the manual checklist.
type Item struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// Manual is the human checklist of spec §9.8, in order. Each answer goes to the journal.
var Manual = []Item{
	{"MAN-1", "Nenhuma conta pessoal logada no navegador ou nos apps desta sessão"},
	{"MAN-2", "O username da persona não é reutilizado de nenhuma outra identidade"},
	{"MAN-3", "O celular pessoal não está na mesma rede, ou está em modo avião"},
	{"MAN-4", "Os arquivos recebidos de alvos serão abertos só em VM offline"},
	{"MAN-5", "O horário da operação não segue o padrão do expediente pessoal"},
}

// Answer is the operator's reply to one manual item.
type Answer struct {
	ID string `json:"id"`
	OK bool   `json:"ok"`
}

// CheckResult is one automatic check.
type CheckResult struct {
	ID       string           `json:"id"`
	Status   string           `json:"status"`
	Findings []map[string]any `json:"findings"`
}

// Report is the preflight outcome (schema: preflight).
type Report struct {
	Result   string        `json:"result"`
	Checks   []CheckResult `json:"checks"`
	Warnings []string      `json:"warnings"`
	Manual   []Answer      `json:"manual"`
	// ManualSkipped is true with --no-manual: the checklist was not asked (WARN).
	ManualSkipped bool `json:"manual_skipped"`
}

// Input is everything one preflight looks at.
type Input struct {
	Snapshot *discovery.Snapshot
	Profile  *profile.Profile
	Warnings []string // profile.Load warnings
	Manual   []Answer // nil = not asked
}

// Run evaluates the automatic checks implemented so far and folds in the manual answers.
// A negative or missing manual answer is FAIL (fail-closed, ADR 0006).
func Run(in Input) Report {
	r := Report{Result: Pass, Checks: []CheckResult{}, Warnings: append([]string{}, in.Warnings...), Manual: []Answer{}}
	raise := func(s string) {
		if rank(s) > rank(r.Result) {
			r.Result = s
		}
	}
	expectV6 := in.Profile != nil && in.Profile.Expect.IPv6
	add := func(id string, fs []checks.Finding) {
		c := CheckResult{ID: id, Status: Pass, Findings: []map[string]any{}}
		for _, f := range fs {
			c.Findings = append(c.Findings, f.Data)
			switch f.Severity {
			case contracts.SeverityCritical:
				c.Status = Fail
			case contracts.SeverityWarning:
				if c.Status == Pass {
					c.Status = Warn
				}
			}
		}
		raise(c.Status)
		r.Checks = append(r.Checks, c)
	}
	egressType := ""
	if in.Profile != nil {
		egressType = in.Profile.Egress.Type
	}
	add("NET-003", checks.NET003{}.Evaluate(in.Snapshot, expectV6))
	add("NET-004", checks.NET004{}.Evaluate(in.Snapshot))
	add("TUN-001", checks.TUN001{}.Evaluate(checks.TunnelExpect{Ifaces: TunnelIfaces(in.Snapshot), Require: checks.RequiresTunnel(egressType)}, in.Snapshot))
	add("TUN-005", checks.TUN005{}.Evaluate(in.Snapshot))
	add("TUN-007", checks.TUN007{}.Evaluate(in.Snapshot))
	for _, u := range in.Snapshot.Unavailable {
		r.Warnings = append(r.Warnings, "source unavailable: "+u)
	}
	if len(r.Warnings) > 0 {
		raise(Warn)
	}
	if in.Manual == nil {
		r.ManualSkipped = true
		raise(Warn)
		return r
	}
	got := map[string]bool{}
	for _, a := range in.Manual {
		got[a.ID] = a.OK
	}
	for _, it := range Manual {
		ok, answered := got[it.ID]
		r.Manual = append(r.Manual, Answer{ID: it.ID, OK: answered && ok})
		if !answered || !ok {
			raise(Fail)
		}
	}
	return r
}

func rank(s string) int {
	switch s {
	case Fail:
		return 2
	case Warn:
		return 1
	}
	return 0
}

// TunnelIfaces lists the tunnel interfaces of a snapshot (the TUN-001 expectation at arm).
func TunnelIfaces(s *discovery.Snapshot) []string {
	var out []string
	for _, t := range s.Tunnels {
		out = append(out, t.Iface)
	}
	return out
}
