// Package report turns a verified session journal into the session report (spec §14.5).
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"lethe/internal/contracts"
	"lethe/internal/journal"
)

// Report is the machine-readable report (schema: report).
type Report struct {
	Session      string         `json:"session"`
	Operation    string         `json:"operation,omitempty"`
	Persona      string         `json:"persona,omitempty"`
	Operator     string         `json:"operator,omitempty"`
	ProfileHash  string         `json:"profile_sha256,omitempty"`
	BaselineHash string         `json:"baseline_sha256,omitempty"`
	GuardMode    string         `json:"guard_mode,omitempty"`
	Start        time.Time      `json:"start"`
	End          time.Time      `json:"end"`
	DurationSec  float64        `json:"duration_s"`
	GreenPercent float64        `json:"green_percent"`
	Timeline     []Interval     `json:"timeline"`
	Alerts       []Alert        `json:"alerts"`
	Responses    []Response     `json:"responses"`
	Preflight    *Preflight     `json:"preflight,omitempty"`
	Selftest     map[string]any `json:"selftest,omitempty"`
	Forced       []string       `json:"forced,omitempty"`
	Integrity    journal.Result `json:"integrity"`
	PublicKey    string         `json:"public_key"`
	Warnings     []string       `json:"warnings"`
}

// Interval is a span of time in one global color.
type Interval struct {
	Color string    `json:"color"`
	From  time.Time `json:"from"`
	To    time.Time `json:"to"`
}

// Alert is one alert with its whole lifecycle.
type Alert struct {
	ID           string            `json:"id"`
	Check        string            `json:"check"`
	Severity     string            `json:"severity"`
	First        time.Time         `json:"first"`
	Last         time.Time         `json:"last"`
	Count        int               `json:"count"`
	Acknowledged bool              `json:"acknowledged"`
	AckReason    string            `json:"ack_reason,omitempty"`
	Resolved     bool              `json:"resolved"`
	Detail       map[string]string `json:"detail,omitempty"`
}

// Response is one executed response action.
type Response struct {
	TS        time.Time `json:"ts"`
	Action    string    `json:"action"`
	OK        bool      `json:"ok"`
	LatencyMS float64   `json:"latency_ms"`
	Error     string    `json:"error,omitempty"`
	AlertID   string    `json:"alert_id,omitempty"`
}

// Preflight summarizes the preflight of the session.
type Preflight struct {
	Result      string            `json:"result"`
	ManualItems map[string]string `json:"manual_items,omitempty"`
}

// Options control what the report reveals.
type Options struct {
	IncludeSensitive bool // requires s.UnlockSensitive beforehand
}

// detailKeys are copied from the first event of an alert into the report.
var detailKeys = []string{"iface", "proto", "dst", "dport", "qname", "ssid", "reason"}

// Build assembles a report from a verified session.
func Build(s *journal.Session, res journal.Result, opt Options) (Report, error) {
	if len(s.Events) == 0 {
		return Report{}, fmt.Errorf("empty session")
	}
	first, last := s.Events[0], s.Events[len(s.Events)-1]
	r := Report{
		Session: s.ID, Operation: first.Str("operation"), Persona: first.Str("persona"), Operator: first.Str("operator"),
		ProfileHash: first.Str("profile_sha256"), BaselineHash: first.Str("baseline_sha256"), GuardMode: first.Str("guard_mode"),
		Start: first.TS, End: last.TS, Integrity: res, PublicKey: first.Str("pubkey"),
		Timeline: []Interval{}, Alerts: []Alert{}, Responses: []Response{}, Warnings: res.Warnings(),
	}
	if r.Warnings == nil {
		r.Warnings = []string{}
	}
	r.DurationSec = r.End.Sub(r.Start).Seconds()
	alerts := map[string]*Alert{}
	var order []string
	for _, ev := range s.Events {
		switch ev.Type {
		case contracts.EvStateChanged:
			r.addColor(ev.Str("color"), ev.TS)
		case contracts.EvCheckAlert:
			if ev.AlertID == "" {
				continue
			}
			a, ok := alerts[ev.AlertID]
			if !ok {
				a = &Alert{ID: ev.AlertID, Check: ev.Check, Severity: string(ev.Severity), First: ev.TS, Detail: detail(s, ev, opt)}
				alerts[ev.AlertID] = a
				order = append(order, ev.AlertID)
			}
			if ev.Severity.Rank() > contracts.Severity(a.Severity).Rank() {
				a.Severity = string(ev.Severity)
			}
			a.Last = ev.TS
			a.Count++
		case contracts.EvAlertAck:
			if a := alerts[ev.AlertID]; a != nil {
				a.Acknowledged, a.AckReason = true, ev.Str("reason")
			}
		case contracts.EvCheckResolved:
			if a := alerts[ev.AlertID]; a != nil {
				a.Resolved = true
			}
		case contracts.EvResponseExecuted:
			ok, _ := ev.Data["ok"].(bool)
			lat, _ := ev.Data["latency_ms"].(float64)
			r.Responses = append(r.Responses, Response{TS: ev.TS, Action: ev.Str("action"), OK: ok, LatencyMS: lat, Error: ev.Str("error"), AlertID: ev.AlertID})
		case contracts.EvPreflightResult:
			if r.Preflight == nil {
				r.Preflight = &Preflight{}
			}
			r.Preflight.Result = ev.Str("result")
		case contracts.EvPreflightManualItem:
			if r.Preflight == nil {
				r.Preflight = &Preflight{}
			}
			if r.Preflight.ManualItems == nil {
				r.Preflight.ManualItems = map[string]string{}
			}
			r.Preflight.ManualItems[ev.Str("item")] = ev.Str("answer")
		case contracts.EvSelftestResult:
			r.Selftest = ev.Data
		case contracts.EvOperatorForce:
			r.Forced = append(r.Forced, ev.Str("reason"))
		}
	}
	r.closeTimeline(r.End)
	for _, id := range order {
		a := alerts[id]
		r.Alerts = append(r.Alerts, *a)
		if a.Severity == string(contracts.SeverityCritical) && !a.Acknowledged {
			r.Warnings = append(r.Warnings, "CRITICAL alert "+a.ID+" ("+a.Check+") was never acknowledged")
		}
	}
	return r, nil
}

func detail(s *journal.Session, ev contracts.Event, opt Options) map[string]string {
	d := map[string]string{}
	for _, k := range detailKeys {
		v, ok := ev.Data[k]
		if !ok {
			continue
		}
		if m, sealed := v.(map[string]any); sealed && m["enc"] == "s1" {
			d[k] = "[cifrado]"
			if opt.IncludeSensitive {
				if pt, err := s.Field(v); err == nil {
					d[k] = pt
				}
			}
			continue
		}
		d[k] = fmt.Sprint(v)
	}
	if exe := ev.ProcExe(); exe != "" {
		d["proc"] = exe
	}
	if len(d) == 0 {
		return nil
	}
	return d
}

func (r *Report) addColor(color string, ts time.Time) {
	if color == "" {
		return
	}
	if n := len(r.Timeline); n > 0 {
		if r.Timeline[n-1].Color == color {
			return
		}
		r.Timeline[n-1].To = ts
	}
	r.Timeline = append(r.Timeline, Interval{Color: color, From: ts})
}

func (r *Report) closeTimeline(end time.Time) {
	if n := len(r.Timeline); n > 0 {
		r.Timeline[n-1].To = end
	}
	var green, total time.Duration
	for _, iv := range r.Timeline {
		d := iv.To.Sub(iv.From)
		total += d
		if iv.Color == "GREEN" {
			green += d
		}
	}
	if total > 0 {
		r.GreenPercent = float64(green) * 100 / float64(total)
	}
}

// WriteJSON renders the report as indented JSON.
func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteMarkdown renders the report as Markdown (pt-BR).
func WriteMarkdown(w io.Writer, r Report) error {
	var b strings.Builder
	f := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	ts := func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05Z") }
	f("# Relatório da sessão %s\n\n", md(r.Session))
	f("| Campo | Valor |\n|---|---|\n")
	f("| Operação | %s |\n| Persona | %s |\n| Operador | %s |\n", dash(r.Operation), dash(r.Persona), dash(r.Operator))
	f("| Modo do guarda | %s |\n| Hash do perfil | %s |\n| Hash da baseline | %s |\n", dash(r.GuardMode), dash(r.ProfileHash), dash(r.BaselineHash))
	f("| Início | %s |\n| Fim | %s |\n| Duração | %s |\n| Tempo em VERDE | %.1f%% |\n\n", ts(r.Start), ts(r.End), time.Duration(r.DurationSec*float64(time.Second)).Round(time.Second), r.GreenPercent)

	f("## Avisos\n\n")
	if len(r.Warnings) == 0 {
		f("Nenhum.\n\n")
	}
	for _, w := range r.Warnings {
		f("- %s\n", md(w))
	}
	if len(r.Warnings) > 0 {
		f("\n")
	}

	f("## Linha do tempo\n\n| Cor | De | Até |\n|---|---|---|\n")
	for _, iv := range r.Timeline {
		f("| %s | %s | %s |\n", md(iv.Color), ts(iv.From), ts(iv.To))
	}
	f("\n## Alertas (%d)\n\n", len(r.Alerts))
	if len(r.Alerts) > 0 {
		f("| ID | Check | Severidade | Primeiro | Ocorrências | Reconhecido | Motivo | Resolvido | Detalhe |\n|---|---|---|---|---|---|---|---|---|\n")
		for _, a := range r.Alerts {
			f("| %s | %s | %s | %s | %d | %s | %s | %s | %s |\n", md(a.ID), md(a.Check), md(a.Severity), ts(a.First), a.Count,
				yes(a.Acknowledged), dash(a.AckReason), yes(a.Resolved), detailString(a.Detail))
		}
	}
	f("\n## Respostas executadas (%d)\n\n", len(r.Responses))
	if len(r.Responses) > 0 {
		f("| Quando | Ação | Resultado | Latência (ms) | Alerta |\n|---|---|---|---|---|\n")
		for _, x := range r.Responses {
			res := "ok"
			if !x.OK {
				res = "erro: " + md(x.Error)
			}
			f("| %s | %s | %s | %.0f | %s |\n", ts(x.TS), md(x.Action), res, x.LatencyMS, dash(x.AlertID))
		}
	}
	f("\n## Preflight\n\n")
	if r.Preflight == nil {
		f("Não registrado.\n")
	} else {
		f("Resultado: **%s**\n", md(r.Preflight.Result))
		keys := make([]string, 0, len(r.Preflight.ManualItems))
		for k := range r.Preflight.ManualItems {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			f("- %s: %s\n", md(k), md(r.Preflight.ManualItems[k]))
		}
	}
	for _, reason := range r.Forced {
		f("\n> **Armado com --force.** Motivo: %s\n", md(reason))
	}
	f("\n## Integridade\n\n")
	f("| Campo | Valor |\n|---|---|\n")
	f("| Eventos | %d |\n| Segmentos | %d |\n| Checkpoints assinados | %d |\n", r.Integrity.Events, r.Integrity.Segments, r.Integrity.Checkpoints)
	f("| Encerrada corretamente | %s |\n| Hash final | `%s` |\n", yes(r.Integrity.Ended), r.Integrity.FinalHash)
	f("| Chave pública | `%s` |\n| Impressão digital | `%s` |\n| Âncora conferida | %s |\n", r.PublicKey, r.Integrity.Fingerprint, yes(r.Integrity.Anchored))
	_, err := io.WriteString(w, b.String())
	return err
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return md(s)
}

// md makes untrusted text (process names, DNS names, operator reasons, error messages) inert in
// Markdown: no links or images (a viewer that fetches them would leak the reader's address), no
// HTML, no emphasis or code spans, and no line breaks that would split a table row.
func md(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '<':
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		case r == '&':
			b.WriteString("&amp;")
		case r == '\n' || r == '\r' || r == '\t':
			b.WriteByte(' ')
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029:
			b.WriteRune('\uFFFD')
		case strings.ContainsRune("\\`*_[]()!|~", r):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func yes(b bool) string {
	if b {
		return "sim"
	}
	return "não"
}

func detailString(d map[string]string) string {
	if len(d) == 0 {
		return "—"
	}
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+d[k])
	}
	return dash(strings.Join(parts, " "))
}
