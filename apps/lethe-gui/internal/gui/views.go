package gui

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"

	"lethe/internal/contracts"
	"lethe/internal/i18n"
)

// What the new pages show (ADR 0016), computed from the status and the events only: nothing
// here is measured by the GUI, and no baseline value reaches it.

// Area is the state of a group of checks: the worst unresolved severity ("" = fine), how many
// alerts are open and how many occurrences they counted in the session.
type Area struct {
	Worst       string
	Open, Count int
}

// AreaOf sums the unresolved alerts of the checks whose ID starts with one of prefixes
// ("NET-001" names one check, "DNS-" a category).
func AreaOf(st contracts.Status, prefixes ...string) Area {
	var a Area
	for _, al := range st.Alerts {
		if al.State == "resolved" || !hasPrefix(al.Check, prefixes) {
			continue
		}
		a.Open++
		a.Count += max(al.Count, 1)
		if contracts.Severity(al.Severity).Rank() > contracts.Severity(a.Worst).Rank() {
			a.Worst = al.Severity
		}
	}
	return a
}

// OpenWorst is the worst severity among the open, unacknowledged alerts ("" = none): the
// tone of the open-alerts counter, which counts the same alerts (OpenCount).
func OpenWorst(st contracts.Status) string {
	worst := ""
	for _, al := range st.Alerts {
		if al.State == "open" && !al.Acked && contracts.Severity(al.Severity).Rank() > contracts.Severity(worst).Rank() {
			worst = al.Severity
		}
	}
	return worst
}

// CountOf counts the occurrences of the checks in the session, resolved alerts included
// (NET-002 attempts the guard stopped).
func CountOf(st contracts.Status, prefixes ...string) int {
	n := 0
	for _, al := range st.Alerts {
		if hasPrefix(al.Check, prefixes) {
			n += max(al.Count, 1)
		}
	}
	return n
}

func hasPrefix(id string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// OverviewAreas are the four summary cards of the overview: key (texts area_<key>) and checks.
var OverviewAreas = []struct {
	Key    string
	Icon   fyne.Resource
	Checks []string
}{
	{"leak", theme.UploadIcon(), []string{"NET-001", "NET-002", "NET-003", "NET-004", "NET-012"}},
	{"dns", theme.SearchIcon(), []string{"DNS-"}},
	{"tun", theme.VisibilityOffIcon(), []string{"TUN-"}},
	{"host", theme.ComputerIcon(), []string{"HOST-", "PER-"}},
}

// Vectors are the ways an identity leaks, as the DNS & IP page lists them (texts vec_<key>).
var Vectors = []struct {
	Key    string
	Icon   fyne.Resource
	Checks []string
}{
	{"ipv4", theme.UploadIcon(), []string{"NET-001", "NET-004"}},
	{"ipv6", theme.UploadIcon(), []string{"NET-003"}},
	{"dns", theme.SearchIcon(), []string{"DNS-001", "DNS-002", "DNS-003", "DNS-004"}},
	{"webrtc", theme.MediaVideoIcon(), []string{"NET-012", "PER-002"}},
	{"lan", theme.ComputerIcon(), []string{"NET-009", "NET-014"}},
	{"exit", theme.AccountIcon(), []string{"NET-011", "PER-001", "TUN-006"}},
}

// Responses are the default actions of spec §10.4 for a guard mode, by severity.
func Responses(guard string) (warning, critical []string) {
	warning = []string{"alert_tray", "alert_sound"}
	switch guard {
	case "strict", "reactive":
		critical = []string{"block_all", "kill_processes", "alert_fullscreen", "alert_sound"}
	default:
		critical = []string{"alert_fullscreen", "alert_sound"}
	}
	return warning, critical
}

// EventRow is one line of the events table.
type EventRow struct {
	Time, Event, Proc, Proto, Dst, Iface, Status string
	Tone                                         tone
}

// RowOf is ev as the events table shows it. Text from the daemon is cleaned of control and
// bidi characters before it is drawn.
func RowOf(ev contracts.Event, lang string) EventRow {
	t := func(k string) string { return i18n.UI(lang, k) }
	r := EventRow{Time: ev.TS.Local().Format("15:04:05.000"), Event: TypeName(ev.Type, lang), Tone: toneMuted}
	if ev.Check != "" {
		r.Event = ev.Check + "  " + i18n.CheckText(lang, ev.Check).Title
	}
	if p, ok := ev.Data["proc"].(map[string]any); ok {
		name, _ := p["exe"].(string)
		if name == "" {
			name, _ = p["comm"].(string)
		}
		if name != "" {
			r.Proc = filepath.Base(name)
		}
		if pid, ok := p["pid"].(float64); ok {
			r.Proc += fmt.Sprintf(" [%d]", int(pid))
		}
	}
	r.Proto = strings.ToUpper(ev.Str("proto"))
	if port, ok := ev.Data["dport"].(float64); ok {
		r.Proto += fmt.Sprintf("/%d", int(port))
	}
	r.Dst, r.Iface = ev.Str("dst"), ev.Str("iface")
	switch {
	case ev.Type == contracts.EvCheckAlert && ev.Check == "NET-002":
		r.Status, r.Tone = t("status_blocked"), toneWarn
	case ev.Type == contracts.EvCheckAlert && ev.Severity == contracts.SeverityCritical:
		r.Status, r.Tone = t("status_crit"), toneBad
	case ev.Type == contracts.EvCheckAlert && ev.Severity == contracts.SeverityWarning:
		r.Status, r.Tone = t("status_warn"), toneWarn
	case ev.Type == contracts.EvCheckResolved:
		r.Status, r.Tone = t("status_resolved"), toneOK
	case ev.Type == contracts.EvResponseExecuted:
		r.Status = i18n.Text(lang, "actions", ev.Str("action"))
		r.Tone = toneGold
	case ev.Type == contracts.EvPanicEngaged:
		r.Status, r.Tone = t("state_panic"), toneBad
	default:
		r.Status = string(ev.Severity)
	}
	if ev.Selftest {
		r.Status += " · selftest"
	}
	for _, s := range []*string{&r.Event, &r.Proc, &r.Proto, &r.Dst, &r.Iface, &r.Status} {
		*s = clean(*s)
	}
	return r
}

// TypeName is an event type in the operator's words (texts evtype_<type>), or the type itself.
func TypeName(t contracts.EventType, lang string) string {
	key := "evtype_" + strings.ReplaceAll(string(t), ".", "_")
	if s := i18n.UI(lang, key); s != key {
		return s
	}
	return string(t)
}

// clean drops the characters a report may not draw (control, bidi), as readReport does.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' ' // one line per cell
		case !shown(r):
			return -1
		}
		return r
	}, s)
}

// Ifaces are the interfaces named by the events, sorted.
func Ifaces(evs []contracts.Event) []string {
	seen := map[string]bool{}
	var out []string
	for _, ev := range evs {
		if i := clean(ev.Str("iface")); i != "" && !seen[i] {
			seen[i] = true
			out = append(out, i)
		}
	}
	sort.Strings(out)
	return out
}

// EventFilter is what the events page filters by.
type EventFilter struct {
	MinSev, Check, Iface string
	LeaksOnly            bool // only check.alert of network and DNS checks
}

// FilterEvents keeps the events that pass f.
func FilterEvents(evs []contracts.Event, f EventFilter) []contracts.Event {
	var out []contracts.Event
	for _, ev := range Filter(evs, f.MinSev, f.Check) {
		if f.Iface != "" && clean(ev.Str("iface")) != f.Iface {
			continue
		}
		if f.LeaksOnly && (ev.Type != contracts.EvCheckAlert || !hasPrefix(ev.Check, []string{"NET-", "DNS-"})) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// Field is one line of an event's detail.
type Field struct{ Key, Value string }

// EventFields are ev's data as key and value, sorted. A sealed field (sensitive key) says so
// and never shows its ciphertext.
func EventFields(ev contracts.Event, lang string) []Field {
	var out []Field
	for k, v := range ev.Data {
		var s string
		switch x := v.(type) {
		case string:
			s = x
		case float64:
			s = fmt.Sprintf("%g", x)
		case bool:
			s = fmt.Sprintf("%t", x)
		case map[string]any:
			if _, sealed := x["enc"]; sealed {
				s = i18n.UI(lang, "ev_sealed")
				break
			}
			var parts []string
			for kk, vv := range x {
				parts = append(parts, fmt.Sprintf("%s=%v", kk, vv))
			}
			sort.Strings(parts)
			s = strings.Join(parts, " ")
		case []any:
			var parts []string
			for _, vv := range x {
				parts = append(parts, fmt.Sprint(vv))
			}
			s = strings.Join(parts, ", ")
		default:
			s = fmt.Sprint(x)
		}
		out = append(out, Field{Key: clean(k), Value: clean(s)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// ServerRow is one DNS server of the last test, as the DNS & IP page lists it.
type ServerRow struct {
	Server, Country, ASN, Status string
	Tone                         tone
}

// ServerRows are the DNS test's servers. One that is a baseline value shows the field it
// matched, never the address, and is marked as the real network.
func ServerRows(r contracts.DNSLeakResult, lang string) []ServerRow {
	t := func(k string) string { return i18n.UI(lang, k) }
	var out []ServerRow
	for _, d := range r.DNS {
		row := ServerRow{Server: clean(d.IP), Country: clean(d.Country), ASN: clean(d.ASN), Status: t("dns_row_ok"), Tone: toneOK}
		switch {
		case d.Matched != "":
			row.Server = fmt.Sprintf(t("dns_real"), clean(d.Matched))
			row.Status, row.Tone = t("dns_row_leak"), toneBad
		case r.Exit != nil && d.Country != "" && r.Exit.Country != "" && d.Country != r.Exit.Country:
			row.Status, row.Tone = t("dns_row_suspect"), toneWarn
		}
		out = append(out, row)
	}
	return out
}

// SensorsUp counts the sensors with a heartbeat.
func SensorsUp(st contracts.Status) (up, total int) {
	for _, s := range st.Sensors {
		total++
		if s.Up {
			up++
		}
	}
	return up, total
}
