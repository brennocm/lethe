package gui

import (
	"fmt"
	"sort"
	"strings"

	"lethe/internal/contracts"
	"lethe/internal/i18n"
)

// What the panel shows, computed from the status and the events without Fyne (tested alone).

// Categories of the check grid, in display order (spec §9).
var Categories = []string{"NET", "DNS", "TUN", "HOST", "PER", "SELF"}

// Row is one check in the grid: the worst unresolved alert of that check, or ok.
type Row struct {
	ID, Title, Severity, State string
	Count                      int
}

// Grid groups every check by category.
func Grid(st contracts.Status, lang string) map[string][]Row {
	worst := map[string]contracts.AlertView{}
	for _, a := range st.Alerts {
		if a.State == "resolved" {
			continue
		}
		if w, ok := worst[a.Check]; !ok || contracts.Severity(a.Severity).Rank() > contracts.Severity(w.Severity).Rank() {
			worst[a.Check] = a
		}
	}
	out := map[string][]Row{}
	for _, id := range i18n.CheckIDs() {
		cat, _, _ := strings.Cut(id, "-")
		r := Row{ID: id, Title: i18n.CheckText(lang, id).Title, State: i18n.UI(lang, "ok_state")}
		if a, ok := worst[id]; ok {
			r.Severity, r.State, r.Count = a.Severity, a.State, a.Count
		}
		out[cat] = append(out[cat], r)
	}
	return out
}

// FullscreenAlert is the alert that takes the screen: the oldest open, unacknowledged CRITICAL.
func FullscreenAlert(st contracts.Status) (contracts.AlertView, bool) {
	var best contracts.AlertView
	found := false
	for _, a := range st.Alerts {
		if a.Severity != string(contracts.SeverityCritical) || a.Acked || a.State != "open" {
			continue
		}
		if !found || a.FirstSeen.Before(best.FirstSeen) {
			best, found = a, true
		}
	}
	return best, found
}

// AckTarget is the alert the Acknowledge button acts on: the full-screen one, else the most
// severe open one (the newest among equals).
func AckTarget(st contracts.Status) (contracts.AlertView, bool) {
	if a, ok := FullscreenAlert(st); ok {
		return a, true
	}
	var open []contracts.AlertView
	for _, a := range st.Alerts {
		if a.State == "open" && !a.Acked {
			open = append(open, a)
		}
	}
	if len(open) == 0 {
		return contracts.AlertView{}, false
	}
	sort.SliceStable(open, func(i, j int) bool {
		ri, rj := contracts.Severity(open[i].Severity).Rank(), contracts.Severity(open[j].Severity).Rank()
		if ri != rj {
			return ri > rj
		}
		return open[i].LastSeen.After(open[j].LastSeen)
	})
	return open[0], true
}

// OpenCount is the number on the tray icon.
func OpenCount(st contracts.Status) int {
	n := 0
	for _, a := range st.Alerts {
		if a.State == "open" && !a.Acked {
			n++
		}
	}
	return n
}

// Details are the destination and the process of the alert (clear data of its check.alert).
func Details(evs []contracts.Event, id string) string {
	for i := len(evs) - 1; i >= 0; i-- {
		ev := evs[i]
		if ev.AlertID != id || ev.Type != contracts.EvCheckAlert {
			continue
		}
		var parts []string
		if dst := ev.Str("dst"); dst != "" {
			if p, ok := ev.Data["dport"].(float64); ok {
				dst = fmt.Sprintf("%s:%d", dst, int(p))
			}
			if proto := ev.Str("proto"); proto != "" {
				dst = proto + " " + dst
			}
			parts = append(parts, "→ "+dst)
		}
		if ifc := ev.Str("iface"); ifc != "" {
			parts = append(parts, "if "+ifc)
		}
		if p, ok := ev.Data["proc"].(map[string]any); ok {
			name, _ := p["exe"].(string)
			if name == "" {
				name, _ = p["comm"].(string)
			}
			if pid, ok := p["pid"].(float64); ok && name != "" {
				parts = append(parts, fmt.Sprintf("%s (pid %d)", name, int(pid)))
			}
		}
		return strings.Join(parts, " · ")
	}
	return ""
}

// ActionsTaken are the alert's response.executed, in operator words ("Rede bloqueada.").
func ActionsTaken(evs []contracts.Event, id, lang string) []string {
	var out []string
	seen := map[string]bool{}
	for _, ev := range evs {
		if ev.AlertID != id || ev.Type != contracts.EvResponseExecuted || ev.Selftest || ev.Str("reported_by") == "gui" {
			continue
		}
		act := ev.Str("action")
		if act == "" || seen[act] {
			continue
		}
		seen[act] = true
		s := i18n.Text(lang, "actions", act)
		if ok, _ := ev.Data["ok"].(bool); !ok {
			s += " (" + i18n.Text(lang, "actions", "failed") + ")"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Filter keeps the events at or above minSev ("" = all) whose check starts with check.
func Filter(evs []contracts.Event, minSev, check string) []contracts.Event {
	check = strings.ToUpper(strings.TrimSpace(check))
	var out []contracts.Event
	for _, ev := range evs {
		if minSev != "" && (!ev.Severity.Valid() || ev.Severity.Rank() < contracts.Severity(minSev).Rank()) {
			continue
		}
		if check != "" && !strings.HasPrefix(ev.Check, check) {
			continue
		}
		out = append(out, ev)
	}
	return out
}

// MergeEvents keeps the newest max events by seq, without duplicates.
func MergeEvents(a, b []contracts.Event, max int) []contracts.Event {
	seen := map[string]bool{}
	var out []contracts.Event
	for _, ev := range append(append([]contracts.Event{}, a...), b...) {
		k := fmt.Sprintf("%s/%d/%s", ev.Session, ev.Seq, ev.Hash)
		if !seen[k] {
			seen[k] = true
			out = append(out, ev)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if len(out) > max {
		out = out[len(out)-max:]
	}
	return out
}
