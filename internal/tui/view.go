package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"lethe/internal/platform"

	"lethe/internal/contracts"
	"lethe/internal/daemon"
	"lethe/internal/i18n"
)

// ANSI SGR, written by hand: the screens need colour and nothing a styling library adds.
const (
	reset   = "\x1b[0m"
	bold    = "\x1b[1m"
	dim     = "\x1b[2m"
	red     = "\x1b[31m"
	green   = "\x1b[32m"
	yellow  = "\x1b[33m"
	gray    = "\x1b[90m"
	alertBG = "\x1b[41;97m" // white on red: the whole alert screen
)

func colorOf(c string) string {
	switch c {
	case "GREEN":
		return green
	case "YELLOW":
		return yellow
	case "RED":
		return red
	}
	return gray
}

func sevColor(s string) string {
	switch contracts.Severity(s) {
	case contracts.SeverityCritical:
		return red
	case contracts.SeverityWarning:
		return yellow
	}
	return gray
}

// View implements tea.Model.
func (m *Model) View() string {
	if a, ok := m.fullscreen(); ok {
		return m.alertView(a)
	}
	return m.mainView()
}

func (m *Model) t(key string) string { return i18n.UI(m.opt.Lang, key) }

func (m *Model) mainView() string {
	var b []string
	st := m.st
	if m.stErr != nil {
		b = append(b, red+bold+m.t("disconnected")+reset+": "+m.stErr.Error())
	} else {
		head := fmt.Sprintf("%slethe%s  %s%s● %s%s", bold, reset, colorOf(st.Color), bold, st.State, reset)
		if st.Guard != "" {
			head += fmt.Sprintf("  %s: %s", m.t("guard"), st.Guard)
		}
		if st.Session != "" {
			head += fmt.Sprintf("  %s: %s", m.t("session"), st.Session)
			if st.StartedAt != nil {
				head += " (" + span(m.opt.Now().Sub(*st.StartedAt)) + ")"
			}
		}
		b = append(b, head)
		if st.Fingerprint != "" {
			b = append(b, gray+st.Fingerprint+reset)
		}
		if st.Exit != nil {
			e := fmt.Sprintf("%s: %s", m.t("exit"), st.Exit.Path)
			if st.Exit.Country != "" {
				e += " · " + st.Exit.Country
			}
			if st.Exit.ASN != 0 {
				e += fmt.Sprintf(" · AS%d", st.Exit.ASN)
			}
			e += " · " + st.Exit.At.In(m.opt.Loc).Format("15:04:05")
			b = append(b, e)
		}
		if st.Lockdown != nil {
			b = append(b, red+bold+m.t("lockdown")+reset+": "+st.Lockdown.What, "  "+st.Lockdown.Why, "  "+m.t("how_out")+": "+st.Lockdown.Exit)
		}
		var down []string
		for _, s := range st.Sensors {
			if !s.Up {
				down = append(down, s.Source)
			}
		}
		if len(down) > 0 {
			b = append(b, yellow+m.t("sensors_down")+": "+strings.Join(down, ", ")+reset)
		}
	}
	b = append(b, "", bold+m.t("alerts")+reset)
	open := m.openAlerts()
	if len(open) == 0 {
		b = append(b, gray+"  "+m.t("no_alerts")+reset)
	}
	for _, a := range open {
		b = append(b, fmt.Sprintf("  %s%-8s%s %-8s %s ×%d  %s", sevColor(a.Severity), a.Severity, reset, a.Check,
			i18n.CheckText(m.opt.Lang, a.Check).Title, a.Count, gray+a.ID+reset))
	}
	foot := m.footer()
	var logs []string
	if m.opt.Logs != nil {
		logs = m.opt.Logs.Last(3)
	}
	room := m.h - len(b) - 3 - len(foot) - len(logs)
	if len(logs) > 0 {
		room--
	}
	b = append(b, "", bold+m.t("events")+reset)
	evs := m.events
	if room < 1 {
		room = 1
	}
	if len(evs) > room {
		evs = evs[len(evs)-room:]
	}
	if len(evs) == 0 {
		b = append(b, gray+"  "+m.t("no_events")+reset)
	}
	for _, ev := range evs {
		b = append(b, m.eventLine(ev))
	}
	if len(logs) > 0 {
		b = append(b, gray+m.t("logs")+":"+reset)
		for _, l := range logs {
			b = append(b, gray+"  "+clip(l, m.w-2)+reset)
		}
	}
	b = append(b, "")
	for _, f := range foot {
		b = append(b, clip(f, m.w+utf8.RuneCountInString(f)-utf8.RuneCountInString(stripANSI(f))))
	}
	return strings.Join(b, "\n")
}

func (m *Model) eventLine(ev contracts.Event) string {
	s := fmt.Sprintf("  %s %s%-8s%s %-22s", ev.TS.In(m.opt.Loc).Format("15:04:05"), sevColor(string(ev.Severity)), string(ev.Severity), reset, ev.Type)
	if ev.Check != "" {
		s += " " + ev.Check + " " + i18n.CheckText(m.opt.Lang, ev.Check).Title
	}
	if ev.Selftest {
		s += gray + " [selftest]" + reset
	}
	return s
}

// footer is the prompt of the current mode, or the flash and the keys.
func (m *Model) footer() []string {
	switch m.mode {
	case modePanicAsk:
		return []string{red + bold + m.t("panic_ask") + reset}
	case modeAckReason:
		return []string{m.target.Check + " " + m.target.ID, m.t("ack_reason") + string(m.reason) + "█"}
	case modeAckPass, modeSelftestPass:
		return []string{m.t("ack_pass") + strings.Repeat("•", utf8.RuneCount(m.pass.bytes())) + "█"}
	case modeSelftestAsk:
		return []string{m.t("selftest_ask"), m.t("selftest_ask2")}
	}
	var out []string
	if m.flash != "" {
		out = append(out, bold+m.flash+reset)
	}
	return append(out, dim+m.t("keys")+reset)
}

// alertView is the full-screen alert (spec §16.3): red, the title, what it means, destination
// and process, the actions already taken and what to do now.
func (m *Model) alertView(a daemon.AlertView) string {
	tx := i18n.CheckText(m.opt.Lang, a.Check)
	lines := []string{
		"",
		bold + "  " + m.t("alert_banner") + " · " + a.Check + " · " + a.ID,
		"",
		bold + "  " + tx.Title,
	}
	lines = append(lines, wrap(tx.Meaning, m.w-4, "  ")...)
	if d := m.details(a.ID); d != "" {
		lines = append(lines, "", "  "+d)
	}
	if acts := m.actionsTaken(a.ID); len(acts) > 0 {
		lines = append(lines, "", bold+"  "+m.t("actions_done")+":")
		for _, s := range acts {
			lines = append(lines, "    "+s)
		}
	}
	lines = append(lines, "", bold+"  "+m.t("what_now")+":")
	lines = append(lines, wrap(tx.Todo, m.w-4, "  ")...)
	if l := m.st.Lockdown; l != nil {
		lines = append(lines, "", bold+"  "+m.t("lockdown")+": "+l.What)
		lines = append(lines, wrap(m.t("how_out")+": "+l.Exit, m.w-4, "  ")...)
	}
	foot := m.footer()
	if m.mode == modeNormal {
		foot = nil
		if m.flash != "" {
			foot = append(foot, m.flash)
		}
		foot = append(foot, m.t("alert_keys"))
	}
	for len(lines) < m.h-len(foot)-1 {
		lines = append(lines, "")
	}
	for _, f := range foot {
		lines = append(lines, "  "+f)
	}
	// every line padded to the width, so the red fills the screen
	out := make([]string, len(lines))
	for i, l := range lines {
		plain := stripANSI(l)
		pad := m.w - utf8.RuneCountInString(plain)
		if pad < 0 {
			pad = 0
		}
		weight := ""
		if strings.HasPrefix(l, bold) {
			weight = bold
		}
		out[i] = alertBG + weight + plain + strings.Repeat(" ", pad) + reset
	}
	return strings.Join(out, "\n")
}

// details are the destination and the process of the alert's last check.alert event: clear
// data only (the sealed fields never reach the TUI).
func (m *Model) details(id string) string {
	for i := len(m.events) - 1; i >= 0; i-- {
		ev := m.events[i]
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
		// process names and paths come from other programs: no control sequence reaches the
		// terminal (an exe named "\x1b]0;..." would drive it)
		return platform.TermSafe(strings.Join(parts, " · "))
	}
	return ""
}

// actionsTaken lists the response.executed events of the alert, in operator words.
func (m *Model) actionsTaken(id string) []string {
	var out []string
	seen := map[string]bool{}
	for _, ev := range m.events {
		if ev.AlertID != id || ev.Type != contracts.EvResponseExecuted || ev.Selftest {
			continue
		}
		act := ev.Str("action")
		if act == "" || seen[act] {
			continue
		}
		seen[act] = true
		s := i18n.Text(m.opt.Lang, "actions", act)
		if ok, _ := ev.Data["ok"].(bool); !ok {
			s += " (" + i18n.Text(m.opt.Lang, "actions", "failed") + ")"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func span(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Truncate(time.Second)
	h, mi, s := int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60
	return fmt.Sprintf("%02d:%02d:%02d", h, mi, s)
}

func clip(s string, n int) string {
	if n <= 0 || utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func wrap(s string, width int, indent string) []string {
	if width < 20 {
		width = 20
	}
	var out []string
	line := ""
	for _, w := range strings.Fields(s) {
		if line != "" && utf8.RuneCountInString(line)+1+utf8.RuneCountInString(w) > width {
			out = append(out, indent+line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		out = append(out, indent+line)
	}
	return out
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
