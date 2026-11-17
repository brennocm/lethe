// Package tui is the terminal interface (spec §16.5): state, alerts and events, with the keys p
// (panic), a (acknowledge), s (selftest) and q (quit without disarming). Under `run --tui` with
// no GUI it is the alert surface: a CRITICAL alert takes the whole screen in red, rings the
// terminal bell every ui.sound_repeat and only goes away when acknowledged with a reason and the
// passphrase. The TUI never decides anything: it shows the daemon's state and sends commands.
package tui

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"lethe/internal/platform"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/sys/unix"

	"lethe/internal/contracts"
	"lethe/internal/daemon"
	"lethe/internal/i18n"
)

// Options configure the model.
type Options struct {
	Lang      string           // ui.language
	BellEvery time.Duration    // ui.sound_repeat (0 = 10 s)
	Bell      io.Writer        // where "\a" goes (the terminal); nil = no bell
	Logs      *Lines           // daemon output shown at the bottom (optional)
	Now       func() time.Time // nil = time.Now
	Tick      time.Duration    // status refresh (0 = 1 s)
	Loc       *time.Location   // clock shown (nil = local time)
}

// Result tells the caller how the TUI ended.
type Result int

// How the TUI ended.
const (
	Quit      Result = iota + 1 // q: leave the session armed
	Interrupt                   // Ctrl-C: the caller disarms, as a signal would
)

type mode int

const (
	modeNormal mode = iota
	modePanicAsk
	modeAckReason
	modeAckPass
	modeSelftestAsk
	modeSelftestPass
)

const maxEvents = 200

// Model is the bubbletea model.
type Model struct {
	be   Backend
	opt  Options
	ctx  context.Context
	stop context.CancelFunc

	st     daemon.Status
	stErr  error
	events []contracts.Event
	sub    <-chan contracts.Event

	mode     mode
	target   daemon.AlertView // alert being acknowledged
	reason   []rune
	pass     *secret
	flash    string
	running  bool // selftest in progress
	w, h     int
	bellFor  string
	lastBell time.Time
	result   Result
}

// New builds the model.
func New(be Backend, opt Options) *Model {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.BellEvery <= 0 {
		opt.BellEvery = 10 * time.Second
	}
	if opt.Loc == nil {
		opt.Loc = time.Local
	}
	if opt.Tick <= 0 {
		opt.Tick = time.Second
	}
	opt.Lang = i18n.Norm(opt.Lang)
	ctx, stop := context.WithCancel(context.Background())
	return &Model{be: be, opt: opt, ctx: ctx, stop: stop, w: 80, h: 24, result: Quit}
}

// Result is how the TUI ended (after the program returns).
func (m *Model) Result() Result { return m.result }

type (
	statusMsg struct {
		st  daemon.Status
		err error
	}
	recentMsg   []contracts.Event
	subMsg      struct{ ch <-chan contracts.Event }
	eventMsg    contracts.Event
	subDoneMsg  struct{}
	tickMsg     time.Time
	flashMsg    string
	selftestMsg struct {
		res daemon.SelftestResult
		err error
	}
)

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(m.fetchStatus(), m.fetchRecent(), m.subscribe(), m.tick())
}

func (m *Model) fetchStatus() tea.Cmd {
	return func() tea.Msg {
		st, err := m.be.Status()
		return statusMsg{st, err}
	}
}

func (m *Model) fetchRecent() tea.Cmd {
	return func() tea.Msg {
		evs, err := m.be.Recent(maxEvents)
		if err != nil {
			return nil
		}
		return recentMsg(evs)
	}
}

func (m *Model) subscribe() tea.Cmd {
	return func() tea.Msg {
		ch, err := m.be.Subscribe(m.ctx)
		if err != nil {
			return subDoneMsg{}
		}
		return subMsg{ch}
	}
}

func wait(ch <-chan contracts.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return subDoneMsg{}
		}
		return eventMsg(ev)
	}
}

func (m *Model) tick() tea.Cmd {
	return tea.Tick(m.opt.Tick, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case statusMsg:
		m.st, m.stErr = msg.st, msg.err
		return m, m.ring()
	case recentMsg:
		m.events = mergeEvents(msg, m.events)
	case subMsg:
		m.sub = msg.ch
		return m, wait(m.sub)
	case eventMsg:
		m.events = mergeEvents(m.events, []contracts.Event{contracts.Event(msg)})
		return m, tea.Batch(wait(m.sub), m.fetchStatus())
	case subDoneMsg:
		m.sub = nil
		if m.ctx.Err() != nil {
			return m, nil
		}
		return m, tea.Tick(2*time.Second, func(time.Time) tea.Msg { return resubscribe{} })
	case resubscribe:
		return m, tea.Batch(m.subscribe(), m.fetchRecent())
	case tickMsg:
		return m, tea.Batch(m.fetchStatus(), m.tick())
	case flashMsg:
		m.flash = string(msg)
		return m, m.fetchStatus()
	case selftestMsg:
		m.running = false
		m.flash = m.selftestText(msg.res, msg.err)
		return m, m.fetchStatus()
	case tea.KeyMsg:
		return m.key(msg)
	}
	return m, nil
}

type resubscribe struct{}

// ring sounds the bell while a full-screen alert waits: at once for a new alert, then every
// ui.sound_repeat.
func (m *Model) ring() tea.Cmd {
	a, ok := m.fullscreen()
	if !ok || m.opt.Bell == nil {
		m.bellFor = ""
		return nil
	}
	now := m.opt.Now()
	if a.ID == m.bellFor && now.Sub(m.lastBell) < m.opt.BellEvery {
		return nil
	}
	m.bellFor, m.lastBell = a.ID, now
	w := m.opt.Bell
	return func() tea.Msg { _, _ = io.WriteString(w, "\a"); return nil }
}

// fullscreen is the alert that takes the screen: the oldest open, unacknowledged CRITICAL.
func (m *Model) fullscreen() (daemon.AlertView, bool) {
	var best daemon.AlertView
	found := false
	for _, a := range m.st.Alerts {
		if a.Severity != string(contracts.SeverityCritical) || a.Acked || a.State != "open" {
			continue
		}
		if !found || a.FirstSeen.Before(best.FirstSeen) {
			best, found = a, true
		}
	}
	return best, found
}

// ackTarget is the alert a acknowledges: the full-screen one, else the most severe open one.
func (m *Model) ackTarget() (daemon.AlertView, bool) {
	if a, ok := m.fullscreen(); ok {
		return a, true
	}
	open := m.openAlerts()
	if len(open) == 0 {
		return daemon.AlertView{}, false
	}
	return open[0], true
}

func (m *Model) openAlerts() []daemon.AlertView {
	var out []daemon.AlertView
	for _, a := range m.st.Alerts {
		if a.State == "open" && !a.Acked {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := contracts.Severity(out[i].Severity).Rank(), contracts.Severity(out[j].Severity).Rank()
		if ri != rj {
			return ri > rj
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

func (m *Model) key(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if k.Type == tea.KeyCtrlC {
		m.result = Interrupt
		return m, m.quit()
	}
	switch m.mode {
	case modePanicAsk:
		m.mode = modeNormal
		if s := strings.ToLower(k.String()); s == "s" || s == "y" {
			return m, m.doPanic()
		}
		m.flash = ""
		return m, nil
	case modeAckReason:
		return m.editReason(k)
	case modeAckPass, modeSelftestPass:
		return m.editPass(k)
	case modeSelftestAsk:
		m.mode = modeNormal
		m.flash = ""
		switch k.String() {
		case "c":
			m.mode, m.pass = modeSelftestPass, newSecret()
		case "r":
			return m, m.doSelftest(false, nil)
		}
		return m, nil
	}
	_, alert := m.fullscreen()
	switch k.String() {
	case "p":
		m.mode, m.flash = modePanicAsk, ""
	case "a":
		a, ok := m.ackTarget()
		if !ok {
			m.flash = i18n.UI(m.opt.Lang, "no_alerts")
			return m, nil
		}
		m.target, m.reason, m.mode, m.flash = a, nil, modeAckReason, ""
	case "s":
		if !m.running && !alert {
			m.mode, m.flash = modeSelftestAsk, ""
		}
	case "q":
		if !alert { // the alert surface only goes away with an acknowledgement
			m.result = Quit
			return m, m.quit()
		}
	}
	return m, nil
}

func (m *Model) quit() tea.Cmd {
	m.stop()
	if m.pass != nil {
		m.pass.wipe()
		m.pass = nil
	}
	return tea.Quit
}

func (m *Model) editReason(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.Type {
	case tea.KeyEsc:
		m.mode = modeNormal
	case tea.KeyEnter:
		critical := m.target.Severity == string(contracts.SeverityCritical)
		if critical && strings.TrimSpace(string(m.reason)) == "" {
			return m, nil // a CRITICAL needs a reason
		}
		if !critical {
			m.mode = modeNormal
			return m, m.doAck(m.target.ID, string(m.reason), nil)
		}
		m.mode, m.pass = modeAckPass, newSecret()
	case tea.KeyBackspace:
		if len(m.reason) > 0 {
			m.reason = m.reason[:len(m.reason)-1]
		}
	case tea.KeyRunes, tea.KeySpace:
		if len(m.reason) < 200 {
			m.reason = append(m.reason, k.Runes...)
		}
	}
	return m, nil
}

func (m *Model) editPass(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.Type {
	case tea.KeyEsc:
		m.pass.wipe()
		m.pass, m.mode = nil, modeNormal
	case tea.KeyEnter:
		p := m.pass
		m.pass = nil
		if m.mode == modeSelftestPass {
			m.mode = modeNormal
			return m, m.doSelftest(true, p)
		}
		m.mode = modeNormal
		return m, m.doAck(m.target.ID, string(m.reason), p)
	case tea.KeyBackspace:
		m.pass.backspace()
	case tea.KeyRunes, tea.KeySpace:
		for _, r := range k.Runes {
			m.pass.add(r)
		}
	}
	return m, nil
}

func (m *Model) doPanic() tea.Cmd {
	lang := m.opt.Lang
	return func() tea.Msg {
		if err := m.be.Panic(); err != nil {
			return flashMsg("pânico: " + err.Error())
		}
		return flashMsg(i18n.UI(lang, "panic_ok"))
	}
}

func (m *Model) doAck(id, reason string, p *secret) tea.Cmd {
	lang := m.opt.Lang
	return func() tea.Msg {
		var b []byte
		if p != nil {
			b = p.bytes()
			defer p.wipe()
		}
		if err := m.be.Ack(id, reason, b); err != nil {
			return flashMsg(id + ": " + err.Error())
		}
		return flashMsg(i18n.UI(lang, "ack_ok"))
	}
}

func (m *Model) doSelftest(full bool, p *secret) tea.Cmd {
	m.running = true
	m.flash = i18n.UI(m.opt.Lang, "selftest_running")
	return func() tea.Msg {
		var b []byte
		if p != nil {
			b = p.bytes()
			defer p.wipe()
		}
		res, err := m.be.Selftest(m.ctx, full, b)
		return selftestMsg{res, err}
	}
}

func (m *Model) selftestText(r daemon.SelftestResult, err error) string {
	if err != nil {
		return "selftest: " + err.Error()
	}
	key := "selftest_passed"
	if !r.Passed {
		key = "selftest_failed"
	}
	var bad []string
	for _, c := range r.Cases {
		if c.Result == "FAIL" {
			bad = append(bad, c.ID)
		}
	}
	s := i18n.UI(m.opt.Lang, key)
	if len(bad) > 0 {
		s += ": " + strings.Join(bad, ", ")
	}
	return s
}

// mergeEvents keeps the newest maxEvents, ordered by seq, without duplicates.
func mergeEvents(a, b []contracts.Event) []contracts.Event {
	seen := map[string]bool{}
	var out []contracts.Event
	for _, ev := range append(append([]contracts.Event{}, a...), b...) {
		k := fmt.Sprintf("%s/%d/%s", ev.Session, ev.Seq, ev.Hash)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Seq != out[j].Seq {
			return out[i].Seq < out[j].Seq
		}
		return out[i].TS.Before(out[j].TS)
	})
	if len(out) > maxEvents {
		out = out[len(out)-maxEvents:]
	}
	return out
}

// secret is the passphrase being typed: a fixed buffer, locked in memory and wiped after use.
type secret struct {
	b []byte
	n int
}

func newSecret() *secret {
	s := &secret{b: make([]byte, 256)}
	_ = unix.Mlock(s.b) // best effort (§19.3)
	return s
}

func (s *secret) add(r rune) {
	var tmp [utf8.UTFMax]byte
	n := utf8.EncodeRune(tmp[:], r)
	if s.n+n <= len(s.b) {
		copy(s.b[s.n:], tmp[:n])
		s.n += n
	}
	clear(tmp[:])
}

func (s *secret) backspace() {
	for s.n > 0 {
		s.n--
		c := s.b[s.n]
		s.b[s.n] = 0
		if c&0xc0 != 0x80 { // stop at the first byte of the rune
			return
		}
	}
}

func (s *secret) bytes() []byte { return s.b[:s.n] }

func (s *secret) wipe() {
	clear(s.b)
	_ = unix.Munlock(s.b)
	s.n = 0
}

// Lines is a goroutine-safe ring of the daemon's output lines.
type Lines struct {
	mu   sync.Mutex
	buf  []string
	part string
	max  int
}

// NewLines keeps the last n lines.
func NewLines(n int) *Lines { return &Lines{max: n} }

// Write implements io.Writer.
func (l *Lines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.part + string(p)
	parts := strings.Split(s, "\n")
	l.part = parts[len(parts)-1]
	for _, line := range parts[:len(parts)-1] {
		l.buf = append(l.buf, platform.TermSafe(strings.TrimRight(line, "\r")))
	}
	if len(l.buf) > l.max {
		l.buf = l.buf[len(l.buf)-l.max:]
	}
	return len(p), nil
}

// Last returns up to n lines.
func (l *Lines) Last(n int) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n > len(l.buf) {
		n = len(l.buf)
	}
	return append([]string{}, l.buf[len(l.buf)-n:]...)
}
