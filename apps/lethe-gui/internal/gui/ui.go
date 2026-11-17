package gui

import (
	"context"
	"fmt"
	"image/color"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

	"lethe/internal/contracts"
	"lethe/internal/i18n"
)

// Options configure the UI.
type Options struct {
	Lang string
	X11  bool             // warn that same-UID programs can read the keyboard (spec §22 item 12)
	Now  func() time.Time // nil = time.Now
}

const maxEvents = 500

// UI is the GUI: the tray, the panel window and the full-screen alert window.
type UI struct {
	app  fyne.App
	be   Backend
	opt  Options
	lang string

	st  contracts.Status
	evs []contracts.Event

	panel      fyne.Window
	header     *widget.Label
	fpr        *widget.Label
	exit       *widget.Label
	lockdown   *widget.Label
	flash      *widget.Label
	rows       map[string]*widget.Label
	timeline   *widget.List
	shown      []contracts.Event
	sevFilter  string
	chkFilter  string
	unpanicBtn *widget.Button
	tray       *fyne.Menu
	trayStatus *fyne.MenuItem

	alertWin  fyne.Window
	alertID   string
	alertBody *fyne.Container
	alertSeen map[string]time.Time

	wg sync.WaitGroup // actions in flight (tests wait on it)
}

// New builds the UI; Build creates the windows.
func New(a fyne.App, be Backend, opt Options) *UI {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &UI{app: a, be: be, opt: opt, lang: i18n.Norm(opt.Lang), rows: map[string]*widget.Label{}, alertSeen: map[string]time.Time{}}
}

func (u *UI) t(key string) string { return i18n.UI(u.lang, key) }

// Build creates the panel and the tray menu (spec §16.1, §16.2).
func (u *UI) Build() {
	u.panel = u.app.NewWindow("lethe")
	u.header = widget.NewLabel("")
	u.header.TextStyle = fyne.TextStyle{Bold: true}
	u.fpr = widget.NewLabel("")
	u.exit = widget.NewLabel("")
	u.lockdown = widget.NewLabel("")
	u.lockdown.Wrapping = fyne.TextWrapWord
	u.lockdown.Importance = widget.DangerImportance
	u.flash = widget.NewLabel("")
	u.flash.Wrapping = fyne.TextWrapWord

	panicBtn := widget.NewButton(u.t("panic_btn"), u.askPanic)
	panicBtn.Importance = widget.DangerImportance
	u.unpanicBtn = widget.NewButton(u.t("unpanic_btn"), func() { u.askPassphrase(u.panel, u.t("unpanic_ask"), u.be.Unpanic) })
	u.unpanicBtn.Hide()
	buttons := container.NewHBox(panicBtn, u.unpanicBtn,
		widget.NewButton(u.t("selftest_btn"), u.askSelftest),
		widget.NewButton(u.t("ack_btn"), func() { u.askAck(u.panel) }),
		widget.NewButton(u.t("disarm_btn"), func() { u.askPassphrase(u.panel, u.t("disarm_ask"), u.be.Disarm) }))

	var cards []fyne.CanvasObject
	grid := Grid(u.st, u.lang)
	for _, cat := range Categories {
		box := container.NewVBox()
		for _, r := range grid[cat] {
			l := widget.NewLabel("")
			u.rows[r.ID] = l
			box.Add(l)
		}
		cards = append(cards, widget.NewCard(u.t("category_"+cat), "", box))
	}

	u.timeline = widget.NewList(func() int { return len(u.shown) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			o.(*widget.Label).SetText(u.eventLine(u.shown[len(u.shown)-1-i]))
		})
	all := u.t("filter_all")
	sev := widget.NewSelect([]string{all, "INFO", "WARNING", "CRITICAL"}, func(s string) {
		u.sevFilter = map[bool]string{true: "", false: s}[s == all]
		u.refreshTimeline()
	})
	sev.SetSelected(all)
	chk := widget.NewEntry()
	chk.SetPlaceHolder(u.t("filter_check"))
	chk.OnChanged = func(s string) { u.chkFilter = s; u.refreshTimeline() }

	top := container.NewVBox(u.header, u.fpr, u.exit, u.lockdown, buttons, u.flash)
	events := container.NewBorder(container.NewGridWithColumns(2, sev, chk), nil, nil, nil, u.timeline)
	body := container.NewVSplit(container.NewVScroll(container.NewGridWithColumns(3, cards...)), events)
	u.panel.SetContent(container.NewBorder(top, nil, nil, nil, body))
	u.panel.Resize(fyne.NewSize(1000, 720))

	if desk, ok := u.app.(desktop.App); ok {
		u.trayStatus = fyne.NewMenuItem("lethe", nil)
		u.trayStatus.Disabled = true
		u.tray = fyne.NewMenu("lethe", u.trayStatus,
			fyne.NewMenuItem(u.t("open_panel"), func() { u.panel.Show(); u.panel.RequestFocus() }),
			fyne.NewMenuItem(u.t("panic_btn"), u.askPanic),
			fyne.NewMenuItem(u.t("selftest_btn"), u.askSelftest),
			fyne.NewMenuItem(u.t("disarm_btn"), func() {
				u.panel.Show()
				u.askPassphrase(u.panel, u.t("disarm_ask"), u.be.Disarm)
			}))
		desk.SetSystemTrayMenu(u.tray)
		desk.SetSystemTrayIcon(TrayIcon("GRAY", 0))
		u.panel.SetCloseIntercept(u.panel.Hide) // the tray keeps the GUI; closing hides the panel
	}
	u.Apply(u.st, nil)
}

// Run feeds the UI until ctx ends: status every second, the event stream and the heartbeat
// (SELF-003). Every widget change goes through fyne.Do.
func (u *UI) Run(ctx context.Context) {
	if evs, err := u.be.Recent(maxEvents); err == nil {
		fyne.Do(func() { u.Apply(u.st, evs) })
	}
	go u.stream(ctx)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		_ = u.be.Heartbeat()
		st, err := u.be.Status()
		fyne.Do(func() {
			if err != nil {
				u.header.SetText(u.t("disconnected") + ": " + err.Error())
				return
			}
			u.Apply(st, nil)
		})
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (u *UI) stream(ctx context.Context) {
	for ctx.Err() == nil {
		ch, err := u.be.Subscribe(ctx)
		if err == nil {
			for ev := range ch {
				fyne.Do(func() { u.Apply(u.st, []contracts.Event{ev}) })
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// Apply shows st and adds evs (UI thread).
func (u *UI) Apply(st contracts.Status, evs []contracts.Event) {
	u.st = st
	u.evs = MergeEvents(u.evs, evs, maxEvents)
	h := fmt.Sprintf("● %s", st.State)
	if st.Guard != "" {
		h += fmt.Sprintf("   %s: %s", u.t("guard"), st.Guard)
	}
	if st.Session != "" {
		h += fmt.Sprintf("   %s: %s", u.t("session"), st.Session)
		if st.StartedAt != nil {
			h += " (" + span(u.opt.Now().Sub(*st.StartedAt)) + ")"
		}
	}
	u.header.SetText(h)
	u.header.Importance = map[string]widget.Importance{"GREEN": widget.SuccessImportance, "YELLOW": widget.WarningImportance,
		"RED": widget.DangerImportance}[st.Color]
	u.header.Refresh()
	u.fpr.SetText(st.Fingerprint)
	u.exit.SetText(exitText(st, u.lang))
	if st.Lockdown != nil {
		u.lockdown.SetText(u.t("lockdown") + ": " + st.Lockdown.What + "\n" + st.Lockdown.Why + "\n" + u.t("how_out") + ": " + st.Lockdown.Exit)
		u.lockdown.Show()
	} else {
		u.lockdown.Hide()
	}
	if st.State == "PANIC" {
		u.unpanicBtn.Show()
	} else {
		u.unpanicBtn.Hide()
	}
	for cat, rows := range Grid(st, u.lang) {
		_ = cat
		for _, r := range rows {
			l, ok := u.rows[r.ID]
			if !ok {
				continue
			}
			text := r.ID + "  " + r.Title + " — " + r.State
			if r.Severity != "" {
				text += fmt.Sprintf(" (%s ×%d)", r.Severity, r.Count)
			}
			imp := widget.LowImportance
			switch contracts.Severity(r.Severity) {
			case contracts.SeverityCritical:
				imp = widget.DangerImportance
			case contracts.SeverityWarning:
				imp = widget.WarningImportance
			}
			if l.Text != text || l.Importance != imp {
				l.Importance = imp
				l.SetText(text)
			}
		}
	}
	u.refreshTimeline()
	if u.trayStatus != nil {
		u.trayStatus.Label = fmt.Sprintf("lethe: %s · %d", st.State, OpenCount(st))
		u.tray.Refresh()
		if desk, ok := u.app.(desktop.App); ok {
			desk.SetSystemTrayIcon(TrayIcon(st.Color, OpenCount(st)))
		}
	}
	u.syncAlert()
}

func exitText(st contracts.Status, lang string) string {
	e := st.Exit
	if e == nil {
		return ""
	}
	s := i18n.UI(lang, "exit") + ": " + e.Path
	if e.Country != "" {
		s += " · " + e.Country
	}
	if e.ASN != 0 {
		s += fmt.Sprintf(" · AS%d", e.ASN)
	}
	return s + " · " + e.At.Local().Format("15:04:05")
}

func (u *UI) refreshTimeline() {
	u.shown = Filter(u.evs, u.sevFilter, u.chkFilter)
	if u.timeline != nil {
		u.timeline.Refresh()
	}
}

func (u *UI) eventLine(ev contracts.Event) string {
	s := ev.TS.Local().Format("15:04:05") + "  " + string(ev.Severity) + "  " + string(ev.Type)
	if ev.Check != "" {
		s += "  " + ev.Check + " " + i18n.CheckText(u.lang, ev.Check).Title
	}
	if ev.Selftest {
		s += "  [selftest]"
	}
	return s
}

// syncAlert shows the full-screen alert while a CRITICAL waits and hides it after the ack
// (spec §16.3). It does not close with Esc or the window's close button.
func (u *UI) syncAlert() {
	a, ok := FullscreenAlert(u.st)
	if !ok {
		if u.alertWin != nil {
			u.alertWin.Hide()
		}
		u.alertID = ""
		return
	}
	if _, seen := u.alertSeen[a.ID]; !seen {
		u.alertSeen[a.ID] = u.opt.Now()
	}
	if u.alertWin == nil {
		u.alertWin = u.app.NewWindow("lethe — " + u.t("alert_banner"))
		u.alertWin.SetCloseIntercept(func() {}) // only the acknowledgement closes it
		u.alertBody = container.NewVBox()
		bg := canvas.NewRectangle(color.NRGBA{0xb0, 0x10, 0x10, 0xff})
		u.alertWin.SetContent(container.NewStack(bg, container.NewPadded(container.NewVScroll(u.alertBody))))
	}
	if u.alertID == a.ID {
		return
	}
	u.alertID = a.ID
	u.fillAlert(a)
	u.alertWin.SetFullScreen(true)
	u.alertWin.Show()
	u.alertWin.RequestFocus()
	// Fyne cannot tell whether the compositor gave the window focus (GNOME/Wayland may not):
	// report "shown" with the time since the GUI first saw the alert (spec §16.4).
	lat := float64(u.opt.Now().Sub(u.alertSeen[a.ID]).Microseconds()) / 1000
	id := a.ID
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		_ = u.be.Fullscreen(contracts.FullscreenReport{AlertID: id, Result: "shown", LatencyMS: lat})
	}()
}

func white(s string, size float32, bold bool) *canvas.Text {
	t := canvas.NewText(s, color.White)
	t.TextSize, t.TextStyle = size, fyne.TextStyle{Bold: bold}
	return t
}

func whiteWrap(s string, width int) []fyne.CanvasObject {
	var out []fyne.CanvasObject
	for _, l := range wrap(s, width) {
		out = append(out, white(l, 18, false))
	}
	return out
}

func (u *UI) fillAlert(a contracts.AlertView) {
	tx := i18n.CheckText(u.lang, a.Check)
	b := u.alertBody
	b.RemoveAll()
	b.Add(white(u.t("alert_banner")+" · "+a.Check+" · "+a.ID, 22, true))
	b.Add(white(tx.Title, 34, true))
	for _, o := range whiteWrap(tx.Meaning, 90) {
		b.Add(o)
	}
	if d := Details(u.evs, a.ID); d != "" {
		b.Add(white(d, 18, false))
	}
	if acts := ActionsTaken(u.evs, a.ID, u.lang); len(acts) > 0 {
		b.Add(white(u.t("actions_done")+": "+strings.Join(acts, " "), 18, true))
	}
	b.Add(white(u.t("what_now")+":", 20, true))
	for _, o := range whiteWrap(tx.Todo, 90) {
		b.Add(o)
	}
	if l := u.st.Lockdown; l != nil {
		b.Add(white(u.t("lockdown")+": "+l.What, 18, true))
		for _, o := range whiteWrap(u.t("how_out")+": "+l.Exit, 90) {
			b.Add(o)
		}
	}
	reason := widget.NewEntry()
	reason.SetPlaceHolder(u.t("reason"))
	pass := NewSecretEntry()
	ack := widget.NewButton(u.t("ack_btn"), func() {
		if strings.TrimSpace(reason.Text) == "" || pass.Len() == 0 {
			return // a CRITICAL needs a reason and the passphrase
		}
		u.runAck(a.ID, reason.Text, pass.Take())
	})
	pass.OnSubmit = ack.OnTapped
	panicBtn := widget.NewButton(u.t("panic_btn"), u.askPanicOn(u.alertWin))
	panicBtn.Importance = widget.DangerImportance
	b.Add(widget.NewSeparator())
	b.Add(white(u.t("reason"), 16, false))
	b.Add(reason)
	b.Add(white(u.t("passphrase"), 16, false))
	b.Add(pass)
	if u.opt.X11 {
		for _, o := range whiteWrap(u.t("x11_warning"), 110) {
			b.Add(o)
		}
	}
	b.Add(container.NewHBox(ack, panicBtn))
	b.Add(white("", 12, false))
	b.Refresh()
}

func (u *UI) runAck(id, reason string, pass []byte) {
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		err := u.be.Ack(id, reason, pass)
		wipe(pass)
		u.say(id, err, u.t("ack_ok"))
	}()
}

// say shows the outcome of an action on the panel (UI thread through fyne.Do).
func (u *UI) say(what string, err error, ok string) {
	msg := ok
	if err != nil {
		msg = what + ": " + err.Error()
	}
	fyne.Do(func() { u.flash.SetText(msg) })
}

func (u *UI) askPanic() { u.askPanicOn(u.panel)() }

func (u *UI) askPanicOn(w fyne.Window) func() {
	return func() {
		dialog.ShowConfirm(u.t("panic_btn"), u.t("panic_ask"), func(yes bool) {
			if !yes {
				return
			}
			u.wg.Add(1)
			go func() {
				defer u.wg.Done()
				u.say(u.t("panic_btn"), u.be.Panic(), u.t("panic_ok"))
			}()
		}, w)
	}
}

// askAck acknowledges the target alert: reason always, passphrase for a CRITICAL.
func (u *UI) askAck(w fyne.Window) {
	a, ok := AckTarget(u.st)
	if !ok {
		u.flash.SetText(u.t("no_alerts"))
		return
	}
	critical := a.Severity == string(contracts.SeverityCritical)
	reason := widget.NewEntry()
	pass := NewSecretEntry()
	items := []fyne.CanvasObject{widget.NewLabel(a.Check + " " + i18n.CheckText(u.lang, a.Check).Title + " · " + a.ID),
		widget.NewLabel(u.t("reason")), reason}
	if critical {
		items = append(items, widget.NewLabel(u.t("passphrase")), pass)
		if u.opt.X11 {
			l := widget.NewLabel(u.t("x11_warning"))
			l.Wrapping = fyne.TextWrapWord
			items = append(items, l)
		}
	}
	d := dialog.NewCustomConfirm(u.t("ack_btn"), u.t("confirm"), u.t("cancel"), container.NewVBox(items...), func(yes bool) {
		if !yes || (critical && (strings.TrimSpace(reason.Text) == "" || pass.Len() == 0)) {
			pass.Wipe()
			return
		}
		var p []byte
		if critical {
			p = pass.Take()
		}
		u.runAck(a.ID, reason.Text, p)
	}, w)
	d.Show()
}

// askPassphrase confirms a sensitive action (disarm, leave panic) with the passphrase.
func (u *UI) askPassphrase(w fyne.Window, question string, act func([]byte) error) {
	u.askPassphraseMsg(w, question, "ok", act)
}

// askPassphraseMsg is askPassphrase with the success message ("" = none).
func (u *UI) askPassphraseMsg(w fyne.Window, question, okMsg string, act func([]byte) error) {
	pass := NewSecretEntry()
	items := []fyne.CanvasObject{widget.NewLabel(question), widget.NewLabel(u.t("passphrase")), pass}
	if u.opt.X11 {
		l := widget.NewLabel(u.t("x11_warning"))
		l.Wrapping = fyne.TextWrapWord
		items = append(items, l)
	}
	dialog.NewCustomConfirm(question, u.t("confirm"), u.t("cancel"), container.NewVBox(items...), func(yes bool) {
		if !yes || pass.Len() == 0 {
			pass.Wipe()
			return
		}
		p := pass.Take()
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			err := act(p)
			wipe(p)
			if err != nil || okMsg != "" {
				u.say(question, err, okMsg)
			}
		}()
	}, w).Show()
}

// askSelftest offers the complete run (RESP-001, passphrase) and the quick one.
func (u *UI) askSelftest() {
	var d dialog.Dialog
	run := func(full bool, p []byte) {
		fyne.Do(func() { u.flash.SetText(u.t("selftest_running")) })
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			res, err := u.be.Selftest(context.Background(), full, p)
			wipe(p)
			u.say("selftest", err, selftestText(res, u.lang))
		}()
	}
	full := widget.NewButton(u.t("selftest_full"), func() {
		d.Hide()
		u.askPassphraseMsg(u.panel, u.t("selftest_full"), "", func(p []byte) error {
			c := append([]byte(nil), p...) // run wipes its copy when the selftest ends
			run(true, c)
			return nil
		})
	})
	quick := widget.NewButton(u.t("selftest_quick"), func() { d.Hide(); run(false, nil) })
	d = dialog.NewCustom(u.t("selftest_btn"), u.t("cancel"), container.NewVBox(full, quick), u.panel)
	d.Show()
}

func selftestText(r contracts.SelftestResult, lang string) string {
	key := "selftest_passed"
	if !r.Passed {
		key = "selftest_failed"
	}
	var bad []string
	for _, c := range r.Cases {
		if c.Result == contracts.CaseFail {
			bad = append(bad, c.ID)
		}
	}
	s := i18n.UI(lang, key)
	if len(bad) > 0 {
		s += ": " + strings.Join(bad, ", ")
	}
	return s
}

// ShowPanel shows the panel window.
func (u *UI) ShowPanel() { u.panel.Show() }

func span(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Truncate(time.Second)
	return fmt.Sprintf("%02d:%02d:%02d", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
}

func wrap(s string, width int) []string {
	var out []string
	line := ""
	for _, w := range strings.Fields(s) {
		if line != "" && len([]rune(line))+1+len([]rune(w)) > width {
			out = append(out, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}
