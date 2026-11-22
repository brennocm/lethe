package gui

import (
	"context"
	"errors"
	"fmt"
	"image/color"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"lethe/internal/buildinfo"
	"lethe/internal/contracts"
	"lethe/internal/i18n"
	"lethe/internal/profile"
	lsetup "lethe/internal/setup"
)

// Options configure the UI.
type Options struct {
	Lang string
	// NoTray: the desktop shows no tray icons, so the panel is the GUI: closing it quits instead
	// of hiding it where nothing could bring it back.
	NoTray bool
	X11    bool             // warn that same-UID programs can read the keyboard (spec §22 item 12)
	Now    func() time.Time // nil = time.Now
	Home   string           // the operator's home: the default profile is Home/lethe/profile.yaml
	// Detect reads the machine for the first-use form (nil = setup.LiveDetect); askIP also asks
	// the public IP. WorkFactor is the baseline's scrypt factor (0 = the default; tests lower it).
	Detect     func(ctx context.Context, askIP bool) lsetup.Detected
	WorkFactor int
	// StartService starts the service for this operator (lethed@<user>.service through systemd's
	// D-Bus API, polkit asking for the password); nil = the panel only says how.
	StartService func(ctx context.Context) error
	// Cleanup releases a block a dead session left (lethe-cleanup.service: lethe cleanup as root,
	// polkit asking the password); nil = the panel only says how.
	Cleanup func(ctx context.Context) error
}

const maxEvents = 500

// UI is the GUI: the tray, the panel window and the full-screen alert window.
type UI struct {
	app  fyne.App
	be   Backend
	opt  Options
	lang string

	st      contracts.Status
	evs     []contracts.Event
	offline error

	panel fyne.Window

	// the shell: sidebar, top bar, block notice and the page on screen (ADR 0016)
	navs      map[string]*navItem
	pages     map[string]fyne.CanvasObject
	page      string
	mode      string // offline, first, idle or session: a change brings the page that fits
	pageTitle *canvas.Text
	pill      *badge
	pillPath  *canvas.Text
	daemonOn  *canvas.Text
	sensorsOn *canvas.Text
	exitTop   *canvas.Text
	timeTop   *canvas.Text
	panicBtn  *widget.Button

	verdict    *canvas.Text
	header     *widget.Label // state, protection, session, time
	fpLine     *widget.Label // the session key's fingerprint, to write down outside the machine
	heroCard   *card
	guardBadge *badge
	startCTA   *widget.Button
	route      *routeView
	routeNote  *widget.Label
	routeActs  *fyne.Container
	svcBtn     *widget.Button  // start the service (offline)
	svcWait    time.Time       // after a start: until when the panel waits for the daemon to answer
	svcBusy    *fyne.Container // in place of svcBtn while a start runs: a spinner and what it waits for
	svcBar     *widget.ProgressBarInfinite
	svcStatus  *widget.Label
	svcRunning bool           // a start is in progress (svcBusy shown, svcBtn hidden)
	cleanBtn   *widget.Button // release a leftover block (block notice)
	cleanOff   *widget.Button // the same, offline: a crash in portable mode leaves no daemon to ask
	block      *fyne.Container
	blockCard  *card
	blockWhat  *widget.Label
	blockText  *widget.Label
	flash      *widget.Label

	// overview
	work                                      *fyne.Container // what only a session has: the areas and the recent events
	areas                                     [4]*statCard
	statDur, statCheck, statOpen, statSensors *canvas.Text
	recent                                    []*eventCells
	recentRows                                []*fyne.Container
	recentBox                                 *fyne.Container
	recentNone                                *widget.Label

	// DNS & IP
	leakActs                                *fyne.Container
	leakNote                                *widget.Label
	checkBtn                                *widget.Button
	quickExit                               *contracts.DNSLeakServer // the exit a test without a session saw
	quickAt                                 time.Time
	idBadge, dnsBadge                       *badge
	idIP, idPlace, idASN, idPath, idChecked *canvas.Text
	dnsOut                                  *widget.Label
	dnsRows                                 *fyne.Container
	vectors                                 map[string]*vecCard

	// events
	evStats    [4]*statCard
	timeline   *widget.List
	shown      []contracts.Event
	filter     EventFilter
	ifaceSel   *widget.Select
	detail     *fyne.Container
	detailCard *card

	// guard
	guardTitle         *canvas.Text
	guardDesc          *widget.Label
	guardState         *badge
	tablesOut          *widget.Label
	modes              map[string]*modeCard
	respWarn, respCrit *widget.Label
	labOut, labNote    *widget.Label
	labActs            *fyne.Container
	scrollH            map[*container.Scroll]float32 // the content height each page scroll last knew

	// checks
	rows map[string]*widget.Label

	// session
	sessInfo, sessOffline        fyne.CanvasObject
	sessID, sessStart, sessGuard *canvas.Text
	sessFP                       *widget.Label
	start                        *fyne.Container // the session start form (no session)
	firstForm                    *firstUse       // the first-use form (no profile yet)
	actions                      *fyne.Container
	profile                      *widget.Entry
	guardSel                     *widget.RadioGroup
	guardNote                    *widget.Label
	startPass                    *SecretEntry
	startBtn                     *widget.Button
	addNetBtn                    *widget.Button // register the current network in the baseline (no session)

	unpanicBtn *widget.Button
	endBtn     *widget.Button
	ackWayBtn  *widget.Button
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
	a.Settings().SetTheme(Theme())
	return &UI{app: a, be: be, opt: opt, lang: i18n.Norm(opt.Lang), rows: map[string]*widget.Label{}, alertSeen: map[string]time.Time{}}
}

func (u *UI) t(key string) string { return i18n.UI(u.lang, key) }

func wrapped(s string) *widget.Label {
	l := widget.NewLabel(s)
	l.Wrapping = fyne.TextWrapWord
	return l
}

// Build creates the panel and the tray menu (spec §16.1, §16.2). The panel is a sidebar of
// pages beside a top bar: the bar always says where the web sees the operator and keeps Panic
// apart from every other action; a block notice, when the network is blocked, sits under it on
// every page.
func (u *UI) Build() {
	u.panel = u.app.NewWindow("lethe")
	u.panel.SetIcon(AppIcon())
	u.verdict = text("", colText, 26, true, false)
	u.header = widget.NewLabel("")
	u.header.Importance = widget.LowImportance
	u.header.Truncation = fyne.TextTruncateEllipsis
	u.fpLine = widget.NewLabel("")
	u.fpLine.Selectable = true
	u.fpLine.Wrapping = fyne.TextWrapWord
	u.fpLine.Hide()
	u.route = newRouteView(u.lang)
	u.routeNote = widget.NewLabel("")
	u.routeNote.Importance = widget.LowImportance
	u.routeNote.Wrapping = fyne.TextWrapWord
	u.dnsOut = wrapped(u.t("dns_none"))
	u.dnsOut.Importance = widget.LowImportance
	u.flash = wrapped("")
	u.flash.Hide()
	u.svcBtn = widget.NewButtonWithIcon(u.t("service_btn"), theme.MediaPlayIcon(), u.startService)
	u.svcBtn.Importance = widget.HighImportance
	u.svcBtn.Hide()
	u.svcBar = widget.NewProgressBarInfinite()
	u.svcBar.Stop()
	u.svcStatus = wrapped("")
	u.svcStatus.TextStyle = fyne.TextStyle{Bold: true}
	u.svcBusy = container.NewVBox(u.svcBar, u.svcStatus)
	u.svcBusy.Hide()
	u.cleanBtn = widget.NewButton(u.t("cleanup_btn"), u.askCleanup)
	u.cleanBtn.Importance = widget.HighImportance
	u.cleanBtn.Hide()
	u.cleanOff = widget.NewButton(u.t("cleanup_btn"), u.askCleanup)
	u.cleanOff.Hide()

	u.blockWhat = wrapped("")
	u.blockWhat.TextStyle = fyne.TextStyle{Bold: true}
	u.blockText = wrapped("")
	u.unpanicBtn = widget.NewButton(u.t("unpanic_btn"), func() { u.askPassphrase(u.panel, u.t("unpanic_ask"), u.be.Unpanic) })
	u.unpanicBtn.Importance = widget.HighImportance
	u.unpanicBtn.Hide()
	u.endBtn = widget.NewButton(u.t("end_btn"), u.askEnd)
	u.ackWayBtn = widget.NewButton(u.t("ack_btn"), func() { u.askAck(u.panel) })
	u.blockCard = newCard(container.NewVBox(caption(u.t("lockdown_label")), u.blockWhat, u.blockText,
		container.NewHBox(u.ackWayBtn, u.unpanicBtn, u.endBtn, u.cleanBtn)))
	u.blockCard.setTone(toneBad)
	u.block = container.NewVBox(u.blockCard.box)
	u.block.Hide()

	u.buildStart()
	u.buildFirstUse()
	u.pages = map[string]fyne.CanvasObject{
		"overview": u.buildOverview(),
		"leaks":    u.buildLeaks(),
		"events":   u.buildEvents(),
		"guard":    u.buildGuard(),
		"checks":   u.buildChecks(),
		"session":  u.buildSession(),
	}
	stack := container.NewStack()
	for _, p := range Pages {
		stack.Add(u.pages[p.Key])
	}

	u.panicBtn = widget.NewButtonWithIcon(u.t("panic_btn"), theme.WarningIcon(), u.askPanic)
	u.panicBtn.Importance = widget.DangerImportance
	u.exitTop = text("", colText, 13, false, true)
	u.timeTop = text("", colText2, 13, false, true)
	u.pageTitle = text("", colText, 20, true, false)
	chip := func(o fyne.CanvasObject) fyne.CanvasObject {
		bg := canvas.NewRectangle(colRaised)
		bg.CornerRadius = 8
		bg.StrokeColor, bg.StrokeWidth = colRule, 1
		return container.NewStack(bg, pad(o, 6, 10))
	}
	top := container.NewBorder(nil, nil, container.NewCenter(u.pageTitle), container.NewHBox(
		chip(container.NewHBox(caption(u.t("top_exit")), u.exitTop)),
		chip(container.NewHBox(caption(u.t("top_session")), u.timeTop)),
		u.panicBtn))

	main := container.NewBorder(container.NewVBox(top, u.block, u.flash), nil, nil, nil, stack)
	u.panel.SetContent(container.NewBorder(nil, nil, u.buildSidebar(), nil, pad(main, 12, 16)))
	u.panel.Resize(fyne.NewSize(1280, 820))

	if desk, ok := u.app.(desktop.App); ok && !u.opt.NoTray {
		u.trayStatus = fyne.NewMenuItem("lethe", nil)
		u.trayStatus.Disabled = true
		u.tray = fyne.NewMenu("lethe", u.trayStatus,
			fyne.NewMenuItem(u.t("open_panel"), func() { u.panel.Show(); u.panel.RequestFocus() }),
			fyne.NewMenuItem(u.t("panic_btn"), u.askPanic),
			fyne.NewMenuItem(u.t("selftest_btn"), u.askSelftest),
			fyne.NewMenuItem(u.t("end_btn"), func() {
				u.panel.Show()
				u.askEnd()
			}))
		desk.SetSystemTrayMenu(u.tray)
		desk.SetSystemTrayIcon(TrayIcon("GRAY", 0))
		u.panel.SetCloseIntercept(u.panel.Hide) // the tray keeps the GUI; closing hides the panel
	}
	u.Apply(u.st, nil)
	if u.needsFirstUse() {
		u.detect(false) // local only: gateway, resolvers, the kind of tunnel
	}
}

// buildSidebar is the logo, the state pill, the pages and the daemon's line.
func (u *UI) buildSidebar() fyne.CanvasObject {
	logo := canvas.NewImageFromResource(AppIcon())
	logo.FillMode = canvas.ImageFillContain
	logo.SetMinSize(fyne.NewSize(34, 34))
	brand := container.NewHBox(logo, container.NewVBox(text("LETHE", colText, 15, true, false), text(u.t("brand_sub"), colText2, 10, false, true)))
	u.pill = newBadge()
	u.pillPath = text("", colText2, 11, false, true)
	nav := container.NewVBox()
	u.navs = map[string]*navItem{}
	for _, p := range Pages {
		key := p.Key
		n := newNavItem(p.Icon(), u.t("nav_"+key), func() { u.go2(key) })
		u.navs[key] = n
		nav.Add(n)
	}
	u.daemonOn = text("", colText, 12, true, true)
	u.sensorsOn = text("", colText2, 11, false, true)
	dbg := canvas.NewRectangle(colRaised)
	dbg.CornerRadius = 10
	daemon := container.NewStack(dbg, pad(container.NewVBox(caption(u.t("daemon_label")), u.daemonOn, u.sensorsOn), 8, 10))
	version := text(buildinfo.Version, colDim, 11, false, true)
	bg := canvas.NewRectangle(colSidebar)
	body := container.NewBorder(
		container.NewVBox(brand, widget.NewSeparator(), container.NewBorder(nil, nil, u.pill.box, u.pillPath), widget.NewSeparator(), nav),
		container.NewVBox(daemon, version), nil, nil)
	return container.New(fixed{w: 232}, container.NewStack(bg, pad(body, 16, 14)))
}

// go2 shows the page key.
func (u *UI) go2(key string) {
	if _, ok := u.pages[key]; !ok {
		return
	}
	u.page = key
	for k, p := range u.pages {
		show(p, k == key)
		u.navs[k].setActive(k == key)
	}
	u.pageTitle.Text = u.t("nav_" + key)
	u.pageTitle.Refresh()
	u.relayout()
	u.panel.Content().Refresh() // a page that comes back is drawn whole
}

// buildStart is the form shown with no session: the profile (the default place lethe setup
// writes to, or another one picked by the operator; never remembered on disk, the path can name
// the operation), the protection and the passphrase.
func (u *UI) buildStart() {
	u.profile = widget.NewEntry()
	if u.opt.Home != "" {
		u.profile.SetText(filepath.Join(u.opt.Home, "lethe", "profile.yaml"))
	}
	pick := widget.NewButton(u.t("profile_pick"), func() {
		d := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
			if err == nil && r != nil {
				u.profile.SetText(r.URI().Path())
				_ = r.Close()
			}
		}, u.panel)
		d.SetFilter(storage.NewExtensionFileFilter([]string{".yaml", ".yml"}))
		d.Show()
	})
	u.guardSel = widget.NewRadioGroup(nil, nil)
	u.guardSel.Required = true
	note := wrapped("")
	note.Importance = widget.LowImportance
	u.guardNote = note
	u.profile.OnChanged = func(string) { u.refreshStrict() }
	u.startPass = NewSecretEntry()
	u.startBtn = widget.NewButton(u.t("start_btn"), u.startSession)
	u.startBtn.Importance = widget.HighImportance
	u.startPass.OnSubmit = u.startSession
	form := container.NewVBox(caption(u.t("session_label")), text(u.t("start_title"), colText, 22, true, false),
		widget.NewLabel(u.t("profile_label")), container.NewBorder(nil, nil, nil, pick, u.profile),
		widget.NewLabel(u.t("guard_label")), u.guardSel, note,
		widget.NewLabel(u.t("passphrase")), u.startPass)
	if u.opt.X11 {
		x := wrapped(u.t("x11_warning"))
		x.Importance = widget.LowImportance
		form.Add(x)
	}
	u.addNetBtn = widget.NewButton(u.t("addnet_btn"), u.askAddNetwork)
	form.Add(container.NewHBox(u.startBtn, u.addNetBtn, widget.NewButton(u.t("reports_btn"), u.showReports)))
	u.refreshStrict()
	// a reading column: the form does not stretch across a wide window
	u.start = container.NewHBox(container.New(&maxWidth{w: 640}, newCard(form).box))
}

// refreshStrict offers strict only after an approved selftest on this machine (spec §10.6
// item 8), read from the profile's storage.dir/state/selftest.json. A profile that asks for
// strict without one starts in observe-only, with the reason, unless the operator insists.
func (u *UI) refreshStrict() {
	ok, why, profStrict := StrictApproval(strings.TrimSpace(u.profile.Text), u.opt.Home, u.opt.Now())
	opts := []string{u.t("guard_profile"), u.t("guard_off")}
	if ok {
		opts = append(opts, u.t("guard_strict"))
	}
	prev := u.guardSel.Selected
	u.guardSel.Options = opts
	switch {
	case ok:
		u.guardNote.SetText(u.t("guard_strict_note"))
	case profStrict:
		u.guardNote.SetText(fmt.Sprintf(u.t("strict_profile_warn"), u.t("strict_why_"+why)))
	default:
		u.guardNote.SetText(fmt.Sprintf(u.t("strict_locked"), u.t("strict_why_"+why)))
	}
	switch {
	case !ok && profStrict && prev != u.t("guard_profile"):
		u.guardSel.Selected = u.t("guard_off")
	case !slices.Contains(opts, prev):
		u.guardSel.Selected = opts[0]
	}
	u.guardSel.Refresh()
}

// StrictApproval says whether strict may be offered (a recent full approved selftest in the
// profile's storage.dir), why not, and whether the profile itself asks for strict. A profile
// that cannot be read counts as no selftest.
func StrictApproval(path, home string, now time.Time) (ok bool, why string, profileStrict bool) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's own profile
	if err != nil {
		return false, contracts.SelftestNone, false
	}
	p, _, err := profile.Parse(raw, home)
	if err != nil || p.Storage.Dir == "" {
		return false, contracts.SelftestNone, false
	}
	st, err := os.ReadFile(filepath.Join(p.Storage.Dir, "state", "selftest.json")) // #nosec G304 G703 -- the operator's own data dir
	if err != nil {
		st = nil
	}
	ok, why = contracts.SelftestApproval(st, now)
	return ok, why, p.Guard.Mode == "strict"
}

// maxWidth lays its children out at most w wide.
type maxWidth struct{ w float32 }

func (m *maxWidth) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	w := min(size.Width, m.w)
	for _, o := range objs {
		o.Resize(fyne.NewSize(w, size.Height))
		o.Move(fyne.NewPos(0, 0))
	}
}

func (m *maxWidth) MinSize(objs []fyne.CanvasObject) fyne.Size {
	var s fyne.Size
	for _, o := range objs {
		s = s.Max(o.MinSize())
	}
	return fyne.NewSize(max(s.Width, m.w), s.Height)
}

// startSession arms with the profile and the baseline it names, both read as the operator.
func (u *UI) startSession() {
	path := strings.TrimSpace(u.profile.Text)
	if u.startPass.Len() == 0 || path == "" {
		return
	}
	guard := map[string]string{u.t("guard_off"): "off", u.t("guard_strict"): "strict"}[u.guardSel.Selected]
	pass := u.startPass.Take()
	u.startBtn.Disable()
	u.setFlash(u.t("start_running"))
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		defer fyne.Do(u.startBtn.Enable)
		req, err := ArmFiles(path, u.opt.Home)
		if err != nil {
			wipe(pass)
			u.say(u.t("start_title"), err, "")
			return
		}
		req.Passphrase, req.Guard = pass, guard
		_, err = u.be.Arm(req)
		wipe(pass)
		u.say(u.t("start_title"), err, u.t("start_ok"))
	}()
}

// ArmFiles reads the profile at path and the baseline it names (baseline.file).
func ArmFiles(path, home string) (ArmRequest, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's own profile, read with their rights
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ArmRequest{}, fmt.Errorf(i18n.UI("", "profile_missing"), path)
		}
		return ArmRequest{}, err
	}
	p, _, err := profile.Parse(raw, home)
	if err != nil {
		return ArmRequest{}, err
	}
	if p.Baseline.File == "" {
		return ArmRequest{}, errors.New("profile: baseline.file is required to start a session")
	}
	base, err := os.ReadFile(p.Baseline.File) // #nosec G703 G304 -- named by the operator's own profile, read with their rights
	if err != nil {
		return ArmRequest{}, fmt.Errorf("baseline: %w", err)
	}
	return ArmRequest{Profile: raw, Baseline: base}, nil
}

// checkNow asks for a NET-011 round now.
func (u *UI) checkNow() {
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		u.say(u.t("check_now_btn"), u.be.CheckNow(), u.t("check_now_ok"))
	}()
}

// askDNS explains what the DNS test reveals before running it.
func (u *UI) askDNS() {
	ask := u.t("dns_ask")
	if u.st.Session == "" {
		ask += "\n\n" + u.t("dns_ask_quick")
	}
	dialog.NewCustomConfirm(u.t("dns_btn"), u.t("dns_run"), u.t("cancel"), wrapped(ask), func(yes bool) {
		if !yes {
			return
		}
		u.go2("leaks") // the result fills the DNS & IP page
		u.dnsOut.SetText(u.t("dns_running"))
		u.dnsOut.Importance = widget.MediumImportance
		u.dnsOut.Show()
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			res, err := u.be.DNSLeak(ctx)
			fyne.Do(func() { u.showDNS(res, err) })
		}()
	}, u.panel).Show()
}

func (u *UI) showDNS(r contracts.DNSLeakResult, err error) {
	u.dnsOut.Show()
	if err != nil {
		u.dnsOut.Importance = widget.WarningImportance
		u.dnsOut.SetText(fmt.Sprintf(u.t("dns_skipped"), err.Error()))
		u.showDNSRows(contracts.DNSLeakResult{})
		return
	}
	s, imp := DNSText(r, u.lang)
	u.dnsOut.Importance = imp
	u.dnsOut.SetText(s)
	u.showDNSRows(r)
	if r.Quick && r.Exit != nil { // no session: the identity card shows what this test saw
		e := *r.Exit
		u.quickExit, u.quickAt = &e, r.At
		u.applyLeaks(u.st, false)
	}
	u.relayout()
}

// DNSText is the DNS test's result as the panel shows it.
func DNSText(r contracts.DNSLeakResult, lang string) (string, widget.Importance) {
	t := func(k string) string { return i18n.UI(lang, k) }
	var s string
	imp := widget.SuccessImportance
	switch r.Verdict {
	case "ok":
		s = t("dns_ok")
	case "suspect":
		s, imp = t("dns_suspect"), widget.WarningImportance
	case "leak":
		s, imp = t("dns_leak"), widget.DangerImportance
		if r.Quick {
			s = t("dns_leak_quick")
		}
	default:
		return fmt.Sprintf(t("dns_skipped"), r.Detail), widget.WarningImportance
	}
	server := func(v contracts.DNSLeakServer) string {
		who := v.IP
		if v.Matched != "" {
			who = fmt.Sprintf(t(matchedKey(r)), v.Matched)
		}
		var more []string
		if v.Country != "" {
			more = append(more, v.Country)
		}
		if v.ASN != "" {
			more = append(more, v.ASN)
		}
		if len(more) > 0 {
			who += " (" + strings.Join(more, ", ") + ")"
		}
		return who
	}
	if r.Quick {
		s += "\n" + t("dns_quick_note")
	}
	if r.Exit != nil {
		s += "\n" + t("dns_web_sees") + ": " + server(*r.Exit)
	}
	if len(r.DNS) > 0 {
		var list []string
		for _, d := range r.DNS {
			list = append(list, server(d))
		}
		s += "\n" + t("dns_seen") + ": " + strings.Join(list, "; ")
	}
	return s, imp
}

// askEnd ends the session with the passphrase; in PANIC it says the block is lifted without the
// tunnel re-check (spec §10.6 item 10).
func (u *UI) askEnd() {
	q := u.t("disarm_ask")
	if u.st.State == "PANIC" {
		q = u.t("end_panic_ask")
	}
	u.askPassphrase(u.panel, q, u.be.Disarm)
}

// WaysText is the way out of a block in the panel's words, one numbered step per line, in the
// order to try them; without Ways (an older daemon), the terminal text.
func WaysText(l *contracts.Lockdown, lang string) string {
	if len(l.Ways) == 0 {
		return l.Exit
	}
	var lines []string
	for i, w := range l.Ways {
		lines = append(lines, fmt.Sprintf("%d. %s", i+1, i18n.UI(lang, "way_"+w)))
	}
	return strings.Join(lines, "\n")
}

// Verdict is the panel's first line: whether the operator is covered, in their words.
func Verdict(st contracts.Status, offline bool, lang string) (string, color.Color) {
	t := func(k string) string { return i18n.UI(lang, k) }
	switch {
	case offline:
		return t("verdict_offline"), colText2
	case st.State == "PANIC" || st.Lockdown != nil:
		return t("verdict_blocked"), colBrick
	case st.Session == "":
		return t("verdict_idle"), colText2
	case st.Color == "RED":
		return t("verdict_leak"), colBrick
	case st.Color == "YELLOW":
		return t("verdict_warn"), colOchre
	}
	return t("verdict_ok"), colGold
}

// StateLine is the line beside the verdict: state, protection and how long.
func StateLine(st contracts.Status, now time.Time, lang string) string {
	if st.Session == "" {
		return ""
	}
	t := func(k string) string { return i18n.UI(lang, k) }
	parts := []string{map[bool]string{true: t("state_panic"), false: t("state_armed")}[st.State == "PANIC"]}
	if g := t("guard_mode_" + st.Guard); st.Guard != "" && g != "guard_mode_"+st.Guard {
		parts = append(parts, g)
	}
	if st.StartedAt != nil {
		parts = append(parts, fmt.Sprintf(t("since"), span(now.Sub(*st.StartedAt))))
	}
	return strings.Join(parts, ", ")
}

// FingerprintLine is the session key's fingerprint as the panel shows it (spec §10.6: written
// down outside the machine at the arm, it is what lethe verify checks). Empty with no session.
func FingerprintLine(st contracts.Status, lang string) string {
	if st.Session == "" || st.Fingerprint == "" {
		return ""
	}
	return fmt.Sprintf(i18n.UI(lang, "fingerprint_line"), st.Fingerprint)
}

// Apply shows st and adds evs (UI thread).
func (u *UI) Apply(st contracts.Status, evs []contracts.Event) {
	u.st = st
	u.evs = MergeEvents(u.evs, evs, maxEvents)
	session := st.Session != "" && u.offline == nil
	v, col := Verdict(st, u.offline != nil, u.lang)
	u.verdict.Text, u.verdict.Color = v, col
	u.verdict.Refresh()
	u.header.SetText(StateLine(st, u.opt.Now(), u.lang))
	if fp := FingerprintLine(st, u.lang); fp != "" {
		u.fpLine.SetText(fp)
		u.fpLine.Show()
	} else {
		u.fpLine.Hide()
	}
	u.applyShell(st, session)

	r := RouteOf(st, u.lang)
	u.route.set(r)
	note := r.Note
	if u.offline != nil {
		note = u.t("offline_how")
		if u.opt.StartService != nil {
			note = u.t("offline_how_btn")
		}
		if u.opt.Cleanup != nil {
			note += " " + u.t("offline_cleanup")
		}
	}
	u.followStart()
	show(u.svcBtn, u.offline != nil && u.opt.StartService != nil && !u.svcRunning)
	show(u.cleanOff, u.offline != nil && u.opt.Cleanup != nil)
	u.routeNote.SetText(note)
	show(u.routeActs, session && st.State != "PANIC") // in panic nothing leaves: no check to run

	if l := st.Lockdown; l != nil {
		u.blockWhat.SetText(clean(l.What))
		u.blockText.SetText(u.t("why") + ": " + clean(l.Why) + "\n" + u.t("how_out") + ":\n" + WaysText(l, u.lang))
		u.block.Show()
	} else {
		u.block.Hide()
	}
	ways := map[string]bool{}
	if st.Lockdown != nil {
		for _, w := range st.Lockdown.Ways {
			ways[w] = true
		}
	}
	show(u.ackWayBtn, ways[contracts.WayAck])
	show(u.unpanicBtn, ways[contracts.WayUnpanic] || st.State == "PANIC")
	show(u.endBtn, session && (ways[contracts.WayDisarm] || len(ways) == 0))
	show(u.cleanBtn, ways[contracts.WayCleanup] && u.opt.Cleanup != nil)

	u.applyOverview(st, session)
	u.applyLeaks(st, session)
	u.applyEvents(st)
	u.applyGuard(st, session)
	u.applyChecks(st)
	needsFirst := !session && u.needsFirstUse()
	u.applySession(st, session, needsFirst)
	u.refreshTimeline()

	// a change of situation brings the page that fits it; otherwise the operator's page stays
	mode := "idle"
	switch {
	case session:
		mode = "session"
	case needsFirst:
		mode = "first"
	case u.offline != nil:
		mode = "offline"
	}
	if mode != u.mode {
		u.mode = mode
		u.go2("overview")
	} else {
		u.relayout()
	}
	if u.trayStatus != nil {
		u.trayStatus.Label = fmt.Sprintf("lethe: %s · %d", st.State, OpenCount(st))
		u.tray.Refresh()
		if desk, ok := u.app.(desktop.App); ok {
			desk.SetSystemTrayIcon(TrayIcon(st.Color, OpenCount(st)))
		}
	}
	u.syncAlert()
}

// applyShell updates the sidebar and the top bar.
func (u *UI) applyShell(st contracts.Status, session bool) {
	word, t := u.t("pill_idle"), toneMuted
	switch {
	case u.offline != nil:
		word = u.t("pill_offline")
	case st.State == "PANIC" || st.Lockdown != nil:
		word, t = u.t("pill_blocked"), toneBad
	case !session:
	case st.Color == "RED":
		word, t = u.t("pill_leak"), toneBad
	case st.Color == "YELLOW":
		word, t = u.t("pill_warn"), toneWarn
	default:
		word, t = u.t("pill_ok"), toneGold
	}
	u.pill.set("● "+word, t)
	path := ""
	if session && st.Exit != nil {
		path = clean(st.Exit.Path)
	}
	setText := func(c *canvas.Text, s string) {
		if c.Text != s {
			c.Text = s
			c.Refresh()
		}
	}
	setText(u.pillPath, path)
	if u.offline != nil {
		setText(u.daemonOn, u.t("daemon_down"))
		u.daemonOn.Color = colBrick
	} else {
		setText(u.daemonOn, u.t("daemon_up"))
		u.daemonOn.Color = colSage
	}
	u.daemonOn.Refresh()
	up, total := SensorsUp(st)
	sensors := ""
	if total > 0 {
		sensors = fmt.Sprintf(u.t("sensors_up"), up, total)
	}
	setText(u.sensorsOn, sensors)
	exit, clock := "—", "—"
	if session {
		r := RouteOf(st, u.lang)
		exit = r.Exit
		u.exitTop.Color = map[HopState]color.Color{HopOK: colGold, HopBroken: colBrick, HopUnknown: colText2}[r.Out]
		if st.StartedAt != nil {
			clock = span(u.opt.Now().Sub(*st.StartedAt))
		}
	} else {
		u.exitTop.Color = colText2
	}
	setText(u.exitTop, exit)
	u.exitTop.Refresh()
	setText(u.timeTop, clock)
	show(u.panicBtn, session)
}

func (u *UI) refreshTimeline() {
	u.shown = FilterEvents(u.evs, u.filter)
	if u.timeline != nil {
		u.timeline.Refresh()
	}
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
		bg := canvas.NewRectangle(colPanicBg)
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
	t := canvas.NewText(s, colText)
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
		b.Add(white(u.t("how_out")+":", 18, true))
		for _, line := range strings.Split(WaysText(l, u.lang), "\n") {
			for _, o := range whiteWrap(line, 90) {
				b.Add(o)
			}
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
	row := container.NewHBox(ack, panicBtn)
	if l := u.st.Lockdown; l != nil && slices.Contains(l.Ways, contracts.WayDisarm) {
		// the session can end from here: the CRITICAL is acknowledged with the end
		row.Add(widget.NewButton(u.t("end_btn"), func() {
			u.askPassphrase(u.alertWin, u.t("end_panic_ask"), u.be.Disarm)
		}))
	}
	b.Add(row)
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
	fyne.Do(func() { u.setFlash(msg) })
}

// setFlash shows the outcome of the last action; an empty one takes no room.
func (u *UI) setFlash(msg string) {
	u.flash.SetText(msg)
	if msg == "" {
		u.flash.Hide()
	} else {
		u.flash.Show()
	}
	u.relayout()
}

// relayout lays the panel out again after parts were shown or hidden: a container does not
// lay itself out again when a child changes visibility, so the tree is walked from the top
// (each parent first, so the children get their new sizes), through the scrolls.
func (u *UI) relayout() {
	if u.panel == nil || u.panel.Content() == nil {
		return
	}
	if u.scrollH == nil {
		u.scrollH = map[*container.Scroll]float32{}
	}
	// Moves and resizes repaint what they touch (fyne's objects do), so the tree is not
	// refreshed as a whole: that would redraw every page, hidden ones too, every second.
	var walk func(o fyne.CanvasObject)
	walk = func(o fyne.CanvasObject) {
		switch c := o.(type) {
		case *fyne.Container:
			if !c.Visible() {
				return
			}
			if c.Layout != nil {
				c.Layout.Layout(c.Objects, c.Size())
			}
			for _, x := range c.Objects {
				walk(x)
			}
		case *container.Scroll:
			if c.Visible() && c.Content != nil {
				h := c.Content.MinSize().Height
				c.Content.Resize(fyne.NewSize(c.Size().Width, max(h, c.Size().Height)))
				walk(c.Content)
				if u.scrollH[c] != h { // the scroll bar follows a new content height
					u.scrollH[c] = h
					c.Refresh()
				}
			}
		}
	}
	walk(u.panel.Content())
}

func (u *UI) askPanic() { u.askPanicOn(u.panel)() }

func (u *UI) askPanicOn(w fyne.Window) func() {
	return func() {
		// the buttons name the action in the panel's language (fyne's Yes/No follow the system's)
		dialog.NewCustomConfirm(u.t("panic_btn"), u.t("panic_btn"), u.t("cancel"), wrapped(u.t("panic_ask")), func(yes bool) {
			if !yes {
				return
			}
			u.wg.Add(1)
			go func() {
				defer u.wg.Done()
				u.say(u.t("panic_btn"), u.be.Panic(), u.t("panic_ok"))
			}()
		}, w).Show()
	}
}

// askAck acknowledges the target alert: reason always, passphrase for a CRITICAL.
func (u *UI) askAck(w fyne.Window) {
	a, ok := AckTarget(u.st)
	if !ok {
		u.setFlash(u.t("no_alerts"))
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
	full := widget.NewButton(u.t("selftest_full"), func() { d.Hide(); u.askSelftestFull() })
	quick := widget.NewButton(u.t("selftest_quick"), func() { d.Hide(); u.runSelftest(false, nil) })
	d = dialog.NewCustom(u.t("selftest_btn"), u.t("cancel"), container.NewVBox(full, quick), u.panel)
	d.Show()
}

// askSelftestFull asks the passphrase for the complete run (RESP-001 blocks the network ~1 s).
func (u *UI) askSelftestFull() {
	u.askPassphraseMsg(u.panel, u.t("selftest_full"), "", func(p []byte) error {
		c := append([]byte(nil), p...) // runSelftest wipes its copy when the selftest ends
		u.runSelftest(true, c)
		return nil
	})
}

// runSelftest runs the selftest and shows its result on the panel and on the guard page.
func (u *UI) runSelftest(full bool, p []byte) {
	fyne.Do(func() { u.setFlash(u.t("selftest_running")) })
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		res, err := u.be.Selftest(context.Background(), full, p)
		wipe(p)
		msg := selftestText(res, u.lang)
		if err != nil {
			msg = "selftest: " + err.Error()
		}
		fyne.Do(func() { u.labOut.SetText(fmt.Sprintf(u.t("lab_last"), msg)) })
		u.say("selftest", err, msg)
	}()
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
