package gui

import (
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"lethe/internal/contracts"
	"lethe/internal/i18n"
)

// The panel's pages (ADR 0016). Each has a build, run once, and an apply, run on every status.

// Pages in sidebar order: key (texts nav_<key>) and icon.
var Pages = []struct {
	Key  string
	Icon func() fyne.Resource // looked up when the panel is built: at init no app exists yet (Fyne logs an error per icon)
}{
	{"overview", theme.HomeIcon},
	{"leaks", theme.SearchIcon},
	{"events", theme.ListIcon},
	{"guard", theme.WarningIcon},
	{"checks", theme.GridIcon},
	{"session", theme.SettingsIcon},
}

// statCard is a summary number with its state.
type statCard struct {
	badge       *badge
	value, unit *canvas.Text
	note        *widget.Label
	card        *card
}

// iconTile is a small icon on a dark square, the top-left of a card.
func iconTile(res fyne.Resource) fyne.CanvasObject {
	bg := canvas.NewRectangle(colCanvas)
	bg.CornerRadius = 8
	bg.SetMinSize(fyne.NewSize(32, 32))
	return container.NewStack(bg, pad(widget.NewIcon(res), 4, 4))
}

// newStatCard: the icon and the state badge on top, then the title, the number and a note.
// Stacked, so four cards fit side by side in a narrow window.
func newStatCard(res fyne.Resource, title, note string) *statCard {
	s := &statCard{badge: newBadge(), value: text("—", colText, 30, true, true), unit: text("", colText2, 12, false, false)}
	s.note = wrapped(note)
	s.note.Importance = widget.LowImportance
	head := container.NewBorder(nil, nil, iconTile(res), container.NewCenter(s.badge.box))
	s.card = newCard(container.NewVBox(head, caption(title), container.NewHBox(s.value, container.NewCenter(s.unit)), s.note))
	return s
}

func (s *statCard) set(value, unit string, t tone, word string) {
	s.value.Text, s.unit.Text = value, unit
	s.value.Color = colText
	if t == toneBad || t == toneWarn {
		s.value.Color = toneColor(t)
	}
	s.value.Refresh()
	s.unit.Refresh()
	s.badge.set(word, t)
	s.card.setTone(map[bool]tone{true: t, false: toneMuted}[t == toneBad])
}

// miniStat is a caption over a monospace value (the route card's footer).
func miniStat(title string) (fyne.CanvasObject, *canvas.Text) {
	v := text("—", colText, 13, false, true)
	bg := canvas.NewRectangle(colCanvas)
	bg.CornerRadius = 8
	return container.NewStack(bg, pad(container.NewVBox(caption(title), v), 8, 10)), v
}

// eventCells is one row of an events table.
type eventCells struct{ cells []*widget.Label }

var (
	eventCols  = []float32{1.45, 2.6, 1.5, 1, 1.7, 0.9, 1.3}
	recentCols = []float32{1.3, 3, 1.8, 1.4}
)

func newEventCells(n int) *eventCells {
	e := &eventCells{}
	for i := 0; i < n; i++ {
		e.cells = append(e.cells, cell(i != 1)) // the check's title reads better in the platform font
	}
	return e
}

func (e *eventCells) objects() []fyne.CanvasObject {
	out := make([]fyne.CanvasObject, len(e.cells))
	for i, c := range e.cells {
		out[i] = c
	}
	return out
}

func importanceOf(t tone) widget.Importance {
	switch t {
	case toneBad:
		return widget.DangerImportance
	case toneWarn:
		return widget.WarningImportance
	case toneOK:
		return widget.SuccessImportance
	case toneGold:
		return widget.HighImportance
	}
	return widget.LowImportance
}

func setCell(l *widget.Label, s string, imp widget.Importance) {
	if l.Text != s || l.Importance != imp {
		l.Importance = imp
		l.SetText(s)
	}
}

// fill writes r into the full table's seven columns.
func (e *eventCells) fill(r EventRow) {
	vals := []string{r.Time, r.Event, r.Proc, r.Proto, r.Dst, r.Iface, r.Status}
	for i, v := range vals {
		imp := widget.MediumImportance
		if i == 0 || i == 5 {
			imp = widget.LowImportance
		}
		if i == 6 {
			imp = importanceOf(r.Tone)
		}
		setCell(e.cells[i], v, imp)
	}
}

// fillRecent writes r into the overview's four columns.
func (e *eventCells) fillRecent(r EventRow) {
	dst := r.Dst
	if r.Proc != "" {
		dst = strings.TrimSpace(r.Proc + " → " + dst)
	}
	vals := []string{r.Time, r.Event, dst, r.Status}
	for i, v := range vals {
		imp := widget.MediumImportance
		if i == 0 {
			imp = widget.LowImportance
		}
		if i == 3 {
			imp = importanceOf(r.Tone)
		}
		setCell(e.cells[i], v, imp)
	}
}

func header(names []string, weights []float32) fyne.CanvasObject {
	var objs []fyne.CanvasObject
	for _, n := range names {
		objs = append(objs, pad(caption(n), 6, 8))
	}
	bg := canvas.NewRectangle(colCanvas)
	bg.CornerRadius = 8
	return container.NewStack(bg, container.New(cols{w: weights}, objs...))
}

// page wraps a page's content in a scroll with the page's margins.
func page(objs ...fyne.CanvasObject) fyne.CanvasObject {
	return container.NewVScroll(pad(container.NewVBox(objs...), 4, 4))
}

// ---- Overview ----

func (u *UI) buildOverview() fyne.CanvasObject {
	u.guardBadge = newBadge()
	u.startCTA = widget.NewButtonWithIcon(u.t("start_cta"), theme.NavigateNextIcon(), func() { u.go2("session") })
	u.startCTA.Importance = widget.HighImportance
	u.startCTA.Hide()
	checkBtn := widget.NewButtonWithIcon(u.t("check_now_btn"), theme.ViewRefreshIcon(), u.checkNow)
	checkBtn.Importance = widget.HighImportance
	u.routeActs = container.NewVBox(checkBtn, widget.NewButtonWithIcon(u.t("dns_btn"), theme.SearchIcon(), u.askDNS))
	right := container.NewVBox(u.routeActs, u.startCTA, u.svcBtn, u.cleanOff)
	left := container.NewVBox(u.verdict, container.NewBorder(nil, nil, container.NewCenter(u.guardBadge.box), nil, u.header), u.fpLine)
	u.heroCard = newCard(container.NewBorder(nil, nil, nil, container.New(fixed{w: 230}, right), left))

	for i, a := range OverviewAreas {
		u.areas[i] = newStatCard(a.Icon(), u.t("area_"+a.Key), u.t("area_"+a.Key+"_note"))
	}
	areas := container.NewGridWithColumns(4, u.areas[0].card.box, u.areas[1].card.box, u.areas[2].card.box, u.areas[3].card.box)

	d, dv := miniStat(u.t("stat_duration"))
	c, cv := miniStat(u.t("stat_last_check"))
	o, ov := miniStat(u.t("stat_open"))
	s, sv := miniStat(u.t("stat_sensors"))
	u.statDur, u.statCheck, u.statOpen, u.statSensors = dv, cv, ov, sv
	routeCard := cardOf(caption(u.t("route_title")), widget.NewSeparator(),
		pad(u.route.box, 10, 8), u.routeNote, container.NewGridWithColumns(4, d, c, o, s))

	u.recent, u.recentRows = nil, nil
	rows := container.NewVBox(header([]string{u.t("col_time"), u.t("col_event"), u.t("col_dst"), u.t("col_status")}, recentCols))
	for i := 0; i < 6; i++ {
		r := newEventCells(len(recentCols))
		row := container.New(cols{w: recentCols}, r.objects()...)
		u.recent, u.recentRows = append(u.recent, r), append(u.recentRows, row)
		rows.Add(row)
	}
	u.recentNone = widget.NewLabel(u.t("no_events"))
	u.recentNone.Importance = widget.LowImportance
	more := widget.NewButton(u.t("recent_all"), func() { u.go2("events") })
	more.Importance = widget.LowImportance
	recentCard := cardOf(container.NewBorder(nil, nil, caption(u.t("recent_title")), more), rows, u.recentNone)

	u.work = container.NewVBox(areas)
	u.recentBox = container.NewVBox(recentCard)
	return page(u.heroCard.box, u.work, routeCard, u.recentBox)
}

func (u *UI) applyOverview(st contracts.Status, session bool) {
	u.guardBadge.set("", toneMuted)
	if session {
		word := strings.ToUpper(u.t("guard_mode_" + guardOf(st)))
		if st.State == "PANIC" {
			word = strings.ToUpper(u.t("state_panic"))
		}
		u.guardBadge.set(word, map[bool]tone{true: toneBad, false: toneGold}[st.State == "PANIC"])
	}
	_, col := Verdict(st, u.offline != nil, u.lang)
	u.heroCard.setTone(map[bool]tone{true: toneBad, false: toneMuted}[col == colBrick])
	show(u.startCTA, !session && u.offline == nil)
	show(u.work, session)
	show(u.recentBox, session)
	for i, a := range OverviewAreas {
		ar := AreaOf(st, a.Checks...)
		t := toneOf(ar.Worst)
		word := map[tone]string{toneOK: u.t("badge_ok"), toneWarn: u.t("badge_warn"), toneBad: u.t("badge_crit")}[t]
		u.areas[i].set(fmt.Sprint(ar.Open), u.t("open_alerts"), t, word)
	}
	dur, last := "—", "—"
	if st.StartedAt != nil {
		dur = span(u.opt.Now().Sub(*st.StartedAt))
	}
	if st.Exit != nil {
		last = st.Exit.At.Local().Format("15:04:05")
	}
	up, total := SensorsUp(st)
	sensors := "—"
	if total > 0 {
		sensors = fmt.Sprintf("%d / %d", up, total)
	}
	for v, s := range map[*canvas.Text]string{u.statDur: dur, u.statCheck: last, u.statOpen: fmt.Sprint(OpenCount(st)), u.statSensors: sensors} {
		if v.Text != s {
			v.Text = s
			v.Refresh()
		}
	}
	n := len(u.evs)
	for i, r := range u.recent {
		if i < n {
			r.fillRecent(RowOf(u.evs[n-1-i], u.lang))
		}
		show(u.recentRows[i], i < n)
	}
	show(u.recentNone, n == 0)
}

// ---- DNS & IP ----

// vecCard is one way an identity leaks.
type vecCard struct {
	badge *badge
	card  *card
}

func (u *UI) buildLeaks() fyne.CanvasObject {
	dnsBtn := widget.NewButtonWithIcon(u.t("dns_btn"), theme.SearchIcon(), u.askDNS)
	dnsBtn.Importance = widget.HighImportance
	u.leakActs = container.NewHBox(dnsBtn, widget.NewButtonWithIcon(u.t("check_now_btn"), theme.ViewRefreshIcon(), u.checkNow))
	u.leakNote = wrapped(u.t("leaks_need_session"))
	u.leakNote.Importance = widget.LowImportance
	title := text(u.t("leaks_title"), colText, 22, true, false)
	hero := cardOf(caption(u.t("leaks_label")), title, wrapped(u.t("leaks_intro")), u.leakActs, u.leakNote)

	u.idBadge = newBadge()
	u.idIP = text("—", colText, 22, true, true)
	field := func(key string) (fyne.CanvasObject, *canvas.Text) {
		v := text("—", colText, 13, false, true)
		return container.NewVBox(caption(u.t(key)), v), v
	}
	pl, plv := field("id_place")
	as, asv := field("id_asn")
	pa, pav := field("id_path")
	ch, chv := field("id_checked")
	u.idPlace, u.idASN, u.idPath, u.idChecked = plv, asv, pav, chv
	ipBg := canvas.NewRectangle(colCanvas)
	ipBg.CornerRadius = 10
	identity := cardOf(container.NewBorder(nil, nil, caption(u.t("identity_title")), u.idBadge.box),
		container.NewStack(ipBg, pad(container.NewVBox(caption(u.t("id_ip")), u.idIP), 10, 12)),
		container.NewGridWithColumns(2, pl, as), container.NewGridWithColumns(2, pa), ch)

	u.dnsBadge = newBadge()
	u.dnsRows = container.NewVBox()
	dnsCard := cardOf(container.NewBorder(nil, nil, caption(u.t("dns_title")), u.dnsBadge.box), u.dnsOut,
		header([]string{u.t("dns_col_server"), u.t("dns_col_country"), u.t("dns_col_asn"), u.t("dns_col_status")}, []float32{3, 1, 1.4, 1.2}),
		u.dnsRows)

	u.vectors = map[string]*vecCard{}
	var vecs []fyne.CanvasObject
	for _, v := range Vectors {
		b := newBadge()
		desc := wrapped(u.t("vec_" + v.Key + "_note"))
		desc.Importance = widget.LowImportance
		ids := lowLabel(strings.Join(v.Checks, " · "))
		ids.TextStyle = fyne.TextStyle{Monospace: true}
		c := newCard(container.NewVBox(container.NewBorder(nil, nil, iconTile(v.Icon()), container.NewCenter(b.box)),
			text(u.t("vec_"+v.Key), colText, 15, true, false), desc, ids))
		u.vectors[v.Key] = &vecCard{badge: b, card: c}
		vecs = append(vecs, c.box)
	}
	return page(hero, container.NewGridWithColumns(2, identity, dnsCard), caption(u.t("vectors_title")), container.NewGridWithColumns(3, vecs...))
}

func (u *UI) applyLeaks(st contracts.Status, session bool) {
	acts := session && u.offline == nil && st.State != "PANIC"
	show(u.leakActs, acts)
	show(u.leakNote, !acts)
	set := func(t *canvas.Text, s string) {
		if t.Text != s {
			t.Text = s
			t.Refresh()
		}
	}
	r := RouteOf(st, u.lang)
	ip, place, asn, path, checked := "—", "—", "—", "—", "—"
	switch {
	case !session:
		u.idBadge.set(u.t("badge_none"), toneMuted)
	case st.State == "PANIC":
		u.idBadge.set(u.t("badge_blocked"), toneBad) // nothing leaves: blocked, not exposed
	case r.Out == HopBroken:
		u.idBadge.set(u.t("badge_exposed"), toneBad)
	case st.Exit != nil:
		u.idBadge.set(u.t("badge_masked"), toneOK)
	default:
		u.idBadge.set(u.t("badge_waiting"), toneMuted)
	}
	if e := st.Exit; session && e != nil {
		ip = map[bool]string{true: e.IP, false: u.t("id_ip_hidden")}[e.IP != ""]
		var p []string
		for _, s := range []string{e.City, e.PlaceCountry} {
			if s != "" {
				p = append(p, s)
			}
		}
		if len(p) == 0 && e.Country != "" {
			p = append(p, e.Country)
		}
		if len(p) > 0 {
			place = strings.Join(p, ", ")
		}
		if e.ASN != 0 {
			asn = fmt.Sprintf("AS%d", e.ASN)
		}
		path = e.Path
		checked = e.At.Local().Format("15:04:05")
		if e.PlaceSource != "" {
			checked += " · " + e.PlaceSource
		}
	}
	switch {
	case !session:
	case st.State == "PANIC":
		ip = u.t("route_blocked")
	case AreaOf(st, "NET-011").Worst == string(contracts.SeverityCritical):
		ip = u.t("route_real_ip")
	}
	u.idIP.Color = colText
	if r.Out == HopBroken && session {
		u.idIP.Color = colBrick // the real IP, the block or "nothing leaves", in brick
	}
	set(u.idIP, ip)
	u.idIP.Refresh()
	set(u.idPlace, place)
	set(u.idASN, asn)
	set(u.idPath, path)
	set(u.idChecked, checked)
	for _, v := range Vectors {
		vc := u.vectors[v.Key]
		if !session {
			vc.badge.set(u.t("badge_none"), toneMuted)
			vc.card.setTone(toneMuted)
			continue
		}
		a := AreaOf(st, v.Checks...)
		t := toneOf(a.Worst)
		vc.badge.set(map[tone]string{toneOK: u.t("badge_safe"), toneWarn: u.t("badge_warn"), toneBad: u.t("badge_leak")}[t], t)
		vc.card.setTone(t)
	}
}

// showDNSRows lists the last DNS test's servers.
func (u *UI) showDNSRows(r contracts.DNSLeakResult) {
	u.dnsRows.RemoveAll()
	for _, s := range ServerRows(r, u.lang) {
		cs := []*widget.Label{cell(true), cell(true), cell(true), cell(true)}
		setCell(cs[0], s.Server, widget.MediumImportance)
		setCell(cs[1], s.Country, widget.MediumImportance)
		setCell(cs[2], s.ASN, widget.LowImportance)
		setCell(cs[3], s.Status, importanceOf(s.Tone))
		u.dnsRows.Add(container.New(cols{w: []float32{3, 1, 1.4, 1.2}}, cs[0], cs[1], cs[2], cs[3]))
	}
	switch r.Verdict {
	case "ok":
		u.dnsBadge.set(u.t("badge_safe"), toneOK)
	case "suspect":
		u.dnsBadge.set(u.t("badge_warn"), toneWarn)
	case "leak":
		u.dnsBadge.set(u.t("badge_leak"), toneBad)
	default:
		u.dnsBadge.set(u.t("badge_none"), toneMuted)
	}
	u.dnsRows.Refresh()
}

// ---- Events ----

func (u *UI) buildEvents() fyne.CanvasObject {
	for i, k := range []string{"ev_outside", "ev_blocked", "ev_open", "ev_total"} {
		icon := []fyne.Resource{theme.UploadIcon(), theme.CancelIcon(), theme.WarningIcon(), theme.ListIcon()}[i]
		u.evStats[i] = newStatCard(icon, u.t(k), u.t(k+"_note"))
	}
	stats := container.NewGridWithColumns(4, u.evStats[0].card.box, u.evStats[1].card.box, u.evStats[2].card.box, u.evStats[3].card.box)

	u.timeline = widget.NewList(func() int { return len(u.shown) },
		func() fyne.CanvasObject {
			e := newEventCells(len(eventCols))
			return container.New(cols{w: eventCols}, e.objects()...)
		},
		func(i widget.ListItemID, o fyne.CanvasObject) {
			box := o.(*fyne.Container)
			e := &eventCells{}
			for _, c := range box.Objects {
				e.cells = append(e.cells, c.(*widget.Label))
			}
			e.fill(RowOf(u.shown[len(u.shown)-1-i], u.lang))
		})
	u.timeline.OnSelected = func(i widget.ListItemID) {
		// new events shift the rows every second: the detail keeps the event, the highlight
		// would move to another one, so it is dropped
		u.timeline.UnselectAll()
		if i >= 0 && i < len(u.shown) {
			u.showDetail(u.shown[len(u.shown)-1-i])
		}
	}
	all := u.t("filter_all")
	sev := widget.NewSelect([]string{all, "INFO", "WARNING", "CRITICAL"}, func(s string) {
		u.filter.MinSev = map[bool]string{true: "", false: s}[s == all]
		u.refreshTimeline()
	})
	sev.SetSelected(all)
	chk := widget.NewEntry()
	chk.SetPlaceHolder(u.t("filter_check"))
	chk.OnChanged = func(s string) { u.filter.Check = s; u.refreshTimeline() }
	u.ifaceSel = widget.NewSelect([]string{u.t("filter_iface_all")}, func(s string) {
		u.filter.Iface = map[bool]string{true: "", false: s}[s == u.t("filter_iface_all")]
		u.refreshTimeline()
	})
	u.ifaceSel.SetSelected(u.t("filter_iface_all"))
	leaks := widget.NewCheck(u.t("leaks_only"), func(on bool) { u.filter.LeaksOnly = on; u.refreshTimeline() })
	filters := container.NewGridWithColumns(2, u.ifaceSel, sev, chk, leaks)
	note := wrapped(u.t("events_note"))
	note.Importance = widget.LowImportance
	table := cardOf(filters, header([]string{u.t("col_time"), u.t("col_event"), u.t("col_proc"), u.t("col_proto"), u.t("col_dst"), u.t("col_iface"), u.t("col_status")}, eventCols),
		container.New(fixed{h: 330}, u.timeline), note)

	u.detail = container.NewVBox()
	u.detailCard = newCard(container.NewVBox(caption(u.t("ev_detail")), u.detail))
	u.showDetail(contracts.Event{})
	return page(stats, table, u.detailCard.box)
}

func (u *UI) applyEvents(st contracts.Status) {
	outside := CountOf(st, "NET-001", "NET-012", "DNS-001")
	blocked := CountOf(st, "NET-002")
	open := OpenCount(st)
	u.evStats[0].set(fmt.Sprint(outside), u.t("ev_times"), map[bool]tone{true: toneBad, false: toneOK}[outside > 0], "")
	u.evStats[1].set(fmt.Sprint(blocked), u.t("ev_times"), map[bool]tone{true: toneWarn, false: toneOK}[blocked > 0], "")
	u.evStats[2].set(fmt.Sprint(open), "", toneOf(OpenWorst(st)), "")
	u.evStats[3].set(fmt.Sprint(len(u.evs)), "", toneMuted, "")
	opts := append([]string{u.t("filter_iface_all")}, Ifaces(u.evs)...)
	if strings.Join(opts, "\x00") != strings.Join(u.ifaceSel.Options, "\x00") {
		u.ifaceSel.Options = opts
		u.ifaceSel.Refresh()
	}
}

// showDetail fills the detail card with ev (an empty event: the hint).
func (u *UI) showDetail(ev contracts.Event) {
	u.detail.RemoveAll()
	if ev.Type == "" {
		hint := wrapped(u.t("ev_pick"))
		hint.Importance = widget.LowImportance
		u.detail.Add(hint)
		u.detailCard.setTone(toneMuted)
		u.detail.Refresh()
		return
	}
	r := RowOf(ev, u.lang)
	u.detailCard.setTone(map[bool]tone{true: toneBad, false: toneMuted}[r.Tone == toneBad])
	b := newBadge()
	b.set(r.Status, r.Tone)
	u.detail.Add(container.NewBorder(nil, nil, nil, b.box, text(r.Event, colText, 16, true, false)))
	if ev.Check != "" {
		tx := i18n.CheckText(u.lang, ev.Check)
		if tx.Meaning != "" {
			u.detail.Add(wrapped(tx.Meaning))
		}
		if tx.Todo != "" {
			todo := wrapped(u.t("what_now") + ": " + tx.Todo)
			todo.TextStyle = fyne.TextStyle{Bold: true}
			u.detail.Add(todo)
		}
	}
	grid := container.NewGridWithColumns(2)
	add := func(k, v string) {
		l := cell(true)
		l.Truncation = fyne.TextTruncateOff
		l.Wrapping = fyne.TextWrapBreak
		l.SetText(v)
		grid.Add(container.NewVBox(caption(strings.ToUpper(k)), l))
	}
	add(u.t("col_time"), ev.TS.Local().Format("2006-01-02 15:04:05.000"))
	add("seq", fmt.Sprint(ev.Seq))
	if ev.AlertID != "" {
		add("alert", clean(ev.AlertID))
	}
	for _, f := range EventFields(ev, u.lang) {
		add(f.Key, f.Value)
	}
	u.detail.Add(grid)
	if ev.AlertID != "" {
		if acts := ActionsTaken(u.evs, ev.AlertID, u.lang); len(acts) > 0 {
			u.detail.Add(wrapped(u.t("actions_done") + ": " + strings.Join(acts, " ")))
		}
	}
	u.detail.Refresh()
	u.relayout()
}

// ---- Guard ----

// modeCard is one of the three protections.
type modeCard struct {
	badge *badge
	card  *card
}

func (u *UI) buildGuard() fyne.CanvasObject {
	u.guardTitle = text("", colText, 22, true, false)
	u.guardDesc = wrapped("")
	u.guardState = newBadge()
	u.tablesOut = wrapped("")
	u.tablesOut.Importance = widget.LowImportance
	hero := cardOf(container.NewBorder(nil, nil, caption(u.t("guard_label_top")), u.guardState.box), u.guardTitle, u.guardDesc, u.tablesOut)

	u.modes = map[string]*modeCard{}
	var cards []fyne.CanvasObject
	for _, m := range []string{"off", "reactive", "strict"} {
		b := newBadge()
		desc := wrapped(u.t("mode_" + m + "_desc"))
		desc.Importance = widget.LowImportance
		icon := map[string]fyne.Resource{"off": theme.VisibilityIcon(), "reactive": theme.MediaFastForwardIcon(), "strict": theme.VisibilityOffIcon()}[m]
		c := newCard(container.NewVBox(container.NewBorder(nil, nil, iconTile(icon), container.NewCenter(b.box)),
			text(u.t("mode_"+m+"_title"), colText, 15, true, false), desc))
		u.modes[m] = &modeCard{badge: b, card: c}
		cards = append(cards, c.box)
	}
	modeNote := wrapped(u.t("mode_note"))
	modeNote.Importance = widget.LowImportance

	u.respWarn, u.respCrit = wrapped(""), wrapped("")
	resp := cardOf(caption(u.t("responses_title")),
		container.NewBorder(nil, nil, container.New(fixed{w: 90}, text("WARNING", colOchre, 12, true, true)), nil, u.respWarn),
		container.NewBorder(nil, nil, container.New(fixed{w: 90}, text("CRITICAL", colBrick, 12, true, true)), nil, u.respCrit),
		lowLabel(u.t("responses_note")))

	u.labOut = wrapped(u.t("lab_none"))
	u.labOut.Importance = widget.LowImportance
	quick := widget.NewButtonWithIcon(u.t("selftest_quick"), theme.MediaPlayIcon(), func() { u.runSelftest(false, nil) })
	full := widget.NewButton(u.t("selftest_full"), u.askSelftestFull)
	quick.Importance = widget.HighImportance
	u.labActs = container.NewVBox(container.NewHBox(quick), container.NewHBox(full))
	u.labNote = lowLabel(u.t("leaks_need_session"))
	lab := cardOf(caption(u.t("lab_title")), wrapped(u.t("lab_desc")), u.labActs, u.labNote, u.labOut)

	return page(hero, caption(u.t("modes_title")), container.NewGridWithColumns(3, cards...), modeNote,
		container.NewGridWithColumns(2, resp, lab))
}

func lowLabel(s string) *widget.Label {
	l := wrapped(s)
	l.Importance = widget.LowImportance
	return l
}

func (u *UI) applyGuard(st contracts.Status, session bool) {
	mode := guardOf(st)
	if !session {
		mode = "none"
	}
	u.guardTitle.Text = u.t("guard_now_" + mode)
	u.guardTitle.Refresh()
	u.guardDesc.SetText(u.t("guard_desc_" + mode))
	switch {
	case st.State == "PANIC":
		u.guardState.set(strings.ToUpper(u.t("state_panic")), toneBad)
	case st.Lockdown != nil:
		u.guardState.set(u.t("badge_blocked"), toneBad)
	case session && mode != "off":
		u.guardState.set(u.t("badge_armed"), toneGold)
	case session:
		u.guardState.set(u.t("badge_watching"), toneOK)
	default:
		u.guardState.set(u.t("badge_none"), toneMuted)
	}
	tables := u.t("tables_none")
	if l := st.Lockdown; l != nil {
		tables = fmt.Sprintf(u.t("tables_list"), l.What)
		if len(l.Tables) > 0 {
			tables += " (" + strings.Join(l.Tables, ", ") + ")"
		}
	}
	u.tablesOut.SetText(clean(tables))
	for m, c := range u.modes {
		if session && m == mode {
			c.badge.set(u.t("mode_current"), toneGold)
			c.card.setTone(toneGold)
		} else {
			c.badge.set("", toneMuted)
			c.card.setTone(toneMuted)
		}
	}
	w, c := Responses(mode)
	if !session {
		w, c = nil, nil
	}
	words := func(acts []string) string {
		if len(acts) == 0 {
			return "—"
		}
		var out []string
		for _, a := range acts {
			out = append(out, i18n.Text(u.lang, "actions", a))
		}
		return strings.Join(out, " ")
	}
	u.respWarn.SetText(words(w))
	u.respCrit.SetText(words(c))
	lab := session && u.offline == nil && st.State != "PANIC"
	show(u.labActs, lab)
	show(u.labNote, !lab)
}

// ---- Checks ----

func (u *UI) buildChecks() fyne.CanvasObject {
	var groups []fyne.CanvasObject
	grid := Grid(u.st, u.lang)
	for _, cat := range Categories {
		box := container.NewVBox(caption(strings.ToUpper(u.t("category_"+cat))), widget.NewSeparator())
		for _, r := range grid[cat] {
			l := widget.NewLabel("")
			l.Truncation = fyne.TextTruncateEllipsis
			u.rows[r.ID] = l
			box.Add(l)
		}
		groups = append(groups, newCard(box).box)
	}
	intro := lowLabel(u.t("checks_intro"))
	return page(intro, container.NewGridWithColumns(2, groups...))
}

func (u *UI) applyChecks(st contracts.Status) {
	for _, rows := range Grid(st, u.lang) {
		for _, r := range rows {
			l, ok := u.rows[r.ID]
			if !ok {
				continue
			}
			text := r.ID + "  " + r.Title + ": " + r.State
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
			setCell(l, text, imp)
		}
	}
}

// ---- Session ----

func (u *UI) buildSession() fyne.CanvasObject {
	u.sessID, u.sessStart, u.sessGuard = text("—", colText, 13, false, true), text("—", colText, 13, false, true), text("—", colText, 13, false, true)
	u.sessFP = widget.NewLabel("")
	u.sessFP.Selectable = true
	u.sessFP.TextStyle = fyne.TextStyle{Monospace: true}
	u.sessFP.Wrapping = fyne.TextWrapBreak
	field := func(key string, v fyne.CanvasObject) fyne.CanvasObject {
		return container.NewVBox(caption(u.t(key)), v)
	}
	u.actions = container.NewHBox(
		widget.NewButtonWithIcon(u.t("ack_btn"), theme.ConfirmIcon(), func() { u.askAck(u.panel) }),
		widget.NewButtonWithIcon(u.t("selftest_btn"), theme.MediaPlayIcon(), u.askSelftest),
		widget.NewButtonWithIcon(u.t("end_btn"), theme.LogoutIcon(), u.askEnd),
		layout.NewSpacer(),
		widget.NewButtonWithIcon(u.t("reports_btn"), theme.DocumentIcon(), u.showReports))
	u.sessInfo = container.NewVBox(cardOf(caption(u.t("session_label")), text(u.t("session_active"), colText, 22, true, false),
		container.NewGridWithColumns(2, field("session_id", u.sessID), field("session_guard", u.sessGuard)), field("session_started", u.sessStart),
		field("session_fp", u.sessFP), lowLabel(u.t("session_fp_note")), u.actions))
	u.sessOffline = cardOf(caption(u.t("session_label")), text(u.t("verdict_offline"), colText, 22, true, false), lowLabel(u.t("session_offline")))
	return page(u.sessInfo, u.sessOffline, u.firstForm.box, u.start)
}

func (u *UI) applySession(st contracts.Status, session, needsFirst bool) {
	first := !session && needsFirst // needs no daemon: the files are the operator's
	show(u.sessInfo, session)
	show(u.firstForm.box, first)
	show(u.start, !session && !first && u.offline == nil)
	show(u.sessOffline, !session && !first && u.offline != nil)
	if !session {
		return
	}
	set := func(t *canvas.Text, s string) {
		if t.Text != s {
			t.Text = s
			t.Refresh()
		}
	}
	set(u.sessID, clean(st.Session))
	start := "—"
	if st.StartedAt != nil {
		start = st.StartedAt.Local().Format("2006-01-02 15:04:05") + "  (" + span(u.opt.Now().Sub(*st.StartedAt)) + ")"
	}
	set(u.sessStart, start)
	set(u.sessGuard, u.t("guard_mode_"+guardOf(st)))
	fp := clean(st.Fingerprint)
	if fp == "" {
		fp = "—"
	}
	if u.sessFP.Text != fp {
		u.sessFP.SetText(fp)
	}
}

// guardOf is the session's guard mode; an older daemon that says none means off.
func guardOf(st contracts.Status) string {
	if st.Guard == "" {
		return "off"
	}
	return st.Guard
}
