package gui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"

	"lethe/internal/buildinfo"
	lsetup "lethe/internal/setup"
)

// minPassphrase is the baseline's own floor (baseline.Encrypt refuses less).
const minPassphrase = 8

// firstUse is the first-use form (spec §15.1): shown instead of the start form while the default
// profile does not exist. It writes the profile and the baseline as the operator; it needs no
// daemon and no key: the only secret is the passphrase, typed twice.
type firstUse struct {
	box                         *fyne.Container
	opID, persona, country      *widget.Entry
	tz, locale, kb              *widget.Entry
	netName, netIP, resolvers   *widget.Entry
	gateway                     *widget.Entry
	egress                      *widget.Select
	detectNote                  *widget.Label
	detectBtn, createBtn        *widget.Button
	pass1, pass2                *SecretEntry
	egressLabels, egressByLabel map[string]string
	baseExists                  bool // a baseline is already there: kept, opened with its passphrase
	// the form goes in steps, in the order the operator does them: the real network with the
	// VPN off, then the persona, then the passphrase
	step       int
	steps      []*fyne.Container
	stepNames  []*canvas.Text
	back, next *widget.Button
	tunnelUp   bool // the last detection saw a tunnel carrying the default route
	tunnelNote *widget.Label
}

// needsFirstUse: the operator's home is known and its default profile is missing.
func (u *UI) needsFirstUse() bool {
	return u.opt.Home != "" && !lsetup.Exists(u.firstDir())
}

func (u *UI) firstDir() string { return lsetup.Defaults(u.opt.Home).Dir }

func (u *UI) buildFirstUse() {
	f := &firstUse{egressLabels: map[string]string{}, egressByLabel: map[string]string{}}
	def := lsetup.Defaults(u.opt.Home)
	entry := func(v string) *widget.Entry {
		e := widget.NewEntry()
		e.SetText(v)
		return e
	}
	// the operation ID and the persona have no real default: an example, as a placeholder
	example := func(v string) *widget.Entry {
		e := widget.NewEntry()
		e.SetPlaceHolder(v)
		return e
	}
	f.opID, f.persona, f.country = example(def.OpID), example(def.Persona), entry(def.Country)
	f.tz, f.locale, f.kb = entry(def.Timezone), entry(def.Locale), entry(def.Keyboard)
	f.netName, f.netIP, f.resolvers, f.gateway = entry(def.Network.Name), entry(""), entry(""), entry("")
	f.netIP.TextStyle = fyne.TextStyle{Monospace: true}
	f.resolvers.TextStyle = fyne.TextStyle{Monospace: true}
	f.gateway.TextStyle = fyne.TextStyle{Monospace: true}
	labels := make([]string, 0, len(lsetup.Egresses))
	for _, e := range lsetup.Egresses {
		l := e
		if e == "auto" {
			l = u.t("egress_auto")
		}
		f.egressLabels[e], f.egressByLabel[l] = l, e
		labels = append(labels, l)
	}
	f.egress = widget.NewSelect(labels, nil)
	f.egress.SetSelected(f.egressLabels[def.Egress])
	f.detectNote = wrapped(u.t("detect_ip_note"))
	f.detectNote.Importance = widget.LowImportance
	f.detectBtn = widget.NewButton(u.t("detect_ip_btn"), func() { u.detect(true) })
	f.pass1, f.pass2 = NewSecretEntry(), NewSecretEntry()
	f.createBtn = widget.NewButton(u.t("first_btn"), u.createFirst)
	f.createBtn.Importance = widget.HighImportance
	f.pass2.OnSubmit = u.createFirst

	title := text(u.t("first_title"), colText, 20, true, false)
	intro := wrapped(u.t("first_intro"))
	// a label is small and muted above its field, so it never reads as typed text
	field := func(key string, o fyne.CanvasObject) fyne.CanvasObject {
		return container.NewVBox(pad(text(u.t(key), colText2, 12, false, false), 0, 2), o)
	}
	f.tunnelNote = wrapped(u.t("first_tunnel_up"))
	f.tunnelNote.Importance = widget.DangerImportance
	f.tunnelNote.Hide()
	network := container.NewVBox(pad(text(u.t("first_net_hint"), colText2, 13, false, false), 0, 4), f.tunnelNote,
		container.NewGridWithColumns(2, field("net_name", f.netName), field("net_gateway", f.gateway)),
		field("net_ip", container.NewBorder(nil, nil, nil, f.detectBtn, f.netIP)), f.detectNote,
		field("net_resolvers", f.resolvers))
	passes := container.NewGridWithColumns(2, field("new_pass", f.pass1), field("new_pass2", f.pass2))
	_, base, _ := lsetup.Paths(u.firstDir())
	if _, err := os.Stat(base); err == nil {
		// the baseline is kept: its own passphrase, and no network questions (they would be lost)
		f.baseExists = true
		network = container.NewVBox(wrapped(fmt.Sprintf(u.t("first_base_exists"), base)))
		passes = container.NewGridWithColumns(2, field("passphrase", f.pass1), field("new_pass2", f.pass2))
	}
	persona := container.NewVBox(
		container.NewGridWithColumns(2, field("op_id", f.opID), field("persona", f.persona)),
		container.NewGridWithColumns(2, field("egress_type", f.egress), field("expect_country", f.country)),
		container.NewGridWithColumns(3, field("persona_tz", f.tz), field("persona_locale", f.locale), field("persona_kb", f.kb)))
	pass := container.NewVBox(passes)
	if u.opt.X11 {
		x := wrapped(u.t("x11_warning"))
		x.Importance = widget.LowImportance
		pass.Add(x)
	}
	after := wrapped(u.t("first_after"))
	after.Importance = widget.LowImportance
	pass.Add(after)
	f.steps = []*fyne.Container{network, persona, pass}
	row := container.NewHBox()
	for i, k := range []string{"real_net", "sec_persona", "sec_pass"} {
		n := text(fmt.Sprintf("%d  %s", i+1, strings.ToUpper(u.t(k))), colDim, 12, true, false)
		f.stepNames = append(f.stepNames, n)
		if i > 0 {
			row.Add(text("›", colDim, 12, false, false))
		}
		row.Add(n)
	}
	f.back = widget.NewButton(u.t("step_back"), func() { u.firstStep(f.step - 1) })
	f.next = widget.NewButton(u.t("step_next"), func() {
		if f.step == 1 { // every field Validate checks is on the persona step: say it here
			a := u.firstAnswers()
			if err := a.Validate(); err != nil {
				u.setFlash(u.t("first_title") + ": " + err.Error())
				return
			}
			u.setFlash("")
		}
		u.firstStep(f.step + 1)
	})
	f.next.Importance = widget.HighImportance
	form := container.NewVBox(title, intro, widget.NewSeparator(), pad(row, 0, 4), network, persona, pass,
		container.NewHBox(f.back, f.next, f.createBtn))
	u.firstForm = f
	u.firstStep(0)
	// no scroll of its own: the Session page scrolls, and a scroll inside its VBox gets the
	// minimum height (one line), which showed the title alone
	f.box = container.NewHBox(container.New(&maxWidth{w: 720}, newCard(form).box))
}

// firstStep shows step i of the first-use form. The network step does not go on while a tunnel
// carries the default route: what it would record is the tunnel, not the real network.
func (u *UI) firstStep(i int) {
	f := u.firstForm
	if i < 0 || i >= len(f.steps) {
		return
	}
	f.step = i
	for k, c := range f.steps {
		show(c, k == i)
		col := colDim
		switch {
		case k == i:
			col = colGold
		case k < i:
			col = colSage
		}
		if f.stepNames[k].Color != col {
			f.stepNames[k].Color = col
			f.stepNames[k].Refresh()
		}
	}
	block := i == 0 && f.tunnelUp && !f.baseExists
	show(f.tunnelNote, block)
	show(f.back, i > 0)
	show(f.next, i < len(f.steps)-1)
	show(f.createBtn, i == len(f.steps)-1)
	if block {
		f.next.Disable()
	} else {
		f.next.Enable()
	}
}

// detect fills what the machine knows (local reading; askIP also asks the public IP, never with
// a tunnel up). Fields the operator already typed are kept.
func (u *UI) detect(askIP bool) {
	f := u.firstForm
	if askIP {
		f.detectBtn.Disable()
	}
	run := u.opt.Detect
	if run == nil {
		run = lsetup.LiveDetect
	}
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		d := run(ctx, askIP)
		fyne.Do(func() {
			f.detectBtn.Enable()
			f.tunnelUp = d.TunnelUp
			u.firstStep(f.step)
			keep := func(e *widget.Entry, v string) {
				if strings.TrimSpace(e.Text) == "" && v != "" {
					e.SetText(v)
				}
			}
			keep(f.gateway, d.Network.GatewayIP)
			keep(f.resolvers, strings.Join(d.Network.Resolvers, ", "))
			if f.egressByLabel[f.egress.Selected] == "auto" && d.Egress != "" {
				f.egress.SetSelected(f.egressLabels[d.Egress])
			}
			if !askIP {
				return
			}
			ip := d.Network.PublicIPv4
			if ip == "" {
				ip = d.Network.PublicIPv6
			}
			keep(f.netIP, ip)
			switch {
			case d.TunnelUp:
				f.detectNote.SetText(u.t("detect_ip_note")) // the red note above says why
			case ip == "":
				f.detectNote.SetText(u.t("detect_failed"))
			default:
				f.detectNote.SetText(u.t("detect_ip_note"))
			}
		})
	}()
}

// FirstAnswers reads the form into setup answers.
func (u *UI) firstAnswers() lsetup.Answers {
	f := u.firstForm
	a := lsetup.Defaults(u.opt.Home)
	tr := func(e *widget.Entry) string { return strings.TrimSpace(e.Text) }
	orExample := func(e *widget.Entry) string { // left empty: the example it shows
		if v := tr(e); v != "" {
			return v
		}
		return e.PlaceHolder
	}
	a.OpID, a.Persona, a.Egress, a.Country = orExample(f.opID), orExample(f.persona), f.egressByLabel[f.egress.Selected], tr(f.country)
	a.Timezone, a.Locale, a.Keyboard = tr(f.tz), tr(f.locale), tr(f.kb)
	a.WorkLimit = u.opt.WorkFactor
	a.Network.Name, a.Network.GatewayIP = tr(f.netName), tr(f.gateway)
	if ip := tr(f.netIP); strings.Contains(ip, ":") {
		a.Network.PublicIPv6 = ip
	} else {
		a.Network.PublicIPv4 = ip
	}
	for _, r := range strings.Split(f.resolvers.Text, ",") {
		if r = strings.TrimSpace(r); r != "" {
			a.Network.Resolvers = append(a.Network.Resolvers, r)
		}
	}
	return a
}

func (u *UI) createFirst() {
	f := u.firstForm
	p1, p2 := f.pass1.Take(), f.pass2.Take()
	if (len(p1) < minPassphrase && !f.baseExists) || len(p1) == 0 || string(p1) != string(p2) {
		wipe(p1)
		wipe(p2)
		u.setFlash(u.t("pass_mismatch"))
		return
	}
	wipe(p2)
	a := u.firstAnswers()
	if err := a.Validate(); err != nil {
		wipe(p1)
		u.setFlash(u.t("first_title") + ": " + err.Error())
		u.firstStep(1)
		return
	}
	f.createBtn.Disable()
	u.setFlash(u.t("start_running"))
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		path, err := lsetup.Create(a, u.opt.Home, p1, u.opt.Now(), buildinfo.Version)
		wipe(p1)
		fyne.Do(func() {
			f.createBtn.Enable()
			if err != nil {
				u.setFlash(u.t("first_title") + ": " + err.Error())
				return
			}
			u.profile.SetText(path)
			u.refreshStrict()
			u.setFlash(fmt.Sprintf(u.t("first_ok"), path))
			u.Apply(u.st, nil)
		})
	}()
}
