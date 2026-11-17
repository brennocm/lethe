package gui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
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
	f.opID, f.persona, f.country = entry(def.OpID), entry(def.Persona), entry(def.Country)
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

	title := widget.NewLabel(u.t("first_title"))
	title.TextStyle = fyne.TextStyle{Bold: true}
	intro := wrapped(u.t("first_intro"))
	sub := widget.NewLabel(u.t("real_net"))
	sub.TextStyle = fyne.TextStyle{Bold: true}
	field := func(key string, o fyne.CanvasObject) fyne.CanvasObject {
		return container.NewVBox(widget.NewLabel(u.t(key)), o)
	}
	form := container.NewVBox(title, intro,
		container.NewGridWithColumns(2, field("op_id", f.opID), field("persona", f.persona)),
		container.NewGridWithColumns(2, field("egress_type", f.egress), field("expect_country", f.country)),
		container.NewGridWithColumns(3, field("persona_tz", f.tz), field("persona_locale", f.locale), field("persona_kb", f.kb)),
		widget.NewSeparator(), sub,
		container.NewGridWithColumns(2, field("net_name", f.netName), field("net_gateway", f.gateway)),
		field("net_ip", container.NewBorder(nil, nil, nil, f.detectBtn, f.netIP)), f.detectNote,
		field("net_resolvers", f.resolvers),
		widget.NewSeparator(),
		container.NewGridWithColumns(2, field("new_pass", f.pass1), field("new_pass2", f.pass2)))
	if u.opt.X11 {
		x := wrapped(u.t("x11_warning"))
		x.Importance = widget.LowImportance
		form.Add(x)
	}
	form.Add(container.NewHBox(f.createBtn))
	u.firstForm = f
	f.box = container.NewStack(container.NewVScroll(container.NewHBox(container.New(&maxWidth{w: 720}, form))))
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
				f.detectNote.SetText(u.t("detect_tunnel_up"))
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
	a.OpID, a.Persona, a.Egress, a.Country = tr(f.opID), tr(f.persona), f.egressByLabel[f.egress.Selected], tr(f.country)
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
	if len(p1) < minPassphrase || string(p1) != string(p2) {
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
