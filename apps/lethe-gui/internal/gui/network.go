package gui

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"lethe/internal/profile"
	lsetup "lethe/internal/setup"
)

// baselineOf is the baseline file the profile at path names.
func baselineOf(path, home string) (string, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's own profile
	if err != nil {
		return "", err
	}
	p, _, err := profile.Parse(raw, home)
	if err != nil {
		return "", err
	}
	if p.Baseline.File == "" {
		return "", errors.New("profile: baseline.file is empty")
	}
	return p.Baseline.File, nil
}

// askAddNetwork registers the network this machine is on in the baseline (spec §15.1, the GUI's
// lethe baseline add-network): what the machine knows is filled in, the public IP is asked only
// on request and never through a tunnel, and the passphrase opens and seals the baseline again.
// It is offered with no session: the daemon reads the baseline when a session starts.
func (u *UI) askAddNetwork() {
	base, err := baselineOf(strings.TrimSpace(u.profile.Text), u.opt.Home)
	if err != nil {
		u.setFlash(u.t("addnet_btn") + ": " + err.Error())
		return
	}
	name, ip, resolvers, gateway := widget.NewEntry(), widget.NewEntry(), widget.NewEntry(), widget.NewEntry()
	for _, e := range []*widget.Entry{ip, resolvers, gateway} {
		e.TextStyle = fyne.TextStyle{Monospace: true}
	}
	note := wrapped(u.t("detect_ip_note"))
	note.Importance = widget.LowImportance
	pass := NewSecretEntry()
	fill := func(askIP bool, done func()) {
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
				keep := func(e *widget.Entry, v string) {
					if strings.TrimSpace(e.Text) == "" && v != "" {
						e.SetText(v)
					}
				}
				keep(gateway, d.Network.GatewayIP)
				keep(resolvers, strings.Join(d.Network.Resolvers, ", "))
				if askIP {
					v := d.Network.PublicIPv4
					if v == "" {
						v = d.Network.PublicIPv6
					}
					keep(ip, v)
					switch {
					case d.TunnelUp:
						note.SetText(u.t("detect_tunnel_up"))
					case v == "":
						note.SetText(u.t("detect_failed"))
					}
				}
				if done != nil {
					done()
				}
			})
		}()
	}
	var detect *widget.Button
	detect = widget.NewButton(u.t("detect_ip_btn"), func() {
		detect.Disable()
		fill(true, detect.Enable)
	})
	field := func(key string, o fyne.CanvasObject) fyne.CanvasObject {
		return container.NewVBox(widget.NewLabel(u.t(key)), o)
	}
	content := container.NewVBox(wrapped(u.t("addnet_intro")),
		container.NewGridWithColumns(2, field("net_name", name), field("net_gateway", gateway)),
		field("net_ip", container.NewBorder(nil, nil, nil, detect, ip)), note,
		field("net_resolvers", resolvers),
		field("passphrase", pass))
	d := dialog.NewCustomConfirm(u.t("addnet_btn"), u.t("addnet_save"), u.t("cancel"), content, func(ok bool) {
		pw := pass.Take()
		if !ok {
			wipe(pw)
			return
		}
		n := lsetup.Network{Name: strings.TrimSpace(name.Text), GatewayIP: strings.TrimSpace(gateway.Text)}
		if v := strings.TrimSpace(ip.Text); strings.Contains(v, ":") {
			n.PublicIPv6 = v
		} else {
			n.PublicIPv4 = v
		}
		for _, r := range strings.Split(resolvers.Text, ",") {
			if r = strings.TrimSpace(r); r != "" {
				n.Resolvers = append(n.Resolvers, r)
			}
		}
		u.setFlash(u.t("start_running"))
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			count, err := lsetup.AddNetwork(base, pw, n, u.opt.WorkFactor)
			wipe(pw)
			u.say(u.t("addnet_btn"), err, fmt.Sprintf(u.t("addnet_ok"), count))
		}()
	}, u.panel)
	d.Resize(fyne.NewSize(620, 0))
	d.Show()
	fill(false, nil) // local only: gateway and resolvers
}
