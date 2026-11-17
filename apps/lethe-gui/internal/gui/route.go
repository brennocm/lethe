package gui

import (
	"fmt"
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"

	"lethe/internal/contracts"
	"lethe/internal/i18n"
)

// Route is the path the traffic takes, as the panel draws it: this machine, the tunnel, and the
// address the web sees. Each hop has a state; a broken hop is drawn in brick and says why.
type Route struct {
	Machine string
	Tunnel  string // "" = unknown
	Exit    string // where the web sees you; "" = not checked yet
	Note    string // the line under the route: source and time of the last check
	Tun     HopState
	Out     HopState
}

// HopState is how a segment of the route is drawn.
type HopState int

// Segment states.
const (
	HopUnknown HopState = iota // dim: not known yet (no session, no answer)
	HopOK                      // gold: the traffic goes this way
	HopBroken                  // brick: a leak or a fallen tunnel
)

// RouteOf builds the route from the status. Only what the daemon says is shown: no address of
// the baseline ever reaches the status (spec §9.9).
func RouteOf(st contracts.Status, lang string) Route {
	r := Route{Machine: i18n.UI(lang, "route_machine"), Tunnel: i18n.UI(lang, "route_no_tunnel"), Exit: i18n.UI(lang, "route_no_exit")}
	if st.Session == "" {
		r.Note = i18n.UI(lang, "route_idle")
		return r
	}
	open := map[string]string{}
	for _, a := range st.Alerts {
		if !a.Acked || a.Severity == string(contracts.SeverityCritical) {
			if cur, ok := open[a.Check]; !ok || cur != string(contracts.SeverityCritical) {
				open[a.Check] = a.Severity
			}
		}
	}
	if e := st.Exit; e != nil {
		r.Tunnel = e.Path
		r.Tun = HopOK
		r.Exit = exitPlace(e, lang)
		r.Out = HopOK
		r.Note = fmt.Sprintf(i18n.UI(lang, "route_checked"), e.At.Local().Format("15:04:05"))
		if e.PlaceSource != "" {
			r.Note += ", " + fmt.Sprintf(i18n.UI(lang, "route_source"), e.PlaceSource)
		}
	} else {
		r.Note = i18n.UI(lang, "route_waiting")
	}
	for _, c := range []string{"TUN-001", "TUN-003"} {
		if _, ok := open[c]; ok {
			r.Tun, r.Out = HopBroken, HopBroken
		}
	}
	for _, c := range []string{"NET-001", "NET-003", "DNS-001"} {
		if open[c] == string(contracts.SeverityCritical) {
			r.Out = HopBroken
		}
	}
	if open["NET-011"] == string(contracts.SeverityCritical) {
		r.Out = HopBroken
		r.Exit = i18n.UI(lang, "route_real_ip")
	}
	if st.State == "PANIC" {
		r.Tun, r.Out = HopBroken, HopBroken
		r.Exit = i18n.UI(lang, "route_blocked")
	}
	return r
}

func exitPlace(e *contracts.ExitView, lang string) string {
	var place []string
	if e.City != "" {
		place = append(place, e.City)
	}
	switch {
	case e.PlaceCountry != "":
		place = append(place, e.PlaceCountry)
	case e.Country != "":
		place = append(place, e.Country)
	}
	s := strings.Join(place, ", ")
	if e.IP != "" {
		if s == "" {
			return e.IP
		}
		s = e.IP + "  " + s
	}
	if s == "" {
		return i18n.UI(lang, "route_no_exit")
	}
	return s
}

func hopColor(h HopState) color.Color {
	switch h {
	case HopOK:
		return colGold
	case HopBroken:
		return colBrick
	}
	return colDim
}

// routeView draws a Route: three labels joined by two lines that take the free width.
type routeView struct {
	labels [3]*canvas.Text
	lines  [2]*canvas.Line
	box    *fyne.Container
}

func newRouteView() *routeView {
	v := &routeView{}
	objs := make([]fyne.CanvasObject, 0, 5)
	for i := range v.labels {
		t := canvas.NewText("", colText)
		t.TextSize = 15
		if i > 0 {
			t.TextStyle = fyne.TextStyle{Monospace: true}
		}
		v.labels[i] = t
	}
	for i := range v.lines {
		l := canvas.NewLine(colDim)
		l.StrokeWidth = 3
		v.lines[i] = l
	}
	objs = append(objs, v.labels[0], v.lines[0], v.labels[1], v.lines[1], v.labels[2])
	v.box = fyne.NewContainerWithLayout(routeLayout{}, objs...) //nolint:staticcheck // a custom layout needs this constructor
	return v
}

func (v *routeView) set(r Route) {
	texts := [3]string{r.Machine, r.Tunnel, r.Exit}
	for i, t := range v.labels {
		t.Text = texts[i]
		t.Color = colText
		t.Refresh()
	}
	v.labels[1].Color = hopColor(r.Tun)
	if r.Tun == HopOK {
		v.labels[1].Color = colText
	}
	v.labels[2].Color = map[HopState]color.Color{HopBroken: colBrick, HopOK: colText, HopUnknown: colText2}[r.Out]
	v.labels[1].Refresh()
	v.labels[2].Refresh()
	for i, h := range []HopState{r.Tun, r.Out} {
		v.lines[i].StrokeColor = hopColor(h)
		v.lines[i].Refresh()
	}
}

// routeLayout: label, line, label, line, label on one row; the lines share the free width and
// sit on the text's middle.
type routeLayout struct{}

const routeGap = 12

func (routeLayout) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	var used float32
	for i := 0; i < len(objs); i += 2 {
		used += objs[i].MinSize().Width
	}
	free := size.Width - used - 4*routeGap
	if free < 0 {
		free = 0
	}
	x := float32(0)
	for i, o := range objs {
		if i%2 == 0 {
			m := o.MinSize()
			o.Resize(m)
			o.Move(fyne.NewPos(x, (size.Height-m.Height)/2))
			x += m.Width
			continue
		}
		x += routeGap
		l := o.(*canvas.Line)
		y := size.Height / 2
		l.Position1 = fyne.NewPos(x, y)
		l.Position2 = fyne.NewPos(x+free/2, y)
		x += free/2 + routeGap
	}
}

func (routeLayout) MinSize(objs []fyne.CanvasObject) fyne.Size {
	var w, h float32
	for i := 0; i < len(objs); i += 2 {
		m := objs[i].MinSize()
		w += m.Width
		h = max(h, m.Height)
	}
	return fyne.NewSize(w+4*routeGap+2*24, h+12)
}
