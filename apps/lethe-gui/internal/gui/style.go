package gui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// The panel's building blocks (ADR 0016): cards on the charcoal canvas, small monospace labels,
// badges whose color says the state, and the sidebar's navigation items. Colors come only from
// theme.go.

// tone is the state a badge, a number or a border shows.
type tone int

const (
	toneMuted tone = iota // unknown, no session
	toneOK                // fine: sage
	toneWarn              // WARNING: ochre
	toneBad               // CRITICAL, a block: brick
	toneGold              // the protected route and the primary action
)

func toneColor(t tone) color.NRGBA {
	switch t {
	case toneOK:
		return colSage
	case toneWarn:
		return colOchre
	case toneBad:
		return colBrick
	case toneGold:
		return colGold
	}
	return colDim
}

// toneOf is the tone of a severity ("" = fine).
func toneOf(sev string) tone {
	switch sev {
	case "CRITICAL":
		return toneBad
	case "WARNING":
		return toneWarn
	}
	return toneOK
}

// tint is c at alpha a (badge fills: 0x26 ≈ 15 %).
func tint(c color.NRGBA, a uint8) color.NRGBA { c.A = a; return c }

// text is a canvas text in the panel's palette.
func text(s string, c color.Color, size float32, bold, mono bool) *canvas.Text {
	t := canvas.NewText(s, c)
	t.TextSize = size
	t.TextStyle = fyne.TextStyle{Bold: bold, Monospace: mono}
	return t
}

// caption is a section label: small, monospace, uppercase by its text.
func caption(s string) *canvas.Text { return text(s, colText2, 11, true, true) }

// pad wraps o with the given padding.
func pad(o fyne.CanvasObject, v, h float32) *fyne.Container {
	return container.New(layout.NewCustomPaddedLayout(v, v, h, h), o)
}

// card is a raised surface with a thin border; its border takes the tone's color when it is
// not muted (a block, a leak).
type card struct {
	bg  *canvas.Rectangle
	box *fyne.Container
}

func newCard(content fyne.CanvasObject) *card {
	bg := canvas.NewRectangle(colRaised)
	bg.CornerRadius = 12
	bg.StrokeColor = colRule
	bg.StrokeWidth = 1
	return &card{bg: bg, box: container.NewStack(bg, pad(content, 14, 16))}
}

func (c *card) setTone(t tone) {
	if t == toneMuted || t == toneOK {
		c.bg.FillColor, c.bg.StrokeColor = colRaised, colRule
	} else {
		col := toneColor(t)
		c.bg.FillColor, c.bg.StrokeColor = colRaised, tint(col, 0xb0)
		if t == toneBad {
			c.bg.FillColor = colPanicBg
		}
	}
	c.bg.Refresh()
}

// cardOf is a plain card's object.
func cardOf(content ...fyne.CanvasObject) fyne.CanvasObject {
	return newCard(container.NewVBox(content...)).box
}

// badge is a small pill with a state word.
type badge struct {
	bg  *canvas.Rectangle
	t   *canvas.Text
	box *fyne.Container
}

func newBadge() *badge {
	b := &badge{bg: canvas.NewRectangle(color.Transparent), t: text("", colText2, 11, true, true)}
	b.bg.CornerRadius = 6
	b.box = container.NewStack(b.bg, pad(b.t, 3, 8))
	return b
}

func (b *badge) set(s string, t tone) {
	col := toneColor(t)
	if t == toneMuted {
		col = colText2
	}
	b.t.Text, b.t.Color = s, col
	b.bg.FillColor = tint(col, 0x26)
	b.t.Refresh()
	b.bg.Refresh()
	if s == "" {
		b.box.Hide()
	} else {
		b.box.Show()
	}
}

// fixed lays its children out exactly w wide (0 = free) and at least h tall.
type fixed struct{ w, h float32 }

func (f fixed) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	for _, o := range objs {
		o.Resize(size)
		o.Move(fyne.NewPos(0, 0))
	}
}

func (f fixed) MinSize(objs []fyne.CanvasObject) fyne.Size {
	var s fyne.Size
	for _, o := range objs {
		s = s.Max(o.MinSize())
	}
	if f.w > 0 {
		s.Width = f.w
	}
	return fyne.NewSize(s.Width, max(s.Height, f.h))
}

// navItem is one entry of the sidebar: icon and name, a gold pip and a raised background when
// it is the page on screen.
type navItem struct {
	widget.BaseWidget
	icon         *widget.Icon
	res          fyne.Resource
	name         *canvas.Text
	pip, bg      *canvas.Rectangle
	active, over bool
	onTap        func()
}

var _ desktop.Hoverable = (*navItem)(nil)

func newNavItem(res fyne.Resource, name string, tap func()) *navItem {
	n := &navItem{res: res, onTap: tap, name: text(name, colText2, 13, false, false),
		pip: canvas.NewRectangle(color.Transparent), bg: canvas.NewRectangle(color.Transparent)}
	n.icon = widget.NewIcon(theme.NewColoredResource(res, theme.ColorNamePlaceHolder))
	n.pip.SetMinSize(fyne.NewSize(3, 22))
	n.pip.CornerRadius = 2
	n.bg.CornerRadius = 8
	n.ExtendBaseWidget(n)
	return n
}

func (n *navItem) CreateRenderer() fyne.WidgetRenderer {
	row := container.NewBorder(nil, nil, container.NewHBox(n.pip, n.icon), nil, n.name)
	return widget.NewSimpleRenderer(container.NewStack(n.bg, pad(row, 6, 4)))
}

func (n *navItem) setActive(on bool) {
	n.active = on
	n.paint()
}

func (n *navItem) paint() {
	switch {
	case n.active:
		n.bg.FillColor, n.pip.FillColor, n.name.Color = tint(colTeal, 0x99), colGold, colText
		n.name.TextStyle.Bold = true
		n.icon.SetResource(theme.NewColoredResource(n.res, theme.ColorNamePrimary))
	case n.over:
		n.bg.FillColor, n.pip.FillColor, n.name.Color = color.NRGBA{0xe9, 0xe3, 0xd3, 0x10}, color.Transparent, colText
		n.name.TextStyle.Bold = false
	default:
		n.bg.FillColor, n.pip.FillColor, n.name.Color = color.Transparent, color.Transparent, colText2
		n.name.TextStyle.Bold = false
		n.icon.SetResource(theme.NewColoredResource(n.res, theme.ColorNamePlaceHolder))
	}
	n.bg.Refresh()
	n.pip.Refresh()
	n.name.Refresh()
}

func (n *navItem) Tapped(*fyne.PointEvent) {
	if n.onTap != nil {
		n.onTap()
	}
}

func (n *navItem) MouseIn(*desktop.MouseEvent)    { n.over = true; n.paint() }
func (n *navItem) MouseMoved(*desktop.MouseEvent) {}
func (n *navItem) MouseOut()                      { n.over = false; n.paint() }

// cols lays a table row out: each child gets its share of the width (weights), one line high.
type cols struct{ w []float32 }

func (c cols) Layout(objs []fyne.CanvasObject, size fyne.Size) {
	var total float32
	for _, w := range c.w {
		total += w
	}
	x := float32(0)
	for i, o := range objs {
		if i >= len(c.w) {
			o.Hide()
			continue
		}
		w := size.Width * c.w[i] / total
		o.Resize(fyne.NewSize(w-6, size.Height))
		o.Move(fyne.NewPos(x, 0))
		x += w
	}
}

func (c cols) MinSize(objs []fyne.CanvasObject) fyne.Size {
	var h float32
	for _, o := range objs {
		h = max(h, o.MinSize().Height)
	}
	return fyne.NewSize(float32(len(c.w))*40, h)
}

// cell is a table cell: one line, cut with an ellipsis.
func cell(mono bool) *widget.Label {
	l := widget.NewLabel("")
	l.Truncation = fyne.TextTruncateEllipsis
	l.TextStyle = fyne.TextStyle{Monospace: mono}
	return l
}

// show sets o's visibility.
func show(o fyne.CanvasObject, on bool) {
	if on {
		o.Show()
	} else {
		o.Hide()
	}
}
