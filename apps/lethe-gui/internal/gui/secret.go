package gui

import (
	"strings"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"golang.org/x/sys/unix"
)

// SecretEntry takes the passphrase. widget.Entry keeps its text in a string, which can be
// neither locked nor wiped; this one keeps the bytes in a fixed, mlocked buffer, shows only dots
// and is wiped after use (AGENTS.md: secrets in []byte, never string).
type SecretEntry struct {
	widget.BaseWidget
	buf      []byte
	n        int
	dots     *widget.Label
	focused  bool
	border   *canvas.Rectangle
	OnSubmit func()
}

// NewSecretEntry builds an empty entry.
func NewSecretEntry() *SecretEntry {
	e := &SecretEntry{buf: make([]byte, 256), dots: widget.NewLabel(" ")}
	_ = unix.Mlock(e.buf) // best effort (spec §19.3)
	e.border = canvas.NewRectangle(theme.Color(theme.ColorNameInputBackground))
	e.border.StrokeColor = theme.Color(theme.ColorNameInputBorder)
	e.border.StrokeWidth = 1
	e.ExtendBaseWidget(e)
	return e
}

// CreateRenderer implements fyne.Widget.
func (e *SecretEntry) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(container.NewStack(e.border, e.dots))
}

// MinSize keeps room for a long passphrase.
func (e *SecretEntry) MinSize() fyne.Size {
	return fyne.NewSize(260, e.dots.MinSize().Height)
}

// Tapped focuses the entry.
func (e *SecretEntry) Tapped(*fyne.PointEvent) {
	if c := fyne.CurrentApp().Driver().CanvasForObject(e); c != nil {
		c.Focus(e)
	}
}

// FocusGained implements fyne.Focusable.
func (e *SecretEntry) FocusGained() {
	e.focused = true
	e.border.StrokeColor = theme.Color(theme.ColorNamePrimary)
	e.border.Refresh()
}

// FocusLost implements fyne.Focusable.
func (e *SecretEntry) FocusLost() {
	e.focused = false
	e.border.StrokeColor = theme.Color(theme.ColorNameInputBorder)
	e.border.Refresh()
}

// TypedRune implements fyne.Focusable.
func (e *SecretEntry) TypedRune(r rune) {
	var tmp [utf8.UTFMax]byte
	n := utf8.EncodeRune(tmp[:], r)
	if e.n+n <= len(e.buf) {
		copy(e.buf[e.n:], tmp[:n])
		e.n += n
	}
	clear(tmp[:])
	e.show()
}

// TypedKey implements fyne.Focusable.
func (e *SecretEntry) TypedKey(k *fyne.KeyEvent) {
	switch k.Name {
	case fyne.KeyBackspace:
		for e.n > 0 {
			e.n--
			c := e.buf[e.n]
			e.buf[e.n] = 0
			if c&0xc0 != 0x80 {
				break
			}
		}
		e.show()
	case fyne.KeyReturn, fyne.KeyEnter:
		if e.OnSubmit != nil {
			e.OnSubmit()
		}
	}
}

func (e *SecretEntry) show() {
	e.dots.SetText(strings.Repeat("•", utf8.RuneCount(e.buf[:e.n])) + " ")
}

// Len is the number of bytes typed.
func (e *SecretEntry) Len() int { return e.n }

// Take hands over a copy of the passphrase and wipes the entry; the caller wipes the copy.
func (e *SecretEntry) Take() []byte {
	out := make([]byte, e.n)
	_ = unix.Mlock(out)
	copy(out, e.buf[:e.n])
	e.Wipe()
	return out
}

// Wipe clears the entry.
func (e *SecretEntry) Wipe() {
	clear(e.buf)
	e.n = 0
	e.show()
}

func wipe(b []byte) {
	clear(b)
	_ = unix.Munlock(b)
}
