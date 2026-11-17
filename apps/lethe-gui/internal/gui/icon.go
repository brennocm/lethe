package gui

import (
	"bytes"
	_ "embed"
	"image"
	"image/color"
	"image/png"
	"strconv"

	"fyne.io/fyne/v2"
)

// Tray icon (spec §16.1): a disc in the state colour with the number of open alerts.

var stateColors = map[string]color.NRGBA{
	"GREEN":  {0x2e, 0x9e, 0x44, 0xff},
	"YELLOW": {0xe0, 0xa8, 0x00, 0xff},
	"RED":    {0xd3, 0x20, 0x20, 0xff},
	"GRAY":   {0x80, 0x80, 0x80, 0xff},
}

// 3×5 digits, one row per byte (bit 2 = left column).
var digits = [10][5]byte{
	{7, 5, 5, 5, 7}, {2, 6, 2, 2, 7}, {7, 1, 7, 4, 7}, {7, 1, 7, 1, 7}, {5, 5, 7, 1, 1},
	{7, 4, 7, 1, 7}, {7, 4, 7, 5, 7}, {7, 1, 1, 1, 1}, {7, 5, 7, 5, 7}, {7, 5, 7, 1, 7},
}

// TrayIcon draws the icon for colour c (GREEN, YELLOW, RED, GRAY) and n open alerts (9+ above 9).
func TrayIcon(c string, n int) fyne.Resource {
	const size = 64
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	fill, ok := stateColors[c]
	if !ok {
		fill = stateColors["GRAY"]
	}
	for y := range size {
		for x := range size {
			dx, dy := x-size/2, y-size/2
			if dx*dx+dy*dy <= (size/2-2)*(size/2-2) {
				img.Set(x, y, fill)
			}
		}
	}
	if n > 0 {
		s := strconv.Itoa(min(n, 9))
		if n > 9 {
			s += "+"
		}
		const scale = 7
		w := len(s)*4*scale - scale
		x0, y0 := (size-w)/2, (size-5*scale)/2
		for i, ch := range s {
			var g [5]byte
			if ch == '+' {
				g = [5]byte{0, 2, 7, 2, 0}
			} else {
				g = digits[ch-'0']
			}
			for row := range 5 {
				for col := range 3 {
					if g[row]&(4>>col) == 0 {
						continue
					}
					for yy := range scale {
						for xx := range scale {
							img.Set(x0+i*4*scale+col*scale+xx, y0+row*scale+yy, color.White)
						}
					}
				}
			}
		}
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return fyne.NewStaticResource("lethe-"+c+"-"+strconv.Itoa(n)+".png", b.Bytes())
}

//go:embed lethe.svg
var appIconSVG []byte

// AppIcon is the window and launcher icon; the package installs the same file for the
// application menu (packaging/desktop).
func AppIcon() fyne.Resource { return fyne.NewStaticResource("lethe.svg", appIconSVG) }
