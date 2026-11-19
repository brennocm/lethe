package gui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Palette, taken from the logo (docs/assets/lethe-logo.webp): the charcoal of its background,
// the aged gold of the river and the lettering, the deep teal and the sage of the water. Each
// value has one job; nothing here is decoration.
var (
	colCanvas  = color.NRGBA{0x1f, 0x23, 0x24, 0xff} // window background (logo charcoal, a touch of teal)
	colRaised  = color.NRGBA{0x28, 0x30, 0x32, 0xff} // inputs, list rows, dialogs
	colRule    = color.NRGBA{0x3b, 0x47, 0x49, 0xff} // separators, input borders
	colText    = color.NRGBA{0xe9, 0xe3, 0xd3, 0xff} // primary text: warm paper on charcoal
	colText2   = color.NRGBA{0xa6, 0xae, 0xa1, 0xff} // secondary text, derived from the sage
	colGold    = color.NRGBA{0xc9, 0xad, 0x74, 0xff} // the one strong color: primary action, focus, a protected route
	colOnGold  = color.NRGBA{0x1f, 0x23, 0x24, 0xff} // text on gold
	colTeal    = color.NRGBA{0x2e, 0x57, 0x53, 0xff} // selection, pressed
	colSage    = color.NRGBA{0x8f, 0xae, 0x8a, 0xff} // a check that is fine
	colOchre   = color.NRGBA{0xd9, 0xa4, 0x41, 0xff} // WARNING
	colBrick   = color.NRGBA{0xd8, 0x5c, 0x44, 0xff} // CRITICAL, panic button, a broken route
	colPanicBg = color.NRGBA{0x5a, 0x1c, 0x16, 0xff} // the full-screen alert and the block notice
	colDim     = color.NRGBA{0x6d, 0x77, 0x72, 0xff} // disabled, a route not known yet
	colSidebar = color.NRGBA{0x19, 0x1c, 0x1d, 0xff} // the sidebar: the logo charcoal, a step darker
)

// lethe's theme: one dark composition, because the logo is dark and the panel is watched for
// hours in a dim room during an operation. The platform font stays (an Operate surface);
// monospace is used only for addresses, interfaces and IDs.
type letheTheme struct{}

// Theme is the GUI's theme.
func Theme() fyne.Theme { return letheTheme{} }

func (letheTheme) Color(n fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch n {
	case theme.ColorNameBackground, theme.ColorNameMenuBackground, theme.ColorNameHeaderBackground:
		return colCanvas
	case theme.ColorNameOverlayBackground, theme.ColorNameInputBackground:
		return colRaised
	case theme.ColorNameButton:
		return colRaised
	case theme.ColorNameDisabledButton:
		return colCanvas
	case theme.ColorNameInputBorder, theme.ColorNameSeparator:
		return colRule
	case theme.ColorNameForeground:
		return colText
	case theme.ColorNamePlaceHolder:
		return colText2
	case theme.ColorNameDisabled:
		return colDim
	case theme.ColorNamePrimary, theme.ColorNameFocus, theme.ColorNameHyperlink:
		return colGold
	case theme.ColorNameForegroundOnPrimary:
		return colOnGold
	case theme.ColorNameSelection:
		return colTeal
	case theme.ColorNameHover:
		return color.NRGBA{0xe9, 0xe3, 0xd3, 0x14}
	case theme.ColorNamePressed:
		return color.NRGBA{0x2e, 0x57, 0x53, 0x80}
	case theme.ColorNameScrollBar:
		return color.NRGBA{0xa6, 0xae, 0xa1, 0x55}
	case theme.ColorNameShadow:
		return color.NRGBA{0, 0, 0, 0x66}
	case theme.ColorNameSuccess:
		return colSage
	case theme.ColorNameWarning:
		return colOchre
	case theme.ColorNameError:
		return colBrick
	case theme.ColorNameForegroundOnError, theme.ColorNameForegroundOnWarning, theme.ColorNameForegroundOnSuccess:
		return colCanvas
	}
	return theme.DefaultTheme().Color(n, theme.VariantDark)
}

func (letheTheme) Font(s fyne.TextStyle) fyne.Resource     { return theme.DefaultTheme().Font(s) }
func (letheTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }

// Sizes on a ~1.2 scale for a dense Operate surface: 12, 14, 17, 24.
func (letheTheme) Size(n fyne.ThemeSizeName) float32 {
	switch n {
	case theme.SizeNameText:
		return 14
	case theme.SizeNameCaptionText:
		return 12
	case theme.SizeNameSubHeadingText:
		return 17
	case theme.SizeNameHeadingText:
		return 24
	case theme.SizeNameInputRadius:
		return 3
	case theme.SizeNameSelectionRadius:
		return 2
	case theme.SizeNameInnerPadding:
		return 8
	case theme.SizeNamePadding:
		return 4
	}
	return theme.DefaultTheme().Size(n)
}
