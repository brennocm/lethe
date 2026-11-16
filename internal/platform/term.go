package platform

import "strings"

// TermSafe replaces control characters (C0, DEL, C1) with '?'. Process names, executable paths
// and DNS names are attacker-controlled; printed raw, an escape sequence could rewrite the
// operator's terminal (hide an alert, fake a status line, set the title).
func TermSafe(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}
