package checks

import "lethe/internal/i18n"

// Title is the short operator-facing name of check id (spec §9) in lang ("en-US" or anything
// else = pt-BR). Notifications, the TUI and the GUI use it. The texts live in internal/i18n.
func Title(id, lang string) string { return i18n.CheckText(lang, id).Title }
