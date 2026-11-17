package gui

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"lethe/internal/profile"
)

// maxReport bounds what the panel reads of a report.md.
const maxReport = 1 << 20

// SessionReport is a past session the panel can show.
type SessionReport struct {
	ID     string
	Ended  time.Time // report.md's time: when the session closed
	Path   string    // report.md ("" = none: institutional keys, or a session cut short)
	Folder string
}

// Reports lists the sessions under the profile's storage.dir, newest first. The daemon writes
// report.md, already verified against the journal, when a session ends (spec §14.5); the
// sessions directory is root:operator 02750, so the operator reads it without privileges.
func Reports(profilePath, home string) ([]SessionReport, error) {
	raw, err := os.ReadFile(profilePath) // #nosec G304 -- the operator's own profile
	if err != nil {
		return nil, err
	}
	p, _, err := profile.Parse(raw, home)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(p.Storage.Dir, "sessions")
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []SessionReport
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		r := SessionReport{ID: e.Name(), Folder: filepath.Join(dir, e.Name())}
		if fi, err := os.Stat(filepath.Join(r.Folder, "report.md")); err == nil && fi.Mode().IsRegular() {
			r.Path, r.Ended = filepath.Join(r.Folder, "report.md"), fi.ModTime()
		} else if fi, err := e.Info(); err == nil {
			r.Ended = fi.ModTime()
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ended.After(out[j].Ended) })
	return out, nil
}

// readReport reads at most maxReport bytes of a report, as printable text.
func readReport(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- a report.md under the operator's storage.dir
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxReport))
	if err != nil {
		return "", err
	}
	return strings.Map(func(r rune) rune {
		if shown(r) {
			return r
		}
		return -1
	}, string(raw)), nil
}

// shown: a rune the report may draw. Control characters (C0, DEL, C1) and the bidi overrides
// and isolates, which could reorder what the operator reads, are dropped.
func shown(r rune) bool {
	switch {
	case r == '\n', r == '\t':
		return true
	case r < 0x20, r == 0x7f, r >= 0x80 && r < 0xa0:
		return false
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		return false
	}
	return true
}

// showReports lists past sessions; choosing one opens its report.
func (u *UI) showReports() {
	list, err := Reports(strings.TrimSpace(u.profile.Text), u.opt.Home)
	if err != nil {
		u.setFlash(u.t("reports_btn") + ": " + err.Error())
		return
	}
	if len(list) == 0 {
		u.setFlash(u.t("reports_none"))
		return
	}
	var d dialog.Dialog
	rows := widget.NewList(func() int { return len(list) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			r := list[i]
			line := r.Ended.Local().Format("2006-01-02 15:04") + "   " + r.ID
			if r.Path == "" {
				line += "   (" + u.t("reports_missing") + ")"
			}
			o.(*widget.Label).SetText(line)
		})
	rows.OnSelected = func(i widget.ListItemID) {
		rows.UnselectAll()
		r := list[i]
		if r.Path == "" {
			u.setFlash(u.t("reports_missing_how"))
			return
		}
		text, err := readReport(r.Path)
		if err != nil {
			u.setFlash(u.t("reports_btn") + ": " + err.Error())
			return
		}
		body := widget.NewLabel(text)
		body.TextStyle = fyne.TextStyle{Monospace: true}
		v := dialog.NewCustom(r.ID, u.t("close"), container.NewScroll(body), u.panel)
		v.Resize(fyne.NewSize(900, 640))
		d.Hide()
		v.Show()
	}
	d = dialog.NewCustom(u.t("reports_btn"), u.t("close"), container.NewBorder(wrapped(u.t("reports_intro")), nil, nil, nil, rows), u.panel)
	d.Resize(fyne.NewSize(620, 460))
	d.Show()
}
