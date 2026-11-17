// Command lethe-gui is the optional desktop interface of lethe (spec §16): the tray, the panel
// and the full-screen alert. It runs as the operator, started by the session agent through
// systemd --user (or by hand), and talks to the daemon only over IPC.
package main

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strconv"

	"fyne.io/fyne/v2/app"

	"lethe/apps/lethe-gui/internal/gui"
)

func main() {
	sock := flag.String("socket", filepath.Join("/run/user", strconv.Itoa(os.Getuid()), "lethe", "lethe.sock"), "daemon socket")
	lang := flag.String("lang", os.Getenv("LETHE_LANG"), "pt-BR or en-US")
	flag.Parse()
	a := app.NewWithID("io.lethe.gui")
	x11 := os.Getenv("XDG_SESSION_TYPE") == "x11" || (os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DISPLAY") != "")
	u := gui.New(a, gui.Client{Socket: *sock}, gui.Options{Lang: *lang, X11: x11})
	u.Build()
	u.ShowPanel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx)
	a.Run()
}
