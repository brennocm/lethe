// Package launch is lethe-gui's main without the graphics driver: it parses the flags and wires
// the UI, so the tests compile everything the binary runs except fyne's GL driver (cgo).
package launch

import (
	"context"
	"flag"
	"os"
	"os/user"

	"fyne.io/fyne/v2"

	"lethe/apps/lethe-gui/internal/gui"
	"lethe/apps/lethe-gui/internal/sysd"
)

// Setup builds the UI on a: the flags, the daemon client (the portable socket, then the
// service's), the first-use home and the service start for this operator.
func Setup(a fyne.App, args []string) (*gui.UI, error) {
	fs := flag.NewFlagSet("lethe-gui", flag.ContinueOnError)
	sock := fs.String("socket", "", "daemon socket (default: the portable daemon's, then the service's)")
	lang := fs.String("lang", os.Getenv("LETHE_LANG"), "pt-BR or en-US")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	a.Settings().SetTheme(gui.Theme())
	x11 := os.Getenv("XDG_SESSION_TYPE") == "x11" || (os.Getenv("WAYLAND_DISPLAY") == "" && os.Getenv("DISPLAY") != "")
	opt := gui.Options{Lang: *lang, X11: x11}
	opt.Home, _ = os.UserHomeDir()
	if me, err := user.Current(); err == nil {
		if _, err := sysd.Unit(me.Username); err == nil {
			name := me.Username
			opt.StartService = func(ctx context.Context) error { return sysd.Start(ctx, name) }
		}
	}
	opt.Cleanup = sysd.Cleanup
	u := gui.New(a, gui.Client{Socket: *sock, Others: gui.Sockets(os.Getuid())}, opt)
	u.Build()
	return u, nil
}

// Main runs the GUI until the app quits.
func Main(a fyne.App, args []string) int {
	u, err := Setup(a, args)
	if err != nil {
		return 2
	}
	u.ShowPanel()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx)
	a.Run()
	return 0
}
