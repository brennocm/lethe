// Command lethe-gui is the optional desktop interface of lethe (spec §16): the tray, the panel
// and the full-screen alert. It runs as the operator, started by the session agent through
// systemd --user (or by hand), and talks to the daemon only over IPC. The wiring lives in
// internal/launch, which the tests compile without the GL driver.
package main

import (
	"os"

	"fyne.io/fyne/v2/app"

	"lethe/apps/lethe-gui/internal/launch"
)

func main() {
	os.Exit(launch.Main(app.NewWithID("io.lethe.gui"), os.Args[1:]))
}
