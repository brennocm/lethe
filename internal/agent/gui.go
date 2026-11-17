package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/godbus/dbus/v5"
)

// The GUI is a separate binary (lethe-gui, cgo). lethe never runs external programs (spec §5,
// principle 10), so the agent, already in the operator's session, asks the user's systemd over
// D-Bus to start it as a transient unit. The unit stops when the agent ends.

// GUILauncher starts and stops the GUI.
type GUILauncher interface {
	Start(path, socket, lang string, env []string) (unit string, err error)
	Stop(unit string) error
}

// CheckGUIBinary accepts only a regular file owned by root or uid that its group and others
// cannot write: the GUI is trusted with the passphrase typed in it.
func CheckGUIBinary(path string, uid int) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("lethe-gui path %q is not absolute", path)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others", path)
	}
	if fi.Mode().Perm()&0o100 == 0 {
		return fmt.Errorf("%s is not executable", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid != 0 && int(st.Uid) != uid) {
		return fmt.Errorf("%s must be owned by root or the operator", path)
	}
	return nil
}

// SystemdGUI starts the GUI with org.freedesktop.systemd1.Manager.StartTransientUnit on the
// session bus.
type SystemdGUI struct{ conn *dbus.Conn }

// NewSystemdGUI connects to the session bus.
func NewSystemdGUI() (*SystemdGUI, error) {
	c, err := dbus.ConnectSessionBus()
	if err != nil {
		return nil, err
	}
	return &SystemdGUI{conn: c}, nil
}

type execStart struct {
	Path   string
	Argv   []string
	Ignore bool
}

type unitProp struct {
	Name  string
	Value dbus.Variant
}

// GUIUnitProps are the properties of the transient unit (tested without a bus).
func GUIUnitProps(path, socket, lang string, env []string) []unitProp {
	return []unitProp{
		{"Description", dbus.MakeVariant("lethe GUI")},
		{"ExecStart", dbus.MakeVariant([]execStart{{Path: path, Argv: []string{path, "--socket", socket, "--lang", lang}}})},
		{"Environment", dbus.MakeVariant(env)},
		{"CollectMode", dbus.MakeVariant("inactive-or-failed")},
	}
}

// Start implements GUILauncher.
func (s *SystemdGUI) Start(path, socket, lang string, env []string) (string, error) {
	unit := "lethe-gui-" + strconv.Itoa(os.Getpid()) + ".service"
	obj := s.conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
	var job dbus.ObjectPath
	err := obj.Call("org.freedesktop.systemd1.Manager.StartTransientUnit", 0, unit, "fail",
		GUIUnitProps(path, socket, lang, env), []struct {
			Name  string
			Props []unitProp
		}{}).Store(&job)
	if err != nil {
		return "", fmt.Errorf("systemd --user did not start the GUI: %w", err)
	}
	return unit, nil
}

// Stop implements GUILauncher.
func (s *SystemdGUI) Stop(unit string) error {
	var job dbus.ObjectPath
	return s.conn.Object("org.freedesktop.systemd1", "/org/freedesktop/systemd1").
		Call("org.freedesktop.systemd1.Manager.StopUnit", 0, unit, "replace").Store(&job)
}

// guiEnv is what the GUI needs from the session to draw and to reach the bus.
func guiEnv(getenv func(string) string) []string {
	var env []string
	for _, k := range []string{"DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "XAUTHORITY", "LANG"} {
		if v := getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// startGUI starts the GUI named by LETHE_GUI and returns the stop function (nil when there is
// no GUI to start). Failures are reported, never fatal: the agent's notifications stay.
func startGUI(cfg Config) func() {
	path := cfg.Getenv("LETHE_GUI")
	if path == "" || cfg.GUI == nil {
		return nil
	}
	if err := CheckGUIBinary(path, os.Getuid()); err != nil {
		cfg.Out("lethe agent: GUI not started: %v\n", err)
		return nil
	}
	unit, err := cfg.GUI.Start(path, cfg.Getenv("LETHE_SOCKET"), cfg.Language, guiEnv(cfg.Getenv))
	if err != nil {
		cfg.Out("lethe agent: %v (alerts stay on notifications and the terminal)\n", err)
		return nil
	}
	return func() {
		if err := cfg.GUI.Stop(unit); err != nil && !errors.Is(err, os.ErrNotExist) {
			cfg.Out("lethe agent: stopping the GUI: %v\n", err)
		}
	}
}
