package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeGUI struct {
	started []string
	stopped []string
}

func (f *fakeGUI) Start(path, socket, lang string, env []string) (string, error) {
	f.started = append(f.started, path+" "+socket+" "+lang+" "+strings.Join(env, ","))
	return "lethe-gui-1.service", nil
}

func (f *fakeGUI) Stop(unit string) error { f.stopped = append(f.stopped, unit); return nil }

func TestM13_GUIBinaryChecks(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "lethe-gui")
	_ = os.WriteFile(good, []byte("x"), 0o755)
	if err := CheckGUIBinary(good, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose")
	_ = os.WriteFile(loose, []byte("x"), 0o755)
	_ = os.Chmod(loose, 0o777)
	link := filepath.Join(dir, "link")
	_ = os.Symlink(good, link)
	noexec := filepath.Join(dir, "noexec")
	_ = os.WriteFile(noexec, []byte("x"), 0o644)
	for _, bad := range []string{loose, link, noexec, "relative/lethe-gui", filepath.Join(dir, "missing")} {
		if CheckGUIBinary(bad, os.Getuid()) == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if os.Getuid() != 0 && CheckGUIBinary(good, os.Getuid()+1) == nil {
		t.Error("a binary owned by another user must be refused")
	}
}

func TestM13_AgentStartsAndStopsTheGUI(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "lethe-gui")
	_ = os.WriteFile(bin, []byte("x"), 0o755)
	env := map[string]string{"LETHE_GUI": bin, "LETHE_SOCKET": "/run/user/1000/lethe/lethe.sock", "WAYLAND_DISPLAY": "wayland-0", "SECRET": "x"}
	g := &fakeGUI{}
	cfg := Config{GUI: g, Language: "pt-BR", Getenv: func(k string) string { return env[k] }, Out: func(string, ...any) {}}
	stop := startGUI(cfg)
	if stop == nil || len(g.started) != 1 || !strings.Contains(g.started[0], "WAYLAND_DISPLAY=wayland-0") || strings.Contains(g.started[0], "SECRET") {
		t.Fatalf("%q", g.started)
	}
	stop()
	if len(g.stopped) != 1 {
		t.Fatal("the GUI stops with the agent")
	}
	env["LETHE_GUI"] = ""
	if startGUI(cfg) != nil {
		t.Fatal("no LETHE_GUI, no GUI")
	}
	props := GUIUnitProps(bin, "/s", "en-US", nil)
	if len(props) != 4 || props[1].Name != "ExecStart" {
		t.Fatalf("%+v", props)
	}
}
