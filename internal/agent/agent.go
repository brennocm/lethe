// Package agent is the session agent (spec §5.1): it runs as the operator inside the graphical
// session, keeps a heartbeat with the daemon, shows the alerts as desktop notifications (with the
// severity's sound) and reports what only the session can see: capture and screencast streams in
// PipeWire, the session language and the keyboard layout. It is a low-trust sensor (principle 9):
// it sends facts, never checks or severities, and the daemon never lets them clear an alert.
package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/daemon"
	"lethe/internal/ipc"
)

// Notifier shows one desktop notification (org.freedesktop.Notifications).
type Notifier interface {
	Notify(n Notification) error
}

// Notification is one alert on the desktop.
type Notification struct {
	Summary  string
	Body     string
	Critical bool
	Sound    bool
}

// Config wires the agent. Zero fields take the session defaults.
type Config struct {
	Dial      func() (*ipc.Client, error)
	Notifier  Notifier                       // nil = no notifications (no session bus)
	Getenv    func(string) string            // os.Getenv
	Capture   func() (checks.Capture, error) // nil = PipeWire of the session
	Keyboard  func() string                  // nil = sessionKeyboard
	Language  string                         // ui.language for the texts (pt-BR default)
	BeatEvery time.Duration                  // 1 s
	FactEvery time.Duration                  // 5 s
	Out       func(format string, a ...any)  // diagnostics (nil = none)
	GUI       GUILauncher                    // starts LETHE_GUI (nil = never)
}

// Run keeps the agent alive until ctx ends or the daemon goes away.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Getenv == nil {
		cfg.Getenv = os.Getenv
	}
	if cfg.Capture == nil {
		sock := pwSocket(cfg.Getenv)
		cfg.Capture = func() (checks.Capture, error) { return PipeWireCapture(sock) }
	}
	if cfg.Keyboard == nil {
		cfg.Keyboard = func() string { return sessionKeyboard(cfg.Getenv) }
	}
	if cfg.BeatEvery == 0 {
		cfg.BeatEvery = time.Second
	}
	if cfg.FactEvery == 0 {
		cfg.FactEvery = 5 * time.Second
	}
	if cfg.Out == nil {
		cfg.Out = func(string, ...any) {}
	}
	ctl, err := cfg.Dial()
	if err != nil {
		return err
	}
	defer func() { _ = ctl.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if stop := startGUI(cfg); stop != nil {
		defer stop()
	}
	if cfg.Notifier != nil {
		go func() {
			if err := notifyLoop(ctx, cfg); err != nil {
				cfg.Out("lethe agent: notifications: %v\n", err)
			}
		}()
	}
	beat := time.NewTicker(cfg.BeatEvery)
	defer beat.Stop()
	var last daemon.AgentFacts
	lastSent := time.Time{}
	nextFacts := time.Now()
	for {
		_ = ctl.SetDeadline(time.Now().Add(5 * time.Second))
		if err := ctl.Call("heartbeat", nil, nil, nil); err != nil {
			return err
		}
		if now := time.Now(); !now.Before(nextFacts) {
			nextFacts = now.Add(cfg.FactEvery)
			f := facts(cfg)
			// unchanged facts are repeated every 30 s, so a restarted daemon learns them again
			if !reflect.DeepEqual(f, last) || now.Sub(lastSent) > 30*time.Second {
				if err := ctl.Call("agent.report", f, nil, nil); err != nil {
					var ie *ipc.Error
					if !errors.As(err, &ie) {
						return err
					}
					// not armed yet, or a refusal: keep the heartbeat, try again later
				} else {
					last, lastSent = f, now
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-beat.C:
		}
	}
}

// facts reads what the session shows now.
func facts(cfg Config) daemon.AgentFacts {
	f := daemon.AgentFacts{Lang: sessionLang(cfg.Getenv), Keyboard: cfg.Keyboard()}
	if c, err := cfg.Capture(); err == nil {
		f.Capture = c
	}
	return f
}

func sessionLang(getenv func(string) string) string {
	for _, k := range []string{"LC_ALL", "LANG"} {
		if v := getenv(k); v != "" && v != "C" && v != "POSIX" {
			return clip(v)
		}
	}
	return ""
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// sessionKeyboard reads the active layout of the session: XKB_DEFAULT_LAYOUT (wlroots, sway),
// then KDE's kxkbrc. GNOME keeps it in dconf, which the agent does not parse: the daemon then
// falls back to the system layout (locale1).
func sessionKeyboard(getenv func(string) string) string {
	if v := getenv("XKB_DEFAULT_LAYOUT"); v != "" {
		return clip(v)
	}
	home := getenv("HOME")
	if home == "" {
		return ""
	}
	cfg := getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = filepath.Join(home, ".config")
	}
	f, err := os.Open(filepath.Join(cfg, "kxkbrc")) // #nosec G304 -- the operator's own config
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(sc.Text()), "LayoutList="); ok {
			return clip(rest)
		}
	}
	return ""
}

// notifyLoop subscribes to the alerts and shows the new ones whose plan has alert_tray.
func notifyLoop(ctx context.Context, cfg Config) error {
	c, err := cfg.Dial()
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	go func() { <-ctx.Done(); _ = c.Close() }()
	if err := c.Call("events.subscribe", daemon.QueryParams{Severity: string(contracts.SeverityWarning)}, nil, nil); err != nil {
		return err
	}
	for {
		_ = c.SetDeadline(time.Time{})
		raw, err := c.ReadNotification()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		var ev contracts.Event
		if json.Unmarshal(raw, &ev) != nil {
			continue
		}
		if n, ok := notificationFor(ev, cfg.Language); ok {
			if err := cfg.Notifier.Notify(n); err != nil {
				cfg.Out("lethe agent: notify: %v\n", err)
			}
		}
	}
}

// notificationFor builds the desktop notification of an alert event, if its plan shows one.
func notificationFor(ev contracts.Event, lang string) (Notification, bool) {
	if ev.Type != contracts.EvCheckAlert || ev.AlertID == "" {
		return Notification{}, false
	}
	tray, sound := false, false
	for _, a := range ev.Actions {
		switch a {
		case "alert_tray", "alert_fullscreen":
			tray = true
		case "alert_sound":
			sound = true
		}
	}
	if !tray && !sound {
		return Notification{}, false
	}
	n := Notification{
		Summary:  fmt.Sprintf("lethe: %s", checks.Title(ev.Check, lang)),
		Body:     fmt.Sprintf("%s %s (%s)", ev.AlertID, ev.Check, ev.Severity),
		Critical: ev.Severity == contracts.SeverityCritical,
		Sound:    sound,
	}
	if n.Critical {
		if lang == "en-US" {
			n.Body += "\nCheck the terminal or `lethe status` for what to do."
		} else {
			n.Body += "\nVeja no terminal ou em `lethe status` o que fazer."
		}
	}
	return n, true
}
