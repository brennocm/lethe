package agent

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/daemon"
	"lethe/internal/ipc"
)

// fakePipeWire answers like a PipeWire server: registry globals, a ping, then the sync's done.
func fakePipeWire(t *testing.T, globals [][2]any) (string, chan bool) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "pipewire-0")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ponged := make(chan bool, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		hdr := make([]byte, 16)
		for range 4 { // hello, update properties, get registry, sync
			if _, err := io.ReadFull(c, hdr); err != nil {
				return
			}
			_, _ = io.CopyN(io.Discard, c, int64(binary.LittleEndian.Uint32(hdr[4:])&0xffffff))
		}
		_, _ = c.Write(pwMessage(pwCoreID, pwEvCorePing, 0, podStruct(podInt(7), podInt(99))))
		for i, g := range globals {
			props := g[1].([]string)
			msg := podStruct(podInt(int32(30+i)), podInt(0x1ff), podString(g[0].(string)), podInt(3), podDict(props...))
			_, _ = c.Write(pwMessage(pwRegistryID, pwEvGlobal, 0, msg))
		}
		if _, err := io.ReadFull(c, hdr); err == nil && hdr[7] == pwCorePong {
			ponged <- true
		}
		_, _ = io.CopyN(io.Discard, c, int64(binary.LittleEndian.Uint32(hdr[4:])&0xffffff))
		_, _ = c.Write(pwMessage(pwCoreID, pwEvCoreDone, 0, podStruct(podInt(0), podInt(pwSyncSeq))))
	}()
	return sock, ponged
}

func TestHOST002_HOST003_PipeWireCapture(t *testing.T) {
	sock, ponged := fakePipeWire(t, [][2]any{
		{"PipeWire:Interface:Node", []string{"media.class", "Stream/Input/Audio", "application.name", "zoom"}},
		{"PipeWire:Interface:Node", []string{"media.class", "Audio/Sink"}},
		{"PipeWire:Interface:Node", []string{"media.class", "Stream/Input/Video"}},
		{"PipeWire:Interface:Node", []string{"media.class", "Video/Source", "node.name", "gnome-shell-screencast-1"}},
		{"PipeWire:Interface:Node", []string{"media.class", "Video/Source", "node.name", "v4l2_input.pci-0000"}},
		{"PipeWire:Interface:Port", []string{"media.class", "Stream/Input/Audio"}},
	})
	c, err := PipeWireCapture(sock)
	if err != nil {
		t.Fatal(err)
	}
	if c != (checks.Capture{Audio: 1, Video: 1, Screencast: 1}) {
		t.Fatalf("%+v", c)
	}
	select {
	case <-ponged:
	case <-time.After(time.Second):
		t.Fatal("the ping was not answered")
	}
}

func TestM9_PipeWireMissingSocket(t *testing.T) {
	if _, err := PipeWireCapture(""); err == nil {
		t.Fatal("no socket")
	}
	if _, err := PipeWireCapture(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("missing socket")
	}
	env := map[string]string{"XDG_RUNTIME_DIR": "/run/user/1000"}
	if got := pwSocket(func(k string) string { return env[k] }); got != "/run/user/1000/pipewire-0" {
		t.Fatal(got)
	}
}

func FuzzParsePod(f *testing.F) {
	f.Add(podStruct(podInt(1), podString("x"), podDict("a", "b")))
	f.Add([]byte{8, 0, 0, 0, 14, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 14, 0, 0, 0})
	f.Fuzz(func(_ *testing.T, b []byte) {
		v, _, err := parsePod(b, 0)
		if err == nil {
			_ = v.dict()
		}
	})
}

func TestPER001_SessionKeyboardAndLang(t *testing.T) {
	home := t.TempDir()
	_ = os.MkdirAll(filepath.Join(home, ".config"), 0o755)
	_ = os.WriteFile(filepath.Join(home, ".config", "kxkbrc"), []byte("[Layout]\nLayoutList=br,us\nUse=true\n"), 0o600)
	env := map[string]string{"HOME": home, "LANG": "pt_BR.UTF-8"}
	get := func(k string) string { return env[k] }
	if k := sessionKeyboard(get); k != "br,us" {
		t.Fatal(k)
	}
	env["XKB_DEFAULT_LAYOUT"] = "us"
	if k := sessionKeyboard(get); k != "us" {
		t.Fatal(k)
	}
	if l := sessionLang(get); l != "pt_BR.UTF-8" {
		t.Fatal(l)
	}
	env["LC_ALL"] = "C"
	if l := sessionLang(get); l != "pt_BR.UTF-8" {
		t.Fatal("C is not a session language")
	}
}

func TestM9_NotificationFor(t *testing.T) {
	ev := contracts.Event{Type: contracts.EvCheckAlert, AlertID: "A-0003", Check: "NET-001", Severity: contracts.SeverityCritical,
		Actions: []string{"alert_fullscreen", "alert_sound"}}
	n, ok := notificationFor(ev, "pt-BR")
	if !ok || !n.Critical || !n.Sound || n.Summary != "lethe: Tráfego fora do túnel" {
		t.Fatalf("%+v", n)
	}
	if _, ok := notificationFor(contracts.Event{Type: contracts.EvCheckAlert, AlertID: "A-1", Actions: []string{"block_all"}}, ""); ok {
		t.Fatal("no tray action, no notification")
	}
	if _, ok := notificationFor(contracts.Event{Type: contracts.EvStateChanged}, ""); ok {
		t.Fatal("not an alert")
	}
}

type recNotifier struct {
	mu sync.Mutex
	ns []Notification
}

func (r *recNotifier) Notify(n Notification) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ns = append(r.ns, n)
	return nil
}

func (r *recNotifier) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.ns) }

// The agent beats, reports facts (not checks) and turns alert events into notifications.
func TestSELF003_AgentLoop(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "lethe.sock")
	l, err := ipc.Listen(sock, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	srv := &ipc.Server{OperatorUID: os.Getuid(), IsAgent: func(int) bool { return true }}
	var mu sync.Mutex
	beats, reports := 0, []daemon.AgentFacts{}
	subscribed := make(chan *ipc.Call, 1)
	srv.Handle("heartbeat", func(*ipc.Call) (any, error) { mu.Lock(); beats++; mu.Unlock(); return map[string]any{}, nil })
	srv.Handle("agent.report", func(c *ipc.Call) (any, error) {
		var f daemon.AgentFacts
		_ = jsonUnmarshal(c.Req.Params, &f)
		mu.Lock()
		reports = append(reports, f)
		mu.Unlock()
		return map[string]any{"ok": true}, nil
	})
	srv.Handle("events.subscribe", func(c *ipc.Call) (any, error) {
		go func() {
			time.Sleep(50 * time.Millisecond)
			_ = c.Notify(contracts.Event{Type: contracts.EvCheckAlert, AlertID: "A-0001", Check: "HOST-002", Severity: contracts.SeverityWarning, Actions: []string{"alert_tray", "alert_sound"}})
			<-c.Ctx.Done()
		}()
		select {
		case subscribed <- c:
		default:
		}
		return map[string]any{"subscribed": true}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, l) }()
	rec := &recNotifier{}
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Config{
			Dial:      func() (*ipc.Client, error) { return ipc.Dial(sock, time.Second) },
			Notifier:  rec,
			Getenv:    func(k string) string { return map[string]string{"LANG": "pt_BR.UTF-8"}[k] },
			Capture:   func() (checks.Capture, error) { return checks.Capture{Audio: 1}, nil },
			Keyboard:  func() string { return "br" },
			BeatEvery: 20 * time.Millisecond, FactEvery: 20 * time.Millisecond,
		})
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ok := beats >= 3 && len(reports) >= 1
		mu.Unlock()
		if ok && rec.count() == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if beats < 3 || len(reports) == 0 || rec.count() != 1 {
		t.Fatalf("beats %d reports %d notifications %d", beats, len(reports), rec.count())
	}
	if r := reports[0]; r.Lang != "pt_BR.UTF-8" || r.Keyboard != "br" || r.Capture.Audio != 1 {
		t.Fatalf("report %+v", r)
	}
	if len(reports) > 1 {
		t.Fatalf("unchanged facts must not be resent at every tick: %d", len(reports))
	}
	cancel()
	<-done
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
