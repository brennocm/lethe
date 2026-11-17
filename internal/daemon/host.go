package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"

	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/sensors/dbusmon"
	"lethe/internal/sensors/fswatch"
	"lethe/internal/sensors/hostinfo"
)

// Host, persona and self checks (spec §9.4–§9.6, M9).

const hostEveryDefault = 2 * time.Second

// AgentFacts is agent.report: what the session agent sees in the graphical session. The daemon
// derives the findings itself, so the agent never chooses a check or a severity (principle 9).
type AgentFacts struct {
	Lang     string         `json:"lang,omitempty"`     // LANG of the session
	Keyboard string         `json:"keyboard,omitempty"` // active layout of the session
	Capture  checks.Capture `json:"capture"`            // PipeWire capture and screencast streams
}

const agentFieldMax = 64

func (a AgentFacts) valid() error {
	if len(a.Lang) > agentFieldMax || len(a.Keyboard) > agentFieldMax {
		return errors.New("agent report: field too long")
	}
	if c := a.Capture; c.Audio < 0 || c.Video < 0 || c.Screencast < 0 || c.Audio > 1024 || c.Video > 1024 || c.Screencast > 1024 {
		return errors.New("agent report: stream counts out of range")
	}
	return nil
}

// collector reads the host state for a profile (outside the lock).
func (d *Daemon) collector(s *session) hostinfo.Collector {
	c := hostinfo.Collector{Root: d.cfg.HostRoot, ProcRoot: d.cfg.ProcRoot, Bus: d.cfg.SystemBus}
	if s != nil {
		c.PersonaProfiles = s.prof.Browsers.PersonaProfiles
		c.StateDir = filepath.Join(s.prof.Storage.Dir, "state")
	}
	return c
}

// hostLoop reads the host state every HostEvery and evaluates the session checks.
func (d *Daemon) hostLoop(ctx context.Context, s *session) {
	t := time.NewTicker(d.cfg.HostEvery)
	defer t.Stop()
	col := d.collector(s)
	for {
		st := col.Collect()
		d.ObserveHost(s, st)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ObserveHost evaluates the passive host checks of one reading for session s.
func (d *Daemon) ObserveHost(s *session, st hostinfo.State) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess != s || s == nil {
		return
	}
	s.beats[hostinfo.SourceID] = d.cfg.Now()
	in := checks.HostRules(s.prof, checks.HostInput{State: st, Snapshot: &d.snap, Known: s.known, Now: d.cfg.Now(), AgentKeyboard: s.agentKeyboard})
	if s.stDeny {
		in.Deny = append(in.Deny, checks.DenyRule{Match: "comm", Value: stDenyComm, Severity: contracts.SeverityWarning})
	}
	res := checks.EvaluateHost(in)
	for _, id := range checks.HostChecks {
		fs, ok := res[id]
		if c, known := checks.ByID(id); !ok || !known || c.Kind() != checks.Passive {
			continue // preflight-only checks run once, before the arm
		}
		d.conditionLocked(id, fs)
	}
	if st.BusRead {
		if s.armWiFi == nil {
			s.armWiFi = append([]dbusmon.WiFi{}, st.Bus.NM.WiFi...)
		}
		d.conditionLocked("NET-007", checks.NET007{}.Evaluate(s.armWiFi, st.Bus.NM.WiFi, s.known))
	}
}

// AgentReport turns the agent's facts into findings. They may raise alerts, never clear them:
// nothing the agent says resolves a condition.
func (d *Daemon) AgentReport(f AgentFacts) error {
	if err := f.valid(); err != nil {
		return errParams(err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.sess
	if s == nil {
		return errState(errNotArmed)
	}
	want := checks.Persona{Timezone: s.prof.Expect.Timezone, Locale: s.prof.Expect.Locale, Keyboard: s.prof.Expect.Keyboard}
	if f.Keyboard != "" {
		s.agentKeyboard = f.Keyboard
	}
	var fs []checks.Finding
	fs = append(fs, checks.HOST002{}.FromAgent(f.Capture)...)
	fs = append(fs, checks.HOST003{}.FromAgent(f.Capture)...)
	fs = append(fs, checks.HOST005{}.FromAgent(f.Lang, want)...)
	fs = append(fs, checks.PER001{}.Evaluate(f.Keyboard, true, want)...)
	for _, x := range fs {
		d.findingLocked(x)
	}
	return nil
}

// captureStatsLocked reads the drop counters of every capture socket (SELF-002).
func (d *Daemon) captureStatsLocked() {
	s := d.sess
	if s.sensors == nil {
		return
	}
	for iface, c := range s.sensors.captures {
		st, err := c.Stats()
		if err != nil {
			continue
		}
		for _, f := range (checks.SELF002{}).Evaluate(iface, st.Drops) {
			d.findingLocked(f)
		}
	}
}

// clockLocked compares CLOCK_REALTIME with CLOCK_BOOTTIME every tick (SELF-005): a difference
// that moved by more than 2 s means the wall clock was set.
func (d *Daemon) clockLocked(now time.Time) {
	s := d.sess
	boot := d.cfg.Boottime()
	if boot <= 0 {
		return
	}
	off := time.Duration(now.UnixNano()) - boot
	if s.clockOffset != 0 {
		for _, f := range (checks.SELF005{}).Evaluate(s.clockOffset, off) {
			d.appendLocked(contracts.Event{Type: contracts.EvClockJump, Source: contracts.SourceDaemon, Data: map[string]any{"jump_ms": f.Data["jump_ms"]}})
			d.findingLocked(f)
		}
	}
	s.clockOffset = off
}

func boottime() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}
	return time.Duration(ts.Nano())
}

// systemBus connects to the system bus once and keeps the connection (nil when there is none).
func systemBus() func() dbusmon.Bus {
	var once sync.Once
	var bus dbusmon.Bus
	return func() dbusmon.Bus {
		once.Do(func() {
			if c, err := dbus.ConnectSystemBus(); err == nil {
				bus = c
			}
		})
		return bus
	}
}

// clockSetLoop waits on a CLOCK_REALTIME timerfd with TFD_TIMER_CANCEL_ON_SET: the kernel wakes
// it as soon as the wall clock is set, and the comparison runs at once instead of at the next
// tick (SELF-005). Without timerfd the 1 s comparison alone still catches the jump.
func (d *Daemon) clockSetLoop(ctx context.Context, s *session) {
	fd, err := unix.TimerfdCreate(unix.CLOCK_REALTIME, unix.TFD_CLOEXEC|unix.TFD_NONBLOCK)
	if err != nil {
		return
	}
	f := os.NewFile(uintptr(fd), "timerfd") // the runtime poller: Close unblocks Read
	go func() { <-ctx.Done(); _ = f.Close() }()
	far := unix.ItimerSpec{Value: unix.Timespec{Sec: 1 << 40}}
	buf := make([]byte, 8)
	for ctx.Err() == nil {
		if err := unix.TimerfdSettime(fd, unix.TFD_TIMER_ABSTIME|unix.TFD_TIMER_CANCEL_ON_SET, &far, nil); err != nil {
			return
		}
		_, err := f.Read(buf)
		if !errors.Is(err, unix.ECANCELED) {
			return // closed by ctx, or an error: the tick comparison remains
		}
		d.mu.Lock()
		if d.sess == s {
			d.clockLocked(d.cfg.Now())
		}
		d.mu.Unlock()
	}
}

// ShrinkCapture sets the receive buffer of the capture socket of iface to n bytes (the kernel
// rounds it up to its minimum), so a burst overflows it (selftest ST-SELF-002).
func (d *Daemon) ShrinkCapture(iface string, n int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil || d.sess.sensors == nil {
		return errState(errNotArmed)
	}
	c, ok := d.sess.sensors.captures[iface]
	if !ok {
		return errParams(fmt.Errorf("no capture on %q", iface))
	}
	return c.SetReadBuffer(n)
}

// selftestDNSFile is the watched test file of ST-DNS-004 (never the real resolv.conf).
func selftestDNSFile(s *session) string {
	return filepath.Join(s.prof.Storage.Dir, "state", "selftest-resolv.conf")
}

// dnsWatcher watches the DNS configuration files and the selftest file (DNS-004).
func (d *Daemon) dnsWatcher(s *session) (*fswatch.Watcher, error) {
	st := selftestDNSFile(s)
	if err := os.MkdirAll(filepath.Dir(st), 0o700); err == nil {
		if _, err := os.Lstat(st); errors.Is(err, os.ErrNotExist) {
			_ = os.WriteFile(st, []byte("# lethe selftest (ST-DNS-004)\n"), 0o600)
		}
	}
	return fswatch.New(append(append([]string{}, d.cfg.DNSFiles...), st)...)
}

// onDNSChange raises DNS-004 and re-reads the discovery (the resolvers may have changed).
func (d *Daemon) onDNSChange(s *session, c fswatch.Change) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess != s {
		return
	}
	for _, f := range (checks.DNS004{}).Evaluate(c.Path) {
		d.findingLocked(f)
	}
	if c.Path != selftestDNSFile(s) {
		d.refreshLocked()
	}
}
