// Package daemon orchestrates a lethe session (spec §5): discovery, sensors, checks, the pure
// engine, responses, the journal, the guard and the IPC server. One mutex serializes every call
// into the engine and the journal; sensors and IPC handlers only hand events to it.
package daemon

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/google/nftables"

	"lethe/internal/baseline"
	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/engine"
	"lethe/internal/geo"
	"lethe/internal/guard"
	"lethe/internal/ipc"
	"lethe/internal/journal"
	"lethe/internal/platform"
	"lethe/internal/profile"
	"lethe/internal/response"
	"lethe/internal/sensors/dbusmon"
	"lethe/internal/sensors/nftmon"
	"lethe/internal/sensors/sockdiag"
)

// Config wires the daemon to the host. Every I/O dependency is injectable for tests.
type Config struct {
	Operator    platform.Operator
	SocketPath  string
	ToolVersion string
	Now         func() time.Time
	Mono        func() int64
	Kernel      discovery.Kernel         // nil = discovery.NetlinkKernel{}
	Resolved    discovery.ResolvedClient // optional (systemd-resolved over D-Bus)
	// Tor builds the tor control client for a profile's egress.tor_control and tor_cookie
	// (nil = discovery.NewTorControl).
	Tor      func(addr, cookie string) discovery.TorSource
	NFT      func() (guard.Conn, error) // nil = nftables.New
	ProcRoot string                     // default /proc
	// Sensors starts the live sensors (capture, nflog, netlink, sock_diag) when armed.
	Sensors bool
	// Sockets and Cgroups find the VPN clients (nil with Sensors = sock_diag, /proc and
	// /sys/fs/cgroup; nil without Sensors = not looked up).
	Sockets discovery.SocketSource
	Cgroups discovery.CgroupResolver
	// Geo answers country and ASN for TUN-006 (nil = the embedded database, if this build has one).
	Geo geo.DB
	// Agent, when set, is the argument list for the session agent spawned at arm (portable mode).
	Agent []string
	// AgentEnv is the agent's environment (session bus, display, LANG).
	AgentEnv []string
	// HardenAfterArm drops capabilities after the first arm (portable mode, spec §19.3).
	HardenAfterArm bool
	// ExitAfterSession makes Run return when a session ends (service mode: the capabilities
	// dropped at arm cannot be regained, so systemd restarts a fresh daemon for the next one).
	ExitAfterSession bool
	// Out receives the terminal alert lines (no agent: terminal and journald only, SELF-003).
	Out io.Writer
	// TickEvery is the housekeeping period (default 1 s).
	TickEvery time.Duration
	// DiscoverEvery is the periodic discovery refresh while armed (default 5 s).
	DiscoverEvery time.Duration
	// ArmConfirmPoll is how often the arm confirmation looks for proof (default 500 ms); Sleep
	// waits between looks (default time.Sleep; tests advance a fake clock).
	ArmConfirmPoll time.Duration
	Sleep          func(time.Duration)
	// HostRoot is where the host files and sysfs are read ("/"); SystemBus gives the system bus
	// connection (nil with Sensors = connect once; nil without = no bus). HostEvery is the period
	// of the host checks (default 2 s). Boottime reads CLOCK_BOOTTIME (SELF-005).
	HostRoot  string
	SystemBus func() dbusmon.Bus
	HostEvery time.Duration
	Boottime  func() time.Duration
	// DNSFiles are the DNS configuration files DNS-004 watches (default /etc/resolv.conf).
	DNSFiles []string
	// SelftestOps are the side effects of the selftest (default: netlink, nftables, sockets).
	SelftestOps SelftestOps
}

// Daemon is one lethe daemon. Methods are safe for concurrent use.
type Daemon struct {
	cfg Config
	srv *ipc.Server

	mu       sync.Mutex
	eng      *engine.Engine
	sess     *session            // nil when not armed
	tor      discovery.TorSource // control client of the current arm (nil = tor not queried)
	state    engine.SessionState
	snap     discovery.Snapshot
	subs     map[int]chan contracts.Event
	nextSub  int
	recent   []contracts.Event // ring of journaled events for events.query
	armFails []time.Time
	hardened bool
	agent    *agentProc
	lastBeat map[string]time.Time // IPC peers: "agent", "gui"
	ended    chan struct{}        // closed when a session ends (ExitAfterSession)
	endOnce  sync.Once
}

// session is the state of one armed session.
type session struct {
	id              string
	prof            *profile.Profile
	base            *baseline.Baseline
	guardMode       engine.GuardMode
	features        guard.Features
	gcfg            guard.Config
	journal         *journal.Writer
	exec            *response.Executor
	auth            *ipc.Authenticator
	salt            []byte
	startedAt       time.Time
	color           engine.Color
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	beats           map[string]time.Time // sensor source → last heartbeat
	down            map[string]bool
	conditions      map[string]map[string]map[string]any // check → dedup key → data of the last finding
	tunnels         map[string]bool                      // TUN-001: tunnels seen since arm (only grows)
	learned         []discovery.Endpoint                 // endpoints learned (NFLOG) or confirmed by the operator
	socks           []sockdiag.Sock                      // last socket scan (VPN clients; read under the lock)
	owners          map[uint32]sockdiag.Owner
	endpointUnknown bool
	nftArm          []nftmon.Table // TUN-004: third-party tables at arm (nil = not readable)
	tx              *checks.TxTracker
	dirF            *os.File        // the session directory, open (see ioDir)
	torExpected     bool            // TUN-003: the session depends on tor (checks.TorExpected at arm)
	armEndpoints    map[string]bool // TUN-006: endpoints known at arm
	critical        int
	sensors         *sensorSet
	protected       map[int]bool // pids never killed by responses (self, agent)
	confirming      bool         // strict arm waiting for the tunnel's proof (spec §10.6)
	panic           panicCause   // why the session is in PANIC (lockdown explanation)
	known           checks.Known // the baseline values the host checks compare with
	armWiFi         []dbusmon.WiFi
	agentKeyboard   string
	clockOffset     time.Duration        // realtime − boottime at the last tick (SELF-005)
	paused          map[string]time.Time // heartbeats ignored until then (ST-SELF-001)
	probes          []*stProbe           // selftest findings recognisers
	selftesting     bool
	stExceptions    []guard.Exception // strict exceptions of the running case
	stDeny          bool              // the selftest deny rule is active (ST-HOST-001)
}

const recentMax = 2048

// New builds a daemon in READY (the baseline arrives with each session.arm).
func New(cfg Config) *Daemon {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Mono == nil {
		start := time.Now()
		cfg.Mono = func() int64 { return int64(time.Since(start)) }
	}
	if cfg.Kernel == nil {
		cfg.Kernel = discovery.NetlinkKernel{}
	}
	if cfg.NFT == nil {
		cfg.NFT = func() (guard.Conn, error) { return nftables.New() }
	}
	if cfg.ProcRoot == "" {
		cfg.ProcRoot = "/proc"
	}
	if cfg.Geo == nil {
		cfg.Geo, _ = geo.Embedded() // none before M11: TUN-006 stays inactive
	}
	if cfg.Sensors && cfg.Sockets == nil {
		cfg.Sockets = discovery.SystemSockets(cfg.ProcRoot)
	}
	if cfg.Sensors && cfg.Cgroups == nil {
		cfg.Cgroups = discovery.SystemCgroups(cfg.ProcRoot, "/sys/fs/cgroup")
	}
	if cfg.Out == nil {
		cfg.Out = io.Discard
	}
	if cfg.TickEvery == 0 {
		cfg.TickEvery = time.Second
	}
	if cfg.DiscoverEvery == 0 {
		cfg.DiscoverEvery = 5 * time.Second
	}
	if cfg.ArmConfirmPoll == 0 {
		cfg.ArmConfirmPoll = 500 * time.Millisecond
	}
	if cfg.Sleep == nil {
		cfg.Sleep = time.Sleep
	}
	if cfg.HostRoot == "" {
		cfg.HostRoot = "/"
	}
	if cfg.Sensors && cfg.SystemBus == nil {
		cfg.SystemBus = systemBus()
	}
	if cfg.HostEvery == 0 {
		cfg.HostEvery = hostEveryDefault
	}
	if cfg.SelftestOps == nil {
		cfg.SelftestOps = liveOps{nft: func() (guard.Conn, error) { return cfg.NFT() }}
	}
	if cfg.DNSFiles == nil {
		cfg.DNSFiles = []string{"/etc/resolv.conf"}
	}
	if cfg.Boottime == nil {
		cfg.Boottime = boottime
	}
	d := &Daemon{cfg: cfg, state: engine.StateReady, subs: map[int]chan contracts.Event{}, lastBeat: map[string]time.Time{}, ended: make(chan struct{})}
	d.eng = engine.New(clock{cfg.Now}, engine.Config{}, engine.StateReady)
	d.srv = &ipc.Server{
		OperatorUID:    cfg.Operator.UID,
		IsAgent:        d.isAgent,
		Denied:         d.denied,
		SelfAuthorized: map[string]bool{"session.arm": true},
	}
	d.routes()
	return d
}

type clock struct{ now func() time.Time }

func (c clock) Now() time.Time { return c.now() }

// Run serves IPC on cfg.SocketPath and runs housekeeping until ctx ends; then it disarms.
func (d *Daemon) Run(ctx context.Context) error {
	l, err := ipc.Listen(d.cfg.SocketPath, d.cfg.Operator.UID, d.cfg.Operator.GID)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() { errc <- d.srv.Serve(ctx, l) }()
	t := time.NewTicker(d.cfg.TickEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			d.Shutdown("daemon_stopped")
			return <-errc
		case err := <-errc:
			d.Shutdown("ipc_failed")
			return err
		case <-d.ended:
			return nil
		case <-t.C:
			d.Tick()
		}
	}
}

// Shutdown ends the session if one is open. In PANIC the guard stays (fail-closed): only
// cleanup or a later daemon removes it.
func (d *Daemon) Shutdown(reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sess == nil {
		return
	}
	keep := d.eng.Session() == engine.StatePanic
	d.endLocked(reason, keep)
}

// State returns the session state and color.
func (d *Daemon) State() (engine.SessionState, engine.Color) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.eng.Session(), d.colorLocked()
}

func (d *Daemon) colorLocked() engine.Color {
	if d.sess == nil {
		return engine.ColorGray
	}
	return d.eng.Color()
}

// appendLocked journals ev, keeps it for events.query and pushes it to subscribers.
func (d *Daemon) appendLocked(ev contracts.Event) contracts.Event {
	if d.sess == nil {
		return ev
	}
	if ev.Type == contracts.EvCheckAlert && d.sess.base != nil {
		// No baseline value leaves the daemon (spec §12.1): the journal, IPC and report get a
		// scrubbed copy; responses already ran on the original. On failure the data is dropped.
		data, err := d.sess.base.Scrub(ev.Data)
		if err != nil {
			data = map[string]any{"redacted": true}
		}
		ev.Data = data
	}
	out, err := d.sess.journal.Append(ev)
	if err != nil {
		// A journal that cannot write is a visibility loss: say so on the terminal (no values).
		_, _ = fmt.Fprintf(d.cfg.Out, "lethe: journal: %v\n", err)
		return ev
	}
	d.publishLocked(out)
	return out
}

func (d *Daemon) publishLocked(ev contracts.Event) {
	d.recent = append(d.recent, ev)
	if len(d.recent) > recentMax {
		d.recent = append([]contracts.Event(nil), d.recent[len(d.recent)-recentMax:]...)
	}
	for _, ch := range d.subs {
		select {
		case ch <- ev:
		default: // a slow subscriber loses events; it can re-query
		}
	}
}

func (d *Daemon) denied(p ipc.Peer, method, reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	data := map[string]any{"uid": p.UID, "pid": p.PID, "reason": reason}
	if method != "" {
		data["method"] = method
	}
	if d.sess == nil {
		_, _ = fmt.Fprintf(d.cfg.Out, "lethe: ipc denied uid=%d pid=%d: %s\n", p.UID, p.PID, reason)
		return
	}
	d.appendLocked(contracts.Event{Type: contracts.EvIPCDenied, Source: contracts.SourceDaemon, Data: data})
}

// newUUID returns a random (v4) UUID.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// errState marks an invalid transition or unmet precondition (IPC code -32003).
func errState(err error) error { return &ipc.Error{Code: ipc.CodeState, Message: err.Error()} }

func errAuth(msg string) error { return &ipc.Error{Code: ipc.CodeAuth, Message: msg} }

func errParams(err error) error { return &ipc.Error{Code: ipc.CodeInvalidParams, Message: err.Error()} }

var errNotArmed = errors.New("no armed session")

func isRoot() bool { return os.Geteuid() == 0 }
