package cli

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/google/nftables"
	"github.com/spf13/cobra"

	"lethe/internal/agent"
	"lethe/internal/buildinfo"
	"lethe/internal/checks"
	"lethe/internal/contracts"
	"lethe/internal/daemon"
	"lethe/internal/discovery"
	"lethe/internal/guard"
	"lethe/internal/ipc"
	"lethe/internal/platform"
	"lethe/internal/preflight"
	"lethe/internal/profile"
	"lethe/internal/sensors/dbusmon"
	"lethe/internal/sensors/hostinfo"
)

// Socket locations (spec §17.1). LETHE_SOCKET overrides both (tests, unusual setups).
const serviceSocket = "/run/lethe/lethe.sock"

// portableSocket is $XDG_RUNTIME_DIR/lethe/lethe.sock of the operator, or the service path
// when the operator has no runtime directory.
func portableSocket(op platform.Operator) string {
	if p := os.Getenv("LETHE_SOCKET"); p != "" {
		return p
	}
	rt := filepath.Join("/run/user", strconv.Itoa(op.UID))
	if fi, err := os.Stat(rt); err == nil && fi.IsDir() {
		return filepath.Join(rt, "lethe", "lethe.sock")
	}
	return serviceSocket
}

func clientSocket() (string, error) {
	if p := os.Getenv("LETHE_SOCKET"); p != "" {
		return p, nil
	}
	op, err := platform.CurrentOperator(os.Getenv)
	if err != nil {
		return "", err
	}
	for _, p := range []string{filepath.Join("/run/user", strconv.Itoa(op.UID), "lethe", "lethe.sock"), serviceSocket} {
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return p, nil
		}
	}
	return "", errors.New("no lethe daemon socket found (is `lethe run` or lethed.service running?)")
}

func dialDaemon() (*ipc.Client, error) {
	p, err := clientSocket()
	if err != nil {
		return nil, WithCode(ExitDaemonDown, err)
	}
	c, err := ipc.Dial(p, 2*time.Second)
	if err != nil {
		return nil, WithCode(ExitDaemonDown, fmt.Errorf("daemon unreachable: %w", err))
	}
	return c, nil
}

// rpcErr maps daemon errors to exit codes (spec §15.2).
func rpcErr(err error) error {
	var ie *ipc.Error
	if !errors.As(err, &ie) {
		return err
	}
	e := errors.New(ie.Message)
	switch {
	case ie.Code == ipc.CodeAuth || ie.Code == ipc.CodeDenied:
		return WithCode(ExitAuth, e)
	case ie.Code == ipc.CodeArmUnconfirmed:
		return WithCode(ExitArmUnconfirmed, e)
	case strings.Contains(ie.Message, "preflight failed"):
		return WithCode(ExitPreflightFailed, e)
	}
	return e
}

// prove derives K = scrypt(passphrase, salt of the session) and signs method(params).
func prove(c *ipc.Client, src *passphraseSource, method string, params any) (*ipc.Auth, error) {
	var st daemon.Status
	if err := c.Call("status.get", nil, nil, &st); err != nil {
		return nil, rpcErr(err)
	}
	if len(st.AuthSalt) == 0 {
		return nil, errors.New("no armed session")
	}
	pw, err := src.read("Passphrase da baseline: ", false)
	if err != nil {
		return nil, err
	}
	key, err := ipc.DeriveKey(pw, st.AuthSalt)
	wipeBytes(pw)
	if err != nil {
		return nil, err
	}
	defer wipeBytes(key)
	return c.Prove(key, method, params)
}

// askManual runs the human checklist (spec §9.8) on the terminal.
func askManual(in io.Reader, out io.Writer) ([]preflight.Answer, error) {
	pr := &prompter{in: bufio.NewReader(in), out: out}
	var ans []preflight.Answer
	for _, it := range preflight.Manual {
		a, err := pr.ask(fmt.Sprintf("[%s] %s? [s/N] ", it.ID, it.Text))
		if err != nil {
			return nil, err
		}
		a = strings.ToLower(a)
		ans = append(ans, preflight.Answer{ID: it.ID, OK: a == "s" || a == "sim" || a == "y" || a == "yes"})
	}
	return ans, nil
}

// armFlags are shared by run and arm.
type armFlags struct {
	profile  string
	guard    string
	force    bool
	reason   string
	noManual bool
	secret   secretFlags
	window   time.Duration // strict arm confirmation window of the profile (set by request)
	lang     string        // ui.language of the profile (set by request)
}

// confirming tells the operator why the arm takes a while (spec §10.6 item 2).
func (f *armFlags) confirming(w io.Writer) {
	if f.window > 0 {
		_, _ = fmt.Fprintf(w, "Guarda estrito: aguardando até %s o túnel provar que passa tráfego (abra uma página para acelerar)...\n", f.window)
	}
}

// armFailed prints what the operator needs after a refused or undone arm.
func armFailed(w io.Writer, rep preflight.Report, err error) error {
	err = rpcErr(err)
	if exitCode(err) == ExitPreflightFailed && rep.Result != "" {
		printPreflight(w, rep)
	}
	if exitCode(err) == ExitArmUnconfirmed {
		_, _ = fmt.Fprintln(w, "lethe: o bloqueio foi desfeito e a rede está como antes do arm; nada da operação começou")
	}
	return err
}

func (f *armFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.profile, "profile", "p", "", "operation profile (YAML)")
	cmd.Flags().StringVar(&f.guard, "guard", "", "override guard.mode: off | reactive | strict")
	cmd.Flags().BoolVar(&f.force, "force", false, "arm even if the preflight fails (needs --reason; journaled)")
	cmd.Flags().StringVar(&f.reason, "reason", "", "why --force was used")
	cmd.Flags().BoolVar(&f.noManual, "no-manual", false, "skip the manual checklist (preflight becomes WARN)")
	f.secret.register(cmd)
	_ = cmd.MarkFlagRequired("profile")
}

// request reads the profile and the baseline as the operator and asks the checklist and the
// passphrase. The caller owns (and wipes) req.Passphrase.
func (f *armFlags) request(cmd *cobra.Command, op platform.Operator) (daemon.ArmRequest, error) {
	raw, err := os.ReadFile(f.profile)
	if err != nil {
		return daemon.ArmRequest{}, err
	}
	p, _, err := profile.Parse(raw, op.Home)
	if err != nil {
		return daemon.ArmRequest{}, err
	}
	if p.Baseline.File == "" {
		return daemon.ArmRequest{}, errors.New("profile: baseline.file is required to arm")
	}
	base, err := os.ReadFile(p.Baseline.File) // #nosec G703 G304 -- the operator's own profile, read with their rights
	if err != nil {
		return daemon.ArmRequest{}, fmt.Errorf("baseline: %w", err)
	}
	f.window, f.lang = 0, p.UI.Language
	if mode := cmp.Or(f.guard, p.Guard.Mode); mode == "strict" {
		f.window = p.Guard.ArmWindow
	}
	req := daemon.ArmRequest{Profile: raw, Baseline: base, Guard: f.guard, Force: f.force, Reason: f.reason}
	if !f.noManual {
		if req.Manual, err = askManual(cmd.InOrStdin(), cmd.ErrOrStderr()); err != nil {
			return req, err
		}
	}
	if req.Passphrase, err = f.secret.source(cmd).read("Passphrase da baseline: ", false); err != nil {
		return req, err
	}
	return req, nil
}

func printArmed(w io.Writer, res daemon.ArmResult) {
	_, _ = fmt.Fprintf(w, "ARMADO  sessão %s  guarda %s  preflight %s\n", res.Session, res.Guard, res.Preflight.Result)
	_, _ = fmt.Fprintf(w, "Impressão digital da chave de sessão (anote FORA desta máquina):\n  %s\n", res.Fingerprint)
}

func newRunCmd() *cobra.Command {
	var f armFlags
	var noGUI, tui, noActive bool
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Portable mode: start the daemon in the foreground and arm",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tui {
				return fmt.Errorf("%w: the TUI arrives with M12", ErrNotImplemented)
			}
			_ = noGUI    // the GUI (M13) is never started yet
			_ = noActive // active checks (M11) are not wired yet
			if os.Geteuid() != 0 {
				return WithCode(ExitPrivileges, errors.New("run needs root (sudo lethe run ...)"))
			}
			op, err := platform.CurrentOperator(os.Getenv)
			if err != nil {
				return err
			}
			req, err := f.request(cmd, op)
			defer wipeBytes(req.Passphrase)
			if err != nil {
				return err
			}
			sock := portableSocket(op)
			d := daemon.New(daemon.Config{
				Operator: op, SocketPath: sock, ToolVersion: buildinfo.Version, Sensors: true,
				Agent: []string{"agent", "--socket", sock}, AgentEnv: agentEnv(op, sock, f.lang),
				HardenAfterArm: true, Out: cmd.ErrOrStderr(), Resolved: resolved(),
			})
			defer d.Close()
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			// The daemon has its own context: a signal disarms first, then stops it.
			runCtx, stopDaemon := context.WithCancel(context.Background())
			defer stopDaemon()
			errc := make(chan error, 1)
			go func() { errc <- d.Run(runCtx) }()
			f.confirming(cmd.ErrOrStderr())
			res, rep, err := d.Arm(req)
			if err != nil {
				stopDaemon()
				<-errc
				return armFailed(cmd.ErrOrStderr(), rep, err)
			}
			printArmed(cmd.OutOrStdout(), res)
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Ctrl-C desarma. Em PÂNICO, use `lethe unpanic` antes.")
			<-ctx.Done()
			st := d.Status()
			if st.State == "PANIC" {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "lethe: sessão encerrada em PÂNICO: o bloqueio fica ativo de propósito.\n  como sair: sudo lethe cleanup (remove só as tabelas lethe*), ou reinicie a máquina")
			}
			var dr daemon.DisarmResult
			if st.State == "ARMED" {
				dr, err = d.Disarm()
			}
			stopDaemon()
			if rerr := <-errc; err == nil {
				err = rerr
			}
			if err != nil {
				return rpcErr(err)
			}
			crit := dr.Critical
			for _, a := range st.Alerts {
				if a.Severity == "CRITICAL" && st.State == "PANIC" {
					crit++
				}
			}
			if crit > 0 {
				return WithCode(ExitSessionCritical, fmt.Errorf("session %s ended with %d CRITICAL alert(s)", res.Session, crit))
			}
			return nil
		},
	}
	f.register(cmd)
	cmd.Flags().BoolVar(&noGUI, "no-gui", false, "do not start the GUI")
	cmd.Flags().BoolVar(&tui, "tui", false, "terminal UI instead of the GUI")
	cmd.Flags().BoolVar(&noActive, "no-active", false, "disable the active checks (NET-011)")
	return cmd
}

func resolved() discovery.ResolvedClient {
	r, err := discovery.NewDBusResolved()
	if err != nil {
		return nil
	}
	return r
}

// agentEnv is the minimal environment the session agent needs (bus, display, language).
func agentEnv(op platform.Operator, sock, lang string) []string {
	env := []string{"HOME=" + op.Home, "LETHE_SOCKET=" + sock, "PATH=/usr/bin:/bin", "LETHE_LANG=" + lang}
	for _, k := range []string{"LANG", "LC_ALL", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
		"XDG_CONFIG_HOME", "XKB_DEFAULT_LAYOUT", "PIPEWIRE_REMOTE", "PIPEWIRE_RUNTIME_DIR"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func newDaemonCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:    "daemon",
		Short:  "Service mode daemon (lethed.service); one session per process",
		Args:   cobra.NoArgs,
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 {
				return WithCode(ExitPrivileges, errors.New("the daemon runs as root"))
			}
			op, err := platform.CurrentOperator(os.Getenv)
			if err != nil {
				return err
			}
			if sock == "" {
				sock = serviceSocket
				if p := os.Getenv("LETHE_SOCKET"); p != "" {
					sock = p
				}
			}
			d := daemon.New(daemon.Config{Operator: op, SocketPath: sock, ToolVersion: buildinfo.Version, Sensors: true,
				HardenAfterArm: true, ExitAfterSession: true, Out: cmd.ErrOrStderr(), Resolved: resolved()})
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return d.Run(ctx)
		},
	}
	cmd.Flags().StringVar(&sock, "socket", "", "socket path (default "+serviceSocket+")")
	return cmd
}

func newAgentCmd() *cobra.Command {
	var sock string
	cmd := &cobra.Command{
		Use:    "agent",
		Short:  "Session agent (spawned by run; low-trust sensor, spec §5.1)",
		Args:   cobra.NoArgs,
		Hidden: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sock == "" {
				var err error
				if sock, err = clientSocket(); err != nil {
					return WithCode(ExitDaemonDown, err)
				}
			}
			dial := func() (*ipc.Client, error) {
				var c *ipc.Client
				var err error
				for range 50 { // the daemon may still be binding the socket
					if c, err = ipc.Dial(sock, time.Second); err == nil {
						return c, nil
					}
					time.Sleep(100 * time.Millisecond)
				}
				return nil, err
			}
			cfg := agent.Config{Dial: dial, Language: os.Getenv("LETHE_LANG"),
				Out: func(format string, a ...any) { _, _ = fmt.Fprintf(cmd.ErrOrStderr(), format, a...) }}
			if n, err := agent.NewDBusNotifier(); err == nil {
				cfg.Notifier = n
			} else {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "lethe agent: no session bus (%v): alerts only on the terminal\n", err)
			}
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			if err := agent.Run(ctx, cfg); err != nil {
				return WithCode(ExitDaemonDown, err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&sock, "socket", "", "daemon socket")
	return cmd
}

func newArmCmd() *cobra.Command {
	var f armFlags
	cmd := &cobra.Command{
		Use:   "arm",
		Short: "Arm a session on the running daemon (service mode)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			op, err := platform.CurrentOperator(os.Getenv)
			if err != nil {
				return err
			}
			c, err := dialDaemon()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			req, err := f.request(cmd, op)
			defer wipeBytes(req.Passphrase)
			if err != nil {
				return err
			}
			_ = c.SetDeadline(time.Now().Add(2*time.Minute + f.window))
			f.confirming(cmd.ErrOrStderr())
			var res daemon.ArmResult
			if err := c.Call("session.arm", req, nil, &res); err != nil {
				var rep preflight.Report
				return armFailed(cmd.ErrOrStderr(), rep, err)
			}
			printArmed(cmd.OutOrStdout(), res)
			return nil
		},
	}
	f.register(cmd)
	return cmd
}

// sensitiveCmd builds disarm / unpanic: one sensitive call proven with the passphrase.
func sensitiveCmd(use, short, method string, done func(io.Writer, json.RawMessage) error) *cobra.Command {
	var s secretFlags
	cmd := &cobra.Command{
		Use: use, Short: short, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := dialDaemon()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			proof, err := prove(c, s.source(cmd), method, nil)
			if err != nil {
				return err
			}
			var out json.RawMessage
			if err := c.Call(method, nil, proof, &out); err != nil {
				return rpcErr(err)
			}
			return done(cmd.OutOrStdout(), out)
		},
	}
	s.register(cmd)
	return cmd
}

func newDisarmCmd() *cobra.Command {
	return sensitiveCmd("disarm", "Disarm the session: remove the guard, close and sign the journal", "session.disarm",
		func(w io.Writer, raw json.RawMessage) error {
			var r daemon.DisarmResult
			if err := json.Unmarshal(raw, &r); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(w, "DESARMADO  sessão %s  (%s)\n", r.Session, r.Dir)
			if r.Critical > 0 {
				return WithCode(ExitSessionCritical, fmt.Errorf("session ended with %d CRITICAL alert(s)", r.Critical))
			}
			return nil
		})
}

func newUnpanicCmd() *cobra.Command {
	return sensitiveCmd("unpanic", "Leave PANIC (all CRITICAL acknowledged, state re-check, passphrase)", "panic.release",
		func(w io.Writer, _ json.RawMessage) error {
			_, _ = fmt.Fprintln(w, "PÂNICO liberado: sessão ARMADA")
			return nil
		})
}

func newPanicCmd() *cobra.Command {
	return &cobra.Command{
		Use: "panic", Short: "Block all traffic now and kill the configured processes", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := dialDaemon()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			if err := c.Call("panic.engage", nil, nil, nil); err != nil {
				return rpcErr(err)
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), "PÂNICO: rede bloqueada")
			return nil
		},
	}
}

func newAckCmd() *cobra.Command {
	var reason string
	var s secretFlags
	cmd := &cobra.Command{
		Use: "ack ID", Short: "Acknowledge an alert (CRITICAL needs --reason and the passphrase)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := dialDaemon()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			var st daemon.Status
			if err := c.Call("status.get", nil, nil, &st); err != nil {
				return rpcErr(err)
			}
			params := map[string]string{"id": args[0], "reason": reason}
			var proof *ipc.Auth
			for _, a := range st.Alerts {
				if a.ID == args[0] && a.Severity == "CRITICAL" {
					if reason == "" {
						return errors.New("a CRITICAL alert needs --reason")
					}
					if proof, err = prove(c, s.source(cmd), "alert.ack", params); err != nil {
						return err
					}
				}
			}
			if err := c.Call("alert.ack", params, proof, nil); err != nil {
				return rpcErr(err)
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%s reconhecido\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&reason, "reason", "", "why (required for CRITICAL)")
	s.register(cmd)
	return cmd
}

func newStatusCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use: "status", Short: "Session state, open alerts and sensors", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := dialDaemon()
			if err != nil {
				return statusNoDaemon(cmd.OutOrStdout(), asJSON, err)
			}
			defer func() { _ = c.Close() }()
			var st daemon.Status
			if err := c.Call("status.get", nil, nil, &st); err != nil {
				return rpcErr(err)
			}
			st.AuthSalt = nil // not for humans or scripts; clients fetch it when they prove
			return writeStatus(cmd.OutOrStdout(), st, asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (schema: status)")
	return cmd
}

func writeStatus(w io.Writer, st daemon.Status, asJSON bool) error {
	if asJSON {
		if err := contracts.Validate("status", st); err != nil {
			return fmt.Errorf("internal: status output violates contract: %w", err)
		}
		return json.NewEncoder(w).Encode(st)
	}
	return printStatus(w, st)
}

// leftoverTables lists lethe* tables in this network namespace (a variable for tests).
var leftoverTables = func() ([]string, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, err
	}
	refs, err := guard.Leftovers(c)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, r := range refs {
		out = append(out, r.String())
	}
	return out, nil
}

var isRoot = func() bool { return os.Geteuid() == 0 }

// statusNoDaemon does not stop at "daemon unreachable" (spec §10.6 item 6): as root it looks
// for lethe* tables left by a crash and says how to remove them. The exit code stays 12.
func statusNoDaemon(w io.Writer, asJSON bool, cause error) error {
	st := daemon.Status{State: "NO_DAEMON", Color: "GRAY", Alerts: []daemon.AlertView{}, Degraded: []string{}, Sensors: []daemon.SensorView{}}
	note := ""
	switch {
	case !isRoot():
		st.Degraded = append(st.Degraded, "leftover_tables_unchecked")
		note = "sem root não dá para ver se sobraram tabelas lethe* bloqueando a rede; sudo lethe status verifica"
	default:
		tables, err := leftoverTables()
		if err != nil {
			st.Degraded = append(st.Degraded, "leftover_tables_unchecked")
			note = fmt.Sprintf("não deu para listar as tabelas nftables: %v", err)
			break
		}
		st.Lockdown = daemon.LeftoverLockdown(tables)
		if st.Lockdown == nil {
			note = "nenhuma tabela lethe* encontrada: o lethe não está bloqueando a rede"
		}
	}
	if err := writeStatus(w, st, asJSON); err != nil {
		return err
	}
	if !asJSON && note != "" {
		_, _ = fmt.Fprintln(w, note)
	}
	return WithCode(ExitDaemonDown, cause)
}

func printStatus(w io.Writer, st daemon.Status) error {
	if st.State == "NO_DAEMON" {
		_, _ = fmt.Fprintln(w, "nenhum daemon do lethe rodando")
		if st.Lockdown != nil {
			_, _ = fmt.Fprintf(w, "BLOQUEIO: %s\n", st.Lockdown)
		}
		return nil
	}
	_, _ = fmt.Fprintf(w, "estado %s  cor %s", st.State, st.Color)
	if st.Session != "" {
		_, _ = fmt.Fprintf(w, "  sessão %s  guarda %s  impressão %s", st.Session, st.Guard, st.Fingerprint)
	}
	_, _ = fmt.Fprintln(w)
	if st.Confirming {
		_, _ = fmt.Fprintln(w, "arm em confirmação: o túnel ainda não provou que passa tráfego")
	}
	if st.Lockdown != nil {
		_, _ = fmt.Fprintf(w, "BLOQUEIO: %s\n", st.Lockdown)
	}
	if len(st.Degraded) > 0 {
		_, _ = fmt.Fprintf(w, "visibilidade degradada: %s\n", strings.Join(st.Degraded, ", "))
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ALERTA\tCHECK\tSEVERIDADE\tESTADO\tCONTAGEM\tÚLTIMO")
	for _, a := range st.Alerts {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\n", a.ID, a.Check, a.Severity, a.State, a.Count, a.LastSeen.Format(time.RFC3339))
	}
	return tw.Flush()
}

func newEventsCmd() *cobra.Command {
	var follow, asJSON bool
	var sev string
	cmd := &cobra.Command{
		Use: "events", Short: "Event stream of the session", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if sev != "" && !contracts.Severity(sev).Valid() {
				return fmt.Errorf("--severity %q: want INFO, WARNING or CRITICAL", sev)
			}
			c, err := dialDaemon()
			if err != nil {
				return err
			}
			defer func() { _ = c.Close() }()
			q := daemon.QueryParams{Severity: sev}
			var evs []contracts.Event
			if err := c.Call("events.query", q, nil, &evs); err != nil {
				return rpcErr(err)
			}
			for _, ev := range evs {
				printEvent(cmd.OutOrStdout(), ev, asJSON)
			}
			if !follow {
				return nil
			}
			if err := c.Call("events.subscribe", q, nil, nil); err != nil {
				return rpcErr(err)
			}
			for {
				raw, err := c.ReadNotification()
				if err != nil {
					return nil // daemon gone or session over
				}
				var ev contracts.Event
				if json.Unmarshal(raw, &ev) == nil {
					printEvent(cmd.OutOrStdout(), ev, asJSON)
				}
			}
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new events")
	cmd.Flags().StringVar(&sev, "severity", "", "minimum severity")
	cmd.Flags().BoolVar(&asJSON, "json", false, "one event per line (schema: event)")
	return cmd
}

func printEvent(w io.Writer, ev contracts.Event, asJSON bool) {
	if asJSON {
		_ = json.NewEncoder(w).Encode(ev)
		return
	}
	line := fmt.Sprintf("%s #%d %s", ev.TS.Format("15:04:05.000"), ev.Seq, ev.Type)
	if ev.Check != "" {
		line += " " + ev.Check + " " + string(ev.Severity)
	}
	if ev.AlertID != "" {
		line += " " + ev.AlertID
	}
	if len(ev.Actions) > 0 {
		line += " actions=" + strings.Join(ev.Actions, ",")
	}
	_, _ = fmt.Fprintln(w, platform.TermSafe(line))
}

func newPreflightCmd() *cobra.Command {
	var path string
	var asJSON, noManual bool
	cmd := &cobra.Command{
		Use: "preflight", Short: "Run the preflight (automatic checks + manual checklist)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			op, err := platform.CurrentOperator(os.Getenv)
			if err != nil {
				return err
			}
			p, warns, err := profile.Load(path, op.Home)
			if err != nil {
				return err
			}
			opt := discovery.Options{Now: time.Now(), Overrides: discovery.Overrides{Egress: p.Network.EgressIfaces, Internal: p.Network.InternalIfaces}}
			for _, e := range p.Egress.ParsedEndpoints {
				opt.ProfileEndpoints = append(opt.ProfileEndpoints, discovery.Endpoint{Addr: e.Addr, Proto: e.Proto})
			}
			if r := resolved(); r != nil {
				opt.Resolved = r
			}
			if checks.TorQueried(p.Egress.Type) {
				tc := discovery.NewTorControl(p.Egress.TorControl, p.Egress.TorCookie, op.UID)
				defer func() { _ = tc.Close() }()
				opt.Tor, opt.TorRequired = tc, checks.TorRequired(p.Egress.Type)
			}
			snap := discovery.Discover(discovery.NetlinkKernel{}, opt)
			host := hostCollector(p).Collect()
			in := preflight.Input{Snapshot: &snap, Profile: p, Warnings: warns, Host: &host, Now: time.Now()}
			if !noManual {
				if in.Manual, err = askManual(cmd.InOrStdin(), cmd.ErrOrStderr()); err != nil {
					return err
				}
			}
			rep := preflight.Run(in)
			if asJSON {
				if err := contracts.Validate("preflight", rep); err != nil {
					return fmt.Errorf("internal: preflight output violates contract: %w", err)
				}
				if err := json.NewEncoder(cmd.OutOrStdout()).Encode(rep); err != nil {
					return err
				}
			} else {
				printPreflight(cmd.OutOrStdout(), rep)
			}
			if rep.Result == preflight.Fail {
				return WithCode(ExitPreflightFailed, errors.New("preflight FAIL"))
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&path, "profile", "p", "", "operation profile (YAML)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output (schema: preflight)")
	cmd.Flags().BoolVar(&noManual, "no-manual", false, "skip the manual checklist (result at most WARN)")
	_ = cmd.MarkFlagRequired("profile")
	return cmd
}

// hostCollector reads the host state with the operator's rights. Without the passphrase the
// baseline comparisons (HOST-004, HOST-008, NET-014) are not made here; the arm makes them.
func hostCollector(p *profile.Profile) hostinfo.Collector {
	return hostinfo.Collector{
		Bus: func() dbusmon.Bus {
			c, err := dbus.ConnectSystemBus()
			if err != nil {
				return nil
			}
			return c
		},
		PersonaProfiles: p.Browsers.PersonaProfiles,
		StateDir:        filepath.Join(p.Storage.Dir, "state"),
	}
}

func printPreflight(w io.Writer, r preflight.Report) {
	for _, c := range r.Checks {
		_, _ = fmt.Fprintf(w, "%-8s %s\n", c.ID, c.Status)
	}
	for _, m := range r.Manual {
		st := "OK"
		if !m.OK {
			st = "NÃO"
		}
		_, _ = fmt.Fprintf(w, "%-8s %s\n", m.ID, st)
	}
	for _, x := range r.Warnings {
		_, _ = fmt.Fprintf(w, "WARN     %s\n", x)
	}
	if r.ManualSkipped {
		_, _ = fmt.Fprintln(w, "WARN     checklist manual não respondido (--no-manual)")
	}
	_, _ = fmt.Fprintf(w, "preflight: %s\n", r.Result)
}
