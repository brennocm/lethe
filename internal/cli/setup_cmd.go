package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"lethe/internal/buildinfo"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/platform"
	"lethe/internal/preflight"
	"lethe/internal/profile"
	"lethe/internal/sensors/hostinfo"
	"lethe/internal/setup"
)

// lethe setup (spec §10.6 item 8): profile and baseline from simple questions, the profile in
// off; strict is offered only after an approved selftest on this machine. Running it again
// with an existing profile goes straight to that offer.

// setupEnv is what the wizard reads from the machine (fakes in tests).
type setupEnv struct {
	discover  func(p *profile.Profile) discovery.Snapshot
	host      func() hostinfo.Facts
	now       func() time.Time
	preflight func(p *profile.Profile, snap discovery.Snapshot) preflight.Report
}

func liveSetupEnv() setupEnv {
	return setupEnv{
		discover: func(p *profile.Profile) discovery.Snapshot {
			opt := discovery.Options{Now: time.Now()}
			if p != nil {
				opt.Overrides = discovery.Overrides{Egress: p.Network.EgressIfaces, Internal: p.Network.InternalIfaces}
			}
			if r := resolved(); r != nil {
				opt.Resolved = r
			}
			return discovery.Discover(discovery.NetlinkKernel{}, opt)
		},
		host: func() hostinfo.Facts { return hostinfo.Reader{Root: "/"}.Read() },
		now:  time.Now,
		preflight: func(p *profile.Profile, snap discovery.Snapshot) preflight.Report {
			host := hostCollector(p).Collect()
			return preflight.Run(preflight.Input{Snapshot: &snap, Profile: p, Guard: "strict", Host: &host, Now: time.Now()})
		},
	}
}

func newSetupCmd() *cobra.Command {
	var dir string
	var sec secretFlags
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "First-use assistant: profile and baseline, starting in off (strict after an approved selftest)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			op, err := platform.CurrentOperator(os.Getenv)
			if err != nil {
				return err
			}
			if dir == "" {
				dir = filepath.Join(op.Home, "lethe")
			}
			w := &wizard{
				pr:  &prompter{in: bufio.NewReader(cmd.InOrStdin()), out: cmd.OutOrStdout()},
				out: cmd.OutOrStdout(), dir: dir, home: op.Home, env: liveSetupEnv(),
				pass: func() ([]byte, error) { return sec.source(cmd).read("Baseline passphrase (new): ", true) },
				work: sec.workFactor,
			}
			return w.run()
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "", "where the profile, the baseline and the data go (default ~/lethe)")
	sec.register(cmd)
	return cmd
}

type wizard struct {
	pr   *prompter
	out  io.Writer
	dir  string
	home string
	env  setupEnv
	pass func() ([]byte, error)
	work int
}

func (w *wizard) say(format string, a ...any) { _, _ = fmt.Fprintf(w.out, format, a...) }

// askDefault asks q, showing and returning def on an empty answer.
func (w *wizard) askDefault(q, def string) (string, error) {
	if def != "" {
		q += " [" + def + "]"
	}
	v, err := w.pr.ask(q + ": ")
	if err != nil {
		return "", err
	}
	if v == "" {
		v = def
	}
	if strings.ContainsAny(v, "\n\r\"\\") || len(v) > 128 {
		return "", fmt.Errorf("invalid answer to %q", q)
	}
	return v, nil
}

func (w *wizard) yes(q string) (bool, error) {
	v, err := w.pr.ask(q + " [y/N] ")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(v) {
	case "s", "sim", "y", "yes":
		return true, nil
	}
	return false, nil
}

func (w *wizard) paths() (prof, base, data string) {
	return filepath.Join(w.dir, "profile.yaml"), filepath.Join(w.dir, "baseline.age"), filepath.Join(w.dir, "data")
}

func (w *wizard) run() error {
	profPath, basePath, dataDir := w.paths()
	if _, err := os.Stat(profPath); err == nil {
		w.say("Profile already exists at %s.\n", profPath)
		return w.offerStrict(profPath, dataDir)
	}
	if err := os.MkdirAll(w.dir, 0o700); err != nil {
		return err
	}
	w.say("lethe setup: profile and baseline in %s. Enter accepts the value in brackets.\n\n", w.dir)

	snap := w.env.discover(nil)
	kind := setup.SuggestEgress(snap)
	w.say("Discovered: %s.\n", describeSnap(snap))
	facts := w.env.host()

	opID, err := w.askDefault("Operation ID", "OP-0000-000")
	if err != nil {
		return err
	}
	persona, err := w.askDefault("Persona name", "persona")
	if err != nil {
		return err
	}
	egress, err := w.askDefault("Egress type (wireguard, openvpn, tor, vpn+tor, auto)", kind)
	if err != nil {
		return err
	}
	if !map[string]bool{"wireguard": true, "openvpn": true, "tor": true, "vpn+tor": true, "auto": true}[egress] {
		return fmt.Errorf("unknown egress type %q", egress)
	}
	country, err := w.askDefault("Expected country of the exit IP (two letters, e.g. NL)", "NL")
	if err != nil {
		return err
	}
	country = strings.ToUpper(country)
	if !regexp.MustCompile(`^[A-Z]{2}$`).MatchString(country) {
		return fmt.Errorf("country %q: use the two-letter code (ISO 3166-1)", country)
	}
	w.say("The persona should look like it is from there: the time zone, locale and keyboard the target would expect.\n")
	tz, err := w.askDefault("Persona time zone", "UTC")
	if err != nil {
		return err
	}
	if _, err := time.LoadLocation(tz); err != nil {
		w.say("warning: time zone %q does not exist on this system; check it before arming.\n", tz)
	}
	loc, err := w.askDefault("Persona locale", "en_US.UTF-8")
	if err != nil {
		return err
	}
	kb, err := w.askDefault("Persona keyboard layout", "us")
	if err != nil {
		return err
	}
	if facts.Timezone != "" && facts.Timezone != tz {
		w.say("Note: the system is on %s; HOST-005 will warn until you change the time zone.\n", facts.Timezone)
	}

	ans := setup.Answers{Dir: w.dir, OpID: opID, Persona: persona, Egress: egress, Country: country,
		Timezone: tz, Locale: loc, Keyboard: kb, WorkLimit: w.work}
	var pw []byte
	if _, err := os.Stat(basePath); err == nil {
		w.say("Using the existing baseline at %s.\n", basePath)
	} else {
		w.say("\nBaseline: the real data of this machine and your networks, encrypted. Answer WITHOUT the tunnel up,\n" +
			"on a known network. The values never appear in logs, only the name of the field that matched.\n")
		// gateway and resolvers as read from this machine; Enter keeps them
		if ans.Network, err = askNetworkWith(w.pr, setup.Detect(context.Background(), snap, nil).Network); err != nil {
			return err
		}
		if pw, err = w.pass(); err != nil {
			return WithCode(ExitAuth, err)
		}
		defer wipeBytes(pw)
	}
	if _, err := setup.Create(ans, w.home, pw, w.env.now(), buildinfo.Version); err != nil {
		return err
	}
	if _, err := os.Stat(basePath); err == nil {
		w.say("Baseline written to %s. Keep the passphrase: without it there is no arm and no report.\n", basePath)
	}
	w.say("\nProfile written to %s with the guard off (observe only; nothing is blocked).\n", profPath)
	return w.offerStrict(profPath, dataDir)
}

// selftestOK says whether this machine has a recent approved full selftest.
func (w *wizard) selftestOK(dataDir string) (bool, string) {
	raw, err := os.ReadFile(filepath.Join(dataDir, "state", "selftest.json")) // #nosec G304 G703 -- the operator's own data dir
	if err != nil {
		raw = nil
	}
	ok, why := contracts.SelftestApproval(raw, w.env.now())
	return ok, map[string]string{
		contracts.SelftestNone:       "no selftest has run on this machine",
		contracts.SelftestUnreadable: "the selftest record is unreadable",
		contracts.SelftestFailed:     "the last selftest had failures",
		contracts.SelftestPartial:    "the last selftest did not run every case",
		contracts.SelftestStale:      "the last selftest is more than 24 h old",
	}[why]
}

// offerStrict switches the profile to strict after an approved selftest, then shows the
// preflight under strict.
func (w *wizard) offerStrict(profPath, dataDir string) error {
	raw, err := os.ReadFile(profPath) // #nosec G304 -- the operator's own profile
	if err != nil {
		return err
	}
	if regexp.MustCompile(`(?m)^  mode: strict\b`).Match(raw) {
		w.say("The guard is already strict.\n")
		return nil
	}
	if p, _, err := profile.Parse(raw, w.home); err == nil && p.Storage.Dir != "" {
		dataDir = p.Storage.Dir
	}
	if ok, why := w.selftestOK(dataDir); !ok {
		w.say("\nStrict (recommended) is offered only after an approved selftest: %s.\n"+
			"Next steps:\n"+
			"  1. sudo lethe run -p %s       (guard off: observe only)\n"+
			"  2. lethe selftest              (in another terminal)\n"+
			"  3. lethe setup                 (again: offers strict)\n", why, profPath)
		return nil
	}
	w.say("\nThis machine's selftest passed. Strict lets only the tunnel out: it prevents the leak,\n" +
		"not just detects it. If the tunnel goes down, the network stops until it comes back (or until `lethe disarm`).\n")
	ok, err := w.yes("Switch the profile to strict?")
	if err != nil || !ok {
		if err == nil {
			w.say("The profile stays off.\n")
		}
		return err
	}
	text, err := setup.SetYAML(string(raw), "mode", "strict")
	if err != nil {
		return err
	}
	p, _, err := profile.Parse([]byte(text), w.home)
	if err != nil {
		return fmt.Errorf("internal: strict profile is invalid: %w", err)
	}
	if err := setup.ReplaceFile(profPath, []byte(text)); err != nil {
		return err
	}
	w.say("Profile is now strict. Preflight under strict (what will be allowed):\n")
	rep := w.env.preflight(p, w.env.discover(p))
	printPreflight(w.out, rep)
	if rep.Result == "FAIL" {
		w.say("The preflight would fail: fix the FAIL items above before arming (`lethe arm` refuses).\n")
	}
	return nil
}

func describeSnap(s discovery.Snapshot) string {
	var parts []string
	if len(s.CaptureIfaces) > 0 {
		parts = append(parts, "physical egress "+strings.Join(s.CaptureIfaces, ", "))
	}
	for _, t := range s.Tunnels {
		parts = append(parts, fmt.Sprintf("tunnel %s (%s)", t.Iface, t.Kind))
	}
	if len(s.Tunnels) == 0 {
		parts = append(parts, "no tunnel up now")
	}
	if len(parts) == 0 {
		return "nothing found"
	}
	return strings.Join(parts, "; ")
}
