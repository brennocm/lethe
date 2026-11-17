package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"lethe/internal/baseline"
	"lethe/internal/buildinfo"
	"lethe/internal/contracts"
	"lethe/internal/discovery"
	"lethe/internal/platform"
	"lethe/internal/preflight"
	"lethe/internal/profile"
	"lethe/internal/sensors/hostinfo"
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
				pass: func() ([]byte, error) { return sec.source(cmd).read("Passphrase da baseline (nova): ", true) },
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
		return "", fmt.Errorf("resposta inválida para %q", q)
	}
	return v, nil
}

func (w *wizard) yes(q string) (bool, error) {
	v, err := w.pr.ask(q + " [s/N] ")
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
		w.say("Perfil já existe em %s.\n", profPath)
		return w.offerStrict(profPath, dataDir)
	}
	if err := os.MkdirAll(w.dir, 0o700); err != nil {
		return err
	}
	w.say("lethe setup: perfil e baseline em %s. Enter aceita o valor entre colchetes.\n\n", w.dir)

	snap := w.env.discover(nil)
	kind := suggestEgress(snap)
	w.say("Descoberta: %s.\n", describeSnap(snap))
	facts := w.env.host()

	opID, err := w.askDefault("Identificador da operação", "OP-0000-000")
	if err != nil {
		return err
	}
	persona, err := w.askDefault("Nome da persona", "persona")
	if err != nil {
		return err
	}
	egress, err := w.askDefault("Tipo de saída (wireguard, openvpn, tor, vpn+tor, auto)", kind)
	if err != nil {
		return err
	}
	if !map[string]bool{"wireguard": true, "openvpn": true, "tor": true, "vpn+tor": true, "auto": true}[egress] {
		return fmt.Errorf("tipo de saída %q desconhecido", egress)
	}
	country, err := w.askDefault("País esperado do IP de saída (duas letras, ex.: NL)", "NL")
	if err != nil {
		return err
	}
	country = strings.ToUpper(country)
	if !regexp.MustCompile(`^[A-Z]{2}$`).MatchString(country) {
		return fmt.Errorf("país %q: use o código de duas letras (ISO 3166-1)", country)
	}
	w.say("A persona deve parecer de lá: fuso, idioma e teclado que o alvo esperaria ver.\n")
	tz, err := w.askDefault("Fuso horário da persona", "UTC")
	if err != nil {
		return err
	}
	if _, err := time.LoadLocation(tz); err != nil {
		w.say("aviso: o fuso %q não existe neste sistema; confira antes de armar.\n", tz)
	}
	loc, err := w.askDefault("Idioma (locale) da persona", "en_US.UTF-8")
	if err != nil {
		return err
	}
	kb, err := w.askDefault("Layout de teclado da persona", "us")
	if err != nil {
		return err
	}
	if facts.Timezone != "" && facts.Timezone != tz {
		w.say("Nota: o sistema está em %s; o HOST-005 vai avisar até você ajustar o fuso.\n", facts.Timezone)
	}

	if _, err := os.Stat(basePath); err == nil {
		w.say("Usando a baseline que já existe em %s.\n", basePath)
	} else if err := w.makeBaseline(basePath); err != nil {
		return err
	}

	text := string(profile.Template)
	for _, kv := range [][2]string{
		{"id", quote(opID)}, {"persona", quote(persona)},
		{"type", egress}, {"expect_country", country},
		{"timezone", quote(tz)}, {"locale", quote(loc)}, {"keyboard", quote(kb)},
		{"file", quote(basePath)}, {"dir", quote(dataDir)},
	} {
		if text, err = setYAML(text, kv[0], kv[1]); err != nil {
			return err
		}
	}
	if _, _, err := profile.Parse([]byte(text), w.home); err != nil {
		return fmt.Errorf("internal: generated profile is invalid: %w", err)
	}
	if err := writeNew(profPath, []byte(text)); err != nil {
		return err
	}
	w.say("\nPerfil gravado em %s com o guarda em off (só observa; nada é bloqueado).\n", profPath)
	return w.offerStrict(profPath, dataDir)
}

// makeBaseline runs the manual baseline questions (no network queries).
func (w *wizard) makeBaseline(path string) error {
	w.say("\nBaseline: os dados reais desta máquina e das suas redes, cifrados. Responda SEM o túnel ligado,\n" +
		"numa rede conhecida. Os valores nunca aparecem nos logs, só o nome do campo que casou.\n")
	b, err := baseline.New(time.Now(), buildinfo.Version)
	if err != nil {
		return err
	}
	baseline.CollectLocal("/", os.Getenv).Apply(b)
	n, err := askNetwork(w.pr)
	if err != nil {
		return err
	}
	if err := b.AddNetwork(n); err != nil {
		return err
	}
	pw, err := w.pass()
	if err != nil {
		return WithCode(ExitAuth, err)
	}
	defer wipeBytes(pw)
	enc, err := baseline.Encrypt(b, pw, w.work)
	if err != nil {
		return err
	}
	if err := writeNew(path, enc); err != nil {
		return err
	}
	w.say("Baseline gravada em %s. Guarde a passphrase: sem ela não há arm nem relatório.\n", path)
	return nil
}

// selftestOK says whether this machine has a recent approved full selftest.
func (w *wizard) selftestOK(dataDir string) (bool, string) {
	raw, err := os.ReadFile(filepath.Join(dataDir, "state", "selftest.json")) // #nosec G304 G703 -- the operator's own data dir
	if err != nil {
		raw = nil
	}
	ok, why := contracts.SelftestApproval(raw, w.env.now())
	return ok, map[string]string{
		contracts.SelftestNone:       "nenhum selftest rodou nesta máquina",
		contracts.SelftestUnreadable: "o registro do selftest está ilegível",
		contracts.SelftestFailed:     "o último selftest teve falhas",
		contracts.SelftestPartial:    "o último selftest não rodou todos os casos",
		contracts.SelftestStale:      "o último selftest tem mais de 24 h",
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
		w.say("O guarda já está em strict.\n")
		return nil
	}
	if p, _, err := profile.Parse(raw, w.home); err == nil && p.Storage.Dir != "" {
		dataDir = p.Storage.Dir
	}
	if ok, why := w.selftestOK(dataDir); !ok {
		w.say("\nO strict (recomendado) só é oferecido depois de um selftest aprovado: %s.\n"+
			"Próximos passos:\n"+
			"  1. sudo lethe run -p %s       (guarda off: só observa)\n"+
			"  2. lethe selftest              (em outro terminal)\n"+
			"  3. lethe setup                 (de novo: oferece o strict)\n", why, profPath)
		return nil
	}
	w.say("\nO selftest desta máquina passou. O strict só deixa sair o túnel: é o que impede o vazamento,\n" +
		"não só o detecta. Se o túnel cair, a rede para até ele voltar (ou até `lethe disarm`).\n")
	ok, err := w.yes("Passar o perfil para strict?")
	if err != nil || !ok {
		if err == nil {
			w.say("O perfil continua em off.\n")
		}
		return err
	}
	text, err := setYAML(string(raw), "mode", "strict")
	if err != nil {
		return err
	}
	p, _, err := profile.Parse([]byte(text), w.home)
	if err != nil {
		return fmt.Errorf("internal: strict profile is invalid: %w", err)
	}
	if err := replaceFile(profPath, []byte(text)); err != nil {
		return err
	}
	w.say("Perfil em strict. Preflight com o strict (o que vai ser permitido):\n")
	rep := w.env.preflight(p, w.env.discover(p))
	printPreflight(w.out, rep)
	if rep.Result == "FAIL" {
		w.say("O preflight falharia: resolva os itens FAIL acima antes de armar (o `lethe arm` recusa).\n")
	}
	return nil
}

// setYAML replaces the value of the first "  key: value" line, keeping its comment.
func setYAML(text, key, value string) (string, error) {
	re := regexp.MustCompile(`(?m)^(  ` + regexp.QuoteMeta(key) + `: )("[^"]*"|\S+)`)
	loc := re.FindStringSubmatchIndex(text)
	if loc == nil {
		return "", fmt.Errorf("internal: profile template has no %q", key)
	}
	return text[:loc[4]] + value + text[loc[5]:], nil
}

func quote(s string) string { b, _ := json.Marshal(s); return string(b) }

// suggestEgress guesses egress.type from the discovery.
func suggestEgress(s discovery.Snapshot) string {
	wg, tun := false, false
	for _, t := range s.Tunnels {
		switch t.Kind {
		case "wireguard":
			wg = true
		default:
			tun = true
		}
	}
	tor := s.Tor != nil && s.Tor.Reachable
	switch {
	case (wg || tun) && tor:
		return "vpn+tor"
	case wg:
		return "wireguard"
	case tun:
		return "openvpn"
	case tor:
		return "tor"
	}
	return "auto"
}

func describeSnap(s discovery.Snapshot) string {
	var parts []string
	if len(s.CaptureIfaces) > 0 {
		parts = append(parts, "saída física "+strings.Join(s.CaptureIfaces, ", "))
	}
	for _, t := range s.Tunnels {
		parts = append(parts, fmt.Sprintf("túnel %s (%s)", t.Iface, t.Kind))
	}
	if len(s.Tunnels) == 0 {
		parts = append(parts, "nenhum túnel ligado agora")
	}
	if len(parts) == 0 {
		return "nada encontrado"
	}
	return strings.Join(parts, "; ")
}
