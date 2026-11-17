// Package setup creates an operator's first profile and baseline (spec §10.6 item 8, §15.1):
// what `lethe setup` asks in the terminal and the GUI asks in its first-use form. It runs as the
// operator, never as root. It reads the machine (discovery, the local identity values) and may
// ask the "what is my IP" services once, only when no tunnel is up, to fill the baseline's public
// IP. It never applies a guard, kills or changes the network (imports_test enforces it).
package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"lethe/internal/baseline"
	"lethe/internal/discovery"
	"lethe/internal/profile"
	"lethe/internal/sensors/egressip"
)

// Egress types the assistant offers.
var Egresses = []string{"auto", "wireguard", "openvpn", "tor", "vpn+tor"}

// Answers is everything the first use asks.
type Answers struct {
	Dir       string // where profile.yaml, baseline.age and data/ go (default ~/lethe)
	OpID      string
	Persona   string
	Egress    string
	Country   string // expected exit country, ISO 3166-1 alpha-2
	Timezone  string // the persona's
	Locale    string
	Keyboard  string
	Network   baseline.Network // the real network (home, office)
	WorkLimit int              // scrypt work factor (0 = baseline.DefaultWorkFactor)
}

// Defaults are the assistant's suggestions.
func Defaults(home string) Answers {
	return Answers{Dir: filepath.Join(home, "lethe"), OpID: "OP-0000-000", Persona: "persona", Egress: "auto",
		Country: "NL", Timezone: "UTC", Locale: "en_US.UTF-8", Keyboard: "us", Network: baseline.Network{Name: "casa"}}
}

// Paths of the files under dir.
func Paths(dir string) (prof, base, data string) {
	return filepath.Join(dir, "profile.yaml"), filepath.Join(dir, "baseline.age"), filepath.Join(dir, "data")
}

var (
	countryRe = regexp.MustCompile(`^[A-Z]{2}$`)
	// ErrPassphrase is an empty passphrase or one that differs from its confirmation.
	ErrPassphrase = errors.New("the passphrase is empty or the two entries differ")
)

// Validate checks the answers; the messages name the field in the operator's words.
func (a *Answers) Validate() error {
	a.Country = strings.ToUpper(strings.TrimSpace(a.Country))
	for name, v := range map[string]string{"identificador da operação": a.OpID, "persona": a.Persona, "fuso": a.Timezone,
		"idioma": a.Locale, "teclado": a.Keyboard} {
		if strings.TrimSpace(v) == "" || strings.ContainsAny(v, "\n\r\"\\") || len(v) > 128 {
			return fmt.Errorf("%s: vazio, longo demais ou com caracteres inválidos", name)
		}
	}
	ok := false
	for _, e := range Egresses {
		ok = ok || a.Egress == e
	}
	if !ok {
		return fmt.Errorf("tipo de saída %q desconhecido", a.Egress)
	}
	if !countryRe.MatchString(a.Country) {
		return fmt.Errorf("país %q: use o código de duas letras (ISO 3166-1), ex.: NL", a.Country)
	}
	if _, err := time.LoadLocation(a.Timezone); err != nil {
		return fmt.Errorf("fuso %q não existe neste sistema", a.Timezone)
	}
	return nil
}

// Exists says whether dir already has a profile (the first use is over).
func Exists(dir string) bool {
	p, _, _ := Paths(dir)
	_, err := os.Stat(p)
	return err == nil
}

// Create writes the baseline (encrypted with pass, which the caller wipes) and the profile,
// guard off, keep_tunnel on. An existing baseline is kept (pass and Network are then unused);
// an existing profile is never overwritten.
func Create(a Answers, home string, pass []byte, now time.Time, version string) (profPath string, err error) {
	if err := a.Validate(); err != nil {
		return "", err
	}
	profPath, basePath, dataDir := Paths(a.Dir)
	if Exists(a.Dir) {
		return "", fmt.Errorf("%s already exists; refusing to overwrite", profPath)
	}
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		return "", err
	}
	if _, err := os.Stat(basePath); err != nil {
		if len(pass) == 0 {
			return "", ErrPassphrase
		}
		if n := strings.TrimSpace(a.Network.Name); n == "" || len(n) > 128 {
			return "", errors.New("nome da rede: diga como você chama a rede real (ex.: casa)")
		}
		b, err := baseline.New(now, version)
		if err != nil {
			return "", err
		}
		baseline.CollectLocal("/", os.Getenv).Apply(b)
		if err := b.AddNetwork(a.Network); err != nil {
			return "", err
		}
		work := a.WorkLimit
		if work == 0 {
			work = baseline.DefaultWorkFactor
		}
		enc, err := baseline.Encrypt(b, pass, work)
		if err != nil {
			return "", err
		}
		if err := WriteNew(basePath, enc); err != nil {
			return "", err
		}
	}
	text := string(profile.Template)
	for _, kv := range [][2]string{
		{"id", Quote(a.OpID)}, {"persona", Quote(a.Persona)},
		{"type", a.Egress}, {"expect_country", a.Country},
		{"timezone", Quote(a.Timezone)}, {"locale", Quote(a.Locale)}, {"keyboard", Quote(a.Keyboard)},
		{"file", Quote(basePath)}, {"dir", Quote(dataDir)},
	} {
		if text, err = SetYAML(text, kv[0], kv[1]); err != nil {
			return "", err
		}
	}
	if _, _, err := profile.Parse([]byte(text), home); err != nil {
		return "", fmt.Errorf("internal: generated profile is invalid: %w", err)
	}
	return profPath, WriteNew(profPath, []byte(text))
}

// Detected is what the machine says about itself before the first use.
type Detected struct {
	Egress   string           // suggested egress.type
	Network  baseline.Network // gateway, resolvers and, with no tunnel up, the public IP
	TunnelUp bool             // a tunnel carries the default route: the public IP was not asked
	Note     string           // why the public IP is missing, when it is
}

// Detect reads the snapshot and, only when no tunnel carries the default route, asks query
// (two "what is my IP" services that must agree) for the real connection's public IP.
func Detect(ctx context.Context, snap discovery.Snapshot, query func(context.Context, []string) egressip.Result) Detected {
	d := Detected{Egress: SuggestEgress(snap)}
	n := &d.Network
	for _, r := range snap.Routes.DefaultV4 {
		if r.Class == discovery.ClassTunnel {
			d.TunnelUp = true
		}
		if r.Gateway != "" && n.GatewayIP == "" && r.Class != discovery.ClassTunnel {
			n.GatewayIP = r.Gateway
		}
	}
	add := func(v string) {
		for _, x := range n.Resolvers {
			if x == v {
				return
			}
		}
		n.Resolvers = append(n.Resolvers, v)
	}
	if !snap.DNS.ResolvConf.Stub {
		for _, v := range snap.DNS.ResolvConf.Nameservers {
			add(v)
		}
	}
	tunnels := map[string]bool{}
	for _, t := range snap.Tunnels {
		tunnels[t.Iface] = true
	}
	for _, l := range snap.DNS.Resolved.Links {
		if l.DefaultRoute && !tunnels[l.Iface] {
			for _, v := range l.Servers {
				add(v)
			}
		}
	}
	if d.TunnelUp {
		d.Note = "tunnel_up"
		return d
	}
	if query == nil {
		d.Note = "no_query"
		return d
	}
	p, _, err := profile.Parse(profile.Template, "/")
	if err != nil {
		d.Note = "no_query"
		return d
	}
	res := query(ctx, p.ActiveChecks.EgressIP.Endpoints)
	switch {
	case res.Skipped != "" || !res.Agreed:
		d.Note = "no_agreement"
	case res.IP.Is4():
		n.PublicIPv4 = res.IP.String()
	default:
		n.PublicIPv6 = res.IP.String()
	}
	return d
}

// SuggestEgress guesses egress.type from the discovery.
func SuggestEgress(s discovery.Snapshot) string {
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

// SetYAML replaces the value of the first "  key: value" line, keeping its comment.
func SetYAML(text, key, value string) (string, error) {
	re := regexp.MustCompile(`(?m)^(  ` + regexp.QuoteMeta(key) + `: )("[^"]*"|\S+)`)
	loc := re.FindStringSubmatchIndex(text)
	if loc == nil {
		return "", fmt.Errorf("internal: profile template has no %q", key)
	}
	return text[:loc[4]] + value + text[loc[5]:], nil
}

// Quote is a YAML double-quoted scalar.
func Quote(s string) string { b, _ := json.Marshal(s); return string(b) }

// WriteNew creates path with 0600 and refuses to overwrite an existing file.
func WriteNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- the operator's own output path
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite", path)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
