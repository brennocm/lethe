package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lethe/internal/baseline"
	"lethe/internal/discovery"
	"lethe/internal/geo"
	"lethe/internal/preflight"
	"lethe/internal/profile"
	"lethe/internal/sensors/egressip"
	"lethe/internal/sensors/hostinfo"
)

func fakeWizard(t *testing.T, dir, input string, ran *bool) (*wizard, *bytes.Buffer) {
	t.Helper()
	out := &bytes.Buffer{}
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	return &wizard{
		pr: &prompter{in: bufio.NewReader(strings.NewReader(input)), out: out}, out: out, dir: dir, home: t.TempDir(),
		env: setupEnv{
			discover: func(*profile.Profile) discovery.Snapshot {
				return discovery.Snapshot{CaptureIfaces: []string{"eth0"}, Tunnels: []discovery.Tunnel{{Iface: "wg0", Kind: "wireguard"}}}
			},
			host: func() hostinfo.Facts { return hostinfo.Facts{Timezone: "America/Sao_Paulo"} },
			now:  func() time.Time { return now },
			preflight: func(*profile.Profile, discovery.Snapshot) preflight.Report {
				*ran = true
				return preflight.Report{Result: "PASS"}
			},
		},
		pass: func() ([]byte, error) { return []byte("lab passphrase"), nil },
		work: 10,
	}, out
}

// The assistant writes the profile in off and the baseline; strict is not offered without a
// selftest; after an approved one, running it again switches to strict and shows the preflight.
func TestM10_SetupOffThenStrictAfterSelftest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "lethe")
	answers := strings.Join([]string{
		"OP-2026-011", "", "", "nl", "Europe/Amsterdam", "nl_NL.UTF-8", "", // operation, persona, egress, country, persona
		"casa", "", "", "", "Provedor", "", "", "", "CasaSentinela", // network of the baseline
	}, "\n") + "\n"
	ran := false
	w, out := fakeWizard(t, dir, answers, &ran)
	if err := w.run(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	profPath, basePath, dataDir := w.paths()
	p, _, err := profile.Load(profPath, w.home)
	if err != nil {
		t.Fatal(err)
	}
	if p.Guard.Mode != "off" || p.Egress.Type != "wireguard" || p.Egress.ExpectCountry != "NL" || p.Expect.Timezone != "Europe/Amsterdam" ||
		p.Operation.ID != "OP-2026-011" || p.Baseline.File != basePath || p.Storage.Dir != dataDir {
		t.Fatalf("profile %+v", p)
	}
	raw, _ := os.ReadFile(basePath)
	b, err := baseline.Decrypt(raw, []byte("lab passphrase"))
	if err != nil || len(b.Networks) != 1 || b.Networks[0].SSIDs[0] != "CasaSentinela" {
		t.Fatalf("baseline %v", err)
	}
	if !strings.Contains(out.String(), "nenhum selftest rodou") || !strings.Contains(out.String(), "America/Sao_Paulo") {
		t.Fatalf("output:\n%s", out)
	}
	if strings.Contains(string(mustRead(t, profPath)), "CasaSentinela") {
		t.Fatal("a baseline value reached the profile")
	}

	// an approved selftest: setup again offers strict
	_ = os.MkdirAll(filepath.Join(dataDir, "state"), 0o700)
	_ = os.WriteFile(filepath.Join(dataDir, "state", "selftest.json"),
		[]byte(`{"finished_at":"2026-11-16T11:00:00Z","passed":true,"full":true}`), 0o600)
	w2, out2 := fakeWizard(t, dir, "s\n", &ran)
	w2.home = w.home
	if err := w2.run(); err != nil {
		t.Fatalf("%v\n%s", err, out2)
	}
	p, _, _ = profile.Load(profPath, w.home)
	if p.Guard.Mode != "strict" || !ran {
		t.Fatalf("mode %s, preflight %v\n%s", p.Guard.Mode, ran, out2)
	}
}

func TestM10_SetupNoStrictWithStaleOrFailedSelftest(t *testing.T) {
	for name, rec := range map[string]string{
		"stale":   `{"finished_at":"2026-11-14T11:00:00Z","passed":true,"full":true}`,
		"failed":  `{"finished_at":"2026-11-16T11:00:00Z","passed":false,"full":true}`,
		"partial": `{"finished_at":"2026-11-16T11:00:00Z","passed":true,"full":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			ran := false
			w, out := fakeWizard(t, dir, "s\n", &ran)
			profPath, _, dataDir := w.paths()
			text, _ := setYAML(string(profile.Template), "dir", quote(dataDir))
			_ = os.WriteFile(profPath, []byte(text), 0o600)
			_ = os.MkdirAll(filepath.Join(dataDir, "state"), 0o700)
			_ = os.WriteFile(filepath.Join(dataDir, "state", "selftest.json"), []byte(rec), 0o600)
			if err := w.run(); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(mustRead(t, profPath)), "mode: strict") || ran {
				t.Fatalf("strict offered with a %s selftest:\n%s", name, out)
			}
		})
	}
}

func TestM10_SetupRejectsBadAnswers(t *testing.T) {
	ran := false
	w, _ := fakeWizard(t, t.TempDir(), "OP\n\n\nNLD\n", &ran)
	if err := w.run(); err == nil {
		t.Fatal("a three-letter country was accepted")
	}
	w, _ = fakeWizard(t, t.TempDir(), "OP\"x\n", &ran)
	if err := w.run(); err == nil {
		t.Fatal("a quote in an answer was accepted")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNET011_BaselineOnlineDetection(t *testing.T) {
	snap := discovery.Snapshot{Routes: discovery.Routes{DefaultV4: []discovery.Route{{Iface: "eth0", Gateway: "192.168.1.1", Class: discovery.ClassEgress}}},
		DNS: discovery.DNS{ResolvConf: discovery.ResolvConf{Nameservers: []string{"192.168.1.1"}}}}
	db := geo.Map{netip.MustParseAddr("198.51.100.77"): {Country: "BR", ASN: 64501, Org: "Provedor"}}
	q := func(context.Context, []string) egressip.Result {
		return egressip.Result{Agreed: true, IP: netip.MustParseAddr("198.51.100.77")}
	}
	var out bytes.Buffer
	n, err := detectNetwork(context.Background(), &out, snap, false, q, db)
	if err != nil || n.PublicIPv4 != "198.51.100.77" || n.ASN != 64501 || n.Provider != "Provedor" || n.GatewayIP != "192.168.1.1" || n.Resolvers[0] != "192.168.1.1" {
		t.Fatalf("%+v %v", n, err)
	}
	snap.Routes.DefaultV4 = []discovery.Route{{Iface: "wg0", Class: discovery.ClassTunnel}}
	if _, err := detectNetwork(context.Background(), &out, snap, false, q, db); !errors.Is(err, ErrTunnelUp) {
		t.Fatal("a baseline through the tunnel would record the VPN's IP")
	}
	// the answers keep the detected value on Enter and take the typed one otherwise
	pr := &prompter{in: bufio.NewReader(strings.NewReader("casa\n\n\n\nOutro\n\n\n\n\n")), out: &out}
	got, err := askNetworkWith(pr, baseline.Network{PublicIPv4: "198.51.100.77", ASN: 64501, Provider: "Provedor"})
	if err != nil || got.PublicIPv4 != "198.51.100.77" || got.ASN != 64501 || got.Provider != "Outro" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestNET011_BaselineAllowTunnel(t *testing.T) {
	snap := discovery.Snapshot{Routes: discovery.Routes{DefaultV4: []discovery.Route{{Iface: "wg0", Class: discovery.ClassTunnel}}}}
	q := func(context.Context, []string) egressip.Result {
		return egressip.Result{Agreed: true, IP: netip.MustParseAddr("203.0.113.9")}
	}
	var out bytes.Buffer
	n, err := detectNetwork(context.Background(), &out, snap, true, q, nil)
	if err != nil || n.PublicIPv4 != "203.0.113.9" || !strings.Contains(out.String(), "--allow-tunnel") {
		t.Fatalf("%+v %v %s", n, err, out.String())
	}
}
