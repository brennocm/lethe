package setup

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"lethe/internal/baseline"
	"lethe/internal/discovery"
	"lethe/internal/profile"
	"lethe/internal/sensors/egressip"
)

// The first use writes a baseline the passphrase opens and a valid profile in off with
// keep_tunnel; it never overwrites.
func TestM10_SetupCreatesProfileAndBaseline(t *testing.T) {
	home := t.TempDir()
	a := Defaults(home)
	a.WorkLimit = 10
	a.Network.Resolvers = []string{"198.51.100.53"}
	if _, err := Create(a, home, nil, time.Now(), "test"); err == nil {
		t.Fatal("no passphrase accepted")
	}
	prof, err := Create(a, home, []byte("lab passphrase"), time.Now(), "test")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(prof)
	p, _, err := profile.Parse(raw, home)
	if err != nil || p.Guard.Mode != "off" || !p.Guard.Panic.KeepTunnel || p.Egress.ExpectCountry != "NL" {
		t.Fatalf("%v %+v", err, p.Guard)
	}
	enc, _ := os.ReadFile(p.Baseline.File)
	b, err := baseline.Decrypt(enc, []byte("lab passphrase"))
	if err != nil || len(b.Networks) != 1 || b.Networks[0].Resolvers[0] != "198.51.100.53" {
		t.Fatalf("%v %+v", err, b)
	}
	if _, err := Create(a, home, []byte("lab passphrase"), time.Now(), "test"); err == nil {
		t.Fatal("overwrote the profile")
	}
	// a baseline already there is kept only with its own passphrase
	_ = os.Remove(prof)
	if _, err := Create(a, home, []byte("another passphrase"), time.Now(), "test"); !errors.Is(err, ErrBaselineExists) {
		t.Fatalf("a passphrase that does not open the baseline: %v", err)
	}
	if _, err := Create(a, home, []byte("lab passphrase"), time.Now(), "test"); err != nil {
		t.Fatal(err)
	}
	bad := Defaults(home)
	bad.Country = "Holanda"
	if bad.Validate() == nil {
		t.Fatal("country not ISO")
	}
}

// Detection: gateway and resolvers from the snapshot; the public IP only with no tunnel up.
func TestM10_SetupDetect(t *testing.T) {
	snap := discovery.Snapshot{}
	snap.Routes.DefaultV4 = []discovery.Route{{Gateway: "192.0.2.1", Class: discovery.ClassEgress}}
	snap.DNS.ResolvConf.Nameservers = []string{"192.0.2.53"}
	asked := 0
	q := func(context.Context, []string) egressip.Result {
		asked++
		return egressip.Result{Agreed: true, IP: netip.MustParseAddr("203.0.113.7")}
	}
	d := Detect(context.Background(), snap, q)
	if d.Network.GatewayIP != "192.0.2.1" || d.Network.Resolvers[0] != "192.0.2.53" || d.Network.PublicIPv4 != "203.0.113.7" || d.TunnelUp {
		t.Fatalf("%+v", d)
	}
	snap.Routes.DefaultV4 = append(snap.Routes.DefaultV4, discovery.Route{Class: discovery.ClassTunnel})
	d = Detect(context.Background(), snap, q)
	if !d.TunnelUp || d.Network.PublicIPv4 != "" || asked != 1 || d.Note != "tunnel_up" {
		t.Fatalf("with a tunnel up the public IP must not be asked: %+v", d)
	}
}

// The package that the GUI imports never reaches the guard, the responses, the daemon or
// privsep, and no lethe package on its path runs a command (os/exec): only third-party code
// (godbus's autolaunch) imports it.
func TestM13_SetupNeverActsOnTheNetwork(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "lethe/internal/guard", "lethe/internal/response", "lethe/internal/daemon", "lethe/internal/privsep":
			t.Errorf("setup depends on %s", f[0])
		}
		if strings.HasPrefix(f[0], "lethe/") {
			for _, im := range f[1:] {
				if im == "os/exec" {
					t.Errorf("%s runs commands", f[0])
				}
			}
		}
	}
}

// The local reading asks nothing on the network: without askIP the public IP stays empty.
func TestM10_SetupLiveDetectStaysLocal(t *testing.T) {
	d := LiveDetect(context.Background(), false)
	if d.Network.PublicIPv4 != "" || d.Network.PublicIPv6 != "" || d.Egress == "" {
		t.Fatalf("%+v", d)
	}
}

// Another network goes into the baseline with its passphrase; a duplicate name or IP and a wrong
// passphrase change nothing.
func TestM10_SetupAddNetwork(t *testing.T) {
	home := t.TempDir()
	a := Defaults(home)
	a.WorkLimit = 10
	a.Network.PublicIPv4 = "203.0.113.7"
	if _, err := Create(a, home, []byte("lab passphrase"), time.Now(), "test"); err != nil {
		t.Fatal(err)
	}
	_, base, _ := Paths(a.Dir)
	before, _ := os.ReadFile(base)
	if _, err := AddNetwork(base, []byte("wrong passphrase"), baseline.Network{Name: "escritório"}, 10); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	if _, err := AddNetwork(base, []byte("lab passphrase"), baseline.Network{Name: "outra", PublicIPv4: "203.0.113.7"}, 10); !errors.Is(err, ErrNetworkKnown) {
		t.Fatalf("same public IP: %v", err)
	}
	if after, _ := os.ReadFile(base); string(after) != string(before) {
		t.Fatal("a refused change touched the file")
	}
	n, err := AddNetwork(base, []byte("lab passphrase"), baseline.Network{Name: "escritório", PublicIPv4: "198.51.100.20", Resolvers: []string{"198.51.100.53"}}, 10)
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	enc, _ := os.ReadFile(base)
	b, err := baseline.Decrypt(enc, []byte("lab passphrase"))
	if err != nil || len(b.Networks) != 2 || b.Networks[1].Resolvers[0] != "198.51.100.53" {
		t.Fatalf("%v %+v", err, b)
	}
	if _, err := os.Stat(base + ".tmp"); err == nil {
		t.Fatal("temporary file left behind")
	}
}
