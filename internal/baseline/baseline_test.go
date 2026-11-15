package baseline

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

const testWF = 10 // fast scrypt for tests

func sample(t *testing.T) *Baseline {
	t.Helper()
	b, err := New(time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC), "test")
	if err != nil {
		t.Fatal(err)
	}
	b.Hostname, b.Username = "SENTINEL-HOST", "sentineluser"
	b.PermMACs = []string{"02:00:5e:10:20:30"}
	if err := b.AddNetwork(Network{Name: "casa", PublicIPv4: "198.51.100.77", ASN: 64500, Provider: "SentinelNet",
		Resolvers: []string{"198.51.100.53"}, GatewayIP: "192.168.1.1", GatewayMAC: "02:00:5e:aa:bb:cc", SSIDs: []string{"SentinelWiFi"}}); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	b := sample(t)
	enc, err := Encrypt(b, []byte("correct horse"), testWF)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range b.Values() {
		if strings.Contains(string(enc), v) {
			t.Fatalf("value %q visible in ciphertext", v)
		}
	}
	got, err := Decrypt(enc, []byte("correct horse"))
	if err != nil || got.Networks[0].Provider != "SentinelNet" || got.LogIdentity != b.LogIdentity {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := Decrypt(enc, []byte("wrong horse!")); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatal(err)
	}
	if _, err := Encrypt(b, []byte("short"), testWF); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

func TestRecovery(t *testing.T) {
	b := sample(t)
	inst, _ := age.GenerateX25519Identity()
	enc, err := EncryptRecovery(b, []age.Recipient{inst.Recipient()})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecryptWith(enc, inst); err != nil || got.Hostname != b.Hostname {
		t.Fatal(err)
	}
	if _, err := EncryptRecovery(b, nil); err == nil {
		t.Fatal("no recipients accepted")
	}
}

func TestValidate_Rejects(t *testing.T) {
	cases := map[string]Network{
		"no name":  {PublicIPv4: "198.51.100.1"},
		"v6 as v4": {Name: "x", PublicIPv4: "2001:db8::1"},
		"v4 as v6": {Name: "x", PublicIPv6: "198.51.100.1"},
		"resolver": {Name: "x", Resolvers: []string{"dns.example"}},
		"gateway":  {Name: "x", GatewayIP: "router"},
		"bad mac":  {Name: "x", GatewayMAC: "zz"},
	}
	for name, n := range cases {
		t.Run(name, func(t *testing.T) {
			b := sample(t)
			if err := b.AddNetwork(n); err == nil {
				t.Fatal("accepted")
			}
			if len(b.Networks) != 1 {
				t.Fatal("rejected network was kept")
			}
		})
	}
	b := sample(t)
	if err := b.AddNetwork(Network{Name: "casa"}); err == nil {
		t.Fatal("duplicate network name accepted")
	}
	b.PermMACs = append(b.PermMACs, "nope")
	b.Version = 2
	b.LogIdentity = "x"
	if err := b.Validate(); err == nil || strings.Count(err.Error(), "\n") < 2 {
		t.Fatalf("want 3 errors, got %v", err)
	}
}

func TestRedact(t *testing.T) {
	b := sample(t)
	msg := "route via 192.168.1.1 on SentinelWiFi for SENTINEL-HOST"
	if got := b.Redact(msg); strings.Contains(got, "SentinelWiFi") || strings.Contains(got, "192.168.1.1") || strings.Contains(got, "SENTINEL-HOST") {
		t.Fatal(got)
	}
	for _, v := range b.Values() {
		if strings.HasPrefix(v, "AGE-SECRET") {
			t.Fatal("log identity listed as a value")
		}
	}
}

func TestCollectLocal(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "etc/hostname"), []byte("box\n"), 0o600)
	_ = os.Symlink("/usr/share/zoneinfo/America/Sao_Paulo", filepath.Join(root, "etc/localtime"))
	env := map[string]string{"SUDO_USER": "op", "LANG": "pt_BR.UTF-8"}
	l := CollectLocal(root, func(k string) string { return env[k] })
	if l != (Local{Hostname: "box", Username: "op", Timezone: "America/Sao_Paulo", Locale: "pt_BR.UTF-8"}) {
		t.Fatalf("%+v", l)
	}
	b := sample(t)
	l.Apply(b)
	if b.Hostname != "box" {
		t.Fatal("apply")
	}
	_ = os.Remove(filepath.Join(root, "etc/localtime"))
	_ = os.WriteFile(filepath.Join(root, "etc/timezone"), []byte("UTC\n"), 0o600)
	if l := CollectLocal(root, func(string) string { return "" }); l.Timezone != "UTC" || l.Username == "" {
		t.Fatalf("%+v", l)
	}
}

func TestDecrypt_RejectsGarbage(t *testing.T) {
	inst, _ := age.GenerateX25519Identity()
	if _, err := DecryptWith([]byte("not age"), inst); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatal(err)
	}
}
