package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"filippo.io/age"

	"lethe/internal/baseline"
)

const networkAnswers = "casa\n198.51.100.77\n\n64500\nSentinelNet\n198.51.100.53, 198.51.100.54\n192.168.1.1\n02:00:5e:aa:bb:cc\nSentinelWiFi\n"

var sentinels = []string{"198.51.100.77", "SentinelNet", "198.51.100.53", "02:00:5e:aa:bb:cc", "SentinelWiFi"}

// runIn runs the CLI with stdin and a passphrase pipe (one line per expected passphrase read).
func runIn(t *testing.T, stdin string, passphrases []string, args ...string) (int, string, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	go func() {
		for _, p := range passphrases {
			_, _ = w.WriteString(p + "\n")
		}
		_ = w.Close()
	}()
	args = append(args, "--passphrase-fd", strconv.Itoa(int(r.Fd())), "--scrypt-work-factor", "10")
	var out, errb bytes.Buffer
	root := newRoot(&out, &errb)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err = root.Execute()
	return exitCode(err), out.String(), errb.String() + errString(err)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestBaselineManual_CreateAddShow_NoValueLeaks(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "baseline.age")
	inst, _ := age.GenerateX25519Identity()
	code, out, errs := runIn(t, networkAnswers, []string{"correct horse"}, "baseline", "create", "--manual", "--out", file, "--recipient", inst.Recipient().String())
	if code != ExitOK {
		t.Fatalf("create: %d %s", code, errs)
	}
	code2, out2, errs2 := runIn(t, "escritorio\n203.0.113.9\n\n\nOfficeNet\n\n\n\n\n", []string{"correct horse"}, "baseline", "add-network", "--manual", file)
	if code2 != ExitOK {
		t.Fatalf("add-network: %d %s", code2, errs2)
	}
	for _, s := range sentinels {
		if strings.Contains(out+errs+out2+errs2, s) {
			t.Fatalf("baseline value %q leaked into create/add-network output", s)
		}
	}
	raw, _ := os.ReadFile(file)
	b, err := baseline.Decrypt(raw, []byte("correct horse"))
	if err != nil || len(b.Networks) != 2 || b.Networks[0].ASN != 64500 || len(b.Networks[0].Resolvers) != 2 {
		t.Fatalf("%+v %v", b, err)
	}
	rec, _ := os.ReadFile(file + ".recovery")
	if _, err := baseline.DecryptWith(rec, inst); err != nil {
		t.Fatalf("recovery copy: %v", err)
	}
	if st, _ := os.Stat(file); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}

	code, out, _ = runIn(t, "", []string{"correct horse"}, "baseline", "show", file)
	var shown baseline.Baseline
	if code != ExitOK || json.Unmarshal([]byte(out), &shown) != nil || shown.Networks[0].Provider != "SentinelNet" || shown.LogIdentity != "[oculta]" {
		t.Fatalf("show: %d %s", code, out)
	}
	if code, _, _ := runIn(t, "", []string{"wrong horse!"}, "baseline", "show", file); code != ExitAuth {
		t.Fatalf("wrong passphrase exit %d", code)
	}
	if code, _, _ := runIn(t, networkAnswers, []string{"correct horse"}, "baseline", "create", "--manual", "--out", file); code == ExitOK {
		t.Fatal("overwrote an existing baseline")
	}
}

func TestNET011_BaselineCreateOnline(t *testing.T) {
	prev := onlineNetwork
	t.Cleanup(func() { onlineNetwork = prev })
	onlineNetwork = func(context.Context, io.Writer, bool) (baseline.Network, error) {
		return baseline.Network{PublicIPv4: "198.51.100.77", ASN: 64501, Provider: "Provedor"}, nil
	}
	file := filepath.Join(t.TempDir(), "b.age")
	code, _, errs := runIn(t, "casa\n\n\n\n\n\n\n\n\n", []string{"correct horse", "correct horse"}, "baseline", "create", "--out", file)
	if code != ExitOK {
		t.Fatalf("%d %s", code, errs)
	}
	onlineNetwork = func(context.Context, io.Writer, bool) (baseline.Network, error) {
		return baseline.Network{}, ErrTunnelUp
	}
	if code, _, errs := runIn(t, "", nil, "baseline", "create", "--out", filepath.Join(t.TempDir(), "c.age")); code == ExitOK || !strings.Contains(errs, "tunnel") {
		t.Fatalf("%d %s", code, errs)
	}
}

func TestBaselineCreate_InvalidAnswers(t *testing.T) {
	bad := strings.Replace(networkAnswers, "64500", "AS64500", 1)
	code, _, errs := runIn(t, bad, []string{"correct horse"}, "baseline", "create", "--manual", "--out", filepath.Join(t.TempDir(), "b.age"))
	if code == ExitOK || !strings.Contains(errs, "ASN") {
		t.Fatalf("%d %s", code, errs)
	}
	if code, _, _ := runIn(t, networkAnswers, []string{"correct horse"}, "baseline", "create", "--manual", "--recipient", "age1bad", "--out", filepath.Join(t.TempDir(), "b.age")); code == ExitOK {
		t.Fatal("bad recipient accepted")
	}
}

func TestProfileInitValidate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "op.yaml")
	if code, _, errs := run("profile", "init", "--out", p); code != ExitOK {
		t.Fatal(errs)
	}
	if code, out, errs := run("profile", "validate", p); code != ExitOK || !strings.Contains(out, "OK") {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	if code, _, _ := run("profile", "init", "--out", p); code == ExitOK {
		t.Fatal("init overwrote a profile")
	}
	_ = os.WriteFile(p, []byte("version: 1\nbogus: true\n"), 0o600)
	if code, _, errs := run("profile", "validate", p); code != ExitGeneric || !strings.Contains(errs, "invalid profile") {
		t.Fatalf("%d %s", code, errs)
	}
	if code, out, _ := run("profile", "init"); code != ExitOK || !strings.Contains(out, "version: 1") {
		t.Fatal("init to stdout")
	}
}
