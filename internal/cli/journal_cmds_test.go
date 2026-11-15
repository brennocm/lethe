package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"lethe/internal/contracts"
	"lethe/internal/journal"
)

func writeSession(t *testing.T) (dir, idFile, fp string) {
	t.Helper()
	id, _ := age.GenerateX25519Identity()
	idFile = filepath.Join(t.TempDir(), "id.txt")
	if err := os.WriteFile(idFile, []byte(id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(t.TempDir(), "sess")
	now := time.Date(2026, 11, 15, 14, 0, 0, 0, time.UTC)
	w, err := journal.Open(journal.Config{Dir: dir, Session: "5f0c9e2a-7b1d-4c3e-9a8f-2d6b1e0c4a77", Recipients: []age.Recipient{id.Recipient()},
		Now: func() time.Time { return now }, Mono: func() int64 { return 1 }})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Append(contracts.Event{Type: contracts.EvStateChanged, Data: map[string]any{"color": "GREEN"}})
	fp = w.Fingerprint()
	if err := w.Close(nil); err != nil {
		t.Fatal(err)
	}
	return dir, idFile, fp
}

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Execute(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVerifyCmd_OKAndTampered(t *testing.T) {
	dir, idFile, fp := writeSession(t)
	code, out, errs := run("verify", dir, "--identity", idFile, "--expect-fingerprint", fp)
	if code != ExitOK || !strings.HasPrefix(out, "OK") {
		t.Fatalf("code %d out %q err %q", code, out, errs)
	}
	code, out, _ = run("verify", dir, "--identity", idFile, "--json")
	if code != ExitOK || contracts.ValidateJSON("verify", []byte(out)) != nil {
		t.Fatalf("json verify: %d %s", code, out)
	}
	seg := filepath.Join(dir, "segment-000001.lseg")
	raw, _ := os.ReadFile(seg)
	raw[len(raw)-100] ^= 0xff
	_ = os.WriteFile(seg, raw, 0o600)
	if code, _, _ := run("verify", dir, "--identity", idFile); code != ExitIntegrity {
		t.Fatalf("tampered session exit %d, want %d", code, ExitIntegrity)
	}
}

func TestVerifyCmd_WrongAnchorAndMissingIdentity(t *testing.T) {
	dir, idFile, _ := writeSession(t)
	if code, _, _ := run("verify", dir, "--identity", idFile, "--expect-fingerprint", "0000"); code != ExitIntegrity {
		t.Fatalf("wrong anchor exit %d", code)
	}
	if code, _, _ := run("verify", dir); code != ExitGeneric {
		t.Fatalf("missing identity exit %d", code)
	}
}

func TestReportCmd_Formats(t *testing.T) {
	dir, idFile, _ := writeSession(t)
	code, out, errs := run("report", dir, "--identity", idFile)
	if code != ExitOK || !strings.Contains(out, "# Relatório da sessão") {
		t.Fatalf("md: %d %s %s", code, out, errs)
	}
	code, out, _ = run("report", dir, "--identity", idFile, "--format", "json")
	if code != ExitOK || contracts.ValidateJSON("report", []byte(out)) != nil {
		t.Fatalf("json: %d %s", code, out)
	}
	if code, _, _ := run("report", dir, "--identity", idFile, "--format", "pdf"); code != ExitGeneric {
		t.Fatal("unknown format accepted")
	}
	if code, _, _ := run("report", dir, "--identity", idFile, "--include-sensitive", "--sensitive-identity", idFile); code != ExitOK {
		t.Fatalf("sensitive key defaults to the log recipients, exit %d", code)
	}
	other, _ := age.GenerateX25519Identity()
	otherFile := filepath.Join(t.TempDir(), "other.txt")
	_ = os.WriteFile(otherFile, []byte(other.String()+"\n"), 0o600)
	if code, _, _ := run("report", dir, "--identity", idFile, "--include-sensitive", "--sensitive-identity", otherFile); code != ExitAuth {
		t.Fatalf("wrong sensitive identity exit %d", code)
	}
}
