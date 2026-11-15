package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"runtime"
	"testing"
	"time"

	"lethe/internal/contracts"
)

func TestVersionJSON_MatchesContract(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Execute([]string{"version", "--json"}, &out, &errb); code != ExitOK {
		t.Fatalf("exit %d, stderr %s", code, errb.String())
	}
	if err := contracts.ValidateJSON("version", out.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownCommand_ExitsGeneric(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Execute([]string{"nope"}, &out, &errb); code != ExitGeneric {
		t.Fatalf("exit %d", code)
	}
}

func TestExitCode_Wrapped(t *testing.T) {
	err := WithCode(ExitIntegrity, errors.New("bad chain"))
	if exitCode(err) != ExitIntegrity || exitCode(nil) != ExitOK || WithCode(3, nil) != nil {
		t.Fatal("exit code mapping broken")
	}
}

func TestDiscover_RunsUnprivilegedAndMatchesContract(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Execute([]string{"discover", "--json"}, &out, &errb); code != ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if err := contracts.ValidateJSON("discover", out.Bytes()); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if code := Execute([]string{"discover"}, &out, &errb); code != ExitOK || !bytes.Contains(out.Bytes(), []byte("INTERFACE")) {
		t.Fatalf("human output: %s", out.String())
	}
	if code := Execute([]string{"discover", "--learn"}, &out, &errb); code == ExitOK {
		t.Fatal("--learn should not be available yet")
	}
}

func TestPassphraseFDIsBorrowedNotOwned(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	_, _ = w.Write([]byte("pw-one\n"))
	_ = w.Close()
	p := &passphraseSource{fd: int(r.Fd()), stderr: io.Discard}
	pw, err := p.read("", false)
	if err != nil || string(pw) != "pw-one" {
		t.Fatalf("pw=%q err=%v", pw, err)
	}
	p.reader = nil
	runtime.GC()
	runtime.GC()
	time.Sleep(20 * time.Millisecond) // finalizers run asynchronously
	// the caller's descriptor must still be open after the reader is garbage collected
	if _, err := r.Stat(); err != nil {
		t.Fatalf("passphrase fd was closed behind the caller's back: %v", err)
	}
}
