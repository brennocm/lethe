package buildinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRead_HashesGivenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(p, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if info.BinarySHA != want {
		t.Fatalf("sha = %s, want %s", info.BinarySHA, want)
	}
	if info.Version == "" || info.Platform == "" {
		t.Fatalf("missing fields: %+v", info)
	}
}

func TestRead_MissingFile(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
