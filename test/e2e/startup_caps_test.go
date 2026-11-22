//go:build e2e

package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lethe/internal/ipc"
	"lethe/internal/platform"
	"lethe/internal/privsep"
	"lethe/test/netlab"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// TestE2E_M14_ServiceStartupCaps runs, in a child bounded to the units' start-up set
// (Keep + Startup, no CAP_FOWNER), what lethed@<user>.service does before the first arm: hand
// /run/lethe and the socket to the operator, twice (a restart finds the directory already
// handed over), and write a file the operator owns. Root without CAP_FOWNER may not chmod what
// it no longer owns, so every chmod has to come before the chown (ADR 0019).
func TestE2E_M14_ServiceStartupCaps(t *testing.T) {
	const op = 65534 // nobody
	if dir := os.Getenv("LETHE_STARTUP_CHILD"); dir != "" {
		vals := append(append([]cap.Value{}, privsep.Keep...), privsep.Startup...)
		c := cap.NewSet()
		err := c.SetFlag(cap.Permitted, true, vals...)
		if err == nil {
			err = c.SetFlag(cap.Effective, true, vals...)
		}
		if err == nil {
			err = c.SetProc()
		}
		if err != nil {
			fmt.Println("CAPS:", err)
			os.Exit(3)
		}
		sock := filepath.Join(dir, "run", "lethe", "lethe.sock")
		for i := range 2 {
			l, err := ipc.Listen(sock, op, op)
			if err != nil {
				fmt.Printf("LISTEN %d: %v\n", i, err)
				os.Exit(4)
			}
			_ = l.Close()
		}
		d, err := os.Open(dir)
		if err != nil {
			fmt.Println("OPEN:", err)
			os.Exit(5)
		}
		if err := platform.WriteFileAt(d, "owned", []byte("x"), 0o640, op, op); err != nil {
			fmt.Println("WRITE:", err)
			os.Exit(6)
		}
		fmt.Println("STARTED")
		os.Exit(0)
	}
	if err := netlab.AssertNotHostNamespace(); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile("/proc/self/uid_map"); err != nil || !strings.Contains(string(raw), "4294967295") { // the initial namespace maps every uid
		t.Skip("SKIP: user namespace maps only root; the operator's uid cannot own files here (run the e2e with sudo)")
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd, err := privsep.Spawn([]string{"-test.run=^TestE2E_M14_ServiceStartupCaps$", "-test.count=1"},
		privsep.SpawnOptions{Env: append(os.Environ(), "LETHE_STARTUP_CHILD="+dir), Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- cmd.Wait() }()
	select {
	case err := <-errc:
		if err != nil || !strings.Contains(out.String(), "STARTED") {
			t.Fatalf("child: %v (exit %d): %s", err, cmd.ProcessState.ExitCode(), out.String())
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child hung")
	}
	st, err := os.Stat(filepath.Join(dir, "run", "lethe"))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("/run/lethe: %v %v", st, err)
	}
}
