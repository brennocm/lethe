//go:build e2e

package e2e

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lethe/internal/privsep"
	"lethe/test/netlab"

	"golang.org/x/sys/unix"
)

// TestE2E_M7_HardenCaps checks, in a child process, that Harden leaves exactly the §19.3
// capabilities on every thread, with no_new_privs, and that the child can still use them.
func TestE2E_M7_HardenCaps(t *testing.T) {
	if os.Getenv("LETHE_HARDEN_CHILD") == "1" {
		done := make(chan struct{})
		for range 8 { // extra OS threads that must be covered too
			go func() { <-done }()
		}
		if err := privsep.Harden(); err != nil {
			fmt.Println("HARDEN:", err)
			os.Exit(3)
		}
		close(done)
		tasks, _ := filepath.Glob("/proc/self/task/*/status")
		for _, p := range tasks {
			st, err := privsep.ReadStatus(p)
			if err != nil {
				continue // thread exited
			}
			if st.Eff != privsep.KeepMask() || st.Prm != privsep.KeepMask() || st.Bnd != privsep.KeepMask() || st.Inh != 0 || st.Amb != 0 || !st.NoNewPrivs {
				fmt.Printf("BAD %s %+v\n", p, st)
				os.Exit(4)
			}
		}
		// seccomp phase 1 is on every thread: mode 2 (filter), and a denied syscall gets EPERM
		// while the daemon's own calls still work
		for _, p := range tasks {
			if raw, err := os.ReadFile(p); err == nil && !strings.Contains(string(raw), "Seccomp:\t2") {
				fmt.Printf("NO SECCOMP %s\n", p)
				os.Exit(5)
			}
		}
		if err := unix.Unshare(0); !errors.Is(err, unix.EPERM) {
			fmt.Printf("UNSHARE %v\n", err)
			os.Exit(6)
		}
		if fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE); err != nil {
			fmt.Printf("SOCKET %v\n", err)
			os.Exit(7)
		} else {
			_ = unix.Close(fd)
		}
		fmt.Println("HARDENED")
		os.Exit(0)
	}
	if err := netlab.AssertNotHostNamespace(); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	cmd, err := privsep.Spawn([]string{"-test.run=^TestE2E_M7_HardenCaps$", "-test.count=1"},
		privsep.SpawnOptions{Env: append(os.Environ(), "LETHE_HARDEN_CHILD=1"), Stdout: &out, Stderr: &out})
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- cmd.Wait() }()
	select {
	case err := <-errc:
		if err != nil || !strings.Contains(out.String(), "HARDENED") {
			t.Fatalf("child: %v (exit %d): %s", err, cmd.ProcessState.ExitCode(), out.String())
		}
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child hung")
	}
}
