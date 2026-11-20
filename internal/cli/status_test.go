package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"lethe/internal/contracts"
)

func withNoDaemon(t *testing.T, root bool, tables []string) {
	t.Helper()
	t.Setenv("LETHE_SOCKET", filepath.Join(t.TempDir(), "none.sock"))
	oldRoot, oldTables := isRoot, leftoverTables
	isRoot = func() bool { return root }
	leftoverTables = func() ([]string, error) { return tables, nil }
	t.Cleanup(func() { isRoot, leftoverTables = oldRoot, oldTables })
}

// status without a daemon finds leftover tables and names the way out (spec §10.6 item 6).
func TestAC18_StatusWithoutDaemonPointsToCleanup(t *testing.T) {
	withNoDaemon(t, true, []string{"inet lethe", "netdev lethe_l2"})
	code, out, _ := run("status")
	if code != ExitDaemonDown || !strings.Contains(out, "BLOCKED") || !strings.Contains(out, "sudo lethe cleanup") {
		t.Fatalf("%d %q", code, out)
	}
	code, out, _ = run("status", "--json")
	if code != ExitDaemonDown || contracts.ValidateJSON("status", []byte(out)) != nil || !strings.Contains(out, `"lockdown"`) {
		t.Fatalf("%d %s", code, out)
	}
}

func TestM81_StatusWithoutDaemonNothingLeft(t *testing.T) {
	withNoDaemon(t, true, nil)
	if code, out, _ := run("status"); code != ExitDaemonDown || !strings.Contains(out, "is not blocking") {
		t.Fatalf("%d %q", code, out)
	}
}

func TestM81_StatusWithoutDaemonNotRoot(t *testing.T) {
	withNoDaemon(t, false, []string{"inet lethe"})
	code, out, _ := run("status")
	if code != ExitDaemonDown || !strings.Contains(out, "sudo lethe status") || strings.Contains(out, "BLOCKED") {
		t.Fatalf("%d %q", code, out)
	}
}
