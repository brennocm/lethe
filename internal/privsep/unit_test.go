package privsep

import (
	"bufio"
	"os"
	"slices"
	"strings"
	"testing"
)

// unitDirectives reads the [Service] keys of a systemd unit (last assignment wins).
func unitDirectives(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- repository file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case l == "" || strings.HasPrefix(l, "#"):
		case strings.HasPrefix(l, "["):
			section = l
		case section == "[Service]":
			k, v, _ := strings.Cut(l, "=")
			out[k] = v
		}
	}
	return out
}

// TestM14_ServiceUnitMatchesSpec: lethed.service carries every directive of spec §19.3, and its
// bounding set is exactly the capabilities Harden keeps.
func TestM14_ServiceUnitMatchesSpec(t *testing.T) {
	d := unitDirectives(t, "../../packaging/systemd/lethed.service")
	want := map[string]string{
		"AmbientCapabilities": "", "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "read-only",
		"PrivateTmp": "yes", "MemoryDenyWriteExecute": "yes", "LockPersonality": "yes", "RestrictNamespaces": "yes",
		"RestrictAddressFamilies": "AF_UNIX AF_NETLINK AF_PACKET AF_INET AF_INET6", "ExecStart": "/usr/bin/lethe daemon",
		"RuntimeDirectory": "lethe lethe-state",
	}
	for k, v := range want {
		if got, ok := d[k]; !ok || got != v {
			t.Errorf("%s=%q, want %q", k, got, v)
		}
	}
	var keep []string
	for _, v := range Keep {
		keep = append(keep, strings.ToUpper(v.String()))
	}
	got := strings.Fields(d["CapabilityBoundingSet"])
	slices.Sort(keep)
	slices.Sort(got)
	if !slices.Equal(keep, got) {
		t.Errorf("CapabilityBoundingSet %v, Harden keeps %v", got, keep)
	}
	if _, ok := d["ReadWritePaths"]; ok {
		t.Error("ReadWritePaths belongs to the operator's drop-in (storage.dir), not to the packaged unit")
	}
	// the per-operator template is the same unit with the drop-in written by systemd's instance
	tpl := unitDirectives(t, "../../packaging/systemd/lethed@.service")
	for k, v := range d {
		if tpl[k] != v {
			t.Errorf("lethed@.service %s=%q, lethed.service has %q", k, tpl[k], v)
		}
	}
	if tpl["Environment"] != "LETHE_OPERATOR=%i" || tpl["ReadWritePaths"] != "-/home/%i/lethe" || len(tpl) != len(d)+2 {
		t.Errorf("lethed@.service adds only the operator and its default storage: %v", tpl)
	}
	a := unitDirectives(t, "../../packaging/systemd/lethe-agent.service")
	if a["ExecStart"] != "/usr/bin/lethe agent --socket /run/lethe/lethe.sock" || a["Environment"] == "" {
		t.Errorf("agent unit: %v", a)
	}
}
