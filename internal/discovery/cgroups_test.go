package discovery

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, v := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTUN005_ExclusionCgroups(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		// v1 net_cls: a populated classid cgroup is an exclusion, whatever its name
		"sys/fs/cgroup/net_cls/net_cls.classid":                    "0\n",
		"sys/fs/cgroup/net_cls/cgroup.procs":                       "1\n2\n",
		"sys/fs/cgroup/net_cls/mullvad-exclusions/net_cls.classid": "5087041\n",
		"sys/fs/cgroup/net_cls/mullvad-exclusions/cgroup.procs":    "4242\n4243\n",
		"sys/fs/cgroup/net_cls/piavpnexclude/net_cls.classid":      "1883271\n",
		"sys/fs/cgroup/net_cls/piavpnexclude/cgroup.procs":         "", // empty: not reported
		"sys/fs/cgroup/net_cls/other/net_cls.classid":              "0\n",
		"sys/fs/cgroup/net_cls/other/cgroup.procs":                 "77\n",
		// v2: recognized by name, only near the top
		"sys/fs/cgroup/cgroup.controllers":                                   "cpu memory\n",
		"sys/fs/cgroup/mullvad-exclusions/cgroup.controllers":                "",
		"sys/fs/cgroup/system.slice/cgroup.controllers":                      "",
		"sys/fs/cgroup/system.slice/ivpn-exclude.service/cgroup.controllers": "",
		"sys/fs/cgroup/mullvad-exclusions/cgroup.procs":                      "4300\n",
		"sys/fs/cgroup/system.slice/cgroup.procs":                            "1\n",
		"sys/fs/cgroup/user.slice/a/b/ivpn-exclude/cgroup.procs":             "9\n", // too deep: ignored
		"sys/fs/cgroup/system.slice/ivpn-exclude.service/cgroup.procs":       "10\n",
	})
	got, err := NetlinkKernel{Root: root}.ExclusionCgroups()
	if err != nil {
		t.Fatal(err)
	}
	want := []ExclusionCgroup{
		{Path: "mullvad-exclusions", Version: 1, ClassID: 5087041, Procs: 2},
		{Path: "mullvad-exclusions", Version: 2, Procs: 1},
		{Path: "system.slice/ivpn-exclude.service", Version: 2, Procs: 1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestTUN005_NoCgroupMounts(t *testing.T) {
	got, err := NetlinkKernel{Root: t.TempDir()}.ExclusionCgroups()
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v %v", got, err)
	}
}
