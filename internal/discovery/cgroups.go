package discovery

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ExclusionCgroup is a cgroup that takes its processes out of the tunnel (TUN-005, spec §9.3).
type ExclusionCgroup struct {
	Path    string `json:"path"`    // relative to the cgroup mount
	Version int    `json:"version"` // 1 (net_cls) or 2
	ClassID uint32 `json:"classid,omitempty"`
	Procs   int    `json:"procs"` // processes currently in it
}

// ExclusionSource is implemented by kernels that can list exclusion cgroups.
type ExclusionSource interface {
	ExclusionCgroups() ([]ExclusionCgroup, error)
}

// exclusionName matches the cgroups commercial clients create for split tunneling
// (mullvad-exclusions, ivpn-exclude, piavpnexclude...).
var exclusionName = regexp.MustCompile(`(?i)(vpn|mullvad|proton|nord|express).*exclu|exclu.*(vpn|tunnel)`)

const (
	netClsMaxDepth = 3
	v2MaxDepth     = 2 // top level and one below: client cgroups are not nested in user slices
	maxCgroupDirs  = 4096
)

// ExclusionCgroups lists populated exclusion cgroups. On cgroup v1 (net_cls) any cgroup with a
// non-zero classid marks traffic for policy routing, which is what split tunneling uses; on v2
// the clients' cgroups are recognized by name. Empty ones (no process inside) are left out.
func (k NetlinkKernel) ExclusionCgroups() ([]ExclusionCgroup, error) {
	var out []ExclusionCgroup
	for _, mount := range []string{"sys/fs/cgroup/net_cls", "sys/fs/cgroup/net_cls,net_prio"} {
		root := k.path(mount)
		walkCgroups(root, netClsMaxDepth, func(dir string) {
			raw, err := os.ReadFile(filepath.Join(dir, "net_cls.classid")) // #nosec G304 -- cgroupfs path
			if err != nil {
				return
			}
			id, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
			if err != nil || id == 0 {
				return
			}
			if n := countProcs(dir); n > 0 {
				out = append(out, ExclusionCgroup{Path: rel(root, dir), Version: 1, ClassID: uint32(id), Procs: n})
			}
		})
	}
	// v2 is at /sys/fs/cgroup (unified) or /sys/fs/cgroup/unified (hybrid). Every v2 cgroup has a
	// cgroup.controllers file and v1 ones do not, which keeps the walk out of v1 hierarchies.
	for _, mount := range []string{"sys/fs/cgroup", "sys/fs/cgroup/unified"} {
		root := k.path(mount)
		if !isV2(root) {
			continue
		}
		walkCgroups(root, v2MaxDepth, func(dir string) {
			if dir == root || !isV2(dir) || !exclusionName.MatchString(filepath.Base(dir)) {
				return
			}
			if n := countProcs(dir); n > 0 {
				out = append(out, ExclusionCgroup{Path: rel(root, dir), Version: 2, Procs: n})
			}
		})
	}
	return out, nil
}

func isV2(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "cgroup.controllers"))
	return err == nil
}

func walkCgroups(root string, depth int, visit func(dir string)) {
	seen := 0
	var walk func(dir string, d int)
	walk = func(dir string, d int) {
		if seen >= maxCgroupDirs {
			return
		}
		seen++
		visit(dir)
		if d == depth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.IsDir() { // DirEntry does not follow symlinks
				walk(filepath.Join(dir, e.Name()), d+1)
			}
		}
	}
	if fi, err := os.Lstat(root); err == nil && fi.IsDir() {
		walk(root, 0)
	}
}

func countProcs(dir string) int {
	raw, err := os.ReadFile(filepath.Join(dir, "cgroup.procs")) // #nosec G304 -- cgroupfs path
	if err != nil {
		return 0
	}
	return len(strings.Fields(string(raw)))
}

func rel(root, dir string) string {
	r, err := filepath.Rel(root, dir)
	if err != nil {
		return filepath.Base(dir)
	}
	return r
}
