package hostinfo

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
)

// ZoneCountries reads which countries use each timezone, from the system tz database
// (zone1970.tab, else zone.tab). PER-001 compares them with the exit country. Missing files
// give an empty map: the timezone part is then not compared.
func ZoneCountries(root string) map[string][]string {
	out := map[string][]string{}
	for _, name := range []string{"zone1970.tab", "zone.tab"} {
		raw := readNoFollow(filepath.Join(root, "usr/share/zoneinfo", name), 1<<20)
		if len(raw) == 0 {
			continue
		}
		sc := bufio.NewScanner(bytes.NewReader(raw))
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "#") {
				continue
			}
			f := strings.Split(line, "\t")
			if len(f) < 3 {
				continue
			}
			out[f[2]] = strings.Split(f[0], ",")
		}
		if len(out) > 0 {
			out["UTC"], out["Etc/UTC"] = nil, nil // no country: not compared
			return out
		}
	}
	return out
}
