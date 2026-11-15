// Command trace-matrix enforces spec §23.3: every check ID implemented under internal/checks
// must have at least one test whose name starts with Test<ID without dash> (e.g. TestNET001_...).
// IDs listed in spec.md but not yet implemented are reported, not failed.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var idRe = regexp.MustCompile(`\b(NET|DNS|TUN|HOST|PER|SELF)-(\d{3})\b`)

func main() {
	spec, err := os.ReadFile("spec.md")
	if err != nil {
		fail("read spec.md: %v", err)
	}
	specIDs := uniq(idRe.FindAllString(string(spec), -1))

	implemented := map[string]bool{}
	tested := map[string]bool{}
	err = filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "docs") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G304 G122 -- dev tool walking our own repo
		if err != nil {
			return err
		}
		src := string(raw)
		if strings.HasSuffix(path, "_test.go") {
			for _, id := range specIDs {
				if strings.Contains(src, "func Test"+strings.ReplaceAll(id, "-", "")) {
					tested[id] = true
				}
			}
			return nil
		}
		if strings.Contains(filepath.ToSlash(path), "internal/checks/") {
			for _, m := range regexp.MustCompile(`ID\(\) string\s*\{\s*return "([A-Z]+-\d{3})"`).FindAllStringSubmatch(src, -1) {
				implemented[m[1]] = true
			}
		}
		return nil
	})
	if err != nil {
		fail("walk: %v", err)
	}

	var missing, pending []string
	for _, id := range specIDs {
		switch {
		case implemented[id] && !tested[id]:
			missing = append(missing, id)
		case !implemented[id]:
			pending = append(pending, id)
		}
	}
	fmt.Printf("trace-matrix: %d IDs in spec, %d implemented, %d pending\n", len(specIDs), len(implemented), len(pending))
	if len(missing) > 0 {
		fail("implemented checks without Test<ID> tests: %s", strings.Join(missing, ", "))
	}
}

func uniq(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		set[s] = true
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "trace-matrix: "+format+"\n", a...)
	os.Exit(1)
}
