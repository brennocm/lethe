// Command third-party keeps the module table of docs/THIRD_PARTY.md equal to what the release
// binaries link, read from their CycloneDX SBOMs (cyclonedx-gomod app -licenses):
//
//	go run ./scripts/third-party [-write] SBOM.json...
//
// Without -write it fails when the table is out of date.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
)

const (
	doc   = "docs/THIRD_PARTY.md"
	start = "<!-- modules:start -->"
	end   = "<!-- modules:end -->"
)

// reviewed corrects what the SBOM's license detector gets wrong, after reading the module's own
// license file. Each entry says where the answer came from.
var reviewed = map[string]string{
	// License, first line: "SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0-only" (the
	// detector reports only the GPL text). lethe takes the BSD-3-Clause option.
	"kernel.org/pub/linux/libs/security/libcap/cap": "BSD-3-Clause OR GPL-2.0-only",
	"kernel.org/pub/linux/libs/security/libcap/psx": "BSD-3-Clause OR GPL-2.0-only",
	// LICENSE: "SPDX-License-Identifier: Unlicense OR BSD-3-Clause" (detected: Unlicense only)
	"github.com/go-text/render":      "Unlicense OR BSD-3-Clause",
	"github.com/go-text/typesetting": "Unlicense OR BSD-3-Clause",
	// LICENSE: the ISC text, with "provided that the above copyright notice ... appear" (0BSD lacks it)
	"github.com/nfnt/resize":                  "ISC",
	"github.com/oschwald/maxminddb-golang/v2": "ISC",
	// LICENSE: the Go BSD-3-Clause text ("Neither the name of Google LLC ...")
	"filippo.io/hpke": "BSD-3-Clause",
}

// reviewedPrefix: every golang.org/x module carries the Go LICENSE (BSD-3-Clause), which the
// detector reports as BSD-Source-Code.
var reviewedPrefix = map[string]string{"golang.org/x/": "BSD-3-Clause"}

type license struct {
	License struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
	Expression string `json:"expression"`
}

type component struct {
	Name     string    `json:"name"`
	Version  string    `json:"version"`
	Licenses []license `json:"licenses"`
	Evidence struct {
		Licenses []license `json:"licenses"`
	} `json:"evidence"`
}

type bom struct {
	Metadata struct {
		Component component `json:"component"`
	} `json:"metadata"`
	Components []component `json:"components"`
}

func ids(ls []license) []string {
	var out []string
	for _, l := range ls {
		switch {
		case l.Expression != "":
			out = append(out, l.Expression)
		case l.License.ID != "":
			out = append(out, l.License.ID)
		case l.License.Name != "":
			out = append(out, l.License.Name)
		}
	}
	return out
}

func main() {
	write := flag.Bool("write", false, "rewrite the table instead of checking it")
	flag.Parse()
	if flag.NArg() == 0 {
		fail("usage: third-party [-write] SBOM.json...")
	}
	type row struct {
		license      string
		versions, in map[string]bool
	}
	rows := map[string]*row{}
	for _, p := range flag.Args() {
		raw, err := os.ReadFile(p) // #nosec G304 -- paths from the caller
		if err != nil {
			fail("%v", err)
		}
		var b bom
		if err := json.Unmarshal(raw, &b); err != nil {
			fail("%s: %v", p, err)
		}
		app := path.Base(b.Metadata.Component.Name) // lethe, lethe-gui
		for _, c := range b.Components {
			if c.Name == "lethe" || strings.HasPrefix(c.Name, "lethe/") {
				continue // this project's own modules
			}
			lic := strings.Join(append(ids(c.Licenses), ids(c.Evidence.Licenses)...), ", ")
			for pre, r := range reviewedPrefix {
				if strings.HasPrefix(c.Name, pre) {
					lic = r
				}
			}
			if r, ok := reviewed[c.Name]; ok {
				lic = r
			}
			if lic == "" {
				lic = "unknown — review before release"
			}
			r := rows[c.Name]
			if r == nil {
				r = &row{license: lic, versions: map[string]bool{}, in: map[string]bool{}}
				rows[c.Name] = r
			}
			r.versions[c.Version] = true
			r.in[app] = true
		}
	}
	names := make([]string, 0, len(rows))
	for n := range rows {
		names = append(names, n)
	}
	sort.Strings(names)
	var t bytes.Buffer
	t.WriteString(start + "\n| Module | Version | License | Linked into |\n|---|---|---|---|\n")
	for _, n := range names {
		r := rows[n]
		fmt.Fprintf(&t, "| `%s` | %s | %s | %s |\n", n, keys(r.versions, " / "), r.license, keys(r.in, ", "))
	}
	t.WriteString(end)
	cur, err := os.ReadFile(doc)
	if err != nil {
		fail("%v", err)
	}
	i, j := bytes.Index(cur, []byte(start)), bytes.Index(cur, []byte(end))
	if i < 0 || j < i {
		fail("%s has no %s … %s block", doc, start, end)
	}
	next := append(append(append([]byte{}, cur[:i]...), t.Bytes()...), cur[j+len(end):]...)
	if *write {
		if err := os.WriteFile(doc, next, 0o600); err != nil { // #nosec G306 G703 -- the fixed docs/THIRD_PARTY.md
			fail("%v", err)
		}
		return
	}
	if !bytes.Equal(cur, next) {
		fail("%s is out of date with the SBOMs: run mise run third-party -- -write", doc)
	}
	fmt.Printf("third-party: %d modules, table up to date\n", len(names))
}

func keys(m map[string]bool, sep string) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, sep)
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "third-party: "+format+"\n", a...)
	os.Exit(1)
}
