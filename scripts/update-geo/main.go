// Command update-geo downloads the DB-IP Lite Country and ASN databases of one month, checks them
// against the SHA-256 pinned in pins.json and writes them to internal/geo/data, where the build
// embeds them. The owner runs it before a release (docs/runbooks/release.md); nothing in the test
// suite or the CI calls it, and lethe itself never downloads anything.
//
//	go run ./scripts/update-geo            # uses pins.json
//	go run ./scripts/update-geo -print     # downloads and prints the hashes to pin (review first)
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"lethe/internal/geo"
)

type pins struct {
	Month         string `json:"month"`
	CountrySHA256 string `json:"country_sha256"`
	ASNSHA256     string `json:"asn_sha256"`
}

const base = "https://download.db-ip.com/free/"

func main() {
	pinFile := flag.String("pins", "scripts/update-geo/pins.json", "pinned month and hashes")
	out := flag.String("out", "internal/geo/data", "output directory")
	printOnly := flag.Bool("print", false, "download and print the SHA-256 to pin, write nothing")
	month := flag.String("month", "", "YYYY-MM (with -print; default: pins.json)")
	flag.Parse()
	if err := run(*pinFile, *out, *month, *printOnly); err != nil {
		fmt.Fprintln(os.Stderr, "update-geo:", err)
		os.Exit(1)
	}
}

func run(pinFile, out, month string, printOnly bool) error {
	raw, err := os.ReadFile(pinFile) // #nosec G304 -- a repository file
	if err != nil {
		return err
	}
	var p pins
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("%s: %w", pinFile, err)
	}
	if month == "" {
		month = p.Month
	}
	if !regexp.MustCompile(`^20[0-9]{2}-(0[1-9]|1[0-2])$`).MatchString(month) {
		return fmt.Errorf("month %q: set it in %s (YYYY-MM) or pass -month", month, pinFile)
	}
	files := []struct{ kind, name, pin string }{
		{"country", geo.CountryFile, p.CountrySHA256},
		{"asn", geo.ASNFile, p.ASNSHA256},
	}
	got := map[string][]byte{}
	for _, f := range files {
		gz, sum, err := fetch(base + "dbip-" + f.kind + "-lite-" + month + ".mmdb.gz")
		if err != nil {
			return err
		}
		if printOnly {
			fmt.Printf("%s_sha256: %s\n", f.kind, sum)
			continue
		}
		if f.pin == "" || sum != f.pin {
			return fmt.Errorf("%s: SHA-256 %s does not match the pin %q; review the file and update %s", f.kind, sum, f.pin, pinFile)
		}
		zr, err := gzip.NewReader(bytes.NewReader(gz))
		if err != nil {
			return err
		}
		mm, err := io.ReadAll(io.LimitReader(zr, 1<<30))
		if err != nil {
			return err
		}
		got[f.name] = mm
	}
	if printOnly {
		return nil
	}
	if _, err := geo.Open(got[geo.CountryFile], got[geo.ASNFile]); err != nil {
		return fmt.Errorf("the downloaded databases do not open: %w", err)
	}
	for name, b := range got {
		if err := os.WriteFile(filepath.Join(out, name), b, 0o644); err != nil { // #nosec G306 -- public data
			return err
		}
	}
	fmt.Printf("geo data %s written to %s (DB-IP Lite, CC BY 4.0: keep the attribution in docs/THIRD_PARTY.md)\n", month, out)
	return nil
}

func fetch(url string) ([]byte, string, error) {
	c := &http.Client{Timeout: 5 * time.Minute}
	resp, err := c.Get(url) // #nosec G107 -- fixed host, pinned hash
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
	if err != nil {
		return nil, "", err
	}
	s := sha256.Sum256(b)
	return b, hex.EncodeToString(s[:]), nil
}
