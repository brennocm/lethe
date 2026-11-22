// Package buildinfo reports the version, commit and binary hash of the running executable.
package buildinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
)

// Version is overridden at release time with -ldflags "-X lethe/internal/buildinfo.Version=v1.2.3".
var Version = "dev"

// GeoDBDate is the build date of the embedded offline geo database ("none" without one; the
// version command fills it from internal/geo).
var GeoDBDate = "none"

// Info describes the running binary. Its JSON form is validated by the "version" schema.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Modified  bool   `json:"modified"`
	GoVersion string `json:"go_version"`
	Platform  string `json:"platform"`
	BinarySHA string `json:"binary_sha256"`
	GeoDBDate string `json:"geo_db_date"`
}

// Commit is the VCS revision this binary was built from, or "" when the build carries none
// (go test, a build outside the repository). The panel compares it with the daemon's.
func Commit() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				return s.Value
			}
		}
	}
	return ""
}

// Read collects build information. exePath is the binary to hash; pass "" for /proc/self/exe.
func Read(exePath string) (Info, error) {
	info := Info{
		Version:   Version,
		Commit:    "unknown",
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		GeoDBDate: GeoDBDate,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				info.Commit = s.Value
			case "vcs.modified":
				info.Modified = s.Value == "true"
			}
		}
	}
	if exePath == "" {
		exePath = "/proc/self/exe"
	}
	sum, err := fileSHA256(exePath)
	if err != nil {
		return info, fmt.Errorf("hash binary %s: %w", exePath, err)
	}
	info.BinarySHA = sum
	return info, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path is our own executable
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
