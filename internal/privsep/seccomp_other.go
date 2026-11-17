//go:build !amd64 && !arm64

package privsep

// lethe ships for amd64 and arm64 (ADR 0002); elsewhere phase 1 is not installed.
const (
	auditArch = 0
	x32       = false
)

var deniedArch []uintptr

var allowed, allowedArch []uintptr
