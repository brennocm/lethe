package privsep

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_AARCH64
	x32       = false
)

var deniedArch []uintptr

// allowedArch: arm64 has only the *at forms, all in the common list.
var allowedArch = []uintptr{unix.SYS_SIGNALFD4}
