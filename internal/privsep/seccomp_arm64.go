package privsep

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_AARCH64
	x32       = false
)

var deniedArch []uintptr
