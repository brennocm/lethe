package privsep

import "golang.org/x/sys/unix"

const (
	auditArch = unix.AUDIT_ARCH_X86_64
	x32       = true
)

var deniedArch = []uintptr{unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_MODIFY_LDT, unix.SYS_USELIB}

// allowedArch are the amd64-only syscalls of the phase-2 allowlist (legacy forms the Go runtime
// and the standard library still use there).
var allowedArch = []uintptr{
	unix.SYS_OPEN, unix.SYS_STAT, unix.SYS_LSTAT, unix.SYS_ACCESS, unix.SYS_PIPE, unix.SYS_POLL,
	unix.SYS_SELECT, unix.SYS_DUP2, unix.SYS_EPOLL_CREATE, unix.SYS_EPOLL_WAIT, unix.SYS_INOTIFY_INIT,
	unix.SYS_EVENTFD, unix.SYS_ARCH_PRCTL, unix.SYS_READLINK, unix.SYS_MKDIR, unix.SYS_RMDIR, unix.SYS_UNLINK,
	unix.SYS_RENAME, unix.SYS_LINK, unix.SYS_SYMLINK, unix.SYS_CHMOD, unix.SYS_CHOWN, unix.SYS_LCHOWN,
	unix.SYS_GETDENTS, unix.SYS_TIME, unix.SYS_ALARM, unix.SYS_GETPGRP, unix.SYS_ACCEPT, unix.SYS_FORK,
	unix.SYS_VFORK, unix.SYS_PAUSE, unix.SYS_SIGNALFD4, unix.SYS_FUTIMESAT, unix.SYS_UTIMES,
}
