package privsep

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Seccomp phase 1 (spec §19.3): a denylist of syscalls the daemon never makes and that serve to
// escalate or to leave its confinement. They fail with EPERM. Nothing kills the process, so a
// syscall missed by this list can never take a session down; the allowlist with
// SECCOMP_RET_KILL_PROCESS is phase 2 (M14), after the e2e suite has recorded what is used.

// denied is common to the supported architectures; deniedArch adds the per-architecture ones.
var denied = []uintptr{
	unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT, // CAP_DAC_READ_SEARCH escape ("shocker")
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_REBOOT,
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_CHROOT,
	unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT, unix.SYS_FSPICK, unix.SYS_MOVE_MOUNT,
	unix.SYS_OPEN_TREE, unix.SYS_MOUNT_SETATTR,
	unix.SYS_SETNS, unix.SYS_UNSHARE,
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN, unix.SYS_USERFAULTFD,
	unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
	unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER, // bypass seccomp per op
	unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_ACCT, unix.SYS_QUOTACTL, unix.SYS_VHANGUP, unix.SYS_SYSLOG,
	unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_CLOCK_ADJTIME, unix.SYS_ADJTIMEX,
}

// Offsets in struct seccomp_data.
const (
	seccompNR   = 0
	seccompArch = 4
	x32Bit      = 0x40000000 // __X32_SYSCALL_BIT
)

// SeccompProgram is the phase-1 filter for this architecture (nil where unsupported).
func SeccompProgram() ([]bpf.RawInstruction, error) {
	if auditArch == 0 {
		return nil, nil
	}
	list := append(append([]uintptr{}, denied...), deniedArch...)
	eperm := unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: seccompArch, Size: 4},
		// A foreign ABI (i386 int 0x80 on amd64) has other syscall numbers: refuse it whole.
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: auditArch, SkipTrue: 1},
		bpf.RetConstant{Val: eperm},
		bpf.LoadAbsolute{Off: seccompNR, Size: 4},
	}
	if x32 {
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: x32Bit, SkipFalse: 1}, bpf.RetConstant{Val: eperm})
	}
	for i, nr := range list {
		// on a match, skip to the EPERM after the list
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(nr), SkipTrue: uint8(len(list) - i)}) // #nosec G115 -- small list
	}
	prog = append(prog, bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}, bpf.RetConstant{Val: eperm})
	if len(list) > 250 {
		return nil, errors.New("privsep: seccomp list too long for 8-bit jumps")
	}
	return bpf.Assemble(prog)
}

// applySeccomp installs the phase-1 filter on every thread (TSYNC). no_new_privs must be set.
func applySeccomp() error {
	raw, err := SeccompProgram()
	if err != nil || raw == nil {
		return err
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filter[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]} // #nosec G115 -- < 300
	r, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&fprog))) // #nosec G103 -- the kernel ABI takes a pointer
	switch {
	case errno != 0:
		return fmt.Errorf("privsep: seccomp: %w", errno)
	case r != 0:
		return fmt.Errorf("privsep: seccomp: thread %d could not be synchronized", r)
	}
	return nil
}
