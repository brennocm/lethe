package privsep

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Seccomp (spec §19.3) in one filter with both phases:
//   - phase 1, a denylist of syscalls the daemon never makes and that serve to escalate or to
//     leave its confinement, answered with EPERM;
//   - phase 2, an allowlist (allow.go) of what the daemon does make; anything else kills the
//     process (SECCOMP_RET_KILL_PROCESS), or with LETHE_SECCOMP=log is only logged by the kernel
//     (SECCOMP_RET_LOG), which is how the list was surveyed on the e2e suite (ADR 0014).
// A killed daemon leaves its tables in place: the network stays closed, and `lethe status`
// names `sudo lethe cleanup` (§18 lockdown), so the failure is never silent nor open.

// Mode is what the filter does with a syscall outside the allowlist.
type Mode int

// The modes. Enforce is the default and what every unknown LETHE_SECCOMP value means.
const (
	ModeEnforce Mode = iota
	ModeLog
)

// SeccompMode reads LETHE_SECCOMP ("log" for the survey; anything else enforces).
func SeccompMode(env string) Mode {
	if env == "log" {
		return ModeLog
	}
	return ModeEnforce
}

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
	maxInsns    = 4096       // BPF_MAXINSNS
)

// SeccompProgram is the filter for this architecture (nil where unsupported).
func SeccompProgram(mode Mode) ([]bpf.RawInstruction, error) {
	if auditArch == 0 {
		return nil, nil
	}
	eperm := unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	other := uint32(unix.SECCOMP_RET_KILL_PROCESS)
	if mode == ModeLog {
		other = unix.SECCOMP_RET_LOG
	}
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
	// Each entry is a compare and a return, so no jump is longer than one instruction.
	for _, nr := range append(append([]uintptr{}, denied...), deniedArch...) {
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(nr), SkipFalse: 1}, bpf.RetConstant{Val: eperm}) // #nosec G115 -- syscall numbers
	}
	for _, nr := range append(append([]uintptr{}, allowed...), allowedArch...) {
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(nr), SkipFalse: 1}, bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW}) // #nosec G115 -- syscall numbers
	}
	prog = append(prog, bpf.RetConstant{Val: other})
	if len(prog) > maxInsns {
		return nil, errors.New("privsep: seccomp program too long")
	}
	return bpf.Assemble(prog)
}

// applySeccomp installs the filter on every thread (TSYNC). no_new_privs must be set.
// SECCOMP_FILTER_FLAG_LOG makes the kernel log the denials and kills too, not only RET_LOG.
func applySeccomp() error {
	raw, err := SeccompProgram(SeccompMode(os.Getenv("LETHE_SECCOMP")))
	if err != nil || raw == nil {
		return err
	}
	filter := make([]unix.SockFilter, len(raw))
	for i, r := range raw {
		filter[i] = unix.SockFilter{Code: r.Op, Jt: r.Jt, Jf: r.Jf, K: r.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]} // #nosec G115 -- < 300
	r, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC|unix.SECCOMP_FILTER_FLAG_LOG,
		uintptr(unsafe.Pointer(&fprog))) // #nosec G103 -- the kernel ABI takes a pointer
	switch {
	case errno != 0:
		return fmt.Errorf("privsep: seccomp: %w", errno)
	case r != 0:
		return fmt.Errorf("privsep: seccomp: thread %d could not be synchronized", r)
	}
	return nil
}
