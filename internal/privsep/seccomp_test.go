//go:build amd64 || arm64

package privsep

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// seccompData builds struct seccomp_data for the cBPF VM, which loads big-endian (the kernel
// loads native-endian, so the values are written in the order the VM reads them).
func seccompData(nr, arch uint32) []byte {
	b := make([]byte, 64)
	binary.BigEndian.PutUint32(b[0:], nr)
	binary.BigEndian.PutUint32(b[4:], arch)
	return b
}

func TestSELF001_SeccompDenylist(t *testing.T) {
	raw, err := SeccompProgram()
	if err != nil {
		t.Fatal(err)
	}
	prog, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("disassemble")
	}
	vm, err := bpf.NewVM(prog)
	if err != nil {
		t.Fatal(err)
	}
	run := func(nr, arch uint32) uint32 {
		out, err := vm.Run(seccompData(nr, arch))
		if err != nil {
			t.Fatal(err)
		}
		return uint32(out) // #nosec G115 -- the VM returns the 32-bit action
	}
	eperm := unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	for _, nr := range []uintptr{unix.SYS_READ, unix.SYS_WRITE, unix.SYS_SOCKET, unix.SYS_SETSOCKOPT, unix.SYS_EXECVE,
		unix.SYS_CLONE, unix.SYS_KILL, unix.SYS_PIDFD_OPEN, unix.SYS_PRCTL, unix.SYS_SECCOMP, unix.SYS_MLOCK} {
		if got := run(uint32(nr), auditArch); got != unix.SECCOMP_RET_ALLOW {
			t.Errorf("syscall %d needed by the daemon is denied (%#x)", nr, got)
		}
	}
	for _, nr := range append(append([]uintptr{}, denied...), deniedArch...) {
		if got := run(uint32(nr), auditArch); got != eperm {
			t.Errorf("syscall %d allowed (%#x)", nr, got)
		}
	}
	if got := run(uint32(unix.SYS_READ), unix.AUDIT_ARCH_I386); got != eperm {
		t.Errorf("foreign ABI allowed (%#x)", got)
	}
	if x32 {
		if got := run(uint32(unix.SYS_READ)|x32Bit, auditArch); got != eperm {
			t.Errorf("x32 ABI allowed (%#x)", got)
		}
	}
}
