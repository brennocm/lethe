// Package privsep is the only place that starts processes (always /proc/self/exe) and the
// place that drops privileges (spec §19.3). Capabilities are per thread in Go, so every change
// goes through libcap/cap, which applies it to all threads (psx).
package privsep

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// Keep is the capability set the daemon runs with after start-up (spec §19.3).
var Keep = []cap.Value{cap.NET_RAW, cap.NET_ADMIN, cap.KILL, cap.SYS_PTRACE, cap.DAC_READ_SEARCH, cap.IPC_LOCK}

// Startup are the capabilities the daemon needs only until Harden (the first arm), on top of
// Keep: handing the socket and the operator's state and session directories to the operator
// (CAP_CHOWN), creating them inside storage.dir, which the operator owns with mode 0700
// (CAP_DAC_OVERRIDE), and keeping their setgid bit, which the kernel clears for a group root is
// not in (CAP_FSETID). Portable mode starts with every capability; the service units bound the
// daemon to Keep plus these, and Harden drops them (spec §19.3, ADR 0019).
var Startup = []cap.Value{cap.CHOWN, cap.DAC_OVERRIDE, cap.FSETID}

// KeepMask is Keep as the bit mask /proc/<pid>/status prints.
func KeepMask() uint64 {
	var m uint64
	for _, v := range Keep {
		m |= 1 << uint(v)
	}
	return m
}

// Harden reduces bounding, permitted, effective, inheritable and ambient sets to Keep, sets
// no_new_privs on every thread, makes the process non-dumpable and disables core dumps.
// It must run after everything that needs other capabilities (forking the agent, setuid).
func Harden() error {
	keep := map[cap.Value]bool{}
	for _, v := range Keep {
		keep[v] = true
	}
	var drop []cap.Value
	for v := cap.Value(0); v < cap.MaxBits(); v++ {
		if !keep[v] {
			drop = append(drop, v)
		}
	}
	// DropBound needs CAP_SETPCAP in the effective set, so it runs before SetProc.
	if err := cap.DropBound(drop...); err != nil {
		return fmt.Errorf("privsep: drop bounding set: %w", err)
	}
	if err := cap.ResetAmbient(); err != nil {
		return fmt.Errorf("privsep: reset ambient: %w", err)
	}
	s := cap.NewSet()
	if err := s.SetFlag(cap.Permitted, true, Keep...); err != nil {
		return err
	}
	if err := s.SetFlag(cap.Effective, true, Keep...); err != nil {
		return err
	}
	if err := s.SetProc(); err != nil {
		return fmt.Errorf("privsep: set capabilities: %w", err)
	}
	if _, err := cap.Prctlw(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("privsep: no_new_privs: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("privsep: dumpable: %w", err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return fmt.Errorf("privsep: rlimit core: %w", err)
	}
	return applySeccomp() // after no_new_privs, which the kernel requires without CAP_SYS_ADMIN
}

// Status is the security-relevant part of /proc/<pid>/status.
type Status struct {
	Inh, Prm, Eff, Bnd, Amb uint64
	NoNewPrivs              bool
}

// ReadStatus parses a status file (/proc/self/status or /proc/self/task/<tid>/status).
func ReadStatus(path string) (Status, error) {
	f, err := os.Open(path) // #nosec G304 -- procfs path chosen by the caller
	if err != nil {
		return Status{}, err
	}
	defer func() { _ = f.Close() }()
	var st Status
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		hex := func() uint64 { n, _ := strconv.ParseUint(v, 16, 64); return n }
		switch k {
		case "CapInh":
			st.Inh = hex()
		case "CapPrm":
			st.Prm = hex()
		case "CapEff":
			st.Eff = hex()
		case "CapBnd":
			st.Bnd = hex()
		case "CapAmb":
			st.Amb = hex()
		case "NoNewPrivs":
			st.NoNewPrivs = v == "1"
		}
	}
	return st, sc.Err()
}

// Credential is who a child runs as.
type Credential struct {
	UID, GID int
	Groups   []int
}

// SpawnOptions configure a child.
type SpawnOptions struct {
	Env            []string // exactly this environment
	Cred           *Credential
	Stdout, Stderr io.Writer
}

// Spawn re-executes this binary (/proc/self/exe, never anything else) with args and asks the
// kernel to SIGTERM it if the daemon dies.
func Spawn(args []string, o SpawnOptions) (*exec.Cmd, error) {
	cmd := exec.Command("/proc/self/exe", args...) // #nosec G204 -- fixed binary, args from the daemon
	cmd.Env = o.Env
	cmd.Stdout, cmd.Stderr = o.Stdout, o.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM, Setpgid: true}
	if cred := o.Cred; cred != nil {
		groups := make([]uint32, 0, len(cred.Groups))
		for _, g := range cred.Groups {
			groups = append(groups, uint32(g)) // #nosec G115 -- gids are u32
		}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(cred.UID), Gid: uint32(cred.GID), Groups: groups} // #nosec G115
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("privsep: spawn: %w", err)
	}
	return cmd, nil
}
