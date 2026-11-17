//go:build amd64 || arm64

package privsep

import "golang.org/x/sys/unix"

// allowed is the phase-2 allowlist common to amd64 and arm64 (spec §19.3): the Go runtime, the
// sockets (AF_PACKET, netlink, nftables, NFLOG, unix, inet), inotify, timerfd, epoll, the
// responses (kill, pidfd) and the selftest's re-execution of /proc/self/exe. allowedArch adds
// the syscalls only one architecture has. The e2e suite runs the hardened daemon with this list
// in enforce mode; LETHE_SECCOMP=log lists what is missing in the kernel log instead (ADR 0014).
var allowed = []uintptr{
	// memory and runtime
	unix.SYS_BRK, unix.SYS_MMAP, unix.SYS_MUNMAP, unix.SYS_MPROTECT, unix.SYS_MREMAP, unix.SYS_MADVISE,
	unix.SYS_MINCORE, unix.SYS_MLOCK, unix.SYS_MLOCK2, unix.SYS_MUNLOCK, unix.SYS_MLOCKALL, unix.SYS_MUNLOCKALL,
	unix.SYS_FUTEX, unix.SYS_SET_ROBUST_LIST, unix.SYS_GET_ROBUST_LIST, unix.SYS_SET_TID_ADDRESS, unix.SYS_RSEQ,
	unix.SYS_MEMBARRIER, unix.SYS_SCHED_YIELD, unix.SYS_SCHED_GETAFFINITY, unix.SYS_SCHED_SETAFFINITY,
	unix.SYS_SCHED_GETPARAM, unix.SYS_SCHED_GETSCHEDULER,
	unix.SYS_CLONE, unix.SYS_CLONE3, unix.SYS_EXECVE, unix.SYS_EXECVEAT, unix.SYS_EXIT, unix.SYS_EXIT_GROUP,
	unix.SYS_WAIT4, unix.SYS_WAITID, unix.SYS_RESTART_SYSCALL,
	unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK, unix.SYS_RT_SIGRETURN, unix.SYS_RT_SIGTIMEDWAIT,
	unix.SYS_RT_SIGQUEUEINFO, unix.SYS_RT_SIGSUSPEND, unix.SYS_SIGALTSTACK,
	unix.SYS_KILL, unix.SYS_TKILL, unix.SYS_TGKILL, unix.SYS_PIDFD_OPEN, unix.SYS_PIDFD_SEND_SIGNAL,
	unix.SYS_GETPID, unix.SYS_GETPPID, unix.SYS_GETTID, unix.SYS_GETPGID, unix.SYS_GETSID, unix.SYS_SETSID,
	unix.SYS_SETPGID,
	unix.SYS_GETUID, unix.SYS_GETEUID, unix.SYS_GETGID, unix.SYS_GETEGID, unix.SYS_GETRESUID, unix.SYS_GETRESGID,
	unix.SYS_GETGROUPS, unix.SYS_SETUID, unix.SYS_SETGID, unix.SYS_SETRESUID, unix.SYS_SETRESGID,
	unix.SYS_SETGROUPS, unix.SYS_SETREUID, unix.SYS_SETREGID, unix.SYS_SETFSUID, unix.SYS_SETFSGID,
	unix.SYS_CAPGET, unix.SYS_CAPSET, unix.SYS_PRCTL, unix.SYS_SECCOMP,
	unix.SYS_GETRLIMIT, unix.SYS_SETRLIMIT, unix.SYS_PRLIMIT64, unix.SYS_GETRUSAGE, unix.SYS_SYSINFO,
	unix.SYS_UNAME, unix.SYS_GETRANDOM, unix.SYS_TIMES, unix.SYS_UMASK, unix.SYS_GETPRIORITY,
	// time
	unix.SYS_CLOCK_GETTIME, unix.SYS_CLOCK_GETRES, unix.SYS_CLOCK_NANOSLEEP, unix.SYS_NANOSLEEP,
	unix.SYS_GETTIMEOFDAY, unix.SYS_SETITIMER, unix.SYS_GETITIMER,
	unix.SYS_TIMER_CREATE, unix.SYS_TIMER_SETTIME, unix.SYS_TIMER_GETTIME, unix.SYS_TIMER_DELETE,
	unix.SYS_TIMERFD_CREATE, unix.SYS_TIMERFD_SETTIME, unix.SYS_TIMERFD_GETTIME,
	// files
	unix.SYS_READ, unix.SYS_WRITE, unix.SYS_READV, unix.SYS_WRITEV, unix.SYS_PREAD64, unix.SYS_PWRITE64,
	unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_CLOSE, unix.SYS_CLOSE_RANGE, unix.SYS_LSEEK, unix.SYS_FSTAT,
	unix.SYS_NEWFSTATAT, unix.SYS_STATX, unix.SYS_FSTATFS, unix.SYS_STATFS, unix.SYS_FACCESSAT, unix.SYS_FACCESSAT2,
	unix.SYS_GETDENTS64, unix.SYS_GETCWD, unix.SYS_CHDIR, unix.SYS_FCHDIR, unix.SYS_READLINKAT,
	unix.SYS_MKDIRAT, unix.SYS_UNLINKAT, unix.SYS_RENAMEAT, unix.SYS_RENAMEAT2, unix.SYS_LINKAT, unix.SYS_SYMLINKAT,
	unix.SYS_FCHMOD, unix.SYS_FCHMODAT, unix.SYS_FCHOWN, unix.SYS_FCHOWNAT, unix.SYS_UTIMENSAT,
	unix.SYS_FTRUNCATE, unix.SYS_TRUNCATE, unix.SYS_FSYNC, unix.SYS_FDATASYNC, unix.SYS_FLOCK, unix.SYS_FADVISE64,
	unix.SYS_FALLOCATE, unix.SYS_FCNTL, unix.SYS_IOCTL, unix.SYS_DUP, unix.SYS_DUP3, unix.SYS_PIPE2,
	unix.SYS_SPLICE, unix.SYS_COPY_FILE_RANGE, unix.SYS_SENDFILE,
	unix.SYS_INOTIFY_INIT1, unix.SYS_INOTIFY_ADD_WATCH, unix.SYS_INOTIFY_RM_WATCH,
	unix.SYS_EVENTFD2, unix.SYS_EPOLL_CREATE1, unix.SYS_EPOLL_CTL, unix.SYS_EPOLL_PWAIT, unix.SYS_EPOLL_PWAIT2,
	unix.SYS_PPOLL, unix.SYS_PSELECT6,
	// sockets
	unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_BIND, unix.SYS_LISTEN, unix.SYS_ACCEPT4, unix.SYS_CONNECT,
	unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME, unix.SYS_SETSOCKOPT, unix.SYS_GETSOCKOPT, unix.SYS_SHUTDOWN,
	unix.SYS_SENDTO, unix.SYS_RECVFROM, unix.SYS_SENDMSG, unix.SYS_RECVMSG, unix.SYS_SENDMMSG, unix.SYS_RECVMMSG,
}
