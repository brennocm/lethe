# 0014. Hardening and packaging

- Status: accepted
- Date: 2026-11-17

## Context
M14 closes spec §19:
- seccomp phase 2;
- the service-mode units;
- deb/rpm packages, a reproducible build, an SBOM and the license list.

Gaps the spec left open:
- how to survey the syscalls;
- what a kill means for the network;
- who the operator is under `lethed.service`, which runs as root with no `SUDO_UID`;
- how to prove reproducibility;
- what to do with the SBOM's wrong license guesses.

## Decision
- **One seccomp filter, both phases.** The order of checks is:
  1. foreign ABI or x32: EPERM;
  2. the phase-1 denylist: EPERM;
  3. the allowlist (`internal/privsep/allow.go`): allow;
  4. anything else: `SECCOMP_RET_KILL_PROCESS`.

  Each entry is a compare and a return, so no jump needs more than 8 bits. `SECCOMP_FILTER_FLAG_LOG` makes denials and kills reach the kernel log. `LETHE_SECCOMP=log` turns step 4 into `SECCOMP_RET_LOG`; any other value enforces. Only root can set the daemon's environment, so this is no new way in.
- **Survey and gate.** `TestE2E_M14_SeccompEnforce` runs the hardened `lethe run` in a child through:
  - the full selftest, RESP-001 included;
  - panic, a CRITICAL in panic and its acknowledgement;
  - unpanic and the disarm.

  It reads `/dev/kmsg` and fails on any seccomp record. Run with `LETHE_SECCOMP=log`, it is the survey that built the list; run as is, it is the gate.
  - The other CLI e2e tests (AC-16/17/18, M7) also run hardened in enforce.
  - Under WSL2 the kernel logs pids of another namespace, so the test takes every record, not only its child's.
- **A kill fails closed and says so.** A killed daemon leaves its tables, so the network stays closed. `lethe status` names `sudo lethe cleanup`, and `docs/runbooks/crash-recovery.md` and `service-mode.md` cover it, including `signal=SYS` and the `LETHE_SECCOMP=log` collection. The unit restarts the daemon, but a new daemon never removes tables it did not create.
- **Service operator.** `lethe daemon` takes the sudo caller when there is one. Otherwise it takes `LETHE_OPERATOR`, declared in a drop-in, and refuses to start without it, with root, or with an unknown user. The error names `systemctl edit lethed`. A socket that admits only root would let the daemon arm sessions whose alerts nobody could acknowledge.
- **Units.**
  - `lethed.service` carries every §19.3 directive, plus `RuntimeDirectory=lethe` (so `/run/lethe` is writable under `ProtectSystem=strict`), `SystemCallArchitectures=native`, `LimitCORE=0` and `Restart=always` (one session per process).
  - `ReadWritePaths` (`storage.dir`) is the operator's, in the drop-in.
  - A test ties `CapabilityBoundingSet` to `privsep.Keep`.
  - `lethe-agent.service` is a user unit bound to `graphical-session.target`.
  - The package enables nothing.
- **Packages and reproducibility.**
  - `scripts/release VERSION` builds the static `lethe` for amd64 and arm64 with:
    - `CGO_ENABLED=0`, `-trimpath`, `-buildvcs`, `-buildid=`;
    - the version through `-X`;
    - the toolchain pinned in mise.
  - nfpm (pinned in mise) packs deb and rpm. `SOURCE_DATE_EPOCH` comes from the commit, and nfpm takes it for every mtime.
  - nfpm expands no variables in `contents`, so each binary is staged at `dist/stage/`.
  - The script writes `SHA256SUMS` and signs nothing.
  - `lethe-gui` is packed only with `--gui`, for the host architecture: cgo cannot cross-compile OpenGL without a sysroot.
  - `scripts/repro-check` builds HEAD twice and requires identical binaries and packages. Each build comes from a local clone at a different path with an empty `GOCACHE`. It uses clones because cyclonedx-gomod cannot read a worktree's `.git` file.
  - CI runs `release:repro`. The SBOMs are left out of the comparison because they carry a timestamp.
- **SBOM and licenses.**
  - `scripts/sbom` writes CycloneDX for both binaries with `-licenses -noserial`. The GUI module is listed with cgo on and nothing compiled.
  - `scripts/third-party` turns them into the module table of `docs/THIRD_PARTY.md`, and `check:all` fails when the table drifts.
  - Where the detector misreads a license file, a reviewed correction names the source line:
    - libcap is `BSD-3-Clause OR GPL-2.0-only`, and lethe takes BSD;
    - go-text is `Unlicense OR BSD-3-Clause`;
    - nfnt/resize and maxminddb are ISC;
    - golang.org/x and filippo.io/hpke are BSD-3-Clause.
  - A module with no license found prints "unknown — review before release".

## Consequences
- A syscall added by a dependency update kills the daemon until the allowlist grows. The seccomp e2e catches that on the paths it exercises. Paths it does not exercise (rare D-Bus errors, for example) surface as `signal=SYS`, with the runbook's collection steps.
- `repro-check` proves reproducibility without the geo databases, which are not in git. A release with them embedded is reproducible as long as both builds embed the same pinned files (`scripts/update-geo` checks the SHA-256).
