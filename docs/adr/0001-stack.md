# 0001. Stack: Go, pure-Go core, Fyne GUI in a separate module

- Status: accepted
- Date: 2026-11-15

## Context
lethe talks to the kernel almost exclusively (netlink, nftables, AF_PACKET, NFLOG, sock_diag,
WireGuard), must ship as a single static binary that runs on Debian, Ubuntu, Fedora and Kali on
amd64 and arm64 without installing anything, and is built by one person plus a coding agent that
relies on a fast, deterministic check loop.

## Decision
Go (toolchain pinned in `.mise.toml`), `CGO_ENABLED=0` for the `lethe` binary, libraries listed in
spec §20.1. The GUI (Fyne, needs cgo/OpenGL) lives in its own Go module under `apps/lethe-gui` and
only speaks IPC.

## Alternatives considered
- **Rust:** stronger memory-safety story, `zeroize`, cleaner seccomp/capabilities. Rejected for v1:
  less complete nftables and netlink crates, slower build/iteration loop, and the largest attack
  surface (packet parser) is small, isolated and continuously fuzzed in Go.
- **C/C++:** best kernel API coverage, but memory-unsafe parsers in a security tool and a much harder
  static, reproducible, cross-compiled build.
- **gopacket/afpacket:** needs cgo; replaced by `mdlayher/packet` (or its `antrea.io/packet` fork).

## Consequences
- Capabilities are per OS thread in Go: dropping them must go through `libcap/cap` (psx).
- Secrets must live in `[]byte` buffers with `mlock` and explicit zeroing, never in `string`.
- Seccomp allowlists must be derived from the e2e suite (log mode first).
- Revisit if the v2 sensor mode must run on hardware where the Go runtime footprint matters.
