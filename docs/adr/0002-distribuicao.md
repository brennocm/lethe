# 0002. Distribution: portable static binary plus deb/rpm; no deploy platform

- Status: accepted
- Date: 2026-11-15

## Context
lethe is a local host tool, not a service. Operators install it on the spot, often from an
internal institutional repository, and must be able to verify what they run.

## Decision
- Portable mode: one static `lethe` binary (+ optional `lethe-gui`) run from any directory.
- Packages: `.deb` and `.rpm` built with nfpm, with optional `lethed.service` and a user unit for the
  session agent.
- Reproducible builds (`-trimpath`, pinned toolchain, `SOURCE_DATE_EPOCH`), CycloneDX SBOM per
  release, signatures (minisign or cosign) produced by the owner, never by automation holding keys.
- No public download at operation time; no self-update; no network access by the tool itself.

## Alternatives considered
- Container image: needs host network/PID namespaces and many capabilities anyway; adds a runtime
  the operator may not have. Rejected for v1.
- Flatpak/Snap: sandboxing conflicts with netlink/nftables/AF_PACKET access. Rejected.

## Consequences
The service contract of web apps (healthz, PORT, stdout logs) does not apply. Release steps that need
keys or the internal repository are documented in `docs/runbooks/release.md` for the owner.
