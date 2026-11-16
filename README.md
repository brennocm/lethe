<p align="center">
  <img src="docs/assets/lethe-logo.webp" alt="lethe" width="520">
</p>

# lethe

Local OpSec leak monitor for Linux. While you work behind a VPN and/or Tor, lethe discovers the
tunnel, checks the setup before you start, watches every egress interface for traffic that bypasses
the tunnel (IP, DNS, IPv6, WebRTC/STUN, LAN broadcasts), optionally blocks it with nftables
(fail-closed), and writes an encrypted, hash-chained, signed session log.

Status: under development — see `spec.md` (scope) and `AGENTS.md` (current milestone).

## Build and test

```sh
mise install          # pinned Go toolchain and linters
mise run check        # format, lint, boundaries, vet, unit tests
mise run e2e          # network-namespace tests (user namespaces or sudo)
mise run build        # static binary in bin/lethe
```

Never run lethe with the guard in `strict`/`reactive` mode, or `lethe panic`, on a machine whose
network you need unless you mean it: that is exactly what it is for.

## License

To be decided by the owner before the first release (see `docs/THIRD_PARTY.md` for bundled data
licenses once added).
