# 0017. Windows 11

- Status: accepted
- Date: 2026-11-19

## Context
lethe v1 is Linux only (spec §1.5). The owner wants a Windows 11 version with the same job: detect, record and stop IP, DNS and identity leaks outside the tunnel. Most of v1 is tied to Linux exactly where the work is done: nftables, AF_PACKET with cBPF, NFLOG, netlink, sock_diag, /proc, capabilities, seccomp, systemd, D-Bus and the network-namespace lab. The shared core (engine, contracts, journal, profile, baseline, report, geo, i18n, TUI, check evaluators) is about 40% of the code and ports unchanged.

## Decision
The owner chose:

1. **Full parity, kill switch included.** The guard (`strict`, `reactive`, panic) is built on the Windows Filtering Platform (WFP), not left for later.
2. **Native APIs only: WFP and ETW, no Npcap.** Npcap may be redistributed only with a paid OEM license; a kernel driver of our own needs an EV certificate and Microsoft attestation signing. Traffic is seen through WFP net events (flows, with executable and user SID) and, if a W0 spike proves it, through the inbox `ndiscap` ETW provider for packet contents (DNS qname, STUN header, announced hostname).
3. **Same repository.** The core stays shared, platform code sits behind Go interfaces in `_linux.go`/`_windows.go` files and `internal/win/*`, and `check` builds for `GOOS=windows`.

The spec gains Part IV (W1–W12): scope, the core/platform split, the Windows architecture (service, named-pipe IPC with SID checks, token privileges and process mitigation policies in place of capabilities and seccomp, reparse-point-safe storage), discovery, sensors, the WFP guard, the check mapping, four Windows-only checks (NET-015, NET-016, DNS-006, HOST-010), responses, distribution (MSI, Authenticode), tests and milestones W0–W11.

Key design choices inside that:
- WFP filters are **non-persistent and created outside a dynamic session**: they survive the daemon's death (fail-closed, like the nft tables) and vanish on reboot (like §11.6). A BFE restart also drops them; `wfpmon` reapplies the guard and raises CRITICAL.
- Strict filters sit at the ALE connect layers (new flows, with process) **and** the outbound IP packet layers (flows opened before arm). Panic adds inbound, forward and the outbound MAC layer (the `netdev egress` equivalent). `link_down` does not exist on Windows.
- Interfaces that are not `tunnel` or `internal` fall into the block, so an unclassified adapter is blocked: same fail-closed rule as the nft `policy drop`.
- Principle 10 holds: no `netsh`, `pktmon`, `powershell` or `wmic`. The only processes lethe starts are its own `lethe.exe` and the `lethe-gui.exe` beside it, hash-checked.
- Tests that touch WFP on hosted CI add a "lab scope" condition (documentation prefixes only) to every block filter, so the runner keeps its network; unscoped guard tests run only in a disposable Hyper-V VM (`test/winlab`) that carries a marker, the Windows counterpart of the netlab's namespace check.

## Rejected
- **Npcap:** licensing (OEM fee to bundle) and a third-party kernel driver in the trust base.
- **WinDivert or an own callout driver:** a kernel driver to sign and maintain; the threat model gains a component that can crash the machine.
- **A separate repository:** every core fix would be made twice.
- **Monitoring only first:** the owner wants the kill switch in the first Windows release.
- **WSL2 as the platform:** WSL2 does not see the Windows host's traffic, so it cannot watch for leaks there.

## Consequences
- The Windows track is several months of work. W0 is a set of spikes whose results (ADR 0018) can narrow W5.1 and W11: without ETW capture, DNS-001, NET-012 and NET-009 classify by port, without contents.
- New dependencies (the WFP library, an MSI tool, possibly WMI over COM for BitLocker) each need an ADR when their milestone starts.
- Owner-side costs appear: an Authenticode certificate (Smart App Control blocks unsigned binaries) and a Hyper-V host with a self-hosted runner for `winlab`.
- `check` grows a Windows cross-build; CI grows a `windows-latest` job. The Linux behaviour must not change in any W milestone.
