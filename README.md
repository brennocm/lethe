<p align="center">
  <img src="docs/assets/lethe-logo.webp" alt="lethe" width="520">
</p>

# lethe

Local OpSec monitor for Linux. While you work behind a VPN and/or Tor, lethe discovers the
tunnel, checks the setup before you start, watches every outbound interface for traffic that
escapes the tunnel (IP, DNS, IPv6, WebRTC/STUN, LAN broadcasts), can block it with nftables
(fail-closed), and keeps an encrypted, hash-chained and signed session log.

Everything is done from the panel (`lethe-gui`). The terminal is only needed to install.

> **Status:** feature-complete, but the manual acceptance runs (real Tor, and the GUI on GNOME
> and KDE) are still pending. Do not rely on it for real operations yet.

## Install

From the release files:

```sh
sudo apt install ./lethe_*.deb ./lethe-gui_*.deb     # Debian, Ubuntu
sudo dnf install ./lethe-*.rpm ./lethe-gui-*.rpm     # Fedora
```

The `lethe-gui` package pulls in the graphics libraries it needs. Check the binary with
`lethe version` against the release notes.

## Use

1. **Open lethe** from the applications menu, or run `lethe-gui`.
2. **First use** (once): with the VPN **off**, on your real network, the panel asks for the
   operation's identity, discovers the public IP and the network's DNS servers when you ask it
   to, and asks for a passphrase typed twice. It creates `~/lethe/profile.yaml` and
   `~/lethe/baseline.age`. There is no key to manage: the passphrase is the only secret. Keep it
   **off** the machine.
3. **Start lethe**: the panel starts the service and the system asks for the administrator
   password.
4. **Turn on the VPN** (or Tor) and click **Start session**. Begin with *Observe only*; *Strict*
   protection is offered after an approved **Selftest** on this machine.
5. During the session, the **Overview** answers "am I covered?" and the route shows where the web
   sees you. The other pages detail the IP and DNS, the events, the guard and the checks. A
   critical leak opens a full-screen red alert that only closes with a reason and the
   passphrase. **Panic** blocks the network at once.
6. **End session** asks for the passphrase, removes the rules and closes the log. The session
   report is under **Reports**, on the **Session** page.

Other real networks (home, office, café): use **Register the current network**, with the VPN off,
so their IP and DNS servers also count as a leak.

## If the network is blocked

A block is always on purpose and always has a way out. The panel says what is blocked, why, and
how to leave: **Leave panic**, **End session** or, after a crash, **Release the network** (asks
for the administrator password). Without the panel: `sudo lethe cleanup`. Rebooting the machine
also releases it. Details in [`docs/runbooks/crash-recovery.md`](docs/runbooks/crash-recovery.md).

## Documentation

The operator guides, the spec and the ADRs are written in Portuguese.

| For | Where |
|---|---|
| Operators | [`operation.md`](docs/runbooks/operation.md) (walkthrough of an operation), [`crash-recovery.md`](docs/runbooks/crash-recovery.md), [`session-verification.md`](docs/runbooks/session-verification.md) |
| Installing on dedicated machines | [`service-mode.md`](docs/runbooks/service-mode.md) |
| Releasing | [`release.md`](docs/runbooks/release.md), [`manual-acceptance.md`](docs/runbooks/manual-acceptance.md), [`ac07-tor.md`](docs/runbooks/ac07-tor.md) |
| Developers | [`spec.md`](spec.md) (scope), [`AGENTS.md`](AGENTS.md) (state and rules), [`docs/adr`](docs/adr) (decisions) |

## Develop

```sh
mise install          # pinned toolchain (Go, linters, nfpm)
mise run gui          # build the GUI and open it (installs the OpenGL/X11/Wayland headers if missing)
mise run check        # definition of done: format, lint, boundaries, vet, tests
mise run e2e          # tests in network namespaces (user namespaces or sudo -E)
mise run build        # static binary in bin/lethe
mise run release -- VERSION --gui   # deb/rpm packages, SBOM and SHA256SUMS (unsigned)
```

Never arm strict protection, or engage panic, on a machine whose network you need, unless that
is the point: it is exactly what they are for. Tests that apply nftables run only inside the
`test/netlab` namespaces.

## License

GPL-3.0-or-later ([`LICENSE`](LICENSE)). The licenses of the dependencies and of the embedded
data are listed in [`docs/THIRD_PARTY.md`](docs/THIRD_PARTY.md).
