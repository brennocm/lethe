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

There are no published release files yet, so for now you build the packages from this
repository (about five minutes, once). Run everything below as your **normal user**, not as
root: `sudo` is asked for only where it is needed.

**1. Install [mise](https://mise.jdx.dev)**, the tool that fetches the pinned Go toolchain and
runs the build. It is not in the distro repositories:

```sh
curl https://mise.run | sh            # installs ~/.local/bin/mise (does not change your shell)
echo $SHELL                           # which shell you use: .../bash or .../zsh
```

Then activate it in that shell (the installer only prints this line, it does not run it):

```sh
echo 'eval "$(~/.local/bin/mise activate bash)"' >> ~/.bashrc && exec bash   # bash
echo 'eval "$(~/.local/bin/mise activate zsh)"' >> ~/.zshrc && exec zsh      # zsh (Kali's default)
mise doctor                                                                  # check
```

**2. Build the packages** (needs `git` and `curl`; the GUI step installs a C compiler and the
OpenGL/X11/Wayland headers if they are missing, after asking once):

```sh
git clone https://github.com/brennocm/lethe.git && cd lethe
mise trust                         # allow this repository's .mise.toml
mise install                       # Go, linters and nfpm at the pinned versions
mise run release -- 0.1.0 --gui    # writes dist/0.1.0/ with the .deb and .rpm files
```

**3. Install them:**

```sh
sudo apt install ./dist/0.1.0/lethe_*_amd64.deb ./dist/0.1.0/lethe-gui_*_amd64.deb   # Debian, Ubuntu, Kali
sudo dnf install ./dist/0.1.0/lethe-[0-9]*.x86_64.rpm ./dist/0.1.0/lethe-gui-*.x86_64.rpm # Fedora
lethe version
```

The `lethe-gui` package pulls in the graphics libraries it needs. On an arm64 machine use the
`arm64` / `aarch64` files.

Once release files are published, only step 3 is needed (with the downloaded files).

**Troubleshooting**

| Message | Fix |
|---|---|
| `mise: command not found` right after installing it | The installer does not touch your shell: run the `echo ... activate` line and `exec $SHELL` (or call `~/.local/bin/mise` directly). |
| `mise: command not found` | Step 1 was skipped, or it was run as root (it went to `/root/.local/bin`): `exit`, repeat it as your user, and remove the root copy with `sudo rm -rf /root/.local/bin/mise /root/.local/share/mise`. |
| `apt install mise`: *Unable to locate package* | Expected: mise is not packaged by the distro; use step 1. |
| `Config files in ... are not trusted` | Run `mise trust` inside the repository. |
| `release: the tree has uncommitted changes` | You edited files; `git stash`, or add `--allow-dirty`. |
| Anything under `sudo su` / as root | Leave the root shell (`exit`) and run as your user. |

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
mise trust && mise install   # pinned toolchain (Go, linters, nfpm); install mise first, see Install
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
