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
repository (about five minutes the first time). Run everything as your **normal user**, not as
root: `sudo` is asked for once, by the installer.

```sh
git clone https://github.com/brennocm/lethe.git && cd lethe
./install.sh
```

`install.sh` needs `git`, `curl`, `sudo` and systemd, and works with apt (Debian, Ubuntu, Kali),
dnf (Fedora) or zypper (openSUSE), on amd64 or arm64. It:

1. installs [mise](https://mise.jdx.dev) to `~/.local/bin` if it is missing (your shell
   configuration is left alone);
2. fetches the pinned Go toolchain and builds the `.deb`/`.rpm` packages into `dist/<version>/`,
   asking once to install a C compiler and the OpenGL/X11/Wayland headers the GUI build needs;
3. installs `lethe` and `lethe-gui` (a rebuild of the same version is reinstalled, not skipped);
4. asks whether to start lethe for your user (`lethed@<user>.service`, also at every boot) and
   waits for it to answer. If it does not, it prints the service's log. A service that was
   already running is restarted on the new version, unless a session is open;
5. lists the next steps and offers to open the panel (`lethe-gui`).

`sudo` is asked for once, at the start. Each step takes one line; the full output goes to
`~/.cache/lethe/install.log`, and when a step fails its last lines are shown.

| Option | Effect |
|---|---|
| `--no-gui` | CLI/TUI only: no GUI package, no C compiler or graphics headers |
| `--no-start` | install only; start later with **Start lethe** in the panel |
| `--yes` | answer yes to every question (needed to start the service without a terminal) |
| `--allow-dirty` | build even with uncommitted changes in the clone |
| `--verbose` | show every command's output instead of one line per step |

To update, `git pull && ./install.sh`. Starting the service applies no firewall rule: the network
is guarded only when you start a session.

<details>
<summary>The same steps by hand</summary>

```sh
curl https://mise.run | sh                                   # ~/.local/bin/mise
echo 'eval "$(~/.local/bin/mise activate bash)"' >> ~/.bashrc && exec bash   # or zsh / ~/.zshrc
mise trust && mise install                                   # inside the clone
mise run release -- 0.1.0 --gui                              # dist/0.1.0/
sudo apt install ./dist/0.1.0/lethe_*_amd64.deb ./dist/0.1.0/lethe-gui_*_amd64.deb      # Debian, Ubuntu, Kali
sudo dnf install ./dist/0.1.0/lethe-[0-9]*.x86_64.rpm ./dist/0.1.0/lethe-gui-*.x86_64.rpm # Fedora
sudo systemctl enable --now lethed@$USER                     # or Start lethe in the panel
```

On arm64 use the `arm64` / `aarch64` files. Once release files are published, only the package
install is needed.
</details>

**Troubleshooting**

| Message | Fix |
|---|---|
| `run as your normal user, not root` | Leave the root shell (`exit`) and run `./install.sh` as your user. If mise was installed as root, remove it: `sudo rm -rf /root/.local/bin/mise /root/.local/share/mise`. |
| `lethe: unknown command "gui"` | The panel is its own program: `lethe-gui` (or lethe in the applications menu). |
| `the clone has uncommitted changes` (or `release: the tree has uncommitted changes`) | You edited files: `git stash`, or `./install.sh --allow-dirty`. |
| `The service did not answer within 15 s`, or in the panel *lethe did not answer* | The log printed below it (or `sudo journalctl -u lethed@$USER -n 40 --no-pager`) says why; report it with that log. Stop the retries with `sudo systemctl disable --now lethed@$USER`. |
| `ipc: chown /run/lethe` or `ipc: chmod /run/lethe: operation not permitted` | Packages built before this fix: `git pull && ./install.sh`. |
| `N: Download is performed unsandboxed as root` | Harmless apt note when installing from a private home by hand; `install.sh` avoids it. |
| `mise: command not found` after a manual install | mise does not touch your shell: run the `activate` line, or call `~/.local/bin/mise`. `install.sh` does not need this. |
| `Config files in ... are not trusted` | Run `mise trust` inside the clone. |

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
