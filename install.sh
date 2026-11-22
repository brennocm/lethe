#!/usr/bin/env bash
# One-step install from this repository: fetches mise if missing, builds the deb/rpm packages
# (CLI + GUI) with the pinned toolchain, installs them with the distro's package manager and,
# if you agree, starts lethe for your user and shows why when it does not come up.
#
#   ./install.sh               build, install, offer to start the service
#   ./install.sh --no-gui      CLI/TUI only (no C compiler or graphics headers needed)
#   ./install.sh --no-start    do not offer to start the service
#   ./install.sh --yes         start the service without asking
#   ./install.sh --allow-dirty build even with uncommitted changes
#
# Run it as your normal user: sudo is asked for only to install packages and start the service.
# Nothing here applies firewall rules: starting the service only opens its socket; the network is
# guarded only when you arm a session.
set -euo pipefail

gui=1 start=ask dirty=0
for a in "$@"; do
  case $a in
    --no-gui) gui=0 ;;
    --no-start) start=no ;;
    --yes) start=yes ;;
    --allow-dirty) dirty=1 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install: unknown option $a (see --help)" >&2; exit 2 ;;
  esac
done

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\033[31minstall: %s\033[0m\n' "$*" >&2; exit 1; }

cd "$(dirname "${BASH_SOURCE[0]}")"
[[ -f .mise.toml && -f scripts/release ]] || die "run ./install.sh from a clone of the lethe repository"
[[ $(id -u) -ne 0 ]] || die "run as your normal user, not root (sudo is asked for when needed)"
[[ $(uname -s) == Linux ]] || die "lethe runs on Linux"
for c in git curl sudo systemctl; do
  command -v "$c" >/dev/null 2>&1 || die "'$c' is missing: install it with your package manager first"
done
git rev-parse --git-dir >/dev/null 2>&1 || die "this is not a git clone (a downloaded zip has no history): use git clone"
user=$(id -un) # $USER is unset under some su/sudo setups

if command -v apt-get >/dev/null 2>&1; then pm=apt
elif command -v dnf >/dev/null 2>&1; then pm=dnf
elif command -v zypper >/dev/null 2>&1; then pm=zypper
else die "no apt, dnf or zypper found: build with 'mise run release -- 0.1.0 --gui' and install dist/ by hand"
fi
case $(uname -m) in
  x86_64) debarch=amd64 rpmarch=x86_64 ;;
  aarch64|arm64) debarch=arm64 rpmarch=aarch64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

# 1. mise (not in the distro repositories); called by full path, the shell config is left alone
say "1/4 mise"
mise=$(command -v mise || true)
if [[ -z $mise ]]; then
  mise=$HOME/.local/bin/mise
  if [[ ! -x $mise ]]; then
    echo "mise not found: installing it to $mise (https://mise.run)"
    curl -fsSL https://mise.run | MISE_INSTALL_PATH=$mise sh
  fi
fi
[[ -x $mise ]] || die "mise did not install to $mise"
"$mise" --version

# 2. toolchain and build
say "2/4 building (the first time takes a few minutes)"
"$mise" trust --quiet .
"$mise" install
version=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || true)
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || version=0.1.0
args=("$version")
[[ $dirty == 1 ]] && args+=(--allow-dirty)
[[ $gui == 1 ]] && args+=(--gui)
"$mise" run release -- "${args[@]}"
out=dist/$version

# 3. install. The packages are copied to a world-readable temporary directory: apt reads them
# as its sandbox user, which cannot enter a private home ("Download is performed unsandboxed").
say "3/4 installing the packages"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
chmod 755 "$tmp"
if [[ $pm == apt ]]; then
  pkgs=("$out"/lethe_*_"$debarch".deb)
  [[ $gui == 1 ]] && pkgs+=("$out"/lethe-gui_*_"$debarch".deb)
else
  pkgs=("$out"/lethe-[0-9]*."$rpmarch".rpm)
  [[ $gui == 1 ]] && pkgs+=("$out"/lethe-gui-[0-9]*."$rpmarch".rpm)
fi
files=()
for p in "${pkgs[@]}"; do
  [[ -f $p ]] || die "package not built: $p"
  install -m 644 "$p" "$tmp/"
  files+=("$tmp/$(basename "$p")")
done
# A rebuild keeps the version number, so "install" alone would skip it as already installed.
case $pm in
  apt) sudo apt-get install -y --reinstall "${files[@]}" ;;
  dnf) sudo dnf install -y "${files[@]}" && sudo dnf reinstall -y "${files[@]}" ;;
  zypper) sudo zypper --non-interactive install --force --allow-unsigned-rpm "${files[@]}" ;;
esac
/usr/bin/lethe version

# 4. service for this user (optional)
unit=lethed@$user.service
state() { /usr/bin/lethe status --json 2>/dev/null | grep -o '"state":"[A-Z_]*"' | head -1 | cut -d'"' -f4 || true; }
say "4/4 service"
if [[ $start == ask ]]; then
  if [[ -t 0 ]]; then
    read -r -p "Start lethe now and at every boot ($unit)? [Y/n] " ans || ans=n
    [[ $ans =~ ^[Nn] ]] && start=no || start=yes
  else
    start=no
    echo "no terminal to ask: not starting the service (pass --yes to start it)"
  fi
fi
if [[ $start == yes ]]; then
  sudo systemctl daemon-reload
  if systemctl is-active --quiet "$unit"; then
    # the running daemon is the old binary; restarting it would end an open session
    case $(state) in
      ARMED|VERIFIED|PANIC)
        echo "A session is open: the service keeps the old version until you disarm and run: sudo systemctl restart $unit" ;;
      *) sudo systemctl restart "$unit" ;;
    esac
  else
    sudo systemctl reset-failed "$unit" 2>/dev/null || true
    sudo systemctl enable --now "$unit"
  fi
  ok=0
  for _ in $(seq 30); do
    s=$(state)
    if [[ -n $s && $s != NO_DAEMON ]]; then ok=1; break; fi
    systemctl is-failed --quiet "$unit" && break
    sleep 0.5
  done
  if [[ $ok == 0 ]]; then
    printf '\033[31mThe service did not answer within 15 s. Its log:\033[0m\n'
    sudo journalctl -u "$unit" -n 40 --no-pager || true
    echo
    echo "Report this log with the problem. To stop it retrying: sudo systemctl disable --now $unit"
    exit 1
  fi
  echo "lethe is running for $user."
else
  echo "Not started. Later: the Start lethe button in the GUI, or sudo systemctl enable --now $unit"
fi

echo
echo "Done. Open lethe from the applications menu (GUI) or run: lethe status"
[[ -f $HOME/lethe/profile.yaml ]] || echo "First use: the GUI walks you through it, or run: lethe setup"
