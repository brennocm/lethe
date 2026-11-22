#!/usr/bin/env bash
# One-step install from this repository: fetches mise if missing, builds the deb/rpm packages
# (CLI + GUI) with the pinned toolchain, installs them with the distro's package manager and,
# if you agree, starts lethe for your user and shows why when it does not come up.
#
#   ./install.sh               build, install, offer to start the service and open the panel
#   ./install.sh --no-gui      CLI/TUI only (no C compiler or graphics headers needed)
#   ./install.sh --no-start    do not offer to start the service
#   ./install.sh --yes         answer yes to every question (also without a terminal)
#   ./install.sh --allow-dirty build even with uncommitted changes
#   ./install.sh --verbose     show every command's output instead of one line per step
#
# Run it as your normal user: sudo is asked for once, to install packages and start the service.
# Nothing here applies firewall rules: starting the service only opens its socket; the network is
# guarded only when you start a session. Full output: ~/.cache/lethe/install.log
set -euo pipefail

gui=1 start=ask yes=0 dirty=0 verbose=0
for a in "$@"; do
  case $a in
    --no-gui) gui=0 ;;
    --no-start) start=no ;;
    --yes) yes=1 ;;
    --allow-dirty) dirty=1 ;;
    --verbose) verbose=1 ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install: unknown option $a (see --help)" >&2; exit 2 ;;
  esac
done

# ---- look ----------------------------------------------------------------------------------

tty=0
[[ -t 1 ]] && tty=1
utf8=0
[[ $(locale charmap 2>/dev/null || true) == UTF-8 ]] && utf8=1
color=0
[[ $tty == 1 && -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb ]] && color=1
truecolor=0
[[ ${COLORTERM:-} == truecolor || ${COLORTERM:-} == 24bit ]] && truecolor=1

# the panel's colors (apps/lethe-gui/internal/gui/theme.go), with a 256-color fallback
rgb() { # r g b fallback256
  [[ $color == 1 ]] || return 0
  if [[ $truecolor == 1 ]]; then printf '\033[38;2;%d;%d;%dm' "$1" "$2" "$3"; else printf '\033[38;5;%dm' "$4"; fi
}
GOLD=$(rgb 201 173 116 179) SAGE=$(rgb 143 174 138 108) TEXT=$(rgb 233 227 211 254)
DIM=$(rgb 109 119 114 244) BRICK=$(rgb 216 92 68 167) OCHRE=$(rgb 217 164 65 172)
BOLD='' RESET=''
[[ $color == 1 ]] && BOLD=$'\033[1m' RESET=$'\033[0m'
if [[ $utf8 == 1 ]]; then OK='✓' FAIL='✗' DOT='•' ARROW='→'; else OK='ok' FAIL='x' DOT='*' ARROW='->'; fi

banner() {
  local rows
  if [[ $utf8 == 1 ]]; then
    rows=(
      '██╗     ███████╗████████╗██╗  ██╗███████╗'
      '██║     ██╔════╝╚══██╔══╝██║  ██║██╔════╝'
      '██║     █████╗     ██║   ███████║█████╗  '
      '██║     ██╔══╝     ██║   ██╔══██║██╔══╝  '
      '███████╗███████╗   ██║   ██║  ██║███████╗'
      '╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝'
    )
  else
    rows=(
      ' _      _   _          '
      '| | ___| |_| |__   ___ '
      '| |/ _ \ __| '"'"'_ \ / _ \'
      '| |  __/ |_| | | |  __/'
      '|_|\___|\__|_| |_|\___|'
    )
  fi
  # gold at the top fading to sage, as in the logo
  local from=(201 173 116) to=(143 174 138) n=${#rows[@]} i r g b
  echo
  for i in "${!rows[@]}"; do
    r=$(( from[0] + (to[0] - from[0]) * i / (n - 1) ))
    g=$(( from[1] + (to[1] - from[1]) * i / (n - 1) ))
    b=$(( from[2] + (to[2] - from[2]) * i / (n - 1) ))
    printf '  %s%s%s\n' "$(rgb "$r" "$g" "$b" $(( i < n / 2 ? 179 : 108 )))" "${rows[$i]}" "$RESET"
  done
  printf '  %sOpSec monitor %s IP, DNS and identity leaks outside the tunnel%s\n\n' "$DIM" "$DOT" "$RESET"
}

section() { printf '\n%s%s%s\n' "$BOLD$TEXT" "$*" "$RESET"; }
info() { printf '  %s%s%s %s\n' "$DIM" "$DOT" "$RESET" "$*"; }
note() { printf '  %s!%s %s\n' "$OCHRE" "$RESET" "$*"; }
die() {
  printf '\n  %s%s %s%s\n' "$BRICK" "$FAIL" "$*" "$RESET" >&2
  exit 1
}
ask() { # question default(Y|N) -> 0 for yes
  local q=$1 def=$2 ans hint='[Y/n]'
  [[ $def == N ]] && hint='[y/N]'
  [[ $yes == 1 ]] && return 0
  [[ -t 0 ]] || return 1 # no terminal: only --yes says yes
  printf '  %s?%s %s %s%s%s ' "$GOLD" "$RESET" "$q" "$DIM" "$hint" "$RESET"
  read -r ans || ans=''
  [[ -z $ans ]] && ans=$def
  [[ $ans =~ ^[Yy] ]]
}

# ---- steps ---------------------------------------------------------------------------------

log=${XDG_CACHE_HOME:-$HOME/.cache}/lethe/install.log
cleanup() {
  [[ -n ${keep_pid:-} ]] && kill "$keep_pid" 2>/dev/null
  [[ -n ${tmp:-} ]] && rm -rf "$tmp"
  [[ $tty == 1 ]] && printf '\033[?25h' # cursor back
  return 0
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# step "label" cmd...: one line with a spinner and the time taken; the output goes to the log
# and, when the command fails, its last lines are shown.
step() {
  local label=$1 t0=$SECONDS rc=0
  shift
  printf '\n### %s\n$ %s\n' "$label" "$*" >>"$log"
  if [[ $verbose == 1 || $tty == 0 ]]; then
    printf '  %s%s%s %s\n' "$DIM" "$ARROW" "$RESET" "$label"
    if [[ $verbose == 1 ]]; then
      "$@" </dev/null 2>&1 | tee -a "$log" || rc=$?
    else
      "$@" </dev/null >>"$log" 2>&1 || rc=$?
    fi
  else
    "$@" </dev/null >>"$log" 2>&1 &
    local pid=$! frames i=0
    if [[ $utf8 == 1 ]]; then frames=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏); else frames=('|' '/' '-' '\'); fi
    printf '\033[?25l'
    while kill -0 "$pid" 2>/dev/null; do
      printf '\r  %s%s%s %s %s(%ss)%s' "$GOLD" "${frames[i++ % ${#frames[@]}]}" "$RESET" "$label" "$DIM" $((SECONDS - t0)) "$RESET"
      sleep 0.1
    done
    wait "$pid" || rc=$?
    printf '\r\033[K\033[?25h'
  fi
  if [[ $rc -ne 0 ]]; then
    printf '  %s%s %s%s\n\n' "$BRICK" "$FAIL" "$label" "$RESET"
    printf '%s' "$DIM"
    tail -n 25 "$log" | sed 's/^/    /'
    printf '%s\n  Full output: %s\n' "$RESET" "$log"
    exit 1
  fi
  printf '  %s%s%s %s %s%ss%s\n' "$SAGE" "$OK" "$RESET" "$label" "$DIM" $((SECONDS - t0)) "$RESET"
}

# ---- checks --------------------------------------------------------------------------------

cd "$(dirname "${BASH_SOURCE[0]}")"
banner
[[ -f .mise.toml && -f scripts/release ]] || die "run ./install.sh from a clone of the lethe repository"
[[ $(id -u) -ne 0 ]] || die "run as your normal user, not root (sudo is asked for when needed)"
[[ $(uname -s) == Linux ]] || die "lethe runs on Linux"
for c in git curl sudo systemctl; do
  command -v "$c" >/dev/null 2>&1 || die "'$c' is missing: install it with your package manager first"
done
git rev-parse --git-dir >/dev/null 2>&1 || die "this is not a git clone (a downloaded zip has no history): use git clone"
if [[ $dirty == 0 && -n $(git status --porcelain --untracked-files=no) ]]; then
  die "the clone has uncommitted changes: git stash them, or run ./install.sh --allow-dirty"
fi
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
version=$(git describe --tags --abbrev=0 2>/dev/null | sed 's/^v//' || true)
[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || version=0.1.0
mkdir -p "$(dirname "$log")"
: >"$log"

what="version $version ($(git rev-parse --short HEAD)), $pm, $(uname -m)"
[[ $gui == 0 ]] && what+=', no GUI'
info "$what"
info "full output in $log"

# sudo once, kept fresh while the build runs (the steps cannot prompt behind a spinner)
section "Administrator password"
info "needed to install the packages and start the service"
sudo -v || die "sudo was refused"
( while kill -0 $$ 2>/dev/null; do sudo -n true 2>/dev/null; sleep 50; done ) &
keep_pid=$!

# ---- 1. toolchain --------------------------------------------------------------------------

section "1/4  Toolchain"
mise=$(command -v mise || true)
if [[ -z $mise ]]; then
  mise=$HOME/.local/bin/mise
  if [[ ! -x $mise ]]; then
    step "Install mise to ~/.local/bin" env MISE_INSTALL_PATH="$mise" sh -c 'curl -fsSL https://mise.run | sh'
  fi
fi
[[ -x $mise ]] || die "mise did not install to $mise"
step "Trust this repository's .mise.toml" "$mise" trust --quiet .
step "Pinned Go, linters and nfpm" "$mise" install
if [[ $gui == 1 ]] && ! scripts/gui-deps --check >>"$log" 2>&1; then
  # may ask before installing: runs in the open, not behind a spinner
  info "the GUI build needs a C compiler and the OpenGL/X11/Wayland headers"
  if [[ $yes == 1 ]]; then scripts/gui-deps --yes; else scripts/gui-deps; fi || die "the GUI build headers are missing (or use --no-gui)"
fi

# ---- 2. build ------------------------------------------------------------------------------

section "2/4  Build"
args=("$version")
[[ $dirty == 1 ]] && args+=(--allow-dirty)
[[ $gui == 1 ]] && args+=(--gui)
step "Packages for $version (the first build takes a few minutes)" "$mise" run release -- "${args[@]}"
out=dist/$version
if grep -q 'no geo database embedded' "$log"; then
  note "no geo database: the country checks stay inactive (scripts/update-geo adds it)"
fi

# ---- 3. install ----------------------------------------------------------------------------

section "3/4  Install"
# copied to a world-readable directory: apt reads local packages as its sandbox user, which
# cannot enter a private home ("Download is performed unsandboxed")
tmp=$(mktemp -d)
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
names=lethe
[[ $gui == 1 ]] && names='lethe and lethe-gui'
# a rebuild keeps the version number, so a plain install would skip it as already installed
case $pm in
  apt) step "Install $names" sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall "${files[@]}" ;;
  dnf)
    step "Install $names" sudo -n dnf install -y "${files[@]}"
    step "Replace a same-version build" sudo -n dnf reinstall -y "${files[@]}" ;;
  zypper) step "Install $names" sudo -n zypper --non-interactive install --force --allow-unsigned-rpm "${files[@]}" ;;
esac
ver=$(/usr/bin/lethe version 2>/dev/null || true)
installed=${ver%%$'\n'*}
commit=$(awk '/^commit/ {print substr($2, 1, 7)}' <<<"$ver")
[[ -n $installed ]] || die "the packages installed, but /usr/bin/lethe does not answer"
info "$installed (commit ${commit:-?})"

# ---- 4. service ----------------------------------------------------------------------------

section "4/4  Service"
unit=lethed@$user.service
state() { /usr/bin/lethe status --json 2>/dev/null | grep -o '"state":"[A-Z_]*"' | head -1 | cut -d'"' -f4 || true; }
running=0
if [[ $start == ask ]]; then
  if ask "Start lethe now and at every boot ($unit)?" Y; then start=yes; else start=no; fi
fi
if [[ $start == yes ]]; then
  step "Reload systemd" sudo -n systemctl daemon-reload
  step "Enable $unit at boot" sudo -n systemctl enable "$unit"
  if systemctl is-active --quiet "$unit"; then
    case $(state) in
      ARMED|VERIFIED|PANIC)
        note "a session is open: the service keeps the old version until you end it and run: sudo systemctl restart $unit" ;;
      *) step "Restart $unit on the new version" sudo -n systemctl restart "$unit" ;;
    esac
  else
    sudo -n systemctl reset-failed "$unit" >>"$log" 2>&1 || true
    step "Start $unit" sudo -n systemctl start "$unit"
  fi
  # the daemon answers on its socket, or the unit fails
  wait_daemon() {
    local s
    for _ in $(seq 30); do
      s=$(state)
      [[ -n $s && $s != NO_DAEMON ]] && return 0
      systemctl is-failed --quiet "$unit" && break
      sleep 0.5
    done
    sudo -n journalctl -u "$unit" -n 40 --no-pager
    return 1
  }
  step "Wait for the daemon to answer" wait_daemon
  running=1
else
  info "not started: later, Start lethe in the panel, or sudo systemctl enable --now $unit"
fi

# ---- done ----------------------------------------------------------------------------------

section "Done"
printf '  %s%s%s %s installed%s\n' "$SAGE" "$OK" "$RESET" "${installed:-lethe}" "$([[ $running == 1 ]] && echo ", running for $user")"
echo
printf '  %sNext%s\n' "$BOLD" "$RESET"
n=1
if [[ $gui == 1 ]]; then
  printf '  %s%d.%s Open the panel: %slethe-gui%s, or lethe in the applications menu\n' "$GOLD" $n "$RESET" "$BOLD" "$RESET"
else
  printf '  %s%d.%s Status: %slethe status%s, events: %slethe events%s\n' "$GOLD" $n "$RESET" "$BOLD" "$RESET" "$BOLD" "$RESET"
fi
n=$((n + 1))
if [[ ! -f $HOME/lethe/profile.yaml ]]; then
  if [[ $gui == 1 ]]; then where='on the Session page of the panel'; else where='with: lethe setup'; fi
  printf '  %s%d.%s First use, with the VPN %soff%s: create the profile %s\n' "$GOLD" $n "$RESET" "$BOLD" "$RESET" "$where"
  n=$((n + 1))
fi
if [[ $running == 0 ]]; then
  if [[ $gui == 1 ]]; then how='with the Start lethe button (asks for the administrator password)'; else how="with: sudo systemctl enable --now $unit"; fi
  printf '  %s%d.%s Start lethe %s\n' "$GOLD" $n "$RESET" "$how"
  n=$((n + 1))
fi
if [[ $gui == 1 ]]; then how='Start session'; else how='lethe arm -p ~/lethe/profile.yaml'; fi
printf '  %s%d.%s Turn the VPN on and start a session (%s), in Observe only at first\n' "$GOLD" $n "$RESET" "$how"
echo

if [[ $gui == 1 && -n ${DISPLAY:-}${WAYLAND_DISPLAY:-} ]] && command -v lethe-gui >/dev/null 2>&1; then
  if ask "Open the panel now?" Y; then
    setsid -f lethe-gui >/dev/null 2>&1 </dev/null || note "could not open it: run lethe-gui"
  fi
fi
