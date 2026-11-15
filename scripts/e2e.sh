#!/usr/bin/env bash
# Runs the network-namespace test suite (spec §23.2). Never touches the host network namespace:
# test/netlab aborts if it finds itself in the init netns.
set -euo pipefail
cd "$(dirname "$0")/.."
pkgs=("${@:-./test/...}")
# Build the test binaries outside the namespace (module cache and network access), then run them inside.
bindir=$(mktemp -d)
trap 'rm -rf "$bindir"' EXIT
go test -tags e2e -c -o "$bindir/" "${pkgs[@]}"
inner='set -e; mount -t sysfs sysfs /sys 2>/dev/null || true; for b in "$0"/*.test; do (cd "$(dirname "$b")" && "$b" -test.count=1 -test.timeout=15m ${LETHE_E2E_ARGS:-}); done'
if [[ $(id -u) -eq 0 ]]; then
  exec unshare --net --mount bash -c "$inner" "$bindir"
fi
if unshare --user --map-root-user --net --mount true 2>/dev/null; then
  exec unshare --user --map-root-user --net --mount bash -c "$inner" "$bindir"
fi
echo "e2e: unprivileged user namespaces are blocked here; rerun with: sudo -E env PATH=\"\$PATH\" mise run e2e" >&2
exit 1
