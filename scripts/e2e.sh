#!/usr/bin/env bash
# Runs the network-namespace test suite (spec §23.2). Never touches the host network namespace:
# test/netlab aborts if it finds itself in the init netns.
set -euo pipefail
cd "$(dirname "$0")/.."
args=(go test -tags e2e -count=1 -timeout 15m "${@:-./test/...}")
if [[ $(id -u) -eq 0 ]]; then
  exec unshare --net "${args[@]}"
fi
if unshare --user --map-root-user --net true 2>/dev/null; then
  exec unshare --user --map-root-user --net "${args[@]}"
fi
echo "e2e: unprivileged user namespaces are blocked here; rerun with: sudo -E env PATH=\"\$PATH\" mise run e2e" >&2
exit 1
