#!/usr/bin/env bash
# Runs every Fuzz* target for FUZZTIME (default 60s) each.
set -euo pipefail
cd "$(dirname "$0")/.."
FUZZTIME=${FUZZTIME:-60s}
found=0
while IFS= read -r line; do
  file=${line%%:*}; name=$(sed -E 's/^func (Fuzz[A-Za-z0-9_]+).*/\1/' <<<"${line#*:}")
  pkg=./$(dirname "$file")
  echo "fuzz: $pkg $name ($FUZZTIME)"
  go test -run '^$' -fuzz "^${name}\$" -fuzztime "$FUZZTIME" "$pkg"
  found=1
done < <(grep -rH --include='*_test.go' -E '^func Fuzz[A-Za-z0-9_]+\(' internal || true)
[[ $found -eq 1 ]] || echo "fuzz: no targets yet"
