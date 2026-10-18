#!/usr/bin/env bash
# check_deny_list.sh: fail if any networking or async-runtime crate is in the dependency graph,
# or if an Inquiro crate reaches for std::net (SPEC B1.10, "No network").
#
# Usage:
#   scripts/check_deny_list.sh              check the workspace
#   scripts/check_deny_list.sh --self-test  prove the check catches a banned crate
#
# The graph comes from `cargo metadata --locked` without a platform filter, so dependencies
# that are only pulled in for wasm32 or for a musl target are checked too.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
list="$root/deny-list.txt"
[ -f "$list" ] || { echo "FAIL: $list missing"; exit 1; }

# Banned names, comments and blank lines stripped.
banned() { grep -Ev '^\s*(#|$)' "$list" | sed 's/\s*$//' | sort -u; }

# Reads package names on stdin; prints the banned ones found; returns 1 if any.
find_banned() {
  local hits
  hits="$(sort -u | comm -12 - <(banned) || true)"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits"
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  # A synthetic graph with one banned crate must fail; a clean graph must pass.
  if printf 'sfr-core\nsha2\ntokio\n' | find_banned >/dev/null; then
    echo "FAIL: self-test: tokio was not caught"; exit 1
  fi
  if ! printf 'sfr-core\nsha2\n' | find_banned >/dev/null; then
    echo "FAIL: self-test: clean graph was rejected"; exit 1
  fi
  echo "PASS: deny-list self-test"
  exit 0
fi

command -v jq >/dev/null || { echo "FAIL: jq is required"; exit 1; }

packages="$(cargo metadata --locked --format-version 1 --manifest-path "$root/Cargo.toml" \
  | jq -r '.packages[].name')"

status=0
if hits="$(printf '%s\n' "$packages" | find_banned)"; then
  echo "PASS: no deny-listed crate in the dependency graph ($(printf '%s\n' "$packages" | sort -u | wc -l) packages checked)"
else
  echo "FAIL: deny-listed crate(s) in the dependency graph:"
  printf '  %s\n' $hits
  status=1
fi

# Inquiro crates must not open sockets through the standard library either.
if grep -rnE '\bstd::net\b|\buse net::' "$root/crates" --include='*.rs' >/dev/null 2>&1; then
  echo "FAIL: std::net used in an Inquiro crate:"
  grep -rnE '\bstd::net\b|\buse net::' "$root/crates" --include='*.rs'
  status=1
else
  echo "PASS: no std::net in crates/"
fi

exit $status
