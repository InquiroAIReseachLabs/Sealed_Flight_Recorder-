#!/usr/bin/env bash
# check_deny_list.sh: fail if any networking or async-runtime crate is in the dependency graph,
# or if an Inquiro crate opens a socket through the standard library (SPEC B1.10, "No network").
#
# Usage:
#   scripts/check_deny_list.sh              check the workspace
#   scripts/check_deny_list.sh --self-test  prove the check catches what it exists to catch
#
# The graph comes from `cargo metadata --locked --all-features` with no platform filter, so
# dependencies pulled in only for wasm32, only for a musl target, or only behind a non-default
# feature are all checked. This matches cargo-deny's `[graph] all-features = true` in deny.toml.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
list="$root/deny-list.txt"
[ -f "$list" ] || { echo "FAIL: $list missing"; exit 1; }
command -v jq >/dev/null || { echo "FAIL: jq is required"; exit 1; }

# Banned names, comments and blank lines stripped.
banned() { grep -Ev '^\s*(#|$)' "$list" | sed 's/\s*$//' | sort -u; }

# Package names in the full graph of a manifest: every platform, every feature, every kind.
graph_names() {
  cargo metadata --locked --all-features --format-version 1 --manifest-path "$1" \
    | jq -r '.packages[].name'
}

# Reads package names on stdin; prints the banned ones found; returns 1 if any.
find_banned() {
  local hits
  hits="$(sort -u | comm -12 - <(banned))"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits"
    return 1
  fi
  return 0
}

# Socket types from std, whatever the import style (`std::net::TcpStream`, `use std::{net, io}`
# then `net::TcpStream`, or `std::os::unix::net::UnixStream`).
SOCKET_RE='\b(std::net|std::os::unix::net|TcpStream|TcpListener|UdpSocket|UnixStream|UnixListener|UnixDatagram)\b'

# Prints source lines in a directory tree that use std sockets; returns 1 if any.
find_sockets() {
  local hits
  hits="$(grep -rnE "$SOCKET_RE" "$1" --include='*.rs' || true)"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits"
    return 1
  fi
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  # 1. The name matcher catches a banned crate and accepts a clean list.
  if printf 'sfr-core\nsha2\ntokio\n' | find_banned >/dev/null; then
    echo "FAIL: self-test: tokio was not caught by the name matcher"; exit 1
  fi
  printf 'sfr-core\nsha2\n' | find_banned >/dev/null \
    || { echo "FAIL: self-test: clean list was rejected"; exit 1; }

  # 2. The real extraction sees a banned crate hidden behind a non-default feature.
  #    Offline: the banned crate is a local path dependency named tokio.
  mkdir -p "$tmp/fixture/src" "$tmp/fixture/tokio/src"
  : > "$tmp/fixture/src/lib.rs"; : > "$tmp/fixture/tokio/src/lib.rs"
  printf '[package]\nname = "fixture"\nversion = "0.0.0"\nedition = "2021"\n[features]\nnet = ["dep:tokio"]\n[dependencies]\ntokio = { path = "tokio", optional = true }\n' > "$tmp/fixture/Cargo.toml"
  printf '[package]\nname = "tokio"\nversion = "0.0.0"\nedition = "2021"\n' > "$tmp/fixture/tokio/Cargo.toml"
  (cd "$tmp/fixture" && cargo generate-lockfile --offline --quiet)
  if graph_names "$tmp/fixture/Cargo.toml" | find_banned >/dev/null; then
    echo "FAIL: self-test: feature-gated tokio was not seen by the graph extraction"; exit 1
  fi

  # 3. The socket scan catches each import style and passes clean code.
  mkdir -p "$tmp/src_dirty" "$tmp/src_clean"
  printf 'use std::{io, net};\nfn f() { let _s = net::TcpStream::connect("x"); }\n' > "$tmp/src_dirty/a.rs"
  printf 'fn g() { let _u = std::os::unix::net::UnixStream::pair(); }\n' > "$tmp/src_dirty/b.rs"
  printf 'fn h() -> u8 { 1 }\n' > "$tmp/src_clean/c.rs"
  dirty="$(find_sockets "$tmp/src_dirty" || true)"
  [ "$(printf '%s\n' "$dirty" | grep -c .)" -ge 2 ] \
    || { echo "FAIL: self-test: socket scan missed an import style: $dirty"; exit 1; }
  find_sockets "$tmp/src_clean" >/dev/null \
    || { echo "FAIL: self-test: socket scan rejected clean code"; exit 1; }

  echo "PASS: deny-list self-test (name matcher, feature-gated extraction, socket scan)"
  exit 0
fi

status=0
packages="$(graph_names "$root/Cargo.toml")"
count="$(printf '%s\n' "$packages" | sort -u | grep -c .)"
if hits="$(printf '%s\n' "$packages" | find_banned)"; then
  echo "PASS: no deny-listed crate in the dependency graph ($count packages, all features, all platforms)"
else
  echo "FAIL: deny-listed crate(s) in the dependency graph:"
  printf '  %s\n' $hits
  status=1
fi

if hits="$(find_sockets "$root/crates")"; then
  echo "PASS: no std socket use in crates/"
else
  echo "FAIL: std socket use in an Inquiro crate:"
  printf '%s\n' "$hits"
  status=1
fi

exit $status
