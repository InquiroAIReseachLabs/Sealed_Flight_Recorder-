#!/usr/bin/env bash
# check_engine_bundle.sh: an engine bundle (scripts/build_engine.sh, docs/SANDBOX.md) is whole and
# names its source. Fails unless every required file is there, SHA256SUMS lists every other file
# exactly once and each digest matches, and BUILDINFO names the given commit.
#
# Usage: scripts/check_engine_bundle.sh <bundle-dir> <commit>
#        scripts/check_engine_bundle.sh --self-test
set -euo pipefail
required="sfr.js sfr-worker.js README.md BUILDINFO SHA256SUMS pkg/sfr_wasm.js pkg/sfr_wasm_bg.wasm
rules/rules.default.toml rules/rules.extended.toml samples/samples.json samples/NOTICE.md samples/TESTDATA.md"

check() { # check <dir> <commit>: prints each problem; returns 1 if any
  local dir="$1" commit="$2" f status=0 listed present
  for f in $required; do
    [ -f "$dir/$f" ] || { echo "  missing $f"; status=1; }
  done
  [ -f "$dir/SHA256SUMS" ] || return 1
  grep -q -x "commit $commit" "$dir/BUILDINFO" 2> /dev/null \
    || { echo "  BUILDINFO does not name commit $commit"; status=1; }
  listed="$(awk '{ print $2 }' "$dir/SHA256SUMS" | LC_ALL=C sort)"
  present="$(cd "$dir" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort)"
  [ "$listed" = "$present" ] || { echo "  SHA256SUMS does not list exactly the bundle's other files:"
    diff <(printf '%s\n' "$listed") <(printf '%s\n' "$present") | sed 's/^/    /'; status=1; }
  (cd "$dir" && sha256sum -c --quiet SHA256SUMS) || { echo "  a digest in SHA256SUMS does not match"; status=1; }
  return $status
}

if [ "${1:-}" = --self-test ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  b="$tmp/bundle"
  for f in $required; do mkdir -p "$b/$(dirname "$f")"; echo "$f" > "$b/$f"; done
  echo "commit abc" > "$b/BUILDINFO"
  (cd "$b" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum > SHA256SUMS)
  check "$b" abc > /dev/null || { echo "FAIL: self-test: a whole bundle fails"; exit 1; }
  if check "$b" def > /dev/null 2>&1; then echo "FAIL: self-test: another commit passes"; exit 1; fi
  cp -r "$b" "$tmp/changed" && echo x >> "$tmp/changed/sfr.js"
  if check "$tmp/changed" abc > /dev/null 2>&1; then echo "FAIL: self-test: a changed file passes"; exit 1; fi
  cp -r "$b" "$tmp/extra" && echo x > "$tmp/extra/unlisted.js"
  if check "$tmp/extra" abc > /dev/null 2>&1; then echo "FAIL: self-test: an unlisted file passes"; exit 1; fi
  cp -r "$b" "$tmp/short" && rm "$tmp/short/pkg/sfr_wasm_bg.wasm"
  if check "$tmp/short" abc > /dev/null 2>&1; then echo "FAIL: self-test: a missing file passes"; exit 1; fi
  echo "PASS: engine bundle self-test (whole bundle, other commit, changed file, unlisted file, missing file)"
  exit 0
fi

[ $# -eq 2 ] || { echo "usage: $0 <bundle-dir> <commit> | --self-test" >&2; exit 2; }
if check "$1" "$2"; then
  echo "PASS: engine bundle $1: $(($(wc -l < "$1/SHA256SUMS") + 1)) files, every digest matches, commit $2"
else
  echo "FAIL: engine bundle $1"
  exit 1
fi
