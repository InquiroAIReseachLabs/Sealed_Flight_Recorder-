#!/usr/bin/env bash
# regen_readme_numbers.sh: write the README's numbers from the output of the script or test
# that measured them (CLAUDEME: no number in a doc that no script in this repo produced).
#
# Covered so far: the verify timing block, from the two "perf:" lines that
# crates/sfr/tests/verify_perf.rs prints (SPEC B1.10 Performance). The input is that test's
# output, or a CI job log that contains it; a timestamp before "perf:" is ignored. The block
# names the CI run and the commit the numbers came from. Seal benchmarks join in Chunk 5.
#
# Usage:
#   scripts/regen_readme_numbers.sh <verify-perf.log> <ci-run-id> <commit>          rewrite README.md
#   scripts/regen_readme_numbers.sh --check <verify-perf.log> <ci-run-id> <commit>  exit 1 if README.md differs
#   scripts/regen_readme_numbers.sh --print <verify-perf.log> <ci-run-id> <commit>  print the block only
#   scripts/regen_readme_numbers.sh --self-test
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
begin='<!-- BEGIN verify-timing: written by scripts/regen_readme_numbers.sh, do not edit by hand -->'
end='<!-- END verify-timing -->'
in_process='perf: in-process verify (gated, under 10 ms): '
end_to_end='perf: end-to-end sfr verify (not gated): '

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

die() { echo "regen_readme_numbers.sh: $*" >&2; exit 1; }

# The one line of $1 that carries prefix $2, from the prefix on, with any CR removed.
perf_line() {
  local hits
  hits="$(grep -F -- "$2" "$1" | sed -e 's/^.*\(perf: \)/\1/' -e 's/\r$//' || true)"
  [ -n "$hits" ] || die "$1 has no line starting \"$2\""
  [ "$(printf '%s\n' "$hits" | wc -l)" -eq 1 ] || die "$1 has more than one line starting \"$2\""
  printf '%s\n' "$hits"
}

# Prints the README block for log $1, run id $2, commit $3.
render() {
  local log="$1" run="$2" commit="$3" a b re
  [[ "$run" =~ ^[0-9]+$ ]] || die "the CI run id must be digits, got \"$run\""
  [[ "$commit" =~ ^[0-9a-f]{7,40}$ ]] || die "the commit must be a hex sha, got \"$commit\""
  a="$(perf_line "$log" "$in_process")"
  b="$(perf_line "$log" "$end_to_end")"
  re='^perf: in-process verify \(gated, under 10 ms\): ([0-9,]+) events, ([0-9]+) byte record, median ([0-9.]+ ms), min ([0-9.]+ ms), max ([0-9.]+ ms), ([0-9]+) runs$'
  [[ "$a" =~ $re ]] || die "cannot read the in-process line: $a"
  local events="${BASH_REMATCH[1]}" bytes="${BASH_REMATCH[2]}" a_med="${BASH_REMATCH[3]}" \
    a_min="${BASH_REMATCH[4]}" a_max="${BASH_REMATCH[5]}" a_runs="${BASH_REMATCH[6]}"
  re='^perf: end-to-end sfr verify \(not gated\): same record, median ([0-9.]+ ms), min ([0-9.]+ ms), max ([0-9.]+ ms), ([0-9]+) runs$'
  [[ "$b" =~ $re ]] || die "cannot read the end-to-end line: $b"
  local b_med="${BASH_REMATCH[1]}" b_min="${BASH_REMATCH[2]}" b_max="${BASH_REMATCH[3]}" b_runs="${BASH_REMATCH[4]}"
  cat <<EOF
$begin
Measured by \`crates/sfr/tests/verify_perf.rs\` in a release build, CI run $run on commit \`$commit\`. The record holds $events events ($bytes bytes).

| Measurement | What it times | Median | Min | Max | Runs | Gate (SPEC B1.10) |
|---|---|---|---|---|---|---|
| In-process verify | \`sfr_core::verify\` on the record bytes already in memory | $a_med | $a_min | $a_max | $a_runs | gated: median under 10 ms |
| End-to-end \`sfr verify\` | the whole command: process start, the FIPS module's power-on self-tests, reading the record and the public key, and verify | $b_med | $b_min | $b_max | $b_runs | not gated, reported only |
$end
EOF
}

# Prints README file $1 with the block replaced by file $2; fails unless the markers occur once.
splice() {
  [ "$(grep -c -x -F -- "$begin" "$1")" -eq 1 ] || die "$1 must hold the BEGIN verify-timing marker exactly once"
  [ "$(grep -c -x -F -- "$end" "$1")" -eq 1 ] || die "$1 must hold the END verify-timing marker exactly once"
  awk -v b="$begin" -v e="$end" -v f="$2" '
    $0 == b { while ((getline line < f) > 0) print line; skip = 1; next }
    $0 == e { skip = 0; next }
    !skip { print }
  ' "$1"
}

# mode readme log run commit
main() {
  local mode="$1" readme="$2" tmp="$work/block" out="$work/out"
  render "$3" "$4" "$5" > "$tmp"
  case "$mode" in
    print) cat "$tmp" ;;
    write) splice "$readme" "$tmp" > "$out"; cat "$out" > "$readme" ;;
    check)
      splice "$readme" "$tmp" > "$out"
      if ! diff -u "$readme" "$out"; then die "$readme differs from the numbers in $3"; fi ;;
  esac
}

self_test() {
  local log="$work/perf.log" readme="$work/README.md"
  printf '%s\n' "noise" \
    "2026-01-01T00:00:00Z ${in_process}10,000 events, 123 byte record, median 1.00 ms, min 0.90 ms, max 2.00 ms, 101 runs" \
    "${end_to_end}same record, median 3.00 ms, min 2.50 ms, max 4.00 ms, 101 runs"$'\r' > "$log"
  printf '%s\n' "# Title" "" "$begin" "stale" "$end" "" "tail" > "$readme"
  main write "$readme" "$log" 7 abcdef0
  grep -q -F '| In-process verify | `sfr_core::verify` on the record bytes already in memory | 1.00 ms | 0.90 ms | 2.00 ms | 101 |' "$readme" \
    || die "self-test: the in-process row is wrong"
  grep -q -F '| 3.00 ms | 2.50 ms | 4.00 ms | 101 | not gated, reported only |' "$readme" \
    || die "self-test: the end-to-end row is wrong"
  grep -q -F 'CI run 7 on commit `abcdef0`. The record holds 10,000 events (123 bytes).' "$readme" \
    || die "self-test: the source line is wrong"
  ! grep -q -x stale "$readme" || die "self-test: the old block was kept"
  [ "$(head -1 "$readme")" = "# Title" ] && [ "$(tail -1 "$readme")" = "tail" ] || die "self-test: text outside the markers changed"
  main check "$readme" "$log" 7 abcdef0 >/dev/null || die "self-test: check fails on a fresh write"
  if (main check "$readme" "$log" 8 abcdef0 >/dev/null 2>&1); then die "self-test: check passes on drift"; fi
  printf '%s\n' "${in_process}garbled" "${end_to_end}garbled" > "$log"
  if (main print "$readme" "$log" 7 abcdef0 >/dev/null 2>&1); then die "self-test: an unreadable log is accepted"; fi
  echo "regen_readme_numbers.sh self-test: ok"
}

case "${1:-}" in
  --self-test) self_test ;;
  --check) [ $# -eq 4 ] || die "usage: --check <verify-perf.log> <ci-run-id> <commit>"; main check "$root/README.md" "$2" "$3" "$4" ;;
  --print) [ $# -eq 4 ] || die "usage: --print <verify-perf.log> <ci-run-id> <commit>"; main print "$root/README.md" "$2" "$3" "$4" ;;
  -*) die "unknown option $1" ;;
  *) [ $# -eq 3 ] || die "usage: <verify-perf.log> <ci-run-id> <commit>"; main write "$root/README.md" "$1" "$2" "$3" ;;
esac
