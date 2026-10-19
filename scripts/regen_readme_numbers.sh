#!/usr/bin/env bash
# regen_readme_numbers.sh: write the README's numbers from the CI run that measured them
# (CLAUDEME: no number in a doc that no script in this repo produced; SPEC B1.10 Reproducible
# claims).
#
# The numbers live in one receipt, docs/receipts/ci-run.txt: lines copied verbatim from the job
# logs of one CI run, each prefixed with its job, plus the run id and the commit. `--receipt`
# writes it from downloaded job logs; the default mode writes the README blocks from it; `--check`
# (CI) fails when README.md differs from what the receipt gives. The blocks:
#
#   verify-timing  code-quality job: the two "perf:" lines of crates/sfr/tests/verify_perf.rs
#   tests          code-quality job: the "tests:" line; records job: the two "byte-identical
#                  records and reports" lines of scripts/check_same_records.sh (x86_64 against
#                  aarch64 and against armv7); demo job: the "DEMO PASSED" and "demo:" lines
#   benchmark      benchmark job: the output of scripts/benchmark.sh (x86_64 only: no armv7
#                  timing is published, SPEC B1.10 armv7)
#
# A block is required in README.md, between its markers, exactly when the receipt holds its lines.
#
# Usage:
#   scripts/regen_readme_numbers.sh                    rewrite README.md from the receipt
#   scripts/regen_readme_numbers.sh --check            exit 1 if README.md differs from the receipt
#   scripts/regen_readme_numbers.sh --receipt <run-id> <commit> <job>=<log> ...
#       write the receipt from CI job logs; <job> is code-quality, records, demo, or benchmark;
#       a log may carry the timestamps GitHub puts before each line
#   scripts/regen_readme_numbers.sh --self-test
set -euo pipefail
export LC_ALL=C

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
die() { echo "regen_readme_numbers.sh: $*" >&2; exit 1; }

begin() { echo "<!-- BEGIN $1: written by scripts/regen_readme_numbers.sh, do not edit by hand -->"; }
end() { echo "<!-- END $1 -->"; }

# The lines a job log contributes, by job.
job_pattern() {
  case "$1" in
    code-quality) echo '^(perf|tests): ' ;;
    records) echo '^byte-identical records and reports, ' ;;
    demo) echo '^(DEMO PASSED in |demo: )' ;;
    benchmark) echo '^((benchmark|hardware|note|gate|memory): |\| )' ;;
    *) die "unknown job $1 (code-quality, records, demo, benchmark)" ;;
  esac
}

# receipt <out> <run> <commit> <job>=<log>...
receipt() {
  local out="$1" run="$2" commit="$3" spec job log pattern n
  shift 3
  [[ "$run" =~ ^[0-9]+$ ]] || die "the CI run id must be digits, got \"$run\""
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || die "the commit must be a full hex sha, got \"$commit\""
  {
    echo "# README numbers come only from this file: scripts/regen_readme_numbers.sh writes them into"
    echo "# README.md. Every line after run and commit is copied from a job log of that CI run, after the"
    echo "# name of the job, by scripts/regen_readme_numbers.sh --receipt. Do not edit by hand."
    echo "run $run"
    echo "commit $commit"
    for spec in "$@"; do
      job="${spec%%=*}" log="${spec#*=}"
      [ "$job" != "$spec" ] && [ -f "$log" ] || die "expected <job>=<log file>, got $spec"
      pattern="$(job_pattern "$job")"
      n=0
      while IFS= read -r line; do
        echo "$job $line"
        n=$((n + 1))
      done < <(sed -E -e 's/\r$//' -e 's/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z //' "$log" | grep -E -- "$pattern" || true)
      [ "$n" -gt 0 ] || die "$log has no line for job $job"
    done
  } > "$out"
}

# field <receipt> <run|commit>
field() { awk -v k="$2" '$1 == k { print $2; exit }' "$1"; }
# lines <receipt> <job> <regex>: the job's lines matching the regex, without the job name.
lines() { awk -v j="$2" '$1 == j { sub(/^[^ ]+ /, ""); print }' "$1" | grep -E -- "$3" || true; }
one() { # one <receipt> <job> <regex>: exactly one line
  local hits
  hits="$(lines "$@")"
  [ -n "$hits" ] || die "the receipt has no $2 line matching $3"
  [ "$(printf '%s\n' "$hits" | wc -l)" -eq 1 ] || die "the receipt has more than one $2 line matching $3"
  printf '%s\n' "$hits"
}

render_verify_timing() {
  local r="$1" a b re
  a="$(one "$r" code-quality '^perf: in-process verify')"
  b="$(one "$r" code-quality '^perf: end-to-end sfr verify')"
  re='^perf: in-process verify \(gated, under 10 ms\): ([0-9,]+) events, ([0-9]+) byte record, median ([0-9.]+ ms), min ([0-9.]+ ms), max ([0-9.]+ ms), ([0-9]+) runs$'
  [[ "$a" =~ $re ]] || die "cannot read the in-process line: $a"
  local events="${BASH_REMATCH[1]}" bytes="${BASH_REMATCH[2]}" a_med="${BASH_REMATCH[3]}" \
    a_min="${BASH_REMATCH[4]}" a_max="${BASH_REMATCH[5]}" a_runs="${BASH_REMATCH[6]}"
  re='^perf: end-to-end sfr verify \(not gated\): same record, median ([0-9.]+ ms), min ([0-9.]+ ms), max ([0-9.]+ ms), ([0-9]+) runs$'
  [[ "$b" =~ $re ]] || die "cannot read the end-to-end line: $b"
  cat <<EOF
$(begin verify-timing)
Measured by \`crates/sfr/tests/verify_perf.rs\` in a release build, CI run $(field "$r" run) on commit \`$(field "$r" commit)\`. The record holds $events events ($bytes bytes).

| Measurement | What it times | Median | Min | Max | Runs | Gate (SPEC B1.10) |
|---|---|---|---|---|---|---|
| In-process verify | \`sfr_core::verify\` on the record bytes already in memory | $a_med | $a_min | $a_max | $a_runs | gated: median under 10 ms |
| End-to-end \`sfr verify\` | the whole command: process start, reading the record and the public key, and verify | ${BASH_REMATCH[1]} | ${BASH_REMATCH[2]} | ${BASH_REMATCH[3]} | ${BASH_REMATCH[4]} | not gated, reported only |
$(end verify-timing)
EOF
}

render_tests() {
  local r="$1" tests armv7 aarch64 demo wall re
  tests="$(one "$r" code-quality '^tests: ')"
  re='^tests: ([0-9]+) passed, 0 failed, ([0-9]+) ignored \(cargo test --workspace --locked\)$'
  [[ "$tests" =~ $re ]] || die "cannot read the tests line (or a test failed): $tests"
  local passed="${BASH_REMATCH[1]}" ignored="${BASH_REMATCH[2]}"
  re='^byte-identical records and reports, x86_64 and (aarch64|armv7): ([0-9]+ of [0-9]+) golden logs$'
  armv7="$(one "$r" records 'x86_64 and armv7: ')"
  [[ "$armv7" =~ $re ]] || die "cannot read the armv7 line: $armv7"
  armv7="${BASH_REMATCH[2]}"
  aarch64="$(one "$r" records 'x86_64 and aarch64: ')"
  [[ "$aarch64" =~ $re ]] || die "cannot read the aarch64 line: $aarch64"
  aarch64="${BASH_REMATCH[2]}"
  one "$r" demo '^DEMO PASSED in ' > /dev/null
  demo="$(one "$r" demo '^demo: ')"
  re='^demo: docker run --network=none, image loaded from its saved tarball, wall time ([0-9.]+) s$'
  [[ "$demo" =~ $re ]] || die "cannot read the demo line: $demo"
  wall="${BASH_REMATCH[1]}"
  cat <<EOF
$(begin tests)
CI run $(field "$r" run) on commit \`$(field "$r" commit)\`:

| Check | Result |
|---|---|
| \`cargo test --workspace --locked\` | $passed passed, 0 failed, $ignored ignored |
| Every golden log sealed on x86_64 and on armv7 (QEMU) | byte-identical records and reports: $armv7 golden logs |
| Every golden log sealed on x86_64 and on aarch64 (QEMU) | byte-identical records and reports: $aarch64 golden logs |
| \`scripts/run_demo.sh\` in \`docker run --network=none\`, image loaded from its saved tarball | passed, wall time $wall s |
$(end tests)
EOF
}

render_benchmark() {
  local r="$1" head
  head="$(one "$r" benchmark '^benchmark: ')"
  [[ "$head" == *"; binary x86_64, machine x86_64;"* ]] \
    || die "the README publishes the x86_64 CI benchmark only (no armv7 timing, SPEC B1.10): $head"
  cat <<EOF
$(begin benchmark)
\`scripts/benchmark.sh\` run from the x86_64 release tarball and the benchmark kit, CI run $(field "$r" run) on commit \`$(field "$r" commit)\` (docs/BENCHMARK.md).

- ${head#benchmark: }
- $(one "$r" benchmark '^hardware: ')
- $(one "$r" benchmark '^note: ')

$(lines "$r" benchmark '^\| ')

$(lines "$r" benchmark '^(gate|memory): ' | sed 's/^/- /')
$(end benchmark)
EOF
}

# The blocks the receipt holds lines for, in README order.
blocks() {
  local r="$1"
  [ -z "$(lines "$r" code-quality '^perf: ')" ] || echo verify-timing
  [ -z "$(lines "$r" code-quality '^tests: ')" ] || echo tests
  [ -z "$(lines "$r" benchmark '^benchmark: ')" ] || echo benchmark
}

# splice <readme> <block> <file>: README with the block's text replaced by the file.
splice() {
  local b e
  b="$(begin "$2")" e="$(end "$2")"
  [ "$(grep -c -x -F -- "$b" "$1")" -eq 1 ] || die "$1 must hold the BEGIN $2 marker exactly once"
  [ "$(grep -c -x -F -- "$e" "$1")" -eq 1 ] || die "$1 must hold the END $2 marker exactly once"
  awk -v b="$b" -v e="$e" -v f="$3" '
    $0 == b { while ((getline line < f) > 0) print line; skip = 1; next }
    $0 == e { skip = 0; next }
    !skip { print }
  ' "$1"
}

# regenerate <readme> <receipt> <out>: the README with every block the receipt holds rewritten.
regenerate() {
  local readme="$1" r="$2" out="$3" block
  [ -f "$r" ] || die "no receipt $r"
  [[ "$(field "$r" run)" =~ ^[0-9]+$ ]] || die "$r has no run id"
  [[ "$(field "$r" commit)" =~ ^[0-9a-f]{40}$ ]] || die "$r has no commit"
  cp "$readme" "$out"
  for block in $(blocks "$r"); do
    "render_${block//-/_}" "$r" > "$work/block"
    splice "$out" "$block" "$work/block" > "$work/spliced"
    cp "$work/spliced" "$out"
  done
}

main() { # main <write|check> <readme> <receipt>
  regenerate "$2" "$3" "$work/new"
  case "$1" in
    write) cp "$work/new" "$2" ;;
    check) diff -u "$2" "$work/new" || die "$2 differs from the numbers in $3; run scripts/regen_readme_numbers.sh" ;;
  esac
}

self_test() {
  local t="$work/self" ts='2026-10-19T00:26:29.9281445Z '
  mkdir -p "$t"
  printf '%s\n' "noise" \
    "${ts}perf: in-process verify (gated, under 10 ms): 10,000 events, 123 byte record, median 1.00 ms, min 0.90 ms, max 2.00 ms, 101 runs" \
    "perf: end-to-end sfr verify (not gated): same record, median 3.00 ms, min 2.50 ms, max 4.00 ms, 101 runs"$'\r' \
    "${ts}tests: 10 passed, 0 failed, 2 ignored (cargo test --workspace --locked)" > "$t/cq.log"
  printf '%s\n' "${ts}byte-identical records and reports, x86_64 and aarch64: 13 of 14 golden logs" \
    "byte-identical records and reports, x86_64 and armv7: 14 of 14 golden logs" > "$t/records.log"
  printf '%s\n' "DEMO PASSED in 1 s: every step gave the expected result." \
    "demo: docker run --network=none, image loaded from its saved tarball, wall time 2.50 s" > "$t/demo.log"
  printf '%s\n' "benchmark: sfr 0.1.0 (build abc); binary x86_64, machine x86_64; 5 run(s) per log" \
    "hardware: x86_64; CPU Test" "note: built for size only" "| log | bytes |" "|---|---|" "| large_100mb | 100 |" \
    "gate: x86_64 large_100mb seal median 0.700 s, under 2 s: PASS" "memory: large_100mb seal peak RSS 4000 KB" > "$t/bench.log"
  receipt "$t/receipt" 7 "$(printf 'a%.0s' {1..40})" code-quality="$t/cq.log" records="$t/records.log" \
    demo="$t/demo.log" benchmark="$t/bench.log"
  { echo "# Title"; for b in verify-timing tests benchmark; do echo; begin "$b"; echo stale; end "$b"; done; echo; echo tail; } > "$t/README.md"
  main write "$t/README.md" "$t/receipt"
  grep -q -F '| In-process verify | `sfr_core::verify` on the record bytes already in memory | 1.00 ms | 0.90 ms | 2.00 ms | 101 |' "$t/README.md" \
    || die "self-test: the in-process row is wrong"
  grep -q -F '| 3.00 ms | 2.50 ms | 4.00 ms | 101 | not gated, reported only |' "$t/README.md" || die "self-test: the end-to-end row is wrong"
  grep -q -F '| `cargo test --workspace --locked` | 10 passed, 0 failed, 2 ignored |' "$t/README.md" || die "self-test: the tests row is wrong"
  grep -q -F 'aarch64 (QEMU) | byte-identical records and reports: 13 of 14 golden logs |' "$t/README.md" || die "self-test: the aarch64 row is wrong"
  grep -q -F 'armv7 (QEMU) | byte-identical records and reports: 14 of 14 golden logs |' "$t/README.md" || die "self-test: the armv7 row is wrong"
  grep -q -F '| passed, wall time 2.50 s |' "$t/README.md" || die "self-test: the demo row is wrong"
  grep -q -x -F '| large_100mb | 100 |' "$t/README.md" || die "self-test: the benchmark table is missing"
  grep -q -x -F -- '- gate: x86_64 large_100mb seal median 0.700 s, under 2 s: PASS' "$t/README.md" || die "self-test: the gate line is missing"
  ! grep -q -x stale "$t/README.md" || die "self-test: an old block was kept"
  [ "$(head -1 "$t/README.md")" = "# Title" ] && [ "$(tail -1 "$t/README.md")" = "tail" ] || die "self-test: text outside the markers changed"
  main check "$t/README.md" "$t/receipt" > /dev/null || die "self-test: check fails on a fresh write"
  sed -i 's/1.00 ms/1.01 ms/' "$t/README.md"
  if (main check "$t/README.md" "$t/receipt" > /dev/null 2>&1); then die "self-test: check passes on drift"; fi
  main write "$t/README.md" "$t/receipt"
  grep -v -F "$(begin benchmark)" "$t/README.md" > "$t/no-marker.md"
  if (main check "$t/no-marker.md" "$t/receipt" > /dev/null 2>&1); then die "self-test: a missing marker is accepted"; fi
  sed -i 's/binary x86_64, machine x86_64/binary armv7, machine armv7l/' "$t/bench.log"
  receipt "$t/armv7-receipt" 7 "$(printf 'a%.0s' {1..40})" benchmark="$t/bench.log"
  if (main write "$t/README.md" "$t/armv7-receipt" > /dev/null 2>&1); then die "self-test: an armv7 timing is published"; fi
  sed -i 's/0 failed/1 failed/' "$t/cq.log"
  receipt "$t/failed-receipt" 7 "$(printf 'a%.0s' {1..40})" code-quality="$t/cq.log"
  if (main write "$t/README.md" "$t/failed-receipt" > /dev/null 2>&1); then die "self-test: a failed test run is published"; fi
  if (receipt "$t/r" 7 "$(printf 'a%.0s' {1..40})" demo="$t/cq.log" > /dev/null 2>&1); then die "self-test: a log without the job's lines is accepted"; fi
  echo "regen_readme_numbers.sh self-test: ok"
}

readme="$root/README.md" receipt_file="$root/docs/receipts/ci-run.txt"
case "${1:-}" in
  --self-test) self_test ;;
  --check) [ $# -eq 1 ] || die "usage: --check"; main check "$readme" "$receipt_file" ;;
  --receipt) [ $# -ge 4 ] || die "usage: --receipt <run-id> <commit> <job>=<log> ..."
    receipt "$work/receipt" "${@:2}"; mkdir -p "$(dirname "$receipt_file")"; cp "$work/receipt" "$receipt_file"
    echo "wrote $receipt_file" ;;
  "") main write "$readme" "$receipt_file" ;;
  *) die "unknown argument $1" ;;
esac
