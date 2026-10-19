#!/bin/sh
# run_demo.sh: the offline demo of sfr (Chunk 5; SPEC B1.10 No network: it passes in
# `docker run --network=none`).
#
#   a. keygen an evaluation key
#   b. seal the golden VTOL flight; seal prints the results table and the event count
#   c. verify the record standalone, then with --ulog: VERIFIED both times
#   d. change one byte of a COMMAND event in a copy of the record: verify fails, and verify
#      --ulog names the event and the field
#   e. seal the golden quad tailsitter flight, change the value of VT_B_TRANS_DUR (a VTOL
#      transition parameter) in a copy of its log: verify --ulog fails and names the parameter
#      with its sealed and found values
#   f. print the one-line command that seals the evaluator's own logs
#
# POSIX sh with busybox tools (sh, awk, cp, date, dd, mktemp, od, sed, strings, tr), so it runs in the demo
# image (scripts/build_demo_image.sh) as well as on a Linux machine. Exits 1 if any step does not
# give the expected result. The files come from the directory above this script (testdata/,
# examples/); sfr is $SFR, else bin/sfr there, else sfr on PATH.
set -eu

root="$(cd "$(dirname "$0")/.." && pwd)"
if [ -n "${SFR:-}" ]; then sfr="$SFR"
elif [ -x "$root/bin/sfr" ]; then sfr="$root/bin/sfr"
else sfr="sfr"
fi
vtol="$root/testdata/sitl/v1.17.0/vtol_transition.ulg"
vtol_baseline="$root/testdata/baselines/v1.17.0_vtol_transition.params"
tailsitter="$root/testdata/sitl/v1.17.0/gz_quadtailsitter_transition.ulg"
tailsitter_baseline="$root/testdata/baselines/v1.17.0_gz_quadtailsitter_transition.params"
rules="$root/examples/rules.default.toml"
param=VT_B_TRANS_DUR
start="$(date +%s)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail() { echo "DEMO FAILED: $*" >&2; exit 1; }
step() { printf '\n=== %s ===\n' "$*"; }
for f in "$vtol" "$vtol_baseline" "$tailsitter" "$tailsitter_baseline" "$rules"; do
  [ -f "$f" ] || fail "missing $f"
done
"$sfr" --version > /dev/null 2>&1 || fail "cannot run $sfr"

# Runs sfr with the arguments given, prints its output, and keeps the output and exit code in
# $out and $code.
run() {
  printf '$ sfr'; printf ' %s' "$@" | sed "s#$work/##g; s#$root/##g"; printf '\n'
  code=0
  out="$("$sfr" "$@" 2>&1)" || code=$?
  printf '%s\n' "$out"
  printf '(exit %s)\n' "$code"
}
expect() { # expect <exit code> <text the output must contain>
  [ "$code" = "$1" ] || fail "expected exit $1, got $code"
  case "$out" in *"$2"*) ;; *) fail "expected output containing: $2" ;; esac
}

step "a. keygen an evaluation key"
run keygen --evaluation-only --out "$work/key"
expect 0 "EVALUATION KEY"

step "b. seal the golden VTOL flight (testdata/sitl/v1.17.0/vtol_transition.ulg)"
run seal "$vtol" --rules "$rules" --baseline "$vtol_baseline" --key "$work/key/sfr.key" \
  --evaluation-only --out "$work/sealed"
expect 0 "status    PASS"
events="$(printf '%s\n' "$out" | awk '$1 == "events" { print $2 }')"
[ -n "$events" ] || fail "seal printed no event count"
echo "events in the record: $events"
record="$work/sealed/vtol_transition.sfr"

step "c. verify the record standalone, then with the log"
run verify "$record" --pubkey "$work/key/sfr.pub"
expect 0 "VERIFIED (record)"
run verify "$record" --pubkey "$work/key/sfr.pub" --ulog "$vtol"
expect 0 "VERIFIED (record and log)"

step "d. change one byte of a COMMAND event in a copy of the record"
cp "$record" "$work/tampered.sfr"
# The record is one line of canonical JSON, keys sorted, so a COMMAND event reads
# {"boot_us":...,"category":...,"command":<id>,...,"kind":"COMMAND",...}. Offset of the first
# digit of the first COMMAND event's command id, and that digit:
at="$(LC_ALL=C awk '{
  k = index($0, "\"kind\":\"COMMAND\""); if (k == 0) exit 1
  s = substr($0, 1, k); key = "\"command\":"; p = 0
  for (i = 1; i + length(key) <= k; i++) if (substr(s, i, length(key)) == key) p = i
  if (p == 0) exit 1
  print p - 1 + length(key), substr($0, p + length(key), 1)
}' "$work/tampered.sfr")" || fail "no COMMAND event in the record"
offset="${at% *}" digit="${at#* }"
case "$digit" in [1-8]) new=$((digit + 1)) ;; 9) new=1 ;; *) fail "unexpected byte $digit" ;; esac
printf '%s' "$new" | dd of="$work/tampered.sfr" bs=1 seek="$offset" conv=notrunc 2> /dev/null
echo "byte $offset of the record copy: command id digit $digit changed to $new"
run verify "$work/tampered.sfr" --pubkey "$work/key/sfr.pub"
expect 1 "Merkle root mismatch"
run verify "$work/tampered.sfr" --pubkey "$work/key/sfr.pub" --ulog "$vtol"
expect 1 "(COMMAND) field \`command\`: sealed "

step "e. change $param in a copy of the golden quad tailsitter log"
run seal "$tailsitter" --rules "$rules" --baseline "$tailsitter_baseline" \
  --key "$work/key/sfr.key" --evaluation-only --out "$work/sealed"
expect 0 "$param"
cp "$tailsitter" "$work/tailsitter.ulg"
# A ULog parameter record is: size (2 bytes), type 'P', key length, key "float NAME", value
# (4-byte float32, little-endian). The definitions section holds the 'P' record of each
# parameter at log start; a 'Q' record (default value) carries the same key.
key="float $param"
offset=""
for o in $(strings -t d -n "${#key}" "$work/tailsitter.ulg" | awk -v k="$key" '$2 " " $3 == k { print $1 }'); do
  if [ "$(dd if="$work/tailsitter.ulg" bs=1 skip=$((o - 2)) count=1 2> /dev/null)" = P ]; then
    offset=$((o + ${#key})); break
  fi
done
[ -n "$offset" ] || fail "no 'P' record for $param in the log"
old="$(od -A n -t x1 -j "$offset" -N 4 "$work/tailsitter.ulg" | tr -d ' \n')"
[ "$old" != "0000e040" ] || fail "$param is already 7.0 in the log"
printf '\000\000\340\100' | dd of="$work/tailsitter.ulg" bs=1 seek="$offset" conv=notrunc 2> /dev/null
echo "bytes $offset to $((offset + 3)) of the log copy: $param float32 bytes $old changed to 0000e040 (7.0)"
run verify "$work/sealed/gz_quadtailsitter_transition.sfr" --pubkey "$work/key/sfr.pub" \
  --ulog "$work/tailsitter.ulg"
expect 1 "parameter $param: sealed f32:"
case "$out" in *"found f32:7"*) ;; *) fail "verify did not name the found value f32:7" ;; esac

step "f. seal your own logs"
if [ -n "${SFR_DEMO_IMAGE:-}" ]; then
  echo "With your logs in ./logs and your vehicle's baseline (a QGroundControl .params export plus a '# Firmware:' line) in ./baseline.params, from the directory that holds them:"
  echo "docker run --rm --network=none --user \"\$(id -u):\$(id -g)\" -v \"\$PWD:/work\" -w /work $SFR_DEMO_IMAGE sh -c 'mkdir -p sealed && { [ -f sealed/key/sfr.key ] || sfr keygen --evaluation-only --out sealed/key; } && for f in logs/*.ulg; do sfr seal \"\$f\" --rules /sfr/examples/rules.default.toml --baseline baseline.params --key sealed/key/sfr.key --evaluation-only --out sealed; done'"
else
  echo "With your logs in ./logs and your vehicle's baseline (a QGroundControl .params export plus a '# Firmware:' line) in ./baseline.params:"
  quoted="'$(printf '%s' "$rules" | sed "s/'/'\\\\''/g")'"
  echo "mkdir -p sealed && { [ -f sealed/key/sfr.key ] || sfr keygen --evaluation-only --out sealed/key; } && for f in logs/*.ulg; do sfr seal \"\$f\" --rules $quoted --baseline baseline.params --key sealed/key/sfr.key --evaluation-only --out sealed; done"
fi

printf '\nDEMO PASSED in %s s: every step gave the expected result.\n' "$(($(date +%s) - start))"
