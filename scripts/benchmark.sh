#!/usr/bin/env bash
# benchmark.sh: seal time and peak memory on this machine (SPEC B1.10 Performance and Peak
# memory). Release build; for every golden log and for 10, 50, and 100 MB logs built from the
# golden v1.17.0 VTOL flight (scripts/benchmark/make_large_log.py), it seals RUNS times with an
# evaluation key and reports the median wall time and the largest maximum resident set size
# (/usr/bin/time). Each large log is sealed twice over: with the default rules, and with the
# eight highest-rate topics of that flight declared in [sealed_topics] (`_sealed8`), so the
# sealed topic digests are inside the gate. The large logs end mid-flight wherever the size cut falls, so R5 may fail on
# them; the record is still written and timed. Exits 1 if either 100 MB median is 2 s or more
# (the x86_64 gate). A peak above 256 MB on a 100 MB log is printed as a line to report.
#
# Usage: scripts/benchmark.sh [runs, default 5]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
RUNS="${1:-5}"
command -v /usr/bin/time >/dev/null || { echo "benchmark.sh: /usr/bin/time is required" >&2; exit 1; }
cargo build --release --locked -p sfr >&2
sfr=target/release/sfr
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

flight=testdata/sitl/v1.17.0/vtol_transition.ulg
for mb in 10 50 100; do
  python3 -I scripts/benchmark/make_large_log.py "$flight" "$work/large_${mb}mb.ulg" "$mb" >&2
done
"$sfr" keygen --evaluation-only --out "$work/key" > /dev/null
# The eight highest-rate topics of the flight the large logs repeat (pyulog message counts).
{ cat examples/rules.default.toml
  printf '\n[sealed_topics]\ntopics = ["sensor_combined", "ekf2_timestamps", "vehicle_attitude",\n'
  printf '  "vehicle_thrust_setpoint_virtual_mc", "vehicle_torque_setpoint_virtual_mc",\n'
  printf '  "vehicle_thrust_setpoint_virtual_fw", "vehicle_torque_setpoint_virtual_fw",\n'
  printf '  "vehicle_local_position"]\n'
} > "$work/rules.sealed8.toml"

# name log rules baseline
cases() {
  scripts/testdata/regenerate.sh list | while read -r name log; do
    rules=examples/rules.default.toml
    [ -f "testdata/rules/$name.toml" ] && rules="testdata/rules/$name.toml"
    echo "$name $log $rules testdata/baselines/$name.params"
  done
  for mb in 10 50 100; do
    echo "large_${mb}mb $work/large_${mb}mb.ulg examples/rules.default.toml testdata/baselines/v1.17.0_vtol_transition.params"
    echo "large_${mb}mb_sealed8 $work/large_${mb}mb.ulg $work/rules.sealed8.toml testdata/baselines/v1.17.0_vtol_transition.params"
  done
}

printf '%-36s %12s %10s %12s\n' "log" "bytes" "median s" "peak RSS KB"
gate=0
while read -r name log rules baseline; do
  times=() peak=0
  for i in $(seq 1 "$RUNS"); do
    out="$work/out/$name/$i"
    mkdir -p "$out"
    # A failing rule exits 1 or 2 and still writes the record; 3 and 4 are errors.
    m="$( { /usr/bin/time -f '%e %M' "$sfr" seal "$log" --rules "$rules" --baseline "$baseline" \
      --key "$work/key/sfr.key" --evaluation-only --seal-time 2026-10-18T15:00:00Z --out "$out" \
      > /dev/null 2>"$out.err" || [ $? -le 2 ]; } 2>&1 >/dev/null; tail -1 "$out.err")"
    [ -n "$(find "$out" -name '*.sfr')" ] || { echo "benchmark.sh: $name: no record written" >&2; cat "$out.err" >&2; exit 1; }
    times+=("${m% *}")
    rss="${m#* }"
    [ "$rss" -gt "$peak" ] && peak="$rss"
  done
  median="$(printf '%s\n' "${times[@]}" | sort -g | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}')"
  printf '%-36s %12s %10s %12s\n' "$name" "$(stat -c %s "$log")" "$median" "$peak"
  if [ "$name" = large_100mb ] || [ "$name" = large_100mb_sealed8 ]; then
    awk -v m="$median" 'BEGIN { exit !(m >= 2) }' && { echo "GATE MISSED: $name seal median ${median} s is not under 2 s"; gate=1; }
    [ "$peak" -gt 262144 ] && echo "REPORT: $name peak RSS ${peak} KB is above 256 MB"
  fi
done < <(cases)
exit $gate
