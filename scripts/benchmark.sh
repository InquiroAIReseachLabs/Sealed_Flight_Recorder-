#!/usr/bin/env bash
# benchmark.sh: seal time, standalone verify time, and peak memory of a built sfr on this machine
# (SPEC B1.10 Performance and Peak memory).
#
# Runs from the repository or from the benchmark kit (scripts/build_benchmark_kit.sh) and builds
# nothing: it needs bash 5 or later, GNU time at /usr/bin/time (the Debian and Ubuntu package
# "time") for the maximum resident set size, and the coreutils, awk, sed, find and getconf it
# checks for at start. No compiler, no Python. A missing tool stops it with exit 2.
# docs/BENCHMARK.md says how to run it on another machine.
#
# For every golden log, and for logs of 10, 50 and 100 MB built from the golden VTOL flight, it
# seals RUNS times with an evaluation key and reports the median seal wall time, the median wall
# time of a standalone `sfr verify` of the record, and the largest maximum resident set size of
# seal. Each large log is sealed twice over: with the default rules, and with the eight
# highest-rate topics of that flight in [sealed_topics] (`_sealed8`), so the sealed topic digests
# are inside the gate.
#
# The large logs are built from the golden VTOL flight (24.3 MB) for size only, with the segments
# listed in scripts/benchmark/vtol_transition.segments (runs of whole data records with no
# subscription or info record, at most 1 MB each, written by scripts/benchmark/make_segments.py).
# The 10 MB log is the flight cut at the end of the first segment that reaches 10 MB; the 50 and
# 100 MB logs are one full copy of the flight, then its segments appended in order, again and
# again, until the log reaches the size. Each log overshoots its size by under 1 MB. They are not
# real flights: timestamps restart with each repetition, the 10 MB log ends mid-flight, and R5 may
# fail on them. The record is still written and timed.
#
# Gates (SPEC B1.10): on x86_64 each 100 MB seal median under 2 s; on aarch64 under 4 s, which
# counts only on real aarch64 hardware, not emulation; no timing gate on any other architecture.
# A seal peak above 256 MB on a 100 MB log must be reported with its cause before work continues.
# Exits 1 if a gate is missed or a 100 MB peak is above 256 MB, 2 on a usage or setup error.
#
# Usage: scripts/benchmark.sh --sfr <path to sfr> [--runs N]   (N defaults to 5)
set -euo pipefail
export LC_ALL=C

die() { echo "benchmark.sh: $*" >&2; exit 2; }
sfr="" runs=5
while [ $# -gt 0 ]; do
  case "$1" in
    --sfr) [ $# -ge 2 ] || die "--sfr needs a path"; sfr="$2"; shift 2 ;;
    --runs) [ $# -ge 2 ] || die "--runs needs a number"; runs="$2"; shift 2 ;;
    *) die "usage: $0 --sfr <path to sfr> [--runs N]" ;;
  esac
done
[ -n "$sfr" ] || die "usage: $0 --sfr <path to sfr> [--runs N]"
[ -f "$sfr" ] && [ -x "$sfr" ] || die "$sfr is not an executable file"
sfr="$(cd "$(dirname "$sfr")" && pwd -P)/$(basename "$sfr")"
[[ "$runs" =~ ^[1-9][0-9]*$ ]] || die "--runs must be a positive integer, got $runs"
cd "$(dirname "${BASH_SOURCE[0]}")/.."

[ "${BASH_VERSINFO[0]}" -ge 5 ] || die "bash 5 or later is required (EPOCHREALTIME), this is $BASH_VERSION"
/usr/bin/time -f %M true > /dev/null 2>&1 || die "GNU time at /usr/bin/time is required (package \"time\")"
for tool in awk basename cat cp cut dirname find getconf head mkdir mktemp od rm sed sha256sum sort tail tr uname wc; do
  command -v "$tool" > /dev/null || die "$tool is required"
done
version="$("$sfr" --version 2> /dev/null | head -1)" || die "cannot run $sfr"

manifest=scripts/benchmark/vtol_transition.segments
src="$(awk '$1 == "source" { print $2 }' "$manifest")"
[ -f "$src" ] || die "the flight the large logs repeat is missing: $src"
[ "$(sha256sum "$src" | cut -d' ' -f1)" = "$(awk '$1 == "sha256" { print $2 }' "$manifest")" ] \
  || die "$src does not match $manifest"
# shellcheck source=scripts/testdata/golden_logs.sh
. scripts/testdata/golden_logs.sh

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Microseconds since the epoch.
now_us() { local t="$EPOCHREALTIME"; echo "${t/./}"; }

# The middle value of the numbers on stdin (the lower one of the two middle values for an even count).
median() { sort -n | awk '{ a[NR] = $1 } END { print a[int((NR + 1) / 2)] }'; }

# The hardware this runs on: architecture, CPU model, cores, memory, kernel, OS, board model.
hardware() {
  local cpu="" mem os="" board=""
  command -v lscpu > /dev/null && cpu="$(lscpu | awk -F: '/^Model name/ { sub(/^[ \t]+/, "", $2); print $2; exit }')"
  [ -n "$cpu" ] || cpu="$(awk -F: '/^model name/ { sub(/^[ \t]+/, "", $2); print $2; exit }' /proc/cpuinfo)"
  [ -n "$cpu" ] || cpu="unknown"
  mem="$(awk '/^MemTotal/ { printf "%.1f GiB", $2 / 1048576 }' /proc/meminfo)"
  [ -r /etc/os-release ] && os="$(awk -F= '$1 == "PRETTY_NAME" { gsub(/"/, "", $2); print $2 }' /etc/os-release)"
  [ -r /proc/device-tree/model ] && board="; board $(tr -d '\0' < /proc/device-tree/model)"
  echo "hardware: $(uname -m); CPU $cpu; $(getconf _NPROCESSORS_ONLN) cores; memory $mem; kernel $(uname -r); OS ${os:-unknown}$board"
}

# build_large <out> <bytes>: a log of at least <bytes>, cut at a record boundary. Below the
# flight's size, the flight up to the end of the first segment that reaches <bytes> (every
# subscription before that point included); above it, one copy of the flight, then its segments
# in order until <bytes>.
build_large() {
  local out="$1" want="$2" size kind off len
  if [ "$want" -lt "$(wc -c < "$src")" ]; then
    size="$(awk -v w="$want" '$1 == "segment" && $2 + $3 >= w { print $2 + $3; exit }' "$manifest")"
    head -c "$size" "$src" > "$out"
    [ "$(wc -c < "$out")" -eq "$size" ] || die "$out: short copy"
    return
  fi
  cp "$src" "$out"
  size="$(wc -c < "$out")"
  while [ "$size" -lt "$want" ]; do
    while read -r kind off len; do
      [ "$kind" = segment ] || continue
      # head stops tail early on purpose; the byte count below checks the copy instead.
      set +o pipefail
      tail -c +"$((off + 1))" "$src" | head -c "$len" >> "$out"
      set -o pipefail
      size=$((size + len))
      [ "$size" -lt "$want" ] || break
    done < "$manifest"
  done
  [ "$(wc -c < "$out")" -eq "$size" ] || die "$out: short copy"
}

"$sfr" keygen --evaluation-only --out "$work/key" > /dev/null
{ cat examples/rules.default.toml
  printf '\n[sealed_topics]\ntopics = ["sensor_combined", "ekf2_timestamps", "vehicle_attitude",\n'
  printf '  "vehicle_thrust_setpoint_virtual_mc", "vehicle_torque_setpoint_virtual_mc",\n'
  printf '  "vehicle_thrust_setpoint_virtual_fw", "vehicle_torque_setpoint_virtual_fw",\n'
  printf '  "vehicle_local_position"]\n'
} > "$work/rules.sealed8.toml"
for mb in 10 50 100; do build_large "$work/large_${mb}mb.ulg" "$((mb * 1000000))"; done

# name log rules baseline
cases() {
  golden_logs | while read -r name log; do
    echo "$name $log $(golden_rules_for "$name") testdata/baselines/$name.params"
  done
  for mb in 10 50 100; do
    echo "large_${mb}mb $work/large_${mb}mb.ulg examples/rules.default.toml testdata/baselines/v1.17.0_vtol_transition.params"
    echo "large_${mb}mb_sealed8 $work/large_${mb}mb.ulg $work/rules.sealed8.toml testdata/baselines/v1.17.0_vtol_transition.params"
  done
}

# The gate is the binary's architecture, and only when the machine runs it natively: an aarch64
# binary under QEMU on an x86_64 machine has no gate. ELF e_machine, bytes 18 and 19.
machine="$(uname -m)"
case "$(od -A n -t u1 -j 18 -N 2 "$sfr" 2> /dev/null | tr -s ' ' | sed 's/^ //')" in
  "62 0") arch=x86_64 ;;
  "183 0") arch=aarch64 ;;
  "40 0") arch=armv7 ;;
  *) die "$sfr is not an x86_64, aarch64 or armv7 ELF executable" ;;
esac
native=no
case "$arch:$machine" in
  x86_64:x86_64 | aarch64:aarch64 | armv7:armv7l | armv7:armv8l | armv7:aarch64) native=yes ;;
esac
echo "benchmark: $version; binary $arch, machine $machine; $runs run(s) per log"
hardware
echo "note: the large_* logs are built for size only from the golden VTOL flight ($src) and the whole-record segments of it in $manifest: large_10mb is the flight cut at a record boundary; large_50mb and large_100mb are one copy of the flight followed by its segments repeated (concatenated, timestamps restart). They are not real flights."
echo "| log | bytes | seal median (s) | verify median (ms) | seal peak RSS (KB) |"
echo "|---|---|---|---|---|"
status=0
gates=()
while read -r name log rules baseline; do
  seals=() verifies=() peak=0
  for ((i = 1; i <= runs; i++)); do
    out="$work/out/$name/$i"
    mkdir -p "$out"
    rc=0 start="$(now_us)"
    /usr/bin/time -o "$out.time" -f %M "$sfr" seal "$log" --rules "$rules" --baseline "$baseline" \
      --key "$work/key/sfr.key" --evaluation-only --seal-time 2026-10-18T15:00:00Z --out "$out" $(golden_flags_for "$name") \
      > /dev/null 2> "$out.err" || rc=$?
    end="$(now_us)"
    # A failing rule exits 1 or 2 and still writes the record; 3 and 4 are errors.
    [ "$rc" -le 2 ] || { cat "$out.err" >&2; die "$name: seal exited $rc"; }
    record="$(find "$out" -name '*.sfr')"
    [ -n "$record" ] || { cat "$out.err" >&2; die "$name: no record written"; }
    seals+=("$((end - start))")
    rss="$(tail -1 "$out.time")"
    [[ "$rss" =~ ^[1-9][0-9]*$ ]] || die "$name: GNU time gave no maximum resident set size: $rss"
    [ "$rss" -gt "$peak" ] && peak="$rss"
    start="$(now_us)"
    "$sfr" verify "$record" --pubkey "$work/key/sfr.pub" --allow-evaluation-key --no-report > /dev/null || die "$name: standalone verify failed"
    end="$(now_us)"
    verifies+=("$((end - start))")
  done
  [ "${#seals[@]}" -eq "$runs" ] && [ "${#verifies[@]}" -eq "$runs" ] || die "$name: not every run was timed"
  seal_s="$(printf '%s\n' "${seals[@]}" | median | awk '{ printf "%.3f", $1 / 1e6 }')"
  verify_ms="$(printf '%s\n' "${verifies[@]}" | median | awk '{ printf "%.2f", $1 / 1e3 }')"
  echo "| $name | $(wc -c < "$log") | $seal_s | $verify_ms | $peak |"
  if [ "$name" = large_100mb ] || [ "$name" = large_100mb_sealed8 ]; then
    case "$native:$arch" in
      yes:x86_64) limit=2 ;;
      yes:aarch64) limit=4 ;;
      *) limit="" ;;
    esac
    if [ "$native" = no ]; then
      gates+=("gate: $name seal median $seal_s s: no timing gate, the binary ($arch) does not run natively on this $machine machine (SPEC B1.10)")
    elif [ -z "$limit" ]; then
      gates+=("gate: $arch $name seal median $seal_s s: no timing gate on $arch (SPEC B1.10)")
    elif awk -v m="$seal_s" -v l="$limit" 'BEGIN { exit !(m < l) }'; then
      gates+=("gate: $arch $name seal median $seal_s s, under $limit s: PASS")
    else
      gates+=("gate: $arch $name seal median $seal_s s, not under $limit s: FAIL")
      status=1
    fi
    if [ "$peak" -gt 262144 ]; then
      gates+=("memory: $name seal peak RSS $peak KB is above 256 MB: REPORT THE CAUSE BEFORE WORK CONTINUES")
      status=1
    else
      gates+=("memory: $name seal peak RSS $peak KB, not above 256 MB (262144 KB)")
    fi
  fi
done < <(cases)
printf '%s\n' "${gates[@]}"
[ "$arch:$native" != aarch64:yes ] || echo "gate: the aarch64 gate counts only on real aarch64 hardware, not emulation (SPEC B1.10)"
exit $status
