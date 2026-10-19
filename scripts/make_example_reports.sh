#!/usr/bin/env bash
# make_example_reports.sh: re-seals the example records and reports in examples/reports/
# (SPEC B1.8).
#
# Seals four v1.17.0 golden logs with their golden baselines, one --seal-time, and a new
# evaluation key: vtol_transition, failsafe_gps_loss and gz_quadtailsitter_transition with the
# default rules; gz_x500_vision_hover with its golden rules (which seal vehicle_visual_odometry)
# plus [authorized_sources] listing only the autopilot itself, written to
# examples/reports/gz_x500_vision_hover.rules.toml, so R7 fails on PX4's own start-up DO_GRIPPER
# command (docs/DIAGNOSTIC.md item 12.3). Only the public half of the key, examples/reports/sfr.pub,
# is kept; the private half never leaves a temporary directory and is shredded at the end. Each
# record is then verified against its log. Run it after a record or report format change:
# crates/sfr/tests/seal_verify.rs fails when the examples no longer render from their records
# or verify.
#
# Usage: scripts/make_example_reports.sh [<sfr>]   (default: target/release/sfr)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
sfr="${1:-target/release/sfr}"
out=examples/reports
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"$sfr" keygen --evaluation-only --out "$work" > /dev/null
rm -f "$out"/*.sfr "$out"/*.sfr.md "$out/sfr.pub" "$out"/*.rules.toml
cp "$work/sfr.pub" "$out/sfr.pub"
{
  cat testdata/rules/v1.17.0_gz_x500_vision_hover.toml
  printf '\n# Added for this example: only the autopilot itself (system 1, component 1) may command,\n'
  printf '# so R7 fails on the DO_GRIPPER that PX4 publishes at start-up with uninitialized source ids.\n'
  printf '[authorized_sources]\nsources = [{ system = 1, component = 1 }]\n'
} > "$out/gz_x500_vision_hover.rules.toml"
n=0
for name in vtol_transition failsafe_gps_loss gz_quadtailsitter_transition gz_x500_vision_hover; do
  log="testdata/sitl/v1.17.0/$name.ulg"
  rules=examples/rules.default.toml
  [ -f "$out/$name.rules.toml" ] && rules="$out/$name.rules.toml"
  # A failing rule exits 1 or 2 and still writes the record; anything else is a failure.
  rc=0
  "$sfr" seal "$log" --rules "$rules" \
    --baseline "testdata/baselines/v1.17.0_$name.params" --key "$work/sfr.key" \
    --evaluation-only --seal-time 2026-10-18T15:00:00Z --out "$out" > /dev/null || rc=$?
  [ "$rc" -le 2 ] || { echo "$name: seal exited $rc" >&2; exit 1; }
  "$sfr" verify "$out/$name.sfr" --pubkey "$out/sfr.pub" --ulog "$log" > /dev/null
  n=$((n + 1))
done
shred -u "$work/sfr.key" 2> /dev/null || rm -f "$work/sfr.key"
echo "examples/reports: sealed and verified $n records and their reports"
