#!/usr/bin/env bash
# make_example_reports.sh: re-seals the example records and reports in examples/reports/
# (SPEC B1.8).
#
# Seals the v1.17.0 golden logs vtol_transition and failsafe_gps_loss with the default rules,
# their golden baselines, and one --seal-time, under a new evaluation key. Only the public half,
# examples/reports/sfr.pub, is kept; the private half never leaves a temporary directory and is
# shredded at the end. Each record is then verified against its log. Run it after a record or
# report format change: crates/sfr/tests/seal_verify.rs fails when the examples no longer
# render from their records or verify.
#
# Usage: scripts/make_example_reports.sh [<sfr>]   (default: target/release/sfr)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
sfr="${1:-target/release/sfr}"
out=examples/reports
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"$sfr" keygen --evaluation-only --out "$work" > /dev/null
rm -f "$out"/*.sfr "$out"/*.sfr.md "$out/sfr.pub"
cp "$work/sfr.pub" "$out/sfr.pub"
n=0
for name in vtol_transition failsafe_gps_loss; do
  log="testdata/sitl/v1.17.0/$name.ulg"
  # A failing rule exits 1 or 2 and still writes the record; anything else is a failure.
  rc=0
  "$sfr" seal "$log" --rules examples/rules.default.toml \
    --baseline "testdata/baselines/v1.17.0_$name.params" --key "$work/sfr.key" \
    --evaluation-only --seal-time 2026-10-18T15:00:00Z --out "$out" > /dev/null || rc=$?
  [ "$rc" -le 2 ] || { echo "$name: seal exited $rc" >&2; exit 1; }
  "$sfr" verify "$out/$name.sfr" --pubkey "$out/sfr.pub" --ulog "$log" > /dev/null
  n=$((n + 1))
done
shred -u "$work/sfr.key" 2> /dev/null || rm -f "$work/sfr.key"
echo "examples/reports: sealed and verified $n records and their reports"
