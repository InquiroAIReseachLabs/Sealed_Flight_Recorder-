#!/usr/bin/env bash
# make_fuzz_seeds.sh: re-seals the seed records of the `sfr_verify` fuzz target
# (fuzz/seeds/sfr_verify/, fuzz/README.md) with a new evaluation key. Run it after a record
# format change: crates/sfr/tests/seal_verify.rs fails when a seed no longer verifies. Only the
# public half of the key, fuzz/seeds/sfr_verify_key.pub, is kept; the private half never leaves a
# temporary directory.
#
# Usage: scripts/make_fuzz_seeds.sh [<sfr>]   (default: target/release/sfr)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
sfr="${1:-target/release/sfr}"
out=fuzz/seeds/sfr_verify
logs=fuzz/seeds/ulog_ingest
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
time=2026-10-18T15:00:00Z

"$sfr" keygen --evaluation-only --out "$work/key" > /dev/null
rm -f "$out"/*.sfr
cp "$work/key/sfr.pub" fuzz/seeds/sfr_verify_key.pub

# seed <log> <rules> <baseline> <name> [extra seal option]: seals <log> and keeps the record as
# $out/<name>.sfr. The pyulog sample carries no PX4 version sfr can read, so it is sealed with
# --allow-untested-version.
seed() {
  local log="$1" rules="$2" baseline="$3" name="$4" rc=0
  rm -rf "$work/sealed"
  # A failing rule exits 1 or 2 and still writes the record; anything else is a failure.
  "$sfr" seal "$log" --rules "$rules" --baseline "$baseline" --key "$work/key/sfr.key" \
    --evaluation-only --seal-time "$time" --out "$work/sealed" ${5:+"$5"} > /dev/null || rc=$?
  [ "$rc" -le 2 ] || { echo "make_fuzz_seeds: seal of $log failed (exit $rc)" >&2; exit 1; }
  cp "$work/sealed/$(basename "${log%.ulg}").sfr" "$out/$name.sfr"
}

seed $logs/pyulog_sample_first_65516.ulg examples/rules.default.toml \
  testdata/baselines/pyulog_sample.params pyulog_sample_first_65516 --allow-untested-version
seed $logs/sitl_v1.17.0_failsafe_gps_loss_shrunk.ulg examples/rules.extended.toml \
  testdata/baselines/v1.17.0_failsafe_gps_loss.params sitl_v1.17.0_failsafe_gps_loss_shrunk
seed $logs/sitl_v1.17.0_vtol_transition_abort_shrunk.ulg examples/rules.extended.toml \
  testdata/baselines/v1.17.0_vtol_transition_abort.params sitl_v1.17.0_vtol_transition_abort_shrunk
seed $logs/sitl_v1.17.0_gz_x500_vision_hover_shrunk.ulg testdata/rules/v1.17.0_gz_x500_vision_hover.toml \
  testdata/baselines/v1.17.0_gz_x500_vision_hover.params sitl_v1.17.0_gz_x500_vision_hover_shrunk
seed testdata/synthetic/custom_detection.ulg testdata/rules/synthetic_custom_detection.toml \
  testdata/baselines/synthetic_custom_detection.params synthetic_custom_detection

# Every seed must verify with the kept public key.
for f in "$out"/*.sfr; do
  "$sfr" verify "$f" --pubkey fuzz/seeds/sfr_verify_key.pub --allow-evaluation-key --no-report > /dev/null 2>&1 \
    || { echo "make_fuzz_seeds: $f does not verify" >&2; exit 1; }
done
echo "fuzz/seeds/sfr_verify: sealed and verified $(ls "$out"/*.sfr | wc -l) seed records"
