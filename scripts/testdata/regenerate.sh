#!/usr/bin/env bash
# Regenerates the golden test data and checks it against the independent oracle.
#
#   scripts/testdata/regenerate.sh baselines   # testdata/baselines/*.params   (needs pyulog)
#   scripts/testdata/regenerate.sh oracle      # testdata/expected/oracle/*    (needs pyulog, numpy)
#   scripts/testdata/regenerate.sh expected    # testdata/expected/*.json      (needs a built sfr)
#   scripts/testdata/regenerate.sh compare     # sfr expected versus oracle    (Python only)
#
# The expected files are sfr's own `seal --dry-run --json` output. They count as reviewed
# only while `compare` reports 0 differences against the oracle, which is written from
# docs/SPEC.md on pyulog and shares no code with sfr.
set -euo pipefail
cd "$(dirname "$0")/../.."

SFR="${SFR:-target/debug/sfr}"
RULES=examples/rules.default.toml

# name -> log path
logs() {
  echo "pyulog_sample testdata/pyulog/sample.ulg"
  for f in testdata/sitl/*/*.ulg; do
    v=$(basename "$(dirname "$f")")
    echo "${v}_$(basename "$f" .ulg) $f"
  done
  for f in testdata/synthetic/*.ulg; do
    echo "synthetic_$(basename "$f" .ulg) $f"
  done
}

case "${1:-}" in
  baselines)
    mkdir -p testdata/baselines
    logs | while read -r name log; do
      python3 -I scripts/testdata/make_baseline.py "$log" "testdata/baselines/$name.params"
    done ;;
  oracle)
    mkdir -p testdata/expected/oracle
    logs | while read -r name log; do
      python3 -I scripts/testdata/oracle.py "$log" > "testdata/expected/oracle/$name.oracle.json"
    done ;;
  expected)
    logs | while read -r name log; do
      set +e
      "$SFR" seal "$log" --rules "$RULES" --baseline "testdata/baselines/$name.params" --dry-run --json \
        > "testdata/expected/$name.json"
      code=$?
      set -e
      echo "$name exit $code"
    done ;;
  compare)
    status=0
    logs | { while read -r name _; do
      python3 -I scripts/testdata/compare_oracle.py "testdata/expected/$name.json" \
        "testdata/expected/oracle/$name.oracle.json" || status=1
    done; exit $status; } ;;
  *)
    sed -n '2,12p' "$0"; exit 4 ;;
esac
