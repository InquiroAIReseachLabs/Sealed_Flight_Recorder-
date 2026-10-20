#!/usr/bin/env bash
# T12, second part: the false-pass corpus (testdata/falsepass/, docs/VALIDATION.md). Every crafted
# log and its positive control is sealed with the current build and must give the result
# cases.json states (scripts/testdata/run_falsepass.py). Given an earlier build, the same table is
# printed for it, with no check, to show which cases it let through.
#
#   scripts/claims_audit/t12_falsepass.sh [<earlier sfr>]
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$A_REPO" || exit 1
n_attack="$(python3 -I -c 'import json; c=json.load(open("testdata/falsepass/cases.json")); print(sum(x["kind"]=="attack" for x in c), sum(x["kind"]!="attack" for x in c))')"
echo "false-pass corpus: $n_attack (attack cases, positive controls)"
python3 -I scripts/testdata/make_falsepass.py --check testdata/falsepass
check "testdata/falsepass is what make_falsepass.py writes" $?
echo; echo "current build: $("$A_SFR" --version | head -1)"
python3 -I scripts/testdata/run_falsepass.py "$A_SFR" --table
check "every case gives its stated result on the current build" $?
if [ -n "${1:-}" ]; then
  echo; echo "earlier build: $("$1" --version 2>&1 | head -1) (not checked; shows what it let through)"
  python3 -I scripts/testdata/run_falsepass.py "$1" --table --no-check
fi
finish
