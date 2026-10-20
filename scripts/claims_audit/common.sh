# common.sh: the settings every claims-audit script reads (docs/CLAIMS_AUDIT.md). Sourced, not run.
#   A_REPO  the checkout under test (default: this checkout). The scripts only read it.
#   A_SFR   the sfr binary built from that checkout (default: $A_REPO/target/release/sfr).
#   A_WORK  where every script writes (default: $TMPDIR/sfr-claims-audit). Never inside A_REPO.
A_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
A_REPO="${A_REPO:-$(cd "$A_HERE/../.." && pwd)}"
A_SFR="${A_SFR:-$A_REPO/target/release/sfr}"
A_WORK="${A_WORK:-${TMPDIR:-/tmp}/sfr-claims-audit}"
export A_HERE A_REPO A_SFR A_WORK
mkdir -p "$A_WORK"
# check <condition description> <exit status of the condition>: prints PASS or FAIL for one condition
# and counts failures in $A_FAILS.
A_FAILS=0
check() { if [ "$2" -eq 0 ]; then echo "  PASS: $1"; else echo "  FAIL: $1"; A_FAILS=$((A_FAILS + 1)); fi; }
# finish: the last line of a test: its verdict and the exit status.
finish() { if [ "$A_FAILS" -eq 0 ]; then echo "RESULT: PASS"; exit 0; else echo "RESULT: FAIL ($A_FAILS)"; exit 1; fi; }
