#!/usr/bin/env bash
# claims_audit.sh: runs the claims audit (docs/CLAIMS_AUDIT.md), T1 to T11, and T12 when an earlier build
# is given, against a fresh clone of one commit, writing one log per test and a summary. It does not
# modify the checkout it tests: the clone is read-only to the tests, and every file they make is under
# A_WORK. Needs the network for T1 (Rust toolchain, crates.io) and these tools: git, curl, openssl 3,
# python3, strace, unshare, softhsm2-util, pkcs11-tool, swtpm, tpm2-tools, tpm2-abrmd, dbus-run-session.
#
#   scripts/claims_audit.sh [--earlier <sfr built from the commit before the fixes>]
#
#   A_CLONE_URL   what to clone (default: the origin of this checkout)
#   A_COMMIT      the commit to audit (default: the head of the clone)
#   A_WORK        where everything is written (default: ${TMPDIR:-/tmp}/sfr-claims-audit); logs in $A_WORK/logs
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
earlier=""; [ "${1:-}" = "--earlier" ] && earlier="$2"
export A_WORK="${A_WORK:-${TMPDIR:-/tmp}/sfr-claims-audit}"
url="${A_CLONE_URL:-$(git -C "$here/.." remote get-url origin 2> /dev/null || echo "$here/..")}"
rm -rf "$A_WORK"; mkdir -p "$A_WORK/logs"
echo "claims audit: $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(uname -srm), $(nproc) CPUs, $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')"
git clone -q "$url" "$A_WORK/repo" || exit 1
[ -n "${A_COMMIT:-}" ] && git -C "$A_WORK/repo" checkout -q "$A_COMMIT"
export A_REPO="$A_WORK/repo" A_CLONE_URL="$url"
commit="$(git -C "$A_REPO" rev-parse HEAD)"; echo "commit: $commit"
git -C "$A_REPO" log -1 --format='subject: %s' ; echo
run() { # <id> <title> <command...>
  local id="$1" title="$2"; shift 2
  "$@" > "$A_WORK/logs/$id.log" 2>&1; local rc=$?
  printf '%-4s %-62s %s\n' "$id" "$title" "$([ $rc -eq 0 ] && echo PASS || echo "FAIL (exit $rc)")" | tee -a "$A_WORK/summary.txt"
}
# T1 clones and builds on its own, from a clean toolchain; the others use its binary and the untouched clone.
A_CLONE_URL="$url" A_COMMIT_FOR_T1="$commit" run T1 "Quickstart, cold start (Rust install + clone + build + seal + verify)" "$here/claims_audit/t01_quickstart.sh"
export A_SFR="$A_WORK/sfr-from-t01"
[ -x "$A_SFR" ] || { echo "T1 left no binary; the other tests need one" >&2; exit 1; }
run T2 "Seal and verify each golden log with --pubkey" "$here/claims_audit/t02_golden.sh"
run T3 "Tamper tests (24 cases)" python3 -I "$here/claims_audit/t03_tamper.py"
run T4-T5 "No trusted key; PX4 versions; malformed and foreign formats" python3 -I "$here/claims_audit/t04_t05_inputs.py"
run T6 "Offline: empty network namespace, strace" "$here/claims_audit/t06_offline.sh"
run T7 "Determinism: same inputs, same bytes" "$here/claims_audit/t07_determinism.sh"
run T8 "Rules R1 to R7, one failing fixture each" python3 -I "$here/claims_audit/t08_rules.py"
run T9 "Reproducible build, twice from clean and another directory" "$here/claims_audit/t09_reproducible.sh"
run T10 "Key custody: SoftHSM, swtpm, chain, revoked certificate" "$here/claims_audit/t10_custody.sh"
run T11 "Public text scan" "$here/claims_audit/t11_text_scan.sh"
if [ -n "$earlier" ]; then run T12 "Twelve attacks: succeed on the earlier build, fail on this one" "$here/claims_audit/t12_attacks.sh" "$earlier" "$A_SFR"
else echo "T12  (skipped: give --earlier <sfr built from the commit before the fixes>)" | tee -a "$A_WORK/summary.txt"; fi
dirty="$(git -C "$A_REPO" status --porcelain | wc -l)"
printf '%-4s %-62s %s\n' "-" "The audited checkout was not modified by the tests" "$([ "$dirty" -eq 0 ] && echo PASS || echo "FAIL ($dirty changed paths)")" | tee -a "$A_WORK/summary.txt"
echo; echo "logs: $A_WORK/logs"
! grep -q FAIL "$A_WORK/summary.txt"
