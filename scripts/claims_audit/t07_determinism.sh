#!/usr/bin/env bash
# T7 Determinism: seal each golden log twice with the same key and --seal-time and compare the bytes of the record and
# the report. (That the CI job does the same on x86_64, aarch64 and armv7 under QEMU is stated in docs/CLAIMS_AUDIT.md.)
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
R=$A_REPO; SFR=$A_SFR; W=$A_WORK/t07; rm -rf $W; mkdir -p $W; cd $R
echo "commit $(git rev-parse HEAD)"
$SFR keygen --evaluation-only --out $W/key > /dev/null
# The golden logs and their seal options, from the list every other script reads.
. $R/scripts/testdata/golden_logs.sh
n=0; same=0; total=$(golden_logs | wc -l)
while read -r name log; do
  rules=examples/rules.default.toml; [ -f testdata/rules/$name.toml ] && rules=testdata/rules/$name.toml
  extra=$(golden_flags_for $name)
  for run in a b; do
    $SFR seal $log --rules $rules --baseline testdata/baselines/$name.params --key $W/key/sfr.key --evaluation-only --seal-time 2026-10-18T15:00:00Z --out $W/$name/$run $extra > /dev/null 2>&1
  done
  f=$(ls $W/$name/a/*.sfr); g=$(ls $W/$name/b/*.sfr); n=$((n+1))
  if cmp -s $f $g && cmp -s $f.md $g.md; then same=$((same+1)); r=identical; else r=DIFFERENT; fi
  printf '%-40s %s  sha256(record)=%s  sha256(report)=%s\n' $name $r $(sha256sum < $f | cut -c1-16) $(sha256sum < $f.md | cut -c1-16)
done < <(golden_logs)
echo; echo "same input, same key, same --seal-time sealed twice: $same of $n logs byte-identical (record and report)"
echo
echo "different keys must differ (sanity): $(
 $SFR keygen --evaluation-only --out $W/key2 > /dev/null; $SFR seal testdata/synthetic/custom_detection.ulg --rules testdata/rules/synthetic_custom_detection.toml --baseline testdata/baselines/synthetic_custom_detection.params --key $W/key2/sfr.key --evaluation-only --seal-time 2026-10-18T15:00:00Z --out $W/k2 >/dev/null 2>&1; cmp -s $W/k2/custom_detection.sfr $W/synthetic_custom_detection/a/custom_detection.sfr && echo SAME-BAD || echo different)"

check "every golden log seals to the same bytes twice (record and report)" "$([ $same -eq $n ] && [ $n -eq $total ] && [ $n -ge 19 ]; echo $?)"
check "a different key gives a different record" "$([ "$(cmp -s $W/k2/custom_detection.sfr $W/synthetic_custom_detection/a/custom_detection.sfr && echo same)" != same ]; echo $?)"
finish
