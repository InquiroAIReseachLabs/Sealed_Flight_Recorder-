#!/usr/bin/env bash
# T2 Seal and verify each golden log with --pubkey (and --ulog); record the Integrity and Rule checks lines.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
R=$A_REPO; SFR=$A_SFR; W=$A_WORK/t02; rm -rf $W; mkdir -p $W
echo "commit: $(git -C $R rev-parse HEAD)"; $SFR --version | head -1
$SFR keygen --evaluation-only --out $W/key > /dev/null
# The golden logs and their seal options, from the list every other script reads.
. $R/scripts/testdata/golden_logs.sh
GOLDEN=$(cd $R && golden_logs | tr ' ' ':'); total=$(wc -w <<< "$GOLDEN")
pass=0; fail=0
printf '%-40s %-5s %-30s %-34s %s\n' LOG SEAL INTEGRITY "FLIGHT RULES" RESULT
for e in $GOLDEN; do
  name=${e%%:*}; log=${e#*:}
  rules=examples/rules.default.toml; [ -f $R/testdata/rules/$name.toml ] && rules=testdata/rules/$name.toml
  extra=$(cd $R && golden_flags_for $name)
  cmd_seal="sfr seal $log --rules $rules --baseline testdata/baselines/$name.params --key key/sfr.key --evaluation-only --seal-time 2026-10-18T15:00:00Z --out out/$name $extra"
  (cd $R && $SFR seal $log --rules $rules --baseline testdata/baselines/$name.params --key $W/key/sfr.key --evaluation-only --seal-time 2026-10-18T15:00:00Z --out $W/out/$name $extra > $W/$name.seal.txt 2>&1); sc=$?
  rec=$(ls $W/out/$name/*.sfr | head -1)
  out=$(cd $R && $SFR verify $rec --pubkey $W/key/sfr.pub --allow-evaluation-key --ulog $log 2>&1); vc=$?
  integ=$(grep -m1 '^Integrity' <<< "$out"); rules_line=$(grep -m1 '^Rule checks' <<< "$out")
  res=FAIL; if [ $vc -eq 0 ] && [[ "$integ" == "Integrity: VERIFIED (record and log)" ]]; then res=PASS; pass=$((pass+1)); else fail=$((fail+1)); fi
  printf '%-40s %-5s %-30s %-34s %s\n' "$name" "$sc" "${integ#Integrity: }" "${rules_line#Rule checks: }" "$res"
  echo "    cmd: $cmd_seal" >> $W/commands.txt
  echo "    cmd: sfr verify out/$name/*.sfr --pubkey key/sfr.pub --allow-evaluation-key --ulog $log   (exit $vc)" >> $W/commands.txt
done
echo; echo "golden logs verified: $pass pass, $fail fail"
check "all $total golden logs seal and verify (record and log)" "$([ $fail -eq 0 ] && [ $pass -eq $total ] && [ $total -ge 19 ]; echo $?)"
echo "--- commands (paths relative to the repo for logs, rules, baselines; key and out/ in the work directory):"; sort -u $W/commands.txt

finish
