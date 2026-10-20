#!/usr/bin/env bash
# T2 Seal and verify each golden log with --pubkey (and --ulog); record the Integrity and Rule checks lines.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
R=$A_REPO; SFR=$A_SFR; W=$A_WORK/t02; rm -rf $W; mkdir -p $W
echo "commit: $(git -C $R rev-parse HEAD)"; $SFR --version | head -1
$SFR keygen --evaluation-only --out $W/key > /dev/null
GOLDEN="pyulog_sample:testdata/pyulog/sample.ulg v1.14.4_mc_flight:testdata/sitl/v1.14.4/mc_flight.ulg
v1.17.0_failsafe_battery_empty:testdata/sitl/v1.17.0/failsafe_battery_empty.ulg v1.17.0_failsafe_gps_loss:testdata/sitl/v1.17.0/failsafe_gps_loss.ulg
v1.17.0_gz_quadtailsitter_transition:testdata/sitl/v1.17.0/gz_quadtailsitter_transition.ulg v1.17.0_gz_x500_vision_hover:testdata/sitl/v1.17.0/gz_x500_vision_hover.ulg
v1.17.0_mc_flight_1:testdata/sitl/v1.17.0/mc_flight_1.ulg v1.17.0_mc_flight_2:testdata/sitl/v1.17.0/mc_flight_2.ulg
v1.17.0_payload_two_sources:testdata/sitl/v1.17.0/payload_two_sources.ulg v1.17.0_vtol_transition:testdata/sitl/v1.17.0/vtol_transition.ulg
v1.17.0_vtol_quadchute:testdata/sitl/v1.17.0/vtol_quadchute.ulg v1.17.0_vtol_transition_abort:testdata/sitl/v1.17.0/vtol_transition_abort.ulg
synthetic_r4_quadchute_on_disarm:testdata/synthetic/r4_quadchute_on_disarm.ulg synthetic_custom_detection:testdata/synthetic/custom_detection.ulg"
pass=0; fail=0
printf '%-40s %-5s %-30s %-34s %s\n' LOG SEAL INTEGRITY "FLIGHT RULES" RESULT
for e in $GOLDEN; do
  name=${e%%:*}; log=${e#*:}
  rules=examples/rules.default.toml; [ -f $R/testdata/rules/$name.toml ] && rules=testdata/rules/$name.toml
  extra=""; [ $name = pyulog_sample ] && extra="--allow-untested-version"
  cmd_seal="sfr seal $log --rules $rules --baseline testdata/baselines/$name.params --key key/sfr.key --evaluation-only --seal-time 2026-10-18T15:00:00Z --out out/$name $extra"
  (cd $R && $SFR seal $log --rules $rules --baseline testdata/baselines/$name.params --key $W/key/sfr.key --evaluation-only --seal-time 2026-10-18T15:00:00Z --out $W/out/$name $extra > $W/$name.seal.txt 2>&1); sc=$?
  rec=$W/out/$(basename ${log%.ulg}).sfr; [ $name = pyulog_sample ] && rec=$W/out/$name/sample.sfr
  rec=$(ls $W/out/$name/*.sfr | head -1)
  out=$(cd $R && $SFR verify $rec --pubkey $W/key/sfr.pub --allow-evaluation-key --ulog $log 2>&1); vc=$?
  integ=$(grep -m1 '^Integrity' <<< "$out"); rules_line=$(grep -m1 '^Rule checks' <<< "$out")
  res=FAIL; if [ $vc -eq 0 ] && [[ "$integ" == "Integrity: VERIFIED (record and log)" ]]; then res=PASS; pass=$((pass+1)); else fail=$((fail+1)); fi
  printf '%-40s %-5s %-30s %-34s %s\n' "$name" "$sc" "${integ#Integrity: }" "${rules_line#Rule checks: }" "$res"
  echo "    cmd: $cmd_seal" >> $W/commands.txt
  echo "    cmd: sfr verify out/$name/*.sfr --pubkey key/sfr.pub --allow-evaluation-key --ulog $log   (exit $vc)" >> $W/commands.txt
done
echo; echo "golden logs verified: $pass pass, $fail fail"
check "all 14 golden logs seal and verify (record and log)" "$([ $fail -eq 0 ] && [ $pass -eq 14 ]; echo $?)"
echo "--- commands (paths relative to the repo for logs, rules, baselines; key and out/ in the work directory):"; sort -u $W/commands.txt

finish
