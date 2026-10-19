# vtol_transition_abort.ulg

Generated for this project in PX4 v1.17.0 SITL with the built-in SIH simulator. Not a third-party log.

| Field | Value |
|---|---|
| PX4 | `v1.17.0`, commit `d6f12ad1c4f70ad3230afd7d86e971421e02fef4` |
| Airframe | `10043_sihsim_standard_vtol` |
| Scenario | Standard VTOL: forward transition aborted by an RTL command before reaching fixed wing (R6 ABORT case). |
| SHA-256 | `13489ca66b7c1023278d7b13dbb621e882a7bbe001ceaad2f2beb257cdd9bc79` |
| Size | 15324267 bytes |

The script that drove the flight (the working directory of the generating machine is written `/path/to/work`):

```bash
#!/bin/bash
# vtol_transition_abort.sh <rootfs_dir> <scenario_name>
# Scenario C-abort (extra, for SPEC R6): SIH standard VTOL, arm, takeoff, `commander transition` to FW, then
# ~0.8 s later (while vtol state is TRANSITION_TO_FW; a full front transition took ~3 s in vtol_transition)
# `commander mode auto:rtl`. vtol_att_control_main.cpp vehicle_status_poll() aborts a front transition when RTL
# is entered (sets _transition_command = MC), standard.cpp then goes TRANSITION_TO_FW -> MC_MODE directly.
# RTL at home lands; `commander land` only if still airborne after 90 s. Fresh rootfs, no param changes.
set -u
PX4_DIR=/path/to/work/px4/PX4-Autopilot-v1.17.0
BIN=$PX4_DIR/build/px4_sitl_default/bin
ETC=$PX4_DIR/build/px4_sitl_default/etc
OUT=/path/to/work/sitl_logs/v1.17.0
ROOTFS=${1:?rootfs}; SCENARIO=${2:?scenario}
MODEL=sihsim_standard_vtol
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS" "$OUT"; cd "$ROOTFS"
PX4LOG=$OUT/$SCENARIO.px4.log; CMDLOG=$OUT/$SCENARIO.cmd.log; : > "$CMDLOG"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3N; }
say() { echo "[$(ts)] $*" | tee -a "$CMDLOG"; }
simt() { "$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +timestamp:/{printf "%.3f", $2/1e6}'; }
vs() { say "STATUS: $("$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +(timestamp|arming_state|nav_state|failsafe|vehicle_type|in_transition_mode|in_transition_to_fw|pre_flight_checks_pass):/{gsub(/^ +/,""); printf "%s | ", $0}') VTOL: $("$BIN/px4-listener" vtol_vehicle_status 2>/dev/null | awk '/^ +(vehicle_vtol_state|fixed_wing_system_failure):/{gsub(/^ +/,""); printf "%s | ", $0}') ARSPD: $("$BIN/px4-listener" airspeed_validated 2>/dev/null | awk '/^ +(calibrated_airspeed_m_s|airspeed_source):/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
cmd() { say "CMD (sim t=$(simt)s): $*"; "$BIN/px4-$1" "${@:2}" 2>&1 | sed 's/^/    > /' | tee -a "$CMDLOG"; }
wait_for() { # topic field value timeout_s
  local tp=$1 f=$2 v=$3 to=$4 i=0 cur=
  while [ $i -lt "$to" ]; do
    cur=$("$BIN/px4-listener" "$tp" 2>/dev/null | awk -v f="$f" '$1==f":"{print $2}')
    if [ "$cur" = "$v" ]; then say "WAIT ok: $tp.$f=$v after ${i}s (sim t=$(simt)s)"; return 0; fi
    sleep 1; i=$((i+1))
  done
  say "WAIT TIMEOUT: $tp.$f=$cur (wanted $v) after ${to}s (sim t=$(simt)s)"; return 1
}
say "SCENARIO $SCENARIO  rootfs=$ROOTFS  PX4 $(cd $PX4_DIR && git describe --tags --always) $(cd $PX4_DIR && git rev-parse HEAD)"
say "host load at start: $(cat /proc/loadavg)  ns: /tmp=$(ls -A /tmp | tr '\n' ' ')"
touch .start_marker
say "START px4: cd $ROOTFS && PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim $BIN/px4 -d $ETC > $PX4LOG 2>&1 &"
PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim "$BIN/px4" -d "$ETC" > "$PX4LOG" 2>&1 &
PX4_PID=$!
sleep 3
wait_for vehicle_status pre_flight_checks_pass True 150
wait_for home_position valid_hpos True 60
cmd param show SYS_AUTOSTART; cmd param show MIS_TAKEOFF_ALT; cmd param show VT_ARSP_TRANS; cmd param show VT_TRANS_TIMEOUT; cmd param show VT_TRANS_MIN_TM; cmd param show VT_F_TRANS_DUR; cmd param show VT_B_TRANS_DUR; cmd param show SENS_EN_ARSPDSIM
vs
cmd commander arm
sleep 3; vs
cmd commander takeoff
wait_for vehicle_status nav_state 17 10; vs
wait_for vehicle_status nav_state 4 120; vs
sleep 5; vs
cmd commander transition
sleep 0.8
cmd commander mode auto:rtl
sleep 0.5; vs
wait_for vehicle_status nav_state 5 10; vs
sleep 3; vs
if ! wait_for vehicle_status arming_state 1 90; then
  cmd commander land
  wait_for vehicle_status arming_state 1 120
fi
vs
sleep 6
cmd logger status
cmd shutdown
wait $PX4_PID; say "px4 exit=$?"
ULG=$(find log -name '*.ulg' -newer .start_marker | sort | tail -1)
cp "$ULG" "$OUT/$SCENARIO.ulg"; cp "$0" "$OUT/$SCENARIO.sh"
say "COPIED $ROOTFS/$ULG -> $OUT/$SCENARIO.ulg ($(stat -c %s "$OUT/$SCENARIO.ulg") bytes)"
say "host load at end: $(cat /proc/loadavg)"
say "DONE"
```
