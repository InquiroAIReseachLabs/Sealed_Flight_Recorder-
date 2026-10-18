# failsafe_battery_empty.ulg

Generated for this project in PX4 v1.17.0 SITL with the built-in SIH simulator. Not a third-party log.

| Field | Value |
|---|---|
| PX4 | `v1.17.0`, commit `d6f12ad1c4f70ad3230afd7d86e971421e02fef4` |
| Airframe | `10040_sihsim_quadx` |
| Scenario | Multicopter; `failure battery off`, battery_warning 1, 2, 3, Hold, AUTO_LAND, disarm (second R4 case). |
| SHA-256 | `7bd1633b26acba457f67a575fa9ddace0535e0411c5fdbacbfad777e0eddd75c` |
| Size | 9208891 bytes |

Full procedure, topic counts, and event sequence: `docs/DIAGNOSTIC.md`, item 3.

The script that drove the flight (paths are those of the generating machine):

```bash
#!/bin/bash
# failsafe_battery_empty.sh <rootfs_dir> <scenario_name>
# Scenario E (battery): SIH quadx, arm, takeoff, loiter, `failure battery off` (BatterySimulator handles it:
# battery reported empty -> battery_warning EMERGENCY -> COM_LOW_BAT_ACT 3 = Land). Also one real in-flight param change
# (COM_DISARM_LAND 2 -> 3 s) to show how PARAM_CHANGED_IN_FLIGHT appears. Fresh rootfs.
set -u
PX4_DIR=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0
BIN=$PX4_DIR/build/px4_sitl_default/bin
ETC=$PX4_DIR/build/px4_sitl_default/etc
OUT=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0
ROOTFS=${1:?rootfs}; SCENARIO=${2:?scenario}
MODEL=sihsim_quadx
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS" "$OUT"; cd "$ROOTFS"
PX4LOG=$OUT/$SCENARIO.px4.log; CMDLOG=$OUT/$SCENARIO.cmd.log; : > "$CMDLOG"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3N; }
say() { echo "[$(ts)] $*" | tee -a "$CMDLOG"; }
simt() { "$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +timestamp:/{printf "%.3f", $2/1e6}'; }
vs() { say "STATUS: $("$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +(timestamp|arming_state|nav_state|failsafe|failsafe_defer_state|vehicle_type|pre_flight_checks_pass):/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
ff() { say "FAILSAFE_FLAGS: $("$BIN/px4-listener" failsafe_flags 2>/dev/null | awk '/^ +[a-z_]+: (True|[1-9])/ && !/mode_req_/ && !/timestamp/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
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
cmd param show SYS_FAILURE_EN; cmd param show COM_LOW_BAT_ACT; cmd param show SIM_BAT_ENABLE; cmd param show BAT_LOW_THR; cmd param show BAT_CRIT_THR; cmd param show BAT_EMERGEN_THR
vs
cmd commander arm
sleep 3; vs
cmd commander takeoff
wait_for vehicle_status nav_state 17 10; vs
wait_for vehicle_status nav_state 4 90; vs
sleep 5; vs; ff
cmd param show COM_DISARM_LAND
cmd param set COM_DISARM_LAND 3.0
sleep 3
cmd param show COM_DISARM_LAND
cmd failure battery off
for i in 1 2 3; do sleep 3; vs; ff; done
wait_for vehicle_status failsafe True 30; vs; ff
wait_for vehicle_status arming_state 1 240; vs; ff
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
