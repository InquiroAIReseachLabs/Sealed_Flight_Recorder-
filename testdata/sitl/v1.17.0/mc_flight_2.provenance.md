# mc_flight_2.ulg

Generated for this project in PX4 v1.17.0 SITL with the built-in SIH simulator. Not a third-party log.

| Field | Value |
|---|---|
| PX4 | `v1.17.0`, commit `d6f12ad1c4f70ad3230afd7d86e971421e02fef4` |
| Airframe | `10040_sihsim_quadx` |
| Scenario | Same as mc_flight_1, in the same working directory with no configuration change (volatile-parameter experiment, item 5). |
| SHA-256 | `05592a1bc28c9f82a420320c8a44191fb34aa92662a50c5d7b9cbaa9aba32b9b` |
| Size | 9727973 bytes |

Full procedure, topic counts, and event sequence: `docs/DIAGNOSTIC.md`, item 3.

The script that drove the flight (paths are those of the generating machine):

```bash
#!/bin/bash
# mc_flight.sh <rootfs_dir> <scenario_name> [keep]
# Scenario B1/B2: SIH quadx, arm, takeoff (MIS_TAKEOFF_ALT default 2.5 m), AUTO_LOITER, commanded AUTO_RTL,
# then `commander land` 2 s into the RTL descent (RTL at home lands by itself after ~11 s, see superseded attempt1),
# auto-disarm by landing. Default configuration, no param set. Run via nsrun.sh (private /tmp + loopback).
# "keep" reuses an existing rootfs (parameters.bson persists) -> scenario B2 / volatile parameter experiment.
set -u
PX4_DIR=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0
BIN=$PX4_DIR/build/px4_sitl_default/bin
ETC=$PX4_DIR/build/px4_sitl_default/etc
OUT=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0
ROOTFS=${1:?rootfs}; SCENARIO=${2:?scenario}; KEEP=${3:-}
MODEL=sihsim_quadx
[ -z "$KEEP" ] && rm -rf "$ROOTFS"
mkdir -p "$ROOTFS" "$OUT"; cd "$ROOTFS"
PX4LOG=$OUT/$SCENARIO.px4.log; CMDLOG=$OUT/$SCENARIO.cmd.log; : > "$CMDLOG"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3N; }
say() { echo "[$(ts)] $*" | tee -a "$CMDLOG"; }
simt() { "$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +timestamp:/{printf "%.3f", $2/1e6}'; }
vs() { say "STATUS: $("$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +(timestamp|arming_state|nav_state|failsafe|vehicle_type|in_transition_mode|in_transition_to_fw|pre_flight_checks_pass):/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
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
say "SCENARIO $SCENARIO  rootfs=$ROOTFS keep=${KEEP:-no}  PX4 $(cd $PX4_DIR && git describe --tags --always) $(cd $PX4_DIR && git rev-parse HEAD)"
say "rootfs contents before start: $(ls -A | tr '\n' ' ')"
say "host load at start: $(cat /proc/loadavg)  ns: /tmp=$(ls -A /tmp | tr '\n' ' ')"
touch .start_marker
say "START px4: cd $ROOTFS && PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim $BIN/px4 -d $ETC > $PX4LOG 2>&1 &"
PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim "$BIN/px4" -d "$ETC" > "$PX4LOG" 2>&1 &
PX4_PID=$!
sleep 3
wait_for vehicle_status pre_flight_checks_pass True 150
wait_for home_position valid_hpos True 60
cmd param show SDLOG_MODE; cmd param show SDLOG_PROFILE; cmd param show COM_RC_IN_MODE; cmd param show SYS_FAILURE_EN; cmd param show SYS_AUTOSTART
vs
cmd commander arm
sleep 3; vs
cmd commander takeoff
wait_for vehicle_status nav_state 17 10; vs
wait_for vehicle_status nav_state 4 90; vs
sleep 5
cmd commander mode auto:loiter
sleep 8; vs
cmd commander mode auto:rtl
wait_for vehicle_status nav_state 5 10; vs
sleep 2; vs
cmd commander land
wait_for vehicle_status nav_state 18 10; vs
wait_for vehicle_status arming_state 1 180; vs
sleep 6
cmd logger status
say "ulg files in rootfs newer than start: $(find log -name '*.ulg' -newer .start_marker | tr '\n' ' ')"
cmd shutdown
wait $PX4_PID; say "px4 exit=$?"
ULG=$(find log -name '*.ulg' -newer .start_marker | sort | tail -1)
cp "$ULG" "$OUT/$SCENARIO.ulg"; cp "$0" "$OUT/$SCENARIO.sh"
say "COPIED $ROOTFS/$ULG -> $OUT/$SCENARIO.ulg ($(stat -c %s "$OUT/$SCENARIO.ulg") bytes)"
say "rootfs contents after: $(ls -A | tr '\n' ' ')"
say "host load at end: $(cat /proc/loadavg)"
say "DONE"
```
