# mc_flight.ulg

Generated for this project in PX4 v1.14.4 SITL with the built-in SIH simulator. Not a third-party log.

| Field | Value |
|---|---|
| PX4 | `v1.14.4`, commit `1555f2bd2229544c43966ab5f94879c41d8e1e01` |
| Airframe | `10040_sihsim_quadx` |
| Scenario | Multicopter, oldest supported schema: arm, takeoff, RTL, loiter, land, disarm. |
| SHA-256 | `9324d50388738054afdcee8cb09e3a44e1956c64003978e6aa401be16f09a254` |
| Size | 30583745 bytes |

The script that drove the flight (the working directory of the generating machine is written `/path/to/work`):

```bash
#!/bin/bash
# mc_flight.sh: one headless SIH multicopter flight on PX4 v1.14.4 SITL.
# Equivalent of `make px4_sitl sihsim_quadx` (target defined in
# src/modules/simulation/simulator_sih/CMakeLists.txt:
#   env PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim <build>/bin/px4, cwd <build>/rootfs)
# but run without make, daemon mode (-d, no pxh shell), in a fresh working dir,
# on a non-zero instance so it cannot collide with another SITL on instance 0.
# Usage: mc_flight.sh [working_dir]
set -u
S=/path/to/work
T=$S/px4/PX4-Autopilot-v1.14.4
BUILD=$T/build/px4_sitl_default
B=$BUILD/bin
I=${PX4_INSTANCE_ID:-3}
WD=${1:-$S/sitl_run/v1.14.4_mc_$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$WD"
OUT=$WD/px4.stdout.log
CMDLOG=$WD/commands.log
: > "$CMDLOG"

ts()  { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
log() { echo "$(ts) $*" | tee -a "$CMDLOG"; }
cli() { local m=$1; shift; "$B/px4-$m" --instance "$I" "$@"; }
run() { log "CMD: px4-$1 --instance $I ${*:2}"; cli "$@" 2>&1 | sed 's/^/    | /' | tee -a "$CMDLOG"; }
field() { cli listener "$1" -n 1 2>/dev/null | awk -v f="$2" '$1==f":"{print $2; exit}'; }
snapshot() {
  log "STATE[$1]: arming_state=$(field vehicle_status arming_state) nav_state=$(field vehicle_status nav_state)" \
      "user_intention=$(field vehicle_status nav_state_user_intention) failsafe=$(field vehicle_status failsafe)" \
      "landed=$(field vehicle_land_detected landed) z=$(field vehicle_local_position z)"
}
wait_field() { # topic field value timeout_s
  local end=$(( $(date +%s) + $4 )) v=""
  while [ "$(date +%s)" -lt "$end" ]; do
    v=$(field "$1" "$2")
    if [ "$v" = "$3" ]; then log "OK: $1.$2 == $3"; return 0; fi
    sleep 0.5
  done
  log "TIMEOUT: $1.$2 != $3 after $4 s (last: '$v')"; return 1
}
abort() { log "ABORT: $*"; snapshot abort; cli shutdown >/dev/null 2>&1; sleep 3; kill -INT "$PX4_PID" 2>/dev/null; exit 1; }

cd "$WD" || exit 1
log "PX4 tree: $T ($(git -C "$T" describe --tags --always) $(git -C "$T" rev-parse HEAD))"
log "LAUNCH: cd $WD && PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim $B/px4 -d -i $I -w $WD $BUILD/etc > $OUT 2>&1 < /dev/null &"
PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim "$B/px4" -d -i "$I" -w "$WD" "$BUILD/etc" > "$OUT" 2>&1 < /dev/null &
PX4_PID=$!
log "px4 pid $PX4_PID"

# 1. boot: wait until arming checks pass in the boot mode (default user intention AUTO_LOITER)
wait_field vehicle_status pre_flight_checks_pass True 180 || abort "preflight checks never passed"
sleep 2
snapshot preflight_ok
Z0=$(field vehicle_local_position z); log "ground reference z0=$Z0 (vehicle_local_position.z before arming)"

# 2. arm
run commander arm
wait_field vehicle_status arming_state 2 10 || abort "arm failed"
snapshot armed

# 3. takeoff (NAV_TAKEOFF, then an ARM command that is a no-op since already armed)
run commander takeoff
wait_field vehicle_status nav_state 17 10 || abort "no AUTO_TAKEOFF"
snapshot takeoff
wait_field vehicle_status nav_state 4 60 || abort "takeoff did not complete into AUTO_LOITER"
snapshot takeoff_done
sleep 70
snapshot hover

# 4. mode change 1: auto:rtl (nav_state 5)
run commander mode auto:rtl
wait_field vehicle_status nav_state 5 10 || abort "no AUTO_RTL"
snapshot rtl
for k in $(seq 1 16); do   # stay in RTL up to 8 s, leave early once below 1.2 m above ground (z0)
  z=$(field vehicle_local_position z)
  awk -v z="$z" -v z0="$Z0" 'BEGIN{exit !((z - z0) > -1.2)}' && { log "RTL descending below 1.2 m above ground (z=$z, z0=$Z0), leaving RTL"; break; }
  sleep 0.5
done
snapshot rtl_end

# 5. mode change 2: auto:loiter (nav_state 4)
run commander mode auto:loiter
wait_field vehicle_status nav_state 4 10 || abort "no AUTO_LOITER"
snapshot loiter
sleep 45
snapshot loiter_end

# 6. land (nav_state 18)
run commander land
wait_field vehicle_status nav_state 18 10 || abort "no AUTO_LAND"
snapshot land
wait_field vehicle_land_detected landed True 120 || abort "never landed"
snapshot landed

# 7. disarm, sent as soon as landed is detected (auto disarm COM_DISARM_LAND is 2 s)
run commander disarm
wait_field vehicle_status arming_state 1 10 || log "WARN: still armed after disarm"
snapshot disarmed
log "latest_disarming_reason=$(field vehicle_status latest_disarming_reason)"

# 8. let the logger close the file (SDLOG_MODE 1 stops at disarm), then shut down
sleep 4
run shutdown
for k in $(seq 1 30); do kill -0 "$PX4_PID" 2>/dev/null || break; sleep 1; done
kill -0 "$PX4_PID" 2>/dev/null && { log "px4 still running, sending SIGINT"; kill -INT "$PX4_PID"; sleep 3; }
log "px4 exited"
log "ULOG: $(find "$WD/log" -name '*.ulg' 2>/dev/null | sort | tr '\n' ' ')"
```
