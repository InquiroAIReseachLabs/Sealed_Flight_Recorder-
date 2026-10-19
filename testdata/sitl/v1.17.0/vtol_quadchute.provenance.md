# vtol_quadchute.ulg

Generated for this project in PX4 v1.17.0 SITL with the built-in SIH simulator. Not a third-party log.

| Field | Value |
|---|---|
| PX4 | `v1.17.0`, commit `d6f12ad1c4f70ad3230afd7d86e971421e02fef4` |
| Airframe | `10043_sihsim_standard_vtol` |
| Scenario | Standard VTOL: arm, takeoff, AUTO_LOITER, front transition to fixed wing, then a quadchute in fixed-wing flight (fixed wing straight to multicopter, `failsafe_flags.vtol_fixed_wing_system_failure` true, `vehicle_status.failsafe` true), quadchute failsafe Land, disarm by landing (SPEC R4 quadchute case). |
| SHA-256 | `f76535f492c2ea7e81c5e55977eb9a5225bc5434da8804791fc7408a10e40aa1` |
| Size | 20826338 bytes |

## How it was made

- Run on 2026-10-18 from 16:37:41 to 16:39:07 UTC (wall clock from `vtol_quadchute.cmd.log`), one run, first attempt. ULog info field `boot_time_utc_us` is 1792341462192614.
- Invocation: `cd /path/to/work/quadchute && /path/to/work/sitl_runs/v1.17.0/nsrun.sh ./vtol_quadchute.sh /path/to/work/quadchute/rootfs vtol_quadchute`. `nsrun.sh` gives the run a private `/tmp` and loopback, so PX4 runs as instance 0 with its default configuration.
- PX4 server start (fresh, empty rootfs): `cd <rootfs> && PX4_SIM_MODEL=sihsim_standard_vtol PX4_SIMULATOR=sihsim /path/to/work/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/bin/px4 -d /path/to/work/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/etc`. No `PX4_SIM_SPEED_FACTOR` was set; px4 printed `Simulation loop with 250 Hz (4000 us sim time interval)`, and the SITL build uses the lockstep scheduler (`boards/px4/sitl/sitl.cmake` line 12). The build was used as is, not rebuilt.
- Commands were sent with the px4 client binaries (`px4-param`, `px4-commander`, `px4-logger`, `px4-shutdown`), and each step was confirmed by polling `px4-listener` output. The log is the newest `.ulg` in `<rootfs>/log/2026-10-18/` (`16_37_42.ulg`, same SHA-256 as the copy).
- Host load average (from `/proc/loadavg` in the command log): 0.99 at start, 1.27 at end. `ulog_info` reports no dropouts.

### Why this trigger

From the v1.17.0 source:

- `vtol_type.cpp` line 149: `VtolType::update_fw_state()` (line 111) calls `check_quadchute_condition()` (line 386) on every fixed-wing cycle; line 162 does the same during a transition.
- `isQuadchuteEnabled()` (line 207) needs armed, not landed, and not above `VT_FW_QC_HMAX` (0 here, so no height limit).
- `getQuadchuteReason()` (line 344) checks `isMinAltBreached()` first (line 231); line 236 is `if (-(_local_pos->z) < _param_vt_fw_min_alt.get())`. Raising `VT_FW_MIN_ALT` above the current altitude above the local origin therefore gives `MinimumAltBreached` on the next fixed-wing cycle. It works headless in SIH and needs no stick input.
- `vtol_att_control_main.cpp` line 187 `quadchute()`: line 191 sends the generic 'L' text `Quad-chute triggered`, line 205 sends the event `vtol_att_ctrl_quadchute_min_alt`, and line 234 sets `fixed_wing_system_failure = true`.
- `standard.cpp` lines 74 to 76: when `fixed_wing_system_failure` is true, the mode goes to `MC_MODE` immediately, with no TRANSITION_TO_MC state.
- Commander: `HealthAndArmingChecks/checks/vtolCheck.cpp` line 43 copies the flag into `failsafe_flags.vtol_fixed_wing_system_failure`. `failsafe/failsafe.cpp` lines 520 to 525 raise it only when the user intended mode is AUTO_MISSION, AUTO_LOITER, AUTO_TAKEOFF or AUTO_VTOL_TAKEOFF, so the quadchute was done in AUTO_LOITER. The action comes from `COM_QC_ACT` (`commander_params.c` line 351, default 0 = Return mode). Value 1 is `Land_mode` (`failsafe.h` line 125), which maps to `Action::Land` (`failsafe.cpp` lines 266 to 269).
- `VT_FW_MIN_ALT` is defined at `vtol_att_control_params.c` line 189 (default 0.0, disabled).
- `VT_FW_MIN_ALT` was set only after the front transition had finished and the vehicle had been in fixed wing for a while. If it had been set during the transition, line 162 would have raised the quadchute inside the transition.

## Parameter changes

Only two parameters were changed by the scenario. Values are from `python3 -I /usr/local/bin/ulog_params -t vtol_quadchute.ulg` (initial value, then each logged value with its boot timestamp) and from the `param set` output in the command log.

| parameter | initial value in log | new value | boot time of the logged change | sim t at send (command log) | `param set` output |
|---|---|---|---|---|---|
| `COM_QC_ACT` | 0 (Return mode) | 1 (Land mode) | 4.624 s (4624000 us), on the ground, before arming | 4.608 s | `COM_QC_ACT: curr: 0 -> new: 1` |
| `VT_FW_MIN_ALT` | 0.0 | 60.0 | 39.012 s (39012000 us), in fixed-wing flight | 38.956 s | `VT_FW_MIN_ALT: curr: 0.0000 -> new: 60.0000` |

The altitude at the change was well below 60 m. In `vehicle_local_position`, `z` was -19.54004 at 39.012000 s (dist_bottom 19.634125, valid). While the vehicle was in fixed wing (32.396 s to 39.020 s), `-z` ranged from 19.54 to 22.5632.

Other parameter messages after log start are not scenario changes: CAL, SIH, SENS and SYS_AUTO* parameters are logged again at 0.296 s with unchanged values. `CAL_BARO0_OFF` goes from 0.0 to 2.44140625 at 5.308 s, written by PX4 itself on the ground. pyulog counts `initial_parameters` 1145 and `changed_parameters` 30.

Relevant defaults confirmed with `param show` before the flight (values as printed): `SYS_AUTOSTART` 10043, `MIS_TAKEOFF_ALT` 20.0000, `NAV_LOITER_RAD` 80.0000, `COM_QC_ACT` 0, `VT_FW_MIN_ALT` 0.0000, `VT_FW_QC_HMAX` 0, `VT_FW_QC_P` 0, `VT_FW_QC_R` 0, `VT_QC_ALT_LOSS` 0.0000, `VT_QC_T_ALT_LOSS` 20.0000, `VT_ARSP_TRANS` 10.0000, `VT_TRANS_TIMEOUT` 15.0000, `VT_F_TRANS_DUR` 5.0000, `COM_DISARM_LAND` 2.0000, `SENS_EN_ARSPDSIM` 1. From `ulog_params -i`: `COM_FAIL_ACT_T` 5.0 (the Hold delay before the failsafe action, `commander_params.c` line 311), `SDLOG_MODE` 1, `VT_TYPE` 2.

## Commands, in order

"sim t at send" is printed by the script just before each command. It is the timestamp of the newest `vehicle_status` message that `px4-listener` returned at that moment, so it can be a little earlier than the real send time. The last column gives the logged time of the effect (boot time, from the ULog). `param show` lines are read-only checks. Wall clock is UTC on 2026-10-18.

| wall clock | sim t at send (s) | command or observation | effect in the log |
|---|---|---|---|
| 16:37:41.538 | (boot) | start px4 server (command above) | log opened at 0.296 s |
| 16:37:46.697 | | WAIT ok: `vehicle_status.pre_flight_checks_pass=True` after 2s (sim t=4.104s) | `pre_flight_checks_pass` true at 3.600 s |
| 16:37:46.708 | | WAIT ok: `home_position.valid_hpos=True` after 0s (sim t=4.104s) | |
| 16:37:46.714 | 4.104 | `param show SYS_AUTOSTART` | read only |
| 16:37:46.725 | 4.104 | `param show MIS_TAKEOFF_ALT` | read only |
| 16:37:46.734 | 4.104 | `param show NAV_LOITER_RAD` | read only |
| 16:37:46.743 | 4.104 | `param show COM_QC_ACT` | read only |
| 16:37:46.753 | 4.104 | `param show VT_FW_MIN_ALT` | read only |
| 16:37:46.763 | 4.104 | `param show VT_FW_QC_HMAX` | read only |
| 16:37:46.773 | 4.104 | `param show VT_FW_QC_P` | read only |
| 16:37:46.783 | 4.104 | `param show VT_FW_QC_R` | read only |
| 16:37:46.793 | 4.104 | `param show VT_QC_ALT_LOSS` | read only |
| 16:37:46.804 | 4.104 | `param show VT_QC_T_ALT_LOSS` | read only |
| 16:37:46.813 | 4.104 | `param show VT_ARSP_TRANS` | read only |
| 16:37:46.822 | 4.104 | `param show VT_TRANS_TIMEOUT` | read only |
| 16:37:46.832 | 4.104 | `param show VT_F_TRANS_DUR` | read only |
| 16:37:46.841 | 4.104 | `param show COM_DISARM_LAND` | read only |
| 16:37:46.852 | 4.104 | `param show SENS_EN_ARSPDSIM` | read only |
| 16:37:46.890 | 4.608 | `param set COM_QC_ACT 1` | parameter message at 4.624 s |
| 16:37:47.904 | 5.316 | `param show COM_QC_ACT` | read only, printed 1 |
| 16:37:47.914 | 5.316 | `commander arm` | `vehicle_command` 400 (p1 1) at 5.628 s, ack result 0 at 5.640 s, `arming_state` ARMED at 5.640 s |
| 16:37:50.953 | 8.160 | `commander takeoff` | `vehicle_command` 22 at 8.608 s and 400 at 8.620 s, acks result 0 at 8.616 s and 8.628 s, `nav_state` AUTO_TAKEOFF at 8.628 s |
| 16:37:51.984 | | WAIT ok: `vehicle_status.nav_state=17` after 1s (sim t=9.132s) | `landed` false at 9.452 s |
| 16:38:07.129 | | WAIT ok: `vehicle_status.nav_state=4` after 15s (sim t=23.968s) | `nav_state` AUTO_LOITER at 23.464 s |
| 16:38:12.194 | 29.008 | `commander transition` | `vehicle_command` 3000 (DO_VTOL_TRANSITION, p1 4) at 29.352 s, no ack logged; `vehicle_vtol_state` 1 at 29.356 s |
| 16:38:13.216 | | WAIT ok: `vehicle_status.in_transition_mode=True` after 1s (sim t=29.872s) | true at 29.368 s |
| 16:38:16.272 | | WAIT ok: `vehicle_status.vehicle_type=2` after 3s (sim t=32.908s) | FIXED_WING at 32.404 s |
| 16:38:16.311 | | WAIT ok: `vehicle_status.in_transition_mode=False` after 0s (sim t=32.908s) | false at 32.404 s |
| 16:38:22.377 | 38.956 | `param set VT_FW_MIN_ALT 60` | parameter message at 39.012 s; quadchute at 39.016 s |
| 16:38:22.393 | | WAIT ok: `vtol_vehicle_status.fixed_wing_system_failure=True` after 0s (sim t=39.016s) | true at 39.016 s |
| 16:38:22.430 | | WAIT ok: `vehicle_status.vehicle_type=1` after 0s (sim t=39.028s) | ROTARY_WING at 39.028 s |
| 16:38:22.476 | | WAIT ok: `failsafe_flags.vtol_fixed_wing_system_failure=True` after 0s (sim t=39.028s) | true at 39.016 s |
| 16:38:22.489 | | WAIT ok: `vehicle_status.failsafe=True` after 0s (sim t=39.028s) | true at 39.028 s |
| 16:38:27.571 | | WAIT ok: `vehicle_status.nav_state=18` after 5s (sim t=44.032s) | AUTO_LAND at 44.032 s |
| 16:39:00.906 | | WAIT ok: `vehicle_status.arming_state=1` after 30s (sim t=76.412s) | `landed` true at 73.884 s, DISARMED at 75.896 s. The fallback `commander land` in the script was not needed and was not sent. |
| 16:39:06.962 | 82.460 | `logger status` | printed `Not logging` (SDLOG_MODE 1 closes the log at disarm) |
| 16:39:06.972 | 82.460 | `shutdown` | `px4 exit=0` |

No `commander mode`, `commander land` or other mode command was sent. The Hold, the AUTO_LAND and the disarm all came from the quadchute failsafe and auto-disarm.

## Observed sequence

Boot times are the ULog `timestamp` field (microseconds since boot) divided by 1e6. Enum names are from the v1.17.0 `msg/versioned/VehicleStatus.msg` and `VtolVehicleStatus.msg`: arming_state 1 DISARMED, 2 ARMED; nav_state 4 AUTO_LOITER, 17 AUTO_TAKEOFF, 18 AUTO_LAND; vehicle_type 1 ROTARY_WING, 2 FIXED_WING; vehicle_vtol_state 1 TRANSITION_TO_FW, 2 TRANSITION_TO_MC, 3 MC, 4 FW. `latest_disarming_reason` uses commander's `arm_disarm_reason_t` (`build/px4_sitl_default/events/events_generated.h` line 170: `auto_disarm_land = 6`).

### vtol_vehicle_status (80 messages), every change of vehicle_vtol_state or fixed_wing_system_failure

| boot time | timestamp (us) | vehicle_vtol_state | fixed_wing_system_failure |
|---|---|---|---|
| 0.088 s | 88000 | 3 MC | false |
| 29.356 s | 29356000 | 1 TRANSITION_TO_FW | false |
| 32.396 s | 32396000 | 4 FW | false |
| 39.016 s | 39016000 | 4 FW | **true** |
| 39.020 s | 39020000 | **3 MC** | true |

State 2 (TRANSITION_TO_MC) never appears in the log. The quadchute goes from 4 FW straight to 3 MC. The first message with the flag set (39.016 s) still shows FW, and the next one (39.020 s) shows MC. The flag stays true to the end of the log.

### vehicle_status (163 messages), every change of the listed fields

| boot time | arming_state | nav_state | nav_state_user_intention | failsafe | failsafe_defer_state | in_transition_mode | in_transition_to_fw | vehicle_type | pre_flight_checks_pass | latest_disarming_reason |
|---|---|---|---|---|---|---|---|---|---|---|
| 0.096 s | 1 DISARMED | 4 AUTO_LOITER | 4 | false | 0 | false | false | 1 ROTARY_WING | false | 0 |
| 3.600 s | 1 | 4 | 4 | false | 0 | false | false | 1 | true | 0 |
| 5.640 s | **2 ARMED** | 4 | 4 | false | 0 | false | false | 1 | true | 0 |
| 8.628 s | 2 | 17 AUTO_TAKEOFF | 17 | false | 0 | false | false | 1 | true | 0 |
| 23.464 s | 2 | 4 AUTO_LOITER | 4 | false | 0 | false | false | 1 | true | 0 |
| 29.368 s | 2 | 4 | 4 | false | 0 | **true** | **true** | 1 | true | 0 |
| 32.404 s | 2 | 4 | 4 | false | 0 | **false** | **false** | **2 FIXED_WING** | true | 0 |
| 39.016 s | 2 | 4 | 4 | false | 0 | false | false | 2 | **false** | 0 |
| 39.028 s | 2 | 4 | 4 | **true** | 0 | false | false | **1 ROTARY_WING** | false | 0 |
| 44.032 s | 2 | **18 AUTO_LAND** | 4 | true | 0 | false | false | 1 | false | 0 |
| 75.896 s | **1 DISARMED** | 4 | 4 | **false** | 0 | false | false | 1 | false | 6 |

`latest_arming_reason` goes from 0 to 3 (command_internal) at 5.640 s. `pre_flight_checks_pass` turns false at 39.016 s because `vtolCheck.cpp` reports an arming check failure while the flag is set.

Individual `vehicle_status` rows around the two VTOL events (timestamp us: arming_state, nav_state, failsafe, in_transition_mode, in_transition_to_fw, vehicle_type):

- Front transition: 29008000: 2, 4, 0, 0, 0, 1; 29356000: 2, 4, 0, 0, 0, 1; 29368000: 2, 4, 0, 1, 1, 1; ... 32392000: 2, 4, 0, 1, 1, 1; 32404000: 2, 4, 0, 0, 0, 2.
- Quadchute: 38452000: 2, 4, 0, 0, 0, 2; 38956000: 2, 4, 0, 0, 0, 2; 39016000: 2, 4, 0, 0, 0, 2; **39028000: 2, 4, 1, 0, 0, 1**; 39532000: 2, 4, 1, 0, 0, 1.
- Land and disarm: 44032000: 2, 18, 1, 0, 0, 1; ... 75548000: 2, 18, 1, 0, 0, 1; 75896000: 1, 4, 0, 0, 0, 1; 75908000: 1, 4, 0, 0, 0, 1; 76412000 (last row): 1, 4, 0, 0, 0, 1.

The fixed wing to multicopter edge in `vehicle_status` is at **39.028 s** (39028000 us): `vehicle_type` goes from 2 to 1 while `in_transition_mode` and `in_transition_to_fw` are false in that row and in the row before it. No VTOL transition was in progress at the quadchute. `in_transition_mode` had been false since 32.404 s, and `vehicle_vtol_state` had been 4 FW since 32.396 s.

### failsafe_flags.vtol_fixed_wing_system_failure (146 failsafe_flags messages)

- false from the first row (0.168 s) up to and including 38.776 s (38776000 us);
- **true at 39.016 s (39016000 us)**, and true in every later row up to the last one at 76.880 s.

The only other `failsafe_flags` fields that change (mode_req_* not listed) are the boot-time estimator flags. `attitude_invalid` turns false at 1.440 s; `local_altitude_invalid` at 0.924 s; `local_position_invalid`, `local_position_invalid_relaxed`, `local_velocity_invalid`, `global_position_invalid` and `global_position_invalid_relaxed` at 3.600 s.

### Other topics

- `vehicle_land_detected.landed`: true at 0.168 s, false at 9.452 s, true at 73.884 s.
- `vehicle_command` (8 rows): 211 DO_GRIPPER at 0.144 s (p1 1.7653742e+12, p3 -513.0239, source 75/17020, sent at boot, not by the script); 400 at 5.628 s; 22 at 8.608 s; 400 at 8.620 s; 3000 (p1 4.0, p2 0.0) at 29.352 s; 1001, 1000, 1001 (gimbal manager) at 44.284 s, sent internally after the switch to AUTO_LAND. All have `from_external` 0.
- `vehicle_command_ack` (5 rows): 211 result 5 at 0.148 s and result 0 at 1.244 s; 400 result 0 at 5.640 s; 22 result 0 at 8.616 s; 400 result 0 at 8.628 s. There is no ack for 3000.

### Intervals

Computed from the boot times above with `awk` (command below):

| interval | from, to | length |
|---|---|---|
| front transition (vtol state 1 to 4) | 29.356 s, 32.396 s | 3.040 s |
| in fixed wing before the quadchute (vtol state 4 to 3) | 32.396 s, 39.020 s | 6.624 s |
| `VT_FW_MIN_ALT` change to `fixed_wing_system_failure` true | 39.012 s, 39.016 s | 0.004 s |
| `vehicle_status` FW to MC edge to AUTO_LAND (Hold delay) | 39.028 s, 44.032 s | 5.004 s |
| `vehicle_status.failsafe` true | 39.028 s, 75.896 s | 36.868 s |
| armed | 5.640 s, 75.896 s | 70.256 s |

## Logged messages

### 'L' messages at warning or above

All 20 'L' (logged string) messages were read with the pyulog API, because `ulog_messages` merges in decoded events and drops 'L' strings that end in a tab (pyulog `messages.py`). There are no tagged 'L' messages. These are the ones at level WARNING or above. They have log_level 52, which pyulog prints as WARNING; every other 'L' message has 54 (INFO), so none is above WARNING:

| boot time | timestamp (us) | level | message (repr, so the trailing tab shows as `\t`) |
|---|---|---|---|
| 2.088 s | 2088000 | WARNING | `'[health_and_arming_checks] Preflight Fail: Airspeed selector module down'` |
| 39.016 s | 39016000 | WARNING | `'[vtol_att_control] Quad-chute triggered\t'` |
| 39.028 s | 39028000 | WARNING | `'[failsafe] Failsafe activated: entering Hold for 5 seconds\t'` |
| 44.032 s | 44032000 | WARNING | `'[failsafe] Failsafe activated\t'` |

The airspeed message at 2.088 s is from boot, before `pre_flight_checks_pass` became true at 3.600 s. The same four lines appear as `WARN` in the px4 console output (`vtol_quadchute.px4.log`).

### Events (decoded by `ulog_messages`)

The quadchute reason is only in an event, not in an 'L' string. `ulog_messages` output at warning or above:

```
0:00:02.088 WARNING: [health_and_arming_checks] Preflight Fail: Airspeed selector module down
0:00:39.016 CRITICAL: Quad-chute triggered due to minimum altitude breach
0:00:39.028 WARNING: Failsafe activated: switching to Land in 5 seconds
0:00:44.032 WARNING: Failsafe activated: switching to Land
```

(the first line is the 'L' string above, the other three are events). The full `ulog_messages` output also has, at INFO: `Armed by internal command` 0:00:05.640, `Using default takeoff altitude: 20.00 m` 0:00:08.628, `Takeoff detected` 0:00:09.456, `Landing detected` 0:01:13.892, `Disarmed by landing` 0:01:15.896.

## Log facts (`ulog_info`)

```
Logging start time: 0:00:00, duration: 0:01:16
No Dropouts
SW Version: v1.17.0
Info Messages:
 boot_time_utc_us: 1792341462192614
 metadata_events_sha256: 3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d
 sys_name: PX4
 sys_os_name: Linux
 sys_os_ver_release: 101854463
 sys_toolchain: GNU GCC
 sys_toolchain_ver: 13.3.0
 time_ref_utc: 0
 ver_data_format: 2
 ver_hw: PX4_SITL
 ver_sw: d6f12ad1c4f70ad3230afd7d86e971421e02fef4
 ver_sw_release: 17891583
 ver_vendor_sw_release: 255
Info Multiple Messages: [excluded_optional_topics: 40], [metadata_events: 1], [perf_counter_postflight: 1], [perf_counter_preflight: 1]
```

Topics used above (from the same output): `failsafe_flags (0, 91) 146`, `vehicle_command (0, 55) 8`, `vehicle_command_ack (0, 22) 5`, `vehicle_land_detected (0, 20) 86`, `vehicle_status (0, 74) 163`, `vtol_vehicle_status (0, 10) 80`. pyulog API: `start_timestamp` 296000, `last_timestamp` 76896000, duration 76.6 s, 0 dropouts, `file_corruption` False.

## Extraction commands

All were run in `/path/to/work/quadchute` with pyulog 1.2.4 (`/usr/local/lib/python3.13/dist-packages/pyulog`).

```bash
sha256sum vtol_quadchute.ulg; stat -c '%s bytes' vtol_quadchute.ulg
python3 -I /usr/local/bin/ulog_info vtol_quadchute.ulg
python3 -I /usr/local/bin/ulog_messages vtol_quadchute.ulg
python3 -I /usr/local/bin/ulog_params -t vtol_quadchute.ulg > csv/vtol_quadchute.params_t.csv
awk -F, 'NR%2==1{name=$0; nf=NF; next} NF>2 {print name; print $0}' csv/vtol_quadchute.params_t.csv
python3 -I /usr/local/bin/ulog_params -i vtol_quadchute.ulg | grep -E "^(COM_QC_ACT|VT_FW_MIN_ALT|VT_FW_QC_HMAX|VT_FW_QC_P|VT_FW_QC_R|VT_QC_ALT_LOSS|VT_QC_T_ALT_LOSS|MIS_TAKEOFF_ALT|NAV_LOITER_RAD|COM_DISARM_LAND|COM_FAIL_ACT_T|SYS_AUTOSTART|SDLOG_MODE|VT_TYPE),"
python3 -I /usr/local/bin/ulog2csv -m vehicle_status,vtol_vehicle_status,failsafe_flags,vehicle_command,vehicle_command_ack,vehicle_land_detected,vehicle_local_position,event -o csv vtol_quadchute.ulg

# 'L' messages, raw, with level
python3 -I -c "
from pyulog import ULog
u = ULog('vtol_quadchute.ulg')
print('L messages:', len(u.logged_messages), ' tagged:', len(u.logged_messages_tagged))
for m in u.logged_messages:
    print(m.timestamp, m.log_level, m.log_level_str(), repr(m.message))
"
# time span, dropouts, parameter counts
python3 -I -c "
from pyulog import ULog
u = ULog('vtol_quadchute.ulg')
print('start_timestamp', u.start_timestamp, 'last_timestamp', u.last_timestamp, 'duration_s', (u.last_timestamp-u.start_timestamp)/1e6)
print('dropouts', len(u.dropouts), 'file_corruption', u.file_corruption)
print('initial_parameters', len(u.initial_parameters), 'changed_parameters', len(u.changed_parameters))
"

# vehicle_status: every change of the listed fields
awk -F, 'NR==1{for(i=1;i<=NF;i++)c[$i]=i; print "timestamp_us arming_state nav_state nav_state_user_intention failsafe failsafe_defer_state in_transition_mode in_transition_to_fw vehicle_type pre_flight_checks_pass latest_disarming_reason"; next}
{k=$c["arming_state"]" "$c["nav_state"]" "$c["nav_state_user_intention"]" "$c["failsafe"]" "$c["failsafe_defer_state"]" "$c["in_transition_mode"]" "$c["in_transition_to_fw"]" "$c["vehicle_type"]" "$c["pre_flight_checks_pass"]" "$c["latest_disarming_reason"]; if(k!=p){print $c["timestamp"], k; p=k}}' csv/vtol_quadchute_vehicle_status_0.csv
awk -F, 'NR==1{for(i=1;i<=NF;i++)c[$i]=i; next}{k=$c["latest_arming_reason"]; if(NR==2||k!=p){print $1, "latest_arming_reason="k; p=k}}' csv/vtol_quadchute_vehicle_status_0.csv

# vtol_vehicle_status: every change
awk -F, 'NR==1{for(i=1;i<=NF;i++)c[$i]=i; next}{k=$c["vehicle_vtol_state"]" "$c["fixed_wing_system_failure"]; if(k!=p){print $c["timestamp"], "vehicle_vtol_state="$c["vehicle_vtol_state"], "fixed_wing_system_failure="$c["fixed_wing_system_failure"]; p=k}}' csv/vtol_quadchute_vtol_vehicle_status_0.csv

# rows in a window (the windows used: 29000000 29600000, 32200000 32600000, 38000000 40000000, 43800000 44300000, 75500000 77000000)
awk -F, -v a=38000000 -v b=40000000 'NR==1{for(i=1;i<=NF;i++)c[$i]=i; next} $1>=a && $1<=b {print " ", $c["timestamp"], $c["arming_state"], $c["nav_state"], $c["failsafe"], $c["in_transition_mode"], $c["in_transition_to_fw"], $c["vehicle_type"]}' csv/vtol_quadchute_vehicle_status_0.csv
awk -F, -v a=38000000 -v b=40000000 'NR==1{next} $1>=a && $1<=b {print " ", $1, $2, $3}' csv/vtol_quadchute_vtol_vehicle_status_0.csv

# failsafe_flags: the quadchute flag rows near the edge, and every changing field (mode_req_* skipped)
awk -F, 'NR==1{for(i=1;i<=NF;i++)c[$i]=i; next} $1>=38500000 && $1<=39500000 {print $c["timestamp"], $c["vtol_fixed_wing_system_failure"]}' csv/vtol_quadchute_failsafe_flags_0.csv
awk -F, 'NR==1{for(i=1;i<=NF;i++)h[i]=$i; n=NF; next}{for(i=2;i<=n;i++){if(h[i]~/^mode_req_/)continue; if(!(i in p)||p[i]!=$i){if(i in p)ch[i]=ch[i]" "$1"->"$i; else ch[i]=$1"->"$i; p[i]=$i}}} END{for(i=2;i<=n;i++) if(ch[i]~/ /) print h[i]": "ch[i]}' csv/vtol_quadchute_failsafe_flags_0.csv

# commands, acks, landed
awk -F, 'NR==1{for(i=1;i<=NF;i++)c[$i]=i; next}{print $c["timestamp"], "cmd="$c["command"], "p1="$c["param1"], "p2="$c["param2"], "p3="$c["param3"], "src="$c["source_system"]"/"$c["source_component"], "from_external="$c["from_external"]}' csv/vtol_quadchute_vehicle_command_0.csv
awk -F, 'NR==1{for(i=1;i<=NF;i++)c[$i]=i; next}{print $c["timestamp"], "cmd="$c["command"], "result="$c["result"]}' csv/vtol_quadchute_vehicle_command_ack_0.csv
awk -F, 'NR==1{for(i=1;i<=NF;i++)c[$i]=i; next}{k=$c["landed"]; if(NR==2||k!=p){print $c["timestamp"], "landed="k; p=k}}' csv/vtol_quadchute_vehicle_land_detected_0.csv

# altitude at the parameter change and while in fixed wing
awk -F, 'NR==1{for(i=1;i<=NF;i++)c[$i]=i; next} $1>=38990000 && $1<=39030000 {print $c["timestamp"], "z="$c["z"], "dist_bottom="$c["dist_bottom"], "dist_bottom_valid="$c["dist_bottom_valid"], "vx="$c["vx"], "vy="$c["vy"]}' csv/vtol_quadchute_vehicle_local_position_0.csv
awk -F, 'NR==1{for(i=1;i<=NF;i++)c[$i]=i; next} $1>=32396000 && $1<39020000 {a=-$c["z"]; if(mn==""||a<mn)mn=a; if(mx==""||a>mx)mx=a} END{print "min", mn, "max", mx}' csv/vtol_quadchute_vehicle_local_position_0.csv

# intervals
awk 'BEGIN{
 d("front transition, vtol state 1 to 4", 29356000, 32396000);
 d("fixed wing, vtol state 4 until quadchute state 3", 32396000, 39020000);
 d("VT_FW_MIN_ALT change to fixed_wing_system_failure true", 39012000, 39016000);
 d("vehicle_status FW to MC edge to AUTO_LAND", 39028000, 44032000);
 d("vehicle_status failsafe true interval", 39028000, 75896000);
 d("armed interval", 5640000, 75896000);
 d("quadchute (vehicle_status FW to MC) to disarm", 39028000, 75896000)}
 function d(n,a,b){printf "%-58s %.3f s\n", n, (b-a)/1e6}'
```

## The script that drove the flight

The working directory of the generating machine is written `/path/to/work`. Run it with `nsrun.sh` as shown above.

```bash
#!/bin/bash
# vtol_quadchute.sh <rootfs_dir> <scenario_name>
# Scenario C-quadchute: SIH standard VTOL, `param set COM_QC_ACT 1` on the ground (quadchute action = Land mode,
# default 0 = Return mode), arm, takeoff, AUTO_LOITER, `commander transition` to FW, wait for the front transition
# to finish (vtol state FW, vehicle_type FIXED_WING), stay ~6 s in FW (past the 5 s VT_QC_T_ALT_LOSS window),
# then `param set VT_FW_MIN_ALT 60` (loiter altitude is ~20 m). vtol_type.cpp isMinAltBreached() is then true in
# update_fw_state() -> check_quadchute_condition() -> quadchute(MinimumAltBreached) sets
# fixed_wing_system_failure; standard.cpp update_vtol_state() goes FW_MODE -> MC_MODE directly. Commander copies
# it to failsafe_flags.vtol_fixed_wing_system_failure (vtolCheck.cpp); failsafe.cpp raises it in AUTO_LOITER with
# the COM_QC_ACT action (Land). The failsafe lands and auto-disarms; `commander land` only if still armed after 90 s.
# Fresh rootfs. Run via nsrun.sh (private /tmp + loopback, instance 0).
set -u
PX4_DIR=/path/to/work/px4/PX4-Autopilot-v1.17.0
BIN=$PX4_DIR/build/px4_sitl_default/bin
ETC=$PX4_DIR/build/px4_sitl_default/etc
OUT=/path/to/work/quadchute
ROOTFS=${1:?rootfs}; SCENARIO=${2:?scenario}
MODEL=sihsim_standard_vtol
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS" "$OUT"; cd "$ROOTFS"
PX4LOG=$OUT/$SCENARIO.px4.log; CMDLOG=$OUT/$SCENARIO.cmd.log; : > "$CMDLOG"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3N; }
say() { echo "[$(ts)] $*" | tee -a "$CMDLOG"; }
simt() { "$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +timestamp:/{printf "%.3f", $2/1e6}'; }
vs() { say "STATUS: $("$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +(timestamp|arming_state|nav_state|failsafe|vehicle_type|in_transition_mode|in_transition_to_fw|pre_flight_checks_pass):/{gsub(/^ +/,""); printf "%s | ", $0}') VTOL: $("$BIN/px4-listener" vtol_vehicle_status 2>/dev/null | awk '/^ +(vehicle_vtol_state|fixed_wing_system_failure):/{gsub(/^ +/,""); printf "%s | ", $0}') FSF: $("$BIN/px4-listener" failsafe_flags 2>/dev/null | awk '/^ +(vtol_fixed_wing_system_failure):/{gsub(/^ +/,""); printf "%s | ", $0}') LPOS: $("$BIN/px4-listener" vehicle_local_position 2>/dev/null | awk '/^ +(z|vx|vy):/{gsub(/^ +/,""); printf "%s | ", $0}') ARSPD: $("$BIN/px4-listener" airspeed_validated 2>/dev/null | awk '/^ +(calibrated_airspeed_m_s):/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
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
for p in SYS_AUTOSTART MIS_TAKEOFF_ALT NAV_LOITER_RAD COM_QC_ACT VT_FW_MIN_ALT VT_FW_QC_HMAX VT_FW_QC_P VT_FW_QC_R VT_QC_ALT_LOSS VT_QC_T_ALT_LOSS VT_ARSP_TRANS VT_TRANS_TIMEOUT VT_F_TRANS_DUR COM_DISARM_LAND SENS_EN_ARSPDSIM; do
  cmd param show $p
done
vs
cmd param set COM_QC_ACT 1
sleep 1
cmd param show COM_QC_ACT
cmd commander arm
sleep 3; vs
cmd commander takeoff
wait_for vehicle_status nav_state 17 10; vs
wait_for vehicle_status nav_state 4 120; vs
sleep 5; vs
cmd commander transition
wait_for vehicle_status in_transition_mode True 10; vs
wait_for vehicle_status vehicle_type 2 40; vs
wait_for vehicle_status in_transition_mode False 5; vs
sleep 6; vs
cmd param set VT_FW_MIN_ALT 60
wait_for vtol_vehicle_status fixed_wing_system_failure True 10; vs
wait_for vehicle_status vehicle_type 1 10; vs
wait_for failsafe_flags vtol_fixed_wing_system_failure True 10
wait_for vehicle_status failsafe True 10; vs
wait_for vehicle_status nav_state 18 10; vs
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
cp "$ULG" "$OUT/$SCENARIO.ulg"
say "COPIED $ROOTFS/$ULG -> $OUT/$SCENARIO.ulg ($(stat -c %s "$OUT/$SCENARIO.ulg") bytes)"
say "host load at end: $(cat /proc/loadavg)"
say "DONE"
```
