# Rules

`sfr seal` checks a PX4 log against a rules file and a baseline and seals the results. This page gives every rule, the log data it reads, what PASS, FAIL and N/A mean, and how to write and run your own rules file. The code is `crates/sfr-core/src/evaluate.rs` (the rules), `crates/sfr-core/src/rules.rs` (the rules file) and `crates/sfr-core/src/params.rs` (the baseline); SPEC B1.6 is the normative summary. Supported logs are PX4 v1.14 to v1.17. No threshold in this repository is a recommendation for any aircraft.

## Outcomes and exit codes

- **PASS**: the rule holds.
- **FAIL**: the rule does not hold, or the data it needs is missing from the log. Missing input is never N/A: a log that cannot show a rule holds fails it.
- **N/A**: the rule does not apply. Only two cases exist: R6 on a vehicle that is not VTOL, and R7 when the rules file has no `[authorized_sources]`.

`seal` writes the record whatever the results, and its exit code (`crates/sfr-core/src/lib.rs` `exit_code`) is:

| Exit | When |
|---|---|
| 0 | every rule PASS or N/A |
| 1 | at least one rule FAIL, R1 not among them |
| 2 | R1 FAIL (a required topic or field is missing) |
| 3 | the log, rules file or baseline is malformed, truncated, or over an input limit; nothing is written |
| 4 | a usage, key or file error; nothing is written |

`seal --dry-run` evaluates the same rules, prints the table, writes nothing and exits with the same code. The record's `status` is FAIL when any rule is FAIL. The results are always R1 to R7, then each optional rule the rules file enables, X1 to X5.

## How the rules read the log

- **One `vehicle_status` instance and one `failsafe_flags` instance**: the lowest instance with data records, else the lowest subscribed (`core_rules_read_the_lowest_instance_that_has_rows`). R1 counts data records across every instance.
- **Field types.** Integer fields such as `arming_state` and `nav_state` are read as unsigned integers no larger than their type allows; `failsafe`, `is_vtol`, `in_transition_mode` and `in_transition_to_fw` must be ULog `bool`. A field of another type reads as absent, and the rule that needs it fails. `vehicle_command` and `vehicle_command_ack` fields must be `uint8_t`, `uint16_t` or `uint32_t` (`small_uint` in `crates/sfr-core/src/ingest.rs`).
- **Armed.** The vehicle is armed from a `vehicle_status` sample with `arming_state` equal to 2 until the next sample where it is not. Every armed interval counts; one still open at the end of the log runs to its end.
- **VTOL.** A vehicle is VTOL when `vehicle_status.is_vtol` is true on any sample. Its VTOL state comes from `vehicle_status` alone (`vtol_state` in `crates/sfr-core/src/events.rs`): in transition to fixed wing (`in_transition_mode` and `in_transition_to_fw` true), in transition to multicopter (`in_transition_mode` true, `in_transition_to_fw` false), multicopter (`vehicle_type` 1) or fixed wing (`vehicle_type` 2). PX4 sets these fields the same way for standard, tiltrotor and tailsitter VTOLs, so no rule has a branch for one type. `vtol_vehicle_status` is not read.
- **VTOL type.** On a VTOL vehicle the record names the type from parameter `VT_TYPE` at log start: `tailsitter` (0), `tiltrotor` (1), `standard` (2), `unknown(<n>)` for another value, `unknown` without an int32 `VT_TYPE`. The mapping is the same in PX4 v1.14 and v1.17 (`vtol_type_comes_from_vt_type_only_on_a_vtol_vehicle`).
- **Names by version.** Nav state and arming reason names in events depend on the PX4 version; outside v1.14 to v1.17 they are null, `seal` prints a warning on stderr (`sfr: note: ... is outside the supported range PX4 v1.14 to v1.17`), and no rule result changes. Such a log is accepted and sealed, but no log outside v1.14 to v1.17 is tested; the golden logs are from v1.14.4 and v1.17.0.
- **Detail lines.** R4, R5, R6, R7, X2 and X3 list at most `MAX_DETAIL_LINES` findings, then one line `and N more; ...` that says where the rest are counted. The status does not change.

## R1: required topics present

**Checks** that each required topic has at least one data record, and that the fields the core rules read are present.

**Topics:** the rules file's `[required_topics]` list; `vehicle_status` and `failsafe_flags` always (`CORE_TOPICS` in `crates/sfr-core/src/rules.rs`); every topic in `[sealed_topics]`; and `vehicle_command` when the rules file has `[authorized_sources]`.

**Fields:** `vehicle_status.timestamp`, `arming_state`, `nav_state`, `failsafe`, `is_vtol`, `in_transition_mode`, `in_transition_to_fw` and `vehicle_type` (`VEHICLE_STATUS_FIELDS`); `failsafe_flags.timestamp`; with `[authorized_sources]`, `vehicle_command.command`, `source_system` and `source_component`, in every `vehicle_command` subscription that has data records. R1 checks names only; a field of the wrong type is reported by the rule that reads it.

**Versions and vehicles:** the same fields exist in PX4 v1.14 to v1.17, and the same list is required on every vehicle type. Logs older than v1.14 have `vehicle_status_flags` instead of `failsafe_flags` and fail.

- **PASS:** found `all present`.
- **FAIL:** found `missing: <topic>, <topic>.<field>`, one detail line per item; exit 2. A subscribed topic with no data records is missing (`removing_a_sealed_topics_data_from_its_log_fails_r1_and_names_it`).
- **N/A:** never.

A log with no data records at all is not an R1 failure but a truncated file: exit 3.

## R2: firmware matches baseline

**Checks** the log's firmware against the baseline's `# Firmware:` line.

**Inputs:** the ULog info messages `ver_sw_release` (a `uint32_t`, shown as `major.minor.patch` with `-rc`, `-beta`, `-alpha` or `-dev` from its last byte) and `ver_sw` (the git hash). PX4 v1.14 to v1.17 write both.

- **PASS:** the version equals the baseline's version exactly, and, when the baseline gives a git hash prefix, `ver_sw` starts with it (case does not matter).
- **FAIL:** each difference on its own detail line, for example `version: baseline 1.16.2, log 1.17.0` (`r2_fails_on_other_firmware_and_r5_when_the_log_ends_armed`), or `log has no ver_sw_release info message`.
- **N/A:** never.

## R3: parameters match baseline

**Checks** the parameters at log start (the 'P' records before the first subscription) against the baseline.

**Which parameters:** with `compare = "all"` (the default), every name in the baseline or the log; a parameter on one side only is a difference. With `compare = "baseline"`, only the baseline's names. Names matching a `parameters.ignore` pattern are skipped and counted. Watched parameters are compared like every other.

**Equality:** the same type and value. int32 values compare exactly; float32 values compare as numbers, so `-0` equals `0` and any NaN equals any NaN; an int32 never equals a float32.

**Versions:** each PX4 version has its own parameter set, and some parameters change on their own in flight or between flights (for example `CAL_BARO*_OFF` from barometer calibration in v1.17, `COM_MODE*_HASH` from v1.15). `examples/rules.default.toml` ignores those known to the repository's research.

- **PASS:** found `no differences`.
- **FAIL:** one detail line per difference, `NAME: baseline <value>, flown <value>`, with `absent` for a missing side, for example `MPC_XY_VEL_MAX: baseline f32:9.5, flown f32:12` (`one_changed_baseline_parameter_fails_r3_with_both_values`). Every difference is listed.
- **N/A:** never.

## R4: no failsafe in flight

**Checks** that `vehicle_status.failsafe` is never true in flight and, on a VTOL vehicle, that no quadchute happens in flight.

**In flight** means from the `vehicle_status` sample that arms through the sample that disarms, both included: a failsafe that disarms the vehicle counts (`r4_counts_a_failsafe_that_disarms_the_vehicle`), and so does a quadchute on the disarming sample (`r4_counts_a_quadchute_on_the_row_that_disarms`).

**Inputs:** `vehicle_status.arming_state` and `failsafe`; on a VTOL vehicle also `in_transition_mode`, `in_transition_to_fw` and `vehicle_type`. With no `vehicle_status`, or no `is_vtol` field, the vehicle counts as not VTOL here and R1 reports what is missing. The detail names the `failsafe_flags` booleans (and `battery_warning` above 0) true at that moment and either required by the current nav state or not true at the most recent ARM, or `unattributed`.

**Quadchute:** the VTOL state goes from fixed wing straight to multicopter, with no transition state between. It fails R4 whether or not PX4 raised `vehicle_status.failsafe`, because PX4 raises it for a quadchute only in some modes (`r4_reports_a_quadchute_even_without_vehicle_status_failsafe`). On a multicopter or fixed-wing vehicle a `vehicle_type` change is not a quadchute (`r4_needs_the_vtol_state_only_on_a_vtol_vehicle`).

**Versions:** in PX4 v1.14, `vehicle_status.failsafe` is true for any failsafe action, a warning included; from v1.15, it is true for an action other than none or a warning. Flag names differ between versions (for example `primary_geofence_breached` in v1.14 became `geofence_breached`), which changes the detail text, not the outcome.

**Tailsitters and tiltrotors:** the same rule. From the PX4 source, a quadchute during the front transition shows as a transition abort (R6) and one during the back transition as a completed back transition; no golden log has either on a tailsitter.

- **PASS:** found `never true in flight`.
- **FAIL:** found `true in flight N time(s)`, or with `, quadchute Q time(s)`; one detail line per failsafe (`failsafe in flight at boot_us <t>: <flags>`) and per quadchute (with `failsafe_flags.vtol_fixed_wing_system_failure` true, false or `not logged`).
- **N/A:** never.

The golden logs `failsafe_gps_loss` and `failsafe_battery_empty` fail R4 on a failsafe and `vtol_quadchute` on a quadchute (`failsafe_log_fails_r4_with_flag_and_time` in `crates/sfr/tests/seal_dry_run.rs`).

## R5: arm and disarm consistent

**Checks** that every ARM is followed by a DISARM and the log does not end armed.

**Input:** `vehicle_status.arming_state`; ARM and DISARM are its edges into and out of 2. A log that starts armed has an ARM at its first sample, marked `initial` ([RECORD_FORMAT.md](RECORD_FORMAT.md#event-field-initial)). The same in every supported version and vehicle type.

- **PASS:** found `<n> ARM, <n> DISARM`; a log that never arms passes with `0 ARM, 0 DISARM`.
- **FAIL:** each unmatched event: `ARM seq <n> at boot_us <t> has no DISARM`, `DISARM seq <n> ... has no ARM`, or `... has no DISARM: the log ends armed`.
- **N/A:** never.

## R6: VTOL transitions completed

**Checks** that every VTOL transition that starts also ends, and none is aborted.

**Inputs:** `vehicle_status.is_vtol`, then `in_transition_mode`, `in_transition_to_fw` and `vehicle_type`. A transition starts when a transition state is entered; it ends when transition to fixed wing reaches fixed wing, or transition to multicopter reaches multicopter; it is aborted when the transition state is left any other way. A quadchute is not a transition (R4 reports it).

**Vehicle types:** the derivation is the same for all three VTOL types. On a VTOL vehicle the first detail line is the VTOL type, for example `VTOL type tailsitter (VT_TYPE 0)` (`tailsitter_log_has_start_and_end_passes_r6_and_shows_transition_tuning`). From the PX4 source: a back transition reversed by a fixed-wing request shows as ABORT `to_mc` then START `to_fw` on a standard VTOL, and as ABORT `to_mc` alone on a tiltrotor or tailsitter; the two front transition phases of a tiltrotor are one state in `vehicle_status`, so the step between them is not visible.

- **PASS:** found `<s> START, <e> END, 0 problem(s)`; a VTOL vehicle that never transitions passes.
- **FAIL:** one detail line per abort (`VTOL_TRANSITION_ABORT to_fw seq <n> at boot_us <t>`) and for a transition still open at the end of the log; the golden log `vtol_transition_abort` fails this way (`vtol_log_has_start_and_end_and_passes_r6`).
- **N/A:** `vehicle_status.is_vtol` is false on every sample (`multicopter_log_gives_r6_not_applicable`). Without `vehicle_status` or its `is_vtol` field, R6 is FAIL, not N/A.

## R7: authorized command sources (optional)

**Checks** that every COMMAND event came from a MAVLink source listed in `[authorized_sources]`; with `category`, only commands of that category are checked. It is off unless the rules file has `[authorized_sources]`: only the operator knows their own system and component ids.

**Inputs:** `vehicle_command.command`, `source_system` and `source_component`, every instance, the whole log. A command is PAYLOAD when its id is in `[payload_commands]`, otherwise GENERAL.

**Versions:** `vehicle_command.source_component` is `uint8_t` in PX4 v1.14 and `uint16_t` from v1.15; both are read. PX4 v1.17 builds with `payload_deliverer` (SITL among them) publish a DO_GRIPPER (211, PAYLOAD) at start-up with arbitrary source ids (`docs/DIAGNOSTIC.md` item 12.3), so R7 reports it unless `category = "GENERAL"`. Source ids are what the log recorded: MAVLink source ids are self-reported unless MAVLink message signing is on, so R7 shows which source the log names, not that the source was genuine ([THREAT_MODEL.md](THREAT_MODEL.md)).

- **PASS:** commands are present and none in scope is unauthorized; found `<n> command(s) checked, all from authorized sources`.
- **FAIL:** each unauthorized command, `event seq <n>: command <id> (<category>) from system <s> component <c> at boot_us <t>`; or `cannot evaluate: ...` when `vehicle_command` has no data record, lacks one of the three fields, or holds a sample whose fields are not 8-, 16- or 32-bit unsigned integers. A log with no commands is no evidence of authorized ones (`r7_fails_and_r1_names_the_command_data_when_it_is_missing`).
- **N/A:** no `[authorized_sources]` in the rules file.

The example record `examples/reports/gz_x500_vision_hover.sfr` fails R7 on the start-up DO_GRIPPER ([examples/reports/README.md](../examples/reports/README.md)).

## Optional example rules X1 to X5

`examples/rules.extended.toml` enables all five with example thresholds that show the syntax; each is set by your flight-test lead. X1 to X4 need `vehicle_status.arming_state` and at least one armed interval, or they fail with `the vehicle never armed, so there is no flight to check`. None is ever N/A; each fails without its input data.

| Rule | Table | Reads | FAIL when |
|---|---|---|---|
| X1 minimum battery | `[extended.min_battery]` `min_remaining` (0 to 1) | `battery_status.remaining` (float) on every instance while armed, skipping samples with `connected` false or a negative remaining | the lowest remaining is below the threshold, or no usable sample |
| X2 GPS fix at arm | `[extended.gps_fix_at_arm]` `min_fix_type`, `min_satellites` | the latest `vehicle_gps_position` instance 0 sample at or before each ARM | `fix_type` or `satellites_used` is below its minimum, or no sample |
| X3 estimator fault flags | `[extended.estimator_faults]` (no keys) | `estimator_status.filter_fault_flags` of the primary estimator (`estimator_selector_status.primary_instance`, else instance 0) while armed | any value is nonzero, or no sample |
| X4 vibration and clipping | `[extended.vibration]` `max_accel_vibration_metric`, `max_accel_clipping` | `vehicle_imu_status` of the accelerometer `sensor_selection` names, while armed | the highest vibration metric or the summed clipping increase is above its maximum, or no sample |
| X5 total dropout time | `[extended.dropouts]` `max_total_ms` | every 'O' (dropout) record of the log | the total is above the maximum (a log with no dropouts totals 0) |

`extended_rules_run_when_enabled` in `crates/sfr/tests/seal_dry_run.rs` runs them on golden logs.

## The rules file

TOML, read by `parse_rules` in `crates/sfr-core/src/rules.rs`. Unknown keys and tables are errors, and an entry listed twice in any list is an error.

| Table and key | Required | Value |
|---|---|---|
| `format` | yes, before any table | `"sfr-rules/1"` |
| `[required_topics]` `topics` | yes | topic names, each 1 to 64 lowercase letters, digits and `_`; `[]` is allowed |
| `[parameters]` `compare` | no | `"all"` (default) or `"baseline"` |
| `[parameters]` `ignore` | no | name patterns: letters, digits, `_` and `*` (any run of characters, also none), up to 64 characters with at most 8 `*`, matched against the whole name, case-sensitive |
| `[watched_parameters]` `names` | with the table | parameter names shown apart in the report's transition tuning section and listed in `config.watched_parameters`; R3 compares them like the rest; a name an ignore pattern matches is an error |
| `[sealed_topics]` `topics` | with the table | topics to digest into the record ([RECORD_FORMAT.md](RECORD_FORMAT.md#sealed-topic-digests)); each is also required by R1 |
| `[payload_commands]` `ids` | with the table | command ids whose COMMAND events are PAYLOAD |
| `[authorized_sources]` `sources` | with the table | a non-empty list of `{ system = <0 to 255>, component = <0 to 65535> }`; enables R7 |
| `[authorized_sources]` `category` | no | `"PAYLOAD"` or `"GENERAL"` |
| `[extended.*]` | no | the X rules above |

Limits (`crates/sfr-core/src/rules.rs`): each list holds at most `MAX_LIST_ENTRIES` entries; `[sealed_topics]` at most `MAX_SEALED_TOPICS`, and more is a usage error (exit 4); TOML nesting and dotted keys at most `TOML_MAX_DEPTH` levels; the file at most `MAX_TEXT_BYTES` (`crates/sfr/src/main.rs`). Every other rules file error exits 3 and names the line, for example ``rules file bad.toml: line 4: unknown key `required_topics.threshold` ``. [LIMITS.md](LIMITS.md) lists every limit.

The whole rules file is embedded in the record, so a deep verify uses exactly the rules that sealed it.

## The baseline

A QGroundControl parameter export (`.params`) plus one firmware line, read by `parse_baseline` in `crates/sfr-core/src/params.rs`:

- `# Firmware: <version> [<git hash prefix>]`, exactly once, anywhere in the file. The version is compared with the log's as text (`1.17.0`); the optional prefix is 7 to 40 hex digits. Every other line starting with `#` is a comment.
- Each parameter line is five tab-separated columns: vehicle id, component id, name, value, type. The type is 6 (int32) or 9 (float32); a float32 value is rounded to float32 once, as it is read, and `nan`, `inf` and `-inf` are accepted. Names follow the PX4 rule, 1 to 16 letters, digits and `_`. A name may appear once.
- Errors exit 3 and name the line, for example ``baseline bad.params: line 2: MPC_XY_VEL_MAX: `fast` is not a number``.

Each golden log's baseline in `testdata/baselines/` is that log's own parameters at log start, written by `scripts/testdata/make_baseline.py`.

## Write and run your own rules file

Start from `examples/rules.default.toml` (core rules, transition tuning, payload command ids) or `examples/rules.extended.toml` (also the X rules and a commented R7 example). The commands below need `sfr` built as in the [README](../README.md#quickstart) and run from the repository root; they write only into `try/`.

This file requires GPS data, compares only the parameters in the baseline, treats the gripper command as PAYLOAD, and lets only the autopilot itself (system 1, component 1) send GENERAL commands:

```sh doc-test
mkdir -p try
cat > try/my_rules.toml <<'EOF'
format = "sfr-rules/1"

[required_topics]
topics = ["vehicle_status", "failsafe_flags", "vehicle_gps_position"]

[parameters]
compare = "baseline"
ignore = ["COM_FLIGHT_UUID", "LND_FLIGHT_T_*", "EKF2_MAG_DECL", "CAL_BARO*_OFF", "ASPD_SCALE_*", "COM_MODE*_HASH"]

[payload_commands]
ids = [211]

[authorized_sources]
category = "GENERAL"
sources = [{ system = 1, component = 1 }]
EOF
target/release/sfr seal testdata/sitl/v1.17.0/mc_flight_1.ulg --rules try/my_rules.toml \
  --baseline testdata/baselines/v1.17.0_mc_flight_1.params --dry-run
```

```text doc-output
sfr seal --dry-run: v1.0 evaluation release; nothing is signed or written

log       mc_flight_1.ulg (8536869 bytes)
sha256    6e7b6956c20422aa9f31a13e7f074e80cba85760928fd895eed941e9492823fc
blake3    260e044bc265ffd85abb243382d5eb555a65b696ec797438828562d49827467f
firmware  1.17.0 (d6f12ad1c4f70ad3230afd7d86e971421e02fef4)
crypto    blake3 1.8.7, ed25519-dalek 3.0.0, sha2 0.11.1 (crate versions)

RULE  STATUS  NAME                          FOUND
R1    PASS    required topics present       all present
R2    PASS    firmware matches baseline     1.17.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4
R3    PASS    parameters match baseline     no differences
R4    PASS    no failsafe in flight         never true in flight
R5    PASS    arm and disarm consistent     1 ARM, 1 DISARM
R6    N/A     VTOL transitions completed    vehicle_status.is_vtol false on every sample
R7    PASS    authorized command sources    12 command(s) checked, all from authorized sources

events    22
status    PASS
```

Without `category`, R7 checks every command and fails on the DO_GRIPPER that PX4 publishes at start-up, and `seal` exits 1:

```sh doc-test
sed '/^category/d' try/my_rules.toml > try/all_commands.toml
rc=0
target/release/sfr seal testdata/sitl/v1.17.0/mc_flight_1.ulg --rules try/all_commands.toml \
  --baseline testdata/baselines/v1.17.0_mc_flight_1.params --dry-run > try/table.txt || rc=$?
grep -A1 '^R7' try/table.txt
echo "exit $rc"
```

```text doc-output
R7    FAIL    authorized command sources    1 of 13 command(s) from unauthorized sources
              - event seq 1: command 211 (PAYLOAD) from system 191 component 46144 at boot_us 764000
exit 1
```

A mistake in the file stops `seal` before it reads the log, names the line, and exits 3:

```sh doc-test
printf 'format = "sfr-rules/1"\n\n[required_topics]\ntopics = ["vehicle_status"]\nthreshold = 3\n' > try/bad.toml
rc=0
target/release/sfr seal testdata/sitl/v1.17.0/mc_flight_1.ulg --rules try/bad.toml \
  --baseline testdata/baselines/v1.17.0_mc_flight_1.params --dry-run || rc=$?
echo "exit $rc"
```

```text doc-output
sfr: rules file try/bad.toml: line 5: unknown key `required_topics.threshold`
exit 3
```

When the dry run shows what you expect, seal with your key: replace `--dry-run` with `--key <sfr.key> --evaluation-only --out <dir>`.
