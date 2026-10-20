# Rules

`sfr seal` checks a PX4 log against a rules file and a baseline and seals the results. This page lists each rule, the data it reads, and how to write a rules file. The code is `crates/sfr-core/src/evaluate.rs` (rules), `crates/sfr-core/src/rules.rs` (rules file) and `crates/sfr-core/src/params.rs` (baseline); SPEC B1.6 is the normative summary. Supported logs are PX4 v1.14 to v1.17. No threshold here is a recommendation for any aircraft.

## Outcomes and exit codes

- **PASS**: the rule holds.
- **FAIL**: the rule does not hold, or the log lacks the data it needs. Missing input is never N/A.
- **N/A**: only R6 on a non-VTOL vehicle, and R7 when the rules file has no `[authorized_sources]`.

`seal` writes the record whatever the results. Exit codes (`exit_code` in `crates/sfr-core/src/lib.rs`):

| Exit | When |
|---|---|
| 0 | every rule PASS or N/A |
| 1 | at least one rule FAIL, R1 not among them |
| 2 | R1 FAIL (a required topic or field is missing) |
| 3 | the log, rules file or baseline is malformed, truncated, or over an input limit; nothing is written |
| 4 | a usage, key or file error; nothing is written |

`seal --dry-run` runs the same rules, prints the table, writes nothing and exits the same way. The record's `status` is FAIL when any rule is FAIL. Results are R1 to R7, then each optional rule the rules file enables (X1 to X5).

## How the rules read the log

- **Instances.** `vehicle_status` and `failsafe_flags` are read from the lowest instance with data records, else the lowest subscribed. R1 counts records across all instances.
- **Field types.** Integer fields (`arming_state`, `nav_state`) must be unsigned integers that fit their type; `failsafe`, `is_vtol`, `in_transition_mode` and `in_transition_to_fw` must be ULog `bool`. Any other type reads as absent and the rule that needs it fails. `vehicle_command` and `vehicle_command_ack` fields must be `uint8_t`, `uint16_t` or `uint32_t` (`small_uint` in `crates/sfr-core/src/ingest.rs`).
- **Armed.** From a `vehicle_status` sample with `arming_state` 2 until the next sample where it is not, or the end of the log.
- **VTOL.** `vehicle_status.is_vtol` true on any sample. The VTOL state comes from `vehicle_status` alone (`vtol_state` in `crates/sfr-core/src/events.rs`): transition to fixed wing (`in_transition_mode` and `in_transition_to_fw`), transition to multicopter (`in_transition_mode` only), multicopter (`vehicle_type` 1) or fixed wing (`vehicle_type` 2). No rule branches on VTOL type, and `vtol_vehicle_status` is not read. The record names the type from `VT_TYPE` at log start: `tailsitter` (0), `tiltrotor` (1), `standard` (2), `unknown(<n>)`, or `unknown` without an int32 `VT_TYPE`.
- **Versions.** Nav state and arming reason names depend on the PX4 version; outside v1.14 to v1.17 they are null and no result changes. `seal` refuses such a log, or one whose version it cannot read, unless given `--allow-untested-version`. With it, `seal` warns on stderr, and the record (`seal.allow_untested_version`) and report say so. The golden logs are from v1.14.4 and v1.17.0; no log outside the range is tested.
- **Detail lines.** R4, R5, R6, R7, X2 and X3 list at most `MAX_DETAIL_LINES` findings, then `and N more; ...`. The status does not change.

## R1: required topics present

Each required topic has a data record, and the fields the core rules read exist.

- **Topics:** `[required_topics]`; `vehicle_status` and `failsafe_flags` always (`CORE_TOPICS` in `crates/sfr-core/src/rules.rs`); every `[sealed_topics]` topic; `vehicle_command` when `[authorized_sources]` is set.
- **Fields:** `vehicle_status.timestamp`, `arming_state`, `nav_state`, `failsafe`, `is_vtol`, `in_transition_mode`, `in_transition_to_fw`, `vehicle_type` (`VEHICLE_STATUS_FIELDS`); `failsafe_flags.timestamp`; with `[authorized_sources]`, `vehicle_command.command`, `source_system`, `source_component` in every `vehicle_command` subscription that has data. R1 checks names only; the rule that reads a field reports a wrong type.
- Logs older than v1.14 have `vehicle_status_flags` instead of `failsafe_flags` and fail.

**PASS** `all present`. **FAIL** `missing: <topic>, <topic>.<field>`, one detail line per item, exit 2; a subscribed topic with no data is missing. **N/A** never. A log with no data records at all is truncated: exit 3.

## R2: firmware matches baseline

The log's firmware equals the baseline's `# Firmware:` line. Inputs: the info messages `ver_sw_release` (`uint32_t`, shown as `major.minor.patch` plus a `-rc`, `-beta`, `-alpha` or `-dev` suffix) and `ver_sw` (git hash).

**PASS** the versions are equal, and a baseline git hash prefix, if given, starts `ver_sw` (case-insensitive). **FAIL** one line per difference, such as `version: baseline 1.16.2, log 1.17.0` or `log has no ver_sw_release info message`. **N/A** never.

## R3: parameters match baseline

The parameters at log start (the 'P' records before the first subscription) equal the baseline.

- **Which:** with `compare = "all"` (default), every name in the baseline or the log, so a parameter on one side only is a difference; with `"baseline"`, the baseline's names. Names matching a `parameters.ignore` pattern are skipped and counted. Watched parameters are compared like the rest.
- **Equality:** same type and value. int32 compares exactly; float32 compares as numbers (`-0` equals `0`, any NaN equals any NaN); an int32 never equals a float32.
- **Changing parameters:** some change on their own (`CAL_BARO*_OFF` in v1.17, `COM_MODE*_HASH` from v1.15). `examples/rules.default.toml` ignores the ones found here.

**PASS** `no differences`. **FAIL** one line per difference, `NAME: baseline <value>, flown <value>`, `absent` for a missing side, such as `MPC_XY_VEL_MAX: baseline f32:9.5, flown f32:12`. **N/A** never.

## R4: no failsafe in flight

`vehicle_status.failsafe` is never true in flight and, on a VTOL vehicle, no quadchute happens in flight.

- **In flight:** from the `vehicle_status` sample that arms through the sample that disarms, both included. A failsafe or quadchute on the disarming sample counts.
- **Inputs:** `arming_state` and `failsafe`; on a VTOL vehicle also `in_transition_mode`, `in_transition_to_fw`, `vehicle_type`. Without `vehicle_status` or `is_vtol` the vehicle counts as not VTOL here, and R1 reports what is missing. The detail names the `failsafe_flags` booleans (and `battery_warning` above 0) responsible, or `unattributed`.
- **Quadchute:** the VTOL state goes from fixed wing straight to multicopter, with no transition between. It fails R4 whether or not PX4 raised `failsafe`, which it does only in some modes. On other vehicles a `vehicle_type` change is not a quadchute.
- **Versions:** in v1.14 `failsafe` is true for any failsafe action, a warning included; from v1.15 only for an action other than none or a warning. Flag names change between versions, which changes the detail text only.

**PASS** `never true in flight`. **FAIL** `true in flight N time(s)`, plus `, quadchute Q time(s)` if any; one line per failsafe (`failsafe in flight at boot_us <t>: <flags>`) and per quadchute (with `failsafe_flags.vtol_fixed_wing_system_failure` true, false or `not logged`). **N/A** never.

The golden logs `failsafe_gps_loss` and `failsafe_battery_empty` fail on a failsafe and `vtol_quadchute` on a quadchute.

## R5: arm and disarm consistent

Every ARM is followed by a DISARM, and the log does not end armed. Input: `vehicle_status.arming_state`; ARM and DISARM are its edges into and out of 2. A log that starts armed has an ARM at its first sample, marked `initial` ([RECORD_FORMAT.md](RECORD_FORMAT.md#event-field-initial)). Same in every version and vehicle type.

**PASS** `<n> ARM, <n> DISARM`; a log that never arms passes with `0 ARM, 0 DISARM`. **FAIL** each unmatched event: `ARM seq <n> at boot_us <t> has no DISARM`, `DISARM seq <n> ... has no ARM`, or `... has no DISARM: the log ends armed`. **N/A** never.

## R6: VTOL transitions completed

Every VTOL transition that starts also ends, and none is aborted. Inputs: `is_vtol`, `in_transition_mode`, `in_transition_to_fw`, `vehicle_type`. A transition starts when a transition state is entered. It ends when transition to fixed wing reaches fixed wing, or transition to multicopter reaches multicopter. Leaving a transition state any other way is an abort. A quadchute is not a transition (R4 reports it).

The derivation is the same for all three VTOL types. On a VTOL vehicle the first detail line is the type, such as `VTOL type tailsitter (VT_TYPE 0)`.

**PASS** `<s> START, <e> END, 0 problem(s)`; a VTOL vehicle that never transitions passes. **FAIL** one line per abort (`VTOL_TRANSITION_ABORT to_fw seq <n> at boot_us <t>`) and for a transition still open at the end; the golden log `vtol_transition_abort` fails this way. **N/A** `is_vtol` is false on every sample; without `vehicle_status` or `is_vtol`, R6 is FAIL.

## R7: authorized command sources (optional)

Every COMMAND event came from a MAVLink source listed in `[authorized_sources]`; with `category`, only commands of that category are checked. R7 is off without `[authorized_sources]`, because only the operator knows their own system and component ids.

- **Inputs:** `vehicle_command.command`, `source_system`, `source_component`, every instance, the whole log. A command is PAYLOAD when its id is in `[payload_commands]`, else GENERAL.
- **Versions:** `source_component` is `uint8_t` in v1.14 and `uint16_t` from v1.15; both are read. PX4 v1.17 builds with `payload_deliverer` (SITL included) publish a DO_GRIPPER (211, PAYLOAD; listed in `examples/rules.default.toml`) at start-up with arbitrary source ids, so R7 reports it unless `category = "GENERAL"`.
- MAVLink source ids are self-reported unless message signing is on, so R7 shows which source the log names, not that it was genuine ([THREAT_MODEL.md](THREAT_MODEL.md)).

**PASS** `<n> command(s) checked, all from authorized sources`. **FAIL** each unauthorized command, `event seq <n>: command <id> (<category>) from system <s> component <c> at boot_us <t>`; or `cannot evaluate: ...` when `vehicle_command` has no data, lacks one of the three fields, or has a sample whose fields are not `uint8_t`, `uint16_t` or `uint32_t`. A log with no commands is no evidence of authorized ones. **N/A** no `[authorized_sources]`.

The example record `examples/reports/gz_x500_vision_hover.sfr` fails R7 on the start-up DO_GRIPPER ([examples/reports/README.md](../examples/reports/README.md)).

## Optional rules X1 to X5

`examples/rules.extended.toml` enables all five with example thresholds; set your own. X1 to X4 need `arming_state` and at least one armed interval, or they fail with `the vehicle never armed, so there is no flight to check`. None is ever N/A; each fails without its input data.

| Rule | Table | Reads | FAIL when |
|---|---|---|---|
| X1 minimum battery | `[extended.min_battery]` `min_remaining` (0 to 1) | `battery_status.remaining` on every instance while armed, skipping samples with `connected` false or a negative remaining | the lowest value is below the threshold, or no usable sample |
| X2 GPS fix at arm | `[extended.gps_fix_at_arm]` `min_fix_type`, `min_satellites` | the latest `vehicle_gps_position` instance 0 sample at or before each ARM | `fix_type` or `satellites_used` is below its minimum, or no sample |
| X3 estimator fault flags | `[extended.estimator_faults]` (no keys) | `estimator_status.filter_fault_flags` of the primary estimator (`estimator_selector_status.primary_instance`, else 0) while armed | any value is nonzero, or no sample |
| X4 vibration and clipping | `[extended.vibration]` `max_accel_vibration_metric`, `max_accel_clipping` | `vehicle_imu_status` of the accelerometer `sensor_selection` names, while armed | the highest vibration metric or the summed clipping increase is above its maximum, or no sample |
| X5 total dropout time | `[extended.dropouts]` `max_total_ms` | every 'O' (dropout) record | the total is above the maximum (no dropouts totals 0) |

`extended_rules_run_when_enabled` in `crates/sfr/tests/seal_dry_run.rs` runs them on golden logs.

## The rules file

TOML, read by `parse_rules` in `crates/sfr-core/src/rules.rs`. Unknown keys and tables, and an entry listed twice in a list, are errors.

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

Limits (`crates/sfr-core/src/rules.rs`): a list holds at most `MAX_LIST_ENTRIES` entries, `[sealed_topics]` at most `MAX_SEALED_TOPICS` (more is a usage error, exit 4), TOML nesting at most `TOML_MAX_DEPTH` levels, and the file at most `MAX_TEXT_BYTES` (`crates/sfr/src/main.rs`). Every other rules file error exits 3 and names the line. [LIMITS.md](LIMITS.md) lists every limit.

The whole rules file is embedded in the record, so a deep verify uses the rules that sealed it.

## The baseline

A QGroundControl parameter export (`.params`) plus one firmware line, read by `parse_baseline` in `crates/sfr-core/src/params.rs`:

- `# Firmware: <version> [<git hash prefix>]`, exactly once. The version is compared with the log's as text (`1.17.0`); the optional prefix is 7 to 40 hex digits. Other `#` lines are comments.
- Each parameter line has five tab-separated columns: vehicle id, component id, name, value, type. The type is 6 (int32) or 9 (float32); a float32 value is rounded once as it is read, and `nan`, `inf` and `-inf` are accepted. A name is 1 to 16 letters, digits and `_`, and appears once.
- Errors exit 3 and name the line.

Each golden log's baseline in `testdata/baselines/` is that log's own start-of-log parameters (`scripts/testdata/make_baseline.py`).

## Write and run your own rules file

Start from `examples/rules.default.toml` or `examples/rules.extended.toml` (which adds the X rules and a commented R7 example). These commands need `sfr` built as in the [README](../README.md), run from the repository root, and write only into `try/`.

This file requires GPS data, compares only the baseline's parameters, treats the gripper command as PAYLOAD, and lets only the autopilot (system 1, component 1) send GENERAL commands:

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
sfr seal --dry-run: sfr 0.1.0; nothing is signed or written

log       mc_flight_1.ulg (8536869 bytes)
sha256    6e7b6956c20422aa9f31a13e7f074e80cba85760928fd895eed941e9492823fc
blake3    260e044bc265ffd85abb243382d5eb555a65b696ec797438828562d49827467f (index only, adds no security)
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

Without `category`, R7 checks every command and fails on the start-up DO_GRIPPER, so `seal` exits 1:

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

When the dry run looks right, replace `--dry-run` with `--key <sfr.key> --evaluation-only --out <dir>` to seal.
