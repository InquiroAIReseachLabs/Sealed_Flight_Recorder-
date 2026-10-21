# Rules

`sfr seal` checks a PX4 log against a rules file and a baseline and seals the results. This page lists each rule, the data it reads, and how to write a rules file. The code is `crates/sfr-core/src/evaluate.rs` (rules), `crates/sfr-core/src/rules.rs` (rules file) and `crates/sfr-core/src/params.rs` (baseline); SPEC B1.6 is the normative summary. Supported logs are PX4 v1.14 to v1.17. No threshold here is a recommendation for any aircraft.

## Outcomes and exit codes

- **PASS**: the rule holds.
- **WARN**: the rule holds, and the log shows something to look at, named on the result's line: a `failsafe_flags` flag true in flight that the flight mode does not require (R4), or a parameter changed in flight (R3).
- **FAIL**: the rule does not hold, or the log lacks the data it needs, or has it with a type other than PX4's (`cannot evaluate`). Missing or unreadable input is never N/A.
- **N/A**: only R6 on a non-VTOL vehicle, R7 when the rules file has no `[authorized_sources]`, and R4 and R5 on a log with no armed flight (no ARM and no DISARM).

The record's `status` is FAIL when any rule is FAIL; else NO ARMED FLIGHT when the log has no ARM and no DISARM (R5 is N/A), which is not a PASS: the rules had no flight to check; else WARN when any rule is WARN; else PASS.

`seal` writes the record whatever the results. Exit codes (`exit_code` in `crates/sfr-core/src/lib.rs`):

| Exit | When |
|---|---|
| 0 | status PASS or WARN |
| 1 | status FAIL (R1 not among the failures), or NO ARMED FLIGHT |
| 2 | R1 FAIL (a required topic or field is missing) |
| 3 | the log, rules file or baseline is malformed, truncated before the log's first data record, or over an input limit; nothing is written (a log cut later is sealed: see [How the rules read the log](#how-the-rules-read-the-log)) |
| 4 | a usage, key or file error; nothing is written |

`seal --dry-run` runs the same rules, prints the table (with the detail lines of each FAIL and WARN), writes nothing and exits the same way. Results are R1 to R7, then each optional rule the rules file enables (X1 to X5).

## How the rules read the log

- **Instances.** Every `vehicle_status` instance (uORB `multi_id`) with data records is read: R4, R5 and R6 check each one, and a failsafe on any instance fails R4. The record states how many there are (`log.vehicle_status_instances`). Every `failsafe_flags` instance is read for R4; FAILSAFE_SET attribution uses the instance of the same number, else the lowest. R1 counts records across all instances.
- **Field types.** Every field a rule reads (`RULE_FIELDS` in `crates/sfr-core/src/ingest.rs`, and every `failsafe_flags` field PX4 defines) must exist, with the type PX4 gives it, in the message definitions of the PX4 release tag the log's `ver_sw_release` names: for a version that is not a release tag, of any tag of its minor series; with no version or one outside v1.14 to v1.17, of any supported tag. The definitions are read from the PX4-Autopilot source at each tag (`crates/sfr-core/src/px4_tables.rs`, written by `scripts/px4/px4_tables.py`; [VALIDATION.md](VALIDATION.md#px4-sources) lists every file and commit). For example `failsafe_flags` `mode_req_*` are `uint32_t` at every tag, and `vehicle_command.source_component` is `uint8_t` at v1.14 tags and `uint16_t` from v1.15. A field with another type, in any subscription of the topic that has data records, or one the log's tag does not define, is not read, and each rule that needs it FAILs with `cannot evaluate: <topic>.<field> is <type> in the log; PX4 defines <type> (<tags>)` or `... PX4 <tags> does not define it`.
- **Format definitions.** A format that names a field twice is refused: the log is malformed, exit 3, nothing is written. So is a format record after the definitions section, which the ULog specification ends at the first subscription or logged string and to which it confines format records (`docs/en/dev_log/ulog_file_format.md` in PX4-Autopilot at commit `d28a64240f7b7570d65776b9b6397eddec0dd9ba`, lines 90 to 97, 299, and 303 to 315), and a second subscription of a topic instance whose layout differs from its first. A declared field name with `[`, `]` or `.` is refused too (the specification allows letters, digits and `_` only, line 162; `_padding` names aside, which no rule reads), and so is a format that flattens to one name twice, so no declared name can stand in for another field's flattened name such as `accel_clipping[0]` (test `a_field_name_that_could_stand_for_a_flattened_name_is_refused` in `crates/sfr-core/src/ulog.rs`, and the false-pass case `clipping_decoy_field`). A data record longer than its format, trailing padding included, is refused too: the specification says the data is the message its format defines, and only the last padding field may be left out (lines 179, 180 and 359), so extra bytes are something no field describes (test `a_data_record_longer_than_its_format_is_refused` in `crates/sfr-core/src/ulog.rs`). A data record whose timestamp is lower than the one before it in the same subscription is refused: the specification requires the timestamps of one subscription to be "monotonic increasing" (line 176); PX4 logs repeat a timestamp, which is read (test `a_subscription_whose_timestamp_goes_back_is_refused` in `crates/sfr-core/src/ulog.rs`). A topic instance subscribed again with the same layout is read as one instance. Test: `a_format_record_after_the_definitions_section_is_refused` in `crates/sfr-core/src/ulog.rs`.
- **Skipped messages.** Records of a type the reader does not know, data records for a message id with no subscription, and regions dropped to reach an appended-data offset are skipped and counted; the record holds the counts (`log.skipped`), and the report and the table say `sealed with N skipped messages`.
- **A log that ends in the middle of a record.** The ULog specification (`docs/en/dev_log/ulog_file_format.md` in PX4-Autopilot at commit `d28a64240f7b7570d65776b9b6397eddec0dd9ba`, lines 477 and 478): "A parser must be able to correctly handle logs that end abruptly, in the middle of a message. The unfinished message should just be discarded." The rules read every complete record and discard the unfinished one. The tail that was cut off is an incomplete input, never evidence: it holds no DISARM and no transition end, so a log that ends armed fails R5 and one that ends in a transition fails R6, and each such finding ends with `(log ended mid-record at byte N; K trailing bytes not parsed)`. The record (`log.truncated`, schema 5), the report and the table state the same line; `log.size` and the digests cover every byte of the file. A log that ends before its first data record holds no flight and is refused, exit 3. Tests: `a_log_cut_mid_record_seals_says_where_and_its_digests_cover_every_byte` in `crates/sfr/tests/seal_verify.rs`, on `testdata/synthetic/cut_after_arm.ulg`.
- **Armed.** From a `vehicle_status` sample with `arming_state` 2 until the next sample where it is not, or the end of the log (for a log that ends in the middle of a record, its last complete record); with several instances, armed when any instance is.
- **VTOL.** `vehicle_status.is_vtol` true on any sample. The VTOL state comes from `vehicle_status` alone (`vtol_state` in `crates/sfr-core/src/events.rs`): transition to fixed wing (`in_transition_mode` and `in_transition_to_fw`), transition to multicopter (`in_transition_mode` only), multicopter (`vehicle_type` 1) or fixed wing (`vehicle_type` 2). No rule branches on VTOL type, and `vtol_vehicle_status` is not read. The record names the type from `VT_TYPE` at log start: `tailsitter` (0), `tiltrotor` (1), `standard` (2), `unknown(<n>)`, or `unknown` without an int32 `VT_TYPE`.
- **Versions.** Nav state and arming reason names depend on the PX4 version; outside v1.14 to v1.17 they are null and no result changes. `seal` refuses such a log, or one whose version it cannot read, unless given `--allow-untested-version`. With it, `seal` warns on stderr, and the record (`seal.allow_untested_version`) and report say so. The golden logs are from v1.14.4 and v1.17.0; no log outside the range is tested.
- **ULog file format version.** The ULog specification gives the current file format version as 1 (line 65 of the file above) and asks a parser to read future versions as well, with a warning if it likes (line 475). `sfr` reads any version as version 1, and is tested on versions 0 and 1. `seal` refuses a log of a version above 1 (exit 4, nothing written) unless given `--allow-untested-version`; with it, `seal` warns on stderr, and the record (`seal.allow_untested_ulog_version`, `log.ulog_version`, schema 5) and report say `Untested ULog file version`. Test: `a_ulog_file_version_above_1_is_refused_unless_allowed_and_then_recorded` in `crates/sfr/tests/seal_verify.rs`.
- **Fields not read.** A detail line that starts `not read: ` names an input field the rule did not read, such as a `failsafe_flags` field no supported PX4 release defines. The table and the report show such lines whatever the rule's status, as well as every detail line of a FAIL or WARN (test `a_not_read_note_is_shown_in_the_report_and_the_table_when_r4_passes`).
- **Detail lines.** R3's changes in flight, R4, R5, R6, R7, X2 and X3 list at most `MAX_DETAIL_LINES` findings, then `and N more; ...`. The status does not change.

## R1: required topics present

Each required topic has a data record, and the fields the core rules read exist.

- **Topics:** `[required_topics]`; `vehicle_status` and `failsafe_flags` always (`CORE_TOPICS` in `crates/sfr-core/src/rules.rs`); every `[sealed_topics]` topic; `vehicle_command` when `[authorized_sources]` is set.
- **Fields:** `vehicle_status.timestamp`, `arming_state`, `nav_state`, `failsafe`, `is_vtol`, `in_transition_mode`, `in_transition_to_fw`, `vehicle_type` (`VEHICLE_STATUS_FIELDS`); `failsafe_flags.timestamp`; with `[authorized_sources]`, `vehicle_command.command`, `source_system`, `source_component` in every `vehicle_command` subscription that has data. R1 checks names only; the rule that reads a field reports a wrong type.
- Logs older than v1.14 have `vehicle_status_flags` instead of `failsafe_flags` and fail.

**PASS** `all present`. **FAIL** `missing: <topic>, <topic>.<field>`, one detail line per item, exit 2; a subscribed topic with no data is missing. **N/A** never. A log with no data records at all is truncated: exit 3. A log that ends in the middle of a record is read up to it, and R1 counts the complete records.

## R2: firmware matches baseline

The firmware the log states equals the baseline's `# Firmware:` line. Inputs: the info messages `ver_sw_release` (`uint32_t`, shown as `major.minor.patch` plus a `-rc`, `-beta`, `-alpha` or `-dev` suffix) and `ver_sw` (git hash). Both are what the log says about itself, and the baseline is what the operator gave, so the line says so: `log states PX4 <version> <hash> (self-reported); baseline file sha256 <digest> (operator-supplied)`. The baseline file's SHA-256 is in the record (`baseline.sha256`).

**PASS** the versions are equal, and a baseline git hash prefix, if given, starts `ver_sw` (case-insensitive). **FAIL** one line per difference, such as `version: baseline 1.16.2, log 1.17.0` or `log has no ver_sw_release info message`. **N/A** never.

## R3: parameters match baseline

The parameters in effect at every ARM equal the baseline, and none changes in flight. The parameters in effect at an ARM are those at log start (the 'P' records before the first subscription), changed by every data-section 'P' record before the arming `vehicle_status` row in file order. A log with no ARM is compared at its end.

- **Which:** with `compare = "all"` (default), every name in the baseline or the log, so a parameter on one side only is a difference; with `"baseline"`, the baseline's names. Names matching a `parameters.ignore` pattern are skipped and counted. Watched parameters are compared like the rest.
- **Equality:** same type and value. int32 compares exactly; float32 compares as numbers (`-0` equals `0`, any NaN equals any NaN); an int32 never equals a float32.
- **Changes in flight:** a data-section 'P' record that changes a value after an ARM (a later time, or the same time and later in the file) and at or before the DISARM is a PARAM_CHANGED_IN_FLIGHT event. R3 counts those of the parameters it does not ignore: `N parameter(s) changed in flight`, a WARN, one detail line each.
- **The line:** after the result, R3 prints its ignore list and how many differences and changes in flight the list suppressed (`ignore [<patterns>] suppressed N difference(s)`), and the baseline file's SHA-256 marked `(operator-supplied)`.
- **Ignoring everything:** ignore patterns that together match every parameter name turn R3 off: `*` alone, or several patterns that cover every name between them, such as one per character a name can start with (`Pattern::cover_every_name` in `crates/sfr-core/src/params.rs` searches every name of up to 16 characters; test `patterns_cover_every_name_only_when_no_name_escapes_them_all`). `seal` refuses such a rules file (exit 4) unless given `--allow-ignore-all`, which the record states (`seal.allow_ignore_all`) and the report shows.
- **Changing parameters:** some change on their own (`CAL_BARO*_OFF` in v1.17, `COM_MODE*_HASH` from v1.15). `examples/rules.default.toml` ignores the ones found here.

**PASS** `no differences`. **WARN** `no differences at ARM; N parameter(s) changed in flight`. **FAIL** `N differ`, one line per difference, `NAME: baseline <value>, flown <value>`, `absent` for a missing side, such as `MPC_XY_VEL_MAX: baseline f32:9.5, flown f32:12`, followed by `(set by a parameter record at boot_us <t>)` when a data-section record set the flown value. **N/A** never.

## R4: no failsafe in flight

`vehicle_status.failsafe` is never true in flight, no `failsafe_flags` flag that the flight mode in effect requires is true in flight, and, on a VTOL vehicle, no quadchute happens in flight.

- **In flight:** from the `vehicle_status` sample that arms through the sample that disarms, both included. A failsafe or quadchute on the disarming sample counts.
- **Inputs:** `arming_state`, `nav_state`, `failsafe` and `failsafe_flags`; on a VTOL vehicle also `in_transition_mode`, `in_transition_to_fw`, `vehicle_type`. Without `vehicle_status` or `is_vtol` the vehicle counts as not VTOL here, and R1 reports what is missing. Without `failsafe_flags` data R4 FAILs (`cannot evaluate`). The detail of a failsafe names the `failsafe_flags` booleans (and `battery_warning` above 0) responsible, or `unattributed`.
- **Flags:** every `failsafe_flags` field PX4 defines as a boolean (and `battery_warning` above 0) true in flight, on every instance, is listed; a field no supported PX4 release defines is not read, and R4's detail names it (`not read: failsafe_flags.<name> ...`). A flag whose `mode_req_*` field has the bit of the `nav_state` in effect set is required by that mode (the flag and mask pairs of PX4 `FailsafeBase::modeCanRun` in `failsafe/framework.cpp`, and for `mode_req_manual_control` and `mode_req_wind_and_flight_time_compliance` of `HealthAndArmingChecks/checks/modeCheck.cpp`, read at each release tag; the same pairing FAILSAFE_SET attribution uses): R4 FAILs, `required failsafe_flags <names> true in flight`. Any other flag true in flight is a warning, named on the R4 line: `warning: failsafe_flags <names> true in flight`, and R4 is WARN if nothing failed. SITL logs warn on `manual_control_signal_lost` and `gcs_connection_lost`, since SITL runs without an RC link or ground station.
- **Hazard flags:** a hazard-class flag true on every `failsafe_flags` sample of a flight (from the sample that arms through the one that disarms) fails R4 whatever the mode requires: `hazard failsafe_flags <names> true for the whole flight`. The hazard class is `HAZARD_FLAGS` in `crates/sfr-core/src/evaluate.rs`, each name a `bool` in PX4's `msg/FailsafeFlags.msg` at the tags given (test `every_hazard_flag_is_a_px4_bool_exactly_at_its_stated_tags`): `fd_critical_failure`, `fd_esc_arming_failure`, `fd_imbalanced_prop`, `fd_motor_failure`, `battery_unhealthy`, `mission_failure`, `vtol_fixed_wing_system_failure`, `wind_limit_exceeded` and `flight_time_limit_exceeded` (v1.14.0 to v1.17.0), `primary_geofence_breached` (v1.14.0 to v1.14.4), `geofence_breached` (v1.15.0 to v1.17.0) and `navigator_failure` (v1.16.0 to v1.17.0). A hazard flag true on only some samples of a flight, and every other flag, is a warning unless the mode requires it.
- **Nav state range:** a `nav_state` in flight at or above `NAVIGATION_STATE_MAX` of every tag the log's version selects (23 at the v1.14 tags, 31 from v1.15.0) names no mode, so no mode requirement can say whether a flag is required: R4 FAILs with `cannot evaluate: vehicle_status.nav_state is N in flight at boot_us T, at or above NAVIGATION_STATE_MAX (M) of PX4 <tags>` (test `r4_cannot_evaluate_a_nav_state_at_or_above_navigation_state_max`).
- **Gaps in `failsafe_flags`:** PX4 publishes `failsafe_flags` when a check result changes and otherwise once more than 500 ms have passed, with the checks run at most every 100 ms (`HealthAndArmingChecks.cpp` and `Commander.cpp` at every tag v1.14.0 to v1.17.0), so samples are at most 600 ms apart. A gap longer than 1000 ms (`FAILSAFE_FLAGS_MAX_GAP_US` in `crates/sfr-core/src/evaluate.rs`) between two samples of an instance that overlaps a flight is a warning: R4 did not see the flags then. `warning: failsafe_flags N gap(s) over 1000 ms in flight, longest M ms`, and a detail line with where the longest starts (test `r4_warns_on_a_failsafe_flags_gap_in_flight_over_the_bound`). The golden flights' longest gap in flight is 600 ms.
- **No armed flight:** with no ARM and no DISARM, R4 is N/A (`no armed flight: ...`).
- **Quadchute:** the VTOL state goes from fixed wing straight to multicopter, with no transition between. It fails R4 whether or not PX4 raised `failsafe`, which it does only in some modes. On other vehicles a `vehicle_type` change is not a quadchute.
- **Versions:** in v1.14 `failsafe` is true for any failsafe action, a warning included; from v1.15 only for an action other than none or a warning. Flag names change between versions, which changes the detail text only.

**PASS** `never true in flight`. **WARN** `never true in flight; warning: failsafe_flags <names> true in flight`. **FAIL** names what failed, each part only when it happened, joined by `, `: `true in flight N time(s)` (`vehicle_status.failsafe`), `quadchute Q time(s)`, `required failsafe_flags <names> true in flight`, `hazard failsafe_flags <names> true for the whole flight`; one line per failsafe (`failsafe in flight at boot_us <t>: <flags>`) and per quadchute (with `failsafe_flags.vtol_fixed_wing_system_failure` true, false or `not logged`). **N/A** no armed flight.

The golden logs `failsafe_gps_loss` and `failsafe_battery_empty` fail on a failsafe and `vtol_quadchute` on a quadchute.

## R5: arm and disarm consistent

Every ARM is followed by a DISARM, and the log does not end armed, on every `vehicle_status` instance. Input: `vehicle_status.arming_state`; ARM and DISARM are its edges into and out of 2. A log that starts armed has an ARM at its first sample, marked `initial` ([RECORD_FORMAT.md](RECORD_FORMAT.md#event-field-initial)). Same in every version and vehicle type.

**PASS** `<n> ARM, <n> DISARM`. **FAIL** each unmatched event: `ARM seq <n> at boot_us <t> has no DISARM`, `DISARM seq <n> ... has no ARM`, or `... has no DISARM: the log ends armed`, followed by `(log ended mid-record at byte N; K trailing bytes not parsed)` when the log ends in the middle of a record: the cut-off tail is not a DISARM. **N/A** `no armed flight: vehicle_status.arming_state has no ARM and no DISARM`: a log that never arms is no evidence of a consistent flight, and the record's status is NO ARMED FLIGHT.

## R6: VTOL transitions completed

Every VTOL transition that starts also ends, and none is aborted. Inputs: `is_vtol`, `in_transition_mode`, `in_transition_to_fw`, `vehicle_type`. A transition starts when a transition state is entered. It ends when transition to fixed wing reaches fixed wing, or transition to multicopter reaches multicopter. Leaving a transition state any other way is an abort. A quadchute is not a transition (R4 reports it).

The derivation is the same for all three VTOL types. On a VTOL vehicle the first detail line is the type, such as `VTOL type tailsitter (VT_TYPE 0)`.

**PASS** `<s> START, <e> END, 0 problem(s)`; a VTOL vehicle that never transitions passes. **FAIL** one line per abort (`VTOL_TRANSITION_ABORT to_fw seq <n> at boot_us <t>`) and for a transition still open at the end (naming the cut, as R5 does, when the log ends in the middle of a record); the golden log `vtol_transition_abort` fails this way. **N/A** `is_vtol` is false on every sample; without `vehicle_status` or `is_vtol`, R6 is FAIL. When `is_vtol` is false on every sample but `system_type` is one PX4 counts as VTOL (19 to 23, `VTOL_MAV_TYPES` in `crates/sfr-core/src/evaluate.rs`: the values for which `is_vtol` in PX4's `src/modules/commander/commander_helper.cpp` is true, the same at every tag v1.14.0 to v1.17.0) on some sample, the log contradicts itself and R6 FAILs: `cannot evaluate: vehicle_status.system_type is <n>, a VTOL MAV_TYPE, but is_vtol is false on every sample`. MAV_TYPE 24 and 25 are VTOL types in MAVLink that PX4's `is_vtol` does not count, so with `is_vtol` false they are no contradiction: R6 is N/A, and its found text names the type (`... system_type 24 is a MAVLink VTOL MAV_TYPE that PX4's is_vtol does not count (v1.14 to v1.17)`; test `r6_counts_vtol_as_px4_is_vtol_does`).

## R7: authorized command sources (optional)

Every COMMAND event came from a MAVLink source listed in `[authorized_sources]`; with `category`, only commands of that category are checked. R7 is off without `[authorized_sources]`, because only the operator knows their own system and component ids.

- **Inputs:** `vehicle_command.command`, `source_system`, `source_component`, every instance, the whole log. A command is PAYLOAD when its id is in `[payload_commands]`, else GENERAL.
- **The line:** R7 states its scope (`every category`, or `GENERAL only` or `PAYLOAD only`), how many commands the scope excluded, and that source ids are self-reported by the sender; the line is part of the signed record.
- **Versions:** `source_component` is `uint8_t` in v1.14 and `uint16_t` from v1.15; both are read. PX4 v1.17 builds with `payload_deliverer` (SITL included) publish a DO_GRIPPER (211, PAYLOAD; listed in `examples/rules.default.toml`) at start-up with arbitrary source ids, so R7 reports it unless `category = "GENERAL"`.
- MAVLink source ids are self-reported unless message signing is on, so R7 shows which source the log names, not that it was genuine ([THREAT_MODEL.md](THREAT_MODEL.md)).

**PASS** `<n> command(s) checked, all from authorized sources; scope <scope>, <m> excluded by scope; source ids are self-reported by the sender`. **FAIL** each unauthorized command, `event seq <n>: command <id> (<category>) from system <s> component <c> at boot_us <t>`; or `cannot evaluate: ...` when `vehicle_command` has no data, lacks one of the three fields, or has one with a type other than PX4's. A log with no commands is no evidence of authorized ones. **N/A** no `[authorized_sources]`.

The example record `examples/reports/gz_x500_vision_hover.sfr` fails R7 on the start-up DO_GRIPPER ([examples/reports/README.md](../examples/reports/README.md)).

## Optional rules X1 to X5

`examples/rules.extended.toml` enables all five with example thresholds; set your own. X1 to X4 need `arming_state` and at least one armed interval, or they fail with `the vehicle never armed, so there is no flight to check`. None is ever N/A; each fails without its input data, or when a field it reads has a type other than PX4's.

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

Limits (`crates/sfr-core/src/rules.rs`): a list holds at most `MAX_LIST_ENTRIES` entries, `[sealed_topics]` at most `MAX_SEALED_TOPICS` (more is refused, exit 3), TOML nesting at most `TOML_MAX_DEPTH` levels, and the file at most `MAX_TEXT_BYTES` (`crates/sfr/src/main.rs`). Every other rules file error exits 3 and names the line. [LIMITS.md](LIMITS.md) lists every limit.

The whole rules file is embedded in the record, so a deep verify uses the rules that sealed it.

## The baseline

A QGroundControl parameter export (`.params`) plus one firmware line, read by `parse_baseline` in `crates/sfr-core/src/params.rs`:

- `# Firmware: <version> [<git hash prefix>]`, exactly once. The version is compared with the log's as text (`1.17.0`); the optional prefix is 7 to 40 hex digits. Other `#` lines are comments.
- Each parameter line has five tab-separated columns: vehicle id, component id, name, value, type. The type is 6 (int32) or 9 (float32); a float32 value is rounded once as it is read, and `nan`, `inf` and `-inf` are accepted. A name is 1 to 16 letters, digits and `_`, and appears once.
- Errors exit 3 and name the line.

Each golden log's baseline in `testdata/baselines/` is that log's own parameters in effect at its first ARM (`scripts/testdata/make_baseline.py`).

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
blake3    260e044bc265ffd85abb243382d5eb555a65b696ec797438828562d49827467f (checked by verify --ulog like SHA-256; adds no security beyond it)
firmware  1.17.0 (d6f12ad1c4f70ad3230afd7d86e971421e02fef4)
crypto    blake3 1.8.7, ed25519-dalek 3.0.0, sha2 0.11.1 (crate versions)

RULE  STATUS  NAME                          FOUND
R1    PASS    required topics present       all present
R2    PASS    firmware matches baseline     log states PX4 1.17.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4 (self-reported); baseline file sha256 2a9d3eadefab6e234295a2c43f8b8dbec92744812fc7edecec1ceada763c1b63 (operator-supplied)
R3    PASS    parameters match baseline     no differences; ignore [COM_FLIGHT_UUID, LND_FLIGHT_T_*, EKF2_MAG_DECL, CAL_BARO*_OFF, ASPD_SCALE_*, COM_MODE*_HASH] suppressed 1 difference(s); baseline file sha256 2a9d3eadefab6e234295a2c43f8b8dbec92744812fc7edecec1ceada763c1b63 (operator-supplied)
R4    WARN    no failsafe in flight         never true in flight; warning: failsafe_flags auto_mission_missing, gcs_connection_lost, manual_control_signal_lost, offboard_control_signal_lost true in flight
              - warning: failsafe_flags.auto_mission_missing true in flight from boot_us 4424000 (62 sample(s)), not required by the nav_state in effect
              - warning: failsafe_flags.gcs_connection_lost true in flight from boot_us 4424000 (62 sample(s)), not required by the nav_state in effect
              - warning: failsafe_flags.manual_control_signal_lost true in flight from boot_us 4424000 (62 sample(s)), not required by the nav_state in effect
              - warning: failsafe_flags.offboard_control_signal_lost true in flight from boot_us 4424000 (62 sample(s)), not required by the nav_state in effect
R5    PASS    arm and disarm consistent     1 ARM, 1 DISARM
R6    N/A     VTOL transitions completed    vehicle_status.is_vtol false on every sample
R7    PASS    authorized command sources    12 command(s) checked, all from authorized sources; scope GENERAL only, 1 excluded by scope; source ids are self-reported by the sender

events    22
status    WARN
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
R7    FAIL    authorized command sources    1 of 13 command(s) from unauthorized sources; scope every category, 0 excluded by scope; source ids are self-reported by the sender
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
