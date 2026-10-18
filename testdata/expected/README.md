# Golden expected outputs

`<name>.json` is the output of

```
sfr seal <log> --rules <rules> --baseline testdata/baselines/<name>.params --dry-run --json
```

where `<rules>` is `testdata/rules/<name>.toml` when that file exists (the default rules followed by
the sections that log needs, such as `[sealed_topics]`; `seal_dry_run.rs` checks that each one
starts with the default rules), else `examples/rules.default.toml`,

for every log in `testdata/` (`pyulog_sample` is `testdata/pyulog/sample.ulg`; `v1.17.0_mc_flight_1` is
`testdata/sitl/v1.17.0/mc_flight_1.ulg`, `synthetic_r4_quadchute_on_disarm` is
`testdata/synthetic/r4_quadchute_on_disarm.ulg`, and so on). `crates/sfr/tests/seal_dry_run.rs` requires the
output to match byte for byte, with the exit code listed there.

## How the files were reviewed

`oracle/<name>.oracle.json` comes from `scripts/testdata/oracle.py`, an independent implementation of
SPEC B1.5, B1.6 and B1.7 written on pyulog, with its own ULog record reader for the sealed topic
digests of `docs/RECORD_FORMAT.md`. It reads the same rules file `<rules>` as the seal above. It
shares no code with `sfr` and was written without reading `crates/`. Its scope is logs pyulog
reads to the end: pyulog drops the data after a format record that redefines a topic in the data
section, which `sfr` reads, and the oracle says so on stderr; no golden log has one.
`scripts/testdata/compare_oracle.py` compares, for each log:

- the configuration (every parameter and its typed value) and `config.watched_parameters` (the
  `[watched_parameters]` names, sorted, compared as a list);
- the firmware version and git hash, `is_vtol`, and `vtol_type` (null, or its `value` and `name`,
  compared exactly);
- every event: kind, boot time, source topic, instance and index, and the order, with these kind
  fields: `initial` and `reason` (ARM), `reason` (DISARM), `old` and `new` (NAV_STATE_CHANGE),
  `flag` (FAILSAFE_*), `command`, `category`, `source_system`, `source_component` and `result`
  (COMMAND), `direction` (VTOL_*), `vtol_fixed_wing_system_failure` (QUADCHUTE), `name`, `old` and
  `new` (PARAM_CHANGED_IN_FLIGHT), `level` and `text` (LOG_MESSAGE), `duration_ms` (LOG_DROPOUT);
- the status of R1, R4, R5, R6 and R7, and the topics and fields R1 reports missing (the rules
  file's required topics, every sealed topic, and with `[authorized_sources]` `vehicle_command`
  and the three fields R7 reads). The oracle's R4 follows SPEC B1.6: the window
  runs from the ARM sample through the sample that disarms, and the quadchute check reads the VTOL
  state only on a VTOL vehicle. Its R4 was re-derived from that wording at the Chunk 3 gate by a
  pass that did not read `crates/`;
- `sealed_topics`: the same entries in the same order (topic, then `multi_id`), and in each entry
  `topic`, `multi_id`, `format_sha256`, `message_count`, `first_timestamp_us`, `last_timestamp_us`
  and `data_sha256`, plus any field present on one side only. The oracle computes them from the
  raw file bytes with its own record reader, not pyulog, and finds each topic's `timestamp` offset
  by parsing the 'F' formats (nested types and arrays included). It reproduces the worked example
  in `docs/RECORD_FORMAT.md`, and its message counts and first and last timestamps agree with
  pyulog on every subscribed instance of every golden log.

It does not compare the version-dependent names (`old_name`, `new_name`, `reason_name`), `utc_us`,
FAILSAFE_SET `initial`, the log digests and size, R2, R3, or result wording. An independent
pyulog check during the Chunk 2 verification compared those fields on the 8 files then in `testdata/`
(`pyulog_sample`, `v1.14.4_mc_flight`, and the `v1.17.0` flights `mc_flight_1`, `mc_flight_2`,
`vtol_transition`, `vtol_transition_abort`, `failsafe_gps_loss` and `failsafe_battery_empty`) and
found no difference; it is not part of CI.

The result wording left out includes the R6 detail line that states the `vtol_type` and the R7
detail lines: the oracle lists the sequence numbers of unauthorized events in `r7_unauthorized`,
but only R7's status is compared. What the golden files exercise: `vtol_type` is `standard` (2) on
the three `v1.17.0_vtol_*` logs, `tailsitter` (0) on `v1.17.0_gz_quadtailsitter_transition`, value
null and name `unknown` on `synthetic_r4_quadchute_on_disarm` (a VTOL log with no `VT_TYPE`), and
null on the others; COMMAND events of both categories occur; R7 is FAIL on
`v1.17.0_payload_two_sources`, whose rules file lists two of its four command sources (the ground
station 255/190 and the vehicle 6/1), so R7 names the second source 42/191 and the arbitrary
source of PX4's boot-time DO_GRIPPER (`docs/DIAGNOSTIC.md` item 12.3), and N/A on every other
golden file (R7's PASS path is covered by `seal_dry_run.rs`, not by a golden file);
sealed topics are `vehicle_visual_odometry` on `v1.17.0_gz_x500_vision_hover` (one instance) and
`custom_detection` on `synthetic_custom_detection` (three instances, one with no data record).

A file counts as reviewed only while that comparison reports 0 differences. CI runs it on every
push (job `golden-oracle`).

## Regenerating

```
scripts/testdata/regenerate.sh baselines   # testdata/baselines/*.params from the logs (pyulog)
scripts/testdata/regenerate.sh oracle      # oracle/*.oracle.json (pyulog, numpy)
scripts/testdata/regenerate.sh expected    # *.json (a built sfr)
scripts/testdata/regenerate.sh compare     # must report 0 differences
```

The baselines are each log's own initial parameters, written by `scripts/testdata/make_baseline.py`
from pyulog, so R2 and R3 pass on every log except `pyulog_sample`, which has no `ver_sw_release`
and therefore fails R2.
