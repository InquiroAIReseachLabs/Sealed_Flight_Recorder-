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
SPEC B1.5 and B1.6 written on pyulog. It shares no code with `sfr` and was written without reading
`crates/`. `scripts/testdata/compare_oracle.py` compares, for each log:

- the configuration (every parameter and its typed value);
- the firmware version and git hash, and `is_vtol`;
- every event: kind, boot time, source topic, instance and index, and the order, with these kind
  fields: `initial` and `reason` (ARM), `reason` (DISARM), `old` and `new` (NAV_STATE_CHANGE),
  `flag` (FAILSAFE_*), `command`, `source_system`, `source_component` and `result` (COMMAND),
  `direction` (VTOL_*), `vtol_fixed_wing_system_failure` (QUADCHUTE), `name`, `old` and `new` (PARAM_CHANGED_IN_FLIGHT), `level` and `text`
  (LOG_MESSAGE), `duration_ms` (LOG_DROPOUT);
- the status of R1, R4, R5 and R6, and the topics and fields R1 reports missing. The oracle's R4
  follows SPEC B1.6: the window runs from the ARM sample through the sample that disarms, and the
  quadchute check reads the VTOL state only on a VTOL vehicle. Its R4 was re-derived from that
  wording at the Chunk 3 gate by a pass that did not read `crates/`.

It does not compare the version-dependent names (`old_name`, `new_name`, `reason_name`), `utc_us`,
FAILSAFE_SET `initial`, the log digests and size, R2, R3, or result wording. An independent
pyulog check during the Chunk 2 verification compared those fields on the 8 files then in `testdata/`
(all but `v1.17.0_vtol_quadchute` and `synthetic_r4_quadchute_on_disarm`) and found no difference; it is not part of CI.

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
