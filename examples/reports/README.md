# examples/reports/

Four sealed records and the reports `sfr seal` wrote beside them (SPEC B1.8). Each was sealed from a golden PX4 v1.17.0 SITL log in `testdata/sitl/v1.17.0/`, with that log's golden baseline in `testdata/baselines/`.

| Record and report | Rules | What the report shows |
|---|---|---|
| `vtol_transition.sfr`, `.sfr.md` | `examples/rules.default.toml` | standard VTOL, R4 WARN (SITL flags with no RC link or ground station), every other rule PASS or N/A; transition tuning; a parameter changed in flight |
| `failsafe_gps_loss.sfr`, `.sfr.md` | `examples/rules.default.toml` | multicopter, R4 FAIL: failsafe raised in flight after the GPS stopped |
| `gz_quadtailsitter_transition.sfr`, `.sfr.md` | `examples/rules.default.toml` | quad tailsitter (VT_TYPE 0), both transitions; transition tuning |
| `gz_x500_vision_hover.sfr`, `.sfr.md` | `gz_x500_vision_hover.rules.toml` | multicopter with external vision odometry; the sealed topic `vehicle_visual_odometry`; R7 FAIL; a parameter changed in flight |

`gz_x500_vision_hover.rules.toml` is the log's golden rules file (`testdata/rules/v1.17.0_gz_x500_vision_hover.toml`, which seals `vehicle_visual_odometry`) plus `[authorized_sources]` with the autopilot only (system 1, component 1). R7 then fails on one command: the DO_GRIPPER (211) that PX4's `payload_deliverer` publishes at start-up with source ids it never sets. No command the test harness sent fails R7.

`scripts/make_example_reports.sh` made them with `--seal-time 2026-10-18T15:00:00Z` and a new evaluation key, so each report starts with EVALUATION KEY. Only the public half, `sfr.pub`, is here; the private half was shredded.

## Where the events come from

The logs come from scripted SITL flights; each log's `.provenance.md` holds the script and the commands it sent. The harness used only PX4's shell commands (`commander`, `failure`, `param`, `sensor_gps_sim`), so every command in the records comes from system 1, component 1, except the `failure gps off` command in `failsafe_gps_loss`, which publishes from 0/0. Every other event (`scripts/make_example_reports.sh` wrote them) is PX4's own record of the flight: ARM, DISARM, NAV_STATE_CHANGE, VTOL_TRANSITION, FAILSAFE_SET and FAILSAFE_CLEAR; the DO_GRIPPER (211) at start-up; the commands 1001, 1000 and 1001 that navigator publishes on entering LAND; the CAL_BARO0_OFF change in flight from the barometer calibration; and log messages.

## Verify

Only the `.sfr` records are signed. Each `.sfr.md` report is a readable view of its record, and `sfr verify` requires it beside the record and checks it against the one the record renders. `sfr.pub` sits in the same repository as the records, so verifying with it shows the records have not changed since sealing, not who sealed them. For records you receive, get the signer's public key from the signer through a channel you trust.

From the repository root, with `sfr` built as the [README](../../README.md) describes:

```sh doc-test
for name in vtol_transition failsafe_gps_loss gz_quadtailsitter_transition gz_x500_vision_hover; do
  target/release/sfr verify "examples/reports/$name.sfr" --pubkey examples/reports/sfr.pub --allow-evaluation-key \
    --ulog "testdata/sitl/v1.17.0/$name.ulg" | grep -E '^(Integrity|Rule checks)'
done
```

```text doc-output
Integrity: VERIFIED (record and log)
Rule checks: WARN (R4)
Integrity: VERIFIED (record and log)
Rule checks: FAIL (R4)
Integrity: VERIFIED (record and log)
Rule checks: WARN (R4)
Integrity: VERIFIED (record and log)
Rule checks: FAIL (R7)
```

`crates/sfr/tests/seal_verify.rs` checks that each report is exactly what its record renders to and that each record verifies against its log. If a format change makes it fail, run `scripts/make_example_reports.sh` again and commit the new files. Not run in CI, because it makes a new key and rewrites every record, report and `sfr.pub`:

```sh doc-syntax
scripts/make_example_reports.sh target/release/sfr
```
