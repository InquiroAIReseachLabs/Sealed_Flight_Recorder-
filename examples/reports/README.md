# examples/reports/

Four sealed records and the reports `sfr seal` wrote beside them (SPEC B1.8), from the evaluation release. Each was sealed from a golden PX4 v1.17.0 SITL log in `testdata/sitl/v1.17.0/`, with that log's golden baseline in `testdata/baselines/`.

| Record and report | Rules | What the report shows |
|---|---|---|
| `vtol_transition.sfr`, `.sfr.md` | `examples/rules.default.toml` | standard VTOL, every rule PASS or N/A; transition tuning; a parameter changed in flight |
| `failsafe_gps_loss.sfr`, `.sfr.md` | `examples/rules.default.toml` | multicopter, R4 FAIL: failsafe raised in flight after the GPS stopped |
| `gz_quadtailsitter_transition.sfr`, `.sfr.md` | `examples/rules.default.toml` | quad tailsitter (VT_TYPE 0), both transitions; transition tuning |
| `gz_x500_vision_hover.sfr`, `.sfr.md` | `gz_x500_vision_hover.rules.toml` | multicopter with external vision odometry; the sealed topic `vehicle_visual_odometry`; R7 FAIL; a parameter changed in flight |

`gz_x500_vision_hover.rules.toml` is the log's golden rules file (`testdata/rules/v1.17.0_gz_x500_vision_hover.toml`, which seals `vehicle_visual_odometry`) plus `[authorized_sources]` with the autopilot itself only (system 1, component 1). R7 then fails on one command: the DO_GRIPPER (211) that PX4's `payload_deliverer` publishes at start-up with source ids it never sets. No command the test harness sent fails R7.

`scripts/make_example_reports.sh` made them: `--seal-time 2026-10-18T15:00:00Z` and a new evaluation key. Only its public half, `sfr.pub`, is here; the private half was shredded, so no one can seal another record with it. Each report starts with EVALUATION KEY because the key is an evaluation key.

## Events the test harness injected

The logs come from scripted SITL flights (each log's `.provenance.md` holds the script and, for the two Gazebo flights, the table of commands and their effects). The harness acted only through PX4's own shell commands (`commander`, `failure`, `param`, `sensor_gps_sim`), so every command it sent is an internal command from system 1, component 1, except `failure`, which publishes from 0/0. These are the events those commands put in the records (`examples/reports/vtol_transition.sfr` and the other three), by event sequence number:

| Record | Harness command | Events |
|---|---|---|
| `vtol_transition` | `commander arm` | seq 2 (COMMAND 400) |
| | `commander takeoff` | seq 5 and 6 (COMMAND 22, then 400) |
| | `commander transition`, twice | seq 9 and 12 (COMMAND 3000) |
| | `commander land` | seq 15 (COMMAND 21) |
| `failsafe_gps_loss` | `commander arm` | seq 2 (COMMAND 400) |
| | `commander takeoff` | seq 4 and 5 (COMMAND 22, then 400) |
| | `param set SYS_FAILURE_EN 1` | none: the value was already 1 |
| | `failure gps off` | seq 9 (COMMAND 420 from 0/0) and the two LOG_MESSAGE events it printed, seq 8 and 10; under SIH nothing handles it |
| | `sensor_gps_sim stop` (the simulated GPS driver) | none of its own; the GPS loss it caused is what PX4 reports from seq 11 to 19 |
| `gz_quadtailsitter_transition` | `param set MIS_TAKEOFF_ALT 20` | none: the value was already 20 (the log's `.provenance.md`) |
| | `commander arm` | seq 2 (COMMAND 400) |
| | `commander takeoff` | seq 4 and 5 (COMMAND 22, then 400) |
| | `commander transition`, twice | seq 8 and 13 (COMMAND 3000) |
| | `commander land` | seq 16 (COMMAND 21) |
| `gz_x500_vision_hover` | `commander arm` | seq 2 (COMMAND 400) |
| | `commander takeoff` | seq 5 and 6 (COMMAND 22, then 400) |
| | `commander land` | seq 9 (COMMAND 21) |

Every other event in the records (`scripts/make_example_reports.sh` wrote them) is PX4's own record of the flight: the ARM, DISARM, NAV_STATE_CHANGE, VTOL_TRANSITION, FAILSAFE_SET and FAILSAFE_CLEAR events that follow those commands; the DO_GRIPPER (211) at start-up; the commands 1001, 1000 and 1001 that navigator publishes on entering LAND; the CAL_BARO0_OFF change in flight, written by the firmware's barometer calibration; and the log messages. The x500 harness also ran a stand-in ground station heartbeat from system 255 for the whole flight, which sent nothing else and put no event in the record.

## Verify

Only the `.sfr` records are signed; each `.sfr.md` report is a readable view of its record, so check the record, not the report. The public key `sfr.pub` sits in the same repository as the records: verifying with it shows that the records have not changed since sealing, not who sealed them. For records you receive, get the signer's public key from the signer through a channel you trust.

Each report gives the `sfr verify` command for a directory that holds the record, the log and `sfr.pub`. From the repository root, with `sfr` built as in the [README](../../README.md#quickstart) and the files where they are:

```sh doc-test
for name in vtol_transition failsafe_gps_loss gz_quadtailsitter_transition gz_x500_vision_hover; do
  target/release/sfr verify "examples/reports/$name.sfr" --pubkey examples/reports/sfr.pub \
    --ulog "testdata/sitl/v1.17.0/$name.ulg" | grep -E '^(VERIFIED|status)'
done
```

```text doc-output
VERIFIED (record and log)
status    PASS
VERIFIED (record and log)
status    FAIL
VERIFIED (record and log)
status    PASS
VERIFIED (record and log)
status    FAIL
```

`crates/sfr/tests/seal_verify.rs` checks that each report is exactly what its record renders to, that every fact in it comes from the record, and that each record verifies against its log. When a record or report format change makes that test fail, run `scripts/make_example_reports.sh` again and commit the new files.

To make them again after a format change. Not run in CI: it makes a new key, so it rewrites every record, report and `sfr.pub`:

```sh doc-syntax
scripts/make_example_reports.sh target/release/sfr
```
