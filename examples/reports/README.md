# examples/reports/

Two sealed records and the reports `sfr seal` wrote beside them (SPEC B1.8), from the v1.0 evaluation release:

| Record | Report | Log |
|---|---|---|
| `vtol_transition.sfr` | `vtol_transition.sfr.md` | `testdata/sitl/v1.17.0/vtol_transition.ulg` |
| `failsafe_gps_loss.sfr` | `failsafe_gps_loss.sfr.md` | `testdata/sitl/v1.17.0/failsafe_gps_loss.ulg` |

`scripts/make_example_reports.sh` made them: the default rules (`examples/rules.default.toml`), the golden baseline of each flight (`testdata/baselines/`), `--seal-time 2026-10-18T15:00:00Z`, and a new evaluation key. Only its public half, `sfr.pub`, is here; the private half was shredded, so no one can seal another record with it. Each report starts with EVALUATION KEY because the key is an evaluation key.

Each report gives the `sfr verify` command for a directory that holds the record, the log and `sfr.pub`. From the repository root, with the files where they are:

```
sfr verify examples/reports/vtol_transition.sfr --pubkey examples/reports/sfr.pub --ulog testdata/sitl/v1.17.0/vtol_transition.ulg
sfr verify examples/reports/failsafe_gps_loss.sfr --pubkey examples/reports/sfr.pub --ulog testdata/sitl/v1.17.0/failsafe_gps_loss.ulg
```

`crates/sfr/tests/seal_verify.rs` checks that each report is exactly what its record renders to, that every fact in it comes from the record, and that each record verifies against its log. When a record or report format change makes that test fail, run `scripts/make_example_reports.sh` again and commit the new files.
