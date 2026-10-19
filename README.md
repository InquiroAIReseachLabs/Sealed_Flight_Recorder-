# Sealed Flight Record

After a PX4 flight, produce a signed, self-verifying record of the configuration that flew, the readiness rule results, and the operator, failsafe, and transition events, so anyone can later prove none of it was changed.

v1.0 evaluation release, in development.

## The record and its report

`sfr seal` writes the signed record `<name>.sfr` and, beside it, the report `<name>.sfr.md`: Markdown that GitHub and GitLab render, generated only from the record, with the `sfr verify` command that checks it. `examples/reports/` holds the records and reports of four golden SITL flights (standard VTOL, GPS loss failsafe, quad tailsitter, and a multicopter with a sealed topic and an R7 failure), sealed with an evaluation key.

## Verify timing

SPEC B1.10 gates standalone verification in-process and reports the whole `sfr verify` command beside it without a gate. Both come from the same CI test and are labelled below.

<!-- BEGIN verify-timing: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
Measured by `crates/sfr/tests/verify_perf.rs` in a release build, CI run 39172030538 on commit `5e59040ddcb12bf4d3e7d4c49cb9e562189f2ad8`. The record holds 10,000 events (1704147 bytes).

| Measurement | What it times | Median | Min | Max | Runs | Gate (SPEC B1.10) |
|---|---|---|---|---|---|---|
| In-process verify | `sfr_core::verify` on the record bytes already in memory | 5.38 ms | 5.36 ms | 6.04 ms | 101 | gated: median under 10 ms |
| End-to-end `sfr verify` | the whole command: process start, reading the record and the public key, and verify | 7.35 ms | 7.29 ms | 7.96 ms | 101 | not gated, reported only |
<!-- END verify-timing -->
