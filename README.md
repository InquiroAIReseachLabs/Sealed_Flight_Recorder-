# Sealed Flight Record

After a PX4 flight, produce a signed, self-verifying record of the configuration that flew, the readiness rule results, and the operator, failsafe, and transition events, so anyone can later prove none of it was changed.

v1.0 evaluation release, in development.

## Verify timing

SPEC B1.10 gates standalone verification in-process and reports the whole `sfr verify` command beside it without a gate. Both come from the same CI test and are labelled below.

<!-- BEGIN verify-timing: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
Measured by `crates/sfr/tests/verify_perf.rs` in a release build, CI run 39161777984 on commit `d6987cfbe66e048220ba35ff8326b9a450e72671`. The record holds 10,000 events (1701833 bytes).

| Measurement | What it times | Median | Min | Max | Runs | Gate (SPEC B1.10) |
|---|---|---|---|---|---|---|
| In-process verify | `sfr_core::verify` on the record bytes already in memory | 6.87 ms | 6.83 ms | 7.55 ms | 101 | gated: median under 10 ms |
| End-to-end `sfr verify` | the whole command: process start, the FIPS module's power-on self-tests, reading the record and the public key, and verify | 11.71 ms | 11.49 ms | 12.43 ms | 101 | not gated, reported only |
<!-- END verify-timing -->
