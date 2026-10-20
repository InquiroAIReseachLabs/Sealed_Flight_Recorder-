# Measurements

Numbers from one CI run, copied by `scripts/regen_readme_numbers.sh` from the run's job logs into `docs/receipts/ci-run.txt`. CI fails when this page and the receipt differ. How the benchmark is run is in [BENCHMARK.md](BENCHMARK.md).

## Verify timing

The first row is gated: `crates/sfr/tests/verify_perf.rs` requires a median under 10 ms. The second times the whole command and is only reported.

<!-- BEGIN verify-timing: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
Measured by `crates/sfr/tests/verify_perf.rs` in a release build, CI run 39190820606 on commit `0aa307f05d368cbc4984557e4492485a35d0732a`. The record holds 10,000 events (1704147 bytes).

| Measurement | What it times | Median | Min | Max | Runs | Gate (SPEC B1.10) |
|---|---|---|---|---|---|---|
| In-process verify | `sfr_core::verify` on the record bytes already in memory | 6.60 ms | 6.53 ms | 7.27 ms | 101 | gated: median under 10 ms |
| End-to-end `sfr verify` | the whole command: process start, reading the record and the public key, and verify | 9.70 ms | 9.53 ms | 10.27 ms | 101 | not gated, reported only |
<!-- END verify-timing -->

## Tests

<!-- BEGIN tests: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
CI run 39190820606 on commit `0aa307f05d368cbc4984557e4492485a35d0732a`:

| Check | Result |
|---|---|
| `cargo test --workspace --locked` | 136 passed, 0 failed, 1 ignored |
| Every golden log sealed on x86_64 and on armv7 (QEMU) | byte-identical records and reports: 14 of 14 golden logs |
| Every golden log sealed on x86_64 and on aarch64 (QEMU) | byte-identical records and reports: 14 of 14 golden logs |
| `scripts/run_demo.sh` in `docker run --network=none`, image loaded from its saved tarball | passed, wall time 1.30 s |
<!-- END tests -->

## Benchmark

Seal time, standalone verify time and seal peak memory for every golden log and for large logs built for size only. Only the x86_64 CI machine is shown here; aarch64 on an Arm cloud VM is in [BENCHMARK.md](BENCHMARK.md).

<!-- BEGIN benchmark: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
`scripts/benchmark.sh` run from the x86_64 release tarball and the benchmark kit, CI run 39190820606 on commit `0aa307f05d368cbc4984557e4492485a35d0732a` (docs/BENCHMARK.md).

- sfr 0.1.0 (build 0aa307f05d368cbc4984557e4492485a35d0732a); binary x86_64, machine x86_64; 5 run(s) per log
- hardware: x86_64; CPU AMD EPYC 7763 64-Core Processor; 4 cores; memory 15.6 GiB; kernel 6.17.0-1022-azure; OS Debian GNU/Linux 12 (bookworm)
- note: the large_* logs are built for size only from the golden VTOL flight (testdata/sitl/v1.17.0/vtol_transition.ulg) and the whole-record segments of it in scripts/benchmark/vtol_transition.segments: large_10mb is the flight cut at a record boundary; large_50mb and large_100mb are one copy of the flight followed by its segments repeated (concatenated, timestamps restart). They are not real flights.

| log | bytes | seal median (s) | verify median (ms) | seal peak RSS (KB) |
|---|---|---|---|---|
| pyulog_sample | 4053364 | 0.025 | 1.48 | 1920 |
| v1.14.4_mc_flight | 30583745 | 0.140 | 1.65 | 3112 |
| v1.17.0_failsafe_battery_empty | 9208891 | 0.050 | 1.58 | 2556 |
| v1.17.0_failsafe_gps_loss | 10217078 | 0.054 | 1.60 | 2556 |
| v1.17.0_gz_quadtailsitter_transition | 34095400 | 0.163 | 1.74 | 3196 |
| v1.17.0_gz_x500_vision_hover | 15797162 | 0.067 | 1.65 | 2744 |
| v1.17.0_mc_flight_1 | 8536869 | 0.045 | 1.61 | 2472 |
| v1.17.0_mc_flight_2 | 9727973 | 0.050 | 1.59 | 2560 |
| v1.17.0_payload_two_sources | 15572427 | 0.075 | 1.62 | 2612 |
| v1.17.0_vtol_quadchute | 20826338 | 0.119 | 1.73 | 2820 |
| v1.17.0_vtol_transition | 24295307 | 0.134 | 1.71 | 2852 |
| v1.17.0_vtol_transition_abort | 15324267 | 0.096 | 1.68 | 2700 |
| synthetic_custom_detection | 1338 | 0.004 | 1.37 | 1460 |
| synthetic_r4_quadchute_on_disarm | 1020 | 0.004 | 1.37 | 1456 |
| large_10mb | 10229940 | 0.064 | 1.66 | 2600 |
| large_10mb_sealed8 | 10229940 | 0.070 | 1.77 | 2596 |
| large_50mb | 50275889 | 0.262 | 1.78 | 3572 |
| large_50mb_sealed8 | 50275889 | 0.292 | 1.84 | 3488 |
| large_100mb | 100649134 | 0.508 | 1.83 | 4636 |
| large_100mb_sealed8 | 100649134 | 0.629 | 1.91 | 4624 |

- gate: x86_64 large_100mb seal median 0.508 s, under 2 s: PASS
- memory: large_100mb seal peak RSS 4636 KB, not above 256 MB (262144 KB)
- gate: x86_64 large_100mb_sealed8 seal median 0.629 s, under 2 s: PASS
- memory: large_100mb_sealed8 seal peak RSS 4624 KB, not above 256 MB (262144 KB)
<!-- END benchmark -->
