# Sealed Flight Record

After a PX4 flight, produce a signed, self-verifying record of the configuration that flew, the readiness rule results, and the operator, failsafe, and transition events, so anyone can later prove none of it was changed.

v1.0 evaluation release, in development.

## Try it offline

The demo image (`sfr-<version>-demo-image.tar.gz`, x86_64) holds the static `sfr`, two golden SITL logs with their notices, the default rules, and `scripts/run_demo.sh`. With no network it generates an evaluation key; seals the golden VTOL flight and prints the results table and event count; verifies the record alone and against the log; changes one byte of a COMMAND event in a copy of the record and shows verify naming that event; changes VTOL transition parameter `VT_B_TRANS_DUR` in a copy of the quad tailsitter log and shows verify naming the parameter with its sealed and found values; and prints the command that seals your own logs.

```
docker load -i sfr-<version>-demo-image.tar.gz
docker run --rm --network=none sfr-demo:<version>
```

## Downloads

Each build holds, for the version in `Cargo.toml`:

| File | Contents |
|---|---|
| `sfr-<version>-<target>.tar.gz` | the static `sfr` for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, or `armv7-unknown-linux-musleabihf`, this README, `examples/`, and `BUILDINFO` |
| `sfr-<version>-<target>.cdx.json` | the CycloneDX SBOM of that `sfr`: its resolved dependency graph for the target from `Cargo.lock` (a superset of the crates it links; build-time crates marked `excluded`), with version, license, and SHA-256 |
| `sfr-<version>-benchmark.tar.gz` | `scripts/benchmark.sh` and the golden logs it reads, for any architecture ([docs/BENCHMARK.md](docs/BENCHMARK.md)) |
| `sfr-<version>-demo-image.tar.gz` | the demo image above |
| `SHA256SUMS` | the SHA-256 of every file above |
| `SHA256SUMS.sig` | the Ed25519 signature over `SHA256SUMS`, made offline with the release key (a release only) |

CI builds every file but the signature on each commit and keeps them as the `sfr-release-unsigned` artifact of the run. It publishes nothing; [docs/RELEASE.md](docs/RELEASE.md) says how a release is signed and made.

Check a download with OpenSSL 3 and coreutils alone, in the directory that holds the files and `sfr-release.pub`, the release public key below (`release/sfr-release.pub` in this repository at the release's commit):

```
openssl pkeyutl -verify -pubin -inkey sfr-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c --ignore-missing SHA256SUMS
```

The first prints `Signature Verified Successfully` only for a good signature by the release key.

<!-- BEGIN release-key: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
Release public key: not generated yet. The founder generates the release key on an offline machine with `scripts/release_sign.sh keygen <offline path>`, which writes its public half to `release/sfr-release.pub`; `scripts/regen_readme_numbers.sh` then shows it here, and both are committed before the first release.
<!-- END release-key -->

## The record and its report

`sfr seal` writes the signed record `<name>.sfr` and, beside it, the report `<name>.sfr.md`: Markdown that GitHub and GitLab render, generated only from the record, with the `sfr verify` command that checks it. `examples/reports/` holds the records and reports of four golden SITL flights (standard VTOL, GPS loss failsafe, quad tailsitter, and a multicopter with a sealed topic and an R7 failure), sealed with an evaluation key.

## Verify timing

SPEC B1.10 gates standalone verification in-process and reports the whole `sfr verify` command beside it without a gate. Both come from the same CI test and are labelled below.

<!-- BEGIN verify-timing: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
Measured by `crates/sfr/tests/verify_perf.rs` in a release build, CI run 39190820606 on commit `0aa307f05d368cbc4984557e4492485a35d0732a`. The record holds 10,000 events (1704147 bytes).

| Measurement | What it times | Median | Min | Max | Runs | Gate (SPEC B1.10) |
|---|---|---|---|---|---|---|
| In-process verify | `sfr_core::verify` on the record bytes already in memory | 6.60 ms | 6.53 ms | 7.27 ms | 101 | gated: median under 10 ms |
| End-to-end `sfr verify` | the whole command: process start, reading the record and the public key, and verify | 9.70 ms | 9.53 ms | 10.27 ms | 101 | not gated, reported only |
<!-- END verify-timing -->

## Tests

The numbers below are copied from one CI run's job logs into `docs/receipts/ci-run.txt`; CI fails when this section and the receipt differ.

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

Seal time, standalone verify time and seal peak memory for every golden log and for the large logs built for size only ([docs/BENCHMARK.md](docs/BENCHMARK.md)). Only the x86_64 CI machine is shown here. The aarch64 gate is pending a run on real aarch64 hardware ([docs/RELEASE.md](docs/RELEASE.md) step 4); no armv7 timing is published.

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
