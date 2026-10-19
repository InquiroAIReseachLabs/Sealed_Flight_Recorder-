# Sealed Flight Record

After a PX4 flight, `sfr` produces a signed, self-verifying record of the configuration that flew, the readiness rule results, and the operator, failsafe, and transition events, so anyone can later prove none of it was changed.

This is an evaluation release, provided without warranty, and in development: records sealed with it are for evaluation, and it signs only with evaluation keys. A browser version of the same engine is available to invited evaluators and is hosted separately. Third-party material is listed in [NOTICE.md](NOTICE.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## What a record proves

`sfr seal` runs the rules R1 to R7 on a PX4 ULog file and writes a signed record (`.sfr`) and a plain report (`.sfr.md`). `sfr verify` checks the record, and with `--ulog` checks it against the log. A record that verifies proves that this record, signed by this key, matches these log bytes and these rule results.

It does not prove that the log was honest, that the vehicle did what the log says, that the key holder is who they claim, or when the log was made: the seal time is the sealer's own statement. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) gives the details and the attacks that are and are not detected.

## Quickstart

**What is published today:** nothing yet. No container image and no binary has been published. CI builds static `sfr` binaries for Linux (`x86_64`, `aarch64`, `armv7`) and an offline demo image on every commit, but keeps them only as CI artifacts of that run, which are not a release; the first release will publish them with a signature ([docs/RELEASE.md](docs/RELEASE.md)). Until then, build from source as below.

You need git, a C compiler and linker (`cc`; on Debian or Ubuntu, `build-essential`), and [rustup](https://rustup.rs). `rust-toolchain.toml` pins the Rust version, and `cargo` installs it on the first build. The first build downloads the dependencies from crates.io; after that, `sfr` needs no network. CI builds and tests on Linux `x86_64`; other systems have not been tested.

1. Get the source. Not run in CI, which tests the checkout it already has:

   ```sh doc-syntax
   git clone https://github.com/InquiroAIReseachLabs/Sealed_Flight_Recorder-.git
   cd Sealed_Flight_Recorder-
   ```

2. Build. The binary is `target/release/sfr`:

   ```sh doc-test
   cargo build --release --locked
   ```

3. Verify a record sealed earlier, against its log. `examples/reports/` holds four records sealed from golden SITL logs, with the public key `examples/reports/sfr.pub`:

   ```sh doc-test
   target/release/sfr verify examples/reports/vtol_transition.sfr --pubkey examples/reports/sfr.pub \
     --ulog testdata/sitl/v1.17.0/vtol_transition.ulg
   ```

   ```text doc-output
   EVALUATION KEY: not for operational use
   VERIFIED (record and log)
   record    examples/reports/vtol_transition.sfr
   custody   file-evaluation
   key       sha256:e9189283def3921d2c7489ceed37e4680b4768b78faa311fdf49cf6325b5e4f4
   crypto    blake3 1.8.7, ed25519-dalek 3.0.0, sha2 0.11.1 (crate versions)
   sealed    2026-10-18T15:00:00Z
   status    PASS
   events    22
   ```

4. Change one field of a copy of that record. Verify names what no longer matches and exits 1:

   ```sh doc-test
   mkdir -p try
   sed 's/"command":211,/"command":311,/' examples/reports/vtol_transition.sfr > try/changed.sfr
   rc=0
   target/release/sfr verify try/changed.sfr --pubkey examples/reports/sfr.pub || rc=$?
   echo "exit $rc"
   ```

   ```text doc-output
   EVALUATION KEY: not for operational use
   FAILED: Merkle root mismatch: a leaf changed after sealing (recorded 31577a8e29ea34a41f09692efeb856903162f605e62702ba1c2fb8b6dda304c2, computed 95f6c952bbbb0539d677755b628dffa26ccae7250cf03869a81bd5b549146e04)
   exit 1
   ```

5. Make an evaluation key and seal a log. `seal` prints the rule results and writes the record and its report into `try/out/`:

   ```sh doc-test
   mkdir -p try
   target/release/sfr keygen --evaluation-only --out try/keys > try/keygen.txt
   head -1 try/keygen.txt
   target/release/sfr seal testdata/sitl/v1.17.0/vtol_transition.ulg --rules examples/rules.default.toml \
     --baseline testdata/baselines/v1.17.0_vtol_transition.params \
     --key try/keys/sfr.key --evaluation-only --out try/out > try/seal.txt
   grep -E '^(R[0-9] |status|record|report)' try/seal.txt
   ```

   ```text doc-output
   EVALUATION KEY: not for operational use
   R1    PASS    required topics present       all present
   R2    PASS    firmware matches baseline     1.17.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4
   R3    PASS    parameters match baseline     no differences
   R4    PASS    no failsafe in flight         never true in flight
   R5    PASS    arm and disarm consistent     1 ARM, 1 DISARM
   R6    PASS    VTOL transitions completed    2 START, 2 END, 0 problem(s)
   R7    N/A     authorized command sources    no [authorized_sources] in the rules file
   status    PASS
   record    try/out/vtol_transition.sfr
   report    try/out/vtol_transition.sfr.md
   ```

   The key is new each time, so its fingerprint and the record's Merkle root differ from run to run; `try/keygen.txt` and `try/seal.txt` hold the whole output. Open `try/out/vtol_transition.sfr.md` to read the report.

6. Verify the record you sealed, against its log:

   ```sh doc-test
   target/release/sfr verify try/out/vtol_transition.sfr --pubkey try/keys/sfr.pub \
     --ulog testdata/sitl/v1.17.0/vtol_transition.ulg | grep -E '^(EVALUATION|VERIFIED|status)'
   ```

   ```text doc-output
   EVALUATION KEY: not for operational use
   VERIFIED (record and log)
   status    PASS
   ```

To seal your own log you need a rules file (start from `examples/rules.default.toml`) and a baseline: the parameter file QGroundControl exports, plus one line `# Firmware: <version>` ([docs/RULES.md](docs/RULES.md)). Not run in CI: it needs your files.

```sh doc-syntax
target/release/sfr seal "$LOG" --rules my_rules.toml --baseline my_vehicle.params --dry-run
target/release/sfr seal "$LOG" --rules my_rules.toml --baseline my_vehicle.params \
  --key try/keys/sfr.key --evaluation-only --out records
```

## Exit codes

From `crates/sfr-core/src/lib.rs` (`exit_code`):

| Exit | `sfr seal` | `sfr verify` |
|---|---|---|
| 0 | every rule PASS or N/A; record written | VERIFIED |
| 1 | a rule FAIL; the record is still written | verification failed: the record, or the log with `--ulog`, does not match, or is over an input limit |
| 2 | a required topic or field is missing (R1 FAIL); the record is still written | not used |
| 3 | the log, rules file or baseline is malformed, truncated, or over an input limit; nothing written | not used |
| 4 | a usage, key or file error; nothing written | a usage, key or file error |

`sfr keygen` and `sfr --version` exit 0 or 4.

## Documentation

| Page | What it covers |
|---|---|
| [docs/RULES.md](docs/RULES.md) | each rule, the log data it reads, the rules file and the baseline |
| [docs/RECORD_FORMAT.md](docs/RECORD_FORMAT.md) | the record, exactly, and how to verify one with `openssl` and `b3sum` |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | what a seal proves and what it does not |
| [docs/INTEGRATION_NOTES.md](docs/INTEGRATION_NOTES.md) | the topics `sfr` reads, sealing after disarm, CI use, key handling |
| [docs/LIMITS.md](docs/LIMITS.md) | the input limits |
| [docs/RELEASE.md](docs/RELEASE.md), [docs/BENCHMARK.md](docs/BENCHMARK.md) | how a release is made and benchmarked |
| [examples/reports/README.md](examples/reports/README.md) | the example records and reports |

CI runs every command on these pages that can run there and compares its output (`scripts/check_docs.py`).

## The record and its report

`sfr seal` writes the signed record `<name>.sfr` and, beside it, the report `<name>.sfr.md`: Markdown that GitHub and GitLab render, generated only from the record, with the `sfr verify` command that checks it. `examples/reports/` holds the records and reports of four golden SITL flights (standard VTOL, GPS loss failsafe, quad tailsitter, and a multicopter with a sealed topic and an R7 failure), sealed with an evaluation key.

## Release files

Not published yet. Each release will hold, for the version in `Cargo.toml`:

| File | Contents |
|---|---|
| `sfr-<version>-<target>.tar.gz` | the static `sfr` for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, or `armv7-unknown-linux-musleabihf`, this README, `examples/`, and `BUILDINFO` |
| `sfr-<version>-<target>.cdx.json` | the CycloneDX SBOM of that `sfr`: its resolved dependency graph for the target from `Cargo.lock` (a superset of the crates it links; build-time crates marked `excluded`), with version, license, and SHA-256 |
| `sfr-<version>-benchmark.tar.gz` | `scripts/benchmark.sh` and the golden logs it reads, for any architecture ([docs/BENCHMARK.md](docs/BENCHMARK.md)) |
| `sfr-<version>-demo-image.tar.gz` | an offline demo image (x86_64): the static `sfr`, two golden SITL logs, the default rules, and `scripts/run_demo.sh`, which seals, verifies, and shows verify naming a changed event and a changed parameter |
| `SHA256SUMS` | the SHA-256 of every file above |
| `SHA256SUMS.sig` | the Ed25519 signature over `SHA256SUMS`, made offline with the release key |

CI builds every file but the signature on each commit and keeps them as the `sfr-release-unsigned` artifact of the run; [docs/RELEASE.md](docs/RELEASE.md) says how a release is signed and made. To check release files with OpenSSL 3 and coreutils alone, in the directory that holds them and `sfr-release.pub` (the release public key below), run these. Not run in CI: no release has been signed yet.

```sh doc-syntax
openssl pkeyutl -verify -pubin -inkey sfr-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c --ignore-missing SHA256SUMS
```

The first prints `Signature Verified Successfully` only for a good signature by the release key.

<!-- BEGIN release-key: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
Release public key: not generated yet. The founder generates the release key on an offline machine with `scripts/release_sign.sh keygen <offline path>`, which writes its public half to `release/sfr-release.pub`; `scripts/regen_readme_numbers.sh` then shows it here, and both are committed before the first release.
<!-- END release-key -->

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

## Rights

Copyright (c) 2026 Inquiro AI Research Labs. All rights reserved. This source is published for review and evaluation.
