# fuzz/

cargo-fuzz targets (SPEC B1.2, B1.10 "Fuzzing"). This is a separate package with its own `[workspace]` and a committed `Cargo.lock`; the root `Cargo.toml` excludes `fuzz/`. cargo-fuzz needs a nightly toolchain, and the root `rust-toolchain.toml` pins stable, so every command below passes `+nightly-2026-10-18`, the nightly CI pins (`rustup toolchain install nightly-2026-10-18 --profile minimal`). Run them from the repository root.

Gate: 60 seconds per CI run (`.github/workflows/ci.yml`) and 10 minutes nightly (`.github/workflows/fuzz-nightly.yml`) with zero panics, hangs, or out-of-memory.

Targets: `ulog_ingest` (the ULog reader and the whole dry-run path), `sfr_verify` (the `.sfr` reader), and `rules_parse` (the rules file parser and what reads a rules file).

## Target `ulog_ingest`

Arbitrary bytes go through the whole `seal --dry-run` path:

1. `Px4Ingestor::ingest_sealing`: the ULog reader, SHA-256 and BLAKE3 of every byte, field decoding, sealed topic digests, and the event timeline. SHA-256 comes from `RustCrypto`, the backend every build uses.
2. If the log is readable, `evaluate` with `examples/rules.extended.toml` plus the `[authorized_sources]` and `[sealed_topics]` sections it shows commented out (the core rules, R7, and every optional rule) and the baseline `# Firmware: 1.17.0`.
3. `record::dry_run_json`, then `json::canonical`.

The target also checks that the logged size and `Summary.bytes` equal the input length and that events are numbered from 0. A finding is any panic (cargo-fuzz builds check integer overflow, so an overflow is a panic), a failed check, a hang, or an out-of-memory.

## Target `sfr_verify`

Arbitrary bytes go to `sfr_core::verify::verify` without a log: the canonical-form scan, the schema checks, the Merkle tree over byte ranges, and Ed25519 verification (`RustCrypto`, the backend every build uses). Its seeds in `seeds/sfr_verify/` are records sealed from four of the seed logs below and from `testdata/synthetic/custom_detection.ulg`, by an evaluation key whose public half is `seeds/sfr_verify_key.pub`; the private half was discarded. They were last sealed when the comments of `examples/rules.extended.toml` last changed, with a new key, `--seal-time 2026-10-18T15:00:00Z` and these rules and baselines: `pyulog_sample_first_65516` with `examples/rules.default.toml` and `testdata/baselines/pyulog_sample.params`; the shrunk `failsafe_gps_loss` and `vtol_transition_abort` logs with `examples/rules.extended.toml` as it is now and the golden baseline of the same flight; the shrunk `gz_x500_vision_hover` log (one sealed topic) and `custom_detection.ulg` (three sealed instances, saved as `synthetic_custom_detection.sfr`) with their golden rules and baselines (`testdata/rules/`, `testdata/baselines/`). `crates/sfr/tests/seal_verify.rs` fails when a seed no longer verifies or is missing from the target's list, so a record format change cannot leave them stale unnoticed; re-seal all of them with a new key when that happens. Besides panics, hangs and out-of-memory, the target treats any input that verifies but is not one of the seeds as a finding. Run it with the same commands as below, with `sfr_verify` and `seeds/sfr_verify` in place of `ulog_ingest` and `seeds/ulog_ingest`.

## Target `rules_parse`

UTF-8 input goes to `sfr_core::rules::parse_rules`, which reads every section a rules file may hold, the Change Order 01 sections `[watched_parameters]`, `[sealed_topics]`, `[payload_commands]` and `[authorized_sources]` included. A file that parses is then used to ingest the shrunk payload flight seed (`seeds/ulog_ingest/sitl_v1.17.0_payload_two_sources_shrunk.ulg`, commands from several sources) with its sealed topics, evaluate it against the golden baseline of that flight, and build the dry-run JSON, so the fuzzed sections reach the code that uses them. The target checks that the sealed topic and watched parameter lists are sorted and unique, that the sealed topic limit holds, and that every sealed topic is required (R1). Its seeds in `seeds/rules_parse/` are copies of `examples/rules.default.toml`, `examples/rules.extended.toml`, the extended rules with every commented section enabled (as `ulog_ingest` uses them), and each golden rules file in `testdata/rules/` (prefixed `golden_`).

## Seed corpus

`seeds/ulog_ingest/` is committed. Most seeds are complete logs, so the fuzzer starts inside the event and rule code instead of at a truncated record. To regenerate them (not run in CI: it rewrites committed seeds):

```sh doc-syntax
d=fuzz/seeds/ulog_ingest
mkdir -p $d
for n in v1.17.0/mc_flight_1 v1.17.0/failsafe_gps_loss v1.17.0/failsafe_battery_empty \
         v1.17.0/vtol_transition_abort v1.17.0/vtol_quadchute v1.14.4/mc_flight \
         v1.17.0/gz_quadtailsitter_transition v1.17.0/payload_two_sources; do
  python3 -I scripts/testdata/shrink_ulog.py testdata/sitl/$n.ulg \
    $d/sitl_$(echo $n | tr / _)_shrunk.ulg --every 50 --no-multi-info
done
python3 -I scripts/testdata/shrink_ulog.py testdata/sitl/v1.17.0/gz_x500_vision_hover.ulg \
  $d/sitl_v1.17.0_gz_x500_vision_hover_shrunk.ulg --every 50 --no-multi-info --keep vehicle_visual_odometry
head -c 65516 testdata/pyulog/sample.ulg > $d/pyulog_sample_first_65516.ulg
head -c 16 testdata/sitl/v1.17.0/mc_flight_1.ulg > $d/header_only_16_bytes.ulg
: > $d/empty.ulg
python3 -I scripts/testdata/make_amplification_seed.py $d/subscription_amplification.ulg
```

`subscription_amplification.ulg` (78,227 bytes) subscribes one `failsafe_flags` format with 256 long-named flags 3,891 times. Before each format was flattened once and shared by its subscriptions, it made the target run out of memory under `-rss_limit_mb=2048`; it is also the input of the regression tests named in `docs/LIMITS.md`.

Two seeds exercise appended data (the 'B' record's flag bits and offsets), which the SITL logs do not use: `sitl_v1.17.0_mc_flight_1_shrunk_appended.ulg` is the shrunk log with the appended-data bit set and its first offset at a record boundary in the data section, and `fuzz/seeds/ulog_ingest/appended_offset_past_end.ulg` (59 bytes) announces an offset one byte past the end of the file, which must be reported as truncated (it once made the reader loop forever). Both were written by setting those bytes in the files above; the byte layout is the 'B' record in the ULog specification.

`scripts/testdata/shrink_ulog.py` keeps every record except most data rows: all rows of `vehicle_status`, `failsafe_flags`, `vehicle_command` and `vehicle_command_ack`, every 50th row of the topics the optional rules read and of each topic named with `--keep`, and none of the rest; `--no-multi-info` also drops the 'M' blobs. The shrunk logs still arm, disarm, fail safe, and transition, so R1 to R6 and X1 to X5 all run on them. The Change Order 01 seeds add a tailsitter's transitions, commands from two MAVLink sources (R7 and command categories), and every 50th `vehicle_visual_odometry` row, a topic the fuzz rules seal; the vision seed is also the log of the `vehicle_visual_odometry` byte-flip tests in `crates/sfr/tests/seal_verify.rs`. `pyulog_sample` is cut at a record boundary (byte 65,516), so it parses to the end; it comes from a BSD-3-Clause file whose license and notice are in `testdata/pyulog/`.

## Runs

libFuzzer adds new inputs to the corpus directory it is given, so copy the seeds into the git-ignored `fuzz/corpus/` first (not run in CI by the docs test; the fuzz jobs do it):

```sh doc-syntax
mkdir -p fuzz/corpus/ulog_ingest
cp fuzz/seeds/ulog_ingest/* fuzz/corpus/ulog_ingest/
```

CI run, 60 seconds (`.github/workflows/ci.yml`; not run in CI by the docs test, it needs a nightly toolchain):

```sh doc-syntax
cargo +nightly-2026-10-18 fuzz run ulog_ingest fuzz/corpus/ulog_ingest -- -max_total_time=60 -rss_limit_mb=2048 -timeout=10 -max_len=1048576
```

Nightly run, 10 minutes (`.github/workflows/fuzz-nightly.yml`; not run in CI by the docs test):

```sh doc-syntax
cargo +nightly-2026-10-18 fuzz run ulog_ingest fuzz/corpus/ulog_ingest -- -max_total_time=600 -rss_limit_mb=2048 -timeout=10 -max_len=1048576
```

A clean run exits with status 0, and its last line reads `Done <runs> runs in <seconds> second(s)`. On a finding, libFuzzer stops with a non-zero status, prints the panic message or error report with a stack trace, and writes the input to `fuzz/artifacts/ulog_ingest/` as `crash-*`, `timeout-*`, `oom-*` or `leak-*`.

## Reproduce and minimize a finding

Set `CRASH` to the input libFuzzer wrote, for example `fuzz/artifacts/ulog_ingest/crash-<hash>`. Not run in CI: it needs a finding and a nightly toolchain.

```sh doc-syntax
RUST_BACKTRACE=1 cargo +nightly-2026-10-18 fuzz run ulog_ingest "$CRASH"
cargo +nightly-2026-10-18 fuzz tmin ulog_ingest "$CRASH"
```

The first command runs that one input and prints the panic and backtrace. `tmin` writes smaller inputs with the same failure to `fuzz/artifacts/ulog_ingest/minimized-from-*` and prints the path of the last one under `Minimized artifact:`; rerun the first command on that file to confirm.

## Lockfile

`fuzz/Cargo.lock` started as a copy of the root `Cargo.lock`, so the dependencies the two share resolve to the same versions. After the root lockfile changes, refresh it the same way (not run in CI: it rewrites `fuzz/Cargo.lock`):

```sh doc-syntax
cp Cargo.lock fuzz/Cargo.lock
cargo +nightly-2026-10-18 metadata --manifest-path fuzz/Cargo.toml --format-version 1 > /dev/null
```
