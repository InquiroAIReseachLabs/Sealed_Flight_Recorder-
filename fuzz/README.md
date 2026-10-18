# fuzz/

cargo-fuzz targets (SPEC B1.2, B1.10 "Fuzzing"). This is a separate package with its own `[workspace]` and a committed `Cargo.lock`; the root `Cargo.toml` excludes `fuzz/`. cargo-fuzz needs a nightly toolchain, and the root `rust-toolchain.toml` pins stable, so every command below passes `+nightly-2026-10-18`, the nightly CI pins (`rustup toolchain install nightly-2026-10-18 --profile minimal`). Run them from the repository root.

Gate: 60 seconds per CI run and 10 minutes nightly with zero panics, hangs, or out-of-memory.

The `.sfr` reader target arrives in Chunk 3.

## Target `ulog_ingest`

Arbitrary bytes go through the whole `seal --dry-run` path:

1. `Px4Ingestor::ingest`: the ULog reader, SHA-256 and BLAKE3 of every byte, field decoding, and the event timeline. SHA-256 comes from a fuzz-only backend on the `sha2` crate, so the fuzz build does not need the FIPS module.
2. If the log is readable, `evaluate` with `examples/rules.extended.toml` (the core rules and every optional rule) and the baseline `# Firmware: 1.17.0`.
3. `record::dry_run_json`, then `json::canonical`.

The target also checks that the logged size and `Summary.bytes` equal the input length and that events are numbered from 0. A finding is any panic (cargo-fuzz builds check integer overflow, so an overflow is a panic), a failed check, a hang, or an out-of-memory.

## Seed corpus

`seeds/ulog_ingest/` is committed. Most seeds are complete logs, so the fuzzer starts inside the event and rule code instead of at a truncated record. To regenerate them:

```sh
d=fuzz/seeds/ulog_ingest
mkdir -p $d
for n in v1.17.0/mc_flight_1 v1.17.0/failsafe_gps_loss v1.17.0/failsafe_battery_empty \
         v1.17.0/vtol_transition_abort v1.17.0/vtol_quadchute v1.14.4/mc_flight; do
  python3 -I scripts/testdata/shrink_ulog.py testdata/sitl/$n.ulg \
    $d/sitl_$(echo $n | tr / _)_shrunk.ulg --every 50 --no-multi-info
done
head -c 65516 testdata/pyulog/sample.ulg > $d/pyulog_sample_first_65516.ulg
head -c 16 testdata/sitl/v1.17.0/mc_flight_1.ulg > $d/header_only_16_bytes.ulg
: > $d/empty.ulg
```

Two seeds exercise appended data (the 'B' record's flag bits and offsets), which the SITL logs do not use: `sitl_v1.17.0_mc_flight_1_shrunk_appended.ulg` is the shrunk log with the appended-data bit set and its first offset at a record boundary in the data section, and `appended_offset_past_end.ulg` (59 bytes) announces an offset one byte past the end of the file, which must be reported as truncated (it once made the reader loop forever). Both were written by setting those bytes in the files above; the byte layout is the 'B' record in the ULog specification.

`scripts/testdata/shrink_ulog.py` keeps every record except most data rows: all rows of `vehicle_status`, `failsafe_flags`, `vehicle_command` and `vehicle_command_ack`, every 50th row of the topics the optional rules read, and none of the rest; `--no-multi-info` also drops the 'M' blobs. The shrunk logs still arm, disarm, fail safe, and transition, so R1 to R6 and X1 to X5 all run on them. `pyulog_sample` is cut at a record boundary (byte 65,516), so it parses to the end; it comes from a BSD-3-Clause file whose license and notice are in `testdata/pyulog/`.

## Runs

libFuzzer adds new inputs to the corpus directory it is given, so copy the seeds into the git-ignored `fuzz/corpus/` first:

```sh
mkdir -p fuzz/corpus/ulog_ingest
cp fuzz/seeds/ulog_ingest/* fuzz/corpus/ulog_ingest/
```

CI run (60 seconds):

```sh
cargo +nightly-2026-10-18 fuzz run ulog_ingest fuzz/corpus/ulog_ingest -- -max_total_time=60 -rss_limit_mb=2048 -timeout=10 -max_len=1048576
```

Nightly run (10 minutes):

```sh
cargo +nightly-2026-10-18 fuzz run ulog_ingest fuzz/corpus/ulog_ingest -- -max_total_time=600 -rss_limit_mb=2048 -timeout=10 -max_len=1048576
```

A clean run exits with status 0, and its last line reads `Done <runs> runs in <seconds> second(s)`. On a finding, libFuzzer stops with a non-zero status, prints the panic message or error report with a stack trace, and writes the input to `fuzz/artifacts/ulog_ingest/` as `crash-*`, `timeout-*`, `oom-*` or `leak-*`.

## Reproduce and minimize a finding

```sh
RUST_BACKTRACE=1 cargo +nightly-2026-10-18 fuzz run ulog_ingest fuzz/artifacts/ulog_ingest/crash-<hash>
cargo +nightly-2026-10-18 fuzz tmin ulog_ingest fuzz/artifacts/ulog_ingest/crash-<hash>
```

The first command runs that one input and prints the panic and backtrace. `tmin` writes smaller inputs with the same failure to `fuzz/artifacts/ulog_ingest/minimized-from-*` and prints the path of the last one under `Minimized artifact:`; rerun the first command on that file to confirm.

## Lockfile

`fuzz/Cargo.lock` started as a copy of the root `Cargo.lock`, so the dependencies the two share resolve to the same versions. After the root lockfile changes, refresh it the same way:

```sh
cp Cargo.lock fuzz/Cargo.lock
cargo +nightly-2026-10-18 metadata --manifest-path fuzz/Cargo.toml --format-version 1 > /dev/null
```
