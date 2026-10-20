# Benchmark

`scripts/benchmark.sh` measures a built `sfr` on the machine it runs on (SPEC B1.10 Performance and Peak memory). For every golden log and for logs of 10, 50 and 100 MB it reports the median seal wall time, the median wall time of a standalone `sfr verify`, and the largest peak memory of seal. It builds nothing, so it runs from the release tarballs on a machine with no compiler, Rust or Python. The numbers from CI are in [MEASUREMENTS.md](MEASUREMENTS.md).

It needs bash 5 or later, GNU time at `/usr/bin/time` (Debian and Ubuntu: `sudo apt-get install time`), and standard tools (`awk`, `sha256sum`, `sed`, `od`, `getconf` and the like). It checks for each at start and stops with exit 2 when one is missing or the binary is not x86_64, aarch64 or armv7.

## Run it on another machine

1. Take three files from the `sfr-release-unsigned` artifact of a CI run: the tarball for the machine's target (`sfr-<version>-aarch64-unknown-linux-musl.tar.gz` on aarch64), the benchmark kit `sfr-<version>-benchmark.tar.gz`, and `SHA256SUMS`. The kit is not part of a release.
2. Check them: `sha256sum -c --ignore-missing SHA256SUMS`
3. Unpack both tarballs in one directory (not run in CI by the docs test, which has no release files):

   ```sh doc-syntax
   tar -xzf sfr-<version>-aarch64-unknown-linux-musl.tar.gz
   tar -xzf sfr-<version>-benchmark.tar.gz
   ```

4. Run it and keep the output (not run in CI by the docs test; the `benchmark` job runs it):

   ```sh doc-syntax
   sfr-<version>-benchmark/scripts/benchmark.sh --sfr sfr-<version>-aarch64-unknown-linux-musl/bin/sfr | tee benchmark.txt
   ```

Run nothing else on the machine meanwhile. `--runs N` sets the runs per log (default 5). The `hardware:` line of the output names the architecture, CPU, cores, memory, kernel and OS, and the board model when the kernel shows one.

## aarch64, Arm cloud VM

The `benchmark-aarch64` workflow (`.github/workflows/benchmark-aarch64.yml`, run by hand) builds the aarch64 tarball and the kit on GitHub's arm64 hosted runner and runs the benchmark there. Put the receipt it uploads at `docs/receipts/aarch64-benchmark.txt` and run `scripts/regen_readme_numbers.sh` to write the block below; the script refuses a run whose binary or machine is not aarch64. The runner is a cloud virtual machine, not embedded or companion-computer hardware, and no measurement on such hardware has been made.

<!-- BEGIN benchmark-arm-vm: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
Not measured yet. Run the `benchmark-aarch64` workflow (Actions, benchmark-aarch64, Run workflow), put the receipt it uploads at `docs/receipts/aarch64-benchmark.txt`, and run `scripts/regen_readme_numbers.sh`. The result will be labelled "aarch64, Arm cloud VM".
<!-- END benchmark-arm-vm -->

## Gates

As `scripts/benchmark.sh` checks them (SPEC B1.10):

| Architecture | Gate |
|---|---|
| x86_64 | each 100 MB seal median under 2 s |
| aarch64 | each 100 MB seal median under 4 s, counted only on real aarch64 hardware, not emulation |
| armv7 | none; no armv7 timing is published unless measured on real hardware |

`scripts/benchmark.sh` holds the limit: on every architecture a seal peak above 256 MB on a 100 MB log must be reported with its cause. The script prints one `gate:` and one `memory:` line per 100 MB log and exits 1 if a gate is missed or a peak is above 256 MB.

## The large logs

They are built for size only from the golden VTOL flight `testdata/sitl/v1.17.0/vtol_transition.ulg`, using the segments in `scripts/benchmark/vtol_transition.segments`: runs of whole records from the flight's data section that hold no subscription or info record, at most 1 MB each, written by `scripts/benchmark/make_segments.py` (which checks the flight's SHA-256 first).

- `large_10mb`: the flight cut at the end of the first segment that reaches 10,000,000 bytes.
- `large_50mb`, `large_100mb`: one full copy of the flight, then its subscriptions and segments again and again until the log reaches 50,000,000 or 100,000,000 bytes. Repetition r carries every message id raised by r times the flight's count (`msg_ids` in the manifest; `scripts/benchmark/remap_msg_ids.awk`, run on `od` output), so each repetition is a new subscription of the same topic instances and every subscription's timestamps keep increasing, as the ULog specification requires. Every other byte is the flight's.

Each overshoots its size by under 1 MB. They are not real flights, and R5 may fail on them; the record is still written and timed. Each is sealed twice: with `examples/rules.default.toml`, and with the eight highest-rate topics of the flight in `[sealed_topics]` (`_sealed8`).

## In CI

The `benchmark` job runs the script on x86_64 from the x86_64 release tarball and the kit, with no source checkout, inside `debian:12-slim` with only GNU time added. `scripts/regen_readme_numbers.sh` copies its output into [MEASUREMENTS.md](MEASUREMENTS.md).
