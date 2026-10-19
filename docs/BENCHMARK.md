# Benchmark

`scripts/benchmark.sh` measures a built `sfr` on the machine it runs on (SPEC B1.10 Performance and Peak memory): for every golden log and for logs of 10, 50 and 100 MB, the median seal wall time, the median wall time of a standalone `sfr verify` of the record, and the largest maximum resident set size of seal. It builds nothing, so it runs from the release tarballs on a machine with no compiler, no Rust, and no Python.

It needs bash 5 or later, GNU time at `/usr/bin/time` (Debian and Ubuntu: `sudo apt-get install time`), and the usual `head`, `tail`, `sha256sum`, `sort`, `awk`, `mktemp`. A missing tool stops it with exit 2.

## Run it on another machine (for example real aarch64 hardware)

1. Take three files from the CI run or the release: the tarball for the machine's target (`sfr-<version>-aarch64-unknown-linux-musl.tar.gz` on a 64-bit ARM machine), the benchmark kit `sfr-<version>-benchmark.tar.gz`, and `SHA256SUMS`.
2. Check them: `sha256sum -c --ignore-missing SHA256SUMS`
3. Unpack both tarballs in one directory:

   ```
   tar -xzf sfr-<version>-aarch64-unknown-linux-musl.tar.gz
   tar -xzf sfr-<version>-benchmark.tar.gz
   ```

4. Run, keeping the output:

   ```
   sfr-<version>-benchmark/scripts/benchmark.sh --sfr sfr-<version>-aarch64-unknown-linux-musl/bin/sfr | tee benchmark.txt
   ```

5. Report `benchmark.txt` whole. Its `hardware:` line names the architecture, CPU model, cores, memory, kernel, OS, and the board model when the kernel exposes one; add the machine's product name if that line does not show it.

Run nothing else on the machine meanwhile. `--runs N` changes the number of runs per log (default 5).

## Gates

| Architecture | Gate (SPEC B1.10) |
|---|---|
| x86_64 | each 100 MB seal median under 2 s |
| aarch64 | each 100 MB seal median under 4 s, counted only on real aarch64 hardware, not emulation |
| armv7 | none; no armv7 timing is published unless measured on real hardware |

On every architecture, a seal peak above 256 MB on a 100 MB log must be reported with its cause before work continues. The script prints one `gate:` and one `memory:` line per 100 MB log and exits 1 if a gate is missed or a peak is above 256 MB.

## The large logs

They are built for size only from the golden VTOL flight `testdata/sitl/v1.17.0/vtol_transition.ulg` (24.3 MB), using the segments listed in `scripts/benchmark/vtol_transition.segments`: runs of whole records from the flight's data section that hold no subscription or info record (`A`, `I`, `M`), at most 1 MB each, written by `scripts/benchmark/make_segments.py`. The script checks the flight's SHA-256 against that file first.

- `large_10mb`: the flight cut at the end of the first segment that reaches 10,000,000 bytes, so the cut falls between two records and every subscription before it is kept.
- `large_50mb`, `large_100mb`: one full copy of the flight, then its segments appended in order, again and again, until the log reaches 50,000,000 or 100,000,000 bytes.

Each overshoots its size by under 1 MB. Every byte comes from the real SITL flight and nothing is rewritten, so the timestamps restart with each repetition. They are not real flights, and R5 may fail on them; the record is still written and timed. Each large log is sealed twice: with `examples/rules.default.toml`, and with the eight highest-rate topics of the flight in `[sealed_topics]` (`_sealed8`), so the sealed topic digests are inside the gate.

## In CI

The `benchmark` job runs the script on x86_64 from the x86_64 release tarball and the benchmark kit, with no source checkout, inside `debian:12-slim` with only GNU time added: no compiler, no Rust, no Python. `scripts/regen_readme_numbers.sh` copies that run's output into the README.
