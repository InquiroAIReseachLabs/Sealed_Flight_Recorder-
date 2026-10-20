# Phase 0 measurements

Phase 0 of the chunked code review (`docs/review/PLAN.txt`) changes no behavior. It measures how well the tests already hold the code, so that review time goes where they are weak. This page says what was measured, what the numbers mean, and how to measure again. The chunks are in `docs/review/LEDGER.md`; the measurements below are rendered from `docs/review/ledger.json` by `scripts/review/ledger.py render`.

## What is here

| What | Where | Made by |
|---|---|---|
| Chunk ledger | `docs/review/ledger.json`, `docs/review/LEDGER.md` | `scripts/review/ledger.py` |
| Source facts the ledger uses (function ranges, test-only code, code lines, branch counts) | `tools/review_metrics` | `cargo run --release --locked --manifest-path tools/review_metrics/Cargo.toml` |
| Long functions, most branches | `docs/review/LONG_FUNCTIONS.md` | `scripts/review/ledger.py` |
| Lint baseline | `docs/review/lint-baseline.txt` | `scripts/review/lint_baseline.py` |
| Line and branch coverage per chunk | `docs/review/LEDGER.md` | `scripts/review/coverage.py` |
| Mutation testing per chunk | `docs/review/LEDGER.md` | `scripts/review/mutants.py` |
| Property tests | `crates/sfr-core/tests/prop_canonical.rs`, `prop_merkle.rs`, `prop_ulog.rs`, `prop_record.rs`; the `properties` module at the end of `crates/sfr/src/certs.rs` | run with `cargo test --workspace` |
| Fuzz targets and runs | `fuzz/fuzz_targets/crl_parse.rs` (new), `fuzz/seeds/`, `docs/review/FUZZ_RUN.txt` | `scripts/review/fuzz_phase0.py` |

## Results

By group, over every chunk. Lint counts the warnings of `docs/review/lint-baseline.txt` that fall on shipped code. Mutation score is caught divided by caught, missed and timed out; unviable mutants (they do not compile) are left out.

<!-- BEGIN phase0-groups: scripts/review/ledger.py render -->
<!-- END phase0-groups -->

### The ten chunks with the lowest mutation score

Chunks with five or more rated mutants, lowest score first. These are the chunks whose tests would notice the fewest wrong lines, so their review starts from the missed mutants rather than from the code.

<!-- BEGIN phase0-lowest: scripts/review/ledger.py render -->
<!-- END phase0-lowest -->

## How the mutation score is measured

A run of the whole workspace test suite takes minutes in a debug build, and there are thousands of mutants, so a mutant is tried against a cheap set of tests first and only the survivors go on (`scripts/review/mutants.py` has the sets):

1. The unit tests of the crate that holds the file.
2. The end-to-end tests of the `sfr` command line on the golden logs.
3. The record-forging and reference-verifier tests, for the files they hold (verification, sealing, canonical JSON, the Merkle tree, keys, certificates).

A mutant counts as caught when any tier caught it. A survivor on a line that no test of the whole suite executes cannot be caught by a later tier and counts as missed without being run again. The score is therefore a floor: a mutant that only a test outside these sets would catch counts as missed. When a chunk is closed, its mutation run is repeated with the full suite (`docs/review/PLAN.txt`, step 6).

The mutated tree is a clean checkout of the commit named in the ledger, so the property tests added alongside these measurements are not in the numbers: they are what the numbers are measured before.

## What this page does not hold

Per-mutant lists, counterexamples found by the new tests or the fuzz runs, and disagreements between the documents and the code are findings. The plan keeps findings out of the repository until the fix is merged (`docs/review/PLAN.txt`, section 8), so they are not here.

## Measure again

Each command writes into the work tree and reads the commit it is run at; run them from a clean checkout of the commit named in `docs/review/ledger.json`. The commands are not run in CI.

```sh doc-syntax
cargo build --release --locked --manifest-path tools/review_metrics/Cargo.toml
python3 -I scripts/review/ledger.py build
python3 -I scripts/review/lint_baseline.py
python3 -I scripts/review/coverage.py --lines target/covered-lines.json
python3 -I scripts/review/mutants.py run --tier 1 --out target/mutants
python3 -I scripts/review/mutants.py run --tier 2 --out target/mutants --lines target/covered-lines.json
python3 -I scripts/review/mutants.py run --tier 3 --out target/mutants --lines target/covered-lines.json
python3 -I scripts/review/mutants.py collect --out target/mutants --lines target/covered-lines.json
python3 -I scripts/review/fuzz_phase0.py
python3 -I scripts/review/ledger.py check
```

Install what they need (not run in CI):

```sh doc-syntax
cargo install cargo-llvm-cov cargo-mutants --locked
cargo install cargo-fuzz --version 0.13.2 --locked
rustup toolchain install nightly-2026-10-18 --profile minimal --component llvm-tools-preview
```
