# testdata/falsepass/

Crafted logs, each built to look like a passing flight to a reader that trusts what a log declares about its own structure (field types, instances, format definitions, timing), and each beside a positive control: the same log without the trick, which must fail or warn for the reason the trick tries to hide. `cases.json` lists every case: the log, the rules file and baseline it is sealed with, the item of the hardening it tests, and the result `sfr` must give.

Every file here is written by `scripts/testdata/make_falsepass.py` (Python standard library only); nothing is edited by hand. The `golden_*` cases are derived from `testdata/sitl/v1.17.0/mc_flight_1.ulg`, keeping only the topics the core rules read. The baselines are each log's parameters at its first ARM.

- `crates/sfr/tests/falsepass.rs` seals every case with `seal --dry-run --json` and checks the result, and checks that the directory is what the generator writes (`make_falsepass.py --check`).
- `scripts/testdata/run_falsepass.py <sfr>` does the same for any `sfr` binary and prints one line per case, or a table with `--table`; run it with an older binary to see which cases that binary lets through.
