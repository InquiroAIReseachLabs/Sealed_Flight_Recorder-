# Claims audit

Every claim the README and the docs make about `sfr` is tested again, from a fresh clone, by one command. The audit is the list of tests below, T1 to T12. It changes nothing in the repository it tests. A test that does not pass is a claim that is wrong or a bug; neither is hidden.

Run it from a checkout of the commit to audit, with `EARLIER_SFR` set to an `sfr` built from the commit before the fixes (not run in CI, because it builds three times and needs SoftHSM, `swtpm` and a network namespace):

```sh doc-syntax
scripts/claims_audit.sh --earlier "$EARLIER_SFR"
```

The command installs a Rust toolchain into a scratch home, builds the project three times, and needs SoftHSM, `swtpm`, `strace` and a network namespace. `--earlier` is only for T12; without it T12 is skipped and said so.

## Rules of the audit

- A fresh clone of one commit. The commit hash and the machine are the first lines of the output.
- For every test: the command, the output, and PASS or FAIL. The logs are in `$A_WORK/logs`, one file per test (`A_WORK` defaults to `${TMPDIR:-/tmp}/sfr-claims-audit`).
- The clone is not modified while testing. The runner checks `git status` of the clone at the end and fails if anything changed. Every file a test makes is under `A_WORK`.
- A case that should fail and passes is reported as a failure of the test, with the case named.
- Where behaviour is not a pass or a fail (what happens with a log format `sfr` does not read), the test records exactly what happened and compares it with what the docs say.

## The tests

Each script is in [scripts/claims_audit/](../scripts/claims_audit/). Run alone, a script reads `A_REPO` (the checkout), `A_SFR` (the built binary) and `A_WORK` (see `scripts/claims_audit/common.sh`).

| Test | What it checks | Script |
|---|---|---|
| T1 Quickstart | Follow the README exactly from a clean clone, with a new Rust toolchain home: install, clone, build, keygen, seal, verify. Note every deviation from the text. Time the whole cold start and report the number with the machine. | `t01_quickstart.sh` |
| T2 Golden logs | Seal and verify each golden log with `--pubkey` (and `--allow-untested-version` where the log needs it). Record the `Integrity` and `Flight rules` lines of each. | `t02_golden.sh` |
| T3 Tamper | Each separately, verified with `--pubkey` and `--ulog`: flip one byte of the log; truncate it; append bytes; remove or reorder a message; swap in a different log; change any field of the record; change any line of the report; wrong public key; reseal a doctored log with a new key and verify against the original key. Each must fail and name what changed. | `t03_tamper.py` |
| T4 No trusted key | `verify` with neither `--pubkey` nor `--trust-anchor` prints NOT CHECKED and exits non-zero. | `t04_t05_inputs.py` |
| T5 Versions and formats | PX4 1.14 to 1.17 logs pass. A log outside the range is refused unless `--allow-untested-version`, and the flag is in the signed record and the report. A malformed log, a corrupted tail, an ArduPilot `.bin` and a MAVLink `.tlog`: record exactly what happens. | `t04_t05_inputs.py` |
| T6 Offline | Keygen, seal and verify inside an empty network namespace (`unshare -n`) under `strace`, tracing every network system call. A positive control (a `curl` under the same `strace`) must be traced, so an empty trace means something. Also `scripts/check_deny_list.sh`. | `t06_offline.sh` |
| T7 Determinism | Seal each golden log twice with the same key and `--seal-time`; the record and the report must be byte identical. A different key must give a different record. The `records` job of `.github/workflows/release.yml` (`scripts/check_same_records.sh`) compares the records of the x86_64, aarch64 and armv7 binaries; the aarch64 and armv7 binaries run under QEMU emulation, not on hardware. | `t07_determinism.sh` |
| T8 Rules | R1 to R7, one plain sentence each from [RULES.md](RULES.md), and a fixture that makes each rule fail and nothing else. | `t08_rules.py` |
| T9 Reproducible build | Build twice from clean and compare checksums, then build a clone in another directory. The scope is one machine and one toolchain; see the limit below. | `t09_reproducible.sh` |
| T10 Key custody | Seal with a `pkcs11-token` key on SoftHSM and a `tpm-sealed` key on `swtpm`, then verify both. The declared custody prints as unattested. A certificate chain to a supplied trust anchor verifies and attests it. A revoked certificate in a supplied CRL fails. The seal time stays the sealer's claim. | `t10_custody.sh` |
| T11 Public text scan | README, docs, examples and the site pages: every claim not supported by T1 to T10, wording that claims a standard, internal codenames, internal wording, personal information. | `t11_text_scan.sh` |
| T12 Attacks | Twelve attacks run against a build from before the fixes, where each must succeed, and against the current build, where each must fail, after a control that must verify. | `t12_attacks.sh`, `t12_forge.py` |

The language gate (`scripts/check_language.sh`, part of `scripts/validate.sh`) holds the same line for every file in the repository on every change: no wording that claims a standard, no internal codenames, and no wording about who asked for a change or which review found it. The repository states what the software does and nothing about how the work was organised.

## What the audit does not show

- T9 shows that two builds on one machine with one toolchain are identical. Identical builds on different machines are checked by the release workflow (`.github/workflows/release.yml`), not by this audit.
- T7 on aarch64 and armv7 is under emulation. No test here runs on ARM hardware.
- T10 uses software tokens: SoftHSM and `swtpm`. No real hardware token or TPM chip is tested.
- Windows and macOS are not tested. The README says that CI builds and tests on Linux x86_64 only, and the Windows steps in it have not been run.
- The seal time in every record is the sealer's claim. T10 checks that the output says so; nothing in the audit makes it a proven time.

## Results

The results of the latest run are in [receipts/claims-audit.txt](receipts/claims-audit.txt): the commit, the machine, the line of PASS or FAIL for each test, the cold-start time of T1, and what T4 to T5 observed. The full logs are not committed; they are large and every run writes new ones.

The first run, on the commit before this page existed, passed T1 to T10 and T12 and failed T11: the text scan found internal wording in test comments and in two docs. That wording was removed in the change that added this page, and the scan, run on that tree, passes. T11 now fails any change that adds such wording back (`scripts/check_language.sh` holds the same rule in the checks that run on every change).

Three observations from the first run that the docs state and the audit keeps visible:

- A log that is damaged but still well formed (for example the last bytes zeroed, or bytes overwritten in the data section) is sealed without a warning. The seal covers the bytes as they are; it does not say the log is complete. A log cut mid-message or with garbage at the end is refused.
- The README's first command downloads the Rust installer from `sh.rustup.rs`. On a network that blocks that host, T1 fetches the same installer from `static.rust-lang.org` and notes the deviation.
- The Windows steps in the README are untested (see the limits above).

The twelve attacks of T12 and their results on the first run are the table at the end of the receipt: each succeeds against the build from before the fixes (commit 4031c96) and fails against the current one.
