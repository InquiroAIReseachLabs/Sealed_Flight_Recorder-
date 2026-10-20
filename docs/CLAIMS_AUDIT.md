# Claims audit

One command re-tests, from a fresh clone, the claims the README and docs make about `sfr`. It changes nothing in the repository it tests. A test that fails means a wrong claim or a bug, and neither is hidden.

Run it from a checkout of the commit to audit, with `EARLIER_SFR` set to an `sfr` built from the commit before the fixes. Not run in CI: it builds three times and needs SoftHSM, `swtpm`, `strace` and a network namespace.

```sh doc-syntax
scripts/claims_audit.sh --earlier "$EARLIER_SFR"
```

`--earlier` is only for T12; without it T12 is skipped, and the output says so.

## Rules

- A fresh clone of one commit. The commit hash and the machine are the first lines of output.
- Each test records its command, its output, and PASS or FAIL, in one log per test under `$A_WORK/logs` (`A_WORK` defaults to `${TMPDIR:-/tmp}/sfr-claims-audit`).
- The clone is not modified. The runner checks `git status` at the end and fails if anything changed; every file a test makes is under `A_WORK`.
- A case that should fail and passes fails the test, with the case named.
- Where the result is not pass or fail (what happens with a log format `sfr` does not read), the test records exactly what happened.

## The tests

The scripts are in [scripts/claims_audit/](../scripts/claims_audit/). Run alone, a script reads `A_REPO` (the checkout), `A_SFR` (the built binary) and `A_WORK` (`scripts/claims_audit/common.sh`).

| Test | What it checks | Script |
|---|---|---|
| T1 Quickstart | The README steps from a clean clone with a new Rust toolchain home: install, clone, build, keygen, seal, verify. Notes every deviation, and times the cold start. | `t01_quickstart.sh` |
| T2 Golden logs | Seal and verify each golden log with `--pubkey` (with `--allow-untested-version` where the log needs it); records the `Integrity` and `Flight rules` lines. | `t02_golden.sh` |
| T3 Tamper | Each case separately, with `--pubkey` and `--ulog`: flip a byte of the log; truncate it; append bytes; remove or reorder a message; swap in another log; change a field of the record; change a line of the report; wrong public key; reseal a doctored log with a new key and verify against the original key. Each must fail and name what changed. | `t03_tamper.py` |
| T4 No trusted key | `verify` with neither `--pubkey` nor `--trust-anchor` prints NOT CHECKED and exits non-zero. | `t04_t05_inputs.py` |
| T5 Versions and formats | PX4 1.14 to 1.17 logs pass. Others are refused unless `--allow-untested-version`, which then shows in the signed record and the report. A malformed log, a corrupted tail, an ArduPilot `.bin` and a MAVLink `.tlog`: records exactly what happens. | `t04_t05_inputs.py` |
| T6 Offline | Keygen, seal and verify in an empty network namespace (`unshare -n`) under `strace`, tracing every network system call. A `curl` under the same `strace` must be traced, so an empty trace means something. Also runs `scripts/check_deny_list.sh`. | `t06_offline.sh` |
| T7 Determinism | Each golden log sealed twice with the same key and `--seal-time` gives a byte-identical record and report; a different key gives a different record. The `records` job of `.github/workflows/release.yml` (`scripts/check_same_records.sh`) does the same across x86_64, aarch64 and armv7, the last two under QEMU. | `t07_determinism.sh` |
| T8 Rules | R1 to R7: one plain sentence each from [RULES.md](RULES.md), and a fixture that makes that rule fail and nothing else. | `t08_rules.py` |
| T9 Reproducible build | Two clean builds compare equal, and so does a build from a clone in another directory. Scope: one machine, one toolchain. | `t09_reproducible.sh` |
| T10 Key custody | A `pkcs11-token` key on SoftHSM and a `tpm-sealed` key on `swtpm`, sealed and verified. Declared custody prints as unattested; a certificate chain to a supplied trust anchor attests it; a revoked certificate in a supplied CRL fails; the seal time stays the sealer's claim. | `t10_custody.sh` |
| T11 Public text scan | README, docs, examples and site pages: claims not supported by T1 to T10, wording that claims a standard, internal codenames, internal wording, personal information. | `t11_text_scan.sh` |
| T12 Attacks | Twelve attacks against a build from before the fixes (each must succeed) and against the current build (each must fail), after a control that must verify. | `t12_attacks.sh`, `t12_forge.py` |

`scripts/check_language.sh`, part of `scripts/validate.sh`, applies the same wording rules to every file on every change.

## What the audit does not show

- T9: identical builds on different machines are checked by the release workflow (`.github/workflows/release.yml`), not here.
- T7: aarch64 and armv7 run under emulation. Nothing here runs on ARM hardware.
- T10 uses SoftHSM and `swtpm`. No real hardware token or TPM chip is tested.
- Windows and macOS are not tested. The README says CI builds and tests on Linux x86_64 only.
- The seal time in every record is the sealer's claim. T10 checks the output says so; nothing makes it a proven time.

## Results

[receipts/claims-audit.txt](receipts/claims-audit.txt) holds the latest run: the commit, the machine, PASS or FAIL per test, the T1 cold-start time, what T4 and T5 observed, and the T12 table. Full logs are not committed.

The first run passed T1 to T10 and T12 and failed T11, which found internal wording in test comments and two docs. That wording is removed, and T11 now fails any change that adds it back.

Two observations from that run:

- A damaged but well-formed log (the last bytes zeroed, or bytes overwritten in the data section) is sealed without a warning. The seal covers the bytes as they are; it does not say the log is complete. A log cut mid-message or with trailing garbage is refused.
- If the host that serves the Rust installer is blocked, T1 fetches the same installer from `static.rust-lang.org` and notes the deviation.
