# Sealed Flight Record

`sfr` seals a PX4 flight log. After a flight, it writes a signed record of the configuration that flew, the results of seven readiness rules (plus any optional rules the rules file enables), and the operator, failsafe and transition events. Anyone with the signer's public key, or a trust anchor the signer's certificate chains to, can later check that none of it changed after sealing. A seal does not show the data was accurate or genuine before it was sealed.

This repository is the only way to get `sfr` today: build it from source (below). Third-party material is listed in [NOTICE.md](NOTICE.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## What a record proves

`sfr seal` runs the rules R1 to R7 on a PX4 ULog file and writes a signed record (`.sfr`) and a plain report (`.sfr.md`). `sfr verify` checks the record, and with `--ulog` checks it against the log. `Integrity: VERIFIED` means this record, signed by this key, has not changed since it was sealed and, with `--ulog`, matches these log bytes and rule results. It does not mean the log was accurate, that the vehicle did what the log says, or that nothing changed the log between the flight and the seal.

**`sfr verify` checks integrity, not the verdict.** A record whose rules failed verifies and exits 0 if it is intact; its `Rule checks:` line shows the verdict. To require the flight to have passed as well, add `--require-pass`: `verify` then exits 1 when the verdict is FAIL or NO ARMED FLIGHT, and, in text output, prints a `verdict` line saying so (test `require_pass_makes_verify_fail_on_a_failing_or_empty_verdict`).

- **The record is signed; the report is a view of it.** `sfr verify` renders the report again from the verified record and requires the `.sfr.md` beside the record (or the one `--report` names) to match byte for byte. With no report it fails; `--no-report` verifies the record alone and says so. Characters that hide or reorder text, such as U+202E, are written out as `<U+202E>` in the report and in text output; `--json` output writes them as a `\u` escape.
- **Who signed needs the signer's public key.** Give `--pubkey`, or `--trust-anchor` for a certificate chain, with a CRL for every issuer in the chain (`--crl`, repeatable; a missing or expired CRL fails, and so does one older than `--max-crl-age`, 7 days by default, whose value the trust line prints; you, the verifier, must fetch the CRLs from the issuer, since a withheld newer CRL cannot be detected offline; `--no-crl-check` skips revocation and says so). An intermediate CA as the anchor needs `--allow-partial-chain`. With neither a key nor an anchor, `sfr verify` prints `Integrity: NOT CHECKED (no trusted key given)` and exits 4. A key that arrives with the record proves nothing about who signed it.
- **Custody is declared, not proven.** The record says where the key lives (file, PKCS#11 token, TPM). `sfr verify` prints `custody   unattested (declared pkcs11-token)` unless the signer's certificate chains to your trust anchor, and then `attested by certificate chain to the trust anchor ...`. `--require-hardware-key` means attested by such a chain and a record that does not declare `file-evaluation`; with `--pubkey` it always refuses.
- **The seal time is a claim.** It is the sealing machine's clock, or `--seal-time`. It is signed, but it is never checked against a trusted clock: with any trust option, `sfr verify` only requires that it parses and is not more than 5 minutes after the verification time. With `--trust-anchor`, certificates are judged at the verifier's clock (or `--at <RFC3339>`, whole seconds; a time more than 5 minutes in the past needs `--allow-past-at`, and the output then says first that the record verified as of that time and whether the certificate is valid now).
- **Evaluation keys are refused unless allowed.** A record with custody `file-evaluation` (the keys in the examples below) prints `Integrity: REFUSED` and exits 1 although its signature is good. `--allow-evaluation-key` accepts it, and the EVALUATION KEY banner stays.
- **PX4 versions.** Tested on logs from PX4 v1.14.4 and v1.17.0 (`testdata/sitl/`); v1.15 and v1.16 are decoded from the PX4 message definitions but have no test log. `seal` refuses a log outside v1.14 to v1.17, or one whose version it cannot read, unless given `--allow-untested-version`, which is recorded in the signed record and the report.
- **ULog file format version.** The ULog specification (`docs/en/dev_log/ulog_file_format.md` in PX4-Autopilot) gives the current version as 1 (line 65) and asks parsers to read later versions too (line 475). `sfr` reads them as version 1 but is tested on versions 0 and 1 only: `seal` refuses a log of a version above 1 unless given `--allow-untested-version`, and then the signed record holds `seal.allow_untested_ulog_version` and `log.ulog_version`, and the report says `Untested ULog file version`. [docs/VALIDATION.md](docs/VALIDATION.md#the-ulog-specification) names the tests.
- **Logs that end in the middle of a record.** The same specification asks that a parser "correctly handle logs that end abruptly, in the middle of a message" and discard the unfinished one (lines 477 and 478). `seal` reads every complete record and seals the log, unless the log announced appended data at an offset the cut file never reaches, which is refused, exit 3. The signed record holds the offset and the trailing byte count in `log.truncated`, the report says `log ended mid-record at byte N; K trailing bytes not parsed`, and the file's size and digests still cover every byte. The rules treat the missing tail as input that never arrived, so a log that ends armed fails R5. A log that ends before its first data record holds no flight and is refused, exit 3. [docs/RULES.md](docs/RULES.md#how-the-rules-read-the-log) says how each rule reads it.

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) lists the attacks that are and are not detected.

## Build and try it

You need git and a C compiler and linker (`cc`; on Debian or Ubuntu, `build-essential`). The first build downloads dependencies from crates.io; after that `sfr` needs no network. CI builds and tests on Linux `x86_64`. It also runs the test suite for armv7 under QEMU, and cross-compiles the aarch64 and armv7 release binaries and checks their records under QEMU; the aarch64 benchmark is a manual workflow. Other systems are untested.

0. Install Rust with rustup, unless it is installed. `rust-toolchain.toml` pins Rust 1.97.0 and the first `cargo build` installs it. Not run in CI, which installs the toolchain its own way:

   ```sh doc-syntax
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

1. Get the source (`--depth 1` leaves out the history; most of the download is the test logs in `testdata/`). Not run in CI, which tests the checkout it already has:

   ```sh doc-syntax
   git clone --depth 1 https://github.com/InquiroAIReseachLabs/Sealed_Flight_Recorder-.git
   cd Sealed_Flight_Recorder-
   ```

2. Build. The binary is `target/release/sfr`:

   ```sh doc-test
   cargo build --release --locked
   ```

3. Verify a record sealed earlier, against its log. `examples/reports/` holds four records sealed from golden SITL logs, and the public key `sfr.pub`. `Integrity:` says whether the record and log are unchanged since sealing; `Rule checks:` gives the sealed rule results. A record whose rules failed still verifies; the exit code follows integrity only:

   ```sh doc-test
   target/release/sfr verify examples/reports/vtol_transition.sfr --pubkey examples/reports/sfr.pub \
     --allow-evaluation-key \
     --ulog testdata/sitl/v1.17.0/vtol_transition.ulg
   ```

   ```text doc-output
   EVALUATION KEY: not for operational use
   Integrity: VERIFIED (record and log)
   Rule checks: WARN (R4)
   record    examples/reports/vtol_transition.sfr
   report    examples/reports/vtol_transition.sfr.md matches the record
   trust     the public key given with --pubkey (trusted as far as its source is)
   custody   unattested (declared file-evaluation)
   key       sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45
   merkle    cb0183bc5b2bb55bd02c2d2a2f592cb10f60c36520d2ab22f8701c3e66ff9375 (34 leaves)
   crypto    blake3 1.8.7, ed25519-dalek 3.0.0, sha2 0.11.1 (crate versions)
   seal time 2026-10-18T15:00:00Z (claimed by the sealer, not proven)
   events    22
   ```

4. Change one field of a copy of that record and verify the copy twice. With the public key alone, verify can only say the signed Merkle root no longer matches. With the log too, it finds the differing event and names the field and both values. Each exits 1:

   ```sh doc-test
   mkdir -p try
   sed 's/"command":211,/"command":311,/' examples/reports/vtol_transition.sfr > try/changed.sfr
   rc=0
   target/release/sfr verify try/changed.sfr --pubkey examples/reports/sfr.pub --allow-evaluation-key || rc=$?
   echo "exit $rc"
   ```

   ```text doc-output
   EVALUATION KEY: not for operational use
   Integrity: FAILED: Merkle root mismatch: a leaf changed after sealing (recorded cb0183bc5b2bb55bd02c2d2a2f592cb10f60c36520d2ab22f8701c3e66ff9375, computed 78ad1b57928f3c6ab6dc6407ead4012b77ed6fd96e3c84f1d9f782515640587f)
   Rule checks: UNKNOWN (the record failed its integrity check, so its rule results cannot be trusted)
   key       sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45 (named by the record, not proven)
   custody   unattested (declared file-evaluation)
   exit 1
   ```

   ```sh doc-test
   rc=0
   target/release/sfr verify try/changed.sfr --pubkey examples/reports/sfr.pub --allow-evaluation-key \
     --ulog testdata/sitl/v1.17.0/vtol_transition.ulg || rc=$?
   echo "exit $rc"
   ```

   ```text doc-output
   EVALUATION KEY: not for operational use
   Integrity: FAILED: event seq 1 (COMMAND) field `command`: sealed 311, found 211
     also: Merkle root mismatch: a leaf changed after sealing (recorded cb0183bc5b2bb55bd02c2d2a2f592cb10f60c36520d2ab22f8701c3e66ff9375, computed 78ad1b57928f3c6ab6dc6407ead4012b77ed6fd96e3c84f1d9f782515640587f)
   Rule checks: UNKNOWN (the record failed its integrity check, so its rule results cannot be trusted)
   key       sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45 (named by the record, not proven)
   custody   unattested (declared file-evaluation)
   exit 1
   ```

5. Make an evaluation key and seal a log. `seal` prints the rule results and writes the record and report into `try/out/`:

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
   R2    PASS    firmware matches baseline     log states PX4 1.17.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4 (self-reported); baseline file sha256 d4da23c173b4031487e802b4971921f834d255f1eb47c4906228cb93edf18885 (operator-supplied)
   R3    PASS    parameters match baseline     no differences; ignore [COM_FLIGHT_UUID, LND_FLIGHT_T_HI, LND_FLIGHT_T_LO, EKF2_MAG_DECL, CAL_BARO*_OFF, ASPD_SCALE_*, COM_MODE*_HASH] suppressed 1 difference(s); baseline file sha256 d4da23c173b4031487e802b4971921f834d255f1eb47c4906228cb93edf18885 (operator-supplied)
   R4    WARN    no failsafe in flight         never true in flight; warning: failsafe_flags auto_mission_missing, gcs_connection_lost, manual_control_signal_lost, offboard_control_signal_lost true in flight
   R5    PASS    arm and disarm consistent     1 ARM, 1 DISARM
   R6    PASS    VTOL transitions completed    2 START, 2 END, 0 problem(s)
   R7    N/A     authorized command sources    no [authorized_sources] in the rules file
   status    WARN
   record    try/out/vtol_transition.sfr
   report    try/out/vtol_transition.sfr.md
   ```

   The key is new each time, so the fingerprint and Merkle root differ from run to run. `try/keygen.txt` and `try/seal.txt` hold the whole output; `try/out/vtol_transition.sfr.md` is the report.

6. Verify the record you sealed, against its log:

   ```sh doc-test
   target/release/sfr verify try/out/vtol_transition.sfr --pubkey try/keys/sfr.pub --allow-evaluation-key \
     --ulog testdata/sitl/v1.17.0/vtol_transition.ulg | grep -E '^(EVALUATION|Integrity|Rule checks)'
   ```

   ```text doc-output
   EVALUATION KEY: not for operational use
   Integrity: VERIFIED (record and log)
   Rule checks: WARN (R4)
   ```

To seal your own log you need a rules file (start from `examples/rules.default.toml`) and a baseline: the parameter file QGroundControl exports, plus one line `# Firmware: <version>` ([docs/RULES.md](docs/RULES.md)). Operational records use a key in a PKCS#11 token or HSM, or a seed sealed to a TPM ([docs/INTEGRATION_NOTES.md](docs/INTEGRATION_NOTES.md#keys)). Not run in CI: it needs your files.

```sh doc-syntax
target/release/sfr seal "$LOG" --rules my_rules.toml --baseline my_vehicle.params --dry-run
target/release/sfr seal "$LOG" --rules my_rules.toml --baseline my_vehicle.params \
  --key try/keys/sfr.key --evaluation-only --out records
```

## Exit codes

From `crates/sfr-core/src/lib.rs` (`exit_code`):

| Exit | `sfr seal` | `sfr verify` |
|---|---|---|
| 0 | status PASS or WARN; record written | `Integrity: VERIFIED`, whatever the `Rule checks:` line says (with `--require-pass`, only for PASS or WARN) |
| 1 | a rule FAIL, or no armed flight (status NO ARMED FLIGHT); the record is still written | `Integrity: FAILED` (record, log or certificate chain does not check, the `.sfr.md` report is missing or differs, the claimed seal time is more than 5 minutes after the verification time, or an input limit is exceeded) or `Integrity: REFUSED` (good signature, but an evaluation key without `--allow-evaluation-key`, or custody `--require-hardware-key` does not accept), or, with `--require-pass`, `Integrity: VERIFIED` with a FAIL or NO ARMED FLIGHT verdict |
| 2 | a required topic or field is missing (R1 FAIL); the record is still written | not used |
| 3 | the log, rules file or baseline is malformed, truncated before the log's first data record, or over an input limit; nothing written | not used |
| 4 | a usage, key or file error; nothing written (except that a failed write of the result table to stdout comes after the record and report are written) | a usage, key or file error, or no trust source given (`Integrity: NOT CHECKED`) |

`sfr keygen` and `sfr --version` exit 0 or 4.

## Documentation

| Page | What it covers |
|---|---|
| [docs/RULES.md](docs/RULES.md) | each rule, the log data it reads, the rules file and the baseline |
| [docs/RECORD_FORMAT.md](docs/RECORD_FORMAT.md) | the record, exactly, and how to verify one with `openssl` and `b3sum` |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | what a seal proves and what it does not |
| [docs/INTEGRATION_NOTES.md](docs/INTEGRATION_NOTES.md) | the topics `sfr` reads, sealing after disarm, CI use, key handling |
| [docs/LIMITS.md](docs/LIMITS.md) | the input limits |
| [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md), [docs/BENCHMARK.md](docs/BENCHMARK.md) | verify timing, test results and seal benchmarks |
| [docs/VALIDATION.md](docs/VALIDATION.md) | what was tested, the crafted false-pass logs and what became of them, the false passes that remain |
| [docs/CLAIMS_AUDIT.md](docs/CLAIMS_AUDIT.md) | the tests that re-check, from a fresh clone, the claims its table lists (not every sentence of these pages) |
| [docs/design/README.md](docs/design/README.md) | design notes for things a record does not do yet; none is built |
| [docs/RELEASE.md](docs/RELEASE.md) | how a release is made and checked (no release exists yet) |
| [examples/reports/README.md](examples/reports/README.md) | the example records and reports |

CI runs every `doc-test` command in the Markdown pages of this repository (`scripts/check_docs.py`): it must exit 0, and where a `doc-output` block follows, its output must match. The other shell blocks are only syntax-checked.

## Rights

Copyright (c) 2026 Inquiro AI Research Labs. All rights reserved. This source is published for review and evaluation.
