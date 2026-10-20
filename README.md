# Sealed Flight Record

After a PX4 flight, `sfr` produces a signed, self-verifying record of the configuration that flew, the readiness rule results, and the operator, failsafe, and transition events, so that anyone who has the signer's public key, or a trust anchor its certificate chains to, can later check that none of it changed after it was sealed. A seal does not show that the data was genuine or accurate before it was sealed.

This is an evaluation release, provided without warranty, and in development: the quickstart signs with evaluation keys, every record sealed with one says EVALUATION KEY, and `sfr verify` refuses such a record unless you add `--allow-evaluation-key`. Operational records are sealed with a key held in a PKCS#11 token or HSM, or with a seed sealed to a TPM ([docs/INTEGRATION_NOTES.md](docs/INTEGRATION_NOTES.md#keys)). A browser version of the same engine is available to invited evaluators and is hosted separately. Third-party material is listed in [NOTICE.md](NOTICE.md). To report a vulnerability, see [SECURITY.md](SECURITY.md).

## What a record proves

`sfr seal` runs the rules R1 to R7 on a PX4 ULog file and writes a signed record (`.sfr`) and a plain report (`.sfr.md`). `sfr verify` checks the record, and with `--ulog` checks it against the log. A record that verifies (`Integrity: VERIFIED`, which `sfr verify` prints only after checking the signature against a key or trust anchor you supplied) proves that this record, signed by this key, has not changed since it was sealed and, with `--ulog`, matches these log bytes and these rule results.

- **Only the record is signed.** The `.sfr` file is what the signature covers and what `sfr verify` checks. The `.sfr.md` report is a readable view generated from the record; it carries no signature of its own. `sfr verify` binds it to the record instead: it renders the report again from the verified record and requires the `.sfr.md` beside the record (or the one `--report` names) to match it byte for byte, so an edited report fails verification and the line that differs is named. The report is required: with no `.sfr.md` beside the record, and no `--report`, verification fails, so a forged report under another name is never mistaken for the record's; `--no-report` verifies the record alone, prints a notice, and says in the output that the report was not checked. A report on its own, never checked against its record, proves nothing. The Merkle root and the key fingerprint stand at the top of the report, under its title, to compare with the `merkle` and `key` lines `sfr verify` prints. Characters that hide or reorder text, such as the bidirectional controls (U+202E) and zero-width characters, are written out as `<U+202E>` in the report and in everything `sfr` prints, never acted on.
- **The seal proves no change since sealing, not accuracy before it.** A record that verifies has not changed since it was sealed, and with `--ulog` neither has the log. It does not prove that the data was genuine, that the log was accurate or honest when it was sealed, that the vehicle did what the log says, or that nothing changed the log between the flight and the seal.
- **Who signed needs the signer's public key.** The record names its signing key only by fingerprint. `sfr verify` checks the signature against the public key you give it with `--pubkey`, or against the key in the record's signer certificate when that certificate chains to a trust anchor you give it with `--trust-anchor`. Revocation is checked too: give a CRL for every issuer in the chain with `--crl` (repeat it; the order does not matter, and for each issuer the CRL with the highest CRL number is the one used). A missing CRL, or one past its `nextUpdate` by the verifier's clock, fails verification; `--no-crl-check` skips revocation, prints a warning, and says so in the output. It tells you who signed only if you got that key or anchor through a channel you trust. A key that arrives with the record proves nothing about who signed it. Given neither, `sfr verify` checks nothing: it prints `Integrity: NOT CHECKED (no trusted key given)` and exits 4. Every verify prints the key fingerprint and the custody the record declares, and says whether anything attests that custody. The custody is a word the sealer wrote into the record, so it prints as `custody   unattested (declared pkcs11-token)` unless the signer's certificate chains to a trust anchor you supplied, and then as `attested by certificate chain to the trust anchor ...`. An attestation is only as good as that anchor's practice: `sfr` cannot see whether the CA issued the certificate only for a key held in hardware, so supply an anchor whose issuing policy you trust for that. `--require-hardware-key` means attested by such a chain, not declared; with `--pubkey` it always refuses.
- **The seal time is a claim.** `seal time` is the sealing machine's clock, or the time given with `--seal-time`, and `sfr verify` labels it claimed. It is signed, so it cannot change after sealing, but nothing checks that it was right, so it decides nothing about a certificate. With `--trust-anchor`, `sfr verify` checks every certificate at the verifier's own clock, or at the time you give with `--at <RFC3339>`, and prints which time it used. A claimed seal time later than that time (by more than 5 minutes of clock skew) fails verification: a record cannot be sealed in the verifier's future.
- **An evaluation key is refused unless you allow it.** A record that declares custody `file-evaluation` (the quickstart's keys) does not verify as `Integrity: VERIFIED`: `sfr verify` prints `Integrity: REFUSED`, under the EVALUATION KEY banner, and exits 1, although its signature is good. `--allow-evaluation-key` accepts it for evaluation, and the banner stays. A key declared as hardware could still be a file: see custody above.
- **PX4 versions.** `sfr` is tested on logs from PX4 v1.14.4 and v1.17.0 (`testdata/sitl/`); v1.15 and v1.16 are decoded from the PX4 source's message definitions, but no log from them is in the tests. `seal` refuses a log from a version outside v1.14 to v1.17, or one whose version it cannot read, and writes nothing, unless given `--allow-untested-version`. With it, `seal` prints a warning, leaves the version-dependent names in the events empty, and records the flag in the signed record (`seal.allow_untested_version`), and the report says so. No such log is tested.

[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) gives the details and the attacks that are and are not detected.

## Quickstart

Two paths. **No release has been published yet, so today only Path 2 works.** Path 1 is for after the first release: it needs no build tools, downloads the release, checks it without trusting anyone, and runs a demo. Path 2 builds `sfr` from source.

### Path 1: download the release (after the first release)

> **After the first release.** No release exists yet: the download links below do not work until evaluation release 0.1.0 is published. Until then, use [Path 2](#path-2-build-from-source).

Once published, evaluation release 0.1.0 (tag `v0.1.0`) is a pre-release at [github.com/InquiroAIReseachLabs/Sealed_Flight_Recorder-/releases](https://github.com/InquiroAIReseachLabs/Sealed_Flight_Recorder-/releases). It holds a static `sfr` for Linux (`x86_64`, `aarch64` and `armv7`), one SBOM per target, `SHA256SUMS`, `SHA256SUMS.sig` and the release public key `sfr-release.pub`. You need `curl`, `tar`, `sha256sum` and OpenSSL 3. Every command below is run, in this order and in an empty directory, by the post-release check (`.github/workflows/post-release-check.yml`) on clean machines; the quickstart has no steps beyond these.

1. Download your target's tarball and the three files that check it. The two lines at the top choose the release and the target (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` or `armv7-unknown-linux-musleabihf`); the post-release check sets `SFR_VERSION` and `SFR_TARGET`, and you can edit the lines:

   ```sh doc-release
   VERSION="${SFR_VERSION:-0.1.0}"
   TARGET="${SFR_TARGET:-x86_64-unknown-linux-musl}"
   BASE="https://github.com/InquiroAIReseachLabs/Sealed_Flight_Recorder-/releases/download/v$VERSION"
   curl -fsSLO "$BASE/sfr-$VERSION-$TARGET.tar.gz"
   curl -fsSLO "$BASE/SHA256SUMS"
   curl -fsSLO "$BASE/SHA256SUMS.sig"
   curl -fsSLO "$BASE/sfr-release.pub"
   ```

2. Check the release key. The first command fails unless the key you downloaded is byte for byte the key committed in this repository at the release tag, a second channel that someone who can only edit release files cannot change. Then compare every hex digit of the printed fingerprint with the one in the Release files section below and in [docs/RELEASE.md](docs/RELEASE.md), and anywhere else you trust. The signature proves only that the holder of this key signed `SHA256SUMS`, so stop here if anything differs. The post-release check runs this step and compares its output with the committed key:

   ```sh doc-release
   curl -fsSL "https://raw.githubusercontent.com/InquiroAIReseachLabs/Sealed_Flight_Recorder-/v$VERSION/release/sfr-release.pub" | cmp - sfr-release.pub
   FINGERPRINT="$(openssl pkey -pubin -in sfr-release.pub -outform DER | sha256sum | cut -d' ' -f1)"
   echo "release key fingerprint sha256:$FINGERPRINT"
   ```

3. Verify the signature on `SHA256SUMS`, then your tarball against its line in it. The first command prints `Signature Verified Successfully`; the second prints the tarball's name and `OK`, and fails if `SHA256SUMS` has no line for your tarball or the line does not match. The `&&` stops the second command when the signature fails. The post-release check runs both:

   ```sh doc-release
   openssl pkeyutl -verify -pubin -inkey sfr-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig &&
     awk -v f="sfr-$VERSION-$TARGET.tar.gz" '$2 == f' SHA256SUMS | sha256sum --check --strict -
   ```

4. Recommended: check the build provenance attestation, which says which workflow (the release workflow of this repository) built this exact file from which tag. It is a second witness, independent of the key above. It needs the GitHub CLI (`gh`) logged in to GitHub. The post-release check runs it:

   ```sh doc-release
   gh attestation verify "sfr-$VERSION-$TARGET.tar.gz" --repo InquiroAIReseachLabs/Sealed_Flight_Recorder- \
     --signer-workflow InquiroAIReseachLabs/Sealed_Flight_Recorder-/.github/workflows/release.yml --source-ref "refs/tags/v$VERSION"
   ```

5. Unpack it, make an evaluation key, and seal the bundled sample log. The sample is `testdata/synthetic/custom_detection.ulg`, a synthetic log of 1,338 bytes, not a flight. A record is written to `out/`. The post-release check runs these commands:

   ```sh doc-release
   tar -xzf "sfr-$VERSION-$TARGET.tar.gz"
   cd "sfr-$VERSION-$TARGET"
   bin/sfr --version
   mkdir -p keys out
   bin/sfr keygen --evaluation-only --out keys > /dev/null
   bin/sfr seal examples/sample/sample.ulg --rules examples/rules.default.toml \
     --baseline examples/sample/sample.params --key keys/sfr.key --evaluation-only --out out | grep -E '^(status|record)'
   bin/sfr verify out/sample.sfr --pubkey keys/sfr.pub --allow-evaluation-key --ulog examples/sample/sample.ulg | grep -E '^(Integrity|Flight rules)'
   ```

6. Tamper, then verify. Change one parameter value in a copy of the record, and one byte of a copy of the log. Each verify exits 1 and says what no longer matches. The post-release check runs these commands and requires both exits to be 1:

   ```sh doc-release
   sed 's/"SYS_AUTOSTART":"i32:10040"/"SYS_AUTOSTART":"i32:10041"/' out/sample.sfr > out/changed.sfr
   rc=0; bin/sfr verify out/changed.sfr --pubkey keys/sfr.pub --allow-evaluation-key || rc=$?; echo "record changed: exit $rc"; test "$rc" = 1
   cp examples/sample/sample.ulg out/changed.ulg
   printf '\377' | dd of=out/changed.ulg bs=1 seek=600 conv=notrunc 2> /dev/null
   rc=0; bin/sfr verify out/sample.sfr --pubkey keys/sfr.pub --allow-evaluation-key --ulog out/changed.ulg || rc=$?; echo "log changed: exit $rc"; test "$rc" = 1
   ```

What the signature, the checksums and the attestation each prove, and what they do not, is in [docs/RELEASE.md](docs/RELEASE.md).

### Path 2: build from source

You need git, a C compiler and linker (`cc`; on Debian or Ubuntu, `build-essential`; on Windows, the Visual Studio C++ Build Tools that rustup asks for, and Git for Windows, whose Git Bash runs the commands below). The first build downloads the dependencies from crates.io; after that, `sfr` needs no network. CI builds and tests on Linux `x86_64`; other systems have not been tested here.

0. Install Rust with rustup, unless `rustup` is already installed. `rust-toolchain.toml` pins Rust 1.97.0 with the `rustfmt` and `clippy` components and no other target, and the first `cargo build` in the checkout installs exactly that. Not run in CI, which installs the pinned toolchain its own way:

   ```sh doc-syntax
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

   On Windows, download and run `rustup-init.exe` from [rustup.rs](https://rustup.rs) instead, then open a new Git Bash.

1. Get the source. `--depth 1` leaves out the history; most of the download is the golden test logs in `testdata/`. Not run in CI, which tests the checkout it already has:

   ```sh doc-syntax
   git clone --depth 1 https://github.com/InquiroAIReseachLabs/Sealed_Flight_Recorder-.git
   cd Sealed_Flight_Recorder-
   ```

2. Build. The binary is `target/release/sfr`:

   ```sh doc-test
   cargo build --release --locked
   ```

3. Verify a record sealed earlier, against its log. `examples/reports/` holds four records sealed from golden SITL logs, with the public key `examples/reports/sfr.pub`. `Integrity:` says whether the record and the log are unchanged since sealing; `Flight rules:` gives the rule results sealed in the record. They are separate: a record whose rules failed still verifies, and the exit code follows integrity only:

   ```sh doc-test
   target/release/sfr verify examples/reports/vtol_transition.sfr --pubkey examples/reports/sfr.pub \
     --allow-evaluation-key \
     --ulog testdata/sitl/v1.17.0/vtol_transition.ulg
   ```

   ```text doc-output
   EVALUATION KEY: not for operational use
   Integrity: VERIFIED (record and log)
   Flight rules: PASS
   record    examples/reports/vtol_transition.sfr
   report    examples/reports/vtol_transition.sfr.md matches the record
   trust     the public key given with --pubkey (trusted as far as its source is)
   custody   unattested (declared file-evaluation)
   key       sha256:42c677026b5cd80f2a74bdcd5957a90bdb81b4873a3194dca4f100f877b637be
   merkle    745c18ad35e1270ba418fb6d16624a946f431be5d65cc7b0ad1f3aebd6df5430 (34 leaves)
   crypto    blake3 1.8.7, ed25519-dalek 3.0.0, sha2 0.11.1 (crate versions)
   seal time 2026-10-18T15:00:00Z (claimed by the sealer, not proven)
   events    22
   ```

4. Change one field of a copy of that record, then verify the copy twice. First with the public key alone: verify can say only that the signed Merkle root no longer matches some leaf. Then with the log as well: verify reads the log again, finds the event that differs, and names the event, the field and both values. Each exits 1:

   ```sh doc-test
   mkdir -p try
   sed 's/"command":211,/"command":311,/' examples/reports/vtol_transition.sfr > try/changed.sfr
   rc=0
   target/release/sfr verify try/changed.sfr --pubkey examples/reports/sfr.pub --allow-evaluation-key || rc=$?
   echo "exit $rc"
   ```

   ```text doc-output
   EVALUATION KEY: not for operational use
   Integrity: FAILED: Merkle root mismatch: a leaf changed after sealing (recorded 745c18ad35e1270ba418fb6d16624a946f431be5d65cc7b0ad1f3aebd6df5430, computed 7c8b315562e5c20e420dd3ac1efc0ee03dd3776c68ba77f6bd2a05f9a5ba0392)
   Flight rules: UNKNOWN (the record failed its integrity check, so its rule results cannot be trusted)
   key       sha256:42c677026b5cd80f2a74bdcd5957a90bdb81b4873a3194dca4f100f877b637be (named by the record, not proven)
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
     also: Merkle root mismatch: a leaf changed after sealing (recorded 745c18ad35e1270ba418fb6d16624a946f431be5d65cc7b0ad1f3aebd6df5430, computed 7c8b315562e5c20e420dd3ac1efc0ee03dd3776c68ba77f6bd2a05f9a5ba0392)
   Flight rules: UNKNOWN (the record failed its integrity check, so its rule results cannot be trusted)
   key       sha256:42c677026b5cd80f2a74bdcd5957a90bdb81b4873a3194dca4f100f877b637be (named by the record, not proven)
   custody   unattested (declared file-evaluation)
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
   target/release/sfr verify try/out/vtol_transition.sfr --pubkey try/keys/sfr.pub --allow-evaluation-key \
     --ulog testdata/sitl/v1.17.0/vtol_transition.ulg | grep -E '^(EVALUATION|Integrity|Flight rules)'
   ```

   ```text doc-output
   EVALUATION KEY: not for operational use
   Integrity: VERIFIED (record and log)
   Flight rules: PASS
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
| 0 | every rule PASS or N/A; record written | `Integrity: VERIFIED`, whatever the `Flight rules:` line says |
| 1 | a rule FAIL; the record is still written | `Integrity: FAILED`: the record, or the log with `--ulog`, does not match, is over an input limit, or (with `--trust-anchor`) its certificate chain is refused; or `Integrity: REFUSED`: the signature is good but the record is signed with an evaluation key (no `--allow-evaluation-key`), or its custody is not what `--require-hardware-key` accepts |
| 2 | a required topic or field is missing (R1 FAIL); the record is still written | not used |
| 3 | the log, rules file or baseline is malformed, truncated, or over an input limit; nothing written | not used |
| 4 | a usage, key or file error; nothing written | a usage, key or file error, or no trust source given (`Integrity: NOT CHECKED`) |

`sfr keygen` and `sfr --version` exit 0 or 4.

## Documentation

| Page | What it covers |
|---|---|
| [docs/RULES.md](docs/RULES.md) | each rule, the log data it reads, the rules file and the baseline |
| [docs/RECORD_FORMAT.md](docs/RECORD_FORMAT.md) | the record, exactly, and how to verify one with `openssl` and `b3sum` |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | what a seal proves and what it does not |
| [docs/design/README.md](docs/design/README.md) | design notes for five things a record does not do yet: trusted time, a chain of records, sealing at the source, a second verifier, and access; none is built |
| [docs/INTEGRATION_NOTES.md](docs/INTEGRATION_NOTES.md) | the topics `sfr` reads, sealing after disarm, CI use, key handling |
| [docs/LIMITS.md](docs/LIMITS.md) | the input limits |
| [docs/CLAIMS_AUDIT.md](docs/CLAIMS_AUDIT.md) | the tests that re-check every claim in these pages from a fresh clone, and what they do not show |
| [docs/RELEASE.md](docs/RELEASE.md), [docs/BENCHMARK.md](docs/BENCHMARK.md) | how a release is made and benchmarked |
| [examples/reports/README.md](examples/reports/README.md) | the example records and reports |

CI runs every command on these pages that can run there and compares its output (`scripts/check_docs.py`).

## The record and its report

`sfr seal` writes the signed record `<name>.sfr` and, beside it, the report `<name>.sfr.md`: Markdown that GitHub and GitLab render, generated only from the record, with the `sfr verify` command that checks it. Only the record is signed: the report is a readable view of it. `sfr verify` checks the report beside the record against the one the record renders and fails on any difference, or when there is none; a report read without verifying its record is not evidence. To check one, verify its record with the signer's public key. `examples/reports/` holds the records and reports of four golden SITL flights (standard VTOL, GPS loss failsafe, quad tailsitter, and a multicopter with a sealed topic and an R7 failure), sealed with an evaluation key.

## Release files

After the first release, evaluation release 0.1.0 holds these files, for the version in `Cargo.toml`. None is published yet:

| File | Contents |
|---|---|
| `sfr-<version>-<target>.tar.gz` | the static `sfr` for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, or `armv7-unknown-linux-musleabihf`, this README, `examples/` (rules files, example records and reports, and a synthetic sample log with its baseline), and `BUILDINFO` |
| `sfr-<version>-<target>.cdx.json` | the CycloneDX SBOM of that `sfr`: its resolved dependency graph for the target from `Cargo.lock` (a superset of the crates it links; build-time crates marked `excluded`), with version, license, and SHA-256 |
| `SHA256SUMS` | the SHA-256 of every file above |
| `SHA256SUMS.sig` | the Ed25519 signature over `SHA256SUMS`, made offline with the release key |
| `sfr-release.pub` | the release public key, shown below |

Each tarball also has a GitHub build provenance attestation. No container image is published. The commands that check these files are steps 2 to 4 of the quickstart, and [docs/RELEASE.md](docs/RELEASE.md) says what each check proves.

<!-- BEGIN release-key: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
Release public key: not generated yet. The release key holder generates the release key on an offline machine with `scripts/release_sign.sh keygen <offline path>`, which writes its public half to `release/sfr-release.pub`; `scripts/regen_readme_numbers.sh` then shows it here, and both are committed before the first release.
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
