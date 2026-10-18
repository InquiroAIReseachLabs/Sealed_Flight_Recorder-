## B1. SHARED SPEC (Chunk 0 writes this into `docs/SPEC.md` verbatim)

### B1.1 Product
- Name: **Sealed Flight Record**. Binary: `sfr`. Record file extension: `.sfr` (JSON). Report: `<name>.sfr.md` (Markdown).
- Purpose: after a PX4 flight, produce a signed, self-verifying record of the configuration that flew, the readiness rule results, and the operator, failsafe, and transition events, so anyone can later prove none of it was changed.
- Runs offline on Linux x86_64 and Linux aarch64 (Jetson-class companion computers). No network at runtime, ever.
- Contains no AI, no randomness in sealing, and no telemetry.

### B1.2 Workspace
- `crates/sfr-core`: the engine (ingest, events, rules, record, Merkle, signing, verify). No I/O beyond reading provided byte streams; no networking; `#![forbid(unsafe_code)]`. Cryptography comes from one of two backends, chosen explicitly by type and never by default: `crypto-fips` (the AWS-LC FIPS module through aws-lc-rs, the only backend `sfr` links) and `crypto-portable` (`sha2` and `ed25519-dalek`, not validated, used only by `sfr-wasm`).
- `crates/sfr`: the CLI. Thin wrapper over `sfr-core`. Statically linked; never loads a shared library.
- `crates/sfr-wasm`: browser build of `sfr-core` for the sandbox. Thin wrapper. Evaluation only: its records name the portable, not validated backend in `seal.crypto_module`.
- `crates/sfr-pkcs11-helper`: signs one payload with an Ed25519 key held in a PKCS#11 v3.0 token or HSM (CKM_EDDSA). It runs as a separate process because a static musl binary cannot load a vendor module (`dlopen` fails with "Dynamic loading not supported"). It is the only dynamically linked artifact and is never needed for evaluation.
- `fuzz/`: cargo-fuzz targets.
- `site/`: static sandbox page (HTML, CSS, JS that loads `sfr-wasm`). No third-party scripts, no analytics, no CDN calls.
- `scripts/`: demo, benchmark, README-number regeneration, release.
- `testdata/`: golden logs with license notices, expected records.
- `docs/`: SPEC, THREAT_MODEL, RECORD_FORMAT, RULES, INTEGRATION_NOTES, DIAGNOSTIC (Chunk 1 output).
- Pinned toolchain (`rust-toolchain.toml`). All builds `--locked`.

### B1.3 Commands

| Command | Behavior |
|---|---|
| `sfr keygen --evaluation-only --out <dir>` | Creates an evaluation Ed25519 key pair (`sfr.key`, `sfr.pub`) from the FIPS module's DRBG. Private key file mode 0600. Refuses to overwrite existing files. Prints the public key fingerprint and EVALUATION KEY. Without `--evaluation-only` it exits 4 and names the hardware key options. |
| `sfr keygen --tpm-sealed --out <dir> [--tpm-parent <handle>] [--tpm-pcrs <bank:list>]` | Generates the Ed25519 seed in the FIPS module and seals it to this machine's TPM 2.0 through tpm2-tools (object attributes `fixedtpm\|fixedparent`, optional PCR policy; parent defaults to the persistent storage key `0x81000001`). Writes `sfr.tpm.pub` and `sfr.tpm.priv` (sealed blobs that no other TPM can load) and `sfr.pub`. The seed never touches disk. PKCS#11 keys are generated inside the token with the token's own tools (CKM_EC_EDWARDS_KEY_PAIR_GEN, CKA_SENSITIVE true, CKA_EXTRACTABLE false); `docs/INTEGRATION_NOTES.md` gives the commands. |
| `sfr seal <flight.ulg> --rules <rules.toml> --baseline <baseline.params> <key source> [--cert <signer.pem>] [--chain <intermediates.pem>] [--out <dir>] [--seal-time <RFC3339>] [--dry-run]` | Parses the log, extracts configuration and events, runs rules, builds the record, Merkle tree, and signature; writes `<name>.sfr` and `<name>.sfr.md`. The key source is exactly one of: `--key-uri 'pkcs11:<RFC 7512 path>?module-path=<module.so>&pin-source=<file:PATH\|env:VAR>'` (custody `pkcs11-token`: the signature is made inside the token by `sfr-pkcs11-helper`; `pin-value` is refused); `--key-uri tpm-sealed:<dir>` (custody `tpm-sealed`: the seed is unsealed into memory for one signature, then zeroized); `--key <sfr.key> --evaluation-only` (custody `file-evaluation`). `--cert` embeds the signer's X.509 certificate (RFC 8410 Ed25519 key), which must hold the signing key; `--chain` embeds intermediates. Before writing anything, `seal` verifies the signature with the FIPS module against the signing public key; a mismatch writes nothing and exits 4. `--dry-run` runs everything except signing and writing, and prints the results table. `--seal-time` fixes the seal timestamp for deterministic output. |
| `sfr verify <record.sfr> (--pubkey <sfr.pub> \| --trust-anchor <ca.pem> [--crl <crl.der>]...) [--ulog <flight.ulg>] [--require-hardware-key]` | **Trust:** with `--pubkey`, the record must be signed by that key. With `--trust-anchor`, the embedded signer certificate must chain to the anchor offline, carry extended key usage code signing, be valid at the sealed time, not be revoked by any supplied CRL, and verify the record signature with its own key. `--require-hardware-key` fails a record whose custody is `file-evaluation`. The output names the custody and the crypto module, and a `file-evaluation` record prints EVALUATION KEY first. **Standalone:** recomputes every leaf and the Merkle root from the record, checks the signature, and checks that the overall status matches the results. **Deep (with `--ulog`):** additionally re-hashes the log, re-parses it, replays the embedded rules and baseline, and requires byte-identical results, configuration, and events. On failure, names the first mismatch: leaf index and kind, event sequence number and field, parameter name with sealed and found values, or "log digest mismatch". |

Every command supports `--json` for machine-readable output.

### B1.4 Exit codes
| Code | Meaning |
|---|---|
| 0 | Seal: all rules PASS or N/A. Verify: VERIFIED. |
| 1 | Seal: one or more rules FAIL (record is still written). Verify: verification failed. |
| 2 | Required topic missing from the log (record written with status FAIL and the missing topic named). |
| 3 | Malformed or truncated input file. |
| 4 | Usage, key, or file I/O error, including a missing `--evaluation-only`, a hardware key source that fails, a signature that does not verify against the signing key, and a FIPS module that reports it is not in approved mode. |

If the FIPS module fails a power-on self-test or its integrity check, the module aborts the process before `sfr` can choose an exit code (SIGABRT; a shell reports 134). Nothing is written.

### B1.5 What is extracted from the log

Supported: PX4 v1.14 through v1.17 ULog. Exact topic and field names per version come from `docs/DIAGNOSTIC.md` (Chunk 1), never from memory.

- **Log identity:** SHA-256 and BLAKE3 of the raw file bytes; file size; firmware version and git hash from the ULog header; vehicle type.
- **Configuration:** the full parameter set at log start as a sorted key-to-value map; firmware version.
- **Events (the timeline), each with a sequence number, boot-time microseconds, and UTC microseconds when GPS time is available:**
  - ARM, DISARM (from vehicle status)
  - NAV_STATE_CHANGE (old, new)
  - FAILSAFE_SET, FAILSAFE_CLEAR (flag name; from `failsafe_flags`)
  - COMMAND (command id, source system and component, result from the matching `vehicle_command_ack`, or `NO_ACK`)
  - VTOL_TRANSITION_START, VTOL_TRANSITION_END, VTOL_TRANSITION_ABORT (direction)
  - PARAM_CHANGED_IN_FLIGHT (name, old, new)
  - LOG_MESSAGE (flight stack messages at warning level or above)
  - LOG_DROPOUT (duration)
- **Event ordering** is deterministic: boot time, then topic name, then instance id, then message index.
- **Multi-instance topics** are filtered to the active instance where PX4 records one (used by optional estimator rules only).

### B1.6 Rules

Rules file format: TOML (Rust TOML tooling is actively maintained; the common Rust YAML crate is not). The rules file and baseline are embedded in the record so deep verify needs only the log.

**Core rules, on by default:**
| Id | Rule | PASS / FAIL / N/A |
|---|---|---|
| R1 | Required topics present | FAIL names each missing topic; exit 2 |
| R2 | Firmware matches baseline | FAIL shows expected and found |
| R3 | Parameters match baseline, excluding the ignore list | FAIL lists every differing parameter with baseline and flown values |
| R4 | No failsafe raised during flight | FAIL lists each flag and time |
| R5 | Arm and disarm consistency: every ARM has a DISARM, log does not end armed | FAIL names the unmatched event |
| R6 | VTOL transitions completed: every start has an end, none aborted | N/A if the vehicle is not VTOL |

**Optional example rules** (shipped in `examples/rules.extended.toml`, off by default, thresholds labeled "set by your flight-test lead"): minimum battery, GPS fix at arm, estimator fault flags, accelerometer clipping and vibration, total dropout time.

**Volatile parameter ignore list:** configurable in the rules file. Default list is confirmed against real logs in Chunk 1; candidates are flight-time accumulators and per-flight identifiers.

No rule threshold is presented as correct for any aircraft.

### B1.7 Record format (`.sfr`)

JSON, canonicalized with RFC 8785 (JSON Canonicalization Scheme) wherever bytes are hashed.

Top-level fields: `schema_version` (starts at `1`); `tool` (name, version, build commit); `seal` (time UTC, key fingerprint, key label, key custody, crypto module, signer certificate and chain or null); `log` (file name, size, sha256, blake3, firmware, vehicle type); `config` (firmware, sorted parameter map); `baseline` (firmware, parameter map, ignore list); `rules` (embedded rules text and its sha256); `results` (per rule: id, status, expected, found, detail); `events` (ordered list); `status` (PASS or FAIL); `merkle` (algorithm, leaf count, root); `signature` (algorithm `ed25519`, value).

**Leaves**, in this fixed order: seal context (`schema_version`, `tool`, `seal` without the signature); log identity; config; baseline; rules; each result in rule-id order; each event in sequence order.

**Key custody** is one of `pkcs11-token` (the private key never leaves a PKCS#11 token or HSM), `tpm-sealed` (the seed is sealed to one TPM 2.0 at rest and is in process memory for one signature), or `file-evaluation` (a key file; evaluation only). Custody is signed but declared by the sealer; only the certificate chain proves it (B1.9).

**Hashing:** leaf hash = SHA-256(0x00 || JCS(leaf)). Node hash = SHA-256(0x01 || left || right). Odd-node handling follows RFC 6962. **Signed payload** = ASCII `SFR-RECORD-V1` || 0x00 || schema_version as 4-byte big-endian || Merkle root. Ed25519 signature over the signed payload.

**Compatibility rule:** a verifier must reject a `schema_version` it does not know; it must never guess.

`docs/RECORD_FORMAT.md` documents the format exactly enough for an independent implementation, with copy-paste `openssl` and `b3sum` commands that verify the signature and the log digest without `sfr`.

### B1.8 Markdown report (`.sfr.md`)

Emitted by `seal`. Renders in GitHub and GitLab. Contents: overall status; a rules table; parameter differences; an event timeline table; log identity and digests; Merkle root, key fingerprint, key custody, crypto module, and the exact `sfr verify` command. A record sealed with a `file-evaluation` key starts with the line `EVALUATION KEY: not for operational use`. Generated only from the record, so it cannot say anything the record does not.

### B1.9 Threat model (`docs/THREAT_MODEL.md`, one page)

First paragraph, verbatim intent: *The signature binds the sealed record to the holder of the signing key at the moment of sealing. It proves the record and, with `--ulog`, the log have not changed since then. It does not prove the flight stack wrote a truthful log, that nothing happened to the log between disarm and sealing, or that the sealing machine was uncompromised.*

Then: sealing on the companion computer immediately after disarm (documented post-disarm hook example) shrinks the disarm-to-seal gap. A stolen key invalidates trust in every record signed with that fingerprint after the compromise. Operational seals use a key that never leaves a PKCS#11 token or HSM (`pkcs11-token`), or an Ed25519 seed sealed to the companion computer's TPM 2.0 (`tpm-sealed`: no other TPM can load it, and it is in `sfr`'s memory for one signature). File keys are evaluation-only, and every record and report sealed with one says so. Custody is signed but declared by the sealer; it is proven only by the signer certificate chain to the operator's trust anchor, whose CA must issue certificates only to keys it has seen held in hardware. Revocation is checked against CRL files given to `verify`; there is no online revocation check, by design. The record contains the full parameter set and is as sensitive as the log; handle it the same way.

### B1.10 Production-grade gates (all binary; all enforced in CI unless marked)

| Gate | Pass criterion |
|---|---|
| Static binaries | For the x86_64 and aarch64 musl builds of `sfr`, `readelf -lW` shows no INTERP program header and `readelf -dW` shows no NEEDED entry (static-pie is allowed on x86_64; `ldd` is not used because it misreports static-pie and foreign-architecture binaries). Release builds use GCC musl toolchains; zig is not used for the FIPS module. `sfr-pkcs11-helper` is exempt and is the only dynamically linked artifact |
| No network | Dependency tree contains no networking or async-runtime crates (CI check against a deny list); demo passes in `docker run --network=none`. Hardware signing uses child processes over pipes (`sfr-pkcs11-helper`, `tpm2_load`, `tpm2_unseal`), never sockets; a network-attached HSM's own PKCS#11 module may reach its HSM, and that traffic belongs to the operator's HSM deployment, not to `sfr` |
| No unsafe | `#![forbid(unsafe_code)]` in all Inquiro crates |
| Deterministic | Same inputs plus `--seal-time` and key produce byte-identical `.sfr` and `.sfr.md`, across x86_64, aarch64, and the WASM build |
| Replay | `verify --ulog` on every golden log reproduces sealed results byte-for-byte |
| Tamper property | At least 1,000 random single-byte flips in a `.sfr` and 1,000 in a `.ulg`: verification fails 100% of the time |
| Fuzzing | Fuzz targets for the ULog parser and the `.sfr` reader; 60 seconds per CI run and 10 minutes nightly with zero panics, hangs, or out-of-memory |
| Exit codes | An integration test triggers each of codes 0 to 4 |
| Errors | Every error names the file, and where relevant the topic, field, or parameter; no panics on any input |
| Performance | Benchmark script reports seal time for 10, 50, and 100 MB logs and standalone verify time; gates: 100 MB seal under 2 s on x86_64 and under 4 s on real aarch64 hardware (not emulation); standalone verify under 10 ms for records up to 10,000 events |
| Code quality | `rustfmt --check` clean; `clippy` with warnings as errors; all tests green |
| Supply chain | `cargo-deny` clean for licenses (no GPL, AGPL, or unknown) and advisories; CycloneDX SBOM per release. The allow list includes `OpenSSL` because the AWS-LC module carries it (`ISC AND (Apache-2.0 OR ISC) AND OpenSSL`) |
| Crypto | In `sfr`, SHA-256 (record, Merkle tree, log digest), Ed25519 key generation, signing and verification, and certificate signature checks come only from the AWS-LC FIPS module through aws-lc-rs (`fips` feature; EdDSA per FIPS 186-5, SHA-256 per FIPS 180-4). Two build profiles: **development** links the module source that aws-lc-fips-sys vendors, pinned in `Cargo.lock` (approved mode and self-tests, no certificate claim); **validated** links AWS-LC FIPS 3.1.0 built from the source archive and steps in the security policy of the static-module certificate recorded in `docs/DIAGNOSTIC.md` item 11, through aws-lc-fips-sys system-library mode. Only a validated-profile build may name a certificate. `seal.crypto_module` records the profile, the module version string, and the certificate number or `none`. `sfr` runs the module's FIPS-mode check before any other work. BLAKE3 (`blake3`) is a supplementary, non-approved digest of the raw log bytes and never anchors trust. `cargo tree -p sfr` contains neither `sha2` nor `ed25519-dalek`. The wasm32 sandbox uses `crypto-portable`; CI proves both backends produce byte-identical digests and signatures on RFC 8032 and generated vectors. No custom primitives; domain separation as specified |
| Key custody | `seal` exits 4 unless given a hardware key source or `--evaluation-only`; every record sealed with a file key has custody `file-evaluation` and its report's first line says EVALUATION KEY; `seal` verifies every signature with the FIPS module before writing. CI exercises `pkcs11-token` against SoftHSM v2 (CKM_EDDSA) and `tpm-sealed` against swtpm |
| Certificates | `verify --trust-anchor` accepts an Ed25519 signer certificate only if it chains to the anchor offline, carries extended key usage code signing, is valid at the sealed time, is not revoked by a supplied CRL, and verifies the record signature with its own key; CI covers each rejection with generated test certificates |
| Releases | Each release ships `SHA256SUMS` plus an Ed25519 signature over it, and the public release key in the README. Each release names its crypto build profile; a validated-profile release also ships the module build log showing the archive sha256 and `bssl isfips` printing 1 |
| Reproducible claims | Every number in the README sits between markers and is written by `scripts/regen_readme_numbers.sh`; CI fails if the README drifts from the script output |
| Sandbox | Page makes zero network requests after load (verified in browser dev tools and an automated headless test); produces records byte-identical to the CLI for the same inputs |
| Docs | README quickstart a stranger completes in 15 minutes (founder-run test, not CI) |

### B1.11 Out of scope for v1
Onboard or in-flight sealing; C/C++ library or ROS2 node; MAVLink `.tlog` and ArduPilot DataFlash (the ingest layer sits behind a `FlightLogIngestor` trait so ArduPilot is a clean v2 addition); computer-vision events; HTML report; any server, upload, or fleet database; hardware key attestation (PIV attestation, TPM2_Certify); online revocation (OCSP); quantum-resistant signatures; inclusion-proof export (format supports it; command is v2); reason-coded waivers; multi-flight trends; compliance mappings.

### B1.12 Language rules for all docs and README
- No target company, aircraft, or customer names.
- No internal Inquiro codenames.
- No compliance claims (no "DoDD 3000.09 compliant" or similar).
- No number that a script in the repo does not produce.
- Describe as "v1.0 evaluation release."
- Say "uses a FIPS 140-3 validated cryptographic module" only together with the module name, version, and CMVP certificate number. Never "FIPS compliant", "FIPS certified product", or an IL4, IL5, or NIST SP 800-171 status: those describe a whole system and its operation, not this binary.
- No em-dashes.
