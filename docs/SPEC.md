## B1. SHARED SPEC (Chunk 0 writes this into `docs/SPEC.md` verbatim)

### B1.1 Product
- Name: **Sealed Flight Record**. Binary: `sfr`. Record file extension: `.sfr` (JSON). Report: `<name>.sfr.md` (Markdown).
- Purpose: after a PX4 flight, produce a signed, self-verifying record of the configuration that flew, the readiness rule results, and the operator, failsafe, and transition events, so anyone can later prove none of it was changed.
- Runs offline on Linux x86_64 and Linux aarch64 (Jetson-class companion computers). No network at runtime, ever.
- Contains no AI, no randomness in sealing, and no telemetry.

### B1.2 Workspace
- `crates/sfr-core`: the engine (ingest, events, rules, record, Merkle, signing, verify). No I/O beyond reading provided byte streams; no networking; `#![forbid(unsafe_code)]`.
- `crates/sfr`: the CLI. Thin wrapper over `sfr-core`.
- `crates/sfr-wasm`: browser build of `sfr-core` for the sandbox. Thin wrapper.
- `fuzz/`: cargo-fuzz targets.
- `site/`: static sandbox page (HTML, CSS, JS that loads `sfr-wasm`). No third-party scripts, no analytics, no CDN calls.
- `scripts/`: demo, benchmark, README-number regeneration, release.
- `testdata/`: golden logs with license notices, expected records.
- `docs/`: SPEC, THREAT_MODEL, RECORD_FORMAT, RULES, INTEGRATION_NOTES, DIAGNOSTIC (Chunk 1 output).
- Pinned toolchain (`rust-toolchain.toml`). All builds `--locked`.

### B1.3 Commands

| Command | Behavior |
|---|---|
| `sfr keygen --out <dir>` | Creates an Ed25519 key pair (`sfr.key`, `sfr.pub`). Private key file mode 0600. Refuses to overwrite existing files. Prints the public key fingerprint. |
| `sfr seal <flight.ulg> --rules <rules.toml> --baseline <baseline.params> --key <sfr.key> [--out <dir>] [--seal-time <RFC3339>] [--dry-run]` | Parses the log, extracts configuration and events, runs rules, builds the record, Merkle tree, and signature; writes `<name>.sfr` and `<name>.sfr.md`. `--dry-run` runs everything except signing and writing, and prints the results table. `--seal-time` fixes the seal timestamp for deterministic output. |
| `sfr verify <record.sfr> --pubkey <sfr.pub> [--ulog <flight.ulg>]` | **Standalone:** recomputes every leaf and the Merkle root from the record, checks the signature, and checks that the overall status matches the results. **Deep (with `--ulog`):** additionally re-hashes the log, re-parses it, replays the embedded rules and baseline, and requires byte-identical results, configuration, and events. On failure, names the first mismatch: leaf index and kind, event sequence number and field, parameter name with sealed and found values, or "log digest mismatch". |

Every command supports `--json` for machine-readable output.

### B1.4 Exit codes
| Code | Meaning |
|---|---|
| 0 | Seal: all rules PASS or N/A. Verify: VERIFIED. |
| 1 | Seal: one or more rules FAIL (record is still written). Verify: verification failed. |
| 2 | Required topic missing from the log (record written with status FAIL and the missing topic named). |
| 3 | Malformed or truncated input file. |
| 4 | Usage, key, or file I/O error. |

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

Top-level fields: `schema_version` (starts at `1`); `tool` (name, version, build commit); `seal` (time UTC, key fingerprint, key label); `log` (file name, size, sha256, blake3, firmware, vehicle type); `config` (firmware, sorted parameter map); `baseline` (firmware, parameter map, ignore list); `rules` (embedded rules text and its sha256); `results` (per rule: id, status, expected, found, detail); `events` (ordered list); `status` (PASS or FAIL); `merkle` (algorithm, leaf count, root); `signature` (algorithm `ed25519`, value).

**Leaves**, in this fixed order: log identity; config; baseline; rules; each result in rule-id order; each event in sequence order.

**Hashing:** leaf hash = SHA-256(0x00 || JCS(leaf)). Node hash = SHA-256(0x01 || left || right). Odd-node handling follows RFC 6962. **Signed payload** = ASCII `SFR-RECORD-V1` || 0x00 || schema_version as 4-byte big-endian || Merkle root. Ed25519 signature over the signed payload.

**Compatibility rule:** a verifier must reject a `schema_version` it does not know; it must never guess.

`docs/RECORD_FORMAT.md` documents the format exactly enough for an independent implementation, with copy-paste `openssl` and `b3sum` commands that verify the signature and the log digest without `sfr`.

### B1.8 Markdown report (`.sfr.md`)

Emitted by `seal`. Renders in GitHub and GitLab. Contents: overall status; a rules table; parameter differences; an event timeline table; log identity and digests; Merkle root, key fingerprint, and the exact `sfr verify` command. Generated only from the record, so it cannot say anything the record does not.

### B1.9 Threat model (`docs/THREAT_MODEL.md`, one page)

First paragraph, verbatim intent: *The signature binds the sealed record to the holder of the signing key at the moment of sealing. It proves the record and, with `--ulog`, the log have not changed since then. It does not prove the flight stack wrote a truthful log, that nothing happened to the log between disarm and sealing, or that the sealing machine was uncompromised.*

Then: sealing on the companion computer immediately after disarm (documented post-disarm hook example) shrinks the disarm-to-seal gap. A stolen key invalidates trust in every record signed with that fingerprint after the compromise; production deployments should bind keys to hardware (TPM or secure element), which is out of scope for v1. The record contains the full parameter set and is as sensitive as the log; handle it the same way.

### B1.10 Production-grade gates (all binary; all enforced in CI unless marked)

| Gate | Pass criterion |
|---|---|
| Static binaries | `ldd` reports "not a dynamic executable" for x86_64 and aarch64 musl builds |
| No network | Dependency tree contains no networking or async-runtime crates (CI check against a deny list); demo passes in `docker run --network=none` |
| No unsafe | `#![forbid(unsafe_code)]` in all Inquiro crates |
| Deterministic | Same inputs plus `--seal-time` and key produce byte-identical `.sfr` and `.sfr.md`, across x86_64, aarch64, and the WASM build |
| Replay | `verify --ulog` on every golden log reproduces sealed results byte-for-byte |
| Tamper property | At least 1,000 random single-byte flips in a `.sfr` and 1,000 in a `.ulg`: verification fails 100% of the time |
| Fuzzing | Fuzz targets for the ULog parser and the `.sfr` reader; 60 seconds per CI run and 10 minutes nightly with zero panics, hangs, or out-of-memory |
| Exit codes | An integration test triggers each of codes 0 to 4 |
| Errors | Every error names the file, and where relevant the topic, field, or parameter; no panics on any input |
| Performance | Benchmark script reports seal time for 10, 50, and 100 MB logs and standalone verify time; gates: 100 MB seal under 2 s on x86_64 and under 4 s on real aarch64 hardware (not emulation); standalone verify under 10 ms for records up to 10,000 events |
| Code quality | `rustfmt --check` clean; `clippy` with warnings as errors; all tests green |
| Supply chain | `cargo-deny` clean for licenses (no GPL, AGPL, or unknown) and advisories; CycloneDX SBOM per release |
| Crypto | Only `sha2`, `blake3`, and `ed25519-dalek` (or the Chunk 1 audited equivalent); no custom primitives; domain separation as specified |
| Releases | Each release ships `SHA256SUMS` plus an Ed25519 signature over it, and the public release key in the README |
| Reproducible claims | Every number in the README sits between markers and is written by `scripts/regen_readme_numbers.sh`; CI fails if the README drifts from the script output |
| Sandbox | Page makes zero network requests after load (verified in browser dev tools and an automated headless test); produces records byte-identical to the CLI for the same inputs |
| Docs | README quickstart a stranger completes in 15 minutes (founder-run test, not CI) |

### B1.11 Out of scope for v1
Onboard or in-flight sealing; C/C++ library or ROS2 node; MAVLink `.tlog` and ArduPilot DataFlash (the ingest layer sits behind a `FlightLogIngestor` trait so ArduPilot is a clean v2 addition); computer-vision events; HTML report; any server, upload, or fleet database; hardware key storage; quantum-resistant signatures; inclusion-proof export (format supports it; command is v2); reason-coded waivers; multi-flight trends; compliance mappings.

### B1.12 Language rules for all docs and README
- No target company, aircraft, or customer names.
- No internal Inquiro codenames.
- No compliance claims (no "DoDD 3000.09 compliant" or similar).
- No number that a script in the repo does not produce.
- Describe as "v1.0 evaluation release."
- No em-dashes.
