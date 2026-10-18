## B1. SHARED SPEC (Chunk 0 writes this into `docs/SPEC.md` verbatim)

### B1.1 Product
- Name: **Sealed Flight Record**. Binary: `sfr`. Record file extension: `.sfr` (JSON). Report: `<name>.sfr.md` (Markdown).
- Purpose: after a PX4 flight, produce a signed, self-verifying record of the configuration that flew, the readiness rule results, and the operator, failsafe, and transition events, so anyone can later prove none of it was changed.
- Runs offline on Linux x86_64, aarch64, and 32-bit ARMv7 (hard-float). No network at runtime, ever.
- Contains no AI, no randomness in sealing, and no telemetry.

### B1.2 Workspace
- `crates/sfr-core`: the engine (ingest, events, rules, record, Merkle, signing, verify). No I/O beyond reading provided byte streams; no networking; `#![forbid(unsafe_code)]`. Cryptography comes from one backend on every target: `sha2`, `ed25519-dalek`, and `blake3` (B1.10 Crypto).
- `crates/sfr`: the CLI. Thin wrapper over `sfr-core`. Statically linked; never loads a shared library.
- `crates/sfr-wasm`: browser build of `sfr-core` for the sandbox. Thin wrapper. Evaluation only. It uses the same crypto crates as `sfr`, so its records match the CLI's byte for byte.
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
| `sfr keygen --evaluation-only --out <dir>` | Creates an evaluation Ed25519 key pair (`sfr.key`, `sfr.pub`) from a 32-byte seed from the operating system's CSPRNG. Private key file mode 0600. Refuses to overwrite existing files. Prints the public key fingerprint and EVALUATION KEY. Without `--evaluation-only` it exits 4 and names the hardware key options. |
| `sfr keygen --tpm-sealed --out <dir> [--tpm-parent <handle>] [--tpm-pcrs <bank:list>]` | Generates the Ed25519 seed from the operating system's CSPRNG and seals it to this machine's TPM 2.0 through tpm2-tools (object attributes `fixedtpm\|fixedparent`, optional PCR policy; parent defaults to the persistent storage key `0x81000001`). Writes `sfr.tpm.pub` and `sfr.tpm.priv` (sealed blobs that no other TPM can load) and `sfr.pub`. The seed never touches disk. PKCS#11 keys are generated inside the token with the token's own tools (CKM_EC_EDWARDS_KEY_PAIR_GEN, CKA_SENSITIVE true, CKA_EXTRACTABLE false); `docs/INTEGRATION_NOTES.md` gives the commands. |
| `sfr seal <flight.ulg> --rules <rules.toml> --baseline <baseline.params> <key source> [--cert <signer.pem>] [--chain <intermediates.pem>] [--out <dir>] [--seal-time <RFC3339>] [--dry-run]` | Parses the log, extracts configuration and events, runs rules, builds the record, Merkle tree, and signature; writes `<name>.sfr` and `<name>.sfr.md`. The key source is exactly one of: `--key-uri 'pkcs11:<RFC 7512 path>?module-path=<module.so>&pin-source=<file:PATH\|env:VAR>'` (custody `pkcs11-token`: the signature is made inside the token by `sfr-pkcs11-helper`; `pin-value` is refused; requires `--token-cert <CMVP certificate number>`, see the hardware token caveat below); `--key-uri tpm-sealed:<dir>` (custody `tpm-sealed`: the seed is unsealed into memory for one signature, then zeroized); `--key <sfr.key> --evaluation-only` (custody `file-evaluation`; evaluation only, never for operational records). `--cert` embeds the signer's X.509 certificate (RFC 8410 Ed25519 key), which must hold the signing key; `--chain` embeds intermediates. Before writing anything, `seal` verifies the signature against the signing public key; a mismatch writes nothing and exits 4. `--dry-run` runs everything except signing and writing, and prints the results table. `--seal-time` fixes the seal timestamp for deterministic output. |
| `sfr verify <record.sfr> (--pubkey <sfr.pub> \| --trust-anchor <ca.pem> [--crl <crl.der>]...) [--ulog <flight.ulg>] [--require-hardware-key]` | **Trust:** with `--pubkey`, the record must be signed by that key. With `--trust-anchor`, the embedded signer certificate must chain to the anchor offline, carry extended key usage code signing, be valid at the sealed time, not be revoked by any supplied CRL, and verify the record signature with its own key. `--require-hardware-key` fails a record whose custody is `file-evaluation`. The output names the custody and the crypto module, and a `file-evaluation` record prints EVALUATION KEY first. **Standalone:** recomputes every leaf and the Merkle root from the record, checks the signature, and checks that the overall status matches the results. **Deep (with `--ulog`):** additionally re-hashes the log, re-parses it, replays the embedded rules and baseline, and requires byte-identical results, configuration, and events. On failure, names the first mismatch: leaf index and kind, event sequence number and field, parameter name with sealed and found values, or "log digest mismatch". |

Every command supports `--json` for machine-readable output. `sfr --version` prints the tool version and the crypto crates with their crate versions. No command output claims that `sfr` itself holds any compliance status (B1.12).

**Hardware token caveat.** A PKCS#11 token or HSM is in scope for v1 only if its own CMVP certificate lists EdDSA with Ed25519 (FIPS 186-5) as an approved service. The operator's flight-test lead verifies this against the token's certificate before first use and passes that certificate number as `--token-cert`, which `seal` records in the signed seal leaf; `seal` refuses a `pkcs11:` key without it (exit 4). A token whose certificate does not list Ed25519, including any token that offers Ed25519 only as a non-approved service, is out of scope for v1. In `tpm-sealed` the TPM performs no Ed25519 operation (no shipping TPM implements EdDSA); it protects the seed at rest, and the signature is made in `sfr`.

### B1.4 Exit codes
| Code | Meaning |
|---|---|
| 0 | Seal: all rules PASS or N/A. Verify: VERIFIED. |
| 1 | Seal: one or more rules FAIL (record is still written). Verify: verification failed. |
| 2 | Required topic missing from the log (record written with status FAIL and the missing topic named). |
| 3 | Malformed or truncated input file (log, rules, or baseline), including a log with no data records and an input over a limit (Input limits below); the message names the file and the byte offset or line, except as Input limits below says. |
| 4 | Usage, key, or file I/O error, including a key file or public key over its limit, a missing `--evaluation-only`, a hardware key source that fails, a signature that does not verify against the signing key, and a rules file that lists more than 64 sealed topics. |

#### Input limits

Every input except the log's total size is bounded by the limits below, and an input over a limit is refused, never truncated. A message for a count or a size reads `... exceeds the input limit of N <unit> (SPEC B1.4)`; a message for a name, version, or length rule ends with a parenthesis that states the rule and cites SPEC B1.4. `seal` names the byte offset (log) or line (rules file, baseline) where it met the limit, except for exactly these, which name the file only: three counts (parameters at log start, `failsafe_flags` flag fields, events), the file sizes, and TOML dotted-key depth. `seal` exits 3 for the log, the rules file, and the baseline, including a log whose record would be over the record limit (`seal --dry-run` writes no record and does not apply that limit), and 4 for the key file. `verify` exits 4 for the public key and reports any limit in the record or in the `--ulog` log as its first mismatch (exit 1). `docs/LIMITS.md` gives the reason for each limit.

| Input | Limit |
|---|---|
| Log: ULog file format version | 0 or 1 |
| Log: format nesting | 8 levels of nested types below a subscribed format |
| Log: one flattened format | 65,535 bytes and 65,535 fields; array length 1 to 65,535 |
| Log: field definitions across all formats | 1,000,000 (a format with no fields counts as one) |
| Log: format name, field name, field type name | 255 bytes |
| Log: subscriptions | 4,096 |
| Log: flattened fields across all subscriptions | 1,000,000, counted per subscription |
| Log: flattened field names, summed once per distinct subscribed format | 16 MiB (16,777,216 bytes) |
| Log: flattened field name (with its nested prefixes and `[i]` index), subscription name | 255 bytes |
| Log: parameter name | 1 to 16 letters, digits, `_` |
| Log: parameters at log start | 65,536 |
| Log: `failsafe_flags` flag fields | 256 |
| Log: events (B1.5) | 100,000 |
| Rules file, baseline, key file, public key | 16 MiB (16,777,216 bytes) each |
| Rules: `required_topics.topics`, `parameters.ignore`, `watched_parameters.names`, `payload_commands.ids`, `authorized_sources.sources` | 256 entries each |
| Rules: `sealed_topics.topics` | 64 entries; more is a usage error (exit 4) |
| Rules: watched parameter name | 1 to 64 letters, digits, `_` |
| Rules: payload command id; source system id; source component id | 0 to 4,294,967,295; 0 to 255; 0 to 65,535 (`vehicle_command.source_component` is 16 bits in PX4 v1.17) |
| Rules: topic name | 1 to 64 lowercase letters, digits, `_` |
| Rules: parameter name pattern | 1 to 64 letters, digits, `_`, `*`, with at most 8 `*` |
| Rules: TOML nesting and dotted keys | 80 levels (the limit of the `toml` parser) |
| Baseline: parameters | 65,536 |
| Record (`seal` output, `verify` input) | 512 MiB (536,870,912 bytes); JSON with at most 64 nested arrays and objects |

The log has no size limit. It is read once, as a stream. The reader keeps format definitions, subscriptions, one flattened layout per distinct subscribed format (shared by its subscriptions), and the parameters at log start, each bounded by the limits above, and the data records the events and rules use (for example `vehicle_status`, `failsafe_flags`, commands and acks, warning messages, and data-section parameter records); it hashes and drops every other record. The number of kept data records has no limit, so memory grows with them: a log made mostly of them needs memory in proportion to its size. The detail cap limits output, not input: R4, R5, R6, X2, and X3 list at most 1,000 `detail` lines, then one line `and N more; ...` that says where the rest are counted (the events, or for X3 its sample count). R3 lists every differing parameter (B1.6), so at most the two parameter limits together.

### B1.5 What is extracted from the log

Supported: PX4 v1.14 through v1.17 ULog. Exact topic and field names per version come from `docs/DIAGNOSTIC.md` (Chunk 1), never from memory.

- **Log identity:** SHA-256 and BLAKE3 of the raw file bytes; file size; firmware version and git hash from the ULog info messages `ver_sw_release` and `ver_sw`; vehicle type from `vehicle_status.system_type` and `is_vtol`.
- **`vtol_type`** (in the log identity's vehicle): when the vehicle is VTOL (`vehicle_status.is_vtol` true on some sample, as for R4 and R6), parameter `VT_TYPE` from the parameters at log start, recorded as its raw integer and its PX4 name: `0` tailsitter, `1` tiltrotor, `2` standard (the same in PX4 v1.14 and v1.17; `docs/DIAGNOSTIC.md` item 12 cites the source). Any other value is `unknown(<n>)`, never guessed; a log without an int32 `VT_TYPE` records value null and name `unknown`. Null for a vehicle that is not VTOL. `vehicle_status.system_type` uses MAVLink's MAV_TYPE numbering and is not mapped through `VT_TYPE`.
- **Configuration:** the full parameter set at log start (the 'P' records before the first subscription) as a sorted key-to-value map, each value typed int32 or float32; firmware version.
- **Events (the timeline), each with a sequence number, boot-time microseconds, UTC microseconds when GPS time is available, and its source (topic, instance, message index):** UTC comes only from the first GPS sample (`vehicle_gps_position`, else `sensor_gps` instance 0) with `fix_type` of at least 2 and a nonzero `time_utc_usec`, never from `boot_time_utc_us` or a host clock.
  - ARM, DISARM: edges of `vehicle_status.arming_state == 2`, with the reason decoded from PX4's events enum. A log that starts armed reports ARM at its first sample, marked `initial`.
  - NAV_STATE_CHANGE (old, new): edges of `vehicle_status.nav_state`, with per-version names; the first sample is reported with `old` null.
  - FAILSAFE_SET, FAILSAFE_CLEAR (flag name; from `failsafe_flags`): edges of `vehicle_status.failsafe`. Each edge names the `failsafe_flags` booleans (and `battery_warning` above 0) that are true at that moment and are either required by the current `nav_state` (the flag's `mode_req_*` bit is set) or were not true at the most recent ARM (the latest `failsafe_flags` sample at or before that ARM; when there is none, or no ARM precedes the edge, the sample with the earliest timestamp); one event per named flag, or one event with flag `unattributed`. A log that starts in failsafe reports FAILSAFE_SET at its first sample, marked `initial`.
  - COMMAND (command id, category, source system and component, result from the matching `vehicle_command_ack`, or `NO_ACK`): the category is `PAYLOAD` when the command id is in the rules file's `[payload_commands]` list, otherwise `GENERAL`. Every COMMAND event records its source system and component. the matching ack is the earliest unused ack with the same command id, a timestamp not before the command's and before the next identical command from the same source, and target system and component equal to the command's source; a final result is preferred over IN_PROGRESS.
  - VTOL_TRANSITION_START, VTOL_TRANSITION_END, VTOL_TRANSITION_ABORT (direction): from the VTOL state derived from `vehicle_status` (in transition to fixed wing, in transition to multicopter, fixed wing, multicopter). START when a transition state is entered; END on transition-to-fixed-wing then fixed wing, or transition-to-multicopter then multicopter; ABORT when a transition state is left any other way. A quadchute (fixed wing straight to multicopter) is not a transition; R4 reports it.
  - QUADCHUTE (`vtol_fixed_wing_system_failure` true, false, or null when not logged): the VTOL state goes from fixed wing straight to multicopter without a transition state; the flag is the `failsafe_flags` value at that moment. R6 does not count it; R4 fails on it in flight (B1.6).
  - A `failsafe_flags` value "at that moment" (FAILSAFE_*, QUADCHUTE) comes from the latest `failsafe_flags` sample whose timestamp is at or before the `vehicle_status` sample's, in timestamp order whatever the file order, and among samples with that timestamp the one later in the file; with no such sample the flag is null, and a FAILSAFE edge is `unattributed`.
  - Edges (ARM, DISARM, NAV_STATE_CHANGE, FAILSAFE_*, VTOL_*, QUADCHUTE) compare consecutive `vehicle_status` samples in file order; the timeline then orders the events as below.
  - PARAM_CHANGED_IN_FLIGHT (name, old, new): a data-section 'P' record whose value differs from the last known value of that parameter, between ARM and DISARM (ARM time < its time <= DISARM time, so the timeline shows it after ARM and before DISARM); its time is the last data timestamp before it. Firmware-written changes count like any other.
  - LOG_MESSAGE (flight stack messages at warning level or above): 'L' and 'C' records at levels 0 to 4 (emergency to warning), text kept verbatim. PX4 events (the `event` topic) are not decoded in v1.
  - LOG_DROPOUT (duration): an 'O' record, in milliseconds; its time is the last data timestamp before it.
- **Sealed topic digests:** for each topic the rules file lists in `[sealed_topics]` and each instance (`multi_id`) the log subscribes, one entry: `topic`, `multi_id`; `format_sha256`, the SHA-256 of the payload of the 'F' record that defines the topic's format, exactly as stored (`<name>:<fields>`), the latest one before the instance's first subscription; `message_count`, its data records; `first_timestamp_us` and `last_timestamp_us`, the timestamp field of its first and last data record in file order (null with no data record); and `data_sha256`, the SHA-256 over its data records in file order, each contributing its payload length as an 8-byte little-endian integer followed by the payload bytes after the message id (the message id is per file and is not stable across logs). Computed while the log streams; no data record is kept. `docs/RECORD_FORMAT.md` gives the byte layout. A sealed topic needs no knowledge of its message structure; ULog is self-describing. The format digest covers the topic's own 'F' record only, not the 'F' records of the nested types it uses.
- **Event ordering** is deterministic: boot time, then topic name, then instance id, then message index. Records without a topic use the names `ulog.logging`, `ulog.parameter`, and `ulog.dropout`. Several events from one source message keep this order: ARM or DISARM; NAV_STATE_CHANGE; FAILSAFE_SET or FAILSAFE_CLEAR, one per flag, by flag name in byte order; VTOL_TRANSITION_END, VTOL_TRANSITION_ABORT, or QUADCHUTE; VTOL_TRANSITION_START. Sequence numbers start at 0. The message index counts from 0: for a topic, the data record's position among that topic instance's data records; for `ulog.parameter`, among all 'P' records in the file, definitions section included; for `ulog.logging`, among all 'L' and 'C' records; for `ulog.dropout`, among all 'O' records.
- **Multi-instance topics** are filtered to the active instance where PX4 records one (used by optional estimator rules only).

### B1.6 Rules

Rules file format: TOML (Rust TOML tooling is actively maintained; the common Rust YAML crate is not). The rules file and baseline are embedded in the record so deep verify needs only the log.

**Core rules, on by default:**
| Id | Rule | PASS / FAIL / N/A |
|---|---|---|
| R1 | Required topics present (the rules file lists them, every sealed topic is required too, and with `[authorized_sources]` so is `vehicle_command`), each with at least one data record, plus the `vehicle_status` and `failsafe_flags` fields the core rules read and, with `[authorized_sources]`, the `vehicle_command` fields R7 reads (`command`, `source_system`, `source_component`) | FAIL names each missing topic or `topic.field`; exit 2 |
| R2 | Firmware matches baseline | FAIL shows expected and found |
| R3 | Parameters match baseline, excluding the ignore list | FAIL lists every differing parameter with baseline and flown values |
| R4 | No failsafe raised during flight: `vehicle_status.failsafe` never true from ARM through the `vehicle_status` sample that disarms, and no quadchute (fixed wing straight to multicopter, B1.5) in that window. The quadchute check reads the VTOL state fields (`in_transition_mode`, `in_transition_to_fw`, `vehicle_type`) only when the vehicle is VTOL, that is when `vehicle_status.is_vtol` is true on some sample; an absent `vehicle_status`, or an absent `is_vtol` field, means not VTOL here, and R1 carries that failure | FAIL lists each flag and time, and each quadchute |
| R5 | Arm and disarm consistency: every ARM has a DISARM, log does not end armed | FAIL names the unmatched event |
| R6 | VTOL transitions completed: every start has an end, none aborted. On a VTOL vehicle the first detail line states the `vtol_type` (B1.5) | N/A if the vehicle is not VTOL |

**Optional rule R7, authorized command sources** (off by default; only the operator knows their own system and component ids, so `examples/rules.extended.toml` carries a commented example):
| Id | Rule | PASS / FAIL / N/A |
|---|---|---|
| R7 | Every COMMAND event came from a source listed in `[authorized_sources]`; with `category`, only commands of that category are checked | FAIL names each unauthorized event (sequence number, command, category, source system and component); FAIL when its input is missing: no `vehicle_command` data record, one of the three fields absent, or a `vehicle_command` sample whose three fields are not unsigned integers (a log with no commands is no evidence of authorized ones); PASS when commands are present and none in scope is unauthorized; N/A when the rules file has no `[authorized_sources]` |

**Optional rules file sections** (Change Order 01), each absent by default unless noted:
- `[watched_parameters] names = [...]`: parameter names shown apart for presentation. R3 compares them exactly like every other parameter, with no extra rule and no double counting; a watched name the ignore list matches is a rules file error. The record lists them in `config.watched_parameters`, and the results table and report show them in a "Transition tuning" section with the `vtol_type`, each with its baseline and flown values and MATCH or DIFF. `examples/rules.default.toml` watches ten VTOL transition parameters, each confirmed in PX4 v1.14 and v1.17 (`docs/DIAGNOSTIC.md` item 12).
- `[sealed_topics] topics = [...]`: uORB topic names, at most 64. Each is required (R1) and digested (B1.5).
- `[payload_commands] ids = [...]`: command ids whose COMMAND events are `PAYLOAD`. `examples/rules.default.toml` lists the actuator, servo, gripper, winch, payload deploy, camera trigger, and image capture commands, each id and name taken from PX4's `VehicleCommand.msg` for v1.14 and v1.17 (`docs/DIAGNOSTIC.md` item 12); flight termination and parachute commands are not in it.
- `[authorized_sources]`: `sources = [{ system = <id>, component = <id> }, ...]` and an optional `category = "PAYLOAD"` or `"GENERAL"`; enables R7.

**Optional example rules** (shipped in `examples/rules.extended.toml`, off by default, thresholds labeled "set by your flight-test lead"): minimum battery, GPS fix at arm, estimator fault flags, accelerometer clipping and vibration, total dropout time.

**Time windows.** Each rule and in-flight event reads the log over this window. "ARM" and "DISARM" are the boot times of the `vehicle_status` samples where `arming_state` becomes and stops being armed (B1.5); an interval still open at the end of the log runs to its end. Every armed interval counts.

| Rule or event | Window |
|---|---|
| R1 | the whole log |
| R2, R3 | none: the firmware identity and the parameters at log start (B1.5) |
| R4 | `vehicle_status` samples with ARM ≤ t ≤ DISARM: from the ARM sample through the sample that disarms; a quadchute is judged on the sample where the VTOL state becomes multicopter |
| R5, R6 | the whole log (every ARM, DISARM, and VTOL event) |
| R7 | the whole log (every COMMAND event) |
| X1 (battery), X3 (estimator faults), X4 (vibration and clipping) | samples of that topic with ARM ≤ t < DISARM; X4 compares consecutive samples only within one armed interval |
| X2 (GPS fix at arm) | at each ARM: the latest GPS sample with a timestamp at or before it |
| X5 (dropouts) | the whole log |
| PARAM_CHANGED_IN_FLIGHT (B1.5) | records with ARM < t ≤ DISARM, t being the last data timestamp before the record |

**Volatile parameter ignore list:** configurable in the rules file. Default list is confirmed against real logs in Chunk 1; candidates are flight-time accumulators and per-flight identifiers.

No rule threshold is presented as correct for any aircraft.

A rule whose input data is missing is FAIL, never N/A; N/A means only that the rule does not apply (R6 on a vehicle that is not VTOL). The rules file starts with `format = "sfr-rules/1"`, and unknown keys are rejected. A topic, pattern, parameter name, command id, or source listed twice in one list is a rules file error. The baseline file is a QGroundControl `.params` export (tab-separated vehicle id, component id, name, value, type 6 int32 or 9 float32) plus one line `# Firmware: <version> [<git hash prefix>]`; float values compare after rounding to float32, as numbers (-0 equals 0, and any NaN, written `nan`, equals any NaN).

### B1.7 Record format (`.sfr`)

JSON, canonicalized with RFC 8785 (JSON Canonicalization Scheme) wherever bytes are hashed. The record contains no JSON floating-point numbers: unsigned 64-bit measurements (timestamps, sizes) are decimal strings; counts, sequence numbers, message indexes, and enumerated values (nav state, command id, MAVLink ids) are JSON integers, each below 2^53 by construction (a log yields at most 100,000 events); and parameter values are typed strings (`i32:5`, `f32:0.15`, float32 written as its shortest round-trip decimal in plain positional notation, with the digits ECMAScript `Number::toString` would choose: fewest digits, then the closest, an exact tie to the even digit; `f32:NaN` for any NaN, `f32:Infinity` and `f32:-Infinity`). A `.sfr` file is stored as its canonical bytes, and verify rejects any file that differs from the canonical form of its own parse.

Top-level fields: `schema_version` (starts at `1`); `tool` (`name`, `version`, `build_commit`); `seal` (`time_utc` as `YYYY-MM-DDTHH:MM:SSZ`, `key_fingerprint`, `key_label`, `key_custody`, `token_cmvp_certificate` or null, `crypto_crates` (each crate's `name` and crate `version`, sorted by name), `signer_certificate` and `certificate_chain` or null); `log` (file name, size, sha256, blake3, firmware, vehicle type with `vtol_type`); `config` (firmware, sorted parameter map, `watched_parameters`); `baseline` (firmware, parameter map, ignore list); `rules` (embedded rules text and its sha256); `results` (per rule: id, status, expected, found, detail); `sealed_topics` (the sealed topic digests of B1.5, sorted by topic, then `multi_id`; empty without `[sealed_topics]`); `events` (ordered list); `status` (PASS or FAIL); `merkle` (algorithm, leaf count, root); `signature` (algorithm `ed25519`, value).

**Leaves**, in this fixed order: seal context (`schema_version`, `tool`, `seal` without the signature); log identity; config; baseline; rules; each result in rule-id order; each sealed topic digest in topic and `multi_id` order; each event in sequence order. Standalone verify checks each order; deep verify (`--ulog`) recomputes every digest and names a changed sealed topic by topic and instance.

**Key custody** is one of `pkcs11-token` (the private key never leaves a PKCS#11 token or HSM), `tpm-sealed` (the seed is sealed to one TPM 2.0 at rest and is in process memory for one signature), or `file-evaluation` (a key file; evaluation only). Custody is signed but declared by the sealer; only the certificate chain proves it (B1.9).

**Hashing:** leaf hash = SHA-256(0x00 || JCS(leaf)). Node hash = SHA-256(0x01 || left || right). Odd-node handling follows RFC 6962 (the left subtree holds the largest power of two below the leaf count; nothing is duplicated); `merkle.algorithm` is `sha256-rfc6962`, `merkle.root` and `signature.value` are lowercase hex. **Signed payload** = ASCII `SFR-RECORD-V1` || 0x00 || schema_version as 4-byte big-endian || Merkle root. Ed25519 signature over the signed payload.

**Keys:** `sfr.pub` is a PEM `PUBLIC KEY` (RFC 8410 SubjectPublicKeyInfo) and `sfr.key` a PEM `PRIVATE KEY` (PKCS#8 v1), the forms `openssl pkey` reads; `seal` also reads PKCS#8 v2 with the public key and no attributes, and refuses one whose public key does not match. The key fingerprint is `sha256:` and the lowercase hex SHA-256 of the SubjectPublicKeyInfo DER.

**Compatibility rule:** a verifier must reject a `schema_version` it does not know; it must never guess.

`docs/RECORD_FORMAT.md` documents the format exactly enough for an independent implementation, with copy-paste `openssl` and `b3sum` commands that verify the signature and the log digest without `sfr`.

### B1.8 Markdown report (`.sfr.md`)

Emitted by `seal`. Renders in GitHub and GitLab. Contents: overall status; a rules table; parameter differences; a "Transition tuning" section when the vehicle is VTOL (the `vtol_type` and each watched parameter with baseline and flown values, marked MATCH or DIFF); a sealed topics table (topic, instance, message count, time span, digest prefix); an event timeline table with a category column for COMMAND events; log identity and digests; Merkle root, key fingerprint, key custody, crypto crates, and the exact `sfr verify` command. A record sealed with a `file-evaluation` key starts with the line `EVALUATION KEY: not for operational use`. Generated only from the record, so it cannot say anything the record does not.

### B1.9 Threat model (`docs/THREAT_MODEL.md`, one page)

First paragraph, verbatim intent: *The signature binds the sealed record to the holder of the signing key at the moment of sealing. It proves the record and, with `--ulog`, the log have not changed since then. It does not prove the flight stack wrote a truthful log, that nothing happened to the log between disarm and sealing, or that the sealing machine was uncompromised.*

Then: sealing on the companion computer immediately after disarm (documented post-disarm hook example) shrinks the disarm-to-seal gap. A stolen key invalidates trust in every record signed with that fingerprint after the compromise. Operational seals use a key that never leaves a PKCS#11 token or HSM (`pkcs11-token`), or an Ed25519 seed sealed to the companion computer's TPM 2.0 (`tpm-sealed`: no other TPM can load it, and it is in `sfr`'s memory for one signature). File keys are evaluation-only, and every record and report sealed with one says so. Custody is signed but declared by the sealer; it is proven only by the signer certificate chain to the operator's trust anchor, whose CA must issue certificates only to keys it has seen held in hardware. Revocation is checked against CRL files given to `verify`; there is no online revocation check, by design.

`docs/THREAT_MODEL.md` names the crypto crates, states that they have no CMVP certificate, and states that `sfr` makes no FIPS 140 claim. **Sealed topics.** The raw log digest already covers every topic. Sealed topic digests add a per-topic proof inside the record: standalone verify covers them without the log, and a future inclusion-proof export can disclose one topic's digest without revealing the rest of the record. They do not interpret, validate, or judge the topic's contents. **Command sources.** Command source ids are the values recorded in the log. MAVLink source ids are self-reported unless MAVLink message signing is enabled on the link. R7 proves which source the log recorded, not that the source was authentic. The record contains the full parameter set and is as sensitive as the log; handle it the same way.

### B1.10 Production-grade gates (all binary; all enforced in CI unless marked)

| Gate | Pass criterion |
|---|---|
| Static binaries | For the x86_64, aarch64, and armv7 (`armv7-unknown-linux-musleabihf`) musl builds of `sfr`, `readelf -lW` shows no INTERP program header and `readelf -dW` shows no NEEDED entry (static-pie is allowed on x86_64; `ldd` is not used because it misreports static-pie and foreign-architecture binaries); for armv7, `file` also reports a statically linked 32-bit ARM executable. `sfr-pkcs11-helper` is exempt and is the only dynamically linked artifact |
| Peak memory | The maximum resident set size of `seal` is measured and reported on x86_64 for every golden log and for the 100 MB benchmark log; if the 100 MB log needs more than 256 MB, the cause is reported before work continues (small companion boards commonly have 512 MB) |
| armv7 | The full test suite passes on armv7 under QEMU user-mode emulation in CI. This is a correctness gate only: no armv7 performance number is gated or published unless measured on real hardware. CI also seals every golden log on x86_64 and on armv7 and requires byte-identical records (`scripts/check_same_records.sh`) |
| No network | Dependency tree contains no networking or async-runtime crates (CI check against a deny list); demo passes in `docker run --network=none`. Hardware signing uses child processes over pipes (`sfr-pkcs11-helper`, `tpm2_load`, `tpm2_unseal`), never sockets; a network-attached HSM's own PKCS#11 module may reach its HSM, and that traffic belongs to the operator's HSM deployment, not to `sfr` |
| No unsafe | `#![forbid(unsafe_code)]` in all Inquiro crates |
| Deterministic | Same inputs plus `--seal-time` and key produce byte-identical `.sfr` and `.sfr.md`, across x86_64, aarch64, and the WASM build |
| Replay | `verify --ulog` on every golden log reproduces sealed results byte-for-byte |
| Tamper property | At least 1,000 random single-byte flips in a `.sfr` and 1,000 in a `.ulg`: verification fails 100% of the time |
| Fuzzing | Fuzz targets for the ULog parser and the `.sfr` reader; 60 seconds per CI run and 10 minutes nightly with zero panics, hangs, or out-of-memory |
| Exit codes | An integration test triggers each of codes 0 to 4 |
| Errors | Every error names the file, and where relevant the topic, field, or parameter; no panics on any input |
| Performance | Benchmark script reports seal time for 10, 50, and 100 MB logs and standalone verify time; gates: 100 MB seal under 2 s on x86_64 and under 4 s on real aarch64 hardware (not emulation); standalone verify under 10 ms for records up to 10,000 events, measured in-process (`sfr_core::verify` on the record bytes in memory) as the median of 101 runs on the CI runner (`crates/sfr/tests/verify_perf.rs`); the same test reports the end-to-end `sfr verify` time, which adds process start and reading the files, and that time is reported, not gated |
| Code quality | `rustfmt --check` clean; `clippy` with warnings as errors; all tests green |
| Supply chain | `cargo-deny` clean for licenses (no GPL, AGPL, or unknown) and advisories; CycloneDX SBOM per release. |
| Crypto | On every target, SHA-256 (record, Merkle tree, log digest, key fingerprint) comes from `sha2`, Ed25519 key generation, signing and verification from `ed25519-dalek` (verification uses `verify_strict`), and the supplementary BLAKE3 digest of the raw log bytes from `blake3`, which never anchors trust. The keygen seed comes from the operating system's CSPRNG (`getrandom`). The same crates and versions build every target and the sandbox, so a record is byte-identical wherever it is sealed; `scripts/check_crypto_graph.sh` fails CI if another implementation (AWS-LC, ring, OpenSSL, BoringSSL) enters the graph of `sfr` or `sfr-wasm` on any target. `seal.crypto_crates` names each crate and its crate version, which a unit test holds to `Cargo.lock`. No CMVP-validated module is used and none is claimed (B1.12); the AWS-LC FIPS module was removed at Change Order 01 because it cannot be linked into a static armv7 binary (`docs/DIAGNOSTIC.md` item 11). Unit tests check RFC 8032 section 7.1 and the SHA-256 example of FIPS 180-4. No custom primitives; domain separation as specified |
| Key custody | `seal` exits 4 unless given a hardware key source or `--evaluation-only`; every record sealed with a file key has custody `file-evaluation` and its report's first line says EVALUATION KEY; `seal` verifies every signature before writing. CI exercises `pkcs11-token` against SoftHSM v2 (CKM_EDDSA) and `tpm-sealed` against swtpm |
| Certificates | `verify --trust-anchor` accepts an Ed25519 signer certificate only if it chains to the anchor offline, carries extended key usage code signing, is valid at the sealed time, is not revoked by a supplied CRL, and verifies the record signature with its own key; CI covers each rejection with generated test certificates |
| Releases | Each release ships `SHA256SUMS` plus an Ed25519 signature over it, and the public release key in the README. Each release names its crypto crates and their crate versions. Release artifacts for aarch64 are built on native aarch64 hardware; cross-compiling and emulation are for CI feature branches only |
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
- No FIPS, validated, or compliant claim anywhere (founder ruling, Change Order 01): `sfr` uses no CMVP-validated module, and docs, output, and records describe its cryptography only by its crates and crate versions. IL4, IL5, and NIST SP 800-171 apply to whole systems and environments, never to a binary. Never write "FIPS compliant", "FIPS certified", "FIPS validated", or any compliant, certified, accredited, authorized, or validated status for `sfr`; `scripts/check_language.sh` fails CI on such wording.
- No em-dashes.

### Change log

- Change Order 01: VTOL subtype and watched parameters; sealed topics; command categories and R7; armv7 build. With it, by founder ruling: one crypto stack (`sha2`, `ed25519-dalek`, `blake3`) on every target after the AWS-LC FIPS module could not be linked into a static armv7 binary; the record names its crypto by crate version; no FIPS, validated, or compliant claim anywhere.
