# Record format (`.sfr`)

This page specifies schema versions 4 and 5 of the record `sfr seal` writes, in enough detail to write an independent verifier. SPEC B1.7 is the normative summary. The code is `crates/sfr-core/src/seal.rs` (fields, leaves, signed payload), `json.rs` (canonical JSON), `merkle.rs` (the tree), `keys.rs` (keys and fingerprint) and `verify.rs` (verification), all in `crates/sfr-core/src/`. The last section checks a golden record with `openssl`, `b3sum` and the Python standard library, without `sfr`.

## The file

A record is one JSON object stored as its own canonical bytes (RFC 8785, below): UTF-8, no byte order mark, no whitespace between tokens, nothing after the closing brace, not even a newline. `verify` rejects a file that is not exactly the canonical form of its own parse, and names a byte offset (a missing or unknown `schema_version` is reported first, without one): `not in canonical form` for whitespace, key order or escapes, and `not valid JSON` for a value outside the subset below (a float, `-0`, a leading zero, an integer outside the safe range, a duplicate key). `seal` and `verify` refuse a record longer than `MAX_RECORD_BYTES` (536870912 bytes, 512 MiB); one of exactly that length is accepted (`crates/sfr-core/src/verify.rs`).

## Canonical JSON

The record uses a subset of JSON, canonicalized as RFC 8785 specifies (`crates/sfr-core/src/json.rs`):

- **Values:** `null`, `true`, `false`, integers, strings, arrays and objects. A number with a fraction or an exponent is an error.
- **Integers** are decimal with magnitude at most `2^53 - 1` (`MAX_SAFE_INTEGER`), no leading zero, no plus sign, no `-0`. Counts, sequence numbers, message indexes, instance ids and enumerated values (nav state, command id, MAVLink ids, log level) are integers.
- **Unsigned 64-bit measurements** (timestamps, the log size) are decimal strings, so no reader rounds them through a double: `"24295307"`, never `24295307`.
- **Strings** are written as ECMAScript `JSON.stringify` writes them: `"` and `\` as `\"` and `\\`; U+0008, U+0009, U+000A, U+000C and U+000D as `\b`, `\t`, `\n`, `\f`, `\r`; every other code point below U+0020 as `\u` and four lowercase hex digits; everything else as itself in UTF-8 (`/` and non-ASCII characters are not escaped). A string that is not valid UTF-8 or holds an unpaired surrogate is an error.
- **Objects** have their members sorted by key, comparing keys as sequences of UTF-16 code units. Duplicate keys are an error.
- **Nesting** is at most `MAX_DEPTH` (64) arrays and objects deep.
- **No whitespace** outside strings.

Because the file is canonical, each member value's bytes in the file are that value's canonical form, so a verifier can hash leaves straight from the file or from a parse.

### Parameter values

A parameter value is a typed string (`f32_shortest` in `crates/sfr-core/src/ulog.rs`):

- `i32:<n>`: a ULog int32 in decimal (`i32:5`, `i32:-1`).
- `f32:<x>`: a ULog float32. `<x>` is the shortest decimal that reads back as the same float32, with the digits ECMAScript `Number::toString` would choose (fewest digits, then closest to the value, an exact tie to the even digit), in plain positional notation with no exponent (`f32:0.15`, `f32:2.4414062`, `f32:0`, `f32:-0`). Any NaN is `f32:NaN`; infinities are `f32:Infinity` and `f32:-Infinity`.

`crates/sfr-core/tests/canonical.rs` holds this to the rule: the RFC 8785 examples, a large sample of float32 values on every run, and, with `cargo test --release -p sfr-core --test canonical -- --ignored`, all 2^32 float32 bit patterns. Each finite value must read back as itself, have no shorter text that does, be the closest text of its length, and take the even digit at an exact tie; every NaN pattern gives `f32:NaN`. The exhaustive test takes under two hours on four cores and its last full run passed; `--nocapture` prints the count of patterns checked.

## Top-level fields

A record holds exactly these thirteen fields (`RECORD_FIELDS` in `crates/sfr-core/src/seal.rs`), listed in canonical order.

| Field | Type | Contents |
|---|---|---|
| `baseline` | object | the baseline the rules compared against: `firmware`, `ignore`, `parameters`, `sha256` |
| `config` | object | the configuration that flew: `firmware`, `parameters`, `watched_parameters` |
| `events` | array | the timeline, in sequence order |
| `log` | object | the log's identity: `blake3`, `file_name`, `firmware`, `sha256`, `size`, `skipped`, `vehicle`, `vehicle_status_instances` |
| `merkle` | object | `algorithm`, `leaf_count`, `root`, `sections` |
| `results` | array | one result per rule, in rule-id order |
| `rules` | object | the rules file: `sha256`, `text` |
| `schema_version` | integer | `4`, or `5` for a log schema 4 cannot describe: one that ends in the middle of a record, or has a ULog file format version above 1 ([Schema 5](#schema-5)). `seal` writes schema 4 for every other log, byte for byte as before. Schemas 1 and 2 are not verified: their leaves are not bound to a section and the signature does not cover the tree's shape. Schema 3 is not verified: its results come from rules that read less of the log (one `vehicle_status` instance, field names without their types). Seal the log again |
| `seal` | object | who sealed, when, and how the key is held |
| `sealed_topics` | array | one digest per instance of each sealed topic; empty without `[sealed_topics]` |
| `signature` | object | `algorithm`, `value` |
| `status` | string | `PASS`, `WARN`, `FAIL` or `NO ARMED FLIGHT`, computed from the results |
| `tool` | object | `build_commit`, `name`, `version` |

### `tool`

`name` is `sfr`; `version` is the crate version; `build_commit` is the git commit the binary was built from (build variable `SFR_BUILD_COMMIT`), or `unknown`.

### `seal`

| Member | Value |
|---|---|
| `allow_ignore_all` | `true` when the rules file's ignore patterns together match every parameter name (for example `*`), so R3 compared none, and `seal` was given `--allow-ignore-all`; else `false` |
| `allow_untested_ulog_version` | schema 5 only: `true` when the log's ULog file format version is above 1 and `seal` was given `--allow-untested-version`; else `false`. It is `true` exactly when `log.ulog_version` is above 1 |
| `allow_untested_version` | `true` when the log's PX4 version is outside v1.14 to v1.17, or unreadable, and `seal` was given `--allow-untested-version`; else `false` |
| `certificate_chain` | `null`, or beside a signer certificate, the intermediate CA certificates given with `seal --chain`, in the file's order (nearest the signer first, as `verify --trust-anchor` needs), each the padded standard base64 (RFC 4648) of its DER |
| `crypto_crates` | array of `{"name": ..., "version": ...}`, sorted by name: `blake3`, `ed25519-dalek`, `sha2` (`RUSTCRYPTO_CRATES` in `crates/sfr-core/src/crypto.rs`) |
| `key_custody` | `pkcs11-token`, `tpm-sealed` or `file-evaluation` (below) |
| `key_fingerprint` | `sha256:` and the lowercase hex SHA-256 of the signing key's SubjectPublicKeyInfo DER |
| `key_label` | the key file name, token object label (`id=` and the lowercase hex of the key id when the token key has no label, empty when it has neither), or sealed-key directory |
| `signer_certificate` | `null`, or the padded base64 of the DER of the signer's X.509 certificate given with `seal --cert`; its key is the signing key (`seal` refuses another) |
| `time_utc` | `YYYY-MM-DDTHH:MM:SSZ`: `--seal-time` converted to UTC, else the sealing machine's clock |

**Key custody** is the sealer's statement, signed with the record, not a fact. `sfr verify` prints it as `unattested`, or `attested by certificate chain` when the signer's certificate chains to a trust anchor the verifier supplied. `pkcs11-token`: the private key stays in a PKCS#11 token or HSM. `tpm-sealed`: the seed is sealed to one TPM 2.0 and is in `sfr`'s memory for one signature. `file-evaluation`: a key file, for evaluation only. A verifier must treat custody as a claim unless something outside the record attests it ([THREAT_MODEL.md](THREAT_MODEL.md)). The certificates are inside the seal leaf, so the signature covers them; `verify --trust-anchor` checks them (`crates/sfr/src/certs.rs`).

**Seal time** is the sealer's claim: signed, so it cannot change after sealing, but unchecked ([THREAT_MODEL.md](THREAT_MODEL.md)). `verify` labels it claimed, refuses one more than `SEAL_TIME_SKEW_SECONDS` (300 s, `crates/sfr-core/src/seal.rs`) after the verification time, and does nothing else with it.

### `log`

| Member | Value |
|---|---|
| `blake3` | lowercase hex BLAKE3 of the whole file, checked by `verify --ulog` after `sha256`. SHA-256 is the seal. BLAKE3 is a second digest and index field; a mismatch fails verification; it adds no security beyond SHA-256. |
| `file_name` | the file name, without directories |
| `firmware` | `git`: the `ver_sw` info message, or null; `ver_sw_release`: that info message as `0x` and eight lowercase hex digits, or null; `version`: `major.minor.patch` with a `-rc`, `-beta`, `-alpha` or `-dev` suffix from its last byte (`version_string` in `crates/sfr-core/src/ingest.rs`), or null |
| `sha256` | lowercase hex SHA-256 of the whole file |
| `size` | length in bytes, a decimal string: every byte of the file, also when it ends in the middle of a record |
| `truncated` | schema 5 only: `null`, or for a log that ends in the middle of a record, `{"offset": ..., "trailing_bytes": ...}`: the byte offset of the unfinished record and the bytes from there to the end of the file, decimal strings; `trailing_bytes` is above 0 and the two add up to `size` |
| `ulog_version` | schema 5 only: the ULog file format version, byte 7 of the file header, an integer from 0 to 255 |
| `skipped` | what the reader skipped: `unknown_records` (records of a type it does not know), `orphan_data_records` (data records for a message id with no subscription), `regions` (regions skipped to reach an appended-data offset, a record crossing the offset dropped) and `region_bytes` (their bytes, a decimal string); the report says `sealed with N skipped messages` when any count is above 0 |
| `vehicle_status_instances` | the number of `vehicle_status` instances with data records; the rules read every one |
| `vehicle` | `system_type` (MAVLink `MAV_TYPE`, integer) and `is_vtol` (boolean) from the first sample of the lowest-numbered `vehicle_status` instance, each null when absent; `vtol_type`: null for a vehicle that is not VTOL, else `{"name": ..., "value": ...}` from parameter `VT_TYPE` (`tailsitter` for 0, `tiltrotor` for 1, `standard` for 2, `unknown(<n>)` otherwise, and `unknown` with value null without an int32 `VT_TYPE`) |

A vehicle counts as VTOL when `vehicle_status.is_vtol` is true on any sample, so `vtol_type` can be set while `is_vtol`, taken from the first sample, is false.

#### Schema 5

Schema 5 is schema 4 with three more members: `log.truncated`, `log.ulog_version` and `seal.allow_untested_ulog_version` (`schema_for` in `crates/sfr-core/src/record.rs`). `seal` writes it only for a log that ends in the middle of a record (`log.truncated` not null) or whose ULog file format version is above 1 (`seal.allow_untested_ulog_version` true). A schema 4 record holds none of the three members; a schema 5 record holds all three, and states at least one of those two facts. Nothing else differs: the leaves, the tree and the signed payload are built the same way, with `schema_version` 5 in the payload. The ULog specification asks a parser to handle both kinds of log; [VALIDATION.md](VALIDATION.md#the-ulog-specification) cites it and names the tests.

### `config`, `baseline`, `rules`, `results`, `status`

- `config`: `firmware` (the log's version string, as `log.firmware.version`, or null); `parameters` (every parameter at log start, the 'P' records before the first subscription, name to typed value, sorted by name); `watched_parameters` (the names in `[watched_parameters]`, sorted; empty without that section).
- `baseline`: `firmware` (the version, then a space and the git hash prefix if the `# Firmware:` line gives one: `1.17.0 d6f12ad1`); `parameters` (name to typed value); `ignore` (the `parameters.ignore` patterns, in file order); `sha256` (lowercase hex SHA-256 of the baseline file the operator gave, or null). With `rules`, this is everything a deep verify needs besides the log.
- `rules`: `text` (the whole rules file as UTF-8) and `sha256` (lowercase hex SHA-256 of `text`'s UTF-8 bytes).
- `results`: one object per rule, R1 to R7 and then each enabled optional rule X1 to X5, with `id`, `name`, `status` (`PASS`, `WARN`, `FAIL` or `N/A`), `expected` and `found` (strings) and `detail` (array of strings, one per finding; for the in-flight lines of R3, R4 to R7, X2 and X3 at most `MAX_DETAIL_LINES` (1000, `crates/sfr-core/src/evaluate.rs`) lines, then one `and N more; ...` line). An `id` is one uppercase ASCII letter and a decimal number with no leading zero (`R7`, `X1`; not `R01` or `r1`). The array is in strictly increasing id order, by letter then number as an integer (`R2`, `R10`, `X1`). [RULES.md](RULES.md) gives each rule.
- `status`: `FAIL` when any result is `FAIL`; else `NO ARMED FLIGHT` when R5 is `N/A` (the log has no ARM and no DISARM, so no flight was checked); else `WARN` when any result is `WARN`; else `PASS` (`Overall::of` in `crates/sfr-core/src/evaluate.rs`).

### `sealed_topics`

One object per instance of each `[sealed_topics]` topic, in strictly increasing order of `topic` (byte order) then `multi_id`. Members and procedure: [Sealed topic digests](#sealed-topic-digests).

### `events`

Each event has these members, then the members of its kind (`event_json` in `crates/sfr-core/src/events.rs`). Event `i` has `seq` equal to `i`.

| Member | Value |
|---|---|
| `seq` | integer, from 0 |
| `kind` | one of the kinds below |
| `boot_us` | microseconds since boot, decimal string |
| `utc_us` | microseconds since the Unix epoch, decimal string, or null when the log has no GPS row with `fix_type` 2 or more and a nonzero time, or the result would be before the epoch |
| `topic` | the source topic, or `ulog.logging`, `ulog.parameter`, `ulog.dropout` for records without one |
| `instance` | the source topic instance, integer |
| `index` | the source message's index, integer |

| Kind | Further members |
|---|---|
| `ARM` | `initial` (boolean), `reason` (integer or null), `reason_name` (string or null) |
| `DISARM` | `reason`, `reason_name` |
| `NAV_STATE_CHANGE` | `old` (integer, null for the first sample), `old_name`, `new` (integer), `new_name` |
| `FAILSAFE_SET` | `initial`, `flag` (a `failsafe_flags` field name, or `unattributed`) |
| `FAILSAFE_CLEAR` | `flag` |
| `COMMAND` | `command`, `category` (`PAYLOAD` or `GENERAL`), `source_system`, `source_component` (integers), `result` (`ACCEPTED`, `TEMPORARILY_REJECTED`, `DENIED`, `UNSUPPORTED`, `FAILED`, `IN_PROGRESS`, `CANCELLED`, `RESULT_<n>` for any other value `n`, or `NO_ACK`) |
| `VTOL_TRANSITION_START`, `VTOL_TRANSITION_END`, `VTOL_TRANSITION_ABORT` | `direction`: `to_fw` or `to_mc` |
| `QUADCHUTE` | `vtol_fixed_wing_system_failure` (boolean, or null when not logged) |
| `PARAM_CHANGED_IN_FLIGHT` | `name`, `old` (typed value or null), `new` (typed value) |
| `LOG_MESSAGE` | `level` (integer, 0 to 4), `text`; and `text_hex` (the raw bytes in hex) only when the text is not valid UTF-8, in which case `text` has each bad sequence replaced by U+FFFD |
| `LOG_DROPOUT` | `duration_ms` (integer) |

The names in `reason_name`, `old_name` and `new_name` depend on the PX4 version (`reason_name` and `nav_state_name` in `crates/sfr-core/src/events.rs`) and are null outside v1.14 to v1.17 or for a value the version does not name. SPEC B1.5 defines when each event occurs and how events are ordered. `reason` is the value PX4 logged in `latest_arming_reason` or `latest_disarming_reason`, and `reason_name` names it by `arm_disarm_reason_t` in PX4's `src/lib/events/enums.json`, the type Commander casts into those fields at every tag v1.14.0 to v1.17.0. The `ARM_DISARM_REASON_*` constants in `VehicleStatus.msg` number the reasons differently from 6 on (6 is SAFETY_BUTTON there, 7 AUTO_DISARM_LAND) and are not what PX4 logs: a log's 6 is the automatic disarm after landing (`auto_disarm_land`), as the golden landings show.

#### Event field `initial`

ARM and FAILSAFE_SET events carry a boolean `initial` (SPEC B1.5); no other kind has it. It is `true` when the event comes from the first sample of a `vehicle_status` instance because the log starts armed (ARM) or with `failsafe` true (FAILSAFE_SET): the state the log opens in, not a change. It is `false` for a change from the previous `vehicle_status` sample. The report shows it in the event timeline's detail column.

### `merkle` and `signature`

`merkle` holds exactly `algorithm` (`sha256-rfc6962`), `leaf_count` (the tree size), `root` (64 lowercase hex digits) and `sections` (an object with the number of leaves in each section: `seal_context`, `log`, `config`, `baseline`, `rules`, `results`, `sealed_topics`, `events`). `signature` holds exactly `algorithm` (`ed25519`) and `value` (128 lowercase hex digits). Uppercase hex is refused (`hex_decode` in `crates/sfr-core/src/keys.rs`).

## Merkle leaves

The leaves, in this order (`leaves` in `crates/sfr-core/src/seal.rs`):

1. the seal context: `{"schema_version": ..., "seal": ..., "tool": ...}`, the three top-level fields of those names;
2. `log`;
3. `config`;
4. `baseline`;
5. `rules`;
6. each element of `results`;
7. each element of `sealed_topics`;
8. each element of `events`.

`status`, `merkle` and `signature` are not leaves. `status` is bound because it must agree with the results.

Each leaf carries its section's tag byte: `0x01` seal context, `0x02` `log`, `0x03` `config`, `0x04` `baseline`, `0x05` `rules`, `0x06` each result, `0x07` each sealed topic digest, `0x08` each event (`Section` in `crates/sfr-core/src/seal.rs`). A leaf's hash is SHA-256(`0x00` || tag || JCS(leaf)), where JCS(leaf) is its canonical bytes. The tag binds a leaf to its section: a result moved into `sealed_topics`, or an event into `results`, hashes differently and changes the root. An interior node's hash is SHA-256(`0x01` || left || right) over the two 32-byte child hashes. The tree is RFC 6962's (RFC 9162 obsoletes RFC 6962 with the same tree shape; the leaf here adds the documented section tag above, and `merkle.algorithm` keeps the name `sha256-rfc6962`): for `n` leaves, `n` above one, the left subtree holds the first `k` leaves, `k` the largest power of two strictly below `n`, and the right subtree the rest, recursively; a single leaf's tree hash is its leaf hash; nothing is duplicated. `merkle.leaf_count` is five plus the lengths of the three arrays. The unit test `roots_match_an_independent_rfc6962_computation` in `crates/sfr-core/src/merkle.rs` holds independently computed roots for one to seven leaves.

## Signed payload and signature

The signed payload is, byte for byte (`signed_payload` in `crates/sfr-core/src/seal.rs`, tested by `signed_payload_layout`):

| Bytes | Value |
|---|---|
| ASCII `SFR-RECORD-V1` | the domain separation prefix |
| `0x00` | a separator |
| `0x00 0x00 0x00 0x04` (or `0x05`) | `schema_version` as a 4-byte big-endian unsigned integer |
| 8 bytes | the tree size (`merkle.leaf_count`), big-endian unsigned |
| 8 times 8 bytes | the number of leaves in each section, big-endian unsigned, in this order: seal context, `log`, `config`, `baseline`, `rules`, `results`, `sealed_topics`, `events` (the values of `merkle.sections`; the first five are always 1) |
| the Merkle root | its raw bytes, not hex |

The payload is 122 bytes (`signed_payload_layout`). It covers the tree's shape as well as its root, so the leaf counts cannot change without breaking the signature.

The signature is pure Ed25519 (RFC 8032, no prehash) over that payload, stored as lowercase hex. `sfr` checks it with `ed25519-dalek`'s `verify_strict`, which also refuses the weak public keys and malleable signatures that plain RFC 8032 verification accepts. `seal` verifies every signature it makes before writing anything. A less strict verifier accepts everything `sfr` accepts, and possibly more.

## Keys and the key fingerprint

`sfr keygen --evaluation-only` writes `sfr.pub`, a PEM `PUBLIC KEY` (RFC 8410 SubjectPublicKeyInfo), and `sfr.key`, a PEM `PRIVATE KEY` (PKCS#8 v1, RFC 8410), both readable by `openssl pkey`. `seal` also reads PKCS#8 v2 with the public key and no attributes, and refuses one whose public key does not match its seed. The key fingerprint is `sha256:` and the lowercase hex SHA-256 of the SubjectPublicKeyInfo DER, the bytes `openssl pkey -pubin -outform DER` writes.

## What a verifier checks

`sfr verify --pubkey <sfr.pub>` (standalone) checks (`standalone` in `crates/sfr-core/src/verify.rs`). Steps 1 to 4 run in this order; the later checks all run, in the code's own order, so the first fault reported need not be the lowest step:

1. The size is at most `MAX_RECORD_BYTES`.
2. `schema_version` is `4` or `5`. Any other value is rejected, never guessed at; `sfr` names an unknown version when the file parses within the value subset, even if not canonical, and otherwise reports the parse error.
3. The bytes are canonical, and the object holds exactly the thirteen fields.
4. Every `results` element is an object whose `id` is a rule id, in strictly increasing order, with a `status` of `PASS`, `WARN`, `FAIL` or `N/A`; R1 to R7 each appear exactly once, and any other id is X1 to X5; every `sealed_topics` element is an object with a string `topic` and an integer `multi_id`, in strictly increasing order; event `i` has `seq` `i`.
5. `merkle` holds exactly its four members, the algorithm is `sha256-rfc6962`, and `leaf_count`, `root` and `sections` equal the values recomputed from the leaves.
6. `rules.text` and `rules.sha256` are strings, `rules.sha256` is the SHA-256 of `rules.text`, and `rules.text` is a rules file `sfr` reads.
7. `status` is a string equal to the status computed from the results.
8. `seal.key_fingerprint` is a string, the fingerprint of the given public key.
9. `signature` holds exactly `algorithm` `ed25519` and `value`; `value` is 128 and `merkle.root` 64 lowercase hex digits; the signature over the payload, built from the recorded root and the leaf counts the arrays hold, verifies under the given key.
10. `seal.key_custody` is one of the three values.
11. `seal.crypto_crates` is an array of objects with string `name` and `version`, and `seal.time_utc` is a string.
12. `seal.allow_untested_version` and `seal.allow_ignore_all` are booleans, and `seal.allow_ignore_all` is true exactly when the embedded rules file ignores every parameter. In schema 4, `log.truncated`, `log.ulog_version` and `seal.allow_untested_ulog_version` are absent. In schema 5 all three are present: `seal.allow_untested_ulog_version` is a boolean, true exactly when `log.ulog_version`, an integer from 0 to 255, is above 1; `log.truncated` is null, or holds exactly `offset` and `trailing_bytes`, decimal strings, `trailing_bytes` above 0, adding up to `log.size`; and the record states a cut or a version above 1 (`schema_5_members` in `crates/sfr-core/src/verify.rs`).
13. `seal.signer_certificate` is null or base64, and `seal.certificate_chain` is null or, beside a signer certificate, a non-empty array of base64 strings.

With `--trust-anchor` instead of `--pubkey`, step 9 uses the key in `seal.signer_certificate`, and once the record verifies:

- the certificate chain must reach the anchor, and every certificate must be valid at the verification time (the verifier's clock, or `--at`; not `seal.time_utc`);
- the signer certificate must carry the sfr record-signing extended key usage `2.25.182460915354635260549596502533646383540`, not also code signing, TLS server authentication or any usage, and its keyUsage must set digitalSignature (`check_signer_purpose` in `crates/sfr/src/certs.rs`);
- no certificate in the path may be in the current CRL of its issuer. Every CRL given with `--crl` is read in any order; for each issuer the one with the highest `cRLNumber` (RFC 5280 section 5.2.3; at most 20 significant octets) is current; a CRL whose issuer is not a non-empty Name is refused, and when several CRLs are refused the least message is shown, so the order given does not change the answer; every issuer of the signer certificate and the intermediates needs one whose `nextUpdate` is after the verifier's clock, whose `thisUpdate` is at most `--max-crl-age` before it (default 7 days) and at most 300 s after it, unless `--no-crl-check` is given.

Then the custody policy (`custody_policy` in `crates/sfr-core/src/verify.rs`) judges a record whose signature and chain are good: a declared `file-evaluation` is `Integrity: REFUSED` unless `--allow-evaluation-key` is given, and `--require-hardware-key` accepts only custody attested by the certificate chain. These refuse an intact record, so they are not reported as failed checks. Last, the report: the one `--report` names, or `<name>.sfr.md` beside `<name>.sfr`, must be byte for byte the report the record renders (`check` in `crates/sfr-core/src/report.rs`). A record with no report found fails, unless `--no-report` is given, which skips the check and says so. A refused record's report is not compared.

`seal`, `merkle`, `signature` and `rules` must be objects and `results` an array. A failure in steps 1 to 3 is reported alone. From step 4 on, failed checks are noted and the next one runs, then all are reported together (`FAILED:` with the first, `also:` with the others, exit 1); a missing or wrongly typed member, a fault in the booleans or schema 5 members of step 12, in the certificate members of step 13, or an unknown custody, stops verification and is reported alone, dropping the faults noted before it.

With `--ulog <log>` (deep), `verify` also reads the log again, re-derives `log`, `config`, `results`, `sealed_topics` and `events` from it with the embedded rules and baseline, and requires them to equal the sealed ones. Of `log` it compares every member but `file_name`, so a renamed log still verifies and a `note` line names both names. The first difference is named: a parameter, the config firmware, an event, a result, a sealed topic, the watched parameters, `log digest mismatch`, or the log's firmware or vehicle. A deep verify needs the full `sfr` analysis; the commands below check everything else.

## Sealed topic digests

A rules file may list topics in `[sealed_topics]` (at most `MAX_SEALED_TOPICS`, `crates/sfr-core/src/rules.rs`). For each listed topic and each instance (`multi_id`) the log subscribes, `sealed_topics` holds one entry. The tool needs no knowledge of the topic's message structure: ULog is self-describing.

### Inputs

The ULog file, read once in file order: the definitions section, the data section, and appended data as the ULog format describes it. Each record is a 3-byte header (`msg_size` as uint16 little-endian, then `msg_type`) and `msg_size` bytes of payload.

### Procedure

1. **'F' records (format definitions).** The payload is the text `<name>:<fields>` as stored. When `<name>` is a sealed topic, remember `format_sha256[name] = SHA-256(payload)`. A later 'F' record with the same name replaces it.
2. **'A' records (subscriptions).** The payload is `multi_id` (uint8), `msg_id` (uint16 little-endian), then the message name. When the name is a sealed topic and no entry exists for (name, `multi_id`), create one with `format_sha256` as it stands now, `message_count` 0, no timestamps, and a fresh SHA-256 context `H`. Either way, `msg_id` now refers to that entry.
3. **'D' records (data).** The payload is `msg_id` (uint16 little-endian), then the message bytes `P`: every byte after the message id, padding included. When `msg_id` refers to an entry:
   - `message_count` += 1;
   - `t` = the message's `timestamp` field (uint64 little-endian, at the offset the topic's flattened format gives; every ULog format has one);
   - `first_timestamp_us` = `t` of the first such record; `last_timestamp_us` = `t` of the latest;
   - `H.update(le64(len(P)))`, then `H.update(P)`, where `le64` is the 8-byte little-endian encoding.

   The message id is left out because a log assigns it, so it differs between logs that carry the same messages.
4. **Entries.** At the end of the log, each entry is the JSON object below, sorted by `topic` (byte order) then `multi_id`.

| Field | Value |
|---|---|
| `topic` | the message name |
| `multi_id` | integer |
| `format_sha256` | lowercase hex |
| `message_count` | integer |
| `first_timestamp_us`, `last_timestamp_us` | decimal string, or null when `message_count` is 0 |
| `data_sha256` | lowercase hex of `H`'s digest (the SHA-256 of no bytes when `message_count` is 0) |

5. **Leaves.** Each entry is one Merkle leaf, SHA-256(0x00 || 0x07 || JCS(entry)), after the results' leaves and before the events' leaves.

`format_sha256` covers the topic's own 'F' record only, not the 'F' records of nested types it uses.

### Worked example

The unit test `sealed_topics_are_digested_per_instance_while_streaming` (`crates/sfr-core/src/ingest.rs`) builds this log and checks these values:

- 'F' payload: `custom_detection:uint64_t timestamp;uint8_t[4] box;`
- `format_sha256`: `c05f82794614bc08b65ab3dbf5920fb43e7ffbda890061d06e79cfa5364d6143`
- Instance 0 has two data records. Their message bytes are `0a0000000000000001020304` (timestamp 10) and `140000000000000005060708` (timestamp 20), each 12 bytes long.
- `data_sha256` = SHA-256(`0c00000000000000` `0a0000000000000001020304` `0c00000000000000` `140000000000000005060708`) = `a933532016ce84d3fa02c2b0e1f09bab760869b1320c9450571b2f62c4eab43c`
- `message_count` 2, `first_timestamp_us` `"10"`, `last_timestamp_us` `"20"`.
- Instance 1 is subscribed with no data records: `message_count` 0, both timestamps null, `data_sha256` `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

## Verify without sfr

These commands check the golden record `examples/reports/vtol_transition.sfr`, its key `examples/reports/sfr.pub` and its log `testdata/sitl/v1.17.0/vtol_transition.ulg` from the repository root, with no `sfr` binary. CI runs every one on every commit on main and on the newest push of any other branch (`scripts/check_docs.py`) and compares the output shown. Together they do the standalone checks above, except that the rules file is checked only for TOML syntax and its ignore list, and the log's digests and size.

They need:

- **OpenSSL 3.0 or later** for the signature: `openssl pkeyutl -rawin` (Ed25519 over the raw message) arrived in OpenSSL 3.0, and 1.1.1 has no `-rawin` (not run). The commands were also run with OpenSSL `3.0.13`. LibreSSL and other programs installed as `openssl` were not tested. The docs job in `.github/workflows/ci.yml` prints the version it runs.
- **b3sum** for BLAKE3 (`cargo install b3sum --locked`, or a package); CI installs b3sum `1.8.7`, the version of the `blake3` crate `sfr` uses.
- **coreutils** (`sha256sum`, `wc`), `grep`, `sed` and **bash**, whose `printf` turns hex into bytes.
- **Python 3.11 or later**, standard library only, for the reference verifier (step 4).

The commands write only into `try/`.

### 1. The log digests

```sh doc-test
rec=examples/reports/vtol_transition.sfr
log=testdata/sitl/v1.17.0/vtol_transition.ulg
# The log identity, as the canonical record spells it (the firmware object has no braces inside).
ident=$(grep -o '"log":{"blake3":"[0-9a-f]\{64\}","file_name":"[^"\\]*","firmware":{[^}]*},"sha256":"[0-9a-f]\{64\}","size":"[0-9]*"' "$rec")
field() { printf '%s' "$ident" | sed "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/"; }
same() { if [ "$2" = "$3" ]; then echo "$1 matches: $2"; else echo "$1 DIFFERS: record $2, file $3"; fi; }
same blake3 "$(field blake3)" "$(b3sum --no-names "$log")"
same sha256 "$(field sha256)" "$(sha256sum < "$log" | cut -d' ' -f1)"
same size "$(field size)" "$(wc -c < "$log" | tr -d ' ')"
```

```text doc-output
blake3 matches: 0af5378155f2d8dc440697a01096d4af50217c6eb33f93b3bef3d976a54adbfd
sha256 matches: 86d64e54d1261991f4035355550f64e017f8a486c5c665848d6e68ae67fc9bf3
size matches: 24295307
```

### 2. The key fingerprint

```sh doc-test
rec=examples/reports/vtol_transition.sfr
fp=$(openssl pkey -pubin -in examples/reports/sfr.pub -outform DER | sha256sum | cut -d' ' -f1)
recorded=$(grep -o '"key_fingerprint":"sha256:[0-9a-f]\{64\}"' "$rec" | sed 's/.*sha256:\([0-9a-f]*\)"/\1/')
if [ "$fp" = "$recorded" ]; then echo "key fingerprint matches: sha256:$fp"; else echo "key fingerprint DIFFERS"; fi
```

```text doc-output
key fingerprint matches: sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45
```

### 3. The signature over the recorded Merkle root and tree shape

The payload is built from the recorded root and section counts; step 4 shows they match the record's content.

```sh doc-test
rec=examples/reports/vtol_transition.sfr
merkle=$(grep -o '"merkle":{"algorithm":"sha256-rfc6962","leaf_count":[0-9]*,"root":"[0-9a-f]\{64\}","sections":{[^}]*}}' "$rec")
root=$(printf '%s' "$merkle" | sed 's/.*"root":"\([0-9a-f]*\)".*/\1/')
count() { printf '%s' "$merkle" | sed "s/.*\"$1\":\([0-9]*\).*/\1/"; }
sig=$(grep -o '"signature":{"algorithm":"ed25519","value":"[0-9a-f]\{128\}"}' "$rec" | sed 's/.*"value":"\([0-9a-f]*\)".*/\1/')
unhex() { printf '%b' "$(printf '%s' "$1" | sed 's/../\\x&/g')"; }
mkdir -p try
version=$(grep -o '"schema_version":[0-9]*' "$rec" | cut -d: -f2)
be64() { unhex "$(printf '%016x' "$1")"; }
{
  printf 'SFR-RECORD-V1\000\000\000\000'; printf "\\$(printf '%03o' "$version")"
  be64 "$(count leaf_count)"
  for section in seal_context log config baseline rules results sealed_topics events; do be64 "$(count $section)"; done
  unhex "$root"
} > try/payload.bin
unhex "$sig" > try/signature.bin
wc -c < try/payload.bin
openssl pkeyutl -verify -pubin -inkey examples/reports/sfr.pub -rawin -in try/payload.bin -sigfile try/signature.bin
```

```text doc-output
122
Signature Verified Successfully
```

`openssl pkeyutl -verify` exits 0 and prints `Signature Verified Successfully` only for a good signature by that key; for any other it prints `Signature Verification Failure` and exits 1.

### 4. Every standalone check: the reference verifier

`tools/reference_verifier/sfr_ref_verify.py` is a separate program, written from this page and the ignore-pattern rule in [RULES.md](RULES.md): it imports nothing from `sfr`, needs only the Python 3.11+ standard library, and implements Ed25519 itself (RFC 8032). It does every standalone check above: strict JSON, canonical form, field set and member types, results R1 to R7 exactly once each with known statuses, leaf order, rules digest, the overall status, the flags, custody value, the Merkle root, the key fingerprint and the signature. Its header lists what it does not check: certificate chains and CRLs, the custody policy (it accepts an evaluation key), the report, the log, the rules file beyond its TOML syntax and ignore list, and the contents of `log`, `config`, `baseline`, `events` and `results` beyond their digests and the checks above. Its test vectors (`tools/reference_verifier/vectors/`, written by `make_vectors.py`) include records built to trip a lenient JSON reader; `crates/sfr/tests/reference_verifier.rs` requires it and `sfr verify` to give each vector the verdict `expected.json` lists.

```sh doc-test
python3 -I tools/reference_verifier/sfr_ref_verify.py examples/reports/vtol_transition.sfr examples/reports/sfr.pub
```

```text doc-output
VERIFIED
```

Steps 2 and 3 show that the holder of that key signed the recorded root and counts; step 4 ties the content to that root, so together they show the record is unchanged since it was signed. Step 1 shows the log is the one it was sealed from.

### A changed record fails

Change the command id of the first COMMAND event in `examples/reports/vtol_transition.sfr`, 211, to 311, keeping the file canonical. The Merkle root no longer matches, so the signature no longer vouches for the content:

```sh doc-test
mkdir -p try
sed 's/"command":211,/"command":311,/' examples/reports/vtol_transition.sfr > try/changed.sfr
rc=0
python3 -I tools/reference_verifier/sfr_ref_verify.py try/changed.sfr examples/reports/sfr.pub || rc=$?
echo "exit $rc"
```

```text doc-output
FAILED: merkle differs from the leaves: root 78ad1b57928f3c6ab6dc6407ead4012b77ed6fd96e3c84f1d9f782515640587f over 34 leaves
exit 1
```
