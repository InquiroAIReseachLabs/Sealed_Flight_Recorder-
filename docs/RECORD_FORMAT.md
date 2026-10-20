# Record format (`.sfr`)

This page specifies schema version 3 of the record that `sfr seal` writes, exactly enough to write an independent verifier from it. SPEC B1.7 is the normative summary; the code that implements it is `crates/sfr-core/src/seal.rs` (fields, leaves, signed payload), `crates/sfr-core/src/json.rs` (canonical JSON), `crates/sfr-core/src/merkle.rs` (the tree), `crates/sfr-core/src/keys.rs` (keys and fingerprint) and `crates/sfr-core/src/verify.rs` (verification). The last section checks a golden record with `openssl`, `b3sum` and the Python standard library, without `sfr`.

## The file

A record is one JSON object, stored as its own canonical bytes (RFC 8785, JSON Canonicalization Scheme, below): UTF-8, no byte order mark, no whitespace between tokens, and nothing after the closing brace, not even a newline. `verify` rejects a file that is not exactly the canonical form of its own parse and names a byte offset: as `not in canonical form` for whitespace, key order or escapes, and as `not valid JSON` for a value outside the subset below (a float, `-0`, a leading zero, an integer outside the safe range, a duplicate key). A record longer than `MAX_RECORD_BYTES`, 536870912 bytes (512 MiB), is refused by `seal` and by `verify`; a record of exactly that length is accepted (`crates/sfr-core/src/verify.rs`).

## Canonical JSON

The record uses a subset of JSON, and its canonical form is RFC 8785 applied to that subset (`crates/sfr-core/src/json.rs`):

- **Values:** `null`, `true`, `false`, integers, strings, arrays and objects. There are no floating-point numbers: a number with a fraction or an exponent is an error.
- **Integers** lie in the I-JSON safe range, magnitude at most `2^53 - 1` (`MAX_SAFE_INTEGER`), and are written in decimal with no leading zero, no plus sign and no `-0`. Counts, sequence numbers, message indexes, instance ids and enumerated values (nav state, command id, MAVLink ids, log level) are integers. A count above the safe range would be written as a decimal string; no input limit lets one occur.
- **Unsigned 64-bit measurements** (timestamps, the log size) are decimal strings, so no reader rounds them through a double: `"24295307"`, never `24295307`.
- **Strings** are written as ECMAScript `JSON.stringify` writes them: `"` and `\` are escaped as `\"` and `\\`; U+0008, U+0009, U+000A, U+000C and U+000D as `\b`, `\t`, `\n`, `\f`, `\r`; every other code point below U+0020 as `\u` and four lowercase hex digits; every other character as itself in UTF-8 (`/` and non-ASCII characters are not escaped). A string that is not valid UTF-8, or holds an unpaired surrogate, is an error.
- **Objects** are written with their members sorted by key, comparing keys as sequences of UTF-16 code units. Duplicate keys are an error.
- **Nesting** is at most `MAX_DEPTH` (64) arrays and objects deep: a value inside 64 nested arrays and objects is accepted, one inside 65 is refused (`crates/sfr-core/src/json.rs`).
- **No whitespace** anywhere outside strings.

Because the file is canonical, the bytes of every member value in it are that value's own canonical form, so a verifier can hash leaves straight from the file or from a parse; the two agree.

### Parameter values

A parameter value is a typed string (`crates/sfr-core/src/ulog.rs` `f32_shortest`):

- `i32:<n>`: a ULog int32 parameter, in decimal (`i32:5`, `i32:-1`).
- `f32:<x>`: a ULog float32 parameter. `<x>` is the shortest decimal that reads back as the same float32, with the digits ECMAScript `Number::toString` would choose (fewest digits, then the one closest to the value, an exact tie to the even digit), in plain positional notation with no exponent (`f32:0.15`, `f32:2.4414062`, `f32:0`, `f32:-0`). Any NaN is `f32:NaN`; infinities are `f32:Infinity` and `f32:-Infinity`.

The tests in `crates/sfr-core/tests/canonical.rs` hold this to the rule instead of to a sample: the RFC 8785 examples for ordering and for strings, a large sample of float32 values on every run, and, with `cargo test --release -p sfr-core --test canonical -- --ignored`, every one of the 2^32 float32 bit patterns (each finite value must read back as itself, have no shorter text that does, be the closest of the texts of that length, and take the even digit at an exact tie; every NaN pattern gives `f32:NaN`). The exhaustive test takes under two hours on four cores; its last full run passed, and the count of patterns it checked is printed with `--nocapture`.

## Top-level fields

A record holds exactly these thirteen fields, no more and no fewer (`RECORD_FIELDS` in `crates/sfr-core/src/seal.rs`). They are listed here in canonical (sorted) order.

| Field | Type | Contents |
|---|---|---|
| `baseline` | object | the baseline the rules compared against: `firmware`, `ignore`, `parameters` |
| `config` | object | the configuration that flew: `firmware`, `parameters`, `watched_parameters` |
| `events` | array | the timeline, in sequence order |
| `log` | object | the log's identity: `blake3`, `file_name`, `firmware`, `sha256`, `size`, `vehicle` |
| `merkle` | object | `algorithm`, `leaf_count`, `root`, `sections` |
| `results` | array | one result per rule, in rule-id order |
| `rules` | object | the rules file: `sha256`, `text` |
| `schema_version` | integer | `3`. Schema 1 (the first) and schema 2 (which added `seal.allow_untested_version`) are not verified any more: their leaves are not bound to their section, and the signature does not cover the shape of the tree (below). Seal the log again |
| `seal` | object | who sealed, when, and how the key is held |
| `sealed_topics` | array | one digest per instance of each sealed topic; empty without `[sealed_topics]` |
| `signature` | object | `algorithm`, `value` |
| `status` | string | `PASS` or `FAIL` |
| `tool` | object | `build_commit`, `name`, `version` |

### `tool`

`name` is `sfr`; `version` is the crate version; `build_commit` is the git commit the binary was built from (the `SFR_BUILD_COMMIT` build variable), or `unknown`.

### `seal`

| Member | Value |
|---|---|
| `allow_untested_version` | `true` when the log's PX4 version is outside v1.14 to v1.17, or could not be read, and `seal` sealed it because it was given `--allow-untested-version` (the report then says so); `false` otherwise |
| `certificate_chain` | `null`, or, beside a signer certificate, an array of the intermediate CA certificates given with `seal --chain`, nearest the signer first, each the standard base64 (RFC 4648, padded) of its DER |
| `crypto_crates` | array of `{"name": ..., "version": ...}`, one per crate that computed the record, sorted by name: `blake3`, `ed25519-dalek`, `sha2` with their crate versions (`RUSTCRYPTO_CRATES` in `crates/sfr-core/src/crypto.rs`) |
| `key_custody` | `pkcs11-token`, `tpm-sealed` or `file-evaluation` (below) |
| `key_fingerprint` | `sha256:` and the lowercase hex SHA-256 of the signing key's SubjectPublicKeyInfo DER |
| `key_label` | the key file name, token object label, or sealed-key directory |
| `signer_certificate` | `null`, or the standard base64 (RFC 4648, padded) of the DER of the signer's X.509 certificate given with `seal --cert`; its key is the signing key (`seal` refuses another) |
| `time_utc` | `YYYY-MM-DDTHH:MM:SSZ`: the time given with `--seal-time`, converted to UTC, or the sealing machine's clock when none is given. A claim: signed, so it cannot change after sealing, but nothing checks it, and `verify` never uses it to judge a certificate |

**Key custody** is declared by the sealer, signed with the record, and a statement of the sealer's, not a fact (`sfr verify` prints it as `unattested`, or `attested by certificate chain` when the signer's certificate chains to a trust anchor the verifier supplied): `pkcs11-token` (the private key never leaves a PKCS#11 token or HSM), `tpm-sealed` (the seed is sealed to one TPM 2.0 and is in `sfr`'s memory for one signature), `file-evaluation` (a key file, for evaluation only). A verifier must treat custody as a claim unless something outside the record attests it ([THREAT_MODEL.md](THREAT_MODEL.md)). The certificates are inside the seal leaf, so the signature covers them; `verify --trust-anchor` checks them (`crates/sfr/src/certs.rs`).

**Seal time** is the sealer's claim, signed but not proven: nothing in the record shows when it was made unless a trusted time is supplied ([THREAT_MODEL.md](THREAT_MODEL.md)). `verify` labels it claimed, refuses one more than 300 seconds later than the verification time (`SEAL_TIME_SKEW_SECONDS` in `crates/sfr-core/src/seal.rs`), and does nothing else with it.

### `log`

| Member | Value |
|---|---|
| `blake3` | lowercase hex BLAKE3 of the whole log file, every byte: an index for finding the file, which adds no security. SHA-256 is the digest the seal rests on, and `verify --ulog` checks it first |
| `file_name` | the log's file name, without directories |
| `firmware` | `git`: the `ver_sw` info message, or null; `ver_sw_release`: the `ver_sw_release` info message as `0x` and eight lowercase hex digits, or null; `version`: that value as `major.minor.patch` with `-rc`, `-beta`, `-alpha` or `-dev` from its last byte (`version_string` in `crates/sfr-core/src/ingest.rs`), or null |
| `sha256` | lowercase hex SHA-256 of the whole log file |
| `size` | the log's length in bytes, as a decimal string |
| `vehicle` | `system_type` (MAVLink `MAV_TYPE`, integer) and `is_vtol` (boolean) from the first `vehicle_status` sample, each null when absent; `vtol_type`: null for a vehicle that is not VTOL, else `{"name": ..., "value": ...}` from parameter `VT_TYPE` (`tailsitter` for 0, `tiltrotor` for 1, `standard` for 2, `unknown(<n>)` for any other value, and `unknown` with value null when the log has no int32 `VT_TYPE`) |

A vehicle is VTOL here when `vehicle_status.is_vtol` is true on any sample, which is why `vtol_type` can be set while `is_vtol`, taken from the first sample only, is false.

### `config`

`firmware`: the log's firmware version string (as `log.firmware.version`), or null. `parameters`: every parameter at log start (the 'P' records before the first subscription), name to typed value, sorted by name. `watched_parameters`: the names the rules file lists in `[watched_parameters]`, sorted; empty without that section.

### `baseline`

`firmware`: the baseline's `# Firmware:` line, as the version, then a space and the git hash prefix when the line gives one (`1.17.0 d6f12ad1`). `parameters`: the baseline's parameters, name to typed value. `ignore`: the rules file's `parameters.ignore` patterns, in file order. With `rules`, this is everything a deep verify needs besides the log.

### `rules`

`text`: the whole rules file as UTF-8 text. `sha256`: the lowercase hex SHA-256 of `text`'s UTF-8 bytes.

### `results`

One object per rule: R1 to R7 always, then each optional rule X1 to X5 the rules file enables. Members: `id`; `name`; `status` (`PASS`, `FAIL` or `N/A`); `expected` and `found` (strings); `detail` (array of strings, one per finding). An `id` is one uppercase ASCII letter followed by a decimal number with no leading zero (`R7`, `X1`; not `R01` or `r1`). The array is in strictly increasing rule-id order, by the letter, then the number as an integer (`R2` before `R10` before `X1`), so no id appears twice. [RULES.md](RULES.md) gives each rule.

### `status`

`FAIL` when any result has status `FAIL`, else `PASS`.

### `sealed_topics`

One object per instance of each topic in `[sealed_topics]`, in strictly increasing order of `topic` (byte order), then `multi_id`, so no pair appears twice. The members and the digest procedure are under [Sealed topic digests](#sealed-topic-digests).

### `events`

Each event is an object with these members, then the members of its kind (`event_json` in `crates/sfr-core/src/events.rs`). Event `i` of the array has `seq` equal to `i`.

| Member | Value |
|---|---|
| `seq` | integer, from 0 |
| `kind` | one of the kinds below |
| `boot_us` | microseconds since boot, decimal string |
| `utc_us` | microseconds since the Unix epoch, decimal string, or null when the log gives no GPS time |
| `topic` | the source topic, or `ulog.logging`, `ulog.parameter`, `ulog.dropout` for records without one |
| `instance` | the source topic instance, integer |
| `index` | the source message's index, integer |

| Kind | Further members |
|---|---|
| `ARM` | `initial` (boolean), `reason` (integer or null), `reason_name` (string or null) |
| `DISARM` | `reason`, `reason_name` |
| `NAV_STATE_CHANGE` | `old` (integer or null for the first sample), `old_name`, `new` (integer), `new_name` |
| `FAILSAFE_SET` | `initial`, `flag` (a `failsafe_flags` field name, or `unattributed`) |
| `FAILSAFE_CLEAR` | `flag` |
| `COMMAND` | `command`, `category` (`PAYLOAD` or `GENERAL`), `source_system`, `source_component` (integers), `result` (`ACCEPTED`, `TEMPORARILY_REJECTED`, `DENIED`, `UNSUPPORTED`, `FAILED`, `IN_PROGRESS`, `CANCELLED`, `RESULT_<n>` for any other value `n`, or `NO_ACK`) |
| `VTOL_TRANSITION_START`, `VTOL_TRANSITION_END`, `VTOL_TRANSITION_ABORT` | `direction`: `to_fw` or `to_mc` |
| `QUADCHUTE` | `vtol_fixed_wing_system_failure` (boolean, or null when not logged) |
| `PARAM_CHANGED_IN_FLIGHT` | `name`, `old` (typed value, or null), `new` (typed value) |
| `LOG_MESSAGE` | `level` (integer, 0 to 4), `text`; and `text_hex`, the raw bytes in hex, only when the logged text is not valid UTF-8 (then `text` has each bad sequence replaced by U+FFFD) |
| `LOG_DROPOUT` | `duration_ms` (integer) |

The names in `reason_name`, `old_name` and `new_name` depend on the PX4 version (`reason_name` and `nav_state_name` in `crates/sfr-core/src/events.rs`); they are null for a version outside PX4 v1.14 to v1.17 or a value that version does not name. SPEC B1.5 defines when each event occurs and how events are ordered.

#### Event field `initial`

ARM and FAILSAFE_SET events carry a boolean `initial` (SPEC B1.5); no other event kind has it. It is `true` when the event comes from the log's first `vehicle_status` sample, because the log starts armed (ARM) or with `vehicle_status.failsafe` true (FAILSAFE_SET): the event records the state the log opens in, not a change the log shows. It is `false` when the event is a change from the previous `vehicle_status` sample in file order. The report shows the field in the detail column of its event timeline, with this definition in one line under the table.

### `merkle` and `signature`

`merkle`: exactly `algorithm` (`sha256-rfc6962`), `leaf_count` (integer, the tree size), `root` (64 lowercase hex digits, the Merkle root below) and `sections` (an object with one integer for each section below, the number of leaves it holds: `seal_context`, `log`, `config`, `baseline`, `rules`, `results`, `sealed_topics`, `events`). `signature`: exactly `algorithm` (`ed25519`) and `value` (128 lowercase hex digits, the Ed25519 signature over the signed payload below). Uppercase hex is refused (`hex_decode` in `crates/sfr-core/src/keys.rs`).

## Merkle leaves

The leaves, in this fixed order (`leaves` in `crates/sfr-core/src/seal.rs`):

1. the seal context: the object `{"schema_version": ..., "seal": ..., "tool": ...}` holding those three top-level fields;
2. `log`;
3. `config`;
4. `baseline`;
5. `rules`;
6. each element of `results`, in array order;
7. each element of `sealed_topics`, in array order;
8. each element of `events`, in array order.

`status`, `merkle` and `signature` are not leaves. `status` is bound because it must agree with the results, which are leaves.

Each leaf carries the tag byte of its section: `0x01` for the seal context, `0x02` for `log`, `0x03` for `config`, `0x04` for `baseline`, `0x05` for `rules`, `0x06` for each result, `0x07` for each sealed topic digest and `0x08` for each event (`Section` in `crates/sfr-core/src/seal.rs`). A leaf's hash is SHA-256(`0x00` || tag || JCS(leaf)), where JCS(leaf) is the leaf's canonical bytes. The tag binds a leaf to its section: a result moved into `sealed_topics`, or an event into `results`, hashes differently, so the root changes. (In schema 1 and 2 the hash was SHA-256(`0x00` || JCS(leaf)) with no tag, and a leaf moved between sections left the root unchanged.) An interior node's hash is SHA-256(`0x01` || left || right) over the two 32-byte child hashes. The tree is RFC 6962's: for `n` leaves, `n` above one, the left subtree holds the first `k` leaves, where `k` is the largest power of two strictly below `n`, and the right subtree the rest, recursively; a single leaf's tree hash is its leaf hash; nothing is duplicated. `merkle.leaf_count` is the number of leaves, so it is five plus the lengths of the three arrays, and `merkle.sections` gives the number of leaves in each section. The unit test `roots_match_an_independent_rfc6962_computation` in `crates/sfr-core/src/merkle.rs` holds roots for one to seven leaves computed independently.

## Signed payload and signature

The signed payload is, byte for byte (`signed_payload` in `crates/sfr-core/src/seal.rs`, tested by `signed_payload_layout`):

| Bytes | Value |
|---|---|
| ASCII `SFR-RECORD-V1` | the domain separation prefix |
| `0x00` | a separator |
| `0x00 0x00 0x00 0x03` | `schema_version` as a 4-byte big-endian unsigned integer |
| 8 bytes | the tree size (`merkle.leaf_count`) as a big-endian unsigned integer |
| 8 times 8 bytes | the number of leaves in each section as big-endian unsigned integers, in this order: seal context, `log`, `config`, `baseline`, `rules`, `results`, `sealed_topics`, `events` (the values of `merkle.sections`; the first five are always 1) |
| the Merkle root | its raw bytes, not hex |

The payload is 122 bytes (`signed_payload_layout` in `crates/sfr-core/src/seal.rs` checks its layout and length). It covers the shape of the tree as well as its root, so the leaf counts of the sections cannot change without the signature failing, and the record names the same counts that the arrays hold.

The signature is Ed25519 (RFC 8032, pure Ed25519, no prehash) over that payload, stored as the lowercase hex of its raw bytes. `sfr` checks it with `ed25519-dalek`'s `verify_strict`, which also refuses the weak public keys and malleable signature forms that RFC 8032 verification alone accepts. `seal` verifies every signature it makes before it writes anything, so a record it writes always passes `verify_strict`; a verifier that is less strict accepts everything `sfr` accepts, and possibly more.

## Keys and the key fingerprint

`sfr keygen --evaluation-only` writes `sfr.pub`, a PEM `PUBLIC KEY` (RFC 8410 SubjectPublicKeyInfo for Ed25519), and `sfr.key`, a PEM `PRIVATE KEY` (PKCS#8 v1, RFC 8410), the forms `openssl pkey` reads. `seal` also reads PKCS#8 v2 with the public key and no attributes, and refuses one whose public key does not match its seed. The key fingerprint is `sha256:` and the lowercase hex SHA-256 of the SubjectPublicKeyInfo DER, the same bytes `openssl pkey -pubin -outform DER` writes.

## What a verifier checks

`sfr verify --pubkey <sfr.pub>` (standalone) checks, in this order (`standalone` in `crates/sfr-core/src/verify.rs`):

1. The size is at most `MAX_RECORD_BYTES`.
2. `schema_version` is `3`. A verifier must reject any other value and must never guess; `sfr` reports an unknown version as such when the file parses within the value subset, even if it is not canonical, and otherwise reports the parse error.
3. The bytes are canonical, and the object holds exactly the thirteen fields.
4. Every `results` element is an object whose `id` is a rule id (above), in strictly increasing order; every `sealed_topics` element is an object with a string `topic` and an integer `multi_id`, in strictly increasing order; event `i` has the integer `seq` `i`.
5. `merkle` holds exactly its four members, its algorithm is `sha256-rfc6962`, its `leaf_count`, `root` and `sections` equal the ones recomputed from the leaves.
6. `rules.text` and `rules.sha256` are strings, and `rules.sha256` is the SHA-256 of `rules.text`.
7. `status` is a string that agrees with the results.
8. `seal.key_fingerprint` is a string, the fingerprint of the given public key.
9. `signature` holds exactly `algorithm` `ed25519` and `value`; `value` is 128 and `merkle.root` 64 lowercase hex digits; the signature over the signed payload, built from the recorded root and the leaf counts the arrays hold, verifies under the given public key.
10. `seal.key_custody` is one of the three values.
11. `seal.crypto_crates` is an array of objects, each with string `name` and `version`, and `seal.time_utc` is a string.
12. `seal.allow_untested_version` is a boolean.
13. `seal.signer_certificate` is null or base64, and `seal.certificate_chain` is null or, beside a signer certificate, a non-empty array of base64 strings.

With `--trust-anchor` instead of `--pubkey`, the key for step 9 is the one in `seal.signer_certificate`, and once the record verifies, its certificate chain must reach the anchor, every certificate must be valid at the verification time (the verifier's clock, or the time given with `--at`; not `seal.time_utc`, which is the sealer's claim), the signer certificate must carry the sfr record-signing extended key usage `2.25.182460915354635260549596502533646383540` and not also code signing, TLS server authentication or any usage, and its keyUsage must set digitalSignature (`check_signer_purpose` in `crates/sfr/src/certs.rs`), and no certificate in the path may be listed in the current CRL of its issuer (`crates/sfr/src/certs.rs`). Every CRL given with `--crl` is read, whatever the order; for each issuer the one with the highest `cRLNumber` (RFC 5280 section 5.2.3) is current; every issuer of the signer certificate and of the intermediates needs one, and it must not be past its `nextUpdate` by the verifier's clock, unless `--no-crl-check` is given. Then the report: the one `--report` names, or `<name>.sfr.md` beside `<name>.sfr`, must be byte for byte the report the record renders (`check` in `crates/sfr-core/src/report.rs`); a record with no report found fails, unless `--no-report` is given, which skips the check and says so. Last, the custody policy (`custody_policy` in `crates/sfr-core/src/verify.rs`) judges a record whose signature and chain are good: a declared `file-evaluation` is `Integrity: REFUSED` unless `--allow-evaluation-key` is given, and `--require-hardware-key` accepts only custody attested by the certificate chain (never one declared `file-evaluation`); these are refusals of a record that is intact, so they are not reported as a failed check.

`seal`, `merkle`, `signature` and `rules` must be objects and `results` an array. A failure in steps 1 to 4 is reported alone. From step 5 on, a check that fails is noted and the next one runs, and all are reported together, `FAILED:` with the first, then `also:` with the others, and exit code 1; but a member that is missing or of the wrong type, or an unknown custody, stops verification at once and is reported alone. With `--ulog <log>` (deep), `verify` also reads the log again, re-derives `log`, `config`, `results`, `sealed_topics` and `events` from it with the embedded rules and baseline, and requires them to equal the sealed ones (of `log`, every member but `file_name`, so a renamed log still verifies; the output then carries a `note` line naming both names); the first difference is named: a parameter, the config firmware, an event, a result, a sealed topic, the watched parameters, `log digest mismatch`, or the log's firmware or vehicle. A deep verify needs the full `sfr` analysis; the commands below check everything else.

## Sealed topic digests

A rules file may list topics in `[sealed_topics]` (at most `MAX_SEALED_TOPICS`, `crates/sfr-core/src/rules.rs`). For each listed topic and each instance (`multi_id`) the log subscribes, the record holds one entry in `sealed_topics`. The tool needs no knowledge of the topic's message structure: ULog is self-describing.

### Inputs

The ULog file, read once in file order: the definitions section, the data section, and appended data as the ULog file format describes it. Record layouts below are those of the ULog file format: a 3-byte header (`msg_size` as uint16 little-endian, then `msg_type`), then `msg_size` bytes of payload.

### Procedure

1. **'F' records (format definitions).** The payload is the text `<name>:<fields>` exactly as stored. When `<name>` is a sealed topic, remember `format_sha256[name] = SHA-256(payload)`. A later 'F' record with the same name replaces it.
2. **'A' records (subscriptions).** The payload is `multi_id` (uint8), `msg_id` (uint16 little-endian), then the message name. When the name is a sealed topic and no entry exists yet for (name, `multi_id`), create one: `format_sha256` from step 1 as it stands at this point, `message_count` 0, no timestamps, and a fresh SHA-256 context `H`. Either way, `msg_id` now refers to that entry.
3. **'D' records (data).** The payload is `msg_id` (uint16 little-endian), then the message bytes `P`: every byte after the message id, padding included. When `msg_id` refers to an entry:
   - `message_count` += 1;
   - `t` = the message's own `timestamp` field (uint64 little-endian, at the offset the topic's flattened format gives it; every ULog format has one);
   - `first_timestamp_us` = `t` of the first such record; `last_timestamp_us` = `t` of the latest;
   - `H.update(le64(len(P)))`, then `H.update(P)`, where `le64` is the 8-byte little-endian encoding.

   The message id is left out because a log assigns it, so it differs between logs that carry the same messages.
4. **Entries.** At the end of the log, each entry is the JSON object below. Entries are sorted by `topic` (byte order), then `multi_id`.

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

These commands check the golden record `examples/reports/vtol_transition.sfr`, its public key `examples/reports/sfr.pub` and its log `testdata/sitl/v1.17.0/vtol_transition.ulg` from the repository root, with no `sfr` binary. CI runs every one of them on every commit (`scripts/check_docs.py`) and compares the output shown here. Together they do the standalone checks above and the log digest part of a deep verify.

They need:

- **OpenSSL 3.0 or later** for the signature: `openssl pkeyutl -rawin`, which signs and verifies Ed25519 over the raw message, arrived in OpenSSL 3.0; the `pkeyutl` of OpenSSL 1.1.1 has no `-rawin`, so it cannot do step 3 (1.1.1 was not run). CI uses the runner's OpenSSL, which its log prints; these commands were also run with OpenSSL `3.0.13`. Other programs installed as `openssl`, such as LibreSSL, were not tested.
- **b3sum** for the BLAKE3 digest (`cargo install b3sum --locked`, or a package); CI installs b3sum `1.8.7`, the version of the `blake3` crate `sfr` uses.
- **coreutils** (`sha256sum`, `wc`), `grep`, `sed` and **bash**, whose `printf` turns hex into bytes.
- **Python 3**, standard library only, for the Merkle root and the structural checks.

The commands write only into `try/`.

### 1. The log digests

```sh doc-test
rec=examples/reports/vtol_transition.sfr
log=testdata/sitl/v1.17.0/vtol_transition.ulg
# The log identity, as the canonical record spells it (the firmware object has no braces inside).
ident=$(grep -o '"log":{"blake3":"[0-9a-f]\{64\}","file_name":"[^"\\]*","firmware":{[^}]*},"sha256":"[0-9a-f]\{64\}","size":"[0-9]*"' "$rec")
field() { printf '%s' "$ident" | sed "s/.*\"$1\":\"\\([^\"]*\\)\".*/\\1/"; }
same() { if [ "$2" = "$3" ]; then echo "$1 matches: $2"; else echo "$1 DIFFERS: record $2, file $3"; fi; }
same "blake3 (index only)" "$(field blake3)" "$(b3sum --no-names "$log")"
same sha256 "$(field sha256)" "$(sha256sum < "$log" | cut -d' ' -f1)"
same size "$(field size)" "$(wc -c < "$log" | tr -d ' ')"
```

```text doc-output
blake3 (index only) matches: 0af5378155f2d8dc440697a01096d4af50217c6eb33f93b3bef3d976a54adbfd
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
key fingerprint matches: sha256:42c677026b5cd80f2a74bdcd5957a90bdb81b4873a3194dca4f100f877b637be
```

### 3. The signature over the recorded Merkle root and tree shape

The payload is built from the recorded root and section counts; step 4 shows that they are the ones the record's content gives.

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

### 4. Structure, order, digests and the Merkle root

This script (Python 3, standard library only) does every standalone check above except the signature and the key fingerprint, which steps 2 and 3 do: canonical form, the field set, member types, leaf order, the rules digest, the status, the custody value, and the Merkle root and leaf count recomputed from the content.

```sh doc-test
mkdir -p try
cat > try/sfr_check.py <<'EOF'
# sfr_check.py: standalone checks of a schema 3 record, without sfr (docs/RECORD_FORMAT.md).
# Everything but the signature, which openssl checks. Python 3 standard library only.
import hashlib, json, re, sys

def quote(s):
    esc = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    return '"' + "".join(esc.get(c) or ("\\u%04x" % ord(c) if ord(c) < 0x20 else c) for c in s) + '"'

def jcs(v):  # RFC 8785 for the record's subset: null, booleans, safe integers, strings, arrays, objects
    if v is None or isinstance(v, bool):
        return {None: "null", True: "true", False: "false"}[v]
    if isinstance(v, int) and abs(v) <= 2**53 - 1:
        return str(v)
    if isinstance(v, str):
        return quote(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):  # keys in UTF-16 code unit order
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(quote(k) + ":" + jcs(v[k]) for k in keys) + "}"
    raise ValueError("not in the record's value subset: %r" % (v,))

def unique(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("duplicate key")
    return dict(pairs)

def no_float(text):
    raise ValueError("floating-point number " + text)

def sha256(b):
    return hashlib.sha256(b).digest()

def mth(h):  # RFC 6962 Merkle tree hash of leaf hashes
    if len(h) == 1:
        return h[0]
    k = 1
    while k * 2 < len(h):
        k *= 2
    return sha256(b"\x01" + mth(h[:k]) + mth(h[k:]))

def check(path):
    raw = open(path, "rb").read()
    r = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_float=no_float, parse_constant=no_float)
    if r.get("schema_version") != 3:
        return "unknown schema_version %r; this checker knows 3 only" % r.get("schema_version")
    if jcs(r).encode("utf-8") != raw:
        return "not in canonical form"
    fields = {"schema_version", "tool", "seal", "log", "config", "baseline", "rules", "results",
              "sealed_topics", "events", "status", "merkle", "signature"}
    if set(r) != fields:
        return "fields differ from the schema: %s" % sorted(set(r) ^ fields)
    obj = lambda v, *keys: isinstance(v, dict) and all(k in v for k in keys)
    if not (obj(r["seal"], "key_custody", "key_fingerprint", "time_utc", "crypto_crates")
            and obj(r["merkle"]) and obj(r["signature"], "value") and obj(r["rules"], "text", "sha256")
            and all(isinstance(x, list) for x in (r["results"], r["sealed_topics"], r["events"]))):
        return "a field is missing or of the wrong type"
    seal = r["seal"]
    if not (all(isinstance(seal[k], str) for k in ("key_custody", "key_fingerprint", "time_utc"))
            and isinstance(seal["crypto_crates"], list)
            and all(obj(c, "name", "version") and isinstance(c["name"], str) and isinstance(c["version"], str)
                    for c in seal["crypto_crates"])):
        return "a seal member is missing or of the wrong type"
    ids = [re.fullmatch(r"([A-Z])([1-9][0-9]*)", x["id"]) if obj(x, "id") and isinstance(x["id"], str) else None
           for x in r["results"]]
    if not all(ids) or [(m[1], int(m[2])) for m in ids] != sorted({(m[1], int(m[2])) for m in ids}):
        return "results are not in strictly increasing rule-id order"
    if not all(obj(t, "topic", "multi_id") and isinstance(t["topic"], str) and type(t["multi_id"]) is int
               for t in r["sealed_topics"]):
        return "a sealed topic has no topic and multi_id"
    topics = [(t["topic"], t["multi_id"]) for t in r["sealed_topics"]]
    if topics != sorted(set(topics)):
        return "sealed topics are not in strictly increasing topic and multi_id order"
    if [e.get("seq") if isinstance(e, dict) else None for e in r["events"]] != list(range(len(r["events"]))):
        return "events are not in sequence order"
    text, digest = r["rules"]["text"], r["rules"]["sha256"]
    if not (isinstance(text, str) and isinstance(digest, str)) or digest != sha256(text.encode("utf-8")).hex():
        return "rules.sha256 does not match rules.text"
    if r["status"] != ("FAIL" if any(obj(x) and x.get("status") == "FAIL" for x in r["results"]) else "PASS"):
        return "status disagrees with the results"
    if seal["key_custody"] not in ("pkcs11-token", "tpm-sealed", "file-evaluation"):
        return "unknown key custody"
    if not isinstance(seal.get("allow_untested_version"), bool):
        return "seal.allow_untested_version must be a boolean"
    context = {"schema_version": r["schema_version"], "tool": r["tool"], "seal": r["seal"]}
    # Each section's leaves carry the section's tag byte, in the hash and in the signed counts.
    sections = [("seal_context", 1, [context]), ("log", 2, [r["log"]]), ("config", 3, [r["config"]]),
                ("baseline", 4, [r["baseline"]]), ("rules", 5, [r["rules"]]), ("results", 6, r["results"]),
                ("sealed_topics", 7, r["sealed_topics"]), ("events", 8, r["events"])]
    leaves = [(tag, x) for _, tag, xs in sections for x in xs]
    root = mth([sha256(b"\x00" + bytes([tag]) + jcs(x).encode("utf-8")) for tag, x in leaves]).hex()
    counts = {name: len(xs) for name, _, xs in sections}
    if r["merkle"] != {"algorithm": "sha256-rfc6962", "leaf_count": len(leaves), "root": root, "sections": counts}:
        return "merkle differs: computed root %s over %d leaves" % (root, len(leaves))
    sig = r["signature"]
    if set(sig) != {"algorithm", "value"} or sig["algorithm"] != "ed25519" \
            or not (isinstance(sig["value"], str) and re.fullmatch(r"[0-9a-f]{128}", sig["value"])):
        return "signature must hold exactly algorithm ed25519 and a value of 128 lowercase hex digits"
    print("structure, order, rules digest and status: ok")
    print("merkle root %s over %d leaves: matches the record" % (root, len(leaves)))
    return None

problem = check(sys.argv[1])
if problem:
    print("FAILED: " + problem)
    sys.exit(1)
EOF
python3 -I try/sfr_check.py examples/reports/vtol_transition.sfr
```

```text doc-output
structure, order, rules digest and status: ok
merkle root 745c18ad35e1270ba418fb6d16624a946f431be5d65cc7b0ad1f3aebd6df5430 over 34 leaves: matches the record
```

With steps 2 and 3, the record is unchanged since it was signed by the holder of that key. With step 1, the log is the one it was sealed from.

### A changed record fails

Change the command id of the first COMMAND event in `examples/reports/vtol_transition.sfr`, 211, to 311, keeping the file canonical. The Merkle root no longer matches, so the signature, which covers the recorded root, no longer vouches for the content:

```sh doc-test
mkdir -p try
sed 's/"command":211,/"command":311,/' examples/reports/vtol_transition.sfr > try/changed.sfr
rc=0
python3 -I try/sfr_check.py try/changed.sfr || rc=$?
echo "exit $rc"
```

```text doc-output
FAILED: merkle differs: computed root 7c8b315562e5c20e420dd3ac1efc0ee03dd3776c68ba77f6bd2a05f9a5ba0392 over 34 leaves
exit 1
```
