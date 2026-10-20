# Chunk ledger

Every shipped source file is listed here as chunks: ranges of whole functions that hold few enough code lines to read in one sitting. `docs/review/PLAN.txt` says how a chunk is reviewed and closed. A code line is a line that is neither blank nor a comment; inline test modules belong to no chunk.

`docs/review/ledger.json` is the data and this page is rendered from it: do not edit the tables here. `scripts/review/ledger.py set` records a status, the passes done and the fix pull requests; `scripts/review/ledger.py check` fails when the ranges no longer match the source files or this page no longer matches the data. The measurements come from `scripts/review/lint_baseline.py`, `scripts/review/coverage.py` and `scripts/review/mutants.py`; their commands are in `docs/review/PHASE0.md`.

Status is one of `todo`, `contract`, `review`, `fix`, `closed`. A function over the chunk limit is cut at statement boundaries into parts, each its own chunk, and the cut is named in the notes column. `crates/sfr/src/main.rs` is split by function between G4 (the `verify` command) and G8 (everything else).

<!-- BEGIN ledger-summary: scripts/review/ledger.py render -->
Ledger of commit `ce7a28e`: chunks of at most 400 code lines, closed at about 200; a long function has more than 100.

| Group | Name | Files | Chunks | Code lines | Functions over the long-function limit |
|---|---|---|---|---|---|
| G1 | Log parser and ingest | `sfr-core/src/ingest.rs`, `sfr-core/src/px4.rs`, `sfr-core/src/ulog.rs` | 10 | 2345 | 4 |
| G2 | Rule engine and events | `sfr-core/src/evaluate.rs`, `sfr-core/src/events.rs` | 9 | 2281 | 7 |
| G3 | Certificates and signatures | `sfr-core/src/crypto.rs`, `sfr/src/certs.rs` | 5 | 1127 | 2 |
| G4 | Verification | `sfr-core/src/verify.rs`, `sfr/src/main.rs` | 9 | 1734 | 3 |
| G5 | Sealed form | `sfr-core/src/json.rs`, `sfr-core/src/merkle.rs`, `sfr-core/src/record.rs`, `sfr-core/src/seal.rs` | 8 | 1503 | 1 |
| G6 | Configuration | `sfr-core/src/params.rs`, `sfr-core/src/pkcs11_uri.rs`, `sfr-core/src/rules.rs` | 5 | 1157 | 1 |
| G7 | Output | `sfr-core/src/display.rs`, `sfr-core/src/report.rs` | 4 | 771 | 1 |
| G8 | Keys, hardware, CLI | `sfr-core/src/keys.rs`, `sfr-pkcs11-helper/src/main.rs`, `sfr/src/hardware.rs`, `sfr/src/main.rs` | 9 | 1759 | 3 |
| GX | Cross-cutting | `sfr-core/src/lib.rs` | 1 | 47 | 0 |
| | Total | | 60 | 12724 | 22 |

Not in the ledger:
- `crates/sfr-core/src/px4_tables.rs`: generated data, checked against the PX4 sources by scripts/px4/px4_tables.py (docs/VALIDATION.md).
- Test code (`crates/*/tests/`, inline test modules), `fuzz/`, `scripts/`, `tools/`: not production source.
- `sfr-wasm`: named in the plan, but not a crate of this workspace at this commit.
<!-- END ledger-summary -->

## Contract sources by group

<!-- BEGIN ledger-groups: scripts/review/ledger.py render -->
| Group | Contract sources |
|---|---|
| G1 Log parser and ingest | ULog file-format specification; PX4 message definitions at each supported tag; docs/SPEC.md ingest sections; docs/LIMITS.md |
| G2 Rule engine and events | docs/RULES.md; PX4 sources named in docs/VALIDATION.md |
| G3 Certificates and signatures | RFC 5280; docs/THREAT_MODEL.md; library documentation for the pinned versions |
| G4 Verification | docs/SPEC.md verify sections; docs/RECORD_FORMAT.md |
| G5 Sealed form | RFC 8785 subset as written in docs/SPEC.md; RFC 6962 and its replacement RFC 9162 for the tree |
| G6 Configuration | docs/RULES.md; RFC 7512 for PKCS#11 URIs |
| G7 Output | docs/SPEC.md report sections |
| G8 Keys, hardware, CLI | docs/INTEGRATION_NOTES.md; docs/THREAT_MODEL.md |
| GX Cross-cutting | docs/ |
<!-- END ledger-groups -->

## Chunks

<!-- BEGIN ledger-chunks: scripts/review/ledger.py render -->
| ID | File | Lines | Code | Long fns | Status | Passes | Fix PRs | Notes |
|---|---|---|---|---|---|---|---|---|
| C1.1 | `sfr-core/src/ulog.rs` | 1-303 | 204 | 0 | todo | - | - | use std::collections::BTreeMap .. impl PartialEq for ParamValue::eq |
| C1.2 | `sfr-core/src/ulog.rs` | 304-602 | 235 | 0 | todo | - | - | impl impl Eq for ParamValue .. impl Cur<'a>::rest |
| C1.3 | `sfr-core/src/ulog.rs` | 603-823 | 204 | 0 | todo | - | - | ascii .. impl Flattener<'_>::walk |
| C1.4 | `sfr-core/src/ulog.rs` | 824-958 | 115 | 0 | todo | - | - | flatten .. ended_mid_record |
| C1.5 | `sfr-core/src/ulog.rs` | 959-1349 | 369 | 1 | todo | - | - | read .. record_name |
| C1.6 | `sfr-core/src/ingest.rs` | 1-314 | 204 | 0 | todo | - | - | use crate::crypto::{ CryptoBackend, Sha256Stream } .. struct GpsRow |
| C1.7 | `sfr-core/src/ingest.rs` | 315-608 | 203 | 0 | todo | - | - | struct BatteryRow .. get_u8 |
| C1.8 | `sfr-core/src/ingest.rs` | 609-1005 | 347 | 1 | todo | - | - | get_u64 .. impl Visitor for Collector<'_>::subscription |
| C1.9 | `sfr-core/src/ingest.rs` | 1006-1397 | 372 | 2 | todo | - | - | inside `impl Visitor for Collector<'_>`; impl Visitor for Collector<'_>::data .. impl Collector<'_>::finish |
| C1.10 | `sfr-core/src/px4.rs` | 1-115 | 92 | 0 | todo | - | - | use crate::ingest::Firmware .. mode_requirement |
| C2.1 | `sfr-core/src/evaluate.rs` | 1-317 | 245 | 0 | todo | - | - | use crate::events::{ ArmedInterval, Event, EventKind, VtolState, armed_sample, attribute_failsafe, flag_at, flight_armed_intervals, vtol_state, } .. r2 |
| C2.2 | `sfr-core/src/evaluate.rs` | 318-574 | 229 | 1 | todo | - | - | struct Difference .. impl Lines::finish |
| C2.3 | `sfr-core/src/evaluate.rs` | 575-976 | 350 | 1 | todo | - | - | in_flight_sample .. r4 |
| C2.4 | `sfr-core/src/evaluate.rs` | 977-1219 | 224 | 1 | todo | - | - | instance_note .. need_armed |
| C2.5 | `sfr-core/src/evaluate.rs` | 1220-1453 | 224 | 1 | todo | - | - | r7 .. x2 |
| C2.6 | `sfr-core/src/evaluate.rs` | 1454-1697 | 234 | 1 | todo | - | - | x3 .. evaluate |
| C2.7 | `sfr-core/src/events.rs` | 1-309 | 207 | 0 | todo | - | - | use crate::ingest::{ AckRow, CommandRow, Config, FailsafeFlags, FailsafeRow, Firmware, FlightLog, VehicleStatusRow, } .. flight_armed_intervals |
| C2.8 | `sfr-core/src/events.rs` | 310-670 | 311 | 1 | todo | - | - | reason_name .. instance_events |
| C2.9 | `sfr-core/src/events.rs` | 671-948 | 257 | 1 | todo | - | - | pair_commands .. event_json |
| C3.1 | `sfr/src/certs.rs` | 1-287 | 213 | 0 | todo | - | - | use rustls_pki_types::{ AlgorithmIdentifier, CertificateDer, InvalidSignature, SignatureVerificationAlgorithm, UnixTime, alg_id, } .. oid_text |
| C3.2 | `sfr/src/certs.rs` | 288-660 | 325 | 1 | todo | - | - | ascii_safe .. parse_crl |
| C3.3 | `sfr/src/certs.rs` | 661-904 | 202 | 0 | todo | - | - | current_crls .. struct ChainPolicy |
| C3.4 | `sfr/src/certs.rs` | 905-1163 | 213 | 1 | todo | - | - | struct CrlUsed .. no_crl_message |
| C3.5 | `sfr-core/src/crypto.rs` | 1-240 | 174 | 0 | todo | - | - | use std::fmt .. impl impl Signer for FileKey |
| C4.1 | `sfr-core/src/verify.rs` | 17-319 | 202 | 0 | todo | - | - | use crate::crypto::{ CryptoBackend, Custody, Sha256Stream } .. failed_text |
| C4.2 | `sfr-core/src/verify.rs` | 320-583 | 220 | 0 | todo | - | - | claimed_lines .. results_problems |
| C4.3 | `sfr-core/src/verify.rs` | 584-997 | 377 | 1 | todo | - | - | member .. standalone |
| C4.4 | `sfr-core/src/verify.rs` | 998-1210 | 200 | 1 | todo | - | - | struct Tee .. compare |
| C4.5 | `sfr-core/src/verify.rs` | 1211-1315 | 99 | 0 | todo | - | - | verify .. verify_parsed |
| C4.6 | `sfr/src/main.rs` | 974-1057 | 63 | 0 | todo | - | - | enum Trust .. attestation_of |
| C4.7 | `sfr/src/main.rs` | 1058-1341 | 262 | 1 | todo | - | - | `verify_cmd` part 1 of 2; verify_cmd (part 1) .. verify_cmd (part 1) |
| C4.8 | `sfr/src/main.rs` | 1342-1622 | 269 | 0 | todo | - | - | `verify_cmd` part 2 of 2; starts at line 1342: `let policy = CustodyPolicy {`; verify_cmd (part 2) .. verify_cmd (part 2) |
| C4.9 | `sfr/src/main.rs` | 1623-1668 | 42 | 0 | todo | - | - | not_checked .. not_checked |
| C5.1 | `sfr-core/src/json.rs` | 1-381 | 310 | 0 | todo | - | - | use std::collections::BTreeMap .. impl Parser<'_>::integer |
| C5.2 | `sfr-core/src/json.rs` | 382-723 | 307 | 0 | todo | - | - | inside `impl Parser<'_>`; impl Parser<'_>::hex4 .. impl Scanner<'_>::array |
| C5.3 | `sfr-core/src/json.rs` | 724-806 | 78 | 0 | todo | - | - | inside `impl Scanner<'_>`; impl Scanner<'_>::object .. first_non_canonical_offset |
| C5.4 | `sfr-core/src/record.rs` | 1-211 | 185 | 0 | todo | - | - | use crate::evaluate::Evaluation .. dry_run_json |
| C5.5 | `sfr-core/src/merkle.rs` | 1-66 | 46 | 0 | todo | - | - | use crate::crypto::CryptoBackend .. root |
| C5.6 | `sfr-core/src/seal.rs` | 1-308 | 234 | 0 | todo | - | - | use crate::crypto::{ CrateVersion, CryptoBackend, Signer } .. leaves |
| C5.7 | `sfr-core/src/seal.rs` | 309-568 | 219 | 1 | todo | - | - | merkle_root .. seal |
| C5.8 | `sfr-core/src/seal.rs` | 569-714 | 124 | 0 | todo | - | - | days_from_civil .. check_seal_time |
| C6.1 | `sfr-core/src/rules.rs` | 1-334 | 210 | 0 | todo | - | - | use crate::params::Pattern .. as_str_list |
| C6.2 | `sfr-core/src/rules.rs` | 335-658 | 308 | 1 | todo | - | - | as_uint .. parse_rules |
| C6.3 | `sfr-core/src/rules.rs` | 659-849 | 183 | 0 | todo | - | - | valid_param_name .. parse_authorized_sources |
| C6.4 | `sfr-core/src/params.rs` | 1-363 | 299 | 0 | todo | - | - | use crate::ulog::ParamValue .. impl Pattern::matches |
| C6.5 | `sfr-core/src/pkcs11_uri.rs` | 1-200 | 157 | 0 | todo | - | - | use std::fmt .. impl Pkcs11Uri::label |
| C7.1 | `sfr-core/src/report.rs` | 1-361 | 260 | 0 | todo | - | - | use crate::json::Value .. check |
| C7.2 | `sfr-core/src/report.rs` | 362-776 | 387 | 1 | todo | - | - | render .. render |
| C7.3 | `sfr-core/src/report.rs` | 777-868 | 67 | 0 | todo | - | - | const VARIABLE_FORM_NOTE .. watched_mark |
| C7.4 | `sfr-core/src/display.rs` | 1-89 | 57 | 0 | todo | - | - | const FORMAT_CHARACTERS .. terminal_safe |
| C8.1 | `sfr-core/src/keys.rs` | 1-210 | 164 | 0 | todo | - | - | use crate::crypto::CryptoBackend .. hex_decode |
| C8.2 | `sfr/src/hardware.rs` | 1-270 | 212 | 0 | todo | - | - | use sfr_core::crypto::rustcrypto::FileKey .. impl Drop for Scratch::drop |
| C8.3 | `sfr/src/hardware.rs` | 271-513 | 221 | 1 | todo | - | - | check_handle .. tpm_key |
| C8.4 | `sfr-pkcs11-helper/src/main.rs` | 1-251 | 214 | 0 | todo | - | - | use cryptoki::context::{ CInitializeArgs, CInitializeFlags, Pkcs11 } .. ed25519_point |
| C8.5 | `sfr/src/main.rs` | 1-252 | 200 | 0 | todo | - | - | macro compile_error .. file_name |
| C8.6 | `sfr/src/main.rs` | 253-505 | 232 | 1 | todo | - | - | crates_line .. transition_tuning |
| C8.7 | `sfr/src/main.rs` | 506-612 | 101 | 0 | todo | - | - | table .. windows_reserved_name |
| C8.8 | `sfr/src/main.rs` | 613-973 | 340 | 1 | todo | - | - | seal_cmd .. seal_cmd |
| C8.9 | `sfr/src/main.rs` | 1669-1753 | 75 | 0 | todo | - | - | version .. exit_with |
| CX.1 | `sfr-core/src/lib.rs` | 1-97 | 47 | 0 | todo | - | - | mod crypto .. const USAGE |
<!-- END ledger-chunks -->

## Measurements before any review

Lint warnings are those of the set in `docs/review/lint-baseline.txt` that fall on shipped lines of the chunk. Coverage is line and branch coverage of the whole workspace test run (`scripts/review/coverage.py`). Mutants are those of `cargo mutants` on the chunk's lines (`scripts/review/mutants.py`): caught, missed, unviable, timed out; the score is caught / (caught + missed + timed out).

<!-- BEGIN ledger-metrics: scripts/review/ledger.py render -->
| ID | Lint | Line cov | Branch cov | Caught | Missed | Unviable | Timeout | Mutation score |
|---|---|---|---|---|---|---|---|---|
| C1.1 | 17 | 80% | 100% | - | - | - | - | - |
| C1.2 | 22 | 81% | 78% | - | - | - | - | - |
| C1.3 | 6 | 83% | 82% | - | - | - | - | - |
| C1.4 | 2 | 95% | 72% | - | - | - | - | - |
| C1.5 | 6 | 91% | 88% | - | - | - | - | - |
| C1.6 | 14 | 96% | 100% | - | - | - | - | - |
| C1.7 | 9 | 94% | 83% | - | - | - | - | - |
| C1.8 | 4 | 98% | 78% | - | - | - | - | - |
| C1.9 | 9 | 98% | 89% | - | - | - | - | - |
| C1.10 | 11 | 96% | 83% | - | - | - | - | - |
| C2.1 | 8 | 98% | 92% | - | - | - | - | - |
| C2.2 | 6 | 96% | 85% | - | - | - | - | - |
| C2.3 | 12 | 99% | 94% | - | - | - | - | - |
| C2.4 | 4 | 94% | 82% | - | - | - | - | - |
| C2.5 | 9 | 86% | 77% | - | - | - | - | - |
| C2.6 | 7 | 84% | 79% | - | - | - | - | - |
| C2.7 | 12 | 94% | 100% | - | - | - | - | - |
| C2.8 | 13 | 95% | 94% | - | - | - | - | - |
| C2.9 | 10 | 97% | 81% | - | - | - | - | - |
| C3.1 | 6 | 92% | 84% | - | - | - | - | - |
| C3.2 | 4 | 83% | 72% | - | - | - | - | - |
| C3.3 | 0 | 87% | 62% | - | - | - | - | - |
| C3.4 | 1 | 95% | 83% | - | - | - | - | - |
| C3.5 | 6 | 88% | 75% | - | - | - | - | - |
| C4.1 | 14 | 99% | 96% | - | - | - | - | - |
| C4.2 | 5 | 93% | 82% | - | - | - | - | - |
| C4.3 | 3 | 88% | 78% | - | - | - | - | - |
| C4.4 | 1 | 85% | 82% | - | - | - | - | - |
| C4.5 | 3 | 92% | 67% | - | - | - | - | - |
| C4.6 | 0 | 77% | 75% | - | - | - | - | - |
| C4.7 | 6 | 96% | 85% | - | - | - | - | - |
| C4.8 | 5 | 97% | 94% | - | - | - | - | - |
| C4.9 | 1 | 97% | 75% | - | - | - | - | - |
| C5.1 | 29 | 100% | 98% | - | - | - | - | - |
| C5.2 | 35 | 96% | 95% | - | - | - | - | - |
| C5.3 | 7 | 100% | 100% | - | - | - | - | - |
| C5.4 | 9 | 100% | 100% | - | - | - | - | - |
| C5.5 | 2 | 100% | 100% | - | - | - | - | - |
| C5.6 | 16 | 83% | 50% | - | - | - | - | - |
| C5.7 | 11 | 94% | 70% | - | - | - | - | - |
| C5.8 | 25 | 97% | 77% | - | - | - | - | - |
| C6.1 | 5 | 89% | 92% | - | - | - | - | - |
| C6.2 | 7 | 98% | 88% | - | - | - | - | - |
| C6.3 | 6 | 88% | 84% | - | - | - | - | - |
| C6.4 | 13 | 94% | 87% | - | - | - | - | - |
| C6.5 | 8 | 89% | 100% | - | - | - | - | - |
| C7.1 | 17 | 79% | 91% | - | - | - | - | - |
| C7.2 | 12 | 97% | 84% | - | - | - | - | - |
| C7.3 | 5 | 100% | 100% | - | - | - | - | - |
| C7.4 | 5 | 100% | 100% | - | - | - | - | - |
| C8.1 | 36 | 98% | 85% | - | - | - | - | - |
| C8.2 | 0 | 57% | 54% | - | - | - | - | - |
| C8.3 | 0 | 50% | 54% | - | - | - | - | - |
| C8.4 | 1 | 10% | 18% | - | - | - | - | - |
| C8.5 | 4 | 90% | 95% | - | - | - | - | - |
| C8.6 | 6 | 59% | 69% | - | - | - | - | - |
| C8.7 | 10 | 97% | 94% | - | - | - | - | - |
| C8.8 | 6 | 83% | 92% | - | - | - | - | - |
| C8.9 | 2 | 58% | 50% | - | - | - | - | - |
| CX.1 | 4 | 100% | - | - | - | - | - | - |
<!-- END ledger-metrics -->

