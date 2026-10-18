# DIAGNOSTIC: decisions and evidence for the Sealed Flight Record build

**Chunk:** 1 (no feature code). **Date:** 2026-10-18. **Branch:** `chunk-1`.
**Purpose:** answer the eight Chunk 1 items of the build plan with evidence (command output, file paths, links), so that Chunks 2 to 7 take every PX4 topic and field name, every parser and crate choice, and every default from this file and never from memory (SPEC B1.5).

**How to read a verdict:** VERIFIED means reproduced in this session with the command shown. SOURCE-ONLY means read from PX4 source at the named tag and not yet confirmed against a log. CORRECTED means a claim in the build plan was checked and found wrong; the corrected fact follows.

## Contents
1. Reuse audit
2. Parser decision
3. Golden logs
4. Field map (PX4 v1.14 and v1.17)
5. Volatile parameters and the default ignore list
6. VTOL transition semantics
7. Build check (musl, aarch64 musl, wasm32)
8. Canonicalization
9. Corrections to the build plan and to SPEC
10. Decisions the founder must approve before Chunk 2
11. Cryptographic module boundary and key custody (security audit)

Appendix A. Item 11 test programs

Raw outputs sit in collapsed sections inside each item.


## 1. Reuse audit

**Scope searched:** the founder's AIFlightRecorder repository (checked out at commit `8432802`), the only prior project available in this session. The founder has not yet pointed to any other location.

| Check | Result |
|---|---|
| Rust source files (`*.rs`) in AIFlightRecorder | 0 |
| Cargo manifests in AIFlightRecorder | 0 |
| Dual-hash implementation | Python only (`src/core.py`, `dual_hash`: hashlib SHA-256 plus the `blake3` package, with a fallback to SHA-256 alone when blake3 is missing) |
| Merkle implementation | Python only (`src/anchor.py`, dual-hash leaves, duplicate-last odd-node rule, no domain separation) |
| Ed25519 signing | Python only (`pilot/checkpoint.py`, the `cryptography` package) |

**Decision: REPLACE for all three pieces.** No Rust exists to reuse, and the Python designs differ from SPEC B1.7 in ways that matter: the Python Merkle hashes leaves and nodes with the dual hash and no 0x00 / 0x01 domain prefixes, duplicates the last node instead of following RFC 6962, and tolerates a missing BLAKE3 by silently degrading to one hash. SPEC B1.7 requires SHA-256 only inside the tree with domain separation, RFC 6962 odd-node handling, and the dual hash on the raw log bytes alone. The record, Merkle, and signature code is written new in `sfr-core` on `sha2`, `blake3`, and `ed25519-dalek` (versions and build evidence in item 7), with `#![forbid(unsafe_code)]`.

What does carry over from the prior project is discipline, not code: the CLAUDEME laws, the pre-commit validation gate, the commit format, and the tamper demo shape (flip one byte, show the named failure).

If the founder later points to Rust code elsewhere, this item is re-run against it with the same criteria: audited crates only, domain separation as specified, no unsafe, no silent degradation.


## 2. Parser decision

Scope: evidence for choosing the ULog ingest layer of `sfr-core` (SPEC B1.5, B1.6, B1.10; CLAUDEME section 4 and 5). No feature code was written into the repository and nothing under `/home/user/Sealed_Flight_Recorder-` was modified. All probes, inputs and outputs live in the scratchpad (paths in section 9).

**Conditions.** Rust 1.97.0 (the pinned `rust-toolchain.toml` channel), 4 vCPU x86_64 Linux. All cargo builds and all timings ran under `nice -n 10` while two PX4 SITL flights ran on the same machine: load average was 1.9 to 4.6 during the timing runs and 4.5 to 5.2 during the cross-check, with a peak of 8.4 observed in between. **Parse times below were measured under load**; treat them as upper bounds, not clean-machine numbers. The PX4 docs page (docs.px4.io) was unreachable (proxy refused CONNECT, HTTP 403), so pyulog 1.2.4 (`pyulog/core.py`) is the reference implementation for every cross-check.

**Note on the v1.17.0 log named in the brief.** `sitl_logs/v1.17.0/mc_flight_1.ulg` (sha256 `4578b6e9...`) was moved by the SITL runner to `sitl_logs/v1.17.0/superseded/mc_flight_1_attempt1.ulg` while this item ran. I pinned a copy (`inputs/sitl_v1170_attempt1.ulg`, same hash) and used it for timing and fuzz bases. Seven more SITL logs appeared later (a new v1.17.0 `mc_flight_1.ulg` with sha256 `6e7b6956...`, `mc_flight_2`, two failsafe flights, two VTOL flights, and a v1.14.4 flight); all were copied and added to the cross-check, so it covers PX4 v1.14.4 and v1.17.0 plus the six pyulog test logs.

### 1. Recommendation

**Option 4: write a minimal in-house ULog parser in `sfr-core` behind the `FlightLogIngestor` trait** (estimate: 700 to 900 lines of code plus 500 to 700 lines of tests, 3 to 5 engineer-days). Use pyulog-generated expected files (offline Python tooling, allowed by CLAUDEME section 2) and px4-ulog 0.6.1 as a dev-dependency-only differential oracle in tests and fuzzing.

Reasons:

1. **No candidate passes the B1.10 fuzzing gate (zero panics, hangs, out-of-memory) as published.** On small crafted inputs: px4-ulog has 3 panic sites, 1 hang, 1 out-of-memory abort (a 29 KB file reaches 4 GiB) and 1 stack overflow; yule_log has 1 panic, 2 allocation aborts and 1 stack overflow; ulog-rs has 2 panics and 2 aborts. A deterministic 6,000-case mutation sweep found 30 panics in px4-ulog (all in one unchecked branch), 0 in yule_log, 1 in ulog-rs.

2. **The best crate on valid logs needs its core rewritten to pass that gate.** px4-ulog matched pyulog on 112 of 112 category checks across 14 logs, has 1 dependency and 0 unsafe, and parses 100 MB in 0.12 to 0.22 s. But its format flattening runs eagerly over every format in the file (not only subscribed ones), recurses with no depth limit, and loops without bound on zero-size nested formats. Fixing that changes the most complex 400 lines of the crate.

3. **A fork cannot be consumed as a git dependency here.** `deny.toml` sets `unknown-git = "deny"` and allows only the crates.io registry. A fork must be vendored as a workspace crate, which makes it an Inquiro crate under `#![forbid(unsafe_code)]` and `clippy -D warnings` with the repo lints (px4-ulog: 9 unwrap/expect/panic sites and 167 `missing_docs` warnings), or republished under a new crates.io name. Either way we own and maintain the code, so it should be code shaped for B1.5 rather than a general-purpose parser.

4. **What SFR needs from ULog is small and fully specified** (section 4): framing, header, flag bits, formats with bounded flattening, info and multi-info, parameters and defaults, subscriptions, data records with typed field lookup, logged strings, dropouts, sync, appended sections, truncation detection. An in-house parser can make every failure class found here impossible by construction (section 6.4), report the byte offset in every error (CLAUDEME `Malformed { file, offset, reason }`), and keep the dependency graph empty.

5. **Performance is not the constraint.** The zero-copy framing approach px4-ulog uses (which an in-house parser would copy) costs 0.12 to 0.22 s per 100 MB under load; the gate is 2 s for the whole seal.

**Runner-up:** px4-ulog 0.6.1, vendored, with the six changes in section 6.2 plus a thin wrapper. Choose it only if the 3 to 5 days are not available; expect 1.5 to 2.5 days for the fork and the same fuzz and parity work.

**Rejected:** yule_log 0.4.0: silently returns a fabricated final record on truncated input (8 of 19 cuts), silently truncates info keys at `-`, prints to stdout from library code, ignores appended data, 25 transitive dependencies, 2 unsafe blocks. ulog-rs 0.0.4: returns `Ok` with silently truncated data on 9 of 14 logs (for example 14 of 103,604 data records on the v1.17.0 log), rejects logs with appended data, fails `cargo deny` licenses, uses 1.16 GiB of memory for 100 MB, no commits since 2025-01-16.

### 2. Comparison table

| | yule_log 0.4.0 | px4-ulog 0.6.1 | ulog-rs 0.0.4 | Option 4: in-house (estimate) |
|---|---|---|---|---|
| License (Cargo.toml) | MIT | MIT | MIT, but pulls `dirs-sys` (MPL-2.0): `cargo deny` licenses **FAIL** with the repo `deny.toml` | Inquiro |
| Last release / repo state | 0.4.0 on 2025-11-13 (crates.io); no `v0.4.0` git tag (tags stop at v0.3.3); 99 commits; single maintainer | 0.6.1 on 2026-06-24 (tag v0.6.1); dormant 2018-12 to 2026-06, then 0.5.0, 0.6.0, 0.6.1 within 5 days; PX4 org repo, Auterion/PX4 authors | 0.0.4 on 2025-01-16; no tags; last commit 2025-01-16; README says interface still changing | n/a |
| Transitive runtime deps | 25 (env_logger, regex, jiff, lazy_static, thiserror, anstream, ...) | **1** (byteorder) | 34 (clap, dirs, serde_json, bytes, libc, ...) in a library | 0 needed (std `from_le_bytes`) |
| Deny-list (networking, async) hits | none | none | none | none |
| `cargo deny` (repo deny.toml): licenses, bans, sources, advisories | pass | pass | licenses FAIL (MPL-2.0) | pass |
| `unsafe` in crate source | 2 blocks (`model.rs:450`, `encode.rs:370`: `[CChar]` to `[u8]` casts, sound because `CChar` is `repr(transparent)`); vendored it fails `forbid(unsafe_code)` | 0 (one comment in a test) | 0 | 0, `forbid(unsafe_code)` |
| `unsafe` in dependencies (word count) | memchr 340, aho-corasick 227, syn 98, jiff 79, regex-automata 57, byteorder 44, ... | byteorder 44 | libc 811, memchr 340, bytes 171, syn 103+98, zmij 70, ... | none |
| MSRV / edition | no `rust-version`; edition 2021 | no `rust-version`; edition 2021; CI matrix tests stable and 1.85 | no `rust-version`; edition 2021 | workspace 1.97, edition 2024 |
| Builds on 1.97 for x86_64-musl, aarch64-musl, wasm32 | yes | yes | yes | expected yes (std only) |
| clippy on the crate, default lints with `-D warnings` | 8 warnings | 0 | 12 | must be 0 |
| clippy with the repo lint set (matters only if vendored) | 2 `forbid(unsafe)` errors, 7 unwrap, 1 print, 224 missing_docs | 8 unwrap/expect, 1 panic, 167 missing_docs | 1 unwrap, 177 missing_docs, misc | must be 0 |
| API shape | streaming iterator over any `Read`; decodes every field of every record unless given an allow list | streaming push parser (`consume_bytes` on chunks, callbacks with borrowed slices) plus file driver and whole-file `full_parser` | whole parse into owned HashMaps with a columnar copy of all data | streaming over `&[u8]` chunks, borrowed records, typed field lookup |
| Header (version, start timestamp) | yes | yes (`LogParser::version()`, `timestamp()`) | yes | yes |
| Flag bits (compat, incompat, appended offsets) | yes | appended offsets only; compat flags private | not exposed; **rejects** any log with the DATA_APPENDED incompat bit | yes |
| Info messages (ver_sw, ver_hw, sys_name, ...) | yes, decoded; **keys containing `-` are truncated** (65 distinct `perf_counter_preflight-NN` keys collapse to 2) | yes, raw bytes plus type string | yes | yes |
| Multi-info (I with continuation, M) | fragments only | fragments plus reassembly callback | data section only: M records in the definitions section are skipped (0 of 2 keys on the tagged log); on v1.17.0 it stops before reaching them | yes, reassembled |
| Initial parameters | yes | yes (`LogStage::Definitions`) | yes | yes |
| Default parameters (Q) | yes | yes | yes | yes |
| In-flight parameter changes (P after data starts) | yes, file order kept; caller tracks the running timestamp | yes (`LogStage::Data`), file order kept; caller tracks the running timestamp | per-name vectors: no timestamps, cross-parameter order lost | yes, with running timestamp and file order |
| Logged strings L and C with level | yes (`LogLevel` enum; an unknown level byte is an error) | yes (raw level byte) | yes | yes |
| multi_id per subscription | yes | yes | yes | yes |
| Dropouts (O) | yes, but `Dropout.duration` is `pub(crate)` (only via `Display`) | yes | yes (plus a timestamp) | yes |
| Sync (S) | returned as `Unhandled` raw bytes | callback | skipped | counted, used for nothing else in v1 |
| Appended data | **stops at the first appended offset; never reads appended sections; returns the record straddling the offset** | yes, matches pyulog on both appended test logs | **rejects the file** | yes, sequential, straddling record discarded as pyulog does |
| PX4 events (`event` topic + `metadata_events`) | raw topic data only | raw topic data plus reassembled metadata bytes | raw topic data only | raw topic data; decoding is a separate decision (section 7) |
| Truncation sweep (19 cuts of sample.ulg) | no panic, no hang; 7 errors; **8 of 12 OK results include a fabricated final record** (+1 data record vs pyulog), with no error | no panic, no hang; returns the exact pyulog prefix every time and reports `Truncated`; empty or under-16-byte input returns `Ok` (wrapper must check) | error on 17 of 19 cuts (whole parse discarded) | typed `Truncated { offset }` error, exit 3 |
| Crafted inputs (33 files) | 1 panic (`tokenizer.rs:79` unwrap), 2 allocation aborts (`field_helpers.rs:85` `with_capacity`, nested explosion), 1 stack overflow | 3 panics (`file_reader.rs:406`, `418`, `419`), 1 hang (zero-size nested formats), 1 out-of-memory (29 KB file, 4 GiB after 22 s), 1 stack overflow | 2 panics (capacity overflow from `msg_size - 9` and `msg_size - 3`), 2 aborts | all closed by design rules in section 6.4 (unproven until fuzzed) |
| Mutation sweep (6,000 cases) | 0 panics, 0 hangs, 0 aborts | **30 panics** (`file_reader.rs:418` and `419`) | 1 panic | target: 0 |
| Correctness vs pyulog (14 logs x 8 categories) | 109 / 112 | **112 / 112** | 68 / 112 | target 112 / 112 |
| 100 MB parse, median of 5, under load | full decode 1.26 to 1.50 s; 8-topic allow list 0.21 to 0.30 s | **0.12 to 0.22 s** | 5.5 s (sample-based file); stops after 14 records on the v1.17-based file | expected similar to px4-ulog |
| Peak RSS, 100 MB, streaming | 4.0 MiB | 4.4 MiB (file driver) | 1.16 GiB (whole parse) | expected under 10 MiB |
| Library writes to stdout | **yes**: `parser.rs:212` prints any format whose name contains `heartbeat` (fired on `telemetry_heartbeat` in `sample_log_small.ulg`); corrupts `sfr --json` | no | no | no |
| Deterministic output | yes on valid input | yes on valid input; **first error on malformed formats varies run to run** (HashMap iteration in `flatten_format`: 8 different messages in 20 runs) | API is HashMaps; caller must sort | yes (BTreeMap, file order) |
| Error detail | `thiserror` enum, no byte offset | string description, no byte offset; `Completeness` enum | `thiserror` enum, no byte offset | file, byte offset, message type, field |
| Needed to meet SPEC | fork with 8 changes in 6 files (section 6.1) | fork with 6 changes plus a wrapper (section 6.2) | rewrite (section 6.3) | write it (section 6.4) |
| Main risk | silent wrong data on truncated and appended logs | fork upkeep of a fast-moving 2026 revival; flattening redesign | silent truncation on current PX4 logs | own bugs; schedule |

### 3. Evidence by question

#### 3.1 License, release, dependencies, unsafe, MSRV, build

Confirmed from each published `Cargo.toml`, `.cargo_vcs_info.json` (the commit each crate was published from), the git clones, and the crates.io API (reachable). Dependency graphs come from `cargo tree --edges normal` on a scratch project that depends on the exact version, checked against all names in `deny-list.txt`. `cargo deny --all-features check licenses bans sources advisories` was run with a copy of the repository `deny.toml`. All three crates `cargo check` cleanly on Rust 1.97.0 for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and `wasm32-unknown-unknown`. None declares `rust-version`; px4-ulog's CI tests stable and 1.85. The repository lints (`unsafe_code = forbid`, `missing_docs`, `unwrap_used`, `expect_used`, `panic`, `print_stdout`, ...) apply only to workspace members, so they matter for a crate only if it is vendored. px4-ulog's own test suite (149 tests, 3 ignored) passes at the 0.6.1 commit; its corruption tests flip bytes in `sample.ulg` but never reach the unchecked P and A branches found here.

#### 3.2 API shape

- **yule_log**: `ULogParserBuilder::new(reader).build()` gives an iterator of `Result<UlogMessage, ULogError>` over any `Read`; true streaming, one `Vec` per record. With no allow list it decodes every field of every record into `inst::Format` trees (the cost behind its 1.3 to 1.5 s per 100 MB); an allow list returns other records as `Ignored`.

- **px4-ulog**: `LogParser::consume_bytes(&[u8])` with one callback per message type; data callbacks receive `msg_id`, `multi_id`, the flattened format and a borrowed payload, and `FlattenedFormat::get_field_parser::<T>("field")` gives typed access by flattened name (`esc[5].esc_rpm`). `read_file_with_simple_callback` streams a file (seeking to appended sections) and returns `Completeness`. `full_parser::read_file` loads everything into HashMaps.

- **ulog-rs**: `ULog::parse(reader)` parses everything into HashMaps and per-field column vectors; nothing is available until the whole file is parsed.

#### 3.3 Truncated input

`sample.ulg` (4,053,364 bytes) was cut at 10 seeded random offsets (Python `random.Random(20261018)`), mid-message (inside D record #5000 at byte 307024), at the following clean boundary, inside the header, inside FlagBits, mid definitions, at the first subscription and one byte short of the end. Each run had a 60 s timeout and a 4 GiB address-space limit. No crate panicked or hung on any cut.

| cut at byte | where | pyulog 1.2.4 | yule_log 0.4.0 | px4-ulog 0.6.1 | ulog-rs 0.0.4 |
|---|---|---|---|---|---|
| 0 | empty | error returned | error returned | OK, 0 D Complete | error returned |
| 15 | inside 16-byte header | error returned | error returned | OK, 0 D Truncated | error returned |
| 16 | header only | OK, 0 D | OK, 0 D | OK, 0 D Complete | error returned |
| 40 | inside FlagBits | OK, 0 D | error returned | OK, 0 D Truncated | error returned |
| 3164 | mid F message (definitions) | OK, 0 D | error returned | OK, 0 D Truncated | error returned |
| 35127 | start of first A message | OK, 0 D | OK, 0 D | OK, 0 D Complete | error returned |
| 267486 | seeded random | OK, 3720 D | OK, 3721 D (**+1 vs pyulog**) | OK, 3720 D Truncated | error returned |
| 307024 | mid D message #5000 | OK, 4354 D | OK, 4355 D (**+1 vs pyulog**) | OK, 4354 D Truncated | error returned |
| 307043 | clean boundary after it | OK, 4355 D | OK, 4355 D | OK, 4355 D Complete | OK, 4355 D |
| 842618 | seeded random | OK, 12959 D | OK, 12959 D | OK, 12959 D Truncated | OK, 12959 D |
| 1381894 | seeded random | OK, 21629 D | OK, 21630 D (**+1 vs pyulog**) | OK, 21629 D Truncated | error returned |
| 1918207 | seeded random | OK, 30246 D | error returned | OK, 30246 D Truncated | error returned |
| 2106923 | seeded random | OK, 33277 D | OK, 33278 D (**+1 vs pyulog**) | OK, 33277 D Truncated | error returned |
| 3275547 | seeded random | OK, 52054 D | OK, 52055 D (**+1 vs pyulog**) | OK, 52054 D Truncated | error returned |
| 3284387 | seeded random | OK, 52195 D | error returned | OK, 52195 D Truncated | error returned |
| 3593585 | seeded random | OK, 57160 D | OK, 57161 D (**+1 vs pyulog**) | OK, 57160 D Truncated | error returned |
| 3621890 | seeded random | OK, 57611 D | error returned | OK, 57611 D Truncated | error returned |
| 3994320 | seeded random | OK, 63595 D | OK, 63596 D (**+1 vs pyulog**) | OK, 63595 D Truncated | error returned |
| 4053363 | last byte removed | OK, 64541 D | OK, 64542 D (**+1 vs pyulog**) | OK, 64541 D Truncated | error returned |

The yule_log `+1` rows are fabricated records: `DataStream::read_exact` turns `UnexpectedEof` into `Ok(0)` and `ULogParser::read_message` ignores it, so the final record is parsed from a zero-padded buffer and returned as valid data with no error. SFR cannot map that to exit code 3 without a fork. px4-ulog matched pyulog's prefix exactly on every cut and labelled each cut `Truncated`, which maps directly to exit 3.

#### 3.4 Malformed input: crafted files and mutation sweep

33 crafted files (`tools/mkbad.py`, `tools/mkbad2.py`) target each message type's length fields, array sizes, nesting and amplification. Exit codes: 0 OK, 2 error returned, 101 panic, 124 hang (timeout), 134 abort (allocation failure or stack overflow).

| input | pyulog | yule_log | px4-ulog | ulog-rs |
|---|---|---|---|---|
| `amp_formats.ulg` | ok | ok | **ABORT** | ok |
| `bad_arraysize_huge.ulg` | error | **ABORT** | error | error |
| `bad_arraysize_overflow.ulg` | error | **PANIC** | error | ok |
| `bad_logged_short.ulg` | ok | error | ok | **PANIC** |
| `bad_nested_explosion.ulg` | **HANG** | **ABORT** | **HANG** | **ABORT** |
| `bad_param_empty.ulg` | error | error | **PANIC** | error |
| `bad_param_keylen.ulg` | ok | error | **PANIC** | error |
| `bad_sub_short.ulg` | ok | error | **PANIC** | **PANIC** |
| `deep_chain.ulg` | error | **ABORT** | **ABORT** | **ABORT** |

Only rows where at least one Rust crate failed are shown; the other 24 files were handled without a crash by all three (full table in the raw outputs). `amp_formats.ulg` is 29,038 bytes: 2,000 one-line formats that each embed a 64,767-field format; px4-ulog flattens every format at the first subscription and reached the 4 GiB limit after 21.9 s. `deep_chain.ulg` nests 20,000 formats; all three Rust crates overflow the stack. `bad_nested_explosion.ulg` nests arrays of zero-size formats; px4-ulog loops (offset never grows, so its u16 overflow check never fires).

Mutation sweep: in-process, deterministic (`xorshift64`, seed derived from the case index), 3,000 cases on each of two 400 KB bases (prefixes of `sample.ulg` and the v1.17.0 log), mixing single-byte flips, 8-byte flips, random u16 size fields, byte insertion, deletion and truncation, half of them aimed at the definitions section. Panics were caught with `catch_unwind`; aborts and 20 s hangs were recorded and the sweep resumed after them.

```text
px4-ulog_sample_400k: DONE ok=1538 err=1445 panic=17  panic sites: {'src/stream_parser/file_reader.rs:419': 14, 'src/stream_parser/file_reader.rs:418': 3}
px4-ulog_sitl_400k: DONE ok=1667 err=1320 panic=13  panic sites: {'src/stream_parser/file_reader.rs:419': 10, 'src/stream_parser/file_reader.rs:418': 3}
ulog-rs_sample_400k: DONE ok=466 err=2534 panic=0  panic sites: none
ulog-rs_sitl_400k: DONE ok=1398 err=1601 panic=1  panic sites: {'src/raw_vec/mod.rs:28': 1}
yule_log_sample_400k: DONE ok=1297 err=1703 panic=0  panic sites: none
yule_log_sitl_400k: DONE ok=1320 err=1680 panic=0  panic sites: none
```

#### 3.5 Correctness against pyulog

Every log was dumped by pyulog (`tools/ref.py`, using `pyulog.ULog` directly) and by each probe in one shared text format, then compared category by category (`tools/compare.py`). Values are compared numerically (f32 widened to f64 on both sides), so `1` and `1.0` are equal. Categories: header, every initial parameter by value, in-data parameter changes (order, running timestamp, name, value), default-parameter entries, logged strings (level, timestamp, text), dropouts (timestamp, duration), topics (name, multi_id, record count), info messages (key, value). The running timestamp for dropouts and parameter changes follows pyulog: the largest data timestamp seen so far, starting at the header timestamp.

Totals over 14 logs: **px4-ulog 112 / 112**, yule_log 109 / 112 (3 differences, all on the two appended-data logs: one extra straddling `sensor_combined` record and the info-key truncation), ulog-rs 68 / 112.

For `sample.ulg`, pyulog's CLI tools agree with the probes: 493 parameters (`ulog_params`), 4 logged messages at ERROR (`ulog_messages`), 4 dropouts totalling 119 ms (`ulog_info`: count 4, max 62 ms), 15 topics, all with multi_id 0. Named values on `sample.ulg`: ATT_ACC_COMP=1, ATT_BIAS_MAX=0.05000000074505806, MC_ROLL_P=6.5, MC_PITCHRATE_P=0.14000000059604645, SYS_AUTOSTART=10020, COM_RC_LOSS_T=0.5, BAT_V_CHARGED=4.050000190734863, identical in yule_log, px4-ulog and ulog-rs.

Logs in the cross-check (name, bytes, first 16 hex of sha256):

```text
sample.ulg 4053364 81952e6059bc0957
sample_appended.ulg 4548191 029136ccf20f5af2
sample_appended_multiple.ulg 486737 daf30f3224303e39
sample_log_small.ulg 921631 68d1020f688109f0
sample_logging_tagged_and_default_params.ulg 1942808 32f564608d46caf5
sample_px4_events.ulg 1563146 4b43a23a7b7f6490
sitl_v1170_attempt1.ulg 9158705 4578b6e9f0a10dff
v1.14.4_mc_flight.ulg 30583745 9324d50388738054
v1.17.0_failsafe_battery_empty.ulg 9208891 7bd1633b26acba45
v1.17.0_failsafe_gps_loss.ulg 10217078 5ce6ca4963b231d3
v1.17.0_mc_flight_1.ulg 8536869 6e7b6956c20422aa
v1.17.0_mc_flight_2.ulg 9727973 05592a1bc28c9f82
v1.17.0_vtol_transition.ulg 24295307 86d64e54d1261991
v1.17.0_vtol_transition_abort.ulg 15324267 13489ca66b7c1023
syn100_sample.ulg 104485139 8d5a4dc10bd8ff5a
syn100_sitl.ulg 99762405 4290940492214457
```

#### 3.6 Parse time and memory

Wall time is the median of 5 runs and covers process start, reading the file (in-memory modes) and the parse, plus the probe's per-record bookkeeping; it does not include hashing. Peak RSS was measured with a small Rust wrapper calling `getrusage(RUSAGE_CHILDREN)` (floor: 2.2 MiB for `/bin/true`). The 100 MB inputs repeat the data section of a real log (subscriptions dropped from the repeats) and were parsed by pyulog with the expected record counts. **All numbers were measured under load from the concurrent SITL flights.**

| input | yule_log full decode | yule_log, 8 SFR topics | px4-ulog in memory | px4-ulog streaming file | ulog-rs | pyulog |
|---|---|---|---|---|---|---|
| sample.ulg, 4.1 MB | 0.075 s | 0.021 s | 0.012 s | 0.016 s | 0.212 s | 0.227 s |
| v1.17.0 SITL, 9.2 MB | 0.134 s | 0.043 s | 0.026 s | 0.017 s | (stops after 14 records) | 0.288 s |
| synthetic from sample.ulg, 104.5 MB | 1.340 s (stream 1.399 s) | 0.244 s | 0.220 s | 0.156 s | 5.506 s, 1.16 GiB | 2.607 s (1 run) |
| synthetic from v1.17.0, 99.8 MB | 1.501 s (stream 1.262 s) | 0.212 s | 0.190 s | 0.119 s | (stops after 14 records) | 1.838 s (1 run) |
| peak RSS, 100 MB | 101 to 106 MiB in memory; **4.0 MiB streaming** | 3.9 to 4.2 MiB streaming | 101 to 105 MiB | **4.3 to 4.5 MiB** | 1.16 GiB | 219 to 224 MiB |

The 8 SFR topics used for the allow list: vehicle_status, failsafe_flags, vehicle_command, vehicle_command_ack, vtol_vehicle_status, event, vehicle_gps_position, sensor_gps (final names come from DIAGNOSTIC, not from this list).

### 4. SPEC B1.5 needs and where they live in ULog

| B1.5 item | ULog source | yule_log | px4-ulog | ulog-rs | in-house |
|---|---|---|---|---|---|
| SHA-256, BLAKE3, file size | raw bytes (outside the parser) | n/a | n/a; chunked `consume_bytes` lets one pass feed hashers and parser | n/a | one pass: same chunks to hashers and parser |
| Firmware version and git hash | info `ver_sw` (git hash), `ver_sw_release` (packed u32: 17891583 = v1.17.0 release, 17695999 = v1.14.4 release), `ver_sw_branch`; the 16-byte file header holds only the format version and start timestamp | yes | yes (wrapper decodes `char[N]`, `uint32_t`) | yes | yes |
| Vehicle type | data field (for example `vehicle_status`), name per DIAGNOSTIC | typed decode | typed field parser by name | column vectors | typed field lookup |
| Full parameter set at log start | P records in the definitions section | yes | yes | yes when it parses | yes |
| ARM, DISARM, NAV_STATE_CHANGE, FAILSAFE_*, COMMAND and ACK, VTOL_* | data records of the topics named in DIAGNOSTIC | yes | yes | only on logs it parses fully | yes, decode only subscribed topics |
| PARAM_CHANGED_IN_FLIGHT | P records after the data section starts, with the running timestamp | yes (caller tracks timestamp) | yes (`LogStage::Data`) | no timestamps, order lost | yes |
| LOG_MESSAGE at warning or above | L and C records, level byte `'0'` to `'4'` | yes | yes | yes | yes |
| LOG_DROPOUT (duration) | O records | via `Display` only | yes | yes | yes |
| Ordering: boot time, topic, instance, message index | record timestamp, subscription name, multi_id, per-subscription counter | derivable | derivable | derivable | provided directly |
| Multi-instance filtering | multi_id per subscription (A) | yes | yes | yes | yes |
| UTC time when GPS is available | a GPS topic field, or info `boot_time_utc_us` (present in the v1.17.0 logs) | yes | yes | yes | yes |
| PX4 v1.14 to v1.17 | format stable; tested v1.14.4 and v1.17.0 SITL | matches pyulog | matches pyulog | fails on both | parity tests on golden logs |
| Exit 3 for malformed or truncated input | framing, length checks | truncation not detected (fabricated record) | `Completeness::Truncated` or `MalformedRecord`; wrapper rejects empty input | inconsistent | typed error with byte offset |

### 5. SPEC B1.10 gates per option

| gate | yule_log | px4-ulog | ulog-rs | in-house |
|---|---|---|---|---|
| Fuzzing: zero panics, hangs, OOM | FAIL (panic, 2 allocation aborts, stack overflow) | FAIL (3 panic sites, hang, OOM, stack overflow) | FAIL (2 panics, aborts) | designed to pass; unproven until the fuzz target runs 10 min clean |
| No network (deny list) | PASS (25 deps, none listed) | PASS (1 dep) | PASS (34 deps, none listed) | PASS (0 deps) |
| No unsafe in Inquiro crates (deps may have audited unsafe) | PASS as a dependency (2 sound blocks to audit); FAIL if vendored | PASS | PASS (libc in deps) | PASS |
| Deterministic output | PASS on valid input; truncated input yields fabricated data | PASS on valid input; error text on malformed formats varies between runs | needs sorting of HashMap output | PASS by design |
| 100 MB seal under 2 s (x86_64) | risky: 1.26 to 1.50 s for the parse alone with full decode; 0.21 to 0.30 s with an allow list | PASS: 0.12 to 0.22 s | FAIL: 5.5 s | expected PASS |
| Errors name file, topic, field; no panics | FAIL (no offsets; panics) | FAIL as published (no offsets; panics); wrapper can add offsets | FAIL | PASS by design |
| Supply chain (`cargo deny`) | PASS | PASS | FAIL (MPL-2.0) | PASS |
| Static musl and WASM builds | PASS | PASS | PASS | expected PASS |

### 6. Exactly what each option needs

#### 6.1 yule_log 0.4.0 (rejected): fork changes required

1. `src/tokenizer.rs:79`: `parse::<usize>().unwrap()` panics on an oversized array length; return an error.
2. `src/field_helpers.rs:85`: `Vec::with_capacity(array_size)` aborts on a hostile size; bound by the bytes remaining in the record.
3. `src/parser.rs` `parse_data_message_sub` and `parse_field_value`: add a nesting-depth limit and reject zero-size nested formats (stack overflow, allocation abort).
4. `src/datastream.rs` `read_exact` plus `ULogParser::read_message`: a short read must be a `Truncated` error, not `Ok(0)` with a zero-padded record.
5. `src/parser.rs:212`: delete `println!("Heartbeat {format}")`.
6. `src/parser.rs` `parse_info`, `parse_multi_info`: split the key on the first space (as pyulog does) instead of the regex tokenizer, which drops everything after `-`.
7. Appended data: parse the sections after each appended offset instead of stopping at the first, and discard the record that straddles an offset.
8. Drop the library dependency on `env_logger` (it pulls `jiff`, `anstream`, `regex`); replace the two `unsafe` casts with safe code if vendored.

#### 6.2 px4-ulog 0.6.1 (runner-up): fork changes plus wrapper

Fork (vendored as a workspace crate, since `deny.toml` forbids git sources):

1. `src/stream_parser/file_reader.rs:403-406` (AddLoggedMessage): return an error when `msg.data.len() < 3` (panic at line 406).
2. `file_reader.rs:416-419` (Parameter): return an error when `msg.data` is empty or shorter than `1 + key_len` (panics at 418 and 419; all 30 sweep panics).
3. `file_reader.rs:1007` `add_flattened_message`: add a depth limit (stack overflow on `deep_chain.ulg`). Observed maximum nesting in the 14 real logs is 2 levels.
4. `file_reader.rs:934` `flatten_data_type` and `:970` `flatten_field`: reject nested formats whose flattened size is 0 bytes (hang on `bad_nested_explosion.ulg`).
5. `file_reader.rs:293` `transition_to_data_section_if_necessary`: flatten only the formats reachable from subscriptions, at `register_msg_id`, instead of `flatten_format` over every format; or cap the total flattened fields (OOM on the 29 KB `amp_formats.ulg`). This also stops a log being rejected because an unsubscribed format is unresolvable (pyulog and yule_log accept such a file).
6. `file_reader.rs:30` and `:107`: `HashMap` to `BTreeMap` so the first error is deterministic.
7. Lints if vendored: 5 `expect` in `src/unpack/mod.rs`, 3 `unwrap`, the `panic!` in `src/stream_parser/model.rs:37` (unreachable for u16 sizes), and 167 `missing_docs`.

Wrapper in `sfr-core` (no fork needed for these):

- Frame records itself (2-byte size, 1-byte type) and pass one record per `consume_bytes` call, so every error carries the byte offset and message type.
- Require a valid header, FlagBits and at least one subscription; px4-ulog returns `Ok` with `Complete` or `Truncated` for empty, 15-byte and 16-byte inputs.
- Feed appended sections in order and call `clear_leftover()` at each offset (as `raw_parser` does), so one sequential pass works on a stream.
- Track the running timestamp (largest data timestamp so far, starting at the header timestamp) for dropouts and in-data parameter changes.
- Map `Completeness::Truncated` and `MalformedRecord` to `Error::Malformed { file, offset, reason }` and exit 3.

#### 6.3 ulog-rs 0.0.4 (rejected)

`src/lib.rs` `parse_data` returns `Ok(())` on any unexpected type byte, so a misframed record (from its incomplete nested-type and char-array size accounting) silently ends the parse: 14 of 103,604 data records and 0 of 15 logged strings on the v1.17.0 log, with `Ok`. It rejects every log with the DATA_APPENDED bit (`read_flag_bits`), underflows `msg_size - 9` and `msg_size - 3` (capacity-overflow panics), keeps all data in memory (1.16 GiB for 100 MB), and puts clap, dirs and serde_json into a library. Making it fit is a rewrite.

#### 6.4 Option 4: in-house parser, design rules, estimate, risk

Design rules, each closing a failure observed above:

- Read through a bounds-checked cursor; never index or slice unchecked; every read returns `Result` with the byte offset (closes px4-ulog 406/418/419, ulog-rs underflows). Enforced by the repo clippy lints plus `clippy::indexing_slicing`.
- A record whose declared size exceeds the bytes left is `Truncated { offset }`, never a padded record (closes the yule_log fabricated record).
- Formats in a `BTreeMap`; flatten lazily at subscription time only; nesting depth limit 8 (observed maximum 2); flattened size computed with checked arithmetic and at most 65,535 bytes (a record payload cannot be larger); reject zero-size nested types and non-numeric or overflowing array lengths (closes the hang, the OOM amplification, the stack overflows, the tokenizer unwrap and the `with_capacity` abort). Observed maxima in 14 logs: 256 flattened fields, array length 249, 145 formats, largest payload 17,453 bytes.
- Info, multi-info and parameter keys split on the first space, as pyulog does (closes the yule_log key truncation).
- No printing, no logging dependency, zero dependencies.
- Appended sections parsed sequentially from the FlagBits offsets; the record straddling an offset is dropped, as pyulog does.
- Empty, short and header-only inputs are typed errors; unknown incompat flag bits are rejected (pyulog behaviour); unknown message types are skipped by size.
- Records exposed as borrowed `(msg_id, multi_id, timestamp, payload)` with a typed field lookup by flattened name, so event extraction decodes only the topics it needs (the allow-list effect: about 5 times faster in yule_log).

Estimate: about 700 to 900 lines (framing, header and flags 80; formats and bounded flattening 220; info, multi-info, parameters, defaults 140; subscriptions and data records with field lookup 160; logged strings, dropouts, sync, remove 60; appended sections and truncation 60; errors with offsets 60; the `FlightLogIngestor` trait 40) and 500 to 700 lines of tests. Plan: day 1 framing, header, definitions and limits; day 2 data records, appended sections, errors; day 3 parity tests against pyulog-generated expected files for the 14 logs here plus the Chunk 1 golden logs, and a differential test against px4-ulog (dev-dependency; it and byteorder pass the deny list and `cargo deny`); day 4 cargo-fuzz target to 10 minutes clean, clippy and docs; day 5 buffer.

Risks: (1) our own semantic bugs in rarely used corners (padding rules, char arrays, multi-info continuation, appended data): mitigated by the 112-check pyulog parity suite and the px4-ulog differential fuzz, both of which exist now; (2) schedule: 3 to 5 days against 1.5 to 2.5 for the px4-ulog fork; (3) ULog format changes: the format has been stable at version 1, unknown message types are skipped and unknown incompat bits are rejected, so a future change fails loudly.

Risk of each crate, for the record: yule_log, silent wrong data (fabricated records, mangled keys, missing appended data) that would be sealed as truth; px4-ulog, a fork of a crate revived in June 2026 with three releases in five days and changing APIs, plus crash classes in its core; ulog-rs, silent truncation on every current PX4 log tested.

### 7. Findings for other diagnostic items

- **Firmware identity is in info messages, not the file header.** B1.5 says "firmware version and git hash from the ULog header"; the 16-byte header holds only the format version and start timestamp. Use `ver_sw` (git hash) and `ver_sw_release` (packed version, last byte 255 = release).
- **P records after the data section starts are not all in-flight changes.** In 6 of the 7 v1.17.0 SITL logs, 17 to 25 P records arrive right after the subscriptions, before any data timestamp advances (calibration IDs such as `CAL_ACC0_ID` written at boot); in the v1.14.4 log all 662 in-data P records arrive there. PARAM_CHANGED_IN_FLIGHT should be windowed by ARM and DISARM and compared against the previous value. Windowing alone is not enough: in the attempt1 v1.17.0 log, `CAL_BARO0_ID`, `CAL_BARO0_OFF` (0.0 to -12.207) and `CAL_BARO0_PRIO` are rewritten by the firmware at 5.408 s, after `Armed by internal command` at 4.784 s; whether such firmware-written calibration counts as an in-flight change is a Chunk 1 decision.
- **Warnings are L strings in these logs.** In `sample_px4_events.ulg` the two WARNING messages are L records; pyulog decodes 8 PX4 events per log (all INFO) from the `event` topic plus `metadata_events` (xz-compressed JSON). Decoding events in Rust needs an xz decoder and a libevents formatter; decide in Chunk 1 whether LOG_MESSAGE needs events. pyulog's `PX4Events` downloads default metadata from an S3 URL when a log has none; offline scripts must override that callback (as `tools/ev.py` does).
- **Logged strings contain control bytes**, for example `\x1b[32mReady for takeoff!\x1b[0m` and a trailing tab in `Armed by internal command`. RECORD_FORMAT should decide whether text is kept verbatim (JCS escapes control characters) or normalised.

### 8. Method notes and limits

- The probes print one shared text format; probe bookkeeping (BTreeMap counting per record) is included in their times.
- The mutation sweep is a deterministic stand-in for the cargo-fuzz gate (cargo-fuzz is not installed here); coverage-guided fuzzing would find more, not fewer, failures.
- Two harness bugs were found and fixed during the run, and the affected numbers were re-measured: the px4-ulog probe initially started its running timestamp at 0 instead of the header timestamp, and the yule_log streaming probe initially read the whole file before streaming (which inflated its peak RSS).
- The ulog-rs v1.17.0 timings are not meaningful because it stops after 14 records.

### 9. Reproduction

```text
$SCRATCH = /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad
Probes (exact versions from crates.io):  $SCRATCH/work/parsers/{yule_log,px4-ulog,ulog-rs}/  (src/main.rs = probe, src/bin/mutate.rs = sweep)
Reference dump:                          $SCRATCH/work/parsers/tools/ref.py      (python3 -I, pyulog 1.2.4)
Comparison:                              $SCRATCH/work/parsers/tools/compare.py
Crafted inputs:                          $SCRATCH/work/parsers/tools/mkbad.py, mkbad2.py -> inputs/bad/
Truncation offsets:                      $SCRATCH/work/parsers/tools/offsets.py (seed 20261018)
Sweep driver:                            $SCRATCH/work/parsers/tools/sweep.sh
Synthetic 100 MB logs:                   $SCRATCH/work/parsers/tools/mksyn.py
Timing / RSS:                            $SCRATCH/work/parsers/tools/timing.py, tools/rsswrap (getrusage)
All raw outputs:                         $SCRATCH/work/parsers/out/
Pinned log copies:                       $SCRATCH/work/parsers/inputs/ (sitl_v1170_attempt1.ulg, sitl/*.ulg, syn100_*.ulg)
```

### 10. Raw outputs

<details>
<summary>pyulog CLI on sample.ulg (ulog_info, ulog_params, ulog_messages)</summary>

```text
$ ulog_info -v sample.ulg
Logging start time: 0:01:52, duration: 0:01:08
Dropouts: count: 4, total duration: 0.1 s, max: 62 ms, mean: 29 ms
Info Messages:
 sys_name: PX4
 time_ref_utc: 0
 ver_hw: AUAV_X21
 ver_sw: fd483321a5cf50ead91164356d15aa474643aa73

Name (multi id, message size in bytes)    number of data points, total bytes
 actuator_controls_0 (0, 48)                 3269     156912
 actuator_outputs (0, 76)                    1311      99636
 commander_state (0, 9)                       678       6102
 control_state (0, 122)                      3268     398696
 cpuload (0, 16)                               69       1104
 ekf2_innovations (0, 140)                   3271     457940
 estimator_status (0, 309)                   1311     405099
 sensor_combined (0, 72)                    17070    1229040
 sensor_preflight (0, 16)                   17072     273152
 telemetry_status (0, 36)                      70       2520
 vehicle_attitude (0, 36)                    6461     232596
 vehicle_attitude_setpoint (0, 55)           3272     179960
 vehicle_local_position (0, 123)              678      83394
 vehicle_rates_setpoint (0, 24)              6448     154752
 vehicle_status (0, 45)                       294      13230

$ ulog_params sample.ulg | wc -l
493
$ ulog_params sample.ulg | grep -E '^(ATT_ACC_COMP|ATT_BIAS_MAX|MC_ROLL_P|MC_PITCHRATE_P|SYS_AUTOSTART|COM_RC_LOSS_T|BAT_V_CHARGED),'
ATT_ACC_COMP,1
ATT_BIAS_MAX,0.05000000074505806
BAT_V_CHARGED,4.050000190734863
COM_RC_LOSS_T,0.5
MC_PITCHRATE_P,0.14000000059604645
MC_ROLL_P,6.5
SYS_AUTOSTART,10020
$ ulog_params -t sample.ulg (changed parameters with timestamps, first 8 lines)
ATT_ACC_COMP,1
timestamp,0
ATT_BIAS_MAX,0.05000000074505806
timestamp,0
ATT_EXT_HDG_M,0
timestamp,0
ATT_MAG_DECL,0.0
timestamp,0
Traceback (most recent call last):
  File "/usr/local/bin/ulog_params", line 8, in <module>
    sys.exit(main())
             ~~~~^^
  File "/usr/local/lib/python3.13/dist-packages/pyulog/params.py", line 73, in main
    output_file.write(str(params[param_key]))
    ~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^^^^^^^^^^
BrokenPipeError: [Errno 32] Broken pipe

$ ulog_messages sample.ulg
0:02:38.215 ERROR: [sensors] no barometer found on /dev/baro0 (2)
0:02:42.073 ERROR: [sensors] no barometer found on /dev/baro0 (2)
0:02:51.624 ERROR: [sensors] no barometer found on /dev/baro0 (2)
0:02:56.408 ERROR: [sensors] no barometer found on /dev/baro0 (2)
```

</details>

<details>
<summary>Release metadata, git tags, crates.io API, unsafe in crate sources</summary>

```text
yule_log-0.4.0 .cargo_vcs_info.json: {"git":{"sha1":"3a8817b1c07f4d272250db96ff47b46b3b69ee5d"},"path_in_vcs":"core"}
px4-ulog-0.6.1 .cargo_vcs_info.json: {"git":{"sha1":"3b273067a8532516e7185bd09f5c715b98c3b222"},"path_in_vcs":""}
ulog-rs-0.0.4 .cargo_vcs_info.json: {"git":{"sha1":"202c5aa3829fc458e75456a436a0b376d97b35f7"},"path_in_vcs":""}
yule_log 0.4.0 commit 3a8817b1c07f4d272250db96ff47b46b3b69ee5d 2025-11-13 10:40:47 -0500 Change representation of Format name fields from String to Shared<str>.
px4-ulog 0.6.1 commit 3b273067a8532516e7185bd09f5c715b98c3b222 2026-06-24 14:56:40 -0700 release: 0.6.1
ulog-rs 0.0.4 commit 202c5aa3829fc458e75456a436a0b376d97b35f7 2025-01-16 17:26:36 -0500 Merge pull request #17 from BWStearns/serde
repo-yule_log tags: latest_perf_impr vecu8_pool v0.3.3 v0.3.2 v0.3.1  | commits: 99 | last commit: 2025-11-13
repo-px4-ulog-rs tags: v0.6.1 v0.6.0 v0.5.0  | commits: 74 | last commit: 2026-06-25
repo-ulog-rs tags:  | commits: 62 | last commit: 2025-01-16
px4-ulog CI matrix: 33:        rust: [stable, "1.85"]
crates.io yule_log: max_version 0.4.0 updated 2025-11-13 downloads 4278 | versions: 0.4.0 2025-11-13 rust_version=None, 0.3.3 2025-10-03 rust_version=None, 0.3.2 2025-09-25 rust_version=None, 0.3.1 2025-09-23 rust_version=None, 0.3.0 2025-09-23 (yanked) rust_version=None
crates.io px4-ulog: max_version 0.6.1 updated 2026-06-24 downloads 5669 | versions: 0.6.1 2026-06-24 rust_version=None, 0.6.0 2026-06-24 rust_version=None, 0.5.0 2026-06-19 rust_version=None, 0.1.1 2018-12-03 rust_version=None, 0.1.0 2018-11-30 rust_version=None
crates.io ulog-rs: max_version 0.0.4 updated 2025-01-16 downloads 3675 | versions: 0.0.4 2025-01-16 rust_version=None, 0.0.3 2025-01-15 rust_version=None, 0.0.2 2024-12-31 rust_version=None, 0.0.1 2024-12-31 rust_version=None
yule_log-0.4.0: edition edition = "2021" rust-version: none | unsafe (word) in crate .rs files: 2
yule_log-0.4.0/src/encode.rs:370:                let bytes: &[u8] = unsafe {
yule_log-0.4.0/src/model.rs:450:        unsafe { std::slice::from_raw_parts(self.as_ptr() as *const u8, self.len()) }
px4-ulog-0.6.1: edition edition = "2021" rust-version: none | unsafe (word) in crate .rs files: 1
px4-ulog-0.6.1/tests/regression_bugs.rs:142:// for special values before replacing the unsafe block.
ulog-rs-0.0.4: edition edition = "2021" rust-version: none | unsafe (word) in crate .rs files: 0
```

</details>

<details>
<summary>Dependency graphs (cargo tree --edges normal) and deny-list check</summary>

```text
yule_log: 25 transitive runtime dependencies (normal edges, excluding the probe and the crate); deny-list (74 names) hits: none
   aho-corasick anstream anstyle anstyle-parse anstyle-query byteorder colorchoice env_filter env_logger is_terminal_polyfill jiff jiff-core lazy_static log memchr proc-macro2 quote regex regex-automata regex-syntax syn thiserror thiserror-impl unicode-ident utf8parse
px4-ulog: 1 transitive runtime dependencies (normal edges, excluding the probe and the crate); deny-list (74 names) hits: none
   byteorder
ulog-rs: 33 transitive runtime dependencies (normal edges, excluding the probe and the crate); deny-list (74 names) hits: none
   anstream anstyle anstyle-parse anstyle-query byteorder bytes clap clap_builder clap_derive clap_lex colorchoice dirs dirs-sys heck is_terminal_polyfill itoa libc log memchr option-ext proc-macro2 quote serde serde_core serde_derive serde_json strsim syn thiserror thiserror-impl unicode-ident utf8parse zmij

== yule_log
probe-yule-log v0.1.0 ($SCRATCH/work/parsers/yule_log)
└── yule_log v0.4.0
    ├── byteorder v1.5.0
    ├── env_logger v0.11.11
    │   ├── anstream v1.0.0
    │   │   ├── anstyle v1.0.14
    │   │   ├── anstyle-parse v1.0.0
    │   │   │   └── utf8parse v0.2.2
    │   │   ├── anstyle-query v1.1.5
    │   │   ├── colorchoice v1.0.5
    │   │   ├── is_terminal_polyfill v1.70.2
    │   │   └── utf8parse v0.2.2
    │   ├── anstyle v1.0.14
    │   ├── env_filter v2.0.0
    │   │   ├── log v0.4.34
    │   │   └── regex v1.13.1
    │   │       ├── aho-corasick v1.1.5
    │   │       │   └── memchr v2.8.3
    │   │       ├── memchr v2.8.3
    │   │       ├── regex-automata v0.4.18
    │   │       │   ├── aho-corasick v1.1.5 (*)
    │   │       │   ├── memchr v2.8.3
    │   │       │   └── regex-syntax v0.8.11
    │   │       └── regex-syntax v0.8.11
    │   ├── jiff v0.2.38
    │   │   └── jiff-core v0.1.1
    │   └── log v0.4.34
    ├── lazy_static v1.5.1
    ├── log v0.4.34
    ├── regex v1.13.1 (*)
    └── thiserror v1.0.69
        └── thiserror-impl v1.0.69 (proc-macro)
            ├── proc-macro2 v1.0.107
            │   └── unicode-ident v1.0.27
            ├── quote v1.0.47
            │   └── proc-macro2 v1.0.107 (*)
            └── syn v2.0.119
                ├── proc-macro2 v1.0.107 (*)
                ├── quote v1.0.47 (*)
                └── unicode-ident v1.0.27

== px4-ulog
probe-px4-ulog v0.1.0 ($SCRATCH/work/parsers/px4-ulog)
└── px4-ulog v0.6.1
    └── byteorder v1.5.0

== ulog-rs
probe-ulog-rs v0.1.0 ($SCRATCH/work/parsers/ulog-rs)
└── ulog-rs v0.0.4
    ├── byteorder v1.5.0
    ├── bytes v1.12.1
    ├── clap v4.6.7
    │   ├── clap_builder v4.6.7
    │   │   ├── anstream v1.0.0
    │   │   │   ├── anstyle v1.0.14
    │   │   │   ├── anstyle-parse v1.0.0
    │   │   │   │   └── utf8parse v0.2.2
    │   │   │   ├── anstyle-query v1.1.5
    │   │   │   ├── colorchoice v1.0.5
    │   │   │   ├── is_terminal_polyfill v1.70.2
    │   │   │   └── utf8parse v0.2.2
    │   │   ├── anstyle v1.0.14
    │   │   ├── clap_lex v1.1.1
    │   │   └── strsim v0.11.1
    │   └── clap_derive v4.6.7 (proc-macro)
    │       ├── heck v0.5.0
    │       ├── proc-macro2 v1.0.107
    │       │   └── unicode-ident v1.0.27
    │       ├── quote v1.0.47
    │       │   └── proc-macro2 v1.0.107 (*)
    │       └── syn v3.0.9
    │           ├── proc-macro2 v1.0.107 (*)
    │           ├── quote v1.0.47 (*)
    │           └── unicode-ident v1.0.27
    ├── dirs v5.0.1
    │   └── dirs-sys v0.4.1
    │       ├── libc v0.2.191
    │       └── option-ext v0.2.0
    ├── log v0.4.34
    ├── serde v1.0.229
    │   └── serde_core v1.0.229
    ├── serde_derive v1.0.229 (proc-macro)
    │   ├── proc-macro2 v1.0.107 (*)
    │   ├── quote v1.0.47 (*)
    │   └── syn v3.0.9 (*)
    ├── serde_json v1.0.154
    │   ├── itoa v1.0.18
    │   ├── memchr v2.8.3
    │   ├── serde_core v1.0.229
    │   └── zmij v1.0.23
    └── thiserror v1.0.69
        └── thiserror-impl v1.0.69 (proc-macro)
            ├── proc-macro2 v1.0.107 (*)
            ├── quote v1.0.47 (*)
            └── syn v2.0.119
                ├── proc-macro2 v1.0.107 (*)
                ├── quote v1.0.47 (*)
                └── unicode-ident v1.0.27
```

</details>

<details>
<summary>unsafe occurrences in each transitive runtime dependency (word count over .rs files)</summary>

```text
-- yule_log
   aho-corasick-1.1.5          unsafe occurrences: 227
   anstream-1.0.0          unsafe occurrences: 3
   anstyle-1.0.14         unsafe occurrences: 1
   anstyle-parse-1.0.0          unsafe occurrences: 3
   anstyle-query-1.1.5          unsafe occurrences: 1
   byteorder-1.5.0          unsafe occurrences: 44
   colorchoice-1.0.5          unsafe occurrences: 0
   env_filter-2.0.0          unsafe occurrences: 0
   env_logger-0.11.11        unsafe occurrences: 0
   is_terminal_polyfill-1.70.2         unsafe occurrences: 0
   jiff-0.2.38         unsafe occurrences: 79
   jiff-core-0.1.1          unsafe occurrences: 2
   lazy_static-1.5.1          unsafe occurrences: 4
   log-0.4.34         unsafe occurrences: 8
   memchr-2.8.3          unsafe occurrences: 340
   proc-macro2-1.0.107        unsafe occurrences: 6
   quote-1.0.47         unsafe occurrences: 0
   regex-1.13.1         unsafe occurrences: 1
   regex-automata-0.4.18         unsafe occurrences: 57
   regex-syntax-0.8.11         unsafe occurrences: 0
   syn-2.0.119        unsafe occurrences: 104
   thiserror-1.0.69         unsafe occurrences: 0
   thiserror-impl-1.0.69         unsafe occurrences: 1
   unicode-ident-1.0.27         unsafe occurrences: 2
   utf8parse-0.2.2          unsafe occurrences: 1
-- px4-ulog
   byteorder-1.5.0          unsafe occurrences: 44
-- ulog-rs
   anstream-1.0.0          unsafe occurrences: 3
   anstyle-1.0.14         unsafe occurrences: 1
   anstyle-parse-1.0.0          unsafe occurrences: 3
   anstyle-query-1.1.5          unsafe occurrences: 1
   byteorder-1.5.0          unsafe occurrences: 44
   bytes-1.12.1         unsafe occurrences: 171
   clap-4.6.7          unsafe occurrences: 0
   clap_builder-4.6.7          unsafe occurrences: 5
   clap_derive-4.6.7          unsafe occurrences: 0
   clap_lex-1.1.1          unsafe occurrences: 6
   colorchoice-1.0.5          unsafe occurrences: 0
   dirs-5.0.1          unsafe occurrences: 0
   dirs-sys-0.4.1          unsafe occurrences: 4
   heck-0.5.0          unsafe occurrences: 0
   is_terminal_polyfill-1.70.2         unsafe occurrences: 0
   itoa-1.0.18         unsafe occurrences: 13
   libc-0.2.191        unsafe occurrences: 811
   log-0.4.34         unsafe occurrences: 8
   memchr-2.8.3          unsafe occurrences: 340
   option-ext-0.2.0          unsafe occurrences: 0
   proc-macro2-1.0.107        unsafe occurrences: 6
   quote-1.0.47         unsafe occurrences: 0
   serde-1.0.229        unsafe occurrences: 2
   serde_core-1.0.229        unsafe occurrences: 2
   serde_derive-1.0.229        unsafe occurrences: 0
   serde_json-1.0.154        unsafe occurrences: 20
   strsim-0.11.1         unsafe occurrences: 0
   syn-2.0.119        unsafe occurrences: 104
   syn-3.0.9          unsafe occurrences: 108
   thiserror-1.0.69         unsafe occurrences: 0
   thiserror-impl-1.0.69         unsafe occurrences: 1
   unicode-ident-1.0.27         unsafe occurrences: 2
   utf8parse-0.2.2          unsafe occurrences: 1
   zmij-1.0.23         unsafe occurrences: 70
```

</details>

<details>
<summary>cargo deny with the repository deny.toml</summary>

```text
=============== cargo deny yule_log
bans ok, licenses ok, sources ok
exit 0
--- advisories
advisories ok
exit 0
=============== cargo deny px4-ulog
bans ok, licenses ok, sources ok
exit 0
--- advisories
advisories ok
exit 0
=============== cargo deny ulog-rs
         └── ulog-rs v0.0.4 (*)

warning[duplicate]: found 2 duplicate entries for crate 'windows-sys'
   ┌─ $SCRATCH/work/parsers/ulog-rs/Cargo.lock:44:1
   │  
44 │ ╭ windows-sys 0.48.0 registry+https://github.com/rust-lang/crates.io-index
45 │ │ windows-sys 0.61.2 registry+https://github.com/rust-lang/crates.io-index
   │ ╰────────────────────────────────────────────────────────────────────────┘ lock entries
   │  
   ├ windows-sys v0.48.0
     └── dirs-sys v0.4.1
         └── dirs v5.0.1
             └── ulog-rs v0.0.4
                 └── probe-ulog-rs v0.1.0
   ├ windows-sys v0.61.2
     ├── anstyle-query v1.1.5
     │   └── anstream v1.0.0
     │       └── clap_builder v4.6.7
     │           └── clap v4.6.7
     │               └── ulog-rs v0.0.4
     │                   └── probe-ulog-rs v0.1.0
     └── anstyle-wincon v3.0.11
         └── anstream v1.0.0 (*)

bans ok, licenses FAILED, sources ok
exit 4
--- advisories
advisories ok
exit 0
```

</details>

<details>
<summary>cargo check for x86_64-musl, aarch64-musl, wasm32 (Rust 1.97.0)</summary>

```text
=============== yule_log --target wasm32-unknown-unknown
    Finished `release` profile [optimized + debuginfo] target(s) in 4.58s
exit 0
=============== yule_log --target x86_64-unknown-linux-musl
    Finished `release` profile [optimized + debuginfo] target(s) in 4.56s
exit 0
=============== yule_log --target aarch64-unknown-linux-musl
    Finished `release` profile [optimized + debuginfo] target(s) in 4.39s
exit 0
=============== px4-ulog --target wasm32-unknown-unknown
    Finished `release` profile [optimized + debuginfo] target(s) in 0.52s
exit 0
=============== px4-ulog --target x86_64-unknown-linux-musl
    Finished `release` profile [optimized + debuginfo] target(s) in 0.59s
exit 0
=============== px4-ulog --target aarch64-unknown-linux-musl
    Finished `release` profile [optimized + debuginfo] target(s) in 0.57s
exit 0
=============== ulog-rs --target wasm32-unknown-unknown
    Finished `release` profile [optimized + debuginfo] target(s) in 6.38s
exit 0
=============== ulog-rs --target x86_64-unknown-linux-musl
    Finished `release` profile [optimized + debuginfo] target(s) in 2.62s
exit 0
=============== ulog-rs --target aarch64-unknown-linux-musl
    Finished `release` profile [optimized + debuginfo] target(s) in 2.60s
exit 0
```

</details>

<details>
<summary>clippy on each crate library: panic-related lints, and the repository lint set</summary>

```text
=============== clippy (lib only) yule_log-0.4.0
      4 used `unwrap()` on a `Result` value
      4 redundant reference in `debug!` argument
      3 used `unwrap()` on an `Option` value
      3 slicing may panic
      3 indexing may panic
      1 this `impl` can be derived
      1 field `overridden_params` is never read
      1 doc list item overindented
      1 `yule_log` (lib) generated 20 warnings (run `cargo clippy --fix --lib -p yule_log -- -W clippy::all -W clippy::unwrap_used -W clippy::expect_used -W clippy::panic -W clippy::indexing_slicing` to apply 5 suggestions)
exit 0
--- default clippy (-D warnings) summary
8
=============== clippy (lib only) px4-ulog-0.6.1
     41 slicing may panic
     37 indexing may panic
      5 used `expect()` on a `Result` value
      3 used `unwrap()` on an `Option` value
      1 `px4-ulog` (lib) generated 87 warnings
      1 `panic` should not be present in production code
exit 0
--- default clippy (-D warnings) summary
0
=============== clippy (lib only) ulog-rs-0.0.4
     15 indexing may panic
      2 this block may be rewritten with the `?` operator
      2 calls to `push` immediately after creation
      1 variable does not need to be mutable
      1 used `unwrap()` on an `Option` value
      1 unused variable: `header`
      1 unused variable: `array_size`
      1 this comparison involving the minimum or maximum element for this type contains a case that is always true or always false
      1 this `if let` can be collapsed into the outer `if let`
      1 the loop variable `i` is used to index `data`
      1 fields `msg_id` and `time_us` are never read
      1 `ulog-rs` (lib) generated 27 warnings (run `cargo clippy --fix --lib -p ulog-rs -- -W clippy::all -W clippy::unwrap_used -W clippy::expect_used -W clippy::panic -W clippy::indexing_slicing` to apply 5 suggestions)
exit 0
--- default clippy (-D warnings) summary
12

== repository lint set
=============== repo lint set on px4-ulog-0.6.1 (lib only, rust 1.97)
     87 warning: missing documentation for a variant
     34 warning: missing documentation for a struct field
     27 warning: missing documentation for a method
      5 warning: used X on a X value
      5 warning: missing documentation for an associated function
      4 warning: missing documentation for an enum
      4 warning: missing documentation for a module
      3 warning: used X on an X value
      3 warning: missing documentation for a struct
      1 warning: missing documentation for the crate
      1 warning: missing documentation for a trait
      1 warning: missing documentation for a function
      1 warning: X should not be present in production code
=============== repo lint set on yule_log-0.4.0 (lib only, rust 1.97)
     97 warning: missing documentation for a variant
     52 warning: missing documentation for a struct field
     31 warning: missing documentation for a method
     21 warning: missing documentation for a struct
      8 warning: missing documentation for a module
      7 warning: missing documentation for an enum
      5 warning: missing documentation for an associated function
      4 warning: used X on a X value
      4 warning: redundant reference in X argument
      3 warning: used X on an X value
      2 warning: missing documentation for a trait
      2 error: usage of an X block
      1 warning: use of X
      1 warning: this X can be derived
      1 warning: missing documentation for the crate
=============== repo lint set on ulog-rs-0.0.4 (lib only, rust 1.97)
     55 warning: missing documentation for a struct field
     50 warning: missing documentation for a variant
     46 warning: missing documentation for a method
     11 warning: missing documentation for a struct
     10 warning: missing documentation for a module
      2 warning: unused variable: X
      2 warning: this block may be rewritten with the X operator
      2 warning: missing documentation for an enum
      2 warning: missing documentation for an associated function
      2 warning: calls to X immediately after creation
      1 warning: variable does not need to be mutable
      1 warning: used X on an X value
      1 warning: this X can be collapsed into the outer X
      1 warning: the loop variable X is used to index X
      1 warning: missing documentation for a trait
```

</details>

<details>
<summary>Truncation offsets and sweep (sample.ulg)</summary>

```text
size 4053364
messages 65199 first_A_offset 35127
random 3593585 3284387 842618 1381894 3275547 267486 3621890 1918207 2106923 3994320
mid_message 307024 msg_index 5000 type D size 38 start 307002
boundary 307043
mid_definitions 3164 type F size 274

# Truncation sweep on sample.ulg (size 4053364). Offsets: 0,15,16,40 (header area), 3164 (mid definitions F msg), 35127 (first A msg start), 10 seeded random, 307024 (mid D msg #5000), 307043 (clean boundary after it), 4053363 (last byte removed)
== cut at 0
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: TypeError: Invalid file format (Header too short) 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=1 first=Invalid Header 
px4-ulog   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=Complete 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 15
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: TypeError: Invalid file format (Header too short) 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=1 first=Invalid Header 
px4-ulog   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 16
pyulog     OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
yule_log   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
px4-ulog   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=Complete 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 40
pyulog     OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=1 first=Unexpected End of File 
px4-ulog   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 3164
pyulog     OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: Invalid format name. Expected [Identifier, Colon], got: Unknown('\0'), 
px4-ulog   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 35127
pyulog     OK               rc=0   params=493  topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
yule_log   OK               rc=0   params=493  topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
px4-ulog   OK               rc=0   params=493  topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=Complete 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 267486
pyulog     OK               rc=0   params=493  topics=15  datamsgs=3720   logged=0   dropouts=3   | STATUS ok 
yule_log   OK               rc=0   params=493  topics=15  datamsgs=3721   logged=0   dropouts=3   | STATUS ok 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=3720   logged=0   dropouts=3   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 307024
pyulog     OK               rc=0   params=493  topics=15  datamsgs=4354   logged=0   dropouts=3   | STATUS ok 
yule_log   OK               rc=0   params=493  topics=15  datamsgs=4355   logged=0   dropouts=3   | STATUS ok 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=4354   logged=0   dropouts=3   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 307043
pyulog     OK               rc=0   params=493  topics=15  datamsgs=4355   logged=0   dropouts=3   | STATUS ok 
yule_log   OK               rc=0   params=493  topics=15  datamsgs=4355   logged=0   dropouts=3   | STATUS ok 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=4355   logged=0   dropouts=3   | STATUS ok completeness=Complete 
ulog-rs    OK               rc=0   params=493  topics=15  datamsgs=4355   logged=0   dropouts=3   | STATUS ok 
== cut at 842618
pyulog     OK               rc=0   params=493  topics=15  datamsgs=12959  logged=0   dropouts=3   | STATUS ok 
yule_log   OK               rc=0   params=493  topics=15  datamsgs=12959  logged=0   dropouts=3   | STATUS ok 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=12959  logged=0   dropouts=3   | STATUS ok completeness=Truncated 
ulog-rs    OK               rc=0   params=493  topics=15  datamsgs=12959  logged=0   dropouts=3   | STATUS ok 
== cut at 1381894
pyulog     OK               rc=0   params=493  topics=15  datamsgs=21629  logged=0   dropouts=3   | STATUS ok 
yule_log   OK               rc=0   params=493  topics=15  datamsgs=21630  logged=0   dropouts=3   | STATUS ok 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=21629  logged=0   dropouts=3   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 1918207
pyulog     OK               rc=0   params=493  topics=15  datamsgs=30246  logged=0   dropouts=3   | STATUS ok 
yule_log   ERROR_RETURNED   rc=2   params=493  topics=15  datamsgs=30246  logged=0   dropouts=3   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 4 bytes, but only 0 remaining 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=30246  logged=0   dropouts=3   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 2106923
pyulog     OK               rc=0   params=493  topics=15  datamsgs=33277  logged=0   dropouts=3   | STATUS ok 
yule_log   OK               rc=0   params=493  topics=15  datamsgs=33278  logged=0   dropouts=3   | STATUS ok 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=33277  logged=0   dropouts=3   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 3275547
pyulog     OK               rc=0   params=493  topics=15  datamsgs=52054  logged=2   dropouts=4   | STATUS ok 
yule_log   OK               rc=0   params=493  topics=15  datamsgs=52055  logged=2   dropouts=4   | STATUS ok 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=52054  logged=2   dropouts=4   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 3284387
pyulog     OK               rc=0   params=493  topics=15  datamsgs=52195  logged=2   dropouts=4   | STATUS ok 
yule_log   ERROR_RETURNED   rc=2   params=493  topics=15  datamsgs=52195  logged=2   dropouts=4   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 4 bytes, but only 0 remaining 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=52195  logged=2   dropouts=4   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 3593585
pyulog     OK               rc=0   params=493  topics=15  datamsgs=57160  logged=3   dropouts=4   | STATUS ok 
yule_log   OK               rc=0   params=493  topics=15  datamsgs=57161  logged=3   dropouts=4   | STATUS ok 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=57160  logged=3   dropouts=4   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 3621890
pyulog     OK               rc=0   params=493  topics=15  datamsgs=57611  logged=3   dropouts=4   | STATUS ok 
yule_log   ERROR_RETURNED   rc=2   params=493  topics=15  datamsgs=57611  logged=3   dropouts=4   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 4 bytes, but only 0 remaining 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=57611  logged=3   dropouts=4   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 3994320
pyulog     OK               rc=0   params=493  topics=15  datamsgs=63595  logged=4   dropouts=4   | STATUS ok 
yule_log   OK               rc=0   params=493  topics=15  datamsgs=63596  logged=4   dropouts=4   | STATUS ok 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=63595  logged=4   dropouts=4   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== cut at 4053363
pyulog     OK               rc=0   params=493  topics=15  datamsgs=64541  logged=4   dropouts=4   | STATUS ok 
yule_log   OK               rc=0   params=493  topics=15  datamsgs=64542  logged=4   dropouts=4   | STATUS ok 
px4-ulog   OK               rc=0   params=493  topics=15  datamsgs=64541  logged=4   dropouts=4   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
```

</details>

<details>
<summary>Crafted adversarial inputs (all 30 files from mkbad.py)</summary>

```text
# Adversarial inputs (ulimit -v 4 GiB, timeout 60 s). Classification by exit code: 0 OK, 2 error returned, 101 panic, 124 hang, 134 abort (alloc failure or stack overflow), 139 segv.
== bad_appended_offset_garbage.ulg (147 bytes)
pyulog     OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
yule_log   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
px4-ulog   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IncompatibleFlags: [1, 0, 0, 0, 0, 0, 0, 0] 
== bad_array_u16max.ulg (124 bytes)
pyulog     OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok file_corruption 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 1 bytes, but only 0 remaining 
px4-ulog   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: invalid type string: uint8_t[65535] 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== bad_arraysize_huge.ulg (154 bytes)
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: MemoryError:  
yule_log   ABORT_SIGABRT    rc=134 params=     topics=    datamsgs=0      logged=    dropouts=    |  memory allocation of 32000000000000 bytes failed
px4-ulog   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: invalid type string: uint64_t[4000000000000] 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: Parse error: Invalid type/size combination: (UInt64, Some(4000000000000)) 
== bad_arraysize_overflow.ulg (163 bytes)
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: MemoryError:  
yule_log   PANIC            rc=101 params=     topics=    datamsgs=0      logged=    dropouts=    |  thread 'main' (17588) panicked at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/yule_log-0.4.0/src/tokenize
px4-ulog   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: invalid type string: uint8_t[99999999999999999999999] 
ulog-rs    OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
== bad_circular_format.ulg (153 bytes)
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: RecursionError: maximum recursion depth exceeded 
yule_log   ERROR_RETURNED   rc=2   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 8 bytes, but only 0 remaining 
px4-ulog   ERROR_RETURNED   rc=2   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: Found circular reference to b 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== bad_data_short.ulg (128 bytes)
pyulog     OK               rc=0   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
yule_log   ERROR_RETURNED   rc=2   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 2 bytes, but only 1 remaining 
px4-ulog   OK               rc=0   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=MalformedRecord(parse error: encountered data message which was too short) 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: Parse error: Unknown msg_id: 2560 
== bad_data_wrongsize.ulg (133 bytes)
pyulog     OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok file_corruption 
yule_log   ERROR_RETURNED   rc=2   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 8 bytes, but only 4 remaining 
px4-ulog   OK               rc=0   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=MalformedRecord(parse error: data message had wrong size 6, format: FlattenedFormat { m 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: Parse error: Read too many bytes: 10 > 6 for message foo 
== bad_default_short.ulg (111 bytes)
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: error: unpack requires a buffer of 1 bytes 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 1 bytes, but only 0 remaining 
px4-ulog   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: parameter default message too short 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: Parse error: Message types not allowed in default parameters 
== bad_dup_msgid.ulg (133 bytes)
pyulog     OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
yule_log   OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
px4-ulog   OK               rc=0   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=MalformedRecord(parse error: duplicate registration for msg_id 0, initial one: 
ulog-rs    OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
== bad_empty.ulg (0 bytes)
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: TypeError: Invalid file format (Header too short) 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=1 first=Invalid Header 
px4-ulog   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=Complete 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== bad_flagbits_short.ulg (77 bytes)
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: error: unpack requires a buffer of 8 bytes 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 8 bytes, but only 2 remaining 
px4-ulog   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: FlagBits message too small: 10 < 40 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IncompatibleFlags: [0, 0, 23, 0, 70, 102, 111, 111] 
== bad_format_noname.ulg (121 bytes)
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: KeyError: 'foo' 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=2 first=Parse error: Invalid field definition. Expected an Identifier, got: Semicolon 
px4-ulog   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: invalid type_and_name string: uint8_t[3] 
ulog-rs    OK               rc=0   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
== bad_format_utf8.ulg (119 bytes)
pyulog     OK               rc=0   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=2 first=UTF-8 Decoding Error: invalid utf-8 sequence of 1 bytes from index 31 
px4-ulog   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: format message is not a string 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: Invalid string data 
== bad_header_15.ulg (15 bytes)
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: TypeError: Invalid file format (Header too short) 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=1 first=Invalid Header 
px4-ulog   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== bad_header_only.ulg (16 bytes)
pyulog     OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
yule_log   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
px4-ulog   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=Complete 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== bad_info_keylen.ulg (129 bytes)
pyulog     OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok file_corruption 
yule_log   ERROR_RETURNED   rc=2   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 200 bytes, but only 1 remaini 
px4-ulog   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: Info message key_len exceeds message size 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== bad_logged_short.ulg (130 bytes)
pyulog     OK               rc=0   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
yule_log   ERROR_RETURNED   rc=2   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 8 bytes, but only 2 remaining 
px4-ulog   OK               rc=0   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=MalformedRecord(parse error: Logged string message was too short) 
ulog-rs    PANIC            rc=101 params=     topics=    datamsgs=0      logged=    dropouts=    |  thread 'main' (19813) panicked at /rustc/2d8144b7880597b6e6d3dfd63a9a9efae3f533d3/library/alloc/src/raw_vec/mod.rs:28:5:
== bad_msgsize_max.ulg (197 bytes)
pyulog     OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
yule_log   OK               rc=0   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
px4-ulog   OK               rc=0   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=Truncated 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== bad_multiinfo_keylen.ulg (113 bytes)
pyulog     OK               rc=0   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok file_corruption 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 200 bytes, but only 1 remaini 
px4-ulog   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: MultiInfo message key_len exceeds message size 
ulog-rs    OK               rc=0   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
== bad_nested_explosion.ulg (168 bytes)
pyulog     HANG_TIMEOUT     rc=124 params=     topics=    datamsgs=0      logged=    dropouts=    |  
yule_log   ABORT_SIGABRT    rc=134 params=     topics=    datamsgs=0      logged=    dropouts=    |  memory allocation of 2359224 bytes failed
px4-ulog   HANG_TIMEOUT     rc=124 params=     topics=    datamsgs=0      logged=    dropouts=    |  
ulog-rs    ABORT_SIGABRT    rc=134 params=     topics=    datamsgs=0      logged=    dropouts=    |  memory allocation of 786408 bytes failed
== bad_param_array.ulg (131 bytes)
pyulog     OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS error_count=1 first=Unknown Parameter Type 
px4-ulog   ERROR_RETURNED   rc=2   params=0    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: parameter message with wrong size encountered 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: Parse error: Invalid type/size combination: (Int32, Some(2)) 
== bad_param_empty.ulg (110 bytes)
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: error: unpack requires a buffer of 1 bytes 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 1 bytes, but only 0 remaining 
px4-ulog   PANIC            rc=101 params=     topics=    datamsgs=0      logged=    dropouts=    |  thread 'main' (22945) panicked at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_p
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: Parse error: Invalid parameter message key format 
== bad_param_keylen.ulg (112 bytes)
pyulog     OK               rc=0   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok file_corruption 
yule_log   ERROR_RETURNED   rc=2   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 255 bytes, but only 1 remaini 
px4-ulog   PANIC            rc=101 params=     topics=    datamsgs=0      logged=    dropouts=    |  thread 'main' (23079) panicked at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_p
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== bad_self_format.ulg (124 bytes)
pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: RecursionError: maximum recursion depth exceeded 
yule_log   ERROR_RETURNED   rc=2   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 8 bytes, but only 0 remaining 
px4-ulog   ERROR_RETURNED   rc=2   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error: parse error: Found circular reference to a 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: IO error: failed to fill whole buffer 
== bad_sub_short.ulg (119 bytes)
pyulog     OK               rc=0   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
yule_log   ERROR_RETURNED   rc=2   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: MessageBuf: Out of bounds: tried to read 2 bytes, but only 0 remaining 
px4-ulog   PANIC            rc=101 params=     topics=    datamsgs=0      logged=    dropouts=    |  thread 'main' (23347) panicked at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_p
ulog-rs    PANIC            rc=101 params=     topics=    datamsgs=0      logged=    dropouts=    |  thread 'main' (23379) panicked at /rustc/2d8144b7880597b6e6d3dfd63a9a9efae3f533d3/library/alloc/src/raw_vec/mod.rs:28:5:
== bad_unknown_msgid.ulg (137 bytes)
pyulog     OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok file_corruption 
yule_log   ERROR_RETURNED   rc=2   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS error_count=1 first=Parse error: Received logged data with an unknown msg_id 7.  Could not find a subsc 
px4-ulog   OK               rc=0   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok completeness=MalformedRecord(parse error: data message encountered unregistered msg_id: 7) 
ulog-rs    ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: Parse error: Unknown msg_id: 7 
== bad_unknown_type.ulg (130 bytes)
pyulog     OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
yule_log   OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
px4-ulog   OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok completeness=Complete 
ulog-rs    OK               rc=0   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
== bad_zero_size_zero_type.ulg (139 bytes)
pyulog     OK               rc=0   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok file_corruption 
yule_log   OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
px4-ulog   OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok completeness=Complete 
ulog-rs    OK               rc=0   params=1    topics=0   datamsgs=0      logged=0   dropouts=0   | STATUS ok 
== edge_good_minimal.ulg (170 bytes)
pyulog     OK               rc=0   params=1    topics=1   datamsgs=2      logged=0   dropouts=1   | STATUS ok 
yule_log   OK               rc=0   params=1    topics=1   datamsgs=2      logged=0   dropouts=1   | STATUS ok 
px4-ulog   OK               rc=0   params=1    topics=1   datamsgs=2      logged=0   dropouts=1   | STATUS ok completeness=Complete 
ulog-rs    OK               rc=0   params=1    topics=1   datamsgs=2      logged=0   dropouts=1   | STATUS ok 
== edge_logging_before_sub.ulg (141 bytes)
pyulog     OK               rc=0   params=1    topics=1   datamsgs=1      logged=1   dropouts=0   | STATUS ok 
yule_log   OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
px4-ulog   OK               rc=0   params=1    topics=1   datamsgs=1      logged=1   dropouts=0   | STATUS ok completeness=Complete 
ulog-rs    OK               rc=0   params=1    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok 
```

</details>

<details>
<summary>Amplification and deep-chain inputs (wall time and peak RSS via measure.py)</summary>

```text
== amp_formats.ulg
MEASURE wall_s=0.159 max_rss_kb=27076 exit=0 pyulog     OK               rc=0   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok  
MEASURE wall_s=0.042 max_rss_kb=11236 exit=0 yule_log   OK               rc=0   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok  
MEASURE wall_s=21.932 max_rss_kb=4181696 exit=0 px4-ulog   ABORT_SIGABRT    rc=134 params=     topics=    datamsgs=0      logged=    dropouts=    |  memory allocation of 7471120 bytes failed 
MEASURE wall_s=0.033 max_rss_kb=11212 exit=0 ulog-rs    OK               rc=0   params=0    topics=1   datamsgs=1      logged=0   dropouts=0   | STATUS ok  
== deep_chain.ulg
MEASURE wall_s=0.264 max_rss_kb=35460 exit=0 pyulog     ERROR_RETURNED   rc=2   params=     topics=    datamsgs=0      logged=    dropouts=    | STATUS error: RecursionError: maximum recursion depth exceeded  
MEASURE wall_s=0.134 max_rss_kb=18368 exit=0 yule_log   ABORT_SIGABRT    rc=134 params=     topics=    datamsgs=0      logged=    dropouts=    |  fatal runtime error: stack overflow, aborting 
MEASURE wall_s=0.401 max_rss_kb=410084 exit=0 px4-ulog   ABORT_SIGABRT    rc=134 params=     topics=    datamsgs=0      logged=    dropouts=    |  fatal runtime error: stack overflow, aborting 
MEASURE wall_s=0.067 max_rss_kb=24936 exit=0 ulog-rs    ABORT_SIGABRT    rc=134 params=     topics=    datamsgs=0      logged=    dropouts=    |  fatal runtime error: stack overflow, aborting 
== edge_wide_valid.ulg
MEASURE wall_s=0.316 max_rss_kb=89604 exit=0 pyulog     OK               rc=0   params=0    topics=1   datamsgs=200    logged=0   dropouts=0   | STATUS ok  
MEASURE wall_s=0.078 max_rss_kb=16696 exit=0 yule_log   OK               rc=0   params=0    topics=1   datamsgs=200    logged=0   dropouts=0   | STATUS ok  
MEASURE wall_s=0.108 max_rss_kb=46020 exit=0 px4-ulog   OK               rc=0   params=0    topics=1   datamsgs=200    logged=0   dropouts=0   | STATUS ok completeness=Complete  
MEASURE wall_s=0.059 max_rss_kb=40696 exit=0 ulog-rs    OK               rc=0   params=0    topics=1   datamsgs=200    logged=0   dropouts=0   | STATUS ok  
```

</details>

<details>
<summary>Exact panic and abort messages with source lines</summary>

```text
=== px4-ulog bad_param_empty.ulg
thread 'main' (11259) panicked at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:418:31:
index out of bounds: the len is 0 but the index is 0
rc=101
=== px4-ulog bad_param_keylen.ulg
thread 'main' (11264) panicked at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419:46:
range start index 256 out of range for slice of length 2
rc=101
=== px4-ulog bad_sub_short.ulg
thread 'main' (11269) panicked at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:406:57:
range end index 3 out of range for slice of length 1
rc=101
=== yule_log bad_arraysize_overflow.ulg
thread 'main' (11274) panicked at /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/yule_log-0.4.0/src/tokenizer.rs:79:77:
rc=101
=== yule_log bad_arraysize_huge.ulg
memory allocation of 32000000000000 bytes failed
rc=134
=== yule_log bad_nested_explosion.ulg
memory allocation of 2359224 bytes failed
rc=134
=== ulog-rs bad_logged_short.ulg
thread 'main' (11670) panicked at /rustc/2d8144b7880597b6e6d3dfd63a9a9efae3f533d3/library/alloc/src/raw_vec/mod.rs:28:5:
capacity overflow
rc=101
=== ulog-rs bad_sub_short.ulg
thread 'main' (11675) panicked at /rustc/2d8144b7880597b6e6d3dfd63a9a9efae3f533d3/library/alloc/src/raw_vec/mod.rs:28:5:
capacity overflow
rc=101
=== ulog-rs bad_nested_explosion.ulg
memory allocation of 786408 bytes failed
rc=134
=== px4-ulog bad_nested_explosion (hang): timeout 20 s
rc=124
```

</details>

<details>
<summary>Determinism of the first error (multi_bad_formats.ulg, 20 runs)</summary>

```text
$ for i in 1..20: probe-px4-ulog multi_bad_formats.ulg | grep STATUS | sort | uniq -c
      1 STATUS error: parse error: Could not find format definition for message missing0
      3 STATUS error: parse error: Could not find format definition for message missing1
      1 STATUS error: parse error: Could not find format definition for message missing2
      2 STATUS error: parse error: Could not find format definition for message missing3
      3 STATUS error: parse error: Could not find format definition for message missing4
      3 STATUS error: parse error: Could not find format definition for message missing5
      1 STATUS error: parse error: Could not find format definition for message missing6
      6 STATUS error: parse error: Could not find format definition for message missing7
$ same with probe-yule-log
     20 STATUS ok
```

</details>

<details>
<summary>Mutation sweep raw results (first 60 lines per file)</summary>

```text
== sweep_px4-ulog_sample_400k.txt
PANIC 368 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 122 out of range for slice of length 28
PANIC 526 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 103 out of range for slice of length 20
PANIC 954 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 190 out of range for slice of length 25
PANIC 1144 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 106 out of range for slice of length 25
PANIC 1365 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:418 index out of bounds: the len is 0 but the index is 0
PANIC 1366 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 106 out of range for slice of length 21
PANIC 1405 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 125 out of range for slice of length 19
PANIC 1545 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:418 index out of bounds: the len is 0 but the index is 0
PANIC 1852 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 106 out of range for slice of length 25
PANIC 2132 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 82 out of range for slice of length 23
PANIC 2209 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 90 out of range for slice of length 23
PANIC 2274 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 133 out of range for slice of length 25
PANIC 2331 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:418 index out of bounds: the len is 0 but the index is 0
PANIC 2356 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 103 out of range for slice of length 27
PANIC 2524 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 103 out of range for slice of length 26
PANIC 2842 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 103 out of range for slice of length 19
PANIC 2932 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 103 out of range for slice of length 26
DONE ok=1538 err=1445 panic=17

== sweep_px4-ulog_sitl_400k.txt
PANIC 271 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 199 out of range for slice of length 23
PANIC 376 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:418 index out of bounds: the len is 0 but the index is 0
PANIC 769 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 111 out of range for slice of length 23
PANIC 879 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 172 out of range for slice of length 23
PANIC 1323 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 112 out of range for slice of length 23
PANIC 1470 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 211 out of range for slice of length 28
PANIC 1759 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 69 out of range for slice of length 24
PANIC 1785 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:418 index out of bounds: the len is 0 but the index is 0
PANIC 2126 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 117 out of range for slice of length 27
PANIC 2179 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 26 out of range for slice of length 25
PANIC 2452 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 103 out of range for slice of length 22
PANIC 2625 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:418 index out of bounds: the len is 0 but the index is 0
PANIC 2998 /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/px4-ulog-0.6.1/src/stream_parser/file_reader.rs:419 range start index 103 out of range for slice of length 26
DONE ok=1667 err=1320 panic=13

== sweep_ulog-rs_sample_400k.txt
DONE ok=466 err=2534 panic=0

== sweep_ulog-rs_sitl_400k.txt
PANIC 2656 /rustc/2d8144b7880597b6e6d3dfd63a9a9efae3f533d3/library/alloc/src/raw_vec/mod.rs:28 capacity overflow
DONE ok=1398 err=1601 panic=1

== sweep_yule_log_sample_400k.txt
DONE ok=1297 err=1703 panic=0

== sweep_yule_log_sitl_400k.txt
DONE ok=1320 err=1680 panic=0
```

</details>

<details>
<summary>Cross-check against pyulog, all 14 logs, category by category</summary>

```text
############ sample (4053364 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 493 params
  MATCH in-data param changes (order, ts, name, value): 6 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 4 msgs
  MATCH dropouts (ts, ms): 4 dropouts
  MATCH topics (name, multi_id, count): 15 topic instances, 64542 data msgs
  MATCH info messages (key, value): 4 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 493 params
  MATCH in-data param changes (order, ts, name, value): 6 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 4 msgs
  MATCH dropouts (ts, ms): 4 dropouts
  MATCH topics (name, multi_id, count): 15 topic instances, 64542 data msgs
  MATCH info messages (key, value): 4 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  MATCH initial params (all, by value): 493 params
  DIFF  in-data param changes (order, ts, name, value): 6 changes ref=[('158196367', 'COM_AUTOS_PAR', 0.0), ('158196367', 'MPC_Z_VEL_MAX_DN', 1.0), (' got=[('158196367', 'COM_AUTOS_PAR', 0.0), ('158196367', 'COM_AUTOS_PAR', 0.0), ('162
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 4 msgs
  DIFF  dropouts (ts, ms): 4 dropouts ref=['112574774 0', '112574774 26', '112614307 31', '153855108 62'] got=['112571708 0', '112571708 26', '112614307 31', '153847961 62']
  MATCH topics (name, multi_id, count): 15 topic instances, 64542 data msgs
  MATCH info messages (key, value): 4 keys
  STATUS ref: ok | got: ok
############ sample_appended (4548191 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 713 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 1 msgs
  MATCH dropouts (ts, ms): 1 dropouts
  DIFF  topics (name, multi_id, count): 20 topic instances, 81257 data msgs ref={('actuator_controls_0', '0'): 1132, ('actuator_outputs', '0'): 1132, ('battery_ got={('actuator_controls_0', '0'): 1132, ('actuator_outputs', '0'): 1132, ('battery_
  DIFF  info messages (key, value): 78 keys ref={'perf_counter_preflight-00': 'navigator: 3 events, 80us elapsed, 26us avg, min  got={'perf_counter_preflight': 'dma_alloc: 4 events', 'perf_top_preflight': 'Uptime:
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 713 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 1 msgs
  MATCH dropouts (ts, ms): 1 dropouts
  MATCH topics (name, multi_id, count): 20 topic instances, 81257 data msgs
  MATCH info messages (key, value): 78 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  DIFF  initial params (all, by value): 713 params ref={'ATT_VIBE_THRESH': 0.30000001192092896, 'BAT_A_PER_V': 34.0, 'BAT_CAPACITY': -1 got={}
  MATCH in-data param changes (order, ts, name, value): 0 changes
  DIFF  default-param entries:  ref=entries=0 got=None
  DIFF  logged strings (level, ts, text): 1 msgs ref=['4 11919580 [commander_tests] Not ready to fly: Sensors not set up correctly'] got=[]
  DIFF  dropouts (ts, ms): 1 dropouts ref=['5269305 10'] got=[]
  DIFF  topics (name, multi_id, count): 20 topic instances, 81257 data msgs ref={('actuator_controls_0', '0'): 1132, ('actuator_outputs', '0'): 1132, ('battery_ got={}
  DIFF  info messages (key, value): 78 keys ref={'perf_counter_preflight-00': 'navigator: 3 events, 80us elapsed, 26us avg, min  got={}
  STATUS ref: ok | got: error: IncompatibleFlags: [1, 0, 0, 0, 0, 0, 0, 0]
############ sample_appended_multiple (486737 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 750 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 1 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 20 topic instances, 6852 data msgs
  DIFF  info messages (key, value): 89 keys ref={'perf_counter_preflight-00': 'navigator: 9 events, 275us elapsed, 30us avg, min got={'perf_counter_preflight': 'dma_alloc: 7 events', 'perf_top_preflight': 'Uptime:
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 750 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 1 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 20 topic instances, 6852 data msgs
  MATCH info messages (key, value): 89 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  DIFF  initial params (all, by value): 750 params ref={'ATT_VIBE_THRESH': 0.20000000298023224, 'BAT_A_PER_V': 26.399999618530273, 'BAT got={}
  MATCH in-data param changes (order, ts, name, value): 0 changes
  DIFF  default-param entries:  ref=entries=0 got=None
  DIFF  logged strings (level, ts, text): 1 msgs ref=['4 11912381 [commander_tests] Not ready to fly: Sensors not set up correctly'] got=[]
  MATCH dropouts (ts, ms): 0 dropouts
  DIFF  topics (name, multi_id, count): 20 topic instances, 6852 data msgs ref={('actuator_controls_0', '0'): 95, ('actuator_outputs', '0'): 95, ('actuator_out got={}
  DIFF  info messages (key, value): 89 keys ref={'perf_counter_preflight-00': 'navigator: 9 events, 275us elapsed, 30us avg, min got={}
  STATUS ref: ok | got: error: IncompatibleFlags: [1, 0, 0, 0, 0, 0, 0, 0]
############ sample_log_small (921631 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 980 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 3 msgs
  MATCH dropouts (ts, ms): 1 dropouts
  MATCH topics (name, multi_id, count): 70 topic instances, 14604 data msgs
  MATCH info messages (key, value): 14 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 980 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 3 msgs
  MATCH dropouts (ts, ms): 1 dropouts
  MATCH topics (name, multi_id, count): 70 topic instances, 14604 data msgs
  MATCH info messages (key, value): 14 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  DIFF  initial params (all, by value): 980 params ref={'ASPD_BETA_GATE': 1.0, 'ASPD_BETA_NOISE': 0.30000001192092896, 'ASPD_DO_CHECKS' got={}
  MATCH in-data param changes (order, ts, name, value): 0 changes
  DIFF  default-param entries:  ref=entries=0 got=None
  DIFF  logged strings (level, ts, text): 3 msgs ref=['6 22683736 [commander] Takeoff detected', '6 23827776 [commander] Landing dete got=[]
  DIFF  dropouts (ts, ms): 1 dropouts ref=['1194367328 30'] got=[]
  DIFF  topics (name, multi_id, count): 70 topic instances, 14604 data msgs ref={('actuator_armed', '0'): 14, ('actuator_controls_0', '0'): 1812, ('actuator_con got={}
  DIFF  info messages (key, value): 14 keys ref={'sys_mcu': 'STM32H7[4|5]xxx, rev. V', 'sys_name': 'PX4', 'sys_os_name': 'NuttX' got={}
  STATUS ref: ok | got: error: Parse error: Invalid type/size combination: (Int16, Some(8))
############ sample_logging_tagged_and_default_params (1942808 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 696 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 4 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 96 topic instances, 21229 data msgs
  MATCH info messages (key, value): 11 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 696 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 4 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 96 topic instances, 21229 data msgs
  MATCH info messages (key, value): 11 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  MATCH initial params (all, by value): 696 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 4 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 96 topic instances, 21229 data msgs
  MATCH info messages (key, value): 11 keys
  STATUS ref: ok | got: ok
############ sample_px4_events (1563146 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 875 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 18 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 69 topic instances, 29480 data msgs
  MATCH info messages (key, value): 11 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 875 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 18 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 69 topic instances, 29480 data msgs
  MATCH info messages (key, value): 11 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  MATCH initial params (all, by value): 875 params
  MATCH in-data param changes (order, ts, name, value): 0 changes
  MATCH default-param entries: 
  DIFF  logged strings (level, ts, text): 18 msgs ref=['6 1710773350346000 [px4] Startup script returned successfully', '6 17107733503 got=[]
  MATCH dropouts (ts, ms): 0 dropouts
  DIFF  topics (name, multi_id, count): 69 topic instances, 29480 data msgs ref={('actuator_armed', '0'): 69, ('actuator_motors', '0'): 313, ('actuator_outputs' got={('actuator_armed', '0'): 1, ('config_overrides', '0'): 1, ('esc_status', '0'): 
  MATCH info messages (key, value): 11 keys
  STATUS ref: ok | got: ok
############ sitl_v1170_attempt1 (9158705 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  MATCH in-data param changes (order, ts, name, value): 20 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 15 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 86 topic instances, 103604 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  MATCH in-data param changes (order, ts, name, value): 20 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 15 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 86 topic instances, 103604 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  DIFF  in-data param changes (order, ts, name, value): 20 changes ref=[('292000', 'CAL_ACC0_ID', 1310988.0), ('292000', 'CAL_ACC1_ID', 1310996.0), ('2 got=[('292000', 'CAL_ACC0_ID', 1310988.0), ('292000', 'CAL_ACC1_ID', 1310996.0), ('2
  MATCH default-param entries: 
  DIFF  logged strings (level, ts, text): 15 msgs ref=['6 292000 [logger] Opened full log file: ./log/2026-10-18/03_10_21.ulg', '6 292 got=[]
  MATCH dropouts (ts, ms): 0 dropouts
  DIFF  topics (name, multi_id, count): 86 topic instances, 103604 data msgs ref={('actuator_armed', '0'): 88, ('actuator_motors', '0'): 404, ('actuator_outputs' got={('actuator_armed', '0'): 1, ('distance_sensor_mode_change_request', '0'): 1, ('
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
############ v1.14.4_mc_flight (30583745 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 882 params
  MATCH in-data param changes (order, ts, name, value): 662 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 22 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 83 topic instances, 350011 data msgs
  MATCH info messages (key, value): 12 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 882 params
  MATCH in-data param changes (order, ts, name, value): 662 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 22 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 83 topic instances, 350011 data msgs
  MATCH info messages (key, value): 12 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  MATCH initial params (all, by value): 882 params
  MATCH in-data param changes (order, ts, name, value): 662 changes
  MATCH default-param entries: 
  DIFF  logged strings (level, ts, text): 22 msgs ref=['6 244000 [logger] logger started (mode=all)', '6 244000 [logger] Start file lo got=[]
  MATCH dropouts (ts, ms): 0 dropouts
  DIFF  topics (name, multi_id, count): 83 topic instances, 350011 data msgs ref={('actuator_armed', '0'): 298, ('actuator_motors', '0'): 1451, ('actuator_output got={('actuator_armed', '0'): 1, ('failsafe_flags', '0'): 1, ('failure_detector_stat
  MATCH info messages (key, value): 12 keys
  STATUS ref: ok | got: ok
############ v1.17.0_failsafe_battery_empty (9208891 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  MATCH in-data param changes (order, ts, name, value): 21 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 24 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 88 topic instances, 104292 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  MATCH in-data param changes (order, ts, name, value): 21 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 24 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 88 topic instances, 104292 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  DIFF  in-data param changes (order, ts, name, value): 21 changes ref=[('332000', 'CAL_ACC0_ID', 1310988.0), ('332000', 'CAL_ACC1_ID', 1310996.0), ('3 got=[('332000', 'CAL_ACC0_ID', 1310988.0), ('332000', 'CAL_ACC1_ID', 1310996.0), ('3
  MATCH default-param entries: 
  DIFF  logged strings (level, ts, text): 24 msgs ref=['6 328000 [logger] logger started (mode=all)', '6 332000 [logger] Start file lo got=[]
  MATCH dropouts (ts, ms): 0 dropouts
  DIFF  topics (name, multi_id, count): 88 topic instances, 104292 data msgs ref={('actuator_armed', '0'): 88, ('actuator_motors', '0'): 407, ('actuator_outputs' got={('actuator_armed', '0'): 1, ('distance_sensor_mode_change_request', '0'): 1, ('
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
############ v1.17.0_failsafe_gps_loss (10217078 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  MATCH in-data param changes (order, ts, name, value): 20 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 22 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 85 topic instances, 116310 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  MATCH in-data param changes (order, ts, name, value): 20 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 22 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 85 topic instances, 116310 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  DIFF  in-data param changes (order, ts, name, value): 20 changes ref=[('260000', 'CAL_ACC0_ID', 1310988.0), ('260000', 'CAL_ACC1_ID', 1310996.0), ('2 got=[('260000', 'CAL_ACC0_ID', 1310988.0), ('260000', 'CAL_ACC1_ID', 1310996.0), ('2
  MATCH default-param entries: 
  DIFF  logged strings (level, ts, text): 22 msgs ref=['6 260000 [logger] logger started (mode=all)', '6 260000 [logger] Start file lo got=[]
  MATCH dropouts (ts, ms): 0 dropouts
  DIFF  topics (name, multi_id, count): 85 topic instances, 116310 data msgs ref={('actuator_armed', '0'): 98, ('actuator_motors', '0'): 461, ('actuator_outputs' got={('actuator_armed', '0'): 1, ('distance_sensor_mode_change_request', '0'): 1, ('
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
############ v1.17.0_mc_flight_1 (8536869 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  MATCH in-data param changes (order, ts, name, value): 20 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 19 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 89 topic instances, 96640 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  MATCH in-data param changes (order, ts, name, value): 20 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 19 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 89 topic instances, 96640 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  MATCH initial params (all, by value): 901 params
  DIFF  in-data param changes (order, ts, name, value): 20 changes ref=[('992000', 'CAL_ACC0_ID', 1310988.0), ('992000', 'CAL_ACC1_ID', 1310996.0), ('9 got=[('992000', 'CAL_ACC0_ID', 1310988.0), ('992000', 'CAL_ACC1_ID', 1310996.0), ('9
  MATCH default-param entries: 
  DIFF  logged strings (level, ts, text): 19 msgs ref=['6 988000 [logger] logger started (mode=all)', '6 992000 [logger] Start file lo got=[]
  MATCH dropouts (ts, ms): 0 dropouts
  DIFF  topics (name, multi_id, count): 89 topic instances, 96640 data msgs ref={('actuator_armed', '0'): 82, ('actuator_motors', '0'): 376, ('actuator_outputs' got={('actuator_armed', '0'): 1, ('config_overrides', '0'): 1, ('cpuload', '0'): 1, 
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
############ v1.17.0_mc_flight_2 (9727973 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 898 params
  MATCH in-data param changes (order, ts, name, value): 3 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 17 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 89 topic instances, 110452 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 898 params
  MATCH in-data param changes (order, ts, name, value): 3 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 17 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 89 topic instances, 110452 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  MATCH initial params (all, by value): 898 params
  DIFF  in-data param changes (order, ts, name, value): 3 changes ref=[('5408000', 'CAL_BARO0_ID', 6620172.0), ('5408000', 'CAL_BARO0_OFF', -12.207031 got=[]
  MATCH default-param entries: 
  DIFF  logged strings (level, ts, text): 17 msgs ref=['6 388000 [logger] Opened full log file: ./log/2026-10-18/11_12_29.ulg', '6 388 got=[]
  MATCH dropouts (ts, ms): 0 dropouts
  DIFF  topics (name, multi_id, count): 89 topic instances, 110452 data msgs ref={('actuator_armed', '0'): 95, ('actuator_motors', '0'): 432, ('actuator_outputs' got={('actuator_armed', '0'): 1, ('distance_sensor_mode_change_request', '0'): 1, ('
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
############ v1.17.0_vtol_transition (24295307 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 1145 params
  MATCH in-data param changes (order, ts, name, value): 28 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 18 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 115 topic instances, 349108 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 1145 params
  MATCH in-data param changes (order, ts, name, value): 28 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 18 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 115 topic instances, 349108 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  MATCH initial params (all, by value): 1145 params
  DIFF  in-data param changes (order, ts, name, value): 28 changes ref=[('312000', 'CAL_ACC0_ID', 1310988.0), ('312000', 'CAL_ACC1_ID', 1310996.0), ('3 got=[('312000', 'CAL_ACC0_ID', 1310988.0), ('312000', 'CAL_ACC1_ID', 1310996.0), ('3
  MATCH default-param entries: 
  DIFF  logged strings (level, ts, text): 18 msgs ref=['6 312000 [logger] logger started (mode=all)', '6 312000 [logger] Start file lo got=[]
  MATCH dropouts (ts, ms): 0 dropouts
  DIFF  topics (name, multi_id, count): 115 topic instances, 349108 data msgs ref={('actuator_armed', '0'): 188, ('actuator_motors', '0'): 891, ('actuator_outputs got={('actuator_armed', '0'): 1, ('airspeed', '0'): 1, ('distance_sensor_mode_change
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
############ v1.17.0_vtol_transition_abort (15324267 bytes)
 -- yule_log
  MATCH header: 
  MATCH initial params (all, by value): 1145 params
  MATCH in-data param changes (order, ts, name, value): 28 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 16 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 114 topic instances, 217485 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok
 -- px4-ulog
  MATCH header: 
  MATCH initial params (all, by value): 1145 params
  MATCH in-data param changes (order, ts, name, value): 28 changes
  MATCH default-param entries: 
  MATCH logged strings (level, ts, text): 16 msgs
  MATCH dropouts (ts, ms): 0 dropouts
  MATCH topics (name, multi_id, count): 114 topic instances, 217485 data msgs
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok completeness=Complete
 -- ulog-rs
  MATCH header: 
  MATCH initial params (all, by value): 1145 params
  DIFF  in-data param changes (order, ts, name, value): 28 changes ref=[('472000', 'CAL_ACC0_ID', 1310988.0), ('472000', 'CAL_ACC1_ID', 1310996.0), ('4 got=[('472000', 'CAL_ACC0_ID', 1310988.0), ('472000', 'CAL_ACC1_ID', 1310996.0), ('4
  MATCH default-param entries: 
  DIFF  logged strings (level, ts, text): 16 msgs ref=['6 472000 [logger] Opened full log file: ./log/2026-10-18/11_18_44.ulg', '6 476 got=[]
  MATCH dropouts (ts, ms): 0 dropouts
  DIFF  topics (name, multi_id, count): 114 topic instances, 217485 data msgs ref={('actuator_armed', '0'): 121, ('actuator_motors', '0'): 568, ('actuator_outputs got={('actuator_armed', '0'): 1, ('airspeed', '0'): 1, ('distance_sensor_mode_change
  MATCH info messages (key, value): 13 keys
  STATUS ref: ok | got: ok

load during cross-check:
 11:24:17 up 18 min,  0 user,  load average: 5.24, 4.97, 2.82
 11:24:25 up 18 min,  0 user,  load average: 4.51, 4.83, 2.80
```

</details>

<details>
<summary>Data-section message types (explains the ulog-rs early stop) and the sample_appended sections</summary>

```text
sitl_v1170_attempt1.ulg messages 105172 data-section types {'A': 94, 'D': 103604, 'L': 15, 'M': 106, 'P': 20, 'S': 80}
   first occurrence (offset, data msgs before it): {'A': (95940, 0), 'P': (98011, 0), 'D': (98490, 0), 'L': (100867, 38), 'S': (136232, 438), 'M': (9147071, 103604)}
sample_px4_events.ulg messages 30910 data-section types {'A': 84, 'D': 29480, 'L': 18, 'M': 79, 'S': 62}
   first occurrence (offset, data msgs before it): {'A': (85398, 0), 'D': (87153, 0), 'L': (90026, 39), 'S': (90080, 39), 'M': (1554874, 29480)}
sample_log_small.ulg messages 15900 data-section types {'A': 72, 'D': 14604, 'L': 3, 'M': 31, 'O': 1, 'S': 12}
   first occurrence (offset, data msgs before it): {'A': (60954, 0), 'D': (62512, 0), 'O': (65531, 45), 'S': (111248, 824), 'M': (177959, 1955), 'L': (364741, 5096)}
sample_appended.ulg primary section: {'<straddles boundary>': 1, 'A': 43, 'B': 1, 'D': 81257, 'F': 110, 'I': 78, 'L': 1, 'O': 1, 'P': 713} last clean boundary 4530661 first appended offset 4530735
sample_appended.ulg appended section: {'M': 1}
```

</details>

<details>
<summary>PX4 events versus logged strings (pyulog, no download)</summary>

```text
sample_px4_events.ulg
  L levels: {'4': 2, '6': 16}  tagged C: 0
  'event' topic present: True  metadata_events in multi-info: True
  decoded events by level: {'INFO': 8}
mc_flight_1.ulg
  L levels: {'6': 15}  tagged C: 0
  'event' topic present: True  metadata_events in multi-info: True
  decoded events by level: {'INFO': 8}
```

</details>

<details>
<summary>Timing, median of 5 (first run; yule_log stream rows superseded by the next block)</summary>

```text
 11:16:23 up 10 min,  0 user,  load average: 1.91, 1.91, 1.07
sample.ulg                   4.1 MB | yule_log mem full                                | median wall   0.075 s | parse-only      70 ms | peak RSS    10.9 MiB | n=5 | STATUS ok datamsgs=64542
sample.ulg                   4.1 MB | yule_log stream full                             | median wall   0.057 s | parse-only      52 ms | peak RSS    11.0 MiB | n=5 | STATUS ok datamsgs=64542
sample.ulg                   4.1 MB | yule_log stream 8 topics                         | median wall   0.017 s | parse-only      12 ms | peak RSS    11.0 MiB | n=5 | STATUS ok datamsgs=294
sample.ulg                   4.1 MB | px4-ulog mem                                     | median wall   0.012 s | parse-only       6 ms | peak RSS    10.9 MiB | n=5 | STATUS ok completeness=Complete datamsgs=64542
sample.ulg                   4.1 MB | px4-ulog stream (read_file_with_simple_callback) | median wall   0.016 s | parse-only      14 ms | peak RSS    11.0 MiB | n=5 | STATUS ok completeness=Complete datamsgs=64542
sample.ulg                   4.1 MB | ulog-rs mem                                      | median wall   0.212 s | parse-only     200 ms | peak RSS    49.2 MiB | n=5 | STATUS ok datamsgs=64542
sample.ulg                   4.1 MB | pyulog (reference)                               | median wall   0.227 s | parse-only     nan ms | peak RSS    34.5 MiB | n=5 | STATUS ok datamsgs=64542
sitl_v1170_attempt1.ulg      9.2 MB | yule_log mem full                                | median wall   0.134 s | parse-only     125 ms | peak RSS    12.8 MiB | n=5 | STATUS ok datamsgs=103604
sitl_v1170_attempt1.ulg      9.2 MB | yule_log stream full                             | median wall   0.137 s | parse-only     128 ms | peak RSS    11.6 MiB | n=5 | STATUS ok datamsgs=103604
sitl_v1170_attempt1.ulg      9.2 MB | yule_log stream 8 topics                         | median wall   0.033 s | parse-only      25 ms | peak RSS    11.5 MiB | n=5 | STATUS ok datamsgs=577
sitl_v1170_attempt1.ulg      9.2 MB | px4-ulog mem                                     | median wall   0.026 s | parse-only      15 ms | peak RSS    12.4 MiB | n=5 | STATUS ok completeness=Complete datamsgs=103604
sitl_v1170_attempt1.ulg      9.2 MB | px4-ulog stream (read_file_with_simple_callback) | median wall   0.017 s | parse-only      15 ms | peak RSS    11.0 MiB | n=5 | STATUS ok completeness=Complete datamsgs=103604
sitl_v1170_attempt1.ulg      9.2 MB | ulog-rs mem                                      | median wall   0.011 s | parse-only       2 ms | peak RSS    12.4 MiB | n=5 | STATUS ok datamsgs=14
sitl_v1170_attempt1.ulg      9.2 MB | pyulog (reference)                               | median wall   0.288 s | parse-only     nan ms | peak RSS    45.5 MiB | n=5 | STATUS ok datamsgs=103604
syn100_sample.ulg          104.5 MB | yule_log mem full                                | median wall   1.340 s | parse-only    1265 ms | peak RSS   103.6 MiB | n=5 | STATUS ok datamsgs=1678092
syn100_sample.ulg          104.5 MB | yule_log stream full                             | median wall   1.422 s | parse-only    1353 ms | peak RSS   102.5 MiB | n=5 | STATUS ok datamsgs=1678092
syn100_sample.ulg          104.5 MB | yule_log stream 8 topics                         | median wall   0.303 s | parse-only     241 ms | peak RSS   102.6 MiB | n=5 | STATUS ok datamsgs=7644
syn100_sample.ulg          104.5 MB | px4-ulog mem                                     | median wall   0.220 s | parse-only     143 ms | peak RSS   102.9 MiB | n=5 | STATUS ok completeness=Complete datamsgs=1678092
syn100_sample.ulg          104.5 MB | px4-ulog stream (read_file_with_simple_callback) | median wall   0.156 s | parse-only     153 ms | peak RSS    11.0 MiB | n=5 | STATUS ok completeness=Complete datamsgs=1678092
syn100_sample.ulg          104.5 MB | ulog-rs mem                                      | median wall   5.506 s | parse-only    5271 ms | peak RSS  1159.6 MiB | n=5 | STATUS ok datamsgs=1678092
syn100_sample.ulg          104.5 MB | pyulog (reference)                               | median wall   2.607 s | parse-only     nan ms | peak RSS   218.1 MiB | n=1 | STATUS ok datamsgs=1678092
syn100_sitl.ulg             99.8 MB | yule_log mem full                                | median wall   1.501 s | parse-only    1429 ms | peak RSS    99.1 MiB | n=5 | STATUS ok datamsgs=1139644
syn100_sitl.ulg             99.8 MB | yule_log stream full                             | median wall   1.532 s | parse-only    1469 ms | peak RSS    97.9 MiB | n=5 | STATUS ok datamsgs=1139644
syn100_sitl.ulg             99.8 MB | yule_log stream 8 topics                         | median wall   0.277 s | parse-only     217 ms | peak RSS    98.1 MiB | n=5 | STATUS ok datamsgs=6347
syn100_sitl.ulg             99.8 MB | px4-ulog mem                                     | median wall   0.190 s | parse-only      95 ms | peak RSS    98.7 MiB | n=5 | STATUS ok completeness=Complete datamsgs=1139644
syn100_sitl.ulg             99.8 MB | px4-ulog stream (read_file_with_simple_callback) | median wall   0.119 s | parse-only     116 ms | peak RSS    11.0 MiB | n=5 | STATUS ok completeness=Complete datamsgs=1139644
syn100_sitl.ulg             99.8 MB | ulog-rs mem                                      | median wall   0.064 s | parse-only       6 ms | peak RSS    98.8 MiB | n=5 | STATUS ok datamsgs=14
syn100_sitl.ulg             99.8 MB | pyulog (reference)                               | median wall   1.838 s | parse-only     nan ms | peak RSS   213.5 MiB | n=1 | STATUS ok datamsgs=1139644
 11:17:45 up 12 min,  0 user,  load average: 2.87, 2.15, 1.23
```

</details>

<details>
<summary>yule_log streaming re-measure after the probe fix</summary>

```text
 11:17:59 up 12 min,  0 user,  load average: 2.96, 2.21, 1.26
sample.ulg yule_log stream  runs(wall_s:rss_kb): 0.058:11212 0.059:11232 0.051:11220 0.086:11204 0.061:11168
sample.ulg yule_log stream 8-topics runs(wall_s:rss_kb): 0.015:11228 0.021:11212 0.015:11172 0.024:11220 0.023:11188
sitl_v1170_attempt1.ulg yule_log stream  runs(wall_s:rss_kb): 0.146:11236 0.135:11208 0.181:11184 0.169:11160 0.145:11220
sitl_v1170_attempt1.ulg yule_log stream 8-topics runs(wall_s:rss_kb): 0.046:11236 0.037:11192 0.043:11208 0.043:11224 0.025:11172
syn100_sample.ulg yule_log stream  runs(wall_s:rss_kb): 1.399:11228 1.387:11160 1.649:11080 1.309:11212 1.469:11160
syn100_sample.ulg yule_log stream 8-topics runs(wall_s:rss_kb): 0.254:11232 0.240:11164 0.244:11220 0.279:11216 0.228:11184
syn100_sitl.ulg yule_log stream  runs(wall_s:rss_kb): 1.262:11224 1.395:11196 1.330:11232 1.179:11204 1.163:11052
syn100_sitl.ulg yule_log stream 8-topics runs(wall_s:rss_kb): 0.188:11204 0.203:11184 0.232:11196 0.293:11152 0.212:11192
 11:18:18 up 12 min,  0 user,  load average: 3.33, 2.34, 1.33
```

</details>

<details>
<summary>Peak RSS via getrusage wrapper (single run each)</summary>

```text
 11:18:46 up 13 min,  0 user,  load average: 3.62, 2.47, 1.39
sample.ulg yule_log-mem MEASURE wall_s=0.067 max_rss_kb=8028 exit=0
sample.ulg yule_log-stream MEASURE wall_s=0.057 max_rss_kb=3940 exit=0
sample.ulg yule_log-stream-8topics MEASURE wall_s=0.016 max_rss_kb=4188 exit=0
sample.ulg px4-ulog-mem MEASURE wall_s=0.011 max_rss_kb=7288 exit=0
sample.ulg px4-ulog-stream MEASURE wall_s=0.019 max_rss_kb=4248 exit=0
sample.ulg ulog-rs-mem MEASURE wall_s=0.180 max_rss_kb=50272 exit=0
sample.ulg pyulog MEASURE wall_s=0.262 max_rss_kb=35404 exit=0
sitl_v1170_attempt1.ulg yule_log-mem MEASURE wall_s=0.161 max_rss_kb=13088 exit=0
sitl_v1170_attempt1.ulg yule_log-stream MEASURE wall_s=0.163 max_rss_kb=4268 exit=0
sitl_v1170_attempt1.ulg yule_log-stream-8topics MEASURE wall_s=0.033 max_rss_kb=4180 exit=0
sitl_v1170_attempt1.ulg px4-ulog-mem MEASURE wall_s=0.020 max_rss_kb=12660 exit=0
sitl_v1170_attempt1.ulg px4-ulog-stream MEASURE wall_s=0.015 max_rss_kb=4720 exit=0
sitl_v1170_attempt1.ulg ulog-rs-mem MEASURE wall_s=0.011 max_rss_kb=12688 exit=0
sitl_v1170_attempt1.ulg pyulog MEASURE wall_s=0.321 max_rss_kb=46524 exit=0
syn100_sample.ulg yule_log-mem MEASURE wall_s=1.705 max_rss_kb=106120 exit=0
syn100_sample.ulg yule_log-stream MEASURE wall_s=1.907 max_rss_kb=4112 exit=0
syn100_sample.ulg yule_log-stream-8topics MEASURE wall_s=0.451 max_rss_kb=3964 exit=0
syn100_sample.ulg px4-ulog-mem MEASURE wall_s=0.270 max_rss_kb=105216 exit=0
syn100_sample.ulg px4-ulog-stream MEASURE wall_s=0.203 max_rss_kb=4348 exit=0
syn100_sample.ulg ulog-rs-mem MEASURE wall_s=9.504 max_rss_kb=1187372 exit=0
syn100_sample.ulg pyulog MEASURE wall_s=2.941 max_rss_kb=224344 exit=0
syn100_sitl.ulg yule_log-mem MEASURE wall_s=1.801 max_rss_kb=101540 exit=0
syn100_sitl.ulg yule_log-stream MEASURE wall_s=1.833 max_rss_kb=4112 exit=0
syn100_sitl.ulg yule_log-stream-8topics MEASURE wall_s=0.233 max_rss_kb=4192 exit=0
syn100_sitl.ulg px4-ulog-mem MEASURE wall_s=0.155 max_rss_kb=101104 exit=0
syn100_sitl.ulg px4-ulog-stream MEASURE wall_s=0.113 max_rss_kb=4548 exit=0
syn100_sitl.ulg ulog-rs-mem MEASURE wall_s=0.062 max_rss_kb=101168 exit=0
syn100_sitl.ulg pyulog MEASURE wall_s=2.140 max_rss_kb=218736 exit=0
 11:19:11 up 13 min,  0 user,  load average: 4.60, 2.80, 1.53
```

</details>

<details>
<summary>px4-ulog own test suite at the 0.6.1 commit</summary>

```text
running 5 tests
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 5 tests
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s
running 8 tests
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 18 tests
test result: ok. 18 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.66s
running 12 tests
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 13 tests
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 4 tests
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 9 tests
test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
running 15 tests
test result: ok. 12 passed; 0 failed; 3 ignored; 0 measured; 0 filtered out; finished in 0.04s
running 5 tests
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
running 5 tests
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
running 8 tests
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.23s
running 4 tests
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 4 tests
test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 3 tests
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 22 tests
test result: ok. 22 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.06s
running 6 tests
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 6 tests
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.27s
```

</details>


## 3. Golden logs

Every log below was generated for this project; none came from Flight Review. The pyulog sample keeps its BSD-3-Clause notice (`testdata/pyulog/`). Each SITL log has a `.provenance.md` beside it.

| File | Airframe | Size (bytes) | SHA-256 | Scenario |
|---|---|---|---|---|
| `testdata/pyulog/sample.ulg` | (pyulog sample) | 4053364 | `81952e6059bc095717e7911c010e07f85749d6b04d332a5ffc51575a3fd0a558` | Sample shipped with PX4 pyulog (item 3a) |
| `testdata/sitl/v1.17.0/mc_flight_1.ulg` | `10040_sihsim_quadx` | 8536869 | `6e7b6956c20422aa9f31a13e7f074e80cba85760928fd895eed941e9492823fc` | Multicopter: arm, takeoff, loiter, commanded RTL, commanded land, disarm by landing. Fresh working directory. |
| `testdata/sitl/v1.17.0/mc_flight_2.ulg` | `10040_sihsim_quadx` | 9727973 | `05592a1bc28c9f82a420320c8a44191fb34aa92662a50c5d7b9cbaa9aba32b9b` | Same as mc_flight_1, in the same working directory with no configuration change (volatile-parameter experiment, item 5). |
| `testdata/sitl/v1.17.0/vtol_transition.ulg` | `10043_sihsim_standard_vtol` | 24295307 | `86d64e54d1261991f4035355550f64e017f8a486c5c665848d6e68ae67fc9bf3` | Standard VTOL: arm, takeoff, transition to fixed wing, about 25 s in fixed wing, transition back, land, disarm. |
| `testdata/sitl/v1.17.0/vtol_transition_abort.ulg` | `10043_sihsim_standard_vtol` | 15324267 | `13489ca66b7c1023278d7b13dbb621e882a7bbe001ceaad2f2beb257cdd9bc79` | Standard VTOL: forward transition aborted by an RTL command before reaching fixed wing (R6 ABORT case). |
| `testdata/sitl/v1.17.0/failsafe_gps_loss.ulg` | `10040_sihsim_quadx` | 10217078 | `5ce6ca4963b231d3641edcb25e7b3d07c7da6e8971857cbef074ce04e496cdfc` | Multicopter in loiter; GPS simulator stopped, position invalid, vehicle_status.failsafe true, DESCEND, land, disarm (R4 case). |
| `testdata/sitl/v1.17.0/failsafe_battery_empty.ulg` | `10040_sihsim_quadx` | 9208891 | `7bd1633b26acba457f67a575fa9ddace0535e0411c5fdbacbfad777e0eddd75c` | Multicopter; `failure battery off`, battery_warning 1, 2, 3, Hold, AUTO_LAND, disarm (second R4 case). |
| `testdata/sitl/v1.14.4/mc_flight.ulg` | `10040_sihsim_quadx` | 30583745 | `9324d50388738054afdcee8cb09e3a44e1956c64003978e6aa401be16f09a254` | Multicopter, oldest supported schema: arm, takeoff, RTL, loiter, land, disarm. |

Chunk 1 asked for five logs (a to e); `mc_flight_2`, `vtol_transition_abort` and `failsafe_battery_empty` are extras that the volatile-parameter experiment, the R6 ABORT case and a second R4 case need.


### 3.1 PX4 v1.17.0 logs (3b, 3c, 3e; flight parts of items 5 and 6)

Evidence only. Every log below was generated in this session by PX4 SITL (built-in SIH simulator) from the v1.17.0 tree; no third-party or Flight Review log was used. Nothing under `/home/user/Sealed_Flight_Recorder-` was modified (only `docs/SPEC.md` B1.5 and B1.6 were read).

Date of runs: 2026-10-18, 11:11 to 11:20 UTC (one superseded attempt at 03:10 UTC, before a container restart).

### Summary

| log | scenario | airframe | size (bytes) | duration | dropouts | intended events present |
|---|---|---|---|---|---|---|
| `mc_flight_1.ulg` | B1 | 10040_sihsim_quadx | 8536869 | 37.4 s | 0 | yes: ARM, TAKEOFF, LOITER, commanded RTL, commanded LAND, DISARM (by landing) |
| `mc_flight_2.ulg` | B2 | 10040_sihsim_quadx | 9727973 | 43.1 s | 0 | yes: same sequence as mc_flight_1, same rootfs |
| `vtol_transition.ulg` | C | 10043_sihsim_standard_vtol | 24295307 | 89.0 s | 0 | yes: ARM, TAKEOFF, MC to FW transition (start and end), 25.6 s FW, FW to MC transition (start and end), commanded LAND, DISARM |
| `vtol_transition_abort.ulg` | C-abort (extra) | 10043_sihsim_standard_vtol | 15324267 | 56.7 s | 0 | yes: front transition START then ABORT (RTL commanded mid-transition), RTL landing, DISARM |
| `failsafe_gps_loss.ulg` | E | 10040_sihsim_quadx | 10217078 | 45.9 s | 0 | yes: vehicle_status.failsafe true, global/local position invalid, nav DESCEND, landing, DISARM. `failure gps off` itself had no effect (no SIH handler); GPS loss produced by `sensor_gps_sim stop` |
| `failsafe_battery_empty.ulg` | E2 (extra) | 10040_sihsim_quadx | 9208891 | 40.5 s | 0 | yes: `failure battery off` accepted, failsafe_flags.battery_warning 1, 2, 3, failsafe true, Hold then AUTO_LAND, DISARM; plus one real in-flight `param set` (COM_DISARM_LAND) |

All six logs: PX4 `v1.17.0`, commit `d6f12ad1c4f70ad3230afd7d86e971421e02fef4`, ULog header `ver_sw` equals that commit, `ver_sw_release` 17891583 (0x011100FF = 1.17.0, type 0xFF release), no dropouts, `file_corruption` false. Logs and their companions are in `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0`.

Key results, details in the sections below:

- **Volatile parameters (item 5)**: between two identical-configuration flights from the same working directory, initial values of `COM_FLIGHT_UUID`, `LND_FLIGHT_T_LO`, `EKF2_MAG_DECL`, `CAL_BARO0_OFF` differ, and the parameter KEY SET differs (`CAL_BARO1_ID`, `CAL_BARO2_ID`, `CAL_BARO3_ID` exist only in the first-boot log). Only info field `boot_time_utc_us` differs (plus the `perf_counter_*` info-multiple blobs).
- **VTOL (item 6)**: START = `vtol_vehicle_status.vehicle_vtol_state` becomes 1 (TRANSITION_TO_FW) or 2 (TRANSITION_TO_MC); END = it then becomes the target steady state (4 FW after 1, 3 MC after 2); ABORT = state 1 followed directly by 3 (MC) without 4, as observed in `vtol_transition_abort.ulg`. `vehicle_status` mirrors this 8 to 12 ms later. `DO_VTOL_TRANSITION` (3000) commands from the shell have NO `vehicle_command_ack`.
- **In-flight parameter changes**: a real `param set` while armed and airborne appears in pyulog `changed_parameters` (COM_DISARM_LAND 2.0 to 3.0 at 18.232 s). PX4 itself also logs parameter messages after log start that are not pilot changes (boot re-logs with unchanged values; `CAL_BARO0_*` from `SENS_BAR_AUTOCAL` about 5.3 to 5.8 s after boot, which fell inside the armed interval, on the ground, in five of the six logs because arming happened 3.9 to 5.5 s after boot).
- **No dropouts** in any log. Host load average 1.4 to 5.2 on 4 cores during the runs (parallel cargo builds and the v1.14.4 agent); the lockstep sim/wall ratio stayed 0.95 to 0.99 and no EKF, lockstep or timing warning appeared in any px4 output or ULog string. CPU load caused no observable trouble.

### 0. Build, environment, and facts confirmed

- Tree: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0`, `git describe --tags --always` = `v1.17.0`, `git rev-parse HEAD` = `d6f12ad1c4f70ad3230afd7d86e971421e02fef4`.
- Build: `make px4_sitl_default` finished with `build exit=0` (task output `bo6p9nqtb.output`), binary `build/px4_sitl_default/bin/px4` 52691768 bytes, 02:55 UTC. No fix or rebuild was needed. The container restarted later; the binary survived and was reused unchanged.
- **Exact command PX4 uses** (`src/modules/simulation/simulator_sih/CMakeLists.txt` lines 89 to 94): `${CMAKE_COMMAND} -E env PX4_SIM_MODEL=sihsim_${model} PX4_SIMULATOR=sihsim $<TARGET_FILE:px4>` with `WORKING_DIRECTORY ${SITL_WORKING_DIR}`, and `SITL_WORKING_DIR = ${PX4_BINARY_DIR}/rootfs` (`platforms/posix/CMakeLists.txt` line 139). With no arguments, `platforms/posix/src/px4/common/main.cpp` lines 265 to 271 default the data path to `PX4_BINARY_DIR/etc` and the working directory to `PX4_BINARY_DIR/rootfs`.
- **Command I ran instead of make** (per scenario, fresh directory): `cd <rootfs> && PX4_SIM_MODEL=<sihsim_quadx|sihsim_standard_vtol> PX4_SIMULATOR=sihsim /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/bin/px4 -d /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/etc > <scenario>.px4.log 2>&1 &`. `-d` is daemon mode (no pxh shell, `main.cpp` line 222); the positional argument is the data path, and px4 creates `<rootfs>/etc` as a symlink to it (`main.cpp` lines 397 to 449). The startup script is the default `etc/init.d-posix/rcS`. No display, no GUI, headless.
- **Airframe selection confirmed**: rcS line 56 picks `[0-9]+_${PX4_SIM_MODEL}`; px4 output shows `found model autostart file as SYS_AUTOSTART=10040` (quadx) and `=10043` (standard VTOL); `param show SYS_AUTOSTART` returned 10040 and 10043.
- **Facts confirmed in the logs and in px4 output**: `SDLOG_MODE` 1, `SDLOG_PROFILE` 131, `COM_RC_IN_MODE` 1, logs at `<rootfs>/log/2026-10-18/HH_MM_SS.ulg`. Correction to the brief: `SYS_FAILURE_EN` is already 1 by default in SITL (rcS line 187 `param set-default SYS_FAILURE_EN 1`), so `param set SYS_FAILURE_EN 1` is a no-op and leaves no parameter message in the log. Note: SDLOG_MODE 1 means log from boot **until first disarm** (rcS comment line 179); the file is closed at disarm, so nothing after disarm is logged.
- **Driving the flight**: client binaries `build/px4_sitl_default/bin/px4-commander`, `px4-param`, `px4-failure`, `px4-listener`, `px4-logger`, `px4-sensor_gps_sim`, `px4-shutdown`, called from bash scripts with sleeps and `listener` polling (each script waits for the expected `vehicle_status` field before the next step). `commander` subcommands used: `arm`, `takeoff`, `mode auto:loiter`, `mode auto:rtl`, `land`, `transition`.
- **`PX4_SIM_SPEED_FACTOR`** works for SIH (tested once in a throwaway dry run with factor 2: `Simulation with 2.0x speedup. Loop with (2000 us wall time interval)`, sim time 47.7 s after about 25 s wall). It was NOT used for the golden logs, because rcS lines 197 to 213 then `param set` COM_DL_LOSS_T, COM_RC_LOSS_T, COM_OF_LOSS_T and COM_OBC_LOSS_T, which changes the configuration. All golden logs ran at 1.0x, lockstep (`boards/px4/sitl/sitl.cmake` sets `ENABLE_LOCKSTEP_SCHEDULER yes` unless env `replay` is set).
- **Isolation from the parallel v1.14.4 agent**: PX4 posix hard-codes the daemon socket `/tmp/px4-sock-<instance>` (`px4_daemon/sock_protocol.cpp` line 47) and lock `/tmp/px4_lock-<instance>` (`main.cpp` line 84), and instance 0 binds UDP 18570, 14580, 14280, 13030, 19450. Using `-i N` would change `MAV_SYS_ID` and `UXRCE_DDS_KEY` (rcS sets both to instance+1) and spoil the item 5 comparison. Every golden run therefore went through `tools/nsrun.sh`: `unshare -m -n`, a private tmpfs on `/tmp` with only `/tmp/claude-0` bound back, and a private loopback brought up by ioctl. PX4 runs as instance 0 with the default configuration; nothing in PX4 is changed by this.
- **Superseded attempt**: the first B1 run (03:10 UTC, before the container restart, no namespace) took off to the default 2.5 m, and `commander mode auto:rtl` at home made RTL land and disarm on its own (`RTL: land at destination`, `Disarmed by landing` at 39.5 s). My `commander land` came after the disarm, so the log has no commanded land. It is kept in `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/superseded/` for reference, and B1 was re-flown with `commander land` 2 s into the RTL descent.

#### Reproducible procedure (all scenarios)

1. Build: `cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0 && make px4_sitl_default` (exit 0).
2. For each scenario run the invocation listed in its section. Each script: creates (or, for mc_flight_2, keeps) the rootfs; starts px4 with the command above; waits for `vehicle_status.pre_flight_checks_pass: True` and `home_position.valid_hpos: True`; issues the commands in the table, waiting on `listener` fields between steps; waits for `arming_state 1` (disarm); sleeps 6 s; runs `logger status` (shows `Not logging`); runs `shutdown`; copies the newest `.ulg` to `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/<scenario>.ulg` and itself to `<scenario>.sh`. Command log with UTC wall-clock times: `<scenario>.cmd.log`; px4 stdout and stderr: `<scenario>.px4.log`.
3. Analysis: `ulog_info <log>`, `ulog_messages <log>`, `ulog_params [-i] <log>`, and the helper scripts in `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/tools/` (`analyze_ulog.py` for state sequences and topic counts, `param_diff.py` for item 5, `vtol_timeline.py` for item 6), all run as `python3 -I <script> <log>`.

### 1. Topic presence and message counts (all logs)

Instance 0 unless noted. `log_message` is never a logged uORB topic in any log (no format definition); flight-stack strings are stored as ULog logging messages (type L), counted in the last row.

| topic | `mc_flight_1` | `mc_flight_2` | `vtol_transition` | `vtol_transition_abort` | `failsafe_gps_loss` | `failsafe_battery_empty` |
|---|---|---|---|---|---|---|
| vehicle_status | 82 | 95 | 188 | 121 | 98 | 88 |
| failsafe_flags | 72 | 83 | 169 | 108 | 89 | 81 |
| vehicle_command | 13 | 13 | 10 | 10 | 5 | 8 |
| vehicle_command_ack | 8 | 8 | 6 | 6 | 5 | 6 |
| vtol_vehicle_status | ABSENT | ABSENT | 92 | 59 | ABSENT | ABSENT |
| vehicle_land_detected | 46 | 50 | 96 | 65 | 54 | 48 |
| sensor_gps | 37 | 43 | 89 | 56 | 32 | 40 |
| vehicle_gps_position | 301 | 346 | 713 | 454 | 262 | 325 |
| battery_status | 189 | 217 | 446 | 285 | 230 | 204 |
| estimator_status_flags | 51 | 58 | 106 | 70 | 63 | 57 |
| log_message | ABSENT | ABSENT | ABSENT | ABSENT | ABSENT | ABSENT |
| ULog logged strings (`ulog_messages`) | 19 | 17 | 18 | 16 | 22 | 24 |
| ULog tagged strings | 0 | 0 | 0 | 0 | 0 | 0 |

Notes: `sensor_gps` is logged at 1 Hz (`logged_topics.cpp` line 199, interval 1000 ms) and `vehicle_gps_position` at 10 Hz (line 143). In the multicopter logs `vtol_vehicle_status` has neither data nor a format definition. The info-multiple `excluded_optional_topics` cannot explain a missing topic: it is capped at 40 entries (`MAX_EXCLUDED_OPTIONAL_TOPICS_NUM = 40`, `logged_topics.h` line 81), every log has exactly 40, and `vtol_vehicle_status` is not among them in the MC logs. SIH GPS never provides UTC: `time_utc_usec` is 0 in every `sensor_gps` and `vehicle_gps_position` message (`SensorGpsSim.cpp` sets `sensor_gps.time_utc_usec = 0`); the only UTC reference in these logs is the info field `boot_time_utc_us` (host clock) with `time_ref_utc` 0.

### 2. Scenarios

#### B1: `mc_flight_1.ulg`

- Airframe `10040_sihsim_quadx` (`PX4_SIM_MODEL=sihsim_quadx`), fresh rootfs /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/mc_rootfs.
- Invocation: `cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0 && ./nsrun.sh ./mc_flight.sh /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/mc_rootfs mc_flight_1`
- Output: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/mc_flight_1.ulg`, 8536869 bytes, SHA-256 `6e7b6956c20422aa9f31a13e7f074e80cba85760928fd895eed941e9492823fc`, ULog duration 37.4 s, dropouts 0.
- arming_state sequence: 0.704 s DISARMED, 4.424 s ARMED, 37.436 s DISARMED
- nav_state sequence: 0.704 s AUTO_LOITER, 7.304 s AUTO_TAKEOFF, 12.956 s AUTO_LOITER, 26.144 s AUTO_RTL, 29.144 s AUTO_LAND, 37.436 s AUTO_LOITER
- vehicle_status.failsafe sequence: 0.704 s false

Ordered commands with wall-clock times (from `mc_flight_1.cmd.log`; `param show` lines are read-only checks):

| wall clock UTC (2026-10-18) | sim time at send | command / observation |
|---|---|---|
| 11:11:09.068 | (boot) | start px4 server (see command line above) |
| 11:11:15.132 | | WAIT ok: vehicle_status.pre_flight_checks_pass=True after 3s (sim t=3.920s) |
| 11:11:15.150 | | WAIT ok: home_position.valid_hpos=True after 0s (sim t=3.920s) |
| 11:11:15.157 | 3.920 | `param show SDLOG_MODE` |
| 11:11:15.168 | 3.920 | `param show SDLOG_PROFILE` |
| 11:11:15.177 | 3.920 | `param show COM_RC_IN_MODE` |
| 11:11:15.186 | 3.920 | `param show SYS_FAILURE_EN` |
| 11:11:15.196 | 3.920 | `param show SYS_AUTOSTART` |
| 11:11:15.213 | 3.920 | `commander arm` |
| 11:11:18.237 | 6.836 | `commander takeoff` |
| 11:11:19.272 | | WAIT ok: vehicle_status.nav_state=17 after 1s (sim t=7.808s) |
| 11:11:24.355 | | WAIT ok: vehicle_status.nav_state=4 after 5s (sim t=12.956s) |
| 11:11:29.387 | 17.996 | `commander mode auto:loiter` |
| 11:11:37.409 | 25.784 | `commander mode auto:rtl` |
| 11:11:38.430 | | WAIT ok: vehicle_status.nav_state=5 after 1s (sim t=26.912s) |
| 11:11:40.453 | 28.928 | `commander land` |
| 11:11:41.473 | | WAIT ok: vehicle_status.nav_state=18 after 1s (sim t=29.912s) |
| 11:11:49.564 | | WAIT ok: vehicle_status.arming_state=1 after 8s (sim t=37.940s) |
| 11:11:55.585 | 43.988 | `logger status` |
| 11:11:55.609 | 43.988 | `shutdown` |
| 11:11:55.628 | | px4 exit=0 |

Observed: `Armed by internal command`, `Takeoff detected`, `RTL: start return`, `Landing at current position` (the commanded land), `Landing detected`, `Disarmed by landing` (px4 output and ULog strings). `latest_disarming_reason` 6 (= `auto_disarm_land`, see section 6 on the enum mismatch). The `commander mode auto:loiter` at 18.2 s was accepted (ack 0) while already in AUTO_LOITER, so it produced a COMMAND without a nav_state change.

<details><summary>ulog_info mc_flight_1.ulg</summary>

```
Logging start time: 0:00:00, duration: 0:00:37
No Dropouts
SW Version: v1.17.0
Info Messages:
 boot_time_utc_us: 1792321870537686
 metadata_events_sha256: 3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d
 sys_name: PX4
 sys_os_name: Linux
 sys_os_ver_release: 101854463
 sys_toolchain: GNU GCC
 sys_toolchain_ver: 13.3.0
 time_ref_utc: 0
 ver_data_format: 2
 ver_hw: PX4_SITL
 ver_sw: d6f12ad1c4f70ad3230afd7d86e971421e02fef4
 ver_sw_release: 17891583
 ver_vendor_sw_release: 255
Info Multiple Messages: [excluded_optional_topics: 40], [metadata_events: 1], [perf_counter_postflight: 1], [perf_counter_preflight: 1]

Name (multi id, message size in bytes)    number of data points, total bytes
 actuator_armed (0, 15)                        82       1230
 actuator_motors (0, 66)                      376      24816
 actuator_outputs (0, 76)                     376      28576
 battery_status (0, 166)                      189      31374
 config_overrides (0, 14)                      76       1064
 control_allocator_status (0, 54)             189      10206
 cpuload (0, 16)                               76       1216
 distance_sensor (0, 56)                     1873     104888
 distance_sensor_mode_change_request (0, 9)       3         27
 ekf2_timestamps (0, 22)                     9361     205942
 estimator_aid_src_baro_hgt (0, 59)           376      22184
 estimator_aid_src_fake_hgt (0, 59)             3        177
 estimator_aid_src_fake_pos (0, 95)            27       2565
 estimator_aid_src_gnss_hgt (0, 59)           294      17346
 estimator_aid_src_gnss_pos (0, 95)           301      28595
 estimator_aid_src_gnss_vel (0, 115)          301      34615
 estimator_aid_src_gravity (0, 115)          3746     430790
 estimator_aid_src_mag (0, 115)               535      61525
 estimator_aid_src_rng_hgt (0, 59)           1864     109976
 estimator_baro_bias (0, 40)                  337      13480
 estimator_event_flags (0, 37)                 40       1480
 estimator_gnss_hgt_bias (0, 40)              292      11680
 estimator_gps_status (0, 40)                 301      12040
 estimator_innovation_test_ratios (0, 140)    3746     524440
 estimator_innovation_variances (0, 140)     3746     524440
 estimator_innovations (0, 140)              3746     524440
 estimator_sensor_bias (0, 118)               558      65844
 estimator_states (0, 213)                   3746     797898
 estimator_status (0, 129)                   3746     483234
 estimator_status_flags (0, 97)                51       4947
 event (0, 40)                                 23        920
 failsafe_flags (0, 91)                        72       6552
 failure_detector_status (0, 24)               83       1992
 gripper (0, 9)                                 1          9
 home_position (0, 60)                        193      11580
 hover_thrust_estimate (0, 41)                233       9553
 landing_gear (0, 9)                            3         27
 manual_control_setpoint (0, 65)                1         65
 mission_result (0, 38)                        47       1786
 navigator_mission_item (0, 47)                 1         47
 navigator_status (0, 10)                      77        770
 parameter_update (0, 34)                       2         68
 position_setpoint_triplet (0, 248)            43      10664
 rate_ctrl_status (0, 20)                     189       3780
 rtl_status (0, 16)                            19        304
 rtl_time_estimate (0, 17)                     19        323
 sensor_accel (0, 44)                          37       1628
 sensor_baro (0, 32)                           37       1184
 sensor_combined (0, 48)                     9361     449328
 sensor_gps (0, 147)                           37       5439
 sensor_gyro (0, 44)                           37       1628
 sensor_gyro_fft (0, 100)                       8        800
 sensor_mag (0, 40)                            37       1480
 sensor_selection (0, 16)                       1         16
 sensors_status_imu (0, 96)                   189      18144
 system_power (0, 42)                          74       3108
 takeoff_status (0, 13)                        13        169
 telemetry_status (0, 84)                      37       3108
 telemetry_status (1, 84)                      37       3108
 telemetry_status (2, 84)                      37       3108
 telemetry_status (3, 84)                      37       3108
 trajectory_setpoint (0, 64)                  189      12096
 transponder_report (0, 78)                     1         78
 vehicle_acceleration (0, 28)                 750      21000
 vehicle_air_data (0, 38)                     375      14250
 vehicle_angular_velocity (0, 40)            3746     149840
 vehicle_angular_velocity_groundtruth (0, 40)    3746     149840
 vehicle_attitude (0, 49)                    9153     448497
 vehicle_attitude_groundtruth (0, 49)        3746     183554
 vehicle_attitude_setpoint (0, 40)            750      30000
 vehicle_command (0, 55)                       13        715
 vehicle_command_ack (0, 22)                    8        176
 vehicle_constraints (0, 17)                   37        629
 vehicle_control_mode (0, 23)                  82       1886
 vehicle_global_position (0, 67)             4386     293862
 vehicle_global_position_groundtruth (0, 67)     376      25192
 vehicle_gps_position (0, 147)                301      44247
 vehicle_imu (0, 60)                           75       4500
 vehicle_imu_status (0, 132)                   37       4884
 vehicle_land_detected (0, 20)                 46        920
 vehicle_local_position (0, 192)             4681     898752
 vehicle_local_position_groundtruth (0, 192)    1874     359808
 vehicle_local_position_setpoint (0, 64)      376      24064
 vehicle_magnetometer (0, 33)                 535      17655
 vehicle_rates_setpoint (0, 33)              1825      60225
 vehicle_status (0, 74)                        82       6068
 vehicle_thrust_setpoint (0, 28)             1874      52472
 vehicle_torque_setpoint (0, 28)             1874      52472
 yaw_estimator_status (0, 105)               4360     457800
```

</details>

<details><summary>analysis (analyze_ulog.py): state sequences, failsafe_flags, commands, acks, battery, GPS, estimator flags, changed parameters, logged strings</summary>

```
FILE: mc_flight_1.ulg  (8536869 bytes)
start=0.992s last=38.432s duration=37.4s
dropouts: 0 []
file_corruption: False  has_default_parameters: 1
info fields:
  boot_time_utc_us = 1792321870537686
  metadata_events_sha256 = '3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d'
  sys_name = 'PX4'
  sys_os_name = 'Linux'
  sys_os_ver_release = 101854463
  sys_toolchain = 'GNU GCC'
  sys_toolchain_ver = '13.3.0'
  time_ref_utc = 0
  ver_data_format = 2
  ver_hw = 'PX4_SITL'
  ver_sw = 'd6f12ad1c4f70ad3230afd7d86e971421e02fef4'
  ver_sw_release = 17891583
  ver_vendor_sw_release = 255
info multiple: {'perf_counter_preflight': 1, 'metadata_events': 1, 'excluded_optional_topics': 40, 'perf_counter_postflight': 1}
initial_parameters: 901   changed_parameters: 20

TOPIC PRESENCE (required list):
  vehicle_status           PRESENT inst0=82 msgs
  failsafe_flags           PRESENT inst0=72 msgs
  vehicle_command          PRESENT inst0=13 msgs
  vehicle_command_ack      PRESENT inst0=8 msgs
  vtol_vehicle_status      ABSENT
  vehicle_land_detected    PRESENT inst0=46 msgs
  sensor_gps               PRESENT inst0=37 msgs
  vehicle_gps_position     PRESENT inst0=301 msgs
  battery_status           PRESENT inst0=189 msgs
  estimator_status_flags   PRESENT inst0=51 msgs
  log_message              ABSENT

VEHICLE_STATUS:
  arming_state (3 changes):
    t=0.704s  DISARMED
    t=4.424s  ARMED
    t=37.436s  DISARMED
  nav_state (6 changes):
    t=0.704s  AUTO_LOITER
    t=7.304s  AUTO_TAKEOFF
    t=12.956s  AUTO_LOITER
    t=26.144s  AUTO_RTL
    t=29.144s  AUTO_LAND
    t=37.436s  AUTO_LOITER
  failsafe (1 changes):
    t=0.704s  0
  failsafe_defer_state (1 changes):
    t=0.704s  0
  vehicle_type (1 changes):
    t=0.704s  ROTARY_WING
  is_vtol (1 changes):
    t=0.704s  0
  in_transition_mode (1 changes):
    t=0.704s  0
  in_transition_to_fw (1 changes):
    t=0.704s  0
  pre_flight_checks_pass (2 changes):
    t=0.704s  0
    t=3.920s  1
  latest_arming_reason (2 changes):
    t=0.704s  0
    t=4.424s  3
  latest_disarming_reason (2 changes):
    t=0.704s  0
    t=37.436s  6

FAILSAFE_FLAGS (fields that change; mode_req_* skipped):
  attitude_invalid (2 changes):
    t=0.704s  1
    t=1.868s  0
  local_altitude_invalid (2 changes):
    t=0.704s  1
    t=1.436s  0
  local_position_invalid (2 changes):
    t=0.704s  1
    t=3.920s  0
  local_position_invalid_relaxed (2 changes):
    t=0.704s  1
    t=3.920s  0
  local_velocity_invalid (2 changes):
    t=0.704s  1
    t=3.920s  0
  global_position_invalid (2 changes):
    t=0.704s  1
    t=3.920s  0
  global_position_invalid_relaxed (2 changes):
    t=0.704s  1
    t=3.920s  0
  auto_mission_missing (1 changes):
    t=0.704s  1
  offboard_control_signal_lost (1 changes):
    t=0.704s  1
  manual_control_signal_lost (1 changes):
    t=0.704s  1
  gcs_connection_lost (1 changes):
    t=0.704s  1

VTOL_VEHICLE_STATUS:
  absent

VEHICLE_LAND_DETECTED:
  landed (3 changes):
    t=0.708s  1
    t=8.180s  0
    t=35.428s  1
  maybe_landed (3 changes):
    t=0.708s  1
    t=8.180s  0
    t=34.428s  1
  ground_contact (3 changes):
    t=0.708s  1
    t=8.244s  0
    t=33.412s  1
  in_ground_effect (6 changes):
    t=0.708s  0
    t=1.444s  1
    t=2.940s  0
    t=2.964s  1
    t=13.484s  0
    t=26.740s  1

VEHICLE_COMMAND (all rows):
    t=0.764s cmd=211 DO_GRIPPER             p1=-3.60267e+12 p2=1 p3=-3.60281e+12 src=191/46144 tgt=81/212 from_external=False
    t=4.420s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=7.284s cmd=22 NAV_TAKEOFF            p1=nan p2=nan p3=nan src=1/1 tgt=1/1 from_external=False
    t=7.296s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=18.220s cmd=176 DO_SET_MODE            p1=1 p2=4 p3=3 src=1/1 tgt=1/1 from_external=False
    t=26.120s cmd=176 DO_SET_MODE            p1=1 p2=4 p3=5 src=1/1 tgt=1/1 from_external=False
    t=26.396s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=1 p2=1 p3=-1 src=1/1 tgt=1/0 from_external=False
    t=26.396s cmd=1000 DO_GIMBAL_MANAGER_PITCHYAW p1=nan p2=nan p3=nan src=1/1 tgt=1/0 from_external=False
    t=26.396s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=-3 p2=-3 p3=-1 src=1/1 tgt=1/0 from_external=False
    t=29.124s cmd=21 NAV_LAND               p1=nan p2=nan p3=nan src=1/1 tgt=1/1 from_external=False
    t=29.396s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=1 p2=1 p3=-1 src=1/1 tgt=1/0 from_external=False
    t=29.396s cmd=1000 DO_GIMBAL_MANAGER_PITCHYAW p1=nan p2=nan p3=nan src=1/1 tgt=1/0 from_external=False
    t=29.396s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=-3 p2=-3 p3=-1 src=1/1 tgt=1/0 from_external=False

VEHICLE_COMMAND_ACK (all rows):
    t=0.768s cmd=211 DO_GRIPPER             result=5 IN_PROGRESS tgt=191/64 from_external=False
    t=1.864s cmd=211 DO_GRIPPER             result=0 ACCEPTED tgt=191/64 from_external=False
    t=4.424s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False
    t=7.292s cmd=22 NAV_TAKEOFF            result=0 ACCEPTED tgt=1/1 from_external=False
    t=7.304s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False
    t=18.224s cmd=176 DO_SET_MODE            result=0 ACCEPTED tgt=1/1 from_external=False
    t=26.132s cmd=176 DO_SET_MODE            result=0 ACCEPTED tgt=1/1 from_external=False
    t=29.132s cmd=21 NAV_LAND               result=0 ACCEPTED tgt=1/1 from_external=False

BATTERY_STATUS inst0:
  warning (1 changes):
    t=0.988s  0
    remaining first=0.989 last=0.806 min=0.501

SENSOR_GPS / VEHICLE_GPS_POSITION fix_type:
  sensor_gps inst0 fix_type (1 changes):
    t=1.904s  3
    sensor_gps inst0 last msg t=37.904s
  vehicle_gps_position inst0 fix_type (1 changes):
    t=0.904s  3
    vehicle_gps_position inst0 last msg t=38.404s

ESTIMATOR_STATUS_FLAGS inst0 (gps-related):
  cs_gnss_pos (2 changes):
    t=0.676s  0
    t=2.932s  1
  cs_gnss_vel (2 changes):
    t=0.676s  0
    t=2.932s  1
  cs_in_air (3 changes):
    t=0.676s  0
    t=8.332s  1
    t=35.580s  0
  cs_inertial_dead_reckoning (2 changes):
    t=0.676s  1
    t=2.932s  0
  cs_wind_dead_reckoning (1 changes):
    t=0.676s  0

CHANGED_PARAMETERS (20):
    t=0.992s CAL_ACC0_ID = 1310988
    t=0.992s CAL_ACC1_ID = 1310996
    t=0.992s CAL_ACC2_ID = 1311004
    t=0.992s CAL_BARO0_ID = 6620172
    t=0.992s CAL_BARO0_OFF = 0.0
    t=0.992s CAL_BARO0_PRIO = 50
    t=0.992s CAL_GYRO0_ID = 1310988
    t=0.992s CAL_GYRO1_ID = 1310996
    t=0.992s CAL_GYRO2_ID = 1311004
    t=0.992s CAL_MAG0_ID = 197388
    t=0.992s CAL_MAG0_PRIO = 50
    t=0.992s CAL_MAG1_ID = 197644
    t=0.992s CAL_MAG1_PRIO = 50
    t=0.992s SENS_BOARD_X_OFF = 9.999999974752427e-07
    t=0.992s SENS_DPRES_OFF = 0.0010000000474974513
    t=0.992s SYS_AUTOCONFIG = 0
    t=0.992s SYS_AUTOSTART = 10040
    t=5.816s CAL_BARO0_ID = 6620172
    t=5.816s CAL_BARO0_OFF = 7.32421875
    t=5.816s CAL_BARO0_PRIO = 50

LOGGED_MESSAGES (19):
    t=0.988s [INFO] [logger] logger started (mode=all)
    t=0.992s [INFO] [logger] Start file log (type: full)
    t=0.992s [INFO] [logger] Opened full log file: ./log/2026-10-18/11_11_11.ulg
    t=0.992s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.992s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.992s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=1.000s [INFO] [px4] Startup script returned successfully
    t=1.400s [INFO] [tone_alarm] home set
    t=3.920s [INFO] [commander] <ESC>[32mReady for takeoff!<ESC>[0m
    t=4.424s [INFO] [commander] Armed by internal command	
    t=4.424s [INFO] [tone_alarm] arming warning
    t=7.304s [INFO] [navigator] Using default takeoff altitude: 2.5 m	
    t=8.192s [INFO] [commander] Takeoff detected	
    t=26.196s [INFO] [navigator] RTL: start return at 493 m (4 m above destination)	
    t=26.244s [INFO] [navigator] RTL: land at destination	
    t=29.132s [INFO] [commander] Landing at current position	
    t=35.432s [INFO] [commander] Landing detected	
    t=37.436s [INFO] [commander] Disarmed by landing	
    t=37.436s [INFO] [tone_alarm] notify neutral

LOGGED_MESSAGES_TAGGED (0)
```

</details>

<details><summary>ulog_messages mc_flight_1.ulg</summary>

```
0:00:00.988 INFO: [logger] logger started (mode=all)
0:00:00.992 INFO: logging: opening log file 2026-10-18/11_11_11.ulg
0:00:00.992 INFO: [logger] Start file log (type: full)
0:00:00.992 INFO: [logger] Opened full log file: ./log/2026-10-18/11_11_11.ulg
0:00:00.992 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.992 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.992 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:01.000 INFO: [px4] Startup script returned successfully
0:00:01.400 INFO: [tone_alarm] home set
0:00:03.920 INFO: [commander] <ESC>[32mReady for takeoff!<ESC>[0m
0:00:04.424 INFO: Armed by internal command
0:00:04.424 INFO: [tone_alarm] arming warning
0:00:07.304 INFO: Using default takeoff altitude: 2.50 m
0:00:08.192 INFO: Takeoff detected
0:00:26.196 INFO: RTL: start return at 493 m (4 m above destination)
0:00:26.244 INFO: RTL: land at destination
0:00:29.132 INFO: Landing at current position
0:00:35.432 INFO: Landing detected
0:00:37.436 INFO: Disarmed by landing
0:00:37.436 INFO: [tone_alarm] notify neutral
```

</details>

<details><summary>command log mc_flight_1.cmd.log</summary>

```
[2026-10-18T11:11:09.028] SCENARIO mc_flight_1  rootfs=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/mc_rootfs keep=no  PX4 v1.17.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4
[2026-10-18T11:11:09.042] rootfs contents before start: 
[2026-10-18T11:11:09.060] host load at start: 4.03 1.74 0.68 11/207 9298  ns: /tmp=claude-0 
[2026-10-18T11:11:09.068] START px4: cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/mc_rootfs && PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/bin/px4 -d /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/etc > /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/mc_flight_1.px4.log 2>&1 &
[2026-10-18T11:11:15.132] WAIT ok: vehicle_status.pre_flight_checks_pass=True after 3s (sim t=3.920s)
[2026-10-18T11:11:15.150] WAIT ok: home_position.valid_hpos=True after 0s (sim t=3.920s)
[2026-10-18T11:11:15.157] CMD (sim t=3.920s): param show SDLOG_MODE
    > Symbols: x = used, + = saved, * = unsaved
    > x   SDLOG_MODE [808,1338] : 1
    > 
    >  901/1794 parameters used.
[2026-10-18T11:11:15.168] CMD (sim t=3.920s): param show SDLOG_PROFILE
    > Symbols: x = used, + = saved, * = unsaved
    > x   SDLOG_PROFILE [809,1339] : 131
    > 
    >  901/1794 parameters used.
[2026-10-18T11:11:15.177] CMD (sim t=3.920s): param show COM_RC_IN_MODE
    > Symbols: x = used, + = saved, * = unsaved
    > x   COM_RC_IN_MODE [296,520] : 1
    > 
    >  901/1794 parameters used.
[2026-10-18T11:11:15.186] CMD (sim t=3.920s): param show SYS_FAILURE_EN
    > Symbols: x = used, + = saved, * = unsaved
    > x   SYS_FAILURE_EN [871,1433] : 1
    > 
    >  901/1794 parameters used.
[2026-10-18T11:11:15.196] CMD (sim t=3.920s): param show SYS_AUTOSTART
    > Symbols: x = used, + = saved, * = unsaved
    > x + SYS_AUTOSTART [866,1423] : 10040
    > 
    >  901/1794 parameters used.
[2026-10-18T11:11:15.206] STATUS: timestamp: 3920000 (0.488000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:11:15.213] CMD (sim t=3.920s): commander arm
[2026-10-18T11:11:18.227] STATUS: timestamp: 6836000 (0.432000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:11:18.237] CMD (sim t=6.836s): commander takeoff
[2026-10-18T11:11:19.272] WAIT ok: vehicle_status.nav_state=17 after 1s (sim t=7.808s)
[2026-10-18T11:11:19.279] STATUS: timestamp: 7808000 (0.496000 seconds ago) | arming_state: 2 | nav_state: 17 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:11:24.355] WAIT ok: vehicle_status.nav_state=4 after 5s (sim t=12.956s)
[2026-10-18T11:11:24.375] STATUS: timestamp: 12956000 (0.324000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:11:29.387] CMD (sim t=17.996s): commander mode auto:loiter
[2026-10-18T11:11:37.402] STATUS: timestamp: 25784000 (0.324000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:11:37.409] CMD (sim t=25.784s): commander mode auto:rtl
[2026-10-18T11:11:38.430] WAIT ok: vehicle_status.nav_state=5 after 1s (sim t=26.912s)
[2026-10-18T11:11:38.438] STATUS: timestamp: 26912000 (0.216000 seconds ago) | arming_state: 2 | nav_state: 5 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:11:40.446] STATUS: timestamp: 28928000 (0.184000 seconds ago) | arming_state: 2 | nav_state: 5 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:11:40.453] CMD (sim t=28.928s): commander land
[2026-10-18T11:11:41.473] WAIT ok: vehicle_status.nav_state=18 after 1s (sim t=29.912s)
[2026-10-18T11:11:41.482] STATUS: timestamp: 29912000 (0.224000 seconds ago) | arming_state: 2 | nav_state: 18 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:11:49.564] WAIT ok: vehicle_status.arming_state=1 after 8s (sim t=37.940s)
[2026-10-18T11:11:49.572] STATUS: timestamp: 37940000 (0.172000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:11:55.585] CMD (sim t=43.988s): logger status
    > INFO  [logger] Running in mode: all
    > INFO  [logger] Number of subscriptions: 170 (5440 bytes)
    > INFO  [logger] Not logging
[2026-10-18T11:11:55.601] ulg files in rootfs newer than start: log/2026-10-18/11_11_11.ulg 
[2026-10-18T11:11:55.609] CMD (sim t=43.988s): shutdown
[2026-10-18T11:11:55.628] px4 exit=0
[2026-10-18T11:11:55.677] COPIED /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/mc_rootfs/log/2026-10-18/11_11_11.ulg -> /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/mc_flight_1.ulg (8536869 bytes)
[2026-10-18T11:11:55.684] rootfs contents after: .start_marker dataman eeprom etc log parameters.bson parameters_backup.bson test_data 
[2026-10-18T11:11:55.689] host load at end: 3.92 2.08 0.85 2/181 11548
[2026-10-18T11:11:55.692] DONE
```

</details>

<details><summary>px4 stdout and stderr mc_flight_1.px4.log</summary>

```

______  __   __    ___ 
| ___ \ \ \ / /   /   |
| |_/ /  \ V /   / /| |
|  __/   /   \  / /_| |
| |     / /^\ \ \___  |
\_|     \/   \/     |_/

px4 starting.

INFO  [px4] startup script: /bin/sh etc/init.d-posix/rcS 0
INFO  [init] found model autostart file as SYS_AUTOSTART=10040
INFO  [param] selected parameter default file parameters.bson
INFO  [param] selected parameter backup file parameters_backup.bson
  SYS_AUTOCONFIG: curr: 0 -> new: 1
  SYS_AUTOSTART: curr: 0 -> new: 10040
  CAL_ACC0_ID: curr: 0 -> new: 1310988
  CAL_GYRO0_ID: curr: 0 -> new: 1310988
  CAL_ACC1_ID: curr: 0 -> new: 1310996
  CAL_GYRO1_ID: curr: 0 -> new: 1310996
  CAL_ACC2_ID: curr: 0 -> new: 1311004
  CAL_GYRO2_ID: curr: 0 -> new: 1311004
  CAL_MAG0_ID: curr: 0 -> new: 197388
  CAL_MAG0_PRIO: curr: -1 -> new: 50
  CAL_MAG1_ID: curr: 0 -> new: 197644
  CAL_MAG1_PRIO: curr: -1 -> new: 50
  SENS_BOARD_X_OFF: curr: 0.0000 -> new: 0.0000
  SENS_DPRES_OFF: curr: 0.0000 -> new: 0.0010
INFO  [dataman] data manager file './dataman' size is 1208528 bytes
INFO  [init] SIH simulator
INFO  [simulator_sih] Simulation loop with 250 Hz (4000 us sim time interval)
INFO  [simulator_sih] Simulation with 1.0x speedup. Loop with (4000 us wall time interval)
INFO  [lockstep_scheduler] setting initial absolute time to 4000 us
INFO  [commander] LED: open /dev/led0 failed (22)
INFO  [uxrce_dds_client] init UDP agent IP:127.0.0.1, port:8888
INFO  [mavlink] mode: Normal, data rate: 4000000 B/s on udp port 18570 remote port 14550
INFO  [mavlink] mode: Onboard, data rate: 4000000 B/s on udp port 14580 remote port 14540
INFO  [mavlink] mode: Onboard, data rate: 4000 B/s on udp port 14280 remote port 14030
INFO  [mavlink] mode: Gimbal, data rate: 400000 B/s on udp port 13030 remote port 13280
INFO  [mavlink] mode: Custom, data rate: 400000 B/s on udp port 19450 remote port 19410
INFO  [logger] logger started (mode=all)
INFO  [logger] Start file log (type: full)
INFO  [logger] [logger] ./log/2026-10-18/11_11_11.ulg	
INFO  [logger] Opened full log file: ./log/2026-10-18/11_11_11.ulg
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [px4] Startup script returned successfully
INFO  [tone_alarm] home set
INFO  [commander] <ESC>[32mReady for takeoff!<ESC>[0m
INFO  [commander] Armed by internal command	
INFO  [tone_alarm] arming warning
INFO  [navigator] Using default takeoff altitude: 2.5 m	
INFO  [commander] Takeoff detected	
INFO  [navigator] RTL: start return at 493 m (4 m above destination)	
INFO  [navigator] RTL: land at destination	
INFO  [commander] Landing at current position	
INFO  [commander] Landing detected	
INFO  [commander] Disarmed by landing	
INFO  [tone_alarm] notify neutral
INFO  [logger] closed logfile, bytes written: 8536869
Exiting NOW.
```

</details>

<details><summary>script mc_flight_1.sh</summary>

```bash
#!/bin/bash
# mc_flight.sh <rootfs_dir> <scenario_name> [keep]
# Scenario B1/B2: SIH quadx, arm, takeoff (MIS_TAKEOFF_ALT default 2.5 m), AUTO_LOITER, commanded AUTO_RTL,
# then `commander land` 2 s into the RTL descent (RTL at home lands by itself after ~11 s, see superseded attempt1),
# auto-disarm by landing. Default configuration, no param set. Run via nsrun.sh (private /tmp + loopback).
# "keep" reuses an existing rootfs (parameters.bson persists) -> scenario B2 / volatile parameter experiment.
set -u
PX4_DIR=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0
BIN=$PX4_DIR/build/px4_sitl_default/bin
ETC=$PX4_DIR/build/px4_sitl_default/etc
OUT=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0
ROOTFS=${1:?rootfs}; SCENARIO=${2:?scenario}; KEEP=${3:-}
MODEL=sihsim_quadx
[ -z "$KEEP" ] && rm -rf "$ROOTFS"
mkdir -p "$ROOTFS" "$OUT"; cd "$ROOTFS"
PX4LOG=$OUT/$SCENARIO.px4.log; CMDLOG=$OUT/$SCENARIO.cmd.log; : > "$CMDLOG"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3N; }
say() { echo "[$(ts)] $*" | tee -a "$CMDLOG"; }
simt() { "$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +timestamp:/{printf "%.3f", $2/1e6}'; }
vs() { say "STATUS: $("$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +(timestamp|arming_state|nav_state|failsafe|vehicle_type|in_transition_mode|in_transition_to_fw|pre_flight_checks_pass):/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
cmd() { say "CMD (sim t=$(simt)s): $*"; "$BIN/px4-$1" "${@:2}" 2>&1 | sed 's/^/    > /' | tee -a "$CMDLOG"; }
wait_for() { # topic field value timeout_s
  local tp=$1 f=$2 v=$3 to=$4 i=0 cur=
  while [ $i -lt "$to" ]; do
    cur=$("$BIN/px4-listener" "$tp" 2>/dev/null | awk -v f="$f" '$1==f":"{print $2}')
    if [ "$cur" = "$v" ]; then say "WAIT ok: $tp.$f=$v after ${i}s (sim t=$(simt)s)"; return 0; fi
    sleep 1; i=$((i+1))
  done
  say "WAIT TIMEOUT: $tp.$f=$cur (wanted $v) after ${to}s (sim t=$(simt)s)"; return 1
}
say "SCENARIO $SCENARIO  rootfs=$ROOTFS keep=${KEEP:-no}  PX4 $(cd $PX4_DIR && git describe --tags --always) $(cd $PX4_DIR && git rev-parse HEAD)"
say "rootfs contents before start: $(ls -A | tr '\n' ' ')"
say "host load at start: $(cat /proc/loadavg)  ns: /tmp=$(ls -A /tmp | tr '\n' ' ')"
touch .start_marker
say "START px4: cd $ROOTFS && PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim $BIN/px4 -d $ETC > $PX4LOG 2>&1 &"
PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim "$BIN/px4" -d "$ETC" > "$PX4LOG" 2>&1 &
PX4_PID=$!
sleep 3
wait_for vehicle_status pre_flight_checks_pass True 150
wait_for home_position valid_hpos True 60
cmd param show SDLOG_MODE; cmd param show SDLOG_PROFILE; cmd param show COM_RC_IN_MODE; cmd param show SYS_FAILURE_EN; cmd param show SYS_AUTOSTART
vs
cmd commander arm
sleep 3; vs
cmd commander takeoff
wait_for vehicle_status nav_state 17 10; vs
wait_for vehicle_status nav_state 4 90; vs
sleep 5
cmd commander mode auto:loiter
sleep 8; vs
cmd commander mode auto:rtl
wait_for vehicle_status nav_state 5 10; vs
sleep 2; vs
cmd commander land
wait_for vehicle_status nav_state 18 10; vs
wait_for vehicle_status arming_state 1 180; vs
sleep 6
cmd logger status
say "ulg files in rootfs newer than start: $(find log -name '*.ulg' -newer .start_marker | tr '\n' ' ')"
cmd shutdown
wait $PX4_PID; say "px4 exit=$?"
ULG=$(find log -name '*.ulg' -newer .start_marker | sort | tail -1)
cp "$ULG" "$OUT/$SCENARIO.ulg"; cp "$0" "$OUT/$SCENARIO.sh"
say "COPIED $ROOTFS/$ULG -> $OUT/$SCENARIO.ulg ($(stat -c %s "$OUT/$SCENARIO.ulg") bytes)"
say "rootfs contents after: $(ls -A | tr '\n' ' ')"
say "host load at end: $(cat /proc/loadavg)"
say "DONE"
```

</details>

#### B2: `mc_flight_2.ulg`

- Airframe `10040_sihsim_quadx` (`PX4_SIM_MODEL=sihsim_quadx`), SAME rootfs as mc_flight_1 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/mc_rootfs, parameters.bson kept).
- Invocation: `cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0 && ./nsrun.sh ./mc_flight.sh /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/mc_rootfs mc_flight_2 keep`
- Output: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/mc_flight_2.ulg`, 9727973 bytes, SHA-256 `05592a1bc28c9f82a420320c8a44191fb34aa92662a50c5d7b9cbaa9aba32b9b`, ULog duration 43.1 s, dropouts 0.
- arming_state sequence: 0.160 s DISARMED, 4.768 s ARMED, 42.472 s DISARMED
- nav_state sequence: 0.160 s AUTO_LOITER, 7.744 s AUTO_TAKEOFF, 13.492 s AUTO_LOITER, 26.536 s AUTO_RTL, 29.524 s AUTO_LAND, 42.472 s AUTO_LOITER
- vehicle_status.failsafe sequence: 0.160 s false

Ordered commands with wall-clock times (from `mc_flight_2.cmd.log`; `param show` lines are read-only checks):

| wall clock UTC (2026-10-18) | sim time at send | command / observation |
|---|---|---|
| 11:12:28.867 | (boot) | start px4 server (see command line above) |
| 11:12:33.910 | | WAIT ok: vehicle_status.pre_flight_checks_pass=True after 2s (sim t=4.312s) |
| 11:12:33.921 | | WAIT ok: home_position.valid_hpos=True after 0s (sim t=4.312s) |
| 11:12:33.928 | 4.312 | `param show SDLOG_MODE` |
| 11:12:33.938 | 4.312 | `param show SDLOG_PROFILE` |
| 11:12:33.949 | 4.312 | `param show COM_RC_IN_MODE` |
| 11:12:33.959 | 4.312 | `param show SYS_FAILURE_EN` |
| 11:12:33.968 | 4.312 | `param show SYS_AUTOSTART` |
| 11:12:33.984 | 4.312 | `commander arm` |
| 11:12:37.001 | 7.432 | `commander takeoff` |
| 11:12:38.033 | | WAIT ok: vehicle_status.nav_state=17 after 1s (sim t=8.248s) |
| 11:12:43.086 | | WAIT ok: vehicle_status.nav_state=4 after 5s (sim t=13.492s) |
| 11:12:48.100 | 18.532 | `commander mode auto:loiter` |
| 11:12:56.118 | 26.200 | `commander mode auto:rtl` |
| 11:12:57.138 | | WAIT ok: vehicle_status.nav_state=5 after 1s (sim t=27.304s) |
| 11:12:59.164 | 29.320 | `commander land` |
| 11:13:00.189 | | WAIT ok: vehicle_status.nav_state=18 after 1s (sim t=30.292s) |
| 11:13:13.304 | | WAIT ok: vehicle_status.arming_state=1 after 13s (sim t=42.976s) |
| 11:13:19.322 | 49.024 | `logger status` |
| 11:13:19.339 | 49.024 | `shutdown` |
| 11:13:19.346 | | px4 exit=0 |

Observed: same messages and same state sequence as mc_flight_1. The rootfs already contained `parameters.bson` from mc_flight_1, so rcS skipped autoconfig (`param compare SYS_AUTOSTART` matched).

<details><summary>ulog_info mc_flight_2.ulg</summary>

```
Logging start time: 0:00:00, duration: 0:00:43
No Dropouts
SW Version: v1.17.0
Info Messages:
 boot_time_utc_us: 1792321949133369
 metadata_events_sha256: 3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d
 sys_name: PX4
 sys_os_name: Linux
 sys_os_ver_release: 101854463
 sys_toolchain: GNU GCC
 sys_toolchain_ver: 13.3.0
 time_ref_utc: 0
 ver_data_format: 2
 ver_hw: PX4_SITL
 ver_sw: d6f12ad1c4f70ad3230afd7d86e971421e02fef4
 ver_sw_release: 17891583
 ver_vendor_sw_release: 255
Info Multiple Messages: [excluded_optional_topics: 40], [metadata_events: 1], [perf_counter_postflight: 1], [perf_counter_preflight: 1]

Name (multi id, message size in bytes)    number of data points, total bytes
 actuator_armed (0, 15)                        95       1425
 actuator_motors (0, 66)                      432      28512
 actuator_outputs (0, 76)                     432      32832
 battery_status (0, 166)                      217      36022
 config_overrides (0, 14)                      85       1190
 control_allocator_status (0, 54)             217      11718
 cpuload (0, 16)                               85       1360
 distance_sensor (0, 56)                     2155     120680
 distance_sensor_mode_change_request (0, 9)       3         27
 ekf2_timestamps (0, 22)                    10772     236984
 estimator_aid_src_baro_hgt (0, 59)           432      25488
 estimator_aid_src_fake_hgt (0, 59)             3        177
 estimator_aid_src_fake_pos (0, 95)            33       3135
 estimator_aid_src_gnss_hgt (0, 59)           339      20001
 estimator_aid_src_gnss_pos (0, 95)           346      32870
 estimator_aid_src_gnss_vel (0, 115)          346      39790
 estimator_aid_src_gravity (0, 115)          4310     495650
 estimator_aid_src_mag (0, 115)               616      70840
 estimator_aid_src_rng_hgt (0, 59)           2116     124844
 estimator_baro_bias (0, 40)                  392      15680
 estimator_event_flags (0, 37)                 46       1702
 estimator_gnss_hgt_bias (0, 40)              335      13400
 estimator_gps_status (0, 40)                 346      13840
 estimator_innovation_test_ratios (0, 140)    4310     603400
 estimator_innovation_variances (0, 140)     4310     603400
 estimator_innovations (0, 140)              4310     603400
 estimator_sensor_bias (0, 118)               658      77644
 estimator_states (0, 213)                   4310     918030
 estimator_status (0, 129)                   4310     555990
 estimator_status_flags (0, 97)                58       5626
 event (0, 40)                                 23        920
 failsafe_flags (0, 91)                        83       7553
 failure_detector_status (0, 24)               97       2328
 gripper (0, 9)                                 1          9
 home_position (0, 60)                        253      15180
 hover_thrust_estimate (0, 41)                275      11275
 landing_gear (0, 9)                            3         27
 manual_control_setpoint (0, 65)                1         65
 mission_result (0, 38)                        45       1710
 navigator_mission_item (0, 47)                 1         47
 navigator_status (0, 10)                      87        870
 parameter_update (0, 34)                       2         68
 position_setpoint_triplet (0, 248)            47      11656
 rate_ctrl_status (0, 20)                     217       4340
 rtl_status (0, 16)                            21        336
 rtl_time_estimate (0, 17)                     21        357
 sensor_accel (0, 44)                          43       1892
 sensor_baro (0, 32)                           43       1376
 sensor_combined (0, 48)                    10772     517056
 sensor_gps (0, 147)                           43       6321
 sensor_gyro (0, 44)                           43       1892
 sensor_gyro_fft (0, 100)                       5        500
 sensor_mag (0, 40)                            43       1720
 sensor_selection (0, 16)                       1         16
 sensors_status_imu (0, 96)                   217      20832
 system_power (0, 42)                          86       3612
 takeoff_status (0, 13)                        14        182
 telemetry_status (0, 84)                      43       3612
 telemetry_status (1, 84)                      43       3612
 telemetry_status (2, 84)                      43       3612
 telemetry_status (3, 84)                      43       3612
 trajectory_setpoint (0, 64)                  217      13888
 transponder_report (0, 78)                     1         78
 vehicle_acceleration (0, 28)                 863      24164
 vehicle_air_data (0, 38)                     432      16416
 vehicle_angular_velocity (0, 40)            4310     172400
 vehicle_angular_velocity_groundtruth (0, 40)    4310     172400
 vehicle_attitude (0, 49)                   10470     513030
 vehicle_attitude_groundtruth (0, 49)        4310     211190
 vehicle_attitude_setpoint (0, 40)            863      34520
 vehicle_command (0, 55)                       13        715
 vehicle_command_ack (0, 22)                    8        176
 vehicle_constraints (0, 17)                   43        731
 vehicle_control_mode (0, 23)                  95       2185
 vehicle_global_position (0, 67)             5092     341164
 vehicle_global_position_groundtruth (0, 67)     432      28944
 vehicle_gps_position (0, 147)                346      50862
 vehicle_imu (0, 60)                           86       5160
 vehicle_imu_status (0, 132)                   43       5676
 vehicle_land_detected (0, 20)                 50       1000
 vehicle_local_position (0, 192)             5387    1034304
 vehicle_local_position_groundtruth (0, 192)    2156     413952
 vehicle_local_position_setpoint (0, 64)      432      27648
 vehicle_magnetometer (0, 33)                 616      20328
 vehicle_rates_setpoint (0, 33)              2072      68376
 vehicle_status (0, 74)                        95       7030
 vehicle_thrust_setpoint (0, 28)             2156      60368
 vehicle_torque_setpoint (0, 28)             2156      60368
 yaw_estimator_status (0, 105)               4320     453600
```

</details>

<details><summary>analysis (analyze_ulog.py): state sequences, failsafe_flags, commands, acks, battery, GPS, estimator flags, changed parameters, logged strings</summary>

```
FILE: mc_flight_2.ulg  (9727973 bytes)
start=0.388s last=43.472s duration=43.1s
dropouts: 0 []
file_corruption: False  has_default_parameters: 1
info fields:
  boot_time_utc_us = 1792321949133369
  metadata_events_sha256 = '3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d'
  sys_name = 'PX4'
  sys_os_name = 'Linux'
  sys_os_ver_release = 101854463
  sys_toolchain = 'GNU GCC'
  sys_toolchain_ver = '13.3.0'
  time_ref_utc = 0
  ver_data_format = 2
  ver_hw = 'PX4_SITL'
  ver_sw = 'd6f12ad1c4f70ad3230afd7d86e971421e02fef4'
  ver_sw_release = 17891583
  ver_vendor_sw_release = 255
info multiple: {'perf_counter_preflight': 1, 'metadata_events': 1, 'excluded_optional_topics': 40, 'perf_counter_postflight': 1}
initial_parameters: 898   changed_parameters: 3

TOPIC PRESENCE (required list):
  vehicle_status           PRESENT inst0=95 msgs
  failsafe_flags           PRESENT inst0=83 msgs
  vehicle_command          PRESENT inst0=13 msgs
  vehicle_command_ack      PRESENT inst0=8 msgs
  vtol_vehicle_status      ABSENT
  vehicle_land_detected    PRESENT inst0=50 msgs
  sensor_gps               PRESENT inst0=43 msgs
  vehicle_gps_position     PRESENT inst0=346 msgs
  battery_status           PRESENT inst0=217 msgs
  estimator_status_flags   PRESENT inst0=58 msgs
  log_message              ABSENT

VEHICLE_STATUS:
  arming_state (3 changes):
    t=0.160s  DISARMED
    t=4.768s  ARMED
    t=42.472s  DISARMED
  nav_state (6 changes):
    t=0.160s  AUTO_LOITER
    t=7.744s  AUTO_TAKEOFF
    t=13.492s  AUTO_LOITER
    t=26.536s  AUTO_RTL
    t=29.524s  AUTO_LAND
    t=42.472s  AUTO_LOITER
  failsafe (1 changes):
    t=0.160s  0
  failsafe_defer_state (1 changes):
    t=0.160s  0
  vehicle_type (1 changes):
    t=0.160s  ROTARY_WING
  is_vtol (1 changes):
    t=0.160s  0
  in_transition_mode (1 changes):
    t=0.160s  0
  in_transition_to_fw (1 changes):
    t=0.160s  0
  pre_flight_checks_pass (2 changes):
    t=0.160s  0
    t=3.808s  1
  latest_arming_reason (2 changes):
    t=0.160s  0
    t=4.768s  3
  latest_disarming_reason (2 changes):
    t=0.160s  0
    t=42.472s  6

FAILSAFE_FLAGS (fields that change; mode_req_* skipped):
  attitude_invalid (2 changes):
    t=0.184s  1
    t=1.648s  0
  local_altitude_invalid (2 changes):
    t=0.184s  1
    t=0.832s  0
  local_position_invalid (2 changes):
    t=0.184s  1
    t=3.808s  0
  local_position_invalid_relaxed (2 changes):
    t=0.184s  1
    t=3.808s  0
  local_velocity_invalid (2 changes):
    t=0.184s  1
    t=3.808s  0
  global_position_invalid (2 changes):
    t=0.184s  1
    t=3.808s  0
  global_position_invalid_relaxed (2 changes):
    t=0.184s  1
    t=3.808s  0
  auto_mission_missing (1 changes):
    t=0.184s  1
  offboard_control_signal_lost (1 changes):
    t=0.184s  1
  manual_control_signal_lost (1 changes):
    t=0.184s  1
  gcs_connection_lost (1 changes):
    t=0.184s  1

VTOL_VEHICLE_STATUS:
  absent

VEHICLE_LAND_DETECTED:
  landed (3 changes):
    t=0.168s  1
    t=8.712s  0
    t=40.456s  1
  maybe_landed (3 changes):
    t=0.168s  1
    t=8.712s  0
    t=39.456s  1
  ground_contact (3 changes):
    t=0.168s  1
    t=8.720s  0
    t=38.104s  1
  in_ground_effect (6 changes):
    t=0.168s  0
    t=0.800s  1
    t=2.800s  0
    t=2.824s  1
    t=14.912s  0
    t=27.104s  1

VEHICLE_COMMAND (all rows):
    t=0.220s cmd=211 DO_GRIPPER             p1=-1.23039e-11 p2=1 p3=-1.23044e-11 src=209/29760 tgt=88/173 from_external=False
    t=4.756s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=7.728s cmd=22 NAV_TAKEOFF            p1=nan p2=nan p3=nan src=1/1 tgt=1/1 from_external=False
    t=7.740s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=18.632s cmd=176 DO_SET_MODE            p1=1 p2=4 p3=3 src=1/1 tgt=1/1 from_external=False
    t=26.516s cmd=176 DO_SET_MODE            p1=1 p2=4 p3=5 src=1/1 tgt=1/1 from_external=False
    t=26.792s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=1 p2=1 p3=-1 src=1/1 tgt=1/0 from_external=False
    t=26.792s cmd=1000 DO_GIMBAL_MANAGER_PITCHYAW p1=nan p2=nan p3=nan src=1/1 tgt=1/0 from_external=False
    t=26.792s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=-3 p2=-3 p3=-1 src=1/1 tgt=1/0 from_external=False
    t=29.508s cmd=21 NAV_LAND               p1=nan p2=nan p3=nan src=1/1 tgt=1/1 from_external=False
    t=29.776s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=1 p2=1 p3=-1 src=1/1 tgt=1/0 from_external=False
    t=29.776s cmd=1000 DO_GIMBAL_MANAGER_PITCHYAW p1=nan p2=nan p3=nan src=1/1 tgt=1/0 from_external=False
    t=29.776s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=-3 p2=-3 p3=-1 src=1/1 tgt=1/0 from_external=False

VEHICLE_COMMAND_ACK (all rows):
    t=0.224s cmd=211 DO_GRIPPER             result=5 IN_PROGRESS tgt=209/64 from_external=False
    t=1.320s cmd=211 DO_GRIPPER             result=0 ACCEPTED tgt=209/64 from_external=False
    t=4.768s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False
    t=7.732s cmd=22 NAV_TAKEOFF            result=0 ACCEPTED tgt=1/1 from_external=False
    t=7.744s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False
    t=18.640s cmd=176 DO_SET_MODE            result=0 ACCEPTED tgt=1/1 from_external=False
    t=26.524s cmd=176 DO_SET_MODE            result=0 ACCEPTED tgt=1/1 from_external=False
    t=29.512s cmd=21 NAV_LAND               result=0 ACCEPTED tgt=1/1 from_external=False

BATTERY_STATUS inst0:
  warning (1 changes):
    t=0.384s  0
    remaining first=0.989 last=0.800 min=0.500

SENSOR_GPS / VEHICLE_GPS_POSITION fix_type:
  sensor_gps inst0 fix_type (1 changes):
    t=1.268s  3
    sensor_gps inst0 last msg t=43.268s
  vehicle_gps_position inst0 fix_type (1 changes):
    t=0.268s  3
    vehicle_gps_position inst0 last msg t=43.392s

ESTIMATOR_STATUS_FLAGS inst0 (gps-related):
  cs_gnss_pos (2 changes):
    t=0.096s  0
    t=2.792s  1
  cs_gnss_vel (2 changes):
    t=0.096s  0
    t=2.792s  1
  cs_in_air (3 changes):
    t=0.096s  0
    t=8.864s  1
    t=40.608s  0
  cs_inertial_dead_reckoning (2 changes):
    t=0.096s  1
    t=2.792s  0
  cs_wind_dead_reckoning (1 changes):
    t=0.096s  0

CHANGED_PARAMETERS (3):
    t=5.408s CAL_BARO0_ID = 6620172
    t=5.408s CAL_BARO0_OFF = -12.20703125
    t=5.408s CAL_BARO0_PRIO = 50

LOGGED_MESSAGES (17):
    t=0.388s [INFO] [logger] Opened full log file: ./log/2026-10-18/11_12_29.ulg
    t=0.388s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.388s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.388s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.392s [INFO] [px4] Startup script returned successfully
    t=0.880s [INFO] [tone_alarm] home set
    t=3.808s [INFO] [commander] <ESC>[32mReady for takeoff!<ESC>[0m
    t=4.768s [INFO] [commander] Armed by internal command	
    t=4.768s [INFO] [tone_alarm] arming warning
    t=7.744s [INFO] [navigator] Using default takeoff altitude: 2.5 m	
    t=8.716s [INFO] [commander] Takeoff detected	
    t=26.592s [INFO] [navigator] RTL: start return at 492 m (3 m above destination)	
    t=26.736s [INFO] [navigator] RTL: land at destination	
    t=29.512s [INFO] [commander] Landing at current position	
    t=40.468s [INFO] [commander] Landing detected	
    t=42.472s [INFO] [commander] Disarmed by landing	
    t=42.472s [INFO] [tone_alarm] notify neutral

LOGGED_MESSAGES_TAGGED (0)
```

</details>

<details><summary>ulog_messages mc_flight_2.ulg</summary>

```
0:00:00.388 INFO: logging: opening log file 2026-10-18/11_12_29.ulg
0:00:00.388 INFO: [logger] Opened full log file: ./log/2026-10-18/11_12_29.ulg
0:00:00.388 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.388 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.388 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.392 INFO: [px4] Startup script returned successfully
0:00:00.880 INFO: [tone_alarm] home set
0:00:03.808 INFO: [commander] <ESC>[32mReady for takeoff!<ESC>[0m
0:00:04.768 INFO: Armed by internal command
0:00:04.768 INFO: [tone_alarm] arming warning
0:00:07.744 INFO: Using default takeoff altitude: 2.50 m
0:00:08.716 INFO: Takeoff detected
0:00:26.592 INFO: RTL: start return at 492 m (3 m above destination)
0:00:26.736 INFO: RTL: land at destination
0:00:29.512 INFO: Landing at current position
0:00:40.468 INFO: Landing detected
0:00:42.472 INFO: Disarmed by landing
0:00:42.472 INFO: [tone_alarm] notify neutral
```

</details>

<details><summary>command log mc_flight_2.cmd.log</summary>

```
[2026-10-18T11:12:28.813] SCENARIO mc_flight_2  rootfs=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/mc_rootfs keep=keep  PX4 v1.17.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4
[2026-10-18T11:12:28.831] rootfs contents before start: .start_marker dataman eeprom etc log parameters.bson parameters_backup.bson test_data 
[2026-10-18T11:12:28.859] host load at start: 2.74 1.99 0.87 7/183 12172  ns: /tmp=claude-0 
[2026-10-18T11:12:28.867] START px4: cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/mc_rootfs && PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/bin/px4 -d /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/etc > /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/mc_flight_2.px4.log 2>&1 &
[2026-10-18T11:12:33.910] WAIT ok: vehicle_status.pre_flight_checks_pass=True after 2s (sim t=4.312s)
[2026-10-18T11:12:33.921] WAIT ok: home_position.valid_hpos=True after 0s (sim t=4.312s)
[2026-10-18T11:12:33.928] CMD (sim t=4.312s): param show SDLOG_MODE
    > Symbols: x = used, + = saved, * = unsaved
    > x   SDLOG_MODE [805,1338] : 1
    > 
    >  898/1794 parameters used.
[2026-10-18T11:12:33.938] CMD (sim t=4.312s): param show SDLOG_PROFILE
    > Symbols: x = used, + = saved, * = unsaved
    > x   SDLOG_PROFILE [806,1339] : 131
    > 
    >  898/1794 parameters used.
[2026-10-18T11:12:33.949] CMD (sim t=4.312s): param show COM_RC_IN_MODE
    > Symbols: x = used, + = saved, * = unsaved
    > x   COM_RC_IN_MODE [293,520] : 1
    > 
    >  898/1794 parameters used.
[2026-10-18T11:12:33.959] CMD (sim t=4.312s): param show SYS_FAILURE_EN
    > Symbols: x = used, + = saved, * = unsaved
    > x   SYS_FAILURE_EN [868,1433] : 1
    > 
    >  898/1794 parameters used.
[2026-10-18T11:12:33.968] CMD (sim t=4.312s): param show SYS_AUTOSTART
    > Symbols: x = used, + = saved, * = unsaved
    > x + SYS_AUTOSTART [863,1423] : 10040
    > 
    >  898/1794 parameters used.
[2026-10-18T11:12:33.978] STATUS: timestamp: 4312000 (0.432000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:12:33.984] CMD (sim t=4.312s): commander arm
[2026-10-18T11:12:36.995] STATUS: timestamp: 7432000 (0.284000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:12:37.001] CMD (sim t=7.432s): commander takeoff
[2026-10-18T11:12:38.033] WAIT ok: vehicle_status.nav_state=17 after 1s (sim t=8.248s)
[2026-10-18T11:12:38.041] STATUS: timestamp: 8752000 (0.000000 seconds ago) | arming_state: 2 | nav_state: 17 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:12:43.086] WAIT ok: vehicle_status.nav_state=4 after 5s (sim t=13.492s)
[2026-10-18T11:12:43.091] STATUS: timestamp: 13492000 (0.220000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:12:48.100] CMD (sim t=18.532s): commander mode auto:loiter
[2026-10-18T11:12:56.111] STATUS: timestamp: 26200000 (0.304000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:12:56.118] CMD (sim t=26.200s): commander mode auto:rtl
[2026-10-18T11:12:57.138] WAIT ok: vehicle_status.nav_state=5 after 1s (sim t=27.304s)
[2026-10-18T11:12:57.145] STATUS: timestamp: 27304000 (0.216000 seconds ago) | arming_state: 2 | nav_state: 5 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:12:59.156] STATUS: timestamp: 29320000 (0.172000 seconds ago) | arming_state: 2 | nav_state: 5 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:12:59.164] CMD (sim t=29.320s): commander land
[2026-10-18T11:13:00.189] WAIT ok: vehicle_status.nav_state=18 after 1s (sim t=30.292s)
[2026-10-18T11:13:00.196] STATUS: timestamp: 30292000 (0.224000 seconds ago) | arming_state: 2 | nav_state: 18 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:13:13.304] WAIT ok: vehicle_status.arming_state=1 after 13s (sim t=42.976s)
[2026-10-18T11:13:13.312] STATUS: timestamp: 42976000 (0.420000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True | 
[2026-10-18T11:13:19.322] CMD (sim t=49.024s): logger status
    > INFO  [logger] Running in mode: all
    > INFO  [logger] Number of subscriptions: 170 (5440 bytes)
    > INFO  [logger] Not logging
[2026-10-18T11:13:19.331] ulg files in rootfs newer than start: log/2026-10-18/11_12_29.ulg 
[2026-10-18T11:13:19.339] CMD (sim t=49.024s): shutdown
[2026-10-18T11:13:19.346] px4 exit=0
[2026-10-18T11:13:19.401] COPIED /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/mc_rootfs/log/2026-10-18/11_12_29.ulg -> /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/mc_flight_2.ulg (9727973 bytes)
[2026-10-18T11:13:19.406] rootfs contents after: .start_marker dataman eeprom etc log parameters.bson parameters_backup.bson test_data 
[2026-10-18T11:13:19.410] host load at end: 1.46 1.76 0.85 2/153 13479
[2026-10-18T11:13:19.413] DONE
```

</details>

<details><summary>px4 stdout and stderr mc_flight_2.px4.log</summary>

```

______  __   __    ___ 
| ___ \ \ \ / /   /   |
| |_/ /  \ V /   / /| |
|  __/   /   \  / /_| |
| |     / /^\ \ \___  |
\_|     \/   \/     |_/

px4 starting.

INFO  [px4] startup script: /bin/sh etc/init.d-posix/rcS 0
INFO  [init] found model autostart file as SYS_AUTOSTART=10040
INFO  [param] selected parameter default file parameters.bson
INFO  [param] importing from 'parameters.bson'
INFO  [parameters] BSON document size 377 bytes, decoded 377 bytes (INT32:15, FLOAT:4)
INFO  [param] selected parameter backup file parameters_backup.bson
INFO  [dataman] data manager file './dataman' size is 1208528 bytes
INFO  [init] SIH simulator
INFO  [simulator_sih] Simulation loop with 250 Hz (4000 us sim time interval)
INFO  [simulator_sih] Simulation with 1.0x speedup. Loop with (4000 us wall time interval)
INFO  [lockstep_scheduler] setting initial absolute time to 4000 us
INFO  [commander] LED: open /dev/led0 failed (22)
INFO  [uxrce_dds_client] init UDP agent IP:127.0.0.1, port:8888
INFO  [mavlink] mode: Normal, data rate: 4000000 B/s on udp port 18570 remote port 14550
INFO  [mavlink] mode: Onboard, data rate: 4000000 B/s on udp port 14580 remote port 14540
INFO  [mavlink] mode: Onboard, data rate: 4000 B/s on udp port 14280 remote port 14030
INFO  [mavlink] mode: Gimbal, data rate: 400000 B/s on udp port 13030 remote port 13280
INFO  [mavlink] mode: Custom, data rate: 400000 B/s on udp port 19450 remote port 19410
INFO  [logger] logger started (mode=all)
INFO  [logger] Start file log (type: full)
INFO  [logger] [logger] ./log/2026-10-18/11_12_29.ulg	
INFO  [logger] Opened full log file: ./log/2026-10-18/11_12_29.ulg
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [px4] Startup script returned successfully
INFO  [tone_alarm] home set
INFO  [commander] <ESC>[32mReady for takeoff!<ESC>[0m
INFO  [commander] Armed by internal command	
INFO  [tone_alarm] arming warning
INFO  [navigator] Using default takeoff altitude: 2.5 m	
INFO  [commander] Takeoff detected	
INFO  [navigator] RTL: start return at 492 m (3 m above destination)	
INFO  [navigator] RTL: land at destination	
INFO  [commander] Landing at current position	
INFO  [commander] Landing detected	
INFO  [commander] Disarmed by landing	
INFO  [tone_alarm] notify neutral
INFO  [logger] closed logfile, bytes written: 9727973
Exiting NOW.
```

</details>

<details><summary>script mc_flight_2.sh</summary>

```bash
#!/bin/bash
# mc_flight.sh <rootfs_dir> <scenario_name> [keep]
# Scenario B1/B2: SIH quadx, arm, takeoff (MIS_TAKEOFF_ALT default 2.5 m), AUTO_LOITER, commanded AUTO_RTL,
# then `commander land` 2 s into the RTL descent (RTL at home lands by itself after ~11 s, see superseded attempt1),
# auto-disarm by landing. Default configuration, no param set. Run via nsrun.sh (private /tmp + loopback).
# "keep" reuses an existing rootfs (parameters.bson persists) -> scenario B2 / volatile parameter experiment.
set -u
PX4_DIR=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0
BIN=$PX4_DIR/build/px4_sitl_default/bin
ETC=$PX4_DIR/build/px4_sitl_default/etc
OUT=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0
ROOTFS=${1:?rootfs}; SCENARIO=${2:?scenario}; KEEP=${3:-}
MODEL=sihsim_quadx
[ -z "$KEEP" ] && rm -rf "$ROOTFS"
mkdir -p "$ROOTFS" "$OUT"; cd "$ROOTFS"
PX4LOG=$OUT/$SCENARIO.px4.log; CMDLOG=$OUT/$SCENARIO.cmd.log; : > "$CMDLOG"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3N; }
say() { echo "[$(ts)] $*" | tee -a "$CMDLOG"; }
simt() { "$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +timestamp:/{printf "%.3f", $2/1e6}'; }
vs() { say "STATUS: $("$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +(timestamp|arming_state|nav_state|failsafe|vehicle_type|in_transition_mode|in_transition_to_fw|pre_flight_checks_pass):/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
cmd() { say "CMD (sim t=$(simt)s): $*"; "$BIN/px4-$1" "${@:2}" 2>&1 | sed 's/^/    > /' | tee -a "$CMDLOG"; }
wait_for() { # topic field value timeout_s
  local tp=$1 f=$2 v=$3 to=$4 i=0 cur=
  while [ $i -lt "$to" ]; do
    cur=$("$BIN/px4-listener" "$tp" 2>/dev/null | awk -v f="$f" '$1==f":"{print $2}')
    if [ "$cur" = "$v" ]; then say "WAIT ok: $tp.$f=$v after ${i}s (sim t=$(simt)s)"; return 0; fi
    sleep 1; i=$((i+1))
  done
  say "WAIT TIMEOUT: $tp.$f=$cur (wanted $v) after ${to}s (sim t=$(simt)s)"; return 1
}
say "SCENARIO $SCENARIO  rootfs=$ROOTFS keep=${KEEP:-no}  PX4 $(cd $PX4_DIR && git describe --tags --always) $(cd $PX4_DIR && git rev-parse HEAD)"
say "rootfs contents before start: $(ls -A | tr '\n' ' ')"
say "host load at start: $(cat /proc/loadavg)  ns: /tmp=$(ls -A /tmp | tr '\n' ' ')"
touch .start_marker
say "START px4: cd $ROOTFS && PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim $BIN/px4 -d $ETC > $PX4LOG 2>&1 &"
PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim "$BIN/px4" -d "$ETC" > "$PX4LOG" 2>&1 &
PX4_PID=$!
sleep 3
wait_for vehicle_status pre_flight_checks_pass True 150
wait_for home_position valid_hpos True 60
cmd param show SDLOG_MODE; cmd param show SDLOG_PROFILE; cmd param show COM_RC_IN_MODE; cmd param show SYS_FAILURE_EN; cmd param show SYS_AUTOSTART
vs
cmd commander arm
sleep 3; vs
cmd commander takeoff
wait_for vehicle_status nav_state 17 10; vs
wait_for vehicle_status nav_state 4 90; vs
sleep 5
cmd commander mode auto:loiter
sleep 8; vs
cmd commander mode auto:rtl
wait_for vehicle_status nav_state 5 10; vs
sleep 2; vs
cmd commander land
wait_for vehicle_status nav_state 18 10; vs
wait_for vehicle_status arming_state 1 180; vs
sleep 6
cmd logger status
say "ulg files in rootfs newer than start: $(find log -name '*.ulg' -newer .start_marker | tr '\n' ' ')"
cmd shutdown
wait $PX4_PID; say "px4 exit=$?"
ULG=$(find log -name '*.ulg' -newer .start_marker | sort | tail -1)
cp "$ULG" "$OUT/$SCENARIO.ulg"; cp "$0" "$OUT/$SCENARIO.sh"
say "COPIED $ROOTFS/$ULG -> $OUT/$SCENARIO.ulg ($(stat -c %s "$OUT/$SCENARIO.ulg") bytes)"
say "rootfs contents after: $(ls -A | tr '\n' ' ')"
say "host load at end: $(cat /proc/loadavg)"
say "DONE"
```

</details>

#### C: `vtol_transition.ulg`

- Airframe `10043_sihsim_standard_vtol` (`PX4_SIM_MODEL=sihsim_standard_vtol`), fresh rootfs /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/vtol_rootfs.
- Invocation: `cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0 && ./nsrun.sh ./vtol_transition.sh /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/vtol_rootfs vtol_transition`
- Output: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/vtol_transition.ulg`, 24295307 bytes, SHA-256 `86d64e54d1261991f4035355550f64e017f8a486c5c665848d6e68ae67fc9bf3`, ULog duration 89.0 s, dropouts 0.
- arming_state sequence: 0.116 s DISARMED, 4.676 s ARMED, 88.272 s DISARMED
- nav_state sequence: 0.116 s AUTO_LOITER, 7.676 s AUTO_TAKEOFF, 22.244 s AUTO_LOITER, 62.160 s AUTO_LAND, 88.272 s AUTO_LOITER
- vehicle_status.failsafe sequence: 0.116 s false

Ordered commands with wall-clock times (from `vtol_transition.cmd.log`; `param show` lines are read-only checks):

| wall clock UTC (2026-10-18) | sim time at send | command / observation |
|---|---|---|
| 11:13:37.185 | (boot) | start px4 server (see command line above) |
| 11:13:42.215 | | WAIT ok: vehicle_status.pre_flight_checks_pass=True after 2s (sim t=4.352s) |
| 11:13:42.226 | | WAIT ok: home_position.valid_hpos=True after 0s (sim t=4.352s) |
| 11:13:42.232 | 4.352 | `param show SYS_AUTOSTART` |
| 11:13:42.243 | 4.352 | `param show MIS_TAKEOFF_ALT` |
| 11:13:42.252 | 4.352 | `param show VT_ARSP_TRANS` |
| 11:13:42.262 | 4.352 | `param show VT_TRANS_TIMEOUT` |
| 11:13:42.271 | 4.352 | `param show VT_TRANS_MIN_TM` |
| 11:13:42.280 | 4.352 | `param show VT_F_TRANS_DUR` |
| 11:13:42.291 | 4.352 | `param show VT_B_TRANS_DUR` |
| 11:13:42.301 | 4.352 | `param show SENS_EN_ARSPDSIM` |
| 11:13:42.331 | 4.352 | `commander arm` |
| 11:13:45.371 | 7.340 | `commander takeoff` |
| 11:13:46.406 | | WAIT ok: vehicle_status.nav_state=17 after 1s (sim t=8.180s) |
| 11:14:00.569 | | WAIT ok: vehicle_status.nav_state=4 after 14s (sim t=22.244s) |
| 11:14:05.628 | 27.284 | `commander transition` |
| 11:14:06.665 | | WAIT ok: vehicle_status.in_transition_mode=True after 0s (sim t=28.004s) |
| 11:14:09.721 | | WAIT ok: vehicle_status.in_transition_mode=False after 3s (sim t=31.016s) |
| 11:14:34.807 | 55.716 | `commander transition` |
| 11:14:35.843 | | WAIT ok: vehicle_status.in_transition_mode=False after 0s (sim t=56.772s) |
| 11:14:40.901 | 61.812 | `commander land` |
| 11:14:41.927 | | WAIT ok: vehicle_status.nav_state=18 after 1s (sim t=62.928s) |
| 11:15:08.137 | | WAIT ok: vehicle_status.arming_state=1 after 26s (sim t=88.788s) |
| 11:15:14.160 | 94.836 | `logger status` |
| 11:15:14.170 | 94.836 | `shutdown` |
| 11:15:14.177 | | px4 exit=0 |

Observed: the front transition completed in 3.0 s (calibrated airspeed reached about 8.5 m/s at 31.0 s with `VT_ARSP_TRANS` 10, `VT_TRANS_MIN_TM` 2, airspeed from `SENS_EN_ARSPDSIM` 1; `airspeed_validated` is logged). No parameter was changed: defaults transitioned on the first try. The FW leg was flown in AUTO_LOITER (no RC, mission or GCS exists headless, so the FW controller flies the loiter pattern, not a straight line) for 25.6 s, between FW at 30.504 s and the back transition at 56.160 s. The back transition took 0.6 s (exit when forward ground speed drops below `MPC_XY_CRUISE`, `standard.cpp` lines 99 to 115). No quad-chute, `fixed_wing_system_failure` stayed false.

<details><summary>ulog_info vtol_transition.ulg</summary>

```
Logging start time: 0:00:00, duration: 0:01:28
No Dropouts
SW Version: v1.17.0
Info Messages:
 boot_time_utc_us: 1792322017566935
 metadata_events_sha256: 3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d
 sys_name: PX4
 sys_os_name: Linux
 sys_os_ver_release: 101854463
 sys_toolchain: GNU GCC
 sys_toolchain_ver: 13.3.0
 time_ref_utc: 0
 ver_data_format: 2
 ver_hw: PX4_SITL
 ver_sw: d6f12ad1c4f70ad3230afd7d86e971421e02fef4
 ver_sw_release: 17891583
 ver_vendor_sw_release: 255
Info Multiple Messages: [excluded_optional_topics: 40], [metadata_events: 1], [perf_counter_postflight: 1], [perf_counter_preflight: 1]

Name (multi id, message size in bytes)    number of data points, total bytes
 actuator_armed (0, 15)                       188       2820
 actuator_motors (0, 66)                      891      58806
 actuator_outputs (0, 76)                     891      67716
 actuator_servos (0, 48)                      891      42768
 airspeed (0, 28)                            1711      47908
 airspeed_validated (0, 41)                   873      35793
 airspeed_wind (0, 61)                         89       5429
 airspeed_wind (1, 61)                         89       5429
 battery_status (0, 166)                      446      74036
 config_overrides (0, 14)                     176       2464
 control_allocator_status (0, 54)             446      24084
 control_allocator_status (1, 54)             446      24084
 cpuload (0, 16)                              177       2832
 distance_sensor (0, 56)                     4449     249144
 distance_sensor_mode_change_request (0, 9)       1          9
 ekf2_timestamps (0, 22)                    22237     489214
 estimator_aid_src_airspeed (0, 59)           873      51507
 estimator_aid_src_baro_hgt (0, 59)           890      52510
 estimator_aid_src_gnss_hgt (0, 59)           704      41536
 estimator_aid_src_gnss_pos (0, 95)           712      67640
 estimator_aid_src_gnss_vel (0, 115)          712      81880
 estimator_aid_src_gravity (0, 115)          8894    1022810
 estimator_aid_src_mag (0, 115)              1257     144555
 estimator_aid_src_rng_hgt (0, 59)           4406     259954
 estimator_aid_src_sideslip (0, 59)           170      10030
 estimator_baro_bias (0, 40)                  849      33960
 estimator_event_flags (0, 37)                 91       3367
 estimator_gnss_hgt_bias (0, 40)              179       7160
 estimator_gps_status (0, 40)                 712      28480
 estimator_innovation_test_ratios (0, 140)    8894    1245160
 estimator_innovation_variances (0, 140)     8894    1245160
 estimator_innovations (0, 140)              8894    1245160
 estimator_sensor_bias (0, 118)               621      73278
 estimator_states (0, 213)                   8894    1894422
 estimator_status (0, 129)                   8894    1147326
 estimator_status_flags (0, 97)               106      10282
 event (0, 40)                                 30       1200
 failsafe_flags (0, 91)                       169      15379
 failure_detector_status (0, 24)              188       4512
 fixed_wing_lateral_guidance_status (0, 37)     295      10915
 fixed_wing_lateral_setpoint (0, 20)         1457      29140
 fixed_wing_lateral_status (0, 16)            295       4720
 fixed_wing_longitudinal_setpoint (0, 28)    1426      39928
 flaps_setpoint (0, 12)                        88       1056
 fw_virtual_attitude_setpoint (0, 40)        3597     143880
 gripper (0, 9)                                 1          9
 home_position (0, 60)                        341      20460
 hover_thrust_estimate (0, 41)                753      30873
 landing_gear (0, 9)                            5         45
 landing_gear_wheel (0, 12)                   873      10476
 lateral_control_configuration (0, 12)         29        348
 longitudinal_control_configuration (0, 38)      29       1102
 manual_control_setpoint (0, 65)                1         65
 mc_virtual_attitude_setpoint (0, 40)        7830     313200
 mission_result (0, 38)                        45       1710
 navigator_status (0, 10)                     177       1770
 parameter_update (0, 34)                       3        102
 position_setpoint_triplet (0, 248)            45      11160
 rate_ctrl_status (0, 20)                     446       8920
 rate_ctrl_status (1, 20)                     446       8920
 rtl_status (0, 16)                            44        704
 rtl_time_estimate (0, 17)                     44        748
 sensor_accel (0, 44)                          89       3916
 sensor_baro (0, 32)                           89       2848
 sensor_combined (0, 48)                    22237    1067376
 sensor_gps (0, 147)                           89      13083
 sensor_gyro (0, 44)                           89       3916
 sensor_gyro_fft (0, 100)                       8        800
 sensor_mag (0, 40)                            89       3560
 sensor_selection (0, 16)                       1         16
 sensors_status_imu (0, 96)                   446      42816
 spoilers_setpoint (0, 12)                     88       1056
 system_power (0, 42)                         177       7434
 takeoff_status (0, 13)                        15        195
 tecs_status (0, 104)                         131      13624
 telemetry_status (0, 84)                      89       7476
 telemetry_status (1, 84)                      89       7476
 telemetry_status (2, 84)                      89       7476
 telemetry_status (3, 84)                      89       7476
 trajectory_setpoint (0, 64)                  319      20416
 transponder_report (0, 78)                     1         78
 vehicle_acceleration (0, 28)                1781      49868
 vehicle_air_data (0, 38)                     891      33858
 vehicle_angular_velocity (0, 40)            8897     355880
 vehicle_angular_velocity_groundtruth (0, 40)    8897     355880
 vehicle_attitude (0, 49)                   21794    1067906
 vehicle_attitude_groundtruth (0, 49)        8897     435953
 vehicle_attitude_setpoint (0, 40)           1776      71040
 vehicle_command (0, 55)                       10        550
 vehicle_command_ack (0, 22)                    6        132
 vehicle_constraints (0, 17)                   66       1122
 vehicle_control_mode (0, 23)                 188       4324
 vehicle_global_position (0, 67)            10699     716833
 vehicle_global_position_groundtruth (0, 67)     891      59697
 vehicle_gps_position (0, 147)                713     104811
 vehicle_imu (0, 60)                          178      10680
 vehicle_imu_status (0, 132)                   89      11748
 vehicle_land_detected (0, 20)                 96       1920
 vehicle_local_position (0, 192)            11116    2134272
 vehicle_local_position_groundtruth (0, 192)    4449     854208
 vehicle_local_position_setpoint (0, 64)      888      56832
 vehicle_magnetometer (0, 33)                1259      41547
 vehicle_rates_setpoint (0, 33)              4357     143781
 vehicle_status (0, 74)                       188      13912
 vehicle_thrust_setpoint (0, 28)             4449     124572
 vehicle_thrust_setpoint (1, 28)             4449     124572
 vehicle_thrust_setpoint_virtual_fw (0, 28)   21191     593348
 vehicle_thrust_setpoint_virtual_mc (0, 28)   21554     603512
 vehicle_torque_setpoint (0, 28)             4449     124572
 vehicle_torque_setpoint (1, 28)             4449     124572
 vehicle_torque_setpoint_virtual_fw (0, 28)   21180     593040
 vehicle_torque_setpoint_virtual_mc (0, 28)   21549     603372
 vtol_vehicle_status (0, 10)                   92        920
 wind (0, 48)                                4438     213024
 yaw_estimator_status (0, 105)              10654    1118670
```

</details>

<details><summary>analysis (analyze_ulog.py): state sequences, failsafe_flags, commands, acks, battery, GPS, estimator flags, changed parameters, logged strings</summary>

```
FILE: vtol_transition.ulg  (24295307 bytes)
start=0.312s last=89.272s duration=89.0s
dropouts: 0 []
file_corruption: False  has_default_parameters: 1
info fields:
  boot_time_utc_us = 1792322017566935
  metadata_events_sha256 = '3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d'
  sys_name = 'PX4'
  sys_os_name = 'Linux'
  sys_os_ver_release = 101854463
  sys_toolchain = 'GNU GCC'
  sys_toolchain_ver = '13.3.0'
  time_ref_utc = 0
  ver_data_format = 2
  ver_hw = 'PX4_SITL'
  ver_sw = 'd6f12ad1c4f70ad3230afd7d86e971421e02fef4'
  ver_sw_release = 17891583
  ver_vendor_sw_release = 255
info multiple: {'perf_counter_preflight': 1, 'metadata_events': 1, 'excluded_optional_topics': 40, 'perf_counter_postflight': 1}
initial_parameters: 1145   changed_parameters: 28

TOPIC PRESENCE (required list):
  vehicle_status           PRESENT inst0=188 msgs
  failsafe_flags           PRESENT inst0=169 msgs
  vehicle_command          PRESENT inst0=10 msgs
  vehicle_command_ack      PRESENT inst0=6 msgs
  vtol_vehicle_status      PRESENT inst0=92 msgs
  vehicle_land_detected    PRESENT inst0=96 msgs
  sensor_gps               PRESENT inst0=89 msgs
  vehicle_gps_position     PRESENT inst0=713 msgs
  battery_status           PRESENT inst0=446 msgs
  estimator_status_flags   PRESENT inst0=106 msgs
  log_message              ABSENT

VEHICLE_STATUS:
  arming_state (3 changes):
    t=0.116s  DISARMED
    t=4.676s  ARMED
    t=88.272s  DISARMED
  nav_state (5 changes):
    t=0.116s  AUTO_LOITER
    t=7.676s  AUTO_TAKEOFF
    t=22.244s  AUTO_LOITER
    t=62.160s  AUTO_LAND
    t=88.272s  AUTO_LOITER
  failsafe (1 changes):
    t=0.116s  0
  failsafe_defer_state (1 changes):
    t=0.116s  0
  vehicle_type (3 changes):
    t=0.116s  ROTARY_WING
    t=30.512s  FIXED_WING
    t=56.172s  ROTARY_WING
  is_vtol (1 changes):
    t=0.116s  1
  in_transition_mode (5 changes):
    t=0.116s  0
    t=27.500s  1
    t=30.512s  0
    t=56.172s  1
    t=56.772s  0
  in_transition_to_fw (3 changes):
    t=0.116s  0
    t=27.500s  1
    t=30.512s  0
  pre_flight_checks_pass (2 changes):
    t=0.116s  0
    t=4.352s  1
  latest_arming_reason (2 changes):
    t=0.116s  0
    t=4.676s  3
  latest_disarming_reason (2 changes):
    t=0.116s  0
    t=88.272s  6

FAILSAFE_FLAGS (fields that change; mode_req_* skipped):
  attitude_invalid (2 changes):
    t=0.176s  1
    t=2.192s  0
  local_altitude_invalid (2 changes):
    t=0.176s  1
    t=0.932s  0
  local_position_invalid (2 changes):
    t=0.176s  1
    t=4.352s  0
  local_position_invalid_relaxed (2 changes):
    t=0.176s  1
    t=4.352s  0
  local_velocity_invalid (2 changes):
    t=0.176s  1
    t=4.352s  0
  global_position_invalid (2 changes):
    t=0.176s  1
    t=4.352s  0
  global_position_invalid_relaxed (2 changes):
    t=0.176s  1
    t=4.352s  0
  auto_mission_missing (1 changes):
    t=0.176s  1
  offboard_control_signal_lost (1 changes):
    t=0.176s  1
  manual_control_signal_lost (1 changes):
    t=0.176s  1
  gcs_connection_lost (1 changes):
    t=0.176s  1

VTOL_VEHICLE_STATUS:
  vehicle_vtol_state (5 changes):
    t=0.100s  MC
    t=27.488s  TRANSITION_TO_FW
    t=30.504s  FW
    t=56.160s  TRANSITION_TO_MC
    t=56.760s  MC
  fixed_wing_system_failure (1 changes):
    t=0.100s  0

VEHICLE_LAND_DETECTED:
  landed (3 changes):
    t=0.184s  1
    t=8.488s  0
    t=86.260s  1
  maybe_landed (3 changes):
    t=0.184s  1
    t=8.488s  0
    t=85.260s  1
  ground_contact (3 changes):
    t=0.184s  1
    t=8.608s  0
    t=84.260s  1
  in_ground_effect (6 changes):
    t=0.184s  0
    t=0.928s  1
    t=3.304s  0
    t=3.328s  1
    t=12.088s  0
    t=63.940s  1

VEHICLE_COMMAND (all rows):
    t=0.160s cmd=211 DO_GRIPPER             p1=-6.67182e+28 p2=1 p3=-6.67208e+28 src=51/37952 tgt=87/239 from_external=False
    t=4.672s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=7.652s cmd=22 NAV_TAKEOFF            p1=nan p2=nan p3=nan src=1/1 tgt=1/1 from_external=False
    t=7.664s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=27.484s cmd=3000 DO_VTOL_TRANSITION     p1=4 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=56.156s cmd=3000 DO_VTOL_TRANSITION     p1=3 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=62.144s cmd=21 NAV_LAND               p1=nan p2=nan p3=nan src=1/1 tgt=1/1 from_external=False
    t=62.412s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=1 p2=1 p3=-1 src=1/1 tgt=1/0 from_external=False
    t=62.412s cmd=1000 DO_GIMBAL_MANAGER_PITCHYAW p1=nan p2=nan p3=nan src=1/1 tgt=1/0 from_external=False
    t=62.412s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=-3 p2=-3 p3=-1 src=1/1 tgt=1/0 from_external=False

VEHICLE_COMMAND_ACK (all rows):
    t=0.164s cmd=211 DO_GRIPPER             result=5 IN_PROGRESS tgt=51/64 from_external=False
    t=1.260s cmd=211 DO_GRIPPER             result=0 ACCEPTED tgt=51/64 from_external=False
    t=4.676s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False
    t=7.664s cmd=22 NAV_TAKEOFF            result=0 ACCEPTED tgt=1/1 from_external=False
    t=7.676s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False
    t=62.148s cmd=21 NAV_LAND               result=0 ACCEPTED tgt=1/1 from_external=False

BATTERY_STATUS inst0:
  warning (1 changes):
    t=0.316s  0
    remaining first=0.989 last=0.802 min=0.500

SENSOR_GPS / VEHICLE_GPS_POSITION fix_type:
  sensor_gps inst0 fix_type (1 changes):
    t=1.144s  3
    sensor_gps inst0 last msg t=89.144s
  vehicle_gps_position inst0 fix_type (1 changes):
    t=0.268s  3
    vehicle_gps_position inst0 last msg t=89.268s

ESTIMATOR_STATUS_FLAGS inst0 (gps-related):
  cs_gnss_pos (2 changes):
    t=0.344s  0
    t=3.296s  1
  cs_gnss_vel (2 changes):
    t=0.344s  0
    t=3.296s  1
  cs_in_air (3 changes):
    t=0.344s  0
    t=8.640s  1
    t=86.412s  0
  cs_inertial_dead_reckoning (2 changes):
    t=0.344s  1
    t=3.296s  0
  cs_wind_dead_reckoning (1 changes):
    t=0.344s  0

CHANGED_PARAMETERS (28):
    t=0.312s CAL_ACC0_ID = 1310988
    t=0.312s CAL_ACC1_ID = 1310996
    t=0.312s CAL_ACC2_ID = 1311004
    t=0.312s CAL_BARO0_ID = 6620172
    t=0.312s CAL_BARO0_OFF = 0.0
    t=0.312s CAL_BARO0_PRIO = 50
    t=0.312s CAL_GYRO0_ID = 1310988
    t=0.312s CAL_GYRO1_ID = 1310996
    t=0.312s CAL_GYRO2_ID = 1311004
    t=0.312s CAL_MAG0_ID = 197388
    t=0.312s CAL_MAG0_PRIO = 50
    t=0.312s CAL_MAG1_ID = 197644
    t=0.312s CAL_MAG1_PRIO = 50
    t=0.312s SENS_BOARD_X_OFF = 9.999999974752427e-07
    t=0.312s SENS_DPRES_OFF = 0.0010000000474974513
    t=0.312s SIH_IXX = 0.003539999946951866
    t=0.312s SIH_IYY = 0.0006249999860301614
    t=0.312s SIH_IZZ = 0.003000000026077032
    t=0.312s SIH_KDV = 0.20000000298023224
    t=0.312s SIH_MASS = 0.20000000298023224
    t=0.312s SIH_Q_MAX = 0.016499999910593033
    t=0.312s SIH_T_MAX = 2.0
    t=0.312s SIH_VEHICLE_TYPE = 3
    t=0.312s SYS_AUTOCONFIG = 0
    t=0.312s SYS_AUTOSTART = 10043
    t=5.308s CAL_BARO0_ID = 6620172
    t=5.308s CAL_BARO0_OFF = 2.44140625
    t=5.308s CAL_BARO0_PRIO = 50

LOGGED_MESSAGES (18):
    t=0.312s [INFO] [logger] logger started (mode=all)
    t=0.312s [INFO] [logger] Start file log (type: full)
    t=0.312s [INFO] [logger] Opened full log file: ./log/2026-10-18/11_13_37.ulg
    t=0.316s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.316s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.316s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.320s [INFO] [px4] Startup script returned successfully
    t=0.872s [INFO] [tone_alarm] home set
    t=4.352s [INFO] [commander] <ESC>[32mReady for takeoff!<ESC>[0m
    t=4.676s [INFO] [commander] Armed by internal command	
    t=4.676s [INFO] [tone_alarm] arming warning
    t=7.676s [INFO] [navigator] Using default takeoff altitude: 20.0 m	
    t=8.492s [INFO] [commander] Takeoff detected	
    t=62.148s [INFO] [commander] Landing at current position	
    t=86.268s [INFO] [commander] Landing detected	
    t=88.272s [INFO] [commander] Disarmed by landing	
    t=88.272s [INFO] [tone_alarm] notify neutral
    t=88.276s [INFO] [vehicle_imu] ACC 0 (1310988) offset committed: [0.000 0.000 0.000]->[0.103 0.011 0.012])

LOGGED_MESSAGES_TAGGED (0)
```

</details>

<details><summary>ulog_messages vtol_transition.ulg</summary>

```
0:00:00.312 INFO: logging: opening log file 2026-10-18/11_13_37.ulg
0:00:00.312 INFO: [logger] logger started (mode=all)
0:00:00.312 INFO: [logger] Start file log (type: full)
0:00:00.312 INFO: [logger] Opened full log file: ./log/2026-10-18/11_13_37.ulg
0:00:00.316 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.316 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.316 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.320 INFO: [px4] Startup script returned successfully
0:00:00.872 INFO: [tone_alarm] home set
0:00:04.352 INFO: [commander] <ESC>[32mReady for takeoff!<ESC>[0m
0:00:04.676 INFO: Armed by internal command
0:00:04.676 INFO: [tone_alarm] arming warning
0:00:07.676 INFO: Using default takeoff altitude: 20.00 m
0:00:08.492 INFO: Takeoff detected
0:01:02.148 INFO: Landing at current position
0:01:26.268 INFO: Landing detected
0:01:28.272 INFO: Disarmed by landing
0:01:28.272 INFO: [tone_alarm] notify neutral
0:01:28.276 INFO: [vehicle_imu] ACC 0 (1310988) offset committed: [0.000 0.000 0.000]->[0.103 0.011 0.012])
```

</details>

<details><summary>command log vtol_transition.cmd.log</summary>

```
[2026-10-18T11:13:37.142] SCENARIO vtol_transition  rootfs=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/vtol_rootfs  PX4 v1.17.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4
[2026-10-18T11:13:37.169] host load at start: 1.36 1.72 0.85 6/153 13563  ns: /tmp=claude-0 
[2026-10-18T11:13:37.185] START px4: cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/vtol_rootfs && PX4_SIM_MODEL=sihsim_standard_vtol PX4_SIMULATOR=sihsim /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/bin/px4 -d /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/etc > /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/vtol_transition.px4.log 2>&1 &
[2026-10-18T11:13:42.215] WAIT ok: vehicle_status.pre_flight_checks_pass=True after 2s (sim t=4.352s)
[2026-10-18T11:13:42.226] WAIT ok: home_position.valid_hpos=True after 0s (sim t=4.352s)
[2026-10-18T11:13:42.232] CMD (sim t=4.352s): param show SYS_AUTOSTART
    > Symbols: x = used, + = saved, * = unsaved
    > x + SYS_AUTOSTART [1078,1423] : 10043
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:13:42.243] CMD (sim t=4.352s): param show MIS_TAKEOFF_ALT
    > Symbols: x = used, + = saved, * = unsaved
    > x   MIS_TAKEOFF_ALT [773,1031] : 20.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:13:42.252] CMD (sim t=4.352s): param show VT_ARSP_TRANS
    > Symbols: x = used, + = saved, * = unsaved
    > x   VT_ARSP_TRANS [1111,1755] : 10.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:13:42.262] CMD (sim t=4.352s): param show VT_TRANS_TIMEOUT
    > Symbols: x = used, + = saved, * = unsaved
    > x   VT_TRANS_TIMEOUT [1137,1786] : 15.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:13:42.271] CMD (sim t=4.352s): param show VT_TRANS_MIN_TM
    > Symbols: x = used, + = saved, * = unsaved
    > x   VT_TRANS_MIN_TM [1136,1784] : 2.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:13:42.280] CMD (sim t=4.352s): param show VT_F_TRANS_DUR
    > Symbols: x = used, + = saved, * = unsaved
    > x   VT_F_TRANS_DUR [1127,1772] : 5.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:13:42.291] CMD (sim t=4.352s): param show VT_B_TRANS_DUR
    > Symbols: x = used, + = saved, * = unsaved
    > x   VT_B_TRANS_DUR [1114,1759] : 10.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:13:42.301] CMD (sim t=4.352s): param show SENS_EN_ARSPDSIM
    > Symbols: x = used, + = saved, * = unsaved
    > x   SENS_EN_ARSPDSIM [1032,1353] : 1
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:13:42.324] STATUS: timestamp: 4352000 (0.296000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.09767 | airspeed_source: 1 | 
[2026-10-18T11:13:42.331] CMD (sim t=4.352s): commander arm
[2026-10-18T11:13:45.363] STATUS: timestamp: 7340000 (0.284000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.22022 | airspeed_source: 1 | 
[2026-10-18T11:13:45.371] CMD (sim t=7.340s): commander takeoff
[2026-10-18T11:13:46.406] WAIT ok: vehicle_status.nav_state=17 after 1s (sim t=8.180s)
[2026-10-18T11:13:46.425] STATUS: timestamp: 8180000 (0.492000 seconds ago) | arming_state: 2 | nav_state: 17 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.12012 | airspeed_source: 1 | 
[2026-10-18T11:14:00.569] WAIT ok: vehicle_status.nav_state=4 after 14s (sim t=22.244s)
[2026-10-18T11:14:00.598] STATUS: timestamp: 22244000 (0.260000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.76176 | airspeed_source: 1 | 
[2026-10-18T11:14:05.620] STATUS: timestamp: 27284000 (0.172000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.09757 | airspeed_source: 1 | 
[2026-10-18T11:14:05.628] CMD (sim t=27.284s): commander transition
[2026-10-18T11:14:06.653] STATUS: timestamp: 28004000 (0.468000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: True | in_transition_to_fw: True | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 1 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 1.93944 | airspeed_source: 1 | 
[2026-10-18T11:14:06.665] WAIT ok: vehicle_status.in_transition_mode=True after 0s (sim t=28.004s)
[2026-10-18T11:14:06.681] STATUS: timestamp: 28004000 (0.496000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: True | in_transition_to_fw: True | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 1 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 2.44769 | airspeed_source: 1 | 
[2026-10-18T11:14:09.721] WAIT ok: vehicle_status.in_transition_mode=False after 3s (sim t=31.016s)
[2026-10-18T11:14:09.737] STATUS: timestamp: 31016000 (0.496000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 2 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 4 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 8.53897 | airspeed_source: 1 | 
[2026-10-18T11:14:14.758] STATUS: timestamp: 36056000 (0.396000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 2 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 4 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 9.42175 | airspeed_source: 1 | 
[2026-10-18T11:14:24.776] STATUS: timestamp: 46140000 (0.128000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 2 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 4 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 8.87673 | airspeed_source: 1 | 
[2026-10-18T11:14:34.799] STATUS: timestamp: 55716000 (0.412000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 2 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 4 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 9.34708 | airspeed_source: 1 | 
[2026-10-18T11:14:34.807] CMD (sim t=55.716s): commander transition
[2026-10-18T11:14:35.831] STATUS: timestamp: 56772000 (0.376000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 3.61978 | airspeed_source: 1 | 
[2026-10-18T11:14:35.843] WAIT ok: vehicle_status.in_transition_mode=False after 0s (sim t=56.772s)
[2026-10-18T11:14:35.862] STATUS: timestamp: 56772000 (0.404000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 3.61978 | airspeed_source: 1 | 
[2026-10-18T11:14:40.889] STATUS: timestamp: 61812000 (0.300000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 3.94203 | airspeed_source: 1 | 
[2026-10-18T11:14:40.901] CMD (sim t=61.812s): commander land
[2026-10-18T11:14:41.927] WAIT ok: vehicle_status.nav_state=18 after 1s (sim t=62.928s)
[2026-10-18T11:14:41.940] STATUS: timestamp: 62928000 (0.224000 seconds ago) | arming_state: 2 | nav_state: 18 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 3.25297 | airspeed_source: 1 | 
[2026-10-18T11:15:08.137] WAIT ok: vehicle_status.arming_state=1 after 26s (sim t=88.788s)
[2026-10-18T11:15:08.151] STATUS: timestamp: 88788000 (0.128000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.09767 | airspeed_source: 1 | 
[2026-10-18T11:15:14.160] CMD (sim t=94.836s): logger status
    > INFO  [logger] Running in mode: all
    > INFO  [logger] Number of subscriptions: 187 (5984 bytes)
    > INFO  [logger] Not logging
[2026-10-18T11:15:14.170] CMD (sim t=94.836s): shutdown
[2026-10-18T11:15:14.177] px4 exit=0
[2026-10-18T11:15:14.209] COPIED /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/vtol_rootfs/log/2026-10-18/11_13_37.ulg -> /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/vtol_transition.ulg (24295307 bytes)
[2026-10-18T11:15:14.214] host load at end: 2.68 1.99 1.03 2/150 17383
[2026-10-18T11:15:14.217] DONE
```

</details>

<details><summary>px4 stdout and stderr vtol_transition.px4.log</summary>

```

______  __   __    ___ 
| ___ \ \ \ / /   /   |
| |_/ /  \ V /   / /| |
|  __/   /   \  / /_| |
| |     / /^\ \ \___  |
\_|     \/   \/     |_/

px4 starting.

INFO  [px4] startup script: /bin/sh etc/init.d-posix/rcS 0
INFO  [init] found model autostart file as SYS_AUTOSTART=10043
INFO  [param] selected parameter default file parameters.bson
INFO  [param] selected parameter backup file parameters_backup.bson
  SYS_AUTOCONFIG: curr: 0 -> new: 1
  SYS_AUTOSTART: curr: 0 -> new: 10043
  CAL_ACC0_ID: curr: 0 -> new: 1310988
  CAL_GYRO0_ID: curr: 0 -> new: 1310988
  CAL_ACC1_ID: curr: 0 -> new: 1310996
  CAL_GYRO1_ID: curr: 0 -> new: 1310996
  CAL_ACC2_ID: curr: 0 -> new: 1311004
  CAL_GYRO2_ID: curr: 0 -> new: 1311004
  CAL_MAG0_ID: curr: 0 -> new: 197388
  CAL_MAG0_PRIO: curr: -1 -> new: 50
  CAL_MAG1_ID: curr: 0 -> new: 197644
  CAL_MAG1_PRIO: curr: -1 -> new: 50
  SENS_BOARD_X_OFF: curr: 0.0000 -> new: 0.0000
  SENS_DPRES_OFF: curr: 0.0000 -> new: 0.0010
  SIH_T_MAX: curr: 5.0000 -> new: 2.0000
  SIH_Q_MAX: curr: 0.1000 -> new: 0.0165
  SIH_MASS: curr: 1.0000 -> new: 0.2000
  SIH_IXX: curr: 0.0250 -> new: 0.0035
  SIH_IYY: curr: 0.0250 -> new: 0.0006
  SIH_IZZ: curr: 0.0300 -> new: 0.0030
  SIH_KDV: curr: 1.0000 -> new: 0.2000
  SIH_VEHICLE_TYPE: curr: 0 -> new: 3
INFO  [dataman] data manager file './dataman' size is 1208528 bytes
INFO  [init] SIH simulator
INFO  [simulator_sih] Simulation loop with 250 Hz (4000 us sim time interval)
INFO  [simulator_sih] Simulation with 1.0x speedup. Loop with (4000 us wall time interval)
INFO  [lockstep_scheduler] setting initial absolute time to 4000 us
INFO  [commander] LED: open /dev/led0 failed (22)
INFO  [uxrce_dds_client] init UDP agent IP:127.0.0.1, port:8888
INFO  [mavlink] mode: Normal, data rate: 4000000 B/s on udp port 18570 remote port 14550
INFO  [mavlink] mode: Onboard, data rate: 4000000 B/s on udp port 14580 remote port 14540
INFO  [mavlink] mode: Onboard, data rate: 4000 B/s on udp port 14280 remote port 14030
INFO  [mavlink] mode: Gimbal, data rate: 400000 B/s on udp port 13030 remote port 13280
INFO  [mavlink] mode: Custom, data rate: 400000 B/s on udp port 19450 remote port 19410
INFO  [logger] logger started (mode=all)
INFO  [logger] Start file log (type: full)
INFO  [logger] [logger] ./log/2026-10-18/11_13_37.ulg	
INFO  [logger] Opened full log file: ./log/2026-10-18/11_13_37.ulg
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [px4] Startup script returned successfully
INFO  [tone_alarm] home set
INFO  [commander] <ESC>[32mReady for takeoff!<ESC>[0m
INFO  [commander] Armed by internal command	
INFO  [tone_alarm] arming warning
INFO  [navigator] Using default takeoff altitude: 20.0 m	
INFO  [commander] Takeoff detected	
INFO  [commander] Landing at current position	
INFO  [commander] Landing detected	
INFO  [commander] Disarmed by landing	
INFO  [tone_alarm] notify neutral
INFO  [vehicle_imu] ACC 0 (1310988) offset committed: [0.000 0.000 0.000]->[0.103 0.011 0.012])
INFO  [logger] closed logfile, bytes written: 24295307
Exiting NOW.
```

</details>

<details><summary>script vtol_transition.sh</summary>

```bash
#!/bin/bash
# vtol_transition.sh <rootfs_dir> <scenario_name>
# Scenario C: SIH standard VTOL, arm, takeoff (MIS_TAKEOFF_ALT 20 m default for VTOL), transition to FW,
# fly ~25 s in FW (AUTO_LOITER: FW loiter circle, no stick input available headless), transition back to MC,
# commanded land, auto-disarm. Fresh rootfs.
set -u
PX4_DIR=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0
BIN=$PX4_DIR/build/px4_sitl_default/bin
ETC=$PX4_DIR/build/px4_sitl_default/etc
OUT=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0
ROOTFS=${1:?rootfs}; SCENARIO=${2:?scenario}
MODEL=sihsim_standard_vtol
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS" "$OUT"; cd "$ROOTFS"
PX4LOG=$OUT/$SCENARIO.px4.log; CMDLOG=$OUT/$SCENARIO.cmd.log; : > "$CMDLOG"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3N; }
say() { echo "[$(ts)] $*" | tee -a "$CMDLOG"; }
simt() { "$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +timestamp:/{printf "%.3f", $2/1e6}'; }
vs() { say "STATUS: $("$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +(timestamp|arming_state|nav_state|failsafe|vehicle_type|in_transition_mode|in_transition_to_fw|pre_flight_checks_pass):/{gsub(/^ +/,""); printf "%s | ", $0}') VTOL: $("$BIN/px4-listener" vtol_vehicle_status 2>/dev/null | awk '/^ +(vehicle_vtol_state|fixed_wing_system_failure):/{gsub(/^ +/,""); printf "%s | ", $0}') ARSPD: $("$BIN/px4-listener" airspeed_validated 2>/dev/null | awk '/^ +(calibrated_airspeed_m_s|airspeed_source):/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
cmd() { say "CMD (sim t=$(simt)s): $*"; "$BIN/px4-$1" "${@:2}" 2>&1 | sed 's/^/    > /' | tee -a "$CMDLOG"; }
wait_for() { # topic field value timeout_s
  local tp=$1 f=$2 v=$3 to=$4 i=0 cur=
  while [ $i -lt "$to" ]; do
    cur=$("$BIN/px4-listener" "$tp" 2>/dev/null | awk -v f="$f" '$1==f":"{print $2}')
    if [ "$cur" = "$v" ]; then say "WAIT ok: $tp.$f=$v after ${i}s (sim t=$(simt)s)"; return 0; fi
    sleep 1; i=$((i+1))
  done
  say "WAIT TIMEOUT: $tp.$f=$cur (wanted $v) after ${to}s (sim t=$(simt)s)"; return 1
}
say "SCENARIO $SCENARIO  rootfs=$ROOTFS  PX4 $(cd $PX4_DIR && git describe --tags --always) $(cd $PX4_DIR && git rev-parse HEAD)"
say "host load at start: $(cat /proc/loadavg)  ns: /tmp=$(ls -A /tmp | tr '\n' ' ')"
touch .start_marker
say "START px4: cd $ROOTFS && PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim $BIN/px4 -d $ETC > $PX4LOG 2>&1 &"
PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim "$BIN/px4" -d "$ETC" > "$PX4LOG" 2>&1 &
PX4_PID=$!
sleep 3
wait_for vehicle_status pre_flight_checks_pass True 150
wait_for home_position valid_hpos True 60
cmd param show SYS_AUTOSTART; cmd param show MIS_TAKEOFF_ALT; cmd param show VT_ARSP_TRANS; cmd param show VT_TRANS_TIMEOUT; cmd param show VT_TRANS_MIN_TM; cmd param show VT_F_TRANS_DUR; cmd param show VT_B_TRANS_DUR; cmd param show SENS_EN_ARSPDSIM
vs
cmd commander arm
sleep 3; vs
cmd commander takeoff
wait_for vehicle_status nav_state 17 10; vs
wait_for vehicle_status nav_state 4 120; vs
sleep 5; vs
cmd commander transition
sleep 1; vs
wait_for vehicle_status in_transition_mode True 10; vs
wait_for vehicle_status in_transition_mode False 40; vs
sleep 5; vs
sleep 10; vs
sleep 10; vs
cmd commander transition
sleep 1; vs
wait_for vehicle_status in_transition_mode False 40; vs
sleep 5; vs
cmd commander land
wait_for vehicle_status nav_state 18 10; vs
wait_for vehicle_status arming_state 1 240; vs
sleep 6
cmd logger status
cmd shutdown
wait $PX4_PID; say "px4 exit=$?"
ULG=$(find log -name '*.ulg' -newer .start_marker | sort | tail -1)
cp "$ULG" "$OUT/$SCENARIO.ulg"; cp "$0" "$OUT/$SCENARIO.sh"
say "COPIED $ROOTFS/$ULG -> $OUT/$SCENARIO.ulg ($(stat -c %s "$OUT/$SCENARIO.ulg") bytes)"
say "host load at end: $(cat /proc/loadavg)"
say "DONE"
```

</details>

#### C-abort (extra): `vtol_transition_abort.ulg`

- Airframe `10043_sihsim_standard_vtol` (`PX4_SIM_MODEL=sihsim_standard_vtol`), fresh rootfs /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/vtol_abort_rootfs.
- Invocation: `cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0 && ./nsrun.sh ./vtol_transition_abort.sh /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/vtol_abort_rootfs vtol_transition_abort`
- Output: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/vtol_transition_abort.ulg`, 15324267 bytes, SHA-256 `13489ca66b7c1023278d7b13dbb621e882a7bbe001ceaad2f2beb257cdd9bc79`, ULog duration 56.7 s, dropouts 0.
- arming_state sequence: 0.152 s DISARMED, 5.488 s ARMED, 56.128 s DISARMED
- nav_state sequence: 0.152 s AUTO_LOITER, 8.392 s AUTO_TAKEOFF, 23.164 s AUTO_LOITER, 29.020 s AUTO_RTL, 56.128 s AUTO_LOITER
- vehicle_status.failsafe sequence: 0.152 s false

Ordered commands with wall-clock times (from `vtol_transition_abort.cmd.log`; `param show` lines are read-only checks):

| wall clock UTC (2026-10-18) | sim time at send | command / observation |
|---|---|---|
| 11:18:42.867 | (boot) | start px4 server (see command line above) |
| 11:18:48.933 | | WAIT ok: vehicle_status.pre_flight_checks_pass=True after 3s (sim t=4.744s) |
| 11:18:48.960 | | WAIT ok: home_position.valid_hpos=True after 0s (sim t=4.744s) |
| 11:18:48.980 | 4.744 | `param show SYS_AUTOSTART` |
| 11:18:49.001 | 5.248 | `param show MIS_TAKEOFF_ALT` |
| 11:18:49.029 | 5.248 | `param show VT_ARSP_TRANS` |
| 11:18:49.054 | 5.248 | `param show VT_TRANS_TIMEOUT` |
| 11:18:49.078 | 5.248 | `param show VT_TRANS_MIN_TM` |
| 11:18:49.104 | 5.248 | `param show VT_F_TRANS_DUR` |
| 11:18:49.126 | 5.248 | `param show VT_B_TRANS_DUR` |
| 11:18:49.150 | 5.248 | `param show SENS_EN_ARSPDSIM` |
| 11:18:49.199 | 5.428 | `commander arm` |
| 11:18:52.262 | 8.008 | `commander takeoff` |
| 11:18:53.307 | | WAIT ok: vehicle_status.nav_state=17 after 1s (sim t=8.896s) |
| 11:19:07.521 | | WAIT ok: vehicle_status.nav_state=4 after 14s (sim t=23.164s) |
| 11:19:12.592 | 27.700 | `commander transition` |
| 11:19:13.417 | 28.696 | `commander mode auto:rtl` |
| 11:19:13.966 | | WAIT ok: vehicle_status.nav_state=5 after 0s (sim t=29.296s) |
| 11:19:41.229 | | WAIT ok: vehicle_status.arming_state=1 after 24s (sim t=56.128s) |
| 11:19:47.257 | 61.672 | `logger status` |
| 11:19:47.269 | 61.672 | `shutdown` |
| 11:19:47.278 | | px4 exit=0 |

Extra log made for SPEC R6 (not in the brief). After `commander transition`, `commander mode auto:rtl` was sent 0.8 s later, during TRANSITION_TO_FW. `vtol_att_control_main.cpp` lines 105 to 109 abort a front transition when RTL is entered (`_transition_command = MC`), and `standard.cpp` lines 92 to 96 go from TRANSITION_TO_FW straight to MC_MODE. RTL at home then landed and disarmed. A second `commander transition` cannot abort a front transition: `commander transition` picks the target from `vehicle_status.vehicle_type`, which stays ROTARY_WING during a front transition, so it would request FW again (`Commander.cpp` lines 355 to 365).

<details><summary>ulog_info vtol_transition_abort.ulg</summary>

```
Logging start time: 0:00:00, duration: 0:00:56
No Dropouts
SW Version: v1.17.0
Info Messages:
 boot_time_utc_us: 1792322323615287
 metadata_events_sha256: 3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d
 sys_name: PX4
 sys_os_name: Linux
 sys_os_ver_release: 101854463
 sys_toolchain: GNU GCC
 sys_toolchain_ver: 13.3.0
 time_ref_utc: 0
 ver_data_format: 2
 ver_hw: PX4_SITL
 ver_sw: d6f12ad1c4f70ad3230afd7d86e971421e02fef4
 ver_sw_release: 17891583
 ver_vendor_sw_release: 255
Info Multiple Messages: [excluded_optional_topics: 40], [metadata_events: 1], [perf_counter_postflight: 1], [perf_counter_preflight: 1]

Name (multi id, message size in bytes)    number of data points, total bytes
 actuator_armed (0, 15)                       121       1815
 actuator_motors (0, 66)                      568      37488
 actuator_outputs (0, 76)                     568      43168
 actuator_servos (0, 48)                      568      27264
 airspeed (0, 28)                            1090      30520
 airspeed_validated (0, 41)                   551      22591
 airspeed_wind (0, 61)                         56       3416
 airspeed_wind (1, 61)                         56       3416
 battery_status (0, 166)                      285      47310
 config_overrides (0, 14)                     113       1582
 control_allocator_status (0, 54)             285      15390
 control_allocator_status (1, 54)             285      15390
 cpuload (0, 16)                              113       1808
 distance_sensor (0, 56)                     2834     158704
 distance_sensor_mode_change_request (0, 9)       3         27
 ekf2_timestamps (0, 22)                    14161     311542
 estimator_aid_src_airspeed (0, 59)           551      32509
 estimator_aid_src_baro_hgt (0, 59)           568      33512
 estimator_aid_src_fake_hgt (0, 59)             2        118
 estimator_aid_src_fake_pos (0, 95)            34       3230
 estimator_aid_src_gnss_hgt (0, 59)           448      26432
 estimator_aid_src_gnss_pos (0, 95)           454      43130
 estimator_aid_src_gnss_vel (0, 115)          454      52210
 estimator_aid_src_gravity (0, 115)          5666     651590
 estimator_aid_src_mag (0, 115)               810      93150
 estimator_aid_src_rng_hgt (0, 59)           2798     165082
 estimator_baro_bias (0, 40)                  528      21120
 estimator_event_flags (0, 37)                 59       2183
 estimator_gnss_hgt_bias (0, 40)              207       8280
 estimator_gps_status (0, 40)                 454      18160
 estimator_innovation_test_ratios (0, 140)    5666     793240
 estimator_innovation_variances (0, 140)     5666     793240
 estimator_innovations (0, 140)              5666     793240
 estimator_sensor_bias (0, 118)               524      61832
 estimator_states (0, 213)                   5666    1206858
 estimator_status (0, 129)                   5666     730914
 estimator_status_flags (0, 97)                70       6790
 event (0, 40)                                 31       1240
 failsafe_flags (0, 91)                       108       9828
 failure_detector_status (0, 24)              121       2904
 fixed_wing_lateral_guidance_status (0, 37)      11        407
 fixed_wing_lateral_setpoint (0, 20)            8        160
 fixed_wing_lateral_status (0, 16)             11        176
 fixed_wing_longitudinal_setpoint (0, 28)       8        224
 flaps_setpoint (0, 12)                        56        672
 fw_virtual_attitude_setpoint (0, 40)          74       2960
 gripper (0, 9)                                 1          9
 home_position (0, 60)                        281      16860
 hover_thrust_estimate (0, 41)                421      17261
 landing_gear (0, 9)                            3         27
 landing_gear_wheel (0, 12)                   552       6624
 lateral_control_configuration (0, 12)          1         12
 longitudinal_control_configuration (0, 38)       1         38
 manual_control_setpoint (0, 65)                1         65
 mc_virtual_attitude_setpoint (0, 40)        7082     283280
 mission_result (0, 38)                         3        114
 navigator_mission_item (0, 47)                 2         94
 navigator_status (0, 10)                     114       1140
 parameter_update (0, 34)                       2         68
 position_setpoint_triplet (0, 248)            40       9920
 rate_ctrl_status (0, 20)                     285       5700
 rate_ctrl_status (1, 20)                     285       5700
 rtl_status (0, 16)                            16        256
 rtl_time_estimate (0, 17)                     28        476
 sensor_accel (0, 44)                          56       2464
 sensor_baro (0, 32)                           56       1792
 sensor_combined (0, 48)                    14161     679728
 sensor_gps (0, 147)                           56       8232
 sensor_gyro (0, 44)                           56       2464
 sensor_mag (0, 40)                            56       2240
 sensor_selection (0, 16)                       1         16
 sensors_status_imu (0, 96)                   285      27360
 spoilers_setpoint (0, 12)                     56        672
 system_power (0, 42)                         113       4746
 takeoff_status (0, 13)                        14        182
 telemetry_status (0, 84)                      56       4704
 telemetry_status (1, 84)                      56       4704
 telemetry_status (2, 84)                      56       4704
 telemetry_status (3, 84)                      56       4704
 trajectory_setpoint (0, 64)                  285      18240
 transponder_report (0, 78)                     1         78
 vehicle_acceleration (0, 28)                1134      31752
 vehicle_air_data (0, 38)                     567      21546
 vehicle_angular_velocity (0, 40)            5666     226640
 vehicle_angular_velocity_groundtruth (0, 40)    5666     226640
 vehicle_attitude (0, 49)                   13757     674093
 vehicle_attitude_groundtruth (0, 49)        5666     277634
 vehicle_attitude_setpoint (0, 40)           1134      45360
 vehicle_command (0, 55)                       10        550
 vehicle_command_ack (0, 22)                    6        132
 vehicle_constraints (0, 17)                   56        952
 vehicle_control_mode (0, 23)                 121       2783
 vehicle_global_position (0, 67)             6657     446019
 vehicle_global_position_groundtruth (0, 67)     568      38056
 vehicle_gps_position (0, 147)                454      66738
 vehicle_imu (0, 60)                          113       6780
 vehicle_imu_status (0, 132)                   56       7392
 vehicle_land_detected (0, 20)                 65       1300
 vehicle_local_position (0, 192)             7082    1359744
 vehicle_local_position_groundtruth (0, 192)    2834     544128
 vehicle_local_position_setpoint (0, 64)      568      36352
 vehicle_magnetometer (0, 33)                 810      26730
 vehicle_rates_setpoint (0, 33)              2741      90453
 vehicle_status (0, 74)                       121       8954
 vehicle_thrust_setpoint (0, 28)             2834      79352
 vehicle_thrust_setpoint (1, 28)             2834      79352
 vehicle_thrust_setpoint_virtual_fw (0, 28)   13590     380520
 vehicle_thrust_setpoint_virtual_mc (0, 28)   13785     385980
 vehicle_torque_setpoint (0, 28)             2834      79352
 vehicle_torque_setpoint (1, 28)             2834      79352
 vehicle_torque_setpoint_virtual_fw (0, 28)   13584     380352
 vehicle_torque_setpoint_virtual_mc (0, 28)   13784     385952
 vtol_vehicle_status (0, 10)                   59        590
 yaw_estimator_status (0, 105)               6915     726075
```

</details>

<details><summary>analysis (analyze_ulog.py): state sequences, failsafe_flags, commands, acks, battery, GPS, estimator flags, changed parameters, logged strings</summary>

```
FILE: vtol_transition_abort.ulg  (15324267 bytes)
start=0.472s last=57.124s duration=56.7s
dropouts: 0 []
file_corruption: False  has_default_parameters: 1
info fields:
  boot_time_utc_us = 1792322323615287
  metadata_events_sha256 = '3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d'
  sys_name = 'PX4'
  sys_os_name = 'Linux'
  sys_os_ver_release = 101854463
  sys_toolchain = 'GNU GCC'
  sys_toolchain_ver = '13.3.0'
  time_ref_utc = 0
  ver_data_format = 2
  ver_hw = 'PX4_SITL'
  ver_sw = 'd6f12ad1c4f70ad3230afd7d86e971421e02fef4'
  ver_sw_release = 17891583
  ver_vendor_sw_release = 255
info multiple: {'perf_counter_preflight': 1, 'metadata_events': 1, 'excluded_optional_topics': 40, 'perf_counter_postflight': 1}
initial_parameters: 1145   changed_parameters: 28

TOPIC PRESENCE (required list):
  vehicle_status           PRESENT inst0=121 msgs
  failsafe_flags           PRESENT inst0=108 msgs
  vehicle_command          PRESENT inst0=10 msgs
  vehicle_command_ack      PRESENT inst0=6 msgs
  vtol_vehicle_status      PRESENT inst0=59 msgs
  vehicle_land_detected    PRESENT inst0=65 msgs
  sensor_gps               PRESENT inst0=56 msgs
  vehicle_gps_position     PRESENT inst0=454 msgs
  battery_status           PRESENT inst0=285 msgs
  estimator_status_flags   PRESENT inst0=70 msgs
  log_message              ABSENT

VEHICLE_STATUS:
  arming_state (3 changes):
    t=0.152s  DISARMED
    t=5.488s  ARMED
    t=56.128s  DISARMED
  nav_state (5 changes):
    t=0.152s  AUTO_LOITER
    t=8.392s  AUTO_TAKEOFF
    t=23.164s  AUTO_LOITER
    t=29.020s  AUTO_RTL
    t=56.128s  AUTO_LOITER
  failsafe (1 changes):
    t=0.152s  0
  failsafe_defer_state (1 changes):
    t=0.152s  0
  vehicle_type (1 changes):
    t=0.152s  ROTARY_WING
  is_vtol (1 changes):
    t=0.152s  1
  in_transition_mode (3 changes):
    t=0.152s  0
    t=28.192s  1
    t=29.032s  0
  in_transition_to_fw (3 changes):
    t=0.152s  0
    t=28.192s  1
    t=29.032s  0
  pre_flight_checks_pass (2 changes):
    t=0.152s  0
    t=4.240s  1
  latest_arming_reason (2 changes):
    t=0.152s  0
    t=5.488s  3
  latest_disarming_reason (2 changes):
    t=0.152s  0
    t=56.128s  6

FAILSAFE_FLAGS (fields that change; mode_req_* skipped):
  attitude_invalid (2 changes):
    t=0.200s  1
    t=2.188s  0
  local_altitude_invalid (2 changes):
    t=0.200s  1
    t=0.848s  0
  local_position_invalid (2 changes):
    t=0.200s  1
    t=4.240s  0
  local_position_invalid_relaxed (2 changes):
    t=0.200s  1
    t=4.240s  0
  local_velocity_invalid (2 changes):
    t=0.200s  1
    t=4.240s  0
  global_position_invalid (2 changes):
    t=0.200s  1
    t=4.240s  0
  global_position_invalid_relaxed (2 changes):
    t=0.200s  1
    t=4.240s  0
  auto_mission_missing (1 changes):
    t=0.200s  1
  offboard_control_signal_lost (1 changes):
    t=0.200s  1
  manual_control_signal_lost (1 changes):
    t=0.200s  1
  gcs_connection_lost (1 changes):
    t=0.200s  1

VTOL_VEHICLE_STATUS:
  vehicle_vtol_state (3 changes):
    t=0.132s  MC
    t=28.184s  TRANSITION_TO_FW
    t=29.024s  MC
  fixed_wing_system_failure (1 changes):
    t=0.132s  0

VEHICLE_LAND_DETECTED:
  landed (3 changes):
    t=0.208s  1
    t=9.224s  0
    t=54.112s  1
  maybe_landed (3 changes):
    t=0.208s  1
    t=9.224s  0
    t=53.776s  1
  ground_contact (3 changes):
    t=0.208s  1
    t=9.336s  0
    t=53.440s  1
  in_ground_effect (6 changes):
    t=0.208s  0
    t=0.816s  1
    t=3.176s  0
    t=3.192s  1
    t=12.608s  0
    t=29.496s  1

VEHICLE_COMMAND (all rows):
    t=0.260s cmd=211 DO_GRIPPER             p1=-9.38601e+10 p2=1 p3=-9.38646e+10 src=73/54336 tgt=174/209 from_external=False
    t=5.476s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=8.372s cmd=22 NAV_TAKEOFF            p1=nan p2=nan p3=nan src=1/1 tgt=1/1 from_external=False
    t=8.384s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=28.180s cmd=3000 DO_VTOL_TRANSITION     p1=4 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=29.000s cmd=176 DO_SET_MODE            p1=1 p2=4 p3=5 src=1/1 tgt=1/1 from_external=False
    t=29.288s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=1 p2=1 p3=-1 src=1/1 tgt=1/0 from_external=False
    t=29.288s cmd=1000 DO_GIMBAL_MANAGER_PITCHYAW p1=nan p2=nan p3=nan src=1/1 tgt=1/0 from_external=False
    t=29.288s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=-3 p2=-3 p3=-1 src=1/1 tgt=1/0 from_external=False
    t=54.144s cmd=0 ?                      p1=0 p2=10 p3=80 src=1/1 tgt=1/0 from_external=False

VEHICLE_COMMAND_ACK (all rows):
    t=0.268s cmd=211 DO_GRIPPER             result=5 IN_PROGRESS tgt=73/64 from_external=False
    t=1.360s cmd=211 DO_GRIPPER             result=0 ACCEPTED tgt=73/64 from_external=False
    t=5.488s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False
    t=8.380s cmd=22 NAV_TAKEOFF            result=0 ACCEPTED tgt=1/1 from_external=False
    t=8.392s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False
    t=29.008s cmd=176 DO_SET_MODE            result=0 ACCEPTED tgt=1/1 from_external=False

BATTERY_STATUS inst0:
  warning (1 changes):
    t=0.476s  0
    remaining first=0.989 last=0.806 min=0.500

SENSOR_GPS / VEHICLE_GPS_POSITION fix_type:
  sensor_gps inst0 fix_type (1 changes):
    t=1.280s  3
    sensor_gps inst0 last msg t=56.280s
  vehicle_gps_position inst0 fix_type (1 changes):
    t=0.404s  3
    vehicle_gps_position inst0 last msg t=57.028s

ESTIMATOR_STATUS_FLAGS inst0 (gps-related):
  cs_gnss_pos (2 changes):
    t=0.112s  0
    t=3.176s  1
  cs_gnss_vel (2 changes):
    t=0.112s  0
    t=3.176s  1
  cs_in_air (3 changes):
    t=0.112s  0
    t=9.376s  1
    t=54.264s  0
  cs_inertial_dead_reckoning (2 changes):
    t=0.112s  1
    t=3.176s  0
  cs_wind_dead_reckoning (1 changes):
    t=0.112s  0

CHANGED_PARAMETERS (28):
    t=0.472s CAL_ACC0_ID = 1310988
    t=0.472s CAL_ACC1_ID = 1310996
    t=0.472s CAL_ACC2_ID = 1311004
    t=0.472s CAL_BARO0_ID = 6620172
    t=0.472s CAL_BARO0_OFF = 0.0
    t=0.472s CAL_BARO0_PRIO = 50
    t=0.472s CAL_GYRO0_ID = 1310988
    t=0.472s CAL_GYRO1_ID = 1310996
    t=0.472s CAL_GYRO2_ID = 1311004
    t=0.472s CAL_MAG0_ID = 197388
    t=0.472s CAL_MAG0_PRIO = 50
    t=0.472s CAL_MAG1_ID = 197644
    t=0.472s CAL_MAG1_PRIO = 50
    t=0.472s SENS_BOARD_X_OFF = 9.999999974752427e-07
    t=0.472s SENS_DPRES_OFF = 0.0010000000474974513
    t=0.472s SIH_IXX = 0.003539999946951866
    t=0.472s SIH_IYY = 0.0006249999860301614
    t=0.472s SIH_IZZ = 0.003000000026077032
    t=0.472s SIH_KDV = 0.20000000298023224
    t=0.472s SIH_MASS = 0.20000000298023224
    t=0.472s SIH_Q_MAX = 0.016499999910593033
    t=0.472s SIH_T_MAX = 2.0
    t=0.472s SIH_VEHICLE_TYPE = 3
    t=0.472s SYS_AUTOCONFIG = 0
    t=0.472s SYS_AUTOSTART = 10043
    t=5.412s CAL_BARO0_ID = 6620172
    t=5.412s CAL_BARO0_OFF = 4.8828125
    t=5.412s CAL_BARO0_PRIO = 50

LOGGED_MESSAGES (16):
    t=0.472s [INFO] [logger] Opened full log file: ./log/2026-10-18/11_18_44.ulg
    t=0.476s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.476s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.476s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.480s [INFO] [px4] Startup script returned successfully
    t=0.896s [INFO] [tone_alarm] home set
    t=4.240s [INFO] [commander] <ESC>[32mReady for takeoff!<ESC>[0m
    t=5.488s [INFO] [commander] Armed by internal command	
    t=5.488s [INFO] [tone_alarm] arming warning
    t=8.392s [INFO] [navigator] Using default takeoff altitude: 20.0 m	
    t=9.232s [INFO] [commander] Takeoff detected	
    t=29.032s [INFO] [navigator] RTL: start return at 510 m (20 m above destination)	
    t=29.088s [INFO] [navigator] RTL: land at destination	
    t=54.124s [INFO] [commander] Landing detected	
    t=56.128s [INFO] [commander] Disarmed by landing	
    t=56.128s [INFO] [tone_alarm] notify neutral

LOGGED_MESSAGES_TAGGED (0)
```

</details>

<details><summary>ulog_messages vtol_transition_abort.ulg</summary>

```
0:00:00.472 INFO: logging: opening log file 2026-10-18/11_18_44.ulg
0:00:00.472 INFO: [logger] Opened full log file: ./log/2026-10-18/11_18_44.ulg
0:00:00.476 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.476 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.476 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.480 INFO: [px4] Startup script returned successfully
0:00:00.896 INFO: [tone_alarm] home set
0:00:04.240 INFO: [commander] <ESC>[32mReady for takeoff!<ESC>[0m
0:00:05.488 INFO: Armed by internal command
0:00:05.488 INFO: [tone_alarm] arming warning
0:00:08.392 INFO: Using default takeoff altitude: 20.00 m
0:00:09.232 INFO: Takeoff detected
0:00:29.032 INFO: RTL: start return at 510 m (20 m above destination)
0:00:29.088 INFO: RTL: land at destination
0:00:54.124 INFO: Landing detected
0:00:56.128 INFO: Disarmed by landing
0:00:56.128 INFO: [tone_alarm] notify neutral
```

</details>

<details><summary>command log vtol_transition_abort.cmd.log</summary>

```
[2026-10-18T11:18:42.794] SCENARIO vtol_transition_abort  rootfs=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/vtol_abort_rootfs  PX4 v1.17.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4
[2026-10-18T11:18:42.851] host load at start: 3.62 2.47 1.39 12/214 25382  ns: /tmp=claude-0 
[2026-10-18T11:18:42.867] START px4: cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/vtol_abort_rootfs && PX4_SIM_MODEL=sihsim_standard_vtol PX4_SIMULATOR=sihsim /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/bin/px4 -d /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/etc > /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/vtol_transition_abort.px4.log 2>&1 &
[2026-10-18T11:18:48.933] WAIT ok: vehicle_status.pre_flight_checks_pass=True after 3s (sim t=4.744s)
[2026-10-18T11:18:48.960] WAIT ok: home_position.valid_hpos=True after 0s (sim t=4.744s)
[2026-10-18T11:18:48.980] CMD (sim t=4.744s): param show SYS_AUTOSTART
    > Symbols: x = used, + = saved, * = unsaved
    > x + SYS_AUTOSTART [1078,1423] : 10043
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:18:49.001] CMD (sim t=5.248s): param show MIS_TAKEOFF_ALT
    > Symbols: x = used, + = saved, * = unsaved
    > x   MIS_TAKEOFF_ALT [773,1031] : 20.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:18:49.029] CMD (sim t=5.248s): param show VT_ARSP_TRANS
    > Symbols: x = used, + = saved, * = unsaved
    > x   VT_ARSP_TRANS [1111,1755] : 10.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:18:49.054] CMD (sim t=5.248s): param show VT_TRANS_TIMEOUT
    > Symbols: x = used, + = saved, * = unsaved
    > x   VT_TRANS_TIMEOUT [1137,1786] : 15.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:18:49.078] CMD (sim t=5.248s): param show VT_TRANS_MIN_TM
    > Symbols: x = used, + = saved, * = unsaved
    > x   VT_TRANS_MIN_TM [1136,1784] : 2.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:18:49.104] CMD (sim t=5.248s): param show VT_F_TRANS_DUR
    > Symbols: x = used, + = saved, * = unsaved
    > x   VT_F_TRANS_DUR [1127,1772] : 5.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:18:49.126] CMD (sim t=5.248s): param show VT_B_TRANS_DUR
    > Symbols: x = used, + = saved, * = unsaved
    > x   VT_B_TRANS_DUR [1114,1759] : 10.0000
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:18:49.150] CMD (sim t=5.248s): param show SENS_EN_ARSPDSIM
    > Symbols: x = used, + = saved, * = unsaved
    > x   SENS_EN_ARSPDSIM [1032,1353] : 1
    > 
    >  1145/1794 parameters used.
[2026-10-18T11:18:49.184] STATUS: timestamp: 5428000 (0.004000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.09767 | airspeed_source: 1 | 
[2026-10-18T11:18:49.199] CMD (sim t=5.428s): commander arm
[2026-10-18T11:18:52.246] STATUS: timestamp: 8008000 (0.320000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.09767 | airspeed_source: 1 | 
[2026-10-18T11:18:52.262] CMD (sim t=8.008s): commander takeoff
[2026-10-18T11:18:53.307] WAIT ok: vehicle_status.nav_state=17 after 1s (sim t=8.896s)
[2026-10-18T11:18:53.331] STATUS: timestamp: 9400000 (0.004000 seconds ago) | arming_state: 2 | nav_state: 17 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.09767 | airspeed_source: 1 | 
[2026-10-18T11:19:07.521] WAIT ok: vehicle_status.nav_state=4 after 14s (sim t=23.164s)
[2026-10-18T11:19:07.548] STATUS: timestamp: 23164000 (0.124000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.73276 | airspeed_source: 1 | 
[2026-10-18T11:19:12.578] STATUS: timestamp: 27700000 (0.440000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.33276 | airspeed_source: 1 | 
[2026-10-18T11:19:12.592] CMD (sim t=27.700s): commander transition
[2026-10-18T11:19:13.417] CMD (sim t=28.696s): commander mode auto:rtl
[2026-10-18T11:19:13.953] STATUS: timestamp: 29296000 (0.200000 seconds ago) | arming_state: 2 | nav_state: 5 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 1.21971 | airspeed_source: 1 | 
[2026-10-18T11:19:13.966] WAIT ok: vehicle_status.nav_state=5 after 0s (sim t=29.296s)
[2026-10-18T11:19:13.981] STATUS: timestamp: 29296000 (0.236000 seconds ago) | arming_state: 2 | nav_state: 5 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 1.45006 | airspeed_source: 1 | 
[2026-10-18T11:19:17.007] STATUS: timestamp: 32320000 (0.152000 seconds ago) | arming_state: 2 | nav_state: 5 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 1.21403 | airspeed_source: 1 | 
[2026-10-18T11:19:41.229] WAIT ok: vehicle_status.arming_state=1 after 24s (sim t=56.128s)
[2026-10-18T11:19:41.244] STATUS: timestamp: 56128000 (0.016000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | in_transition_mode: False | in_transition_to_fw: False | pre_flight_checks_pass: True |  VTOL: vehicle_vtol_state: 3 | fixed_wing_system_failure: False |  ARSPD: calibrated_airspeed_m_s: 0.36101 | airspeed_source: 1 | 
[2026-10-18T11:19:47.257] CMD (sim t=61.672s): logger status
    > INFO  [logger] Running in mode: all
    > INFO  [logger] Number of subscriptions: 189 (6048 bytes)
    > INFO  [logger] Not logging
[2026-10-18T11:19:47.269] CMD (sim t=61.672s): shutdown
[2026-10-18T11:19:47.278] px4 exit=0
[2026-10-18T11:19:47.310] COPIED /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/vtol_abort_rootfs/log/2026-10-18/11_18_44.ulg -> /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/vtol_transition_abort.ulg (15324267 bytes)
[2026-10-18T11:19:47.316] host load at end: 5.19 3.11 1.68 3/198 30253
[2026-10-18T11:19:47.319] DONE
```

</details>

<details><summary>px4 stdout and stderr vtol_transition_abort.px4.log</summary>

```

______  __   __    ___ 
| ___ \ \ \ / /   /   |
| |_/ /  \ V /   / /| |
|  __/   /   \  / /_| |
| |     / /^\ \ \___  |
\_|     \/   \/     |_/

px4 starting.

INFO  [px4] startup script: /bin/sh etc/init.d-posix/rcS 0
INFO  [init] found model autostart file as SYS_AUTOSTART=10043
INFO  [param] selected parameter default file parameters.bson
INFO  [param] selected parameter backup file parameters_backup.bson
  SYS_AUTOCONFIG: curr: 0 -> new: 1
  SYS_AUTOSTART: curr: 0 -> new: 10043
  CAL_ACC0_ID: curr: 0 -> new: 1310988
  CAL_GYRO0_ID: curr: 0 -> new: 1310988
  CAL_ACC1_ID: curr: 0 -> new: 1310996
  CAL_GYRO1_ID: curr: 0 -> new: 1310996
  CAL_ACC2_ID: curr: 0 -> new: 1311004
  CAL_GYRO2_ID: curr: 0 -> new: 1311004
  CAL_MAG0_ID: curr: 0 -> new: 197388
  CAL_MAG0_PRIO: curr: -1 -> new: 50
  CAL_MAG1_ID: curr: 0 -> new: 197644
  CAL_MAG1_PRIO: curr: -1 -> new: 50
  SENS_BOARD_X_OFF: curr: 0.0000 -> new: 0.0000
  SENS_DPRES_OFF: curr: 0.0000 -> new: 0.0010
  SIH_T_MAX: curr: 5.0000 -> new: 2.0000
  SIH_Q_MAX: curr: 0.1000 -> new: 0.0165
  SIH_MASS: curr: 1.0000 -> new: 0.2000
  SIH_IXX: curr: 0.0250 -> new: 0.0035
  SIH_IYY: curr: 0.0250 -> new: 0.0006
  SIH_IZZ: curr: 0.0300 -> new: 0.0030
  SIH_KDV: curr: 1.0000 -> new: 0.2000
  SIH_VEHICLE_TYPE: curr: 0 -> new: 3
INFO  [dataman] data manager file './dataman' size is 1208528 bytes
INFO  [init] SIH simulator
INFO  [simulator_sih] Simulation loop with 250 Hz (4000 us sim time interval)
INFO  [simulator_sih] Simulation with 1.0x speedup. Loop with (4000 us wall time interval)
INFO  [lockstep_scheduler] setting initial absolute time to 4000 us
INFO  [commander] LED: open /dev/led0 failed (22)
INFO  [uxrce_dds_client] init UDP agent IP:127.0.0.1, port:8888
INFO  [mavlink] mode: Normal, data rate: 4000000 B/s on udp port 18570 remote port 14550
INFO  [mavlink] mode: Onboard, data rate: 4000000 B/s on udp port 14580 remote port 14540
INFO  [mavlink] mode: Onboard, data rate: 4000 B/s on udp port 14280 remote port 14030
INFO  [mavlink] mode: Gimbal, data rate: 400000 B/s on udp port 13030 remote port 13280
INFO  [mavlink] mode: Custom, data rate: 400000 B/s on udp port 19450 remote port 19410
INFO  [logger] logger started (mode=all)
INFO  [logger] Start file log (type: full)
INFO  [logger] [logger] ./log/2026-10-18/11_18_44.ulg	
INFO  [logger] Opened full log file: ./log/2026-10-18/11_18_44.ulg
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [px4] Startup script returned successfully
INFO  [tone_alarm] home set
INFO  [commander] <ESC>[32mReady for takeoff!<ESC>[0m
INFO  [commander] Armed by internal command	
INFO  [tone_alarm] arming warning
INFO  [navigator] Using default takeoff altitude: 20.0 m	
INFO  [commander] Takeoff detected	
INFO  [navigator] RTL: start return at 510 m (20 m above destination)	
INFO  [navigator] RTL: land at destination	
INFO  [commander] Landing detected	
INFO  [commander] Disarmed by landing	
INFO  [tone_alarm] notify neutral
INFO  [logger] closed logfile, bytes written: 15324267
Exiting NOW.
```

</details>

<details><summary>script vtol_transition_abort.sh</summary>

```bash
#!/bin/bash
# vtol_transition_abort.sh <rootfs_dir> <scenario_name>
# Scenario C-abort (extra, for SPEC R6): SIH standard VTOL, arm, takeoff, `commander transition` to FW, then
# ~0.8 s later (while vtol state is TRANSITION_TO_FW; a full front transition took ~3 s in vtol_transition)
# `commander mode auto:rtl`. vtol_att_control_main.cpp vehicle_status_poll() aborts a front transition when RTL
# is entered (sets _transition_command = MC), standard.cpp then goes TRANSITION_TO_FW -> MC_MODE directly.
# RTL at home lands; `commander land` only if still airborne after 90 s. Fresh rootfs, no param changes.
set -u
PX4_DIR=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0
BIN=$PX4_DIR/build/px4_sitl_default/bin
ETC=$PX4_DIR/build/px4_sitl_default/etc
OUT=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0
ROOTFS=${1:?rootfs}; SCENARIO=${2:?scenario}
MODEL=sihsim_standard_vtol
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS" "$OUT"; cd "$ROOTFS"
PX4LOG=$OUT/$SCENARIO.px4.log; CMDLOG=$OUT/$SCENARIO.cmd.log; : > "$CMDLOG"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3N; }
say() { echo "[$(ts)] $*" | tee -a "$CMDLOG"; }
simt() { "$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +timestamp:/{printf "%.3f", $2/1e6}'; }
vs() { say "STATUS: $("$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +(timestamp|arming_state|nav_state|failsafe|vehicle_type|in_transition_mode|in_transition_to_fw|pre_flight_checks_pass):/{gsub(/^ +/,""); printf "%s | ", $0}') VTOL: $("$BIN/px4-listener" vtol_vehicle_status 2>/dev/null | awk '/^ +(vehicle_vtol_state|fixed_wing_system_failure):/{gsub(/^ +/,""); printf "%s | ", $0}') ARSPD: $("$BIN/px4-listener" airspeed_validated 2>/dev/null | awk '/^ +(calibrated_airspeed_m_s|airspeed_source):/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
cmd() { say "CMD (sim t=$(simt)s): $*"; "$BIN/px4-$1" "${@:2}" 2>&1 | sed 's/^/    > /' | tee -a "$CMDLOG"; }
wait_for() { # topic field value timeout_s
  local tp=$1 f=$2 v=$3 to=$4 i=0 cur=
  while [ $i -lt "$to" ]; do
    cur=$("$BIN/px4-listener" "$tp" 2>/dev/null | awk -v f="$f" '$1==f":"{print $2}')
    if [ "$cur" = "$v" ]; then say "WAIT ok: $tp.$f=$v after ${i}s (sim t=$(simt)s)"; return 0; fi
    sleep 1; i=$((i+1))
  done
  say "WAIT TIMEOUT: $tp.$f=$cur (wanted $v) after ${to}s (sim t=$(simt)s)"; return 1
}
say "SCENARIO $SCENARIO  rootfs=$ROOTFS  PX4 $(cd $PX4_DIR && git describe --tags --always) $(cd $PX4_DIR && git rev-parse HEAD)"
say "host load at start: $(cat /proc/loadavg)  ns: /tmp=$(ls -A /tmp | tr '\n' ' ')"
touch .start_marker
say "START px4: cd $ROOTFS && PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim $BIN/px4 -d $ETC > $PX4LOG 2>&1 &"
PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim "$BIN/px4" -d "$ETC" > "$PX4LOG" 2>&1 &
PX4_PID=$!
sleep 3
wait_for vehicle_status pre_flight_checks_pass True 150
wait_for home_position valid_hpos True 60
cmd param show SYS_AUTOSTART; cmd param show MIS_TAKEOFF_ALT; cmd param show VT_ARSP_TRANS; cmd param show VT_TRANS_TIMEOUT; cmd param show VT_TRANS_MIN_TM; cmd param show VT_F_TRANS_DUR; cmd param show VT_B_TRANS_DUR; cmd param show SENS_EN_ARSPDSIM
vs
cmd commander arm
sleep 3; vs
cmd commander takeoff
wait_for vehicle_status nav_state 17 10; vs
wait_for vehicle_status nav_state 4 120; vs
sleep 5; vs
cmd commander transition
sleep 0.8
cmd commander mode auto:rtl
sleep 0.5; vs
wait_for vehicle_status nav_state 5 10; vs
sleep 3; vs
if ! wait_for vehicle_status arming_state 1 90; then
  cmd commander land
  wait_for vehicle_status arming_state 1 120
fi
vs
sleep 6
cmd logger status
cmd shutdown
wait $PX4_PID; say "px4 exit=$?"
ULG=$(find log -name '*.ulg' -newer .start_marker | sort | tail -1)
cp "$ULG" "$OUT/$SCENARIO.ulg"; cp "$0" "$OUT/$SCENARIO.sh"
say "COPIED $ROOTFS/$ULG -> $OUT/$SCENARIO.ulg ($(stat -c %s "$OUT/$SCENARIO.ulg") bytes)"
say "host load at end: $(cat /proc/loadavg)"
say "DONE"
```

</details>

#### E: `failsafe_gps_loss.ulg`

- Airframe `10040_sihsim_quadx` (`PX4_SIM_MODEL=sihsim_quadx`), fresh rootfs /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/fs_gps_rootfs.
- Invocation: `cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0 && ./nsrun.sh ./failsafe_gps_loss.sh /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/fs_gps_rootfs failsafe_gps_loss`
- Output: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/failsafe_gps_loss.ulg`, 10217078 bytes, SHA-256 `5ce6ca4963b231d3641edcb25e7b3d07c7da6e8971857cbef074ce04e496cdfc`, ULog duration 45.9 s, dropouts 0.
- arming_state sequence: 0.096 s DISARMED, 3.868 s ARMED, 45.172 s DISARMED
- nav_state sequence: 0.096 s AUTO_LOITER, 6.856 s AUTO_TAKEOFF, 12.664 s AUTO_LOITER, 37.936 s DESCEND, 45.172 s AUTO_LOITER
- vehicle_status.failsafe sequence: 0.096 s false, 37.936 s true, 45.172 s false

Ordered commands with wall-clock times (from `failsafe_gps_loss.cmd.log`; `param show` lines are read-only checks):

| wall clock UTC (2026-10-18) | sim time at send | command / observation |
|---|---|---|
| 11:15:26.296 | (boot) | start px4 server (see command line above) |
| 11:15:30.329 | | WAIT ok: vehicle_status.pre_flight_checks_pass=True after 1s (sim t=3.592s) |
| 11:15:30.343 | | WAIT ok: home_position.valid_hpos=True after 0s (sim t=3.592s) |
| 11:15:30.350 | 3.592 | `param show SYS_FAILURE_EN` |
| 11:15:30.362 | 3.592 | `param show COM_POSCTL_NAVL` |
| 11:15:30.374 | 3.592 | `param show NAV_RCL_ACT` |
| 11:15:30.386 | 3.592 | `param show COM_LOW_BAT_ACT` |
| 11:15:30.397 | 3.592 | `param show SIM_GPS_USED` |
| 11:15:30.415 | 3.592 | `commander arm` |
| 11:15:33.439 | 6.328 | `commander takeoff` |
| 11:15:34.476 | | WAIT ok: vehicle_status.nav_state=17 after 1s (sim t=7.360s) |
| 11:15:39.529 | | WAIT ok: vehicle_status.nav_state=4 after 5s (sim t=12.664s) |
| 11:15:44.562 | 17.704 | `param set SYS_FAILURE_EN 1` |
| 11:15:44.573 | 17.704 | `failure gps off` |
| 11:16:00.629 | | NOTE: failure gps off did not raise failsafe (no SIH handler). Stopping the simulated GPS driver instead. |
| 11:16:00.638 | 32.376 | `sensor_gps_sim status` |
| 11:16:00.649 | 32.376 | `sensor_gps_sim stop` |
| 11:17:01.014 | | WAIT TIMEOUT: vehicle_status.failsafe=False (wanted True) after 30s (sim t=91.036s) |
| 11:17:01.042 | | WAIT ok: vehicle_status.arming_state=1 after 0s (sim t=91.036s) |
| 11:17:07.068 | 96.580 | `logger status` |
| 11:17:07.080 | 96.580 | `shutdown` |
| 11:17:07.087 | | px4 exit=0 |

What happened: `failure gps off` published `VEHICLE_CMD_INJECT_FAILURE` (420, param1 4, param2 1) and timed out (`ERROR [failure] Timeout waiting for ack`). In v1.17.0 only `simulator_mavlink` (Gazebo-classic bridge) handles `FAILURE_UNIT_SENSOR_GPS` (`SimulatorMavlink.cpp` line 1263); `sensor_gps_sim` (used by SIH) has no failure handler, so nothing changed. **What worked**: stopping the simulated GPS driver with `sensor_gps_sim stop` at sim 32.4 s. The last `sensor_gps` sample is at 32.144 s; EKF2 dead-reckoned (`cs_inertial_dead_reckoning` 1 at 33.920 s); at 37.924 s `failsafe_flags.global_position_invalid`, `global_position_invalid_relaxed`, `local_position_invalid`, `local_position_invalid_relaxed` and `local_velocity_invalid` all became true; at 37.936 s `vehicle_status.failsafe` became true and nav_state became 12 (DESCEND); ULog strings `[mc_pos_control] Failsafe: blind land` and `[failsafe] Failsafe activated`. The vehicle landed (`Landing detected` 43.168 s) and disarmed by landing at 45.172 s. When disarmed, `failsafe` returned to false and nav_state to AUTO_LOITER in the same `vehicle_status` message.

<details><summary>ulog_info failsafe_gps_loss.ulg</summary>

```
Logging start time: 0:00:00, duration: 0:00:45
No Dropouts
SW Version: v1.17.0
Info Messages:
 boot_time_utc_us: 1792322126502244
 metadata_events_sha256: 3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d
 sys_name: PX4
 sys_os_name: Linux
 sys_os_ver_release: 101854463
 sys_toolchain: GNU GCC
 sys_toolchain_ver: 13.3.0
 time_ref_utc: 0
 ver_data_format: 2
 ver_hw: PX4_SITL
 ver_sw: d6f12ad1c4f70ad3230afd7d86e971421e02fef4
 ver_sw_release: 17891583
 ver_vendor_sw_release: 255
Info Multiple Messages: [excluded_optional_topics: 40], [metadata_events: 1], [perf_counter_postflight: 1], [perf_counter_preflight: 1]

Name (multi id, message size in bytes)    number of data points, total bytes
 actuator_armed (0, 15)                        98       1470
 actuator_motors (0, 66)                      461      30426
 actuator_outputs (0, 76)                     461      35036
 battery_status (0, 166)                      230      38180
 config_overrides (0, 14)                      91       1274
 control_allocator_status (0, 54)             230      12420
 cpuload (0, 16)                               92       1472
 distance_sensor (0, 56)                     2296     128576
 distance_sensor_mode_change_request (0, 9)       1          9
 ekf2_timestamps (0, 22)                    11477     252494
 estimator_aid_src_baro_hgt (0, 59)           460      27140
 estimator_aid_src_gnss_hgt (0, 59)           254      14986
 estimator_aid_src_gnss_pos (0, 95)           262      24890
 estimator_aid_src_gnss_vel (0, 115)          262      30130
 estimator_aid_src_gravity (0, 115)          4586     527390
 estimator_aid_src_mag (0, 115)               641      73715
 estimator_aid_src_rng_hgt (0, 59)           2251     132809
 estimator_baro_bias (0, 40)                  439      17560
 estimator_event_flags (0, 37)                 48       1776
 estimator_gnss_hgt_bias (0, 40)              252      10080
 estimator_gps_status (0, 40)                 262      10480
 estimator_innovation_test_ratios (0, 140)    4586     642040
 estimator_innovation_variances (0, 140)     4586     642040
 estimator_innovations (0, 140)              4586     642040
 estimator_sensor_bias (0, 118)               745      87910
 estimator_states (0, 213)                   4586     976818
 estimator_status (0, 129)                   4586     591594
 estimator_status_flags (0, 97)                63       6111
 event (0, 40)                                 38       1520
 failsafe_flags (0, 91)                        89       8099
 failure_detector_status (0, 24)               98       2352
 gripper (0, 9)                                 1          9
 home_position (0, 60)                        229      13740
 hover_thrust_estimate (0, 41)                313      12833
 manual_control_setpoint (0, 65)                1         65
 mission_result (0, 38)                         3        114
 navigator_status (0, 10)                      94        940
 parameter_update (0, 34)                       2         68
 position_setpoint_triplet (0, 248)            30       7440
 rate_ctrl_status (0, 20)                     230       4600
 rtl_status (0, 16)                            23        368
 rtl_time_estimate (0, 17)                     22        374
 sensor_accel (0, 44)                          45       1980
 sensor_baro (0, 32)                           45       1440
 sensor_combined (0, 48)                    11477     550896
 sensor_gps (0, 147)                           32       4704
 sensor_gyro (0, 44)                           46       2024
 sensor_gyro_fft (0, 100)                       4        400
 sensor_mag (0, 40)                            46       1840
 sensor_selection (0, 16)                       1         16
 sensors_status_imu (0, 96)                   230      22080
 system_power (0, 42)                          91       3822
 takeoff_status (0, 13)                        15        195
 telemetry_status (0, 84)                      45       3780
 telemetry_status (1, 84)                      45       3780
 telemetry_status (2, 84)                      45       3780
 telemetry_status (3, 84)                      45       3780
 trajectory_setpoint (0, 64)                  230      14720
 transponder_report (0, 78)                     1         78
 vehicle_acceleration (0, 28)                 920      25760
 vehicle_air_data (0, 38)                     461      17518
 vehicle_angular_velocity (0, 40)            4592     183680
 vehicle_angular_velocity_groundtruth (0, 40)    4592     183680
 vehicle_attitude (0, 49)                   11197     548653
 vehicle_attitude_groundtruth (0, 49)        4592     225008
 vehicle_attitude_setpoint (0, 40)            915      36600
 vehicle_command (0, 55)                        5        275
 vehicle_command_ack (0, 22)                    5        110
 vehicle_constraints (0, 17)                   46        782
 vehicle_control_mode (0, 23)                  98       2254
 vehicle_global_position (0, 67)             5449     365083
 vehicle_global_position_groundtruth (0, 67)     461      30887
 vehicle_gps_position (0, 147)                262      38514
 vehicle_imu (0, 60)                           92       5520
 vehicle_imu_status (0, 132)                   46       6072
 vehicle_land_detected (0, 20)                 54       1080
 vehicle_local_position (0, 192)             5730    1100160
 vehicle_local_position_groundtruth (0, 192)    2297     441024
 vehicle_local_position_setpoint (0, 64)      458      29312
 vehicle_magnetometer (0, 33)                 643      21219
 vehicle_rates_setpoint (0, 33)              2214      73062
 vehicle_status (0, 74)                        98       7252
 vehicle_thrust_setpoint (0, 28)             2297      64316
 vehicle_torque_setpoint (0, 28)             2297      64316
 yaw_estimator_status (0, 105)               3981     418005
```

</details>

<details><summary>analysis (analyze_ulog.py): state sequences, failsafe_flags, commands, acks, battery, GPS, estimator flags, changed parameters, logged strings</summary>

```
FILE: failsafe_gps_loss.ulg  (10217078 bytes)
start=0.260s last=46.172s duration=45.9s
dropouts: 0 []
file_corruption: False  has_default_parameters: 1
info fields:
  boot_time_utc_us = 1792322126502244
  metadata_events_sha256 = '3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d'
  sys_name = 'PX4'
  sys_os_name = 'Linux'
  sys_os_ver_release = 101854463
  sys_toolchain = 'GNU GCC'
  sys_toolchain_ver = '13.3.0'
  time_ref_utc = 0
  ver_data_format = 2
  ver_hw = 'PX4_SITL'
  ver_sw = 'd6f12ad1c4f70ad3230afd7d86e971421e02fef4'
  ver_sw_release = 17891583
  ver_vendor_sw_release = 255
info multiple: {'perf_counter_preflight': 1, 'metadata_events': 1, 'excluded_optional_topics': 40, 'perf_counter_postflight': 1}
initial_parameters: 901   changed_parameters: 20

TOPIC PRESENCE (required list):
  vehicle_status           PRESENT inst0=98 msgs
  failsafe_flags           PRESENT inst0=89 msgs
  vehicle_command          PRESENT inst0=5 msgs
  vehicle_command_ack      PRESENT inst0=5 msgs
  vtol_vehicle_status      ABSENT
  vehicle_land_detected    PRESENT inst0=54 msgs
  sensor_gps               PRESENT inst0=32 msgs
  vehicle_gps_position     PRESENT inst0=262 msgs
  battery_status           PRESENT inst0=230 msgs
  estimator_status_flags   PRESENT inst0=63 msgs
  log_message              ABSENT

VEHICLE_STATUS:
  arming_state (3 changes):
    t=0.096s  DISARMED
    t=3.868s  ARMED
    t=45.172s  DISARMED
  nav_state (5 changes):
    t=0.096s  AUTO_LOITER
    t=6.856s  AUTO_TAKEOFF
    t=12.664s  AUTO_LOITER
    t=37.936s  DESCEND
    t=45.172s  AUTO_LOITER
  failsafe (3 changes):
    t=0.096s  0
    t=37.936s  1
    t=45.172s  0
  failsafe_defer_state (1 changes):
    t=0.096s  0
  vehicle_type (1 changes):
    t=0.096s  ROTARY_WING
  is_vtol (1 changes):
    t=0.096s  0
  in_transition_mode (1 changes):
    t=0.096s  0
  in_transition_to_fw (1 changes):
    t=0.096s  0
  pre_flight_checks_pass (5 changes):
    t=0.096s  0
    t=3.592s  1
    t=37.924s  0
    t=37.936s  1
    t=45.172s  0
  latest_arming_reason (2 changes):
    t=0.096s  0
    t=3.868s  3
  latest_disarming_reason (2 changes):
    t=0.096s  0
    t=45.172s  6

FAILSAFE_FLAGS (fields that change; mode_req_* skipped):
  attitude_invalid (2 changes):
    t=0.168s  1
    t=1.440s  0
  local_altitude_invalid (2 changes):
    t=0.168s  1
    t=0.924s  0
  local_position_invalid (3 changes):
    t=0.168s  1
    t=3.592s  0
    t=37.924s  1
  local_position_invalid_relaxed (3 changes):
    t=0.168s  1
    t=3.592s  0
    t=37.924s  1
  local_velocity_invalid (3 changes):
    t=0.168s  1
    t=3.592s  0
    t=37.924s  1
  global_position_invalid (3 changes):
    t=0.168s  1
    t=3.592s  0
    t=37.924s  1
  global_position_invalid_relaxed (3 changes):
    t=0.168s  1
    t=3.592s  0
    t=37.924s  1
  auto_mission_missing (1 changes):
    t=0.168s  1
  offboard_control_signal_lost (1 changes):
    t=0.168s  1
  manual_control_signal_lost (1 changes):
    t=0.168s  1
  gcs_connection_lost (1 changes):
    t=0.168s  1

VTOL_VEHICLE_STATUS:
  absent

VEHICLE_LAND_DETECTED:
  landed (3 changes):
    t=0.148s  1
    t=7.688s  0
    t=43.160s  1
  maybe_landed (3 changes):
    t=0.148s  1
    t=7.688s  0
    t=42.824s  1
  ground_contact (3 changes):
    t=0.148s  1
    t=7.792s  0
    t=42.472s  1
  in_ground_effect (6 changes):
    t=0.148s  0
    t=0.916s  1
    t=2.556s  0
    t=2.572s  1
    t=13.376s  0
    t=37.936s  1

VEHICLE_COMMAND (all rows):
    t=0.124s cmd=211 DO_GRIPPER             p1=7.42014e-20 p2=1 p3=7.42049e-20 src=17/13376 tgt=175/31 from_external=False
    t=3.864s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=6.836s cmd=22 NAV_TAKEOFF            p1=nan p2=nan p3=nan src=1/1 tgt=1/1 from_external=False
    t=6.848s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=17.752s cmd=420 INJECT_FAILURE         p1=4 p2=1 p3=0 src=0/0 tgt=0/0 from_external=False

VEHICLE_COMMAND_ACK (all rows):
    t=0.128s cmd=211 DO_GRIPPER             result=5 IN_PROGRESS tgt=17/64 from_external=False
    t=1.224s cmd=211 DO_GRIPPER             result=0 ACCEPTED tgt=17/64 from_external=False
    t=3.868s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False
    t=6.844s cmd=22 NAV_TAKEOFF            result=0 ACCEPTED tgt=1/1 from_external=False
    t=6.856s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False

BATTERY_STATUS inst0:
  warning (1 changes):
    t=0.264s  0
    remaining first=0.989 last=0.779 min=0.500

SENSOR_GPS / VEHICLE_GPS_POSITION fix_type:
  sensor_gps inst0 fix_type (1 changes):
    t=1.144s  3
    sensor_gps inst0 last msg t=32.144s
  vehicle_gps_position inst0 fix_type (1 changes):
    t=0.144s  3
    vehicle_gps_position inst0 last msg t=32.768s

ESTIMATOR_STATUS_FLAGS inst0 (gps-related):
  cs_gnss_pos (3 changes):
    t=0.332s  0
    t=2.540s  1
    t=39.768s  0
  cs_gnss_vel (3 changes):
    t=0.332s  0
    t=2.540s  1
    t=39.768s  0
  cs_in_air (3 changes):
    t=0.332s  0
    t=7.840s  1
    t=43.312s  0
  cs_inertial_dead_reckoning (3 changes):
    t=0.332s  1
    t=2.540s  0
    t=33.920s  1
  cs_wind_dead_reckoning (1 changes):
    t=0.332s  0

CHANGED_PARAMETERS (20):
    t=0.260s CAL_ACC0_ID = 1310988
    t=0.260s CAL_ACC1_ID = 1310996
    t=0.260s CAL_ACC2_ID = 1311004
    t=0.260s CAL_BARO0_ID = 6620172
    t=0.260s CAL_BARO0_OFF = 0.0
    t=0.260s CAL_BARO0_PRIO = 50
    t=0.260s CAL_GYRO0_ID = 1310988
    t=0.260s CAL_GYRO1_ID = 1310996
    t=0.260s CAL_GYRO2_ID = 1311004
    t=0.260s CAL_MAG0_ID = 197388
    t=0.260s CAL_MAG0_PRIO = 50
    t=0.260s CAL_MAG1_ID = 197644
    t=0.260s CAL_MAG1_PRIO = 50
    t=0.260s SENS_BOARD_X_OFF = 9.999999974752427e-07
    t=0.260s SENS_DPRES_OFF = 0.0010000000474974513
    t=0.260s SYS_AUTOCONFIG = 0
    t=0.260s SYS_AUTOSTART = 10040
    t=5.308s CAL_BARO0_ID = 6620172
    t=5.308s CAL_BARO0_OFF = 0.0
    t=5.308s CAL_BARO0_PRIO = 50

LOGGED_MESSAGES (22):
    t=0.260s [INFO] [logger] logger started (mode=all)
    t=0.260s [INFO] [logger] Start file log (type: full)
    t=0.260s [INFO] [logger] Opened full log file: ./log/2026-10-18/11_15_26.ulg
    t=0.264s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.264s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.264s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.268s [INFO] [px4] Startup script returned successfully
    t=3.592s [INFO] [commander] <ESC>[32mReady for takeoff!<ESC>[0m
    t=3.868s [INFO] [commander] Armed by internal command	
    t=3.868s [INFO] [tone_alarm] arming warning
    t=6.856s [INFO] [navigator] Using default takeoff altitude: 2.5 m	
    t=7.696s [INFO] [commander] Takeoff detected	
    t=17.752s [WARN] [failure] inject failure unit: gps (4), type: off (1), instance: 0
    t=18.760s [ERR] [failure] Timeout waiting for ack
    t=32.868s [INFO] [sensor_gps_sim] running
    t=37.920s [WARN] [mc_pos_control] invalid setpoints
    t=37.920s [WARN] [mc_pos_control] Failsafe: blind land
    t=37.936s [WARN] [failsafe] Failsafe activated	
    t=37.936s [INFO] [tone_alarm] battery warning (fast)
    t=43.168s [INFO] [commander] Landing detected	
    t=45.172s [INFO] [commander] Disarmed by landing	
    t=45.176s [INFO] [tone_alarm] notify neutral

LOGGED_MESSAGES_TAGGED (0)
```

</details>

<details><summary>ulog_messages failsafe_gps_loss.ulg</summary>

```
0:00:00.260 INFO: logging: opening log file 2026-10-18/11_15_26.ulg
0:00:00.260 INFO: [logger] logger started (mode=all)
0:00:00.260 INFO: [logger] Start file log (type: full)
0:00:00.260 INFO: [logger] Opened full log file: ./log/2026-10-18/11_15_26.ulg
0:00:00.264 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.264 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.264 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.268 INFO: [px4] Startup script returned successfully
0:00:03.592 INFO: [commander] <ESC>[32mReady for takeoff!<ESC>[0m
0:00:03.868 INFO: Armed by internal command
0:00:03.868 INFO: [tone_alarm] arming warning
0:00:06.856 INFO: Using default takeoff altitude: 2.50 m
0:00:07.696 INFO: Takeoff detected
0:00:17.752 WARNING: [failure] inject failure unit: gps (4), type: off (1), instance: 0
0:00:18.760 ERROR: [failure] Timeout waiting for ack
0:00:32.868 INFO: [sensor_gps_sim] running
0:00:37.920 WARNING: [mc_pos_control] invalid setpoints
0:00:37.920 WARNING: [mc_pos_control] Failsafe: blind land
0:00:37.936 WARNING: Failsafe activated: Autopilot disengaged, switching to Descend
0:00:37.936 INFO: [tone_alarm] battery warning (fast)
0:00:39.772 INFO: GNSS data fusion stopped
0:00:43.168 INFO: Landing detected
0:00:45.172 INFO: Disarmed by landing
0:00:45.176 INFO: [tone_alarm] notify neutral
```

</details>

<details><summary>command log failsafe_gps_loss.cmd.log</summary>

```
[2026-10-18T11:15:26.257] SCENARIO failsafe_gps_loss  rootfs=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/fs_gps_rootfs  PX4 v1.17.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4
[2026-10-18T11:15:26.274] host load at start: 2.50 1.97 1.04 6/151 17445  ns: /tmp=claude-0 
[2026-10-18T11:15:26.296] START px4: cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/fs_gps_rootfs && PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/bin/px4 -d /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/etc > /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/failsafe_gps_loss.px4.log 2>&1 &
[2026-10-18T11:15:30.329] WAIT ok: vehicle_status.pre_flight_checks_pass=True after 1s (sim t=3.592s)
[2026-10-18T11:15:30.343] WAIT ok: home_position.valid_hpos=True after 0s (sim t=3.592s)
[2026-10-18T11:15:30.350] CMD (sim t=3.592s): param show SYS_FAILURE_EN
    > Symbols: x = used, + = saved, * = unsaved
    > x   SYS_FAILURE_EN [871,1433] : 1
    > 
    >  901/1794 parameters used.
[2026-10-18T11:15:30.362] CMD (sim t=3.592s): param show COM_POSCTL_NAVL
    > Symbols: x = used, + = saved, * = unsaved
    > 
    >  901/1794 parameters used.
[2026-10-18T11:15:30.374] CMD (sim t=3.592s): param show NAV_RCL_ACT
    > Symbols: x = used, + = saved, * = unsaved
    > x   NAV_RCL_ACT [650,1123] : 2
    > 
    >  901/1794 parameters used.
[2026-10-18T11:15:30.386] CMD (sim t=3.592s): param show COM_LOW_BAT_ACT
    > Symbols: x = used, + = saved, * = unsaved
    > x   COM_LOW_BAT_ACT [280,496] : 3
    > 
    >  901/1794 parameters used.
[2026-10-18T11:15:30.397] CMD (sim t=3.592s): param show SIM_GPS_USED
    > Symbols: x = used, + = saved, * = unsaved
    > x   SIM_GPS_USED [861,1418] : 10
    > 
    >  901/1794 parameters used.
[2026-10-18T11:15:30.408] STATUS: timestamp: 3592000 (0.256000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:15:30.415] CMD (sim t=3.592s): commander arm
[2026-10-18T11:15:33.431] STATUS: timestamp: 6328000 (0.492000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:15:33.439] CMD (sim t=6.328s): commander takeoff
[2026-10-18T11:15:34.476] WAIT ok: vehicle_status.nav_state=17 after 1s (sim t=7.360s)
[2026-10-18T11:15:34.484] STATUS: timestamp: 7360000 (0.496000 seconds ago) | arming_state: 2 | nav_state: 17 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:15:39.529] WAIT ok: vehicle_status.nav_state=4 after 5s (sim t=12.664s)
[2026-10-18T11:15:39.536] STATUS: timestamp: 12664000 (0.144000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:15:44.548] STATUS: timestamp: 17704000 (0.016000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:15:44.555] FAILSAFE_FLAGS: auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | 
[2026-10-18T11:15:44.562] CMD (sim t=17.704s): param set SYS_FAILURE_EN 1
[2026-10-18T11:15:44.573] CMD (sim t=17.704s): failure gps off
    > WARN  [failure] inject failure unit: gps (4), type: off (1), instance: 0
    > ERROR [failure] Timeout waiting for ack
[2026-10-18T11:16:00.610] STATUS: timestamp: 32376000 (0.460000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:16:00.618] FAILSAFE_FLAGS: auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | 
[2026-10-18T11:16:00.629] NOTE: failure gps off did not raise failsafe (no SIH handler). Stopping the simulated GPS driver instead.
[2026-10-18T11:16:00.638] CMD (sim t=32.376s): sensor_gps_sim status
    > INFO  [sensor_gps_sim] running
[2026-10-18T11:16:00.649] CMD (sim t=32.376s): sensor_gps_sim stop
[2026-10-18T11:16:05.684] STATUS: timestamp: 37420000 (0.400000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:16:05.693] FAILSAFE_FLAGS: auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | 
[2026-10-18T11:16:10.701] STATUS: timestamp: 42472000 (0.272000 seconds ago) | arming_state: 2 | nav_state: 12 | vehicle_type: 1 | failsafe: True | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:16:10.708] FAILSAFE_FLAGS: local_position_invalid: True | local_position_invalid_relaxed: True | local_velocity_invalid: True | global_position_invalid: True | global_position_invalid_relaxed: True | auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | 
[2026-10-18T11:16:15.717] STATUS: timestamp: 47188000 (0.488000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: False | 
[2026-10-18T11:16:15.724] FAILSAFE_FLAGS: local_position_invalid: True | local_position_invalid_relaxed: True | local_velocity_invalid: True | global_position_invalid: True | global_position_invalid_relaxed: True | auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | 
[2026-10-18T11:16:20.738] STATUS: timestamp: 52228000 (0.368000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: False | 
[2026-10-18T11:16:20.747] FAILSAFE_FLAGS: local_position_invalid: True | local_position_invalid_relaxed: True | local_velocity_invalid: True | global_position_invalid: True | global_position_invalid_relaxed: True | auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | 
[2026-10-18T11:16:25.755] STATUS: timestamp: 57268000 (0.220000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: False | 
[2026-10-18T11:16:25.763] FAILSAFE_FLAGS: local_position_invalid: True | local_position_invalid_relaxed: True | local_velocity_invalid: True | global_position_invalid: True | global_position_invalid_relaxed: True | auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | 
[2026-10-18T11:16:30.773] STATUS: timestamp: 62308000 (0.116000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: False | 
[2026-10-18T11:16:30.782] FAILSAFE_FLAGS: local_position_invalid: True | local_position_invalid_relaxed: True | local_velocity_invalid: True | global_position_invalid: True | global_position_invalid_relaxed: True | auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | 
[2026-10-18T11:17:01.014] WAIT TIMEOUT: vehicle_status.failsafe=False (wanted True) after 30s (sim t=91.036s)
[2026-10-18T11:17:01.022] STATUS: timestamp: 91036000 (0.072000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: False | 
[2026-10-18T11:17:01.029] FAILSAFE_FLAGS: local_position_invalid: True | local_position_invalid_relaxed: True | local_velocity_invalid: True | global_position_invalid: True | global_position_invalid_relaxed: True | auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | 
[2026-10-18T11:17:01.042] WAIT ok: vehicle_status.arming_state=1 after 0s (sim t=91.036s)
[2026-10-18T11:17:01.050] STATUS: timestamp: 91036000 (0.100000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: False | 
[2026-10-18T11:17:01.058] FAILSAFE_FLAGS: local_position_invalid: True | local_position_invalid_relaxed: True | local_velocity_invalid: True | global_position_invalid: True | global_position_invalid_relaxed: True | auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | 
[2026-10-18T11:17:07.068] CMD (sim t=96.580s): logger status
    > INFO  [logger] Running in mode: all
    > INFO  [logger] Number of subscriptions: 167 (5344 bytes)
    > INFO  [logger] Not logging
[2026-10-18T11:17:07.080] CMD (sim t=96.580s): shutdown
[2026-10-18T11:17:07.087] px4 exit=0
[2026-10-18T11:17:07.105] COPIED /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/fs_gps_rootfs/log/2026-10-18/11_15_26.ulg -> /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/failsafe_gps_loss.ulg (10217078 bytes)
[2026-10-18T11:17:07.110] host load at end: 2.09 1.97 1.13 2/147 19747
[2026-10-18T11:17:07.112] DONE
```

</details>

<details><summary>px4 stdout and stderr failsafe_gps_loss.px4.log</summary>

```

______  __   __    ___ 
| ___ \ \ \ / /   /   |
| |_/ /  \ V /   / /| |
|  __/   /   \  / /_| |
| |     / /^\ \ \___  |
\_|     \/   \/     |_/

px4 starting.

INFO  [px4] startup script: /bin/sh etc/init.d-posix/rcS 0
INFO  [init] found model autostart file as SYS_AUTOSTART=10040
INFO  [param] selected parameter default file parameters.bson
INFO  [param] selected parameter backup file parameters_backup.bson
  SYS_AUTOCONFIG: curr: 0 -> new: 1
  SYS_AUTOSTART: curr: 0 -> new: 10040
  CAL_ACC0_ID: curr: 0 -> new: 1310988
  CAL_GYRO0_ID: curr: 0 -> new: 1310988
  CAL_ACC1_ID: curr: 0 -> new: 1310996
  CAL_GYRO1_ID: curr: 0 -> new: 1310996
  CAL_ACC2_ID: curr: 0 -> new: 1311004
  CAL_GYRO2_ID: curr: 0 -> new: 1311004
  CAL_MAG0_ID: curr: 0 -> new: 197388
  CAL_MAG0_PRIO: curr: -1 -> new: 50
  CAL_MAG1_ID: curr: 0 -> new: 197644
  CAL_MAG1_PRIO: curr: -1 -> new: 50
  SENS_BOARD_X_OFF: curr: 0.0000 -> new: 0.0000
  SENS_DPRES_OFF: curr: 0.0000 -> new: 0.0010
INFO  [dataman] data manager file './dataman' size is 1208528 bytes
INFO  [init] SIH simulator
INFO  [simulator_sih] Simulation loop with 250 Hz (4000 us sim time interval)
INFO  [simulator_sih] Simulation with 1.0x speedup. Loop with (4000 us wall time interval)
INFO  [lockstep_scheduler] setting initial absolute time to 4000 us
INFO  [commander] LED: open /dev/led0 failed (22)
INFO  [tone_alarm] home set
INFO  [uxrce_dds_client] init UDP agent IP:127.0.0.1, port:8888
INFO  [mavlink] mode: Normal, data rate: 4000000 B/s on udp port 18570 remote port 14550
INFO  [mavlink] mode: Onboard, data rate: 4000000 B/s on udp port 14580 remote port 14540
INFO  [mavlink] mode: Onboard, data rate: 4000 B/s on udp port 14280 remote port 14030
INFO  [mavlink] mode: Gimbal, data rate: 400000 B/s on udp port 13030 remote port 13280
INFO  [mavlink] mode: Custom, data rate: 400000 B/s on udp port 19450 remote port 19410
INFO  [logger] logger started (mode=all)
INFO  [logger] Start file log (type: full)
INFO  [logger] [logger] ./log/2026-10-18/11_15_26.ulg	
INFO  [logger] Opened full log file: ./log/2026-10-18/11_15_26.ulg
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [px4] Startup script returned successfully
INFO  [commander] <ESC>[32mReady for takeoff!<ESC>[0m
INFO  [commander] Armed by internal command	
INFO  [tone_alarm] arming warning
INFO  [navigator] Using default takeoff altitude: 2.5 m	
INFO  [commander] Takeoff detected	
WARN  [mc_pos_control] invalid setpoints
WARN  [mc_pos_control] Failsafe: blind land
WARN  [failsafe] Failsafe activated	
INFO  [tone_alarm] battery warning (fast)
INFO  [commander] Landing detected	
INFO  [commander] Disarmed by landing	
INFO  [tone_alarm] notify neutral
INFO  [logger] closed logfile, bytes written: 10217078
Exiting NOW.
```

</details>

<details><summary>script failsafe_gps_loss.sh</summary>

```bash
#!/bin/bash
# failsafe_gps_loss.sh <rootfs_dir> <scenario_name>
# Scenario E (GPS loss): SIH quadx, arm, takeoff, loiter, `param set SYS_FAILURE_EN 1`, `failure gps off`
# (under SIH no module handles FAILURE_UNIT_SENSOR_GPS: only simulator_mavlink does, so expect "Timeout waiting for ack"),
# then stop the simulated GPS driver (`sensor_gps_sim stop`) so sensor_gps data stops and position becomes invalid.
# Observe vehicle_status.failsafe and failsafe_flags, let the failsafe land, auto-disarm. Fresh rootfs.
set -u
PX4_DIR=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0
BIN=$PX4_DIR/build/px4_sitl_default/bin
ETC=$PX4_DIR/build/px4_sitl_default/etc
OUT=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0
ROOTFS=${1:?rootfs}; SCENARIO=${2:?scenario}
MODEL=sihsim_quadx
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS" "$OUT"; cd "$ROOTFS"
PX4LOG=$OUT/$SCENARIO.px4.log; CMDLOG=$OUT/$SCENARIO.cmd.log; : > "$CMDLOG"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3N; }
say() { echo "[$(ts)] $*" | tee -a "$CMDLOG"; }
simt() { "$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +timestamp:/{printf "%.3f", $2/1e6}'; }
vs() { say "STATUS: $("$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +(timestamp|arming_state|nav_state|failsafe|failsafe_defer_state|vehicle_type|pre_flight_checks_pass):/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
ff() { say "FAILSAFE_FLAGS: $("$BIN/px4-listener" failsafe_flags 2>/dev/null | awk '/^ +[a-z_]+: (True|[1-9])/ && !/mode_req_/ && !/timestamp/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
cmd() { say "CMD (sim t=$(simt)s): $*"; "$BIN/px4-$1" "${@:2}" 2>&1 | sed 's/^/    > /' | tee -a "$CMDLOG"; }
wait_for() { # topic field value timeout_s
  local tp=$1 f=$2 v=$3 to=$4 i=0 cur=
  while [ $i -lt "$to" ]; do
    cur=$("$BIN/px4-listener" "$tp" 2>/dev/null | awk -v f="$f" '$1==f":"{print $2}')
    if [ "$cur" = "$v" ]; then say "WAIT ok: $tp.$f=$v after ${i}s (sim t=$(simt)s)"; return 0; fi
    sleep 1; i=$((i+1))
  done
  say "WAIT TIMEOUT: $tp.$f=$cur (wanted $v) after ${to}s (sim t=$(simt)s)"; return 1
}
say "SCENARIO $SCENARIO  rootfs=$ROOTFS  PX4 $(cd $PX4_DIR && git describe --tags --always) $(cd $PX4_DIR && git rev-parse HEAD)"
say "host load at start: $(cat /proc/loadavg)  ns: /tmp=$(ls -A /tmp | tr '\n' ' ')"
touch .start_marker
say "START px4: cd $ROOTFS && PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim $BIN/px4 -d $ETC > $PX4LOG 2>&1 &"
PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim "$BIN/px4" -d "$ETC" > "$PX4LOG" 2>&1 &
PX4_PID=$!
sleep 3
wait_for vehicle_status pre_flight_checks_pass True 150
wait_for home_position valid_hpos True 60
cmd param show SYS_FAILURE_EN; cmd param show COM_POSCTL_NAVL; cmd param show NAV_RCL_ACT; cmd param show COM_LOW_BAT_ACT; cmd param show SIM_GPS_USED
vs
cmd commander arm
sleep 3; vs
cmd commander takeoff
wait_for vehicle_status nav_state 17 10; vs
wait_for vehicle_status nav_state 4 90; vs
sleep 5; vs; ff
cmd param set SYS_FAILURE_EN 1
cmd failure gps off
sleep 15; vs; ff
if [ "$("$BIN/px4-listener" vehicle_status 2>/dev/null | awk '$1=="failsafe:"{print $2}')" != "True" ]; then
  say "NOTE: failure gps off did not raise failsafe (no SIH handler). Stopping the simulated GPS driver instead."
  cmd sensor_gps_sim status
  cmd sensor_gps_sim stop
  for i in 1 2 3 4 5 6; do sleep 5; vs; ff; done
fi
wait_for vehicle_status failsafe True 30; vs; ff
wait_for vehicle_status arming_state 1 240; vs; ff
sleep 6
cmd logger status
cmd shutdown
wait $PX4_PID; say "px4 exit=$?"
ULG=$(find log -name '*.ulg' -newer .start_marker | sort | tail -1)
cp "$ULG" "$OUT/$SCENARIO.ulg"; cp "$0" "$OUT/$SCENARIO.sh"
say "COPIED $ROOTFS/$ULG -> $OUT/$SCENARIO.ulg ($(stat -c %s "$OUT/$SCENARIO.ulg") bytes)"
say "host load at end: $(cat /proc/loadavg)"
say "DONE"
```

</details>

#### E2 (extra): `failsafe_battery_empty.ulg`

- Airframe `10040_sihsim_quadx` (`PX4_SIM_MODEL=sihsim_quadx`), fresh rootfs /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/fs_bat_rootfs.
- Invocation: `cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0 && ./nsrun.sh ./failsafe_battery_empty.sh /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/fs_bat_rootfs failsafe_battery_empty`
- Output: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/failsafe_battery_empty.ulg`, 9208891 bytes, SHA-256 `7bd1633b26acba457f67a575fa9ddace0535e0411c5fdbacbfad777e0eddd75c`, ULog duration 40.5 s, dropouts 0.
- arming_state sequence: 0.092 s DISARMED, 4.664 s ARMED, 39.884 s DISARMED
- nav_state sequence: 0.092 s AUTO_LOITER, 7.604 s AUTO_TAKEOFF, 13.316 s AUTO_LOITER, 28.124 s AUTO_LAND, 39.884 s AUTO_LOITER
- vehicle_status.failsafe sequence: 0.092 s false, 23.120 s true, 39.884 s false

Ordered commands with wall-clock times (from `failsafe_battery_empty.cmd.log`; `param show` lines are read-only checks):

| wall clock UTC (2026-10-18) | sim time at send | command / observation |
|---|---|---|
| 11:17:20.325 | (boot) | start px4 server (see command line above) |
| 11:17:25.360 | | WAIT ok: vehicle_status.pre_flight_checks_pass=True after 2s (sim t=4.316s) |
| 11:17:25.371 | | WAIT ok: home_position.valid_hpos=True after 0s (sim t=4.316s) |
| 11:17:25.378 | 4.316 | `param show SYS_FAILURE_EN` |
| 11:17:25.388 | 4.316 | `param show COM_LOW_BAT_ACT` |
| 11:17:25.398 | 4.316 | `param show SIM_BAT_ENABLE` |
| 11:17:25.409 | 4.316 | `param show BAT_LOW_THR` |
| 11:17:25.419 | 4.316 | `param show BAT_CRIT_THR` |
| 11:17:25.429 | 4.316 | `param show BAT_EMERGEN_THR` |
| 11:17:25.448 | 4.316 | `commander arm` |
| 11:17:28.488 | 7.340 | `commander takeoff` |
| 11:17:28.535 | | WAIT ok: vehicle_status.nav_state=17 after 0s (sim t=7.604s) |
| 11:17:34.645 | | WAIT ok: vehicle_status.nav_state=4 after 6s (sim t=13.316s) |
| 11:17:39.715 | 17.852 | `param show COM_DISARM_LAND` |
| 11:17:39.731 | 17.852 | `param set COM_DISARM_LAND 3.0` |
| 11:17:42.752 | 20.252 | `param show COM_DISARM_LAND` |
| 11:17:42.764 | 20.252 | `failure battery off` |
| 11:17:51.861 | | WAIT ok: vehicle_status.failsafe=True after 0s (sim t=28.892s) |
| 11:18:03.002 | | WAIT ok: vehicle_status.arming_state=1 after 11s (sim t=39.884s) |
| 11:18:09.028 | 45.932 | `logger status` |
| 11:18:09.049 | 45.932 | `shutdown` |
| 11:18:09.064 | | px4 exit=0 |

Extra log (the brief allowed `failure battery off` as an alternative). `failure battery off` was accepted (ack 0, `[battery_simulator] CMD_INJECT_FAILURE, battery empty`). `battery_status.warning` and `failsafe_flags.battery_warning` (a uint8 level, not a bool) went 1 (LOW) at 22.34 s, 2 (CRITICAL) at 23.11 s and 3 (EMERGENCY) at 23.55 s. `vehicle_status.failsafe` became true at 23.120 s with `Failsafe activated: entering Hold for 5 seconds`, and nav_state stayed AUTO_LOITER (hold) until AUTO_LAND at 28.124 s (`COM_LOW_BAT_ACT` 3). Landing detected 36.884 s, disarmed by landing 39.884 s. Before the failure it also contains one real in-flight parameter change (`param set COM_DISARM_LAND 3.0` at sim 17.85 s while armed and in air, logged at 18.232 s). The change took effect: disarm came exactly 3.0 s after `Landing detected`, where the default is 2.0 s.

<details><summary>ulog_info failsafe_battery_empty.ulg</summary>

```
Logging start time: 0:00:00, duration: 0:00:40
No Dropouts
SW Version: v1.17.0
Info Messages:
 boot_time_utc_us: 1792322240593384
 metadata_events_sha256: 3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d
 sys_name: PX4
 sys_os_name: Linux
 sys_os_ver_release: 101854463
 sys_toolchain: GNU GCC
 sys_toolchain_ver: 13.3.0
 time_ref_utc: 0
 ver_data_format: 2
 ver_hw: PX4_SITL
 ver_sw: d6f12ad1c4f70ad3230afd7d86e971421e02fef4
 ver_sw_release: 17891583
 ver_vendor_sw_release: 255
Info Multiple Messages: [excluded_optional_topics: 40], [metadata_events: 1], [perf_counter_postflight: 1], [perf_counter_preflight: 1]

Name (multi id, message size in bytes)    number of data points, total bytes
 actuator_armed (0, 15)                        88       1320
 actuator_motors (0, 66)                      407      26862
 actuator_outputs (0, 76)                     407      30932
 battery_status (0, 166)                      204      33864
 config_overrides (0, 14)                      80       1120
 control_allocator_status (0, 54)             204      11016
 cpuload (0, 16)                               80       1280
 distance_sensor (0, 56)                     2029     113624
 distance_sensor_mode_change_request (0, 9)       1          9
 ekf2_timestamps (0, 22)                    10137     223014
 estimator_aid_src_baro_hgt (0, 59)           407      24013
 estimator_aid_src_fake_hgt (0, 59)             3        177
 estimator_aid_src_fake_pos (0, 95)            32       3040
 estimator_aid_src_gnss_hgt (0, 59)           317      18703
 estimator_aid_src_gnss_pos (0, 95)           325      30875
 estimator_aid_src_gnss_vel (0, 115)          325      37375
 estimator_aid_src_gravity (0, 115)          4056     466440
 estimator_aid_src_mag (0, 115)               566      65090
 estimator_aid_src_rng_hgt (0, 59)           1986     117174
 estimator_baro_bias (0, 40)                  365      14600
 estimator_event_flags (0, 37)                 44       1628
 estimator_gnss_hgt_bias (0, 40)              314      12560
 estimator_gps_status (0, 40)                 325      13000
 estimator_innovation_test_ratios (0, 140)    4056     567840
 estimator_innovation_variances (0, 140)     4056     567840
 estimator_innovations (0, 140)              4056     567840
 estimator_sensor_bias (0, 118)               714      84252
 estimator_states (0, 213)                   4056     863928
 estimator_status (0, 129)                   4056     523224
 estimator_status_flags (0, 97)                57       5529
 event (0, 40)                                 45       1800
 failsafe_flags (0, 91)                        81       7371
 failure_detector_status (0, 24)               88       2112
 gripper (0, 9)                                 1          9
 home_position (0, 60)                        229      13740
 hover_thrust_estimate (0, 41)                240       9840
 landing_gear (0, 9)                            3         27
 manual_control_setpoint (0, 65)                1         65
 mission_result (0, 38)                        67       2546
 navigator_status (0, 10)                      83        830
 parameter_update (0, 34)                       3        102
 position_setpoint_triplet (0, 248)            49      12152
 rate_ctrl_status (0, 20)                     204       4080
 rtl_status (0, 16)                            20        320
 rtl_time_estimate (0, 17)                     20        340
 sensor_accel (0, 44)                          40       1760
 sensor_baro (0, 32)                           40       1280
 sensor_combined (0, 48)                    10137     486576
 sensor_gps (0, 147)                           40       5880
 sensor_gyro (0, 44)                           40       1760
 sensor_gyro_fft (0, 100)                       5        500
 sensor_mag (0, 40)                            40       1600
 sensor_selection (0, 16)                       1         16
 sensors_status_imu (0, 96)                   204      19584
 system_power (0, 42)                          81       3402
 takeoff_status (0, 13)                        16        208
 telemetry_status (0, 84)                      40       3360
 telemetry_status (1, 84)                      40       3360
 telemetry_status (2, 84)                      40       3360
 telemetry_status (3, 84)                      40       3360
 trajectory_setpoint (0, 64)                  204      13056
 transponder_report (0, 78)                     1         78
 vehicle_acceleration (0, 28)                 812      22736
 vehicle_air_data (0, 38)                     408      15504
 vehicle_angular_velocity (0, 40)            4056     162240
 vehicle_angular_velocity_groundtruth (0, 40)    4056     162240
 vehicle_attitude (0, 49)                    9822     481278
 vehicle_attitude_groundtruth (0, 49)        4056     198744
 vehicle_attitude_setpoint (0, 40)            812      32480
 vehicle_command (0, 55)                        8        440
 vehicle_command_ack (0, 22)                    6        132
 vehicle_constraints (0, 17)                   40        680
 vehicle_control_mode (0, 23)                  88       2024
 vehicle_global_position (0, 67)             4686     313962
 vehicle_global_position_groundtruth (0, 67)     407      27269
 vehicle_gps_position (0, 147)                325      47775
 vehicle_imu (0, 60)                           81       4860
 vehicle_imu_status (0, 132)                   40       5280
 vehicle_land_detected (0, 20)                 48        960
 vehicle_local_position (0, 192)             5069     973248
 vehicle_local_position_groundtruth (0, 192)    2029     389568
 vehicle_local_position_setpoint (0, 64)      407      26048
 vehicle_magnetometer (0, 33)                 568      18744
 vehicle_rates_setpoint (0, 33)              1945      64185
 vehicle_status (0, 74)                        88       6512
 vehicle_thrust_setpoint (0, 28)             2029      56812
 vehicle_torque_setpoint (0, 28)             2029      56812
 yaw_estimator_status (0, 105)               4481     470505
```

</details>

<details><summary>analysis (analyze_ulog.py): state sequences, failsafe_flags, commands, acks, battery, GPS, estimator flags, changed parameters, logged strings</summary>

```
FILE: failsafe_battery_empty.ulg  (9208891 bytes)
start=0.332s last=40.880s duration=40.5s
dropouts: 0 []
file_corruption: False  has_default_parameters: 1
info fields:
  boot_time_utc_us = 1792322240593384
  metadata_events_sha256 = '3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d'
  sys_name = 'PX4'
  sys_os_name = 'Linux'
  sys_os_ver_release = 101854463
  sys_toolchain = 'GNU GCC'
  sys_toolchain_ver = '13.3.0'
  time_ref_utc = 0
  ver_data_format = 2
  ver_hw = 'PX4_SITL'
  ver_sw = 'd6f12ad1c4f70ad3230afd7d86e971421e02fef4'
  ver_sw_release = 17891583
  ver_vendor_sw_release = 255
info multiple: {'perf_counter_preflight': 1, 'metadata_events': 1, 'excluded_optional_topics': 40, 'perf_counter_postflight': 1}
initial_parameters: 901   changed_parameters: 21

TOPIC PRESENCE (required list):
  vehicle_status           PRESENT inst0=88 msgs
  failsafe_flags           PRESENT inst0=81 msgs
  vehicle_command          PRESENT inst0=8 msgs
  vehicle_command_ack      PRESENT inst0=6 msgs
  vtol_vehicle_status      ABSENT
  vehicle_land_detected    PRESENT inst0=48 msgs
  sensor_gps               PRESENT inst0=40 msgs
  vehicle_gps_position     PRESENT inst0=325 msgs
  battery_status           PRESENT inst0=204 msgs
  estimator_status_flags   PRESENT inst0=57 msgs
  log_message              ABSENT

VEHICLE_STATUS:
  arming_state (3 changes):
    t=0.092s  DISARMED
    t=4.664s  ARMED
    t=39.884s  DISARMED
  nav_state (5 changes):
    t=0.092s  AUTO_LOITER
    t=7.604s  AUTO_TAKEOFF
    t=13.316s  AUTO_LOITER
    t=28.124s  AUTO_LAND
    t=39.884s  AUTO_LOITER
  failsafe (3 changes):
    t=0.092s  0
    t=23.120s  1
    t=39.884s  0
  failsafe_defer_state (1 changes):
    t=0.092s  0
  vehicle_type (1 changes):
    t=0.092s  ROTARY_WING
  is_vtol (1 changes):
    t=0.092s  0
  in_transition_mode (1 changes):
    t=0.092s  0
  in_transition_to_fw (1 changes):
    t=0.092s  0
  pre_flight_checks_pass (3 changes):
    t=0.092s  0
    t=3.812s  1
    t=23.108s  0
  latest_arming_reason (2 changes):
    t=0.092s  0
    t=4.664s  3
  latest_disarming_reason (2 changes):
    t=0.092s  0
    t=39.884s  6

FAILSAFE_FLAGS (fields that change; mode_req_* skipped):
  attitude_invalid (2 changes):
    t=0.164s  1
    t=1.652s  0
  local_altitude_invalid (2 changes):
    t=0.164s  1
    t=1.004s  0
  local_position_invalid (2 changes):
    t=0.164s  1
    t=3.812s  0
  local_position_invalid_relaxed (2 changes):
    t=0.164s  1
    t=3.812s  0
  local_velocity_invalid (2 changes):
    t=0.164s  1
    t=3.812s  0
  global_position_invalid (2 changes):
    t=0.164s  1
    t=3.812s  0
  global_position_invalid_relaxed (2 changes):
    t=0.164s  1
    t=3.812s  0
  auto_mission_missing (1 changes):
    t=0.164s  1
  offboard_control_signal_lost (1 changes):
    t=0.164s  1
  manual_control_signal_lost (1 changes):
    t=0.164s  1
  gcs_connection_lost (1 changes):
    t=0.164s  1
  battery_warning (4 changes):
    t=0.164s  0
    t=22.340s  1
    t=23.108s  2
    t=23.552s  3

VTOL_VEHICLE_STATUS:
  absent

VEHICLE_LAND_DETECTED:
  landed (3 changes):
    t=0.144s  1
    t=8.464s  0
    t=36.872s  1
  maybe_landed (3 changes):
    t=0.144s  1
    t=8.464s  0
    t=35.872s  1
  ground_contact (3 changes):
    t=0.144s  1
    t=8.560s  0
    t=34.568s  1
  in_ground_effect (6 changes):
    t=0.144s  0
    t=0.920s  1
    t=2.800s  0
    t=2.816s  1
    t=14.872s  0
    t=28.520s  1

VEHICLE_COMMAND (all rows):
    t=0.148s cmd=211 DO_GRIPPER             p1=0.00180495 p2=1 p3=0.00180501 src=72/37952 tgt=236/58 from_external=False
    t=4.656s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=7.580s cmd=22 NAV_TAKEOFF            p1=nan p2=nan p3=nan src=1/1 tgt=1/1 from_external=False
    t=7.592s cmd=400 COMPONENT_ARM_DISARM   p1=1 p2=0 p3=nan src=1/1 tgt=1/1 from_external=False
    t=20.720s cmd=420 INJECT_FAILURE         p1=100 p2=1 p3=0 src=0/0 tgt=0/0 from_external=False
    t=28.376s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=1 p2=1 p3=-1 src=1/1 tgt=1/0 from_external=False
    t=28.376s cmd=1000 DO_GIMBAL_MANAGER_PITCHYAW p1=nan p2=nan p3=nan src=1/1 tgt=1/0 from_external=False
    t=28.376s cmd=1001 DO_GIMBAL_MANAGER_CONFIGURE p1=-3 p2=-3 p3=-1 src=1/1 tgt=1/0 from_external=False

VEHICLE_COMMAND_ACK (all rows):
    t=0.152s cmd=211 DO_GRIPPER             result=5 IN_PROGRESS tgt=72/64 from_external=False
    t=1.248s cmd=211 DO_GRIPPER             result=0 ACCEPTED tgt=72/64 from_external=False
    t=4.664s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False
    t=7.592s cmd=22 NAV_TAKEOFF            result=0 ACCEPTED tgt=1/1 from_external=False
    t=7.604s cmd=400 COMPONENT_ARM_DISARM   result=0 ACCEPTED tgt=1/1 from_external=False
    t=20.728s cmd=420 INJECT_FAILURE         result=0 ACCEPTED tgt=0/0 from_external=False

BATTERY_STATUS inst0:
  warning (4 changes):
    t=0.328s  0
    t=22.400s  1
    t=23.200s  2
    t=23.600s  3
    remaining first=0.989 last=0.000 min=0.000

SENSOR_GPS / VEHICLE_GPS_POSITION fix_type:
  sensor_gps inst0 fix_type (1 changes):
    t=1.144s  3
    sensor_gps inst0 last msg t=40.144s
  vehicle_gps_position inst0 fix_type (1 changes):
    t=0.268s  3
    vehicle_gps_position inst0 last msg t=40.768s

ESTIMATOR_STATUS_FLAGS inst0 (gps-related):
  cs_gnss_pos (2 changes):
    t=0.316s  0
    t=2.792s  1
  cs_gnss_vel (2 changes):
    t=0.316s  0
    t=2.792s  1
  cs_in_air (3 changes):
    t=0.316s  0
    t=8.616s  1
    t=37.024s  0
  cs_inertial_dead_reckoning (2 changes):
    t=0.316s  1
    t=2.792s  0
  cs_wind_dead_reckoning (1 changes):
    t=0.316s  0

CHANGED_PARAMETERS (21):
    t=0.332s CAL_ACC0_ID = 1310988
    t=0.332s CAL_ACC1_ID = 1310996
    t=0.332s CAL_ACC2_ID = 1311004
    t=0.332s CAL_BARO0_ID = 6620172
    t=0.332s CAL_BARO0_OFF = 0.0
    t=0.332s CAL_BARO0_PRIO = 50
    t=0.332s CAL_GYRO0_ID = 1310988
    t=0.332s CAL_GYRO1_ID = 1310996
    t=0.332s CAL_GYRO2_ID = 1311004
    t=0.332s CAL_MAG0_ID = 197388
    t=0.332s CAL_MAG0_PRIO = 50
    t=0.332s CAL_MAG1_ID = 197644
    t=0.332s CAL_MAG1_PRIO = 50
    t=0.332s SENS_BOARD_X_OFF = 9.999999974752427e-07
    t=0.332s SENS_DPRES_OFF = 0.0010000000474974513
    t=0.332s SYS_AUTOCONFIG = 0
    t=0.332s SYS_AUTOSTART = 10040
    t=5.312s CAL_BARO0_ID = 6620172
    t=5.312s CAL_BARO0_OFF = -7.32421875
    t=5.312s CAL_BARO0_PRIO = 50
    t=18.232s COM_DISARM_LAND = 3.0

LOGGED_MESSAGES (24):
    t=0.328s [INFO] [logger] logger started (mode=all)
    t=0.332s [INFO] [logger] Start file log (type: full)
    t=0.332s [INFO] [logger] Opened full log file: ./log/2026-10-18/11_17_20.ulg
    t=0.332s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.332s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.332s [INFO] [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
    t=0.344s [INFO] [px4] Startup script returned successfully
    t=3.812s [INFO] [commander] <ESC>[32mReady for takeoff!<ESC>[0m
    t=4.664s [INFO] [commander] Armed by internal command	
    t=4.664s [INFO] [tone_alarm] arming warning
    t=7.604s [INFO] [navigator] Using default takeoff altitude: 2.5 m	
    t=8.468s [INFO] [commander] Takeoff detected	
    t=20.720s [WARN] [failure] inject failure unit: battery (100), type: off (1), instance: 0
    t=20.728s [WARN] [battery_simulator] CMD_INJECT_FAILURE, battery empty
    t=22.340s [WARN] [health_and_arming_checks] Low battery	
    t=22.352s [INFO] [tone_alarm] battery warning (slow)
    t=23.120s [WARN] [failsafe] Failsafe activated: entering Hold for 5 seconds	
    t=23.120s [INFO] [tone_alarm] battery warning (fast)
    t=23.564s [WARN] [commander] System does not support shutdown	
    t=25.172s [ERR] [health_and_arming_checks] Emergency battery level	
    t=28.124s [WARN] [failsafe] Failsafe activated	
    t=36.884s [INFO] [commander] Landing detected	
    t=39.884s [INFO] [commander] Disarmed by landing	
    t=39.884s [INFO] [tone_alarm] notify neutral

LOGGED_MESSAGES_TAGGED (0)
```

</details>

<details><summary>ulog_messages failsafe_battery_empty.ulg</summary>

```
0:00:00.328 INFO: [logger] logger started (mode=all)
0:00:00.332 INFO: logging: opening log file 2026-10-18/11_17_20.ulg
0:00:00.332 INFO: [logger] Start file log (type: full)
0:00:00.332 INFO: [logger] Opened full log file: ./log/2026-10-18/11_17_20.ulg
0:00:00.332 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.332 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.332 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.344 INFO: [px4] Startup script returned successfully
0:00:03.812 INFO: [commander] <ESC>[32mReady for takeoff!<ESC>[0m
0:00:04.664 INFO: Armed by internal command
0:00:04.664 INFO: [tone_alarm] arming warning
0:00:07.604 INFO: Using default takeoff altitude: 2.50 m
0:00:08.468 INFO: Takeoff detected
0:00:20.720 WARNING: [failure] inject failure unit: battery (100), type: off (1), instance: 0
0:00:20.728 WARNING: [battery_simulator] CMD_INJECT_FAILURE, battery empty
0:00:22.352 INFO: Low battery level, return advised
0:00:22.352 INFO: [tone_alarm] battery warning (slow)
0:00:23.120 WARNING: Critical battery level: switching to RTL in 5 seconds
0:00:23.120 INFO: [tone_alarm] battery warning (fast)
0:00:23.564 ERROR: Dangerously low battery! System shut down failed
0:00:28.124 WARNING: Emergency battery level: switching to Land
0:00:36.884 INFO: Landing detected
0:00:39.884 INFO: Disarmed by landing
0:00:39.884 INFO: [tone_alarm] notify neutral
```

</details>

<details><summary>command log failsafe_battery_empty.cmd.log</summary>

```
[2026-10-18T11:17:20.289] SCENARIO failsafe_battery_empty  rootfs=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/fs_bat_rootfs  PX4 v1.17.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4
[2026-10-18T11:17:20.313] host load at start: 2.00 1.95 1.14 6/151 19859  ns: /tmp=claude-0 
[2026-10-18T11:17:20.325] START px4: cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/fs_bat_rootfs && PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/bin/px4 -d /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0/build/px4_sitl_default/etc > /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/failsafe_battery_empty.px4.log 2>&1 &
[2026-10-18T11:17:25.360] WAIT ok: vehicle_status.pre_flight_checks_pass=True after 2s (sim t=4.316s)
[2026-10-18T11:17:25.371] WAIT ok: home_position.valid_hpos=True after 0s (sim t=4.316s)
[2026-10-18T11:17:25.378] CMD (sim t=4.316s): param show SYS_FAILURE_EN
    > Symbols: x = used, + = saved, * = unsaved
    > x   SYS_FAILURE_EN [871,1433] : 1
    > 
    >  901/1794 parameters used.
[2026-10-18T11:17:25.388] CMD (sim t=4.316s): param show COM_LOW_BAT_ACT
    > Symbols: x = used, + = saved, * = unsaved
    > x   COM_LOW_BAT_ACT [280,496] : 3
    > 
    >  901/1794 parameters used.
[2026-10-18T11:17:25.398] CMD (sim t=4.316s): param show SIM_BAT_ENABLE
    > Symbols: x = used, + = saved, * = unsaved
    > x   SIM_BAT_ENABLE [859,1416] : 1
    > 
    >  901/1794 parameters used.
[2026-10-18T11:17:25.409] CMD (sim t=4.316s): param show BAT_LOW_THR
    > Symbols: x = used, + = saved, * = unsaved
    > x   BAT_LOW_THR [11,63] : 0.1500
    > 
    >  901/1794 parameters used.
[2026-10-18T11:17:25.419] CMD (sim t=4.316s): param show BAT_CRIT_THR
    > Symbols: x = used, + = saved, * = unsaved
    > x   BAT_CRIT_THR [9,61] : 0.0700
    > 
    >  901/1794 parameters used.
[2026-10-18T11:17:25.429] CMD (sim t=4.316s): param show BAT_EMERGEN_THR
    > Symbols: x = used, + = saved, * = unsaved
    > x   BAT_EMERGEN_THR [10,62] : 0.0500
    > 
    >  901/1794 parameters used.
[2026-10-18T11:17:25.441] STATUS: timestamp: 4316000 (0.324000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:17:25.448] CMD (sim t=4.316s): commander arm
[2026-10-18T11:17:28.474] STATUS: timestamp: 7340000 (0.212000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:17:28.488] CMD (sim t=7.340s): commander takeoff
[2026-10-18T11:17:28.535] WAIT ok: vehicle_status.nav_state=17 after 0s (sim t=7.604s)
[2026-10-18T11:17:28.548] STATUS: timestamp: 7604000 (0.020000 seconds ago) | arming_state: 2 | nav_state: 17 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:17:34.645] WAIT ok: vehicle_status.nav_state=4 after 6s (sim t=13.316s)
[2026-10-18T11:17:34.658] STATUS: timestamp: 13316000 (0.100000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:17:39.680] STATUS: timestamp: 17852000 (0.328000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: True | 
[2026-10-18T11:17:39.705] FAILSAFE_FLAGS: auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | 
[2026-10-18T11:17:39.715] CMD (sim t=17.852s): param show COM_DISARM_LAND
    > Symbols: x = used, + = saved, * = unsaved
    > x   COM_DISARM_LAND [256,472] : 2.0000
    > 
    >  901/1794 parameters used.
[2026-10-18T11:17:39.731] CMD (sim t=17.852s): param set COM_DISARM_LAND 3.0
    >   COM_DISARM_LAND: curr: 2.0000 -> new: 3.0000
[2026-10-18T11:17:42.752] CMD (sim t=20.252s): param show COM_DISARM_LAND
    > Symbols: x = used, + = saved, * = unsaved
    > x + COM_DISARM_LAND [256,472] : 3.0000
    > 
    >  901/1794 parameters used.
[2026-10-18T11:17:42.764] CMD (sim t=20.252s): failure battery off
    > WARN  [failure] inject failure unit: battery (100), type: off (1), instance: 0
[2026-10-18T11:17:45.796] STATUS: timestamp: 23120000 (0.308000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: True | failsafe_defer_state: 0 | pre_flight_checks_pass: False | 
[2026-10-18T11:17:45.806] FAILSAFE_FLAGS: auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | battery_warning: 2 | 
[2026-10-18T11:17:48.821] STATUS: timestamp: 26144000 (0.268000 seconds ago) | arming_state: 2 | nav_state: 4 | vehicle_type: 1 | failsafe: True | failsafe_defer_state: 0 | pre_flight_checks_pass: False | 
[2026-10-18T11:17:48.830] FAILSAFE_FLAGS: auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | battery_warning: 3 | 
[2026-10-18T11:17:51.840] STATUS: timestamp: 28892000 (0.468000 seconds ago) | arming_state: 2 | nav_state: 18 | vehicle_type: 1 | failsafe: True | failsafe_defer_state: 0 | pre_flight_checks_pass: False | 
[2026-10-18T11:17:51.848] FAILSAFE_FLAGS: auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | battery_warning: 3 | 
[2026-10-18T11:17:51.861] WAIT ok: vehicle_status.failsafe=True after 0s (sim t=28.892s)
[2026-10-18T11:17:51.869] STATUS: timestamp: 28892000 (0.496000 seconds ago) | arming_state: 2 | nav_state: 18 | vehicle_type: 1 | failsafe: True | failsafe_defer_state: 0 | pre_flight_checks_pass: False | 
[2026-10-18T11:17:51.877] FAILSAFE_FLAGS: auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | battery_warning: 3 | 
[2026-10-18T11:18:03.002] WAIT ok: vehicle_status.arming_state=1 after 11s (sim t=39.884s)
[2026-10-18T11:18:03.009] STATUS: timestamp: 39884000 (0.452000 seconds ago) | arming_state: 1 | nav_state: 4 | vehicle_type: 1 | failsafe: False | failsafe_defer_state: 0 | pre_flight_checks_pass: False | 
[2026-10-18T11:18:03.015] FAILSAFE_FLAGS: auto_mission_missing: True | offboard_control_signal_lost: True | manual_control_signal_lost: True | gcs_connection_lost: True | battery_warning: 3 | 
[2026-10-18T11:18:09.028] CMD (sim t=45.932s): logger status
    > INFO  [logger] Running in mode: all
    > INFO  [logger] Number of subscriptions: 170 (5440 bytes)
    > INFO  [logger] Not logging
[2026-10-18T11:18:09.049] CMD (sim t=45.932s): shutdown
[2026-10-18T11:18:09.064] px4 exit=0
[2026-10-18T11:18:09.094] COPIED /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/fs_bat_rootfs/log/2026-10-18/11_17_20.ulg -> /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/failsafe_battery_empty.ulg (9208891 bytes)
[2026-10-18T11:18:09.105] host load at end: 3.30 2.30 1.30 7/170 22742
[2026-10-18T11:18:09.113] DONE
```

</details>

<details><summary>px4 stdout and stderr failsafe_battery_empty.px4.log</summary>

```

______  __   __    ___ 
| ___ \ \ \ / /   /   |
| |_/ /  \ V /   / /| |
|  __/   /   \  / /_| |
| |     / /^\ \ \___  |
\_|     \/   \/     |_/

px4 starting.

INFO  [px4] startup script: /bin/sh etc/init.d-posix/rcS 0
INFO  [init] found model autostart file as SYS_AUTOSTART=10040
INFO  [param] selected parameter default file parameters.bson
INFO  [param] selected parameter backup file parameters_backup.bson
  SYS_AUTOCONFIG: curr: 0 -> new: 1
  SYS_AUTOSTART: curr: 0 -> new: 10040
  CAL_ACC0_ID: curr: 0 -> new: 1310988
  CAL_GYRO0_ID: curr: 0 -> new: 1310988
  CAL_ACC1_ID: curr: 0 -> new: 1310996
  CAL_GYRO1_ID: curr: 0 -> new: 1310996
  CAL_ACC2_ID: curr: 0 -> new: 1311004
  CAL_GYRO2_ID: curr: 0 -> new: 1311004
  CAL_MAG0_ID: curr: 0 -> new: 197388
  CAL_MAG0_PRIO: curr: -1 -> new: 50
  CAL_MAG1_ID: curr: 0 -> new: 197644
  CAL_MAG1_PRIO: curr: -1 -> new: 50
  SENS_BOARD_X_OFF: curr: 0.0000 -> new: 0.0000
  SENS_DPRES_OFF: curr: 0.0000 -> new: 0.0010
INFO  [dataman] data manager file './dataman' size is 1208528 bytes
INFO  [init] SIH simulator
INFO  [simulator_sih] Simulation loop with 250 Hz (4000 us sim time interval)
INFO  [simulator_sih] Simulation with 1.0x speedup. Loop with (4000 us wall time interval)
INFO  [lockstep_scheduler] setting initial absolute time to 4000 us
INFO  [commander] LED: open /dev/led0 failed (22)
INFO  [tone_alarm] home set
INFO  [uxrce_dds_client] init UDP agent IP:127.0.0.1, port:8888
INFO  [mavlink] mode: Normal, data rate: 4000000 B/s on udp port 18570 remote port 14550
INFO  [mavlink] mode: Onboard, data rate: 4000000 B/s on udp port 14580 remote port 14540
INFO  [mavlink] mode: Onboard, data rate: 4000 B/s on udp port 14280 remote port 14030
INFO  [mavlink] mode: Gimbal, data rate: 400000 B/s on udp port 13030 remote port 13280
INFO  [mavlink] mode: Custom, data rate: 400000 B/s on udp port 19450 remote port 19410
INFO  [logger] logger started (mode=all)
INFO  [logger] Start file log (type: full)
INFO  [logger] [logger] ./log/2026-10-18/11_17_20.ulg	
INFO  [logger] Opened full log file: ./log/2026-10-18/11_17_20.ulg
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [px4] Startup script returned successfully
INFO  [commander] <ESC>[32mReady for takeoff!<ESC>[0m
INFO  [commander] Armed by internal command	
INFO  [tone_alarm] arming warning
INFO  [navigator] Using default takeoff altitude: 2.5 m	
INFO  [commander] Takeoff detected	
WARN  [battery_simulator] CMD_INJECT_FAILURE, battery empty
WARN  [health_and_arming_checks] Low battery	
INFO  [tone_alarm] battery warning (slow)
WARN  [failsafe] Failsafe activated: entering Hold for 5 seconds	
INFO  [tone_alarm] battery warning (fast)
WARN  [commander] System does not support shutdown	
ERROR [health_and_arming_checks] Emergency battery level	
WARN  [failsafe] Failsafe activated	
INFO  [commander] Landing detected	
INFO  [commander] Disarmed by landing	
INFO  [tone_alarm] notify neutral
INFO  [logger] closed logfile, bytes written: 9208891
ERROR [health_and_arming_checks] Emergency battery level	
Exiting NOW.
```

</details>

<details><summary>script failsafe_battery_empty.sh</summary>

```bash
#!/bin/bash
# failsafe_battery_empty.sh <rootfs_dir> <scenario_name>
# Scenario E (battery): SIH quadx, arm, takeoff, loiter, `failure battery off` (BatterySimulator handles it:
# battery reported empty -> battery_warning EMERGENCY -> COM_LOW_BAT_ACT 3 = Land). Also one real in-flight param change
# (COM_DISARM_LAND 2 -> 3 s) to show how PARAM_CHANGED_IN_FLIGHT appears. Fresh rootfs.
set -u
PX4_DIR=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.17.0
BIN=$PX4_DIR/build/px4_sitl_default/bin
ETC=$PX4_DIR/build/px4_sitl_default/etc
OUT=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0
ROOTFS=${1:?rootfs}; SCENARIO=${2:?scenario}
MODEL=sihsim_quadx
rm -rf "$ROOTFS"; mkdir -p "$ROOTFS" "$OUT"; cd "$ROOTFS"
PX4LOG=$OUT/$SCENARIO.px4.log; CMDLOG=$OUT/$SCENARIO.cmd.log; : > "$CMDLOG"
ts() { date -u +%Y-%m-%dT%H:%M:%S.%3N; }
say() { echo "[$(ts)] $*" | tee -a "$CMDLOG"; }
simt() { "$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +timestamp:/{printf "%.3f", $2/1e6}'; }
vs() { say "STATUS: $("$BIN/px4-listener" vehicle_status 2>/dev/null | awk '/^ +(timestamp|arming_state|nav_state|failsafe|failsafe_defer_state|vehicle_type|pre_flight_checks_pass):/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
ff() { say "FAILSAFE_FLAGS: $("$BIN/px4-listener" failsafe_flags 2>/dev/null | awk '/^ +[a-z_]+: (True|[1-9])/ && !/mode_req_/ && !/timestamp/{gsub(/^ +/,""); printf "%s | ", $0}')"; }
cmd() { say "CMD (sim t=$(simt)s): $*"; "$BIN/px4-$1" "${@:2}" 2>&1 | sed 's/^/    > /' | tee -a "$CMDLOG"; }
wait_for() { # topic field value timeout_s
  local tp=$1 f=$2 v=$3 to=$4 i=0 cur=
  while [ $i -lt "$to" ]; do
    cur=$("$BIN/px4-listener" "$tp" 2>/dev/null | awk -v f="$f" '$1==f":"{print $2}')
    if [ "$cur" = "$v" ]; then say "WAIT ok: $tp.$f=$v after ${i}s (sim t=$(simt)s)"; return 0; fi
    sleep 1; i=$((i+1))
  done
  say "WAIT TIMEOUT: $tp.$f=$cur (wanted $v) after ${to}s (sim t=$(simt)s)"; return 1
}
say "SCENARIO $SCENARIO  rootfs=$ROOTFS  PX4 $(cd $PX4_DIR && git describe --tags --always) $(cd $PX4_DIR && git rev-parse HEAD)"
say "host load at start: $(cat /proc/loadavg)  ns: /tmp=$(ls -A /tmp | tr '\n' ' ')"
touch .start_marker
say "START px4: cd $ROOTFS && PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim $BIN/px4 -d $ETC > $PX4LOG 2>&1 &"
PX4_SIM_MODEL=$MODEL PX4_SIMULATOR=sihsim "$BIN/px4" -d "$ETC" > "$PX4LOG" 2>&1 &
PX4_PID=$!
sleep 3
wait_for vehicle_status pre_flight_checks_pass True 150
wait_for home_position valid_hpos True 60
cmd param show SYS_FAILURE_EN; cmd param show COM_LOW_BAT_ACT; cmd param show SIM_BAT_ENABLE; cmd param show BAT_LOW_THR; cmd param show BAT_CRIT_THR; cmd param show BAT_EMERGEN_THR
vs
cmd commander arm
sleep 3; vs
cmd commander takeoff
wait_for vehicle_status nav_state 17 10; vs
wait_for vehicle_status nav_state 4 90; vs
sleep 5; vs; ff
cmd param show COM_DISARM_LAND
cmd param set COM_DISARM_LAND 3.0
sleep 3
cmd param show COM_DISARM_LAND
cmd failure battery off
for i in 1 2 3; do sleep 3; vs; ff; done
wait_for vehicle_status failsafe True 30; vs; ff
wait_for vehicle_status arming_state 1 240; vs; ff
sleep 6
cmd logger status
cmd shutdown
wait $PX4_PID; say "px4 exit=$?"
ULG=$(find log -name '*.ulg' -newer .start_marker | sort | tail -1)
cp "$ULG" "$OUT/$SCENARIO.ulg"; cp "$0" "$OUT/$SCENARIO.sh"
say "COPIED $ROOTFS/$ULG -> $OUT/$SCENARIO.ulg ($(stat -c %s "$OUT/$SCENARIO.ulg") bytes)"
say "host load at end: $(cat /proc/loadavg)"
say "DONE"
```

</details>

### 3. Item 5: volatile parameters (mc_flight_1 versus mc_flight_2)

Same binary, same airframe, same working directory (`parameters.bson` persisted), same command script, no `param set` in either run. Compared with pyulog (`tools/param_diff.py`) and with `ulog_params -i` (raw diff below; plain `ulog_params` appends in-log changes as extra comma-separated values, so `-i` is the clean comparison).

| parameter | mc_flight_1 (first boot) | mc_flight_2 (second boot) | why it differs (source) |
|---|---|---|---|
| `COM_FLIGHT_UUID` | 0 | 1 | incremented at every disarm, saved with `commit_no_notification` (`Commander.cpp` lines 684 to 688); per-flight identifier |
| `LND_FLIGHT_T_LO` | 0 | 29256000 | total flight time accumulator in microseconds, written at disarm (`LandDetector.cpp` lines 185 to 199); `LND_FLIGHT_T_HI` would change after 4295 s of total flight |
| `EKF2_MAG_DECL` | 0.0 | 3.4056053161621094 | magnetic declination learned by EKF2 and saved once per boot (`EKF2.cpp` lines 2750 to 2763) |
| `CAL_BARO0_OFF` | 0.0 | 7.32421875 | baro offset auto-calibrated against GNSS height about 5 s after every boot, `SENS_BAR_AUTOCAL` default 1 (`VehicleAirData.cpp` lines 257 to 262, `BaroGNSSAltitudeOffset`); it also changes during each log (mc_flight_1: 0.0 to 7.32 at 5.816 s, mc_flight_2: 7.32 to -12.21 at 5.408 s) |
| `CAL_BARO1_ID`, `CAL_BARO2_ID`, `CAL_BARO3_ID` | present (0) | ABSENT from the log | ULog stores only parameters marked used; on the first boot autoconfig touches them, on the second boot nothing does. Parameter count 901 versus 898 (`param show` also printed 901/1794 versus 898/1794 used) |

No other initial value differs. Candidate parameters checked and NOT differing in this pair: `LND_FLIGHT_T_HI` (0 in both), `SYS_AUTOCONFIG`, `SYS_AUTOSTART`, all `CAL_ACC*`, `CAL_GYRO*`, `CAL_MAG*` ids and offsets, `SENS_BOARD_X_OFF`, `SENS_DPRES_OFF`, `MAV_SYS_ID`. Source code also writes, at runtime and without notification, `EKF2_MULTI_IMU`, `EKF2_MULT_MAG`, `EKF2_DELAY_MAX`, `EKF2_FUSE_BETA`, `IMU_GYRO_RATEMAX`, `IMU_INTEG_RATE`, `LNDMC_Z_VEL_MAX`, mode-hash parameters (`ModeManagement.cpp`) and `CAL_*` offsets via in-flight mag and gyro calibration (`sensor_calibration/Utilities.cpp`); none of these changed in this pair, but they are further candidates on other setups.

**ULog header info fields**: `ver_sw` (git hash), `ver_sw_release` (17891583), `ver_hw` (`PX4_SITL`), `ver_vendor_sw_release` (255), `sys_name` (`PX4`), `sys_os_name` (`Linux`), `sys_os_ver_release` (101854463 = 0x06122CFF, the HOST kernel 6.18.44 in SITL, so host-dependent), `sys_toolchain` (`GNU GCC`), `sys_toolchain_ver` (`13.3.0`), `ver_data_format` (2), `time_ref_utc` (0), `metadata_events_sha256`, `boot_time_utc_us`. Absent in these logs: `ver_sw_branch`, `sys_uuid`, `ver_hw_subtype`, `sys_mcu`, `ver_oem`, `replay`. **Only `boot_time_utc_us` differs** between the two logs. In the info-multiple messages `excluded_optional_topics` and `metadata_events` are identical, while `perf_counter_preflight` and `perf_counter_postflight` (runtime perf counter text) differ. Default-parameter (Q) messages are identical: 54 system defaults, 14 current-setup defaults.

<details><summary>param_diff.py mc_flight_1.ulg mc_flight_2.ulg (full output)</summary>

```
initial parameter count: A=901 B=898
keys only in A: ['CAL_BARO1_ID', 'CAL_BARO2_ID', 'CAL_BARO3_ID']
keys only in B: []

INITIAL value differences (A -> B):
  CAL_BARO0_OFF        A=0.0  B=7.32421875
  COM_FLIGHT_UUID      A=0  B=1
  EKF2_MAG_DECL        A=0.0  B=3.4056053161621094
  LND_FLIGHT_T_LO      A=0  B=29256000

CHANGED_PARAMETERS in A (20), armed intervals [(4.424, 37.436)]:
  t=   0.992s disarmed  CAL_ACC0_ID          1310988 -> 1310988   (same value re-logged)
  t=   0.992s disarmed  CAL_ACC1_ID          1310996 -> 1310996   (same value re-logged)
  t=   0.992s disarmed  CAL_ACC2_ID          1311004 -> 1311004   (same value re-logged)
  t=   0.992s disarmed  CAL_BARO0_ID         6620172 -> 6620172   (same value re-logged)
  t=   0.992s disarmed  CAL_BARO0_OFF        0.0 -> 0.0   (same value re-logged)
  t=   0.992s disarmed  CAL_BARO0_PRIO       50 -> 50   (same value re-logged)
  t=   0.992s disarmed  CAL_GYRO0_ID         1310988 -> 1310988   (same value re-logged)
  t=   0.992s disarmed  CAL_GYRO1_ID         1310996 -> 1310996   (same value re-logged)
  t=   0.992s disarmed  CAL_GYRO2_ID         1311004 -> 1311004   (same value re-logged)
  t=   0.992s disarmed  CAL_MAG0_ID          197388 -> 197388   (same value re-logged)
  t=   0.992s disarmed  CAL_MAG0_PRIO        50 -> 50   (same value re-logged)
  t=   0.992s disarmed  CAL_MAG1_ID          197644 -> 197644   (same value re-logged)
  t=   0.992s disarmed  CAL_MAG1_PRIO        50 -> 50   (same value re-logged)
  t=   0.992s disarmed  SENS_BOARD_X_OFF     9.999999974752427e-07 -> 9.999999974752427e-07   (same value re-logged)
  t=   0.992s disarmed  SENS_DPRES_OFF       0.0010000000474974513 -> 0.0010000000474974513   (same value re-logged)
  t=   0.992s disarmed  SYS_AUTOCONFIG       0 -> 0   (same value re-logged)
  t=   0.992s disarmed  SYS_AUTOSTART        10040 -> 10040   (same value re-logged)
  t=   5.816s ARMED     CAL_BARO0_ID         6620172 -> 6620172   (same value re-logged)
  t=   5.816s ARMED     CAL_BARO0_OFF        0.0 -> 7.32421875
  t=   5.816s ARMED     CAL_BARO0_PRIO       50 -> 50   (same value re-logged)

CHANGED_PARAMETERS in B (3), armed intervals [(4.768, 42.472)]:
  t=   5.408s ARMED     CAL_BARO0_ID         6620172 -> 6620172   (same value re-logged)
  t=   5.408s ARMED     CAL_BARO0_OFF        7.32421875 -> -12.20703125
  t=   5.408s ARMED     CAL_BARO0_PRIO       50 -> 50   (same value re-logged)

END-OF-LOG A vs INITIAL B (what persisted into parameters.bson and was loaded at next boot):
  CAL_BARO1_ID         A_end=0  B_init='<absent>'
  CAL_BARO2_ID         A_end=0  B_init='<absent>'
  CAL_BARO3_ID         A_end=0  B_init='<absent>'
  COM_FLIGHT_UUID      A_end=0  B_init=1
  EKF2_MAG_DECL        A_end=0.0  B_init=3.4056053161621094
  LND_FLIGHT_T_LO      A_end=0  B_init=29256000

INFO fields:
  boot_time_utc_us         DIFFER A=1792321870537686 B=1792321949133369
  metadata_events_sha256   SAME   A='3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d' B='3e07d215b9591c01d9014acff13d780e310b058438b0d7f0423b23bc9fc1f59d'
  sys_name                 SAME   A='PX4' B='PX4'
  sys_os_name              SAME   A='Linux' B='Linux'
  sys_os_ver_release       SAME   A=101854463 B=101854463
  sys_toolchain            SAME   A='GNU GCC' B='GNU GCC'
  sys_toolchain_ver        SAME   A='13.3.0' B='13.3.0'
  time_ref_utc             SAME   A=0 B=0
  ver_data_format          SAME   A=2 B=2
  ver_hw                   SAME   A='PX4_SITL' B='PX4_SITL'
  ver_sw                   SAME   A='d6f12ad1c4f70ad3230afd7d86e971421e02fef4' B='d6f12ad1c4f70ad3230afd7d86e971421e02fef4'
  ver_sw_release           SAME   A=17891583 B=17891583
  ver_vendor_sw_release    SAME   A=255 B=255

INFO multiple:
  excluded_optional_topics   SAME
  metadata_events            SAME
  perf_counter_postflight    DIFFER (A 1 items, B 1 items)
  perf_counter_preflight     DIFFER (A 1 items, B 1 items)
  excluded_optional_topics A-B: []  B-A: []

DEFAULT parameters (ULog Q messages): A has 1, B has 1
  system defaults count A=54 B=54, differing: []
  current-setup defaults count A=14 B=14, differing: []

ULog header: A start=992000 B start=388000 ; A dropouts=0 B dropouts=0
```

</details>

<details><summary>diff of `ulog_params -i` outputs (mc_flight_1 < , mc_flight_2 >)</summary>

```diff
45c45
< CAL_BARO0_OFF,0.0
---
> CAL_BARO0_OFF,7.32421875
47,49d46
< CAL_BARO1_ID,0
< CAL_BARO2_ID,0
< CAL_BARO3_ID,0
263c260
< COM_FLIGHT_UUID,0
---
> COM_FLIGHT_UUID,1
390c387
< EKF2_MAG_DECL,0.0
---
> EKF2_MAG_DECL,3.4056053161621094
507c504
< LND_FLIGHT_T_LO,0
---
> LND_FLIGHT_T_LO,29256000
```

</details>

### 4. Item 6: VTOL transition semantics (flight evidence)

Merged timeline of every transition-related field change (`tools/vtol_timeline.py`).

<details><summary>vtol_transition.ulg timeline</summary>

```
t=    0.100s  vtol_vehicle_status.fixed_wing_system_failure 0
t=    0.100s  vtol_vehicle_status.vehicle_vtol_state       MC
t=    0.116s  vehicle_status.arming_state                  DISARMED
t=    0.116s  vehicle_status.in_transition_mode            0
t=    0.116s  vehicle_status.in_transition_to_fw           0
t=    0.116s  vehicle_status.nav_state                     AUTO_LOITER
t=    0.116s  vehicle_status.vehicle_type                  ROTARY_WING
t=    4.676s  vehicle_status.arming_state                  ARMED
t=    7.652s  vehicle_command                              cmd=22 p1=nan p2=nan
t=    7.664s  vehicle_command_ack                          cmd=22 result=0
t=    7.676s  vehicle_status.nav_state                     AUTO_TAKEOFF
t=   22.244s  vehicle_status.nav_state                     AUTO_LOITER
t=   27.484s  vehicle_command                              cmd=3000 p1=4 p2=0
t=   27.488s  vtol_vehicle_status.vehicle_vtol_state       TRANSITION_TO_FW
t=   27.500s  vehicle_status.in_transition_mode            1
t=   27.500s  vehicle_status.in_transition_to_fw           1
t=   30.504s  vtol_vehicle_status.vehicle_vtol_state       FW
t=   30.512s  vehicle_status.in_transition_mode            0
t=   30.512s  vehicle_status.in_transition_to_fw           0
t=   30.512s  vehicle_status.vehicle_type                  FIXED_WING
t=   56.156s  vehicle_command                              cmd=3000 p1=3 p2=0
t=   56.160s  vtol_vehicle_status.vehicle_vtol_state       TRANSITION_TO_MC
t=   56.172s  vehicle_status.in_transition_mode            1
t=   56.172s  vehicle_status.vehicle_type                  ROTARY_WING
t=   56.760s  vtol_vehicle_status.vehicle_vtol_state       MC
t=   56.772s  vehicle_status.in_transition_mode            0
t=   62.144s  vehicle_command                              cmd=21 p1=nan p2=nan
t=   62.148s  vehicle_command_ack                          cmd=21 result=0
t=   62.160s  vehicle_status.nav_state                     AUTO_LAND
t=   88.272s  vehicle_status.arming_state                  DISARMED
t=   88.272s  vehicle_status.nav_state                     AUTO_LOITER

vtol_vehicle_status: 92 msgs, publish interval min=0.016s median=1.000s max=1.000s (1 Hz heartbeat + immediate on change)
airspeed_validated present: True
```

</details>

<details><summary>vtol_transition_abort.ulg timeline</summary>

```
t=    0.132s  vtol_vehicle_status.fixed_wing_system_failure 0
t=    0.132s  vtol_vehicle_status.vehicle_vtol_state       MC
t=    0.152s  vehicle_status.arming_state                  DISARMED
t=    0.152s  vehicle_status.in_transition_mode            0
t=    0.152s  vehicle_status.in_transition_to_fw           0
t=    0.152s  vehicle_status.nav_state                     AUTO_LOITER
t=    0.152s  vehicle_status.vehicle_type                  ROTARY_WING
t=    5.488s  vehicle_status.arming_state                  ARMED
t=    8.372s  vehicle_command                              cmd=22 p1=nan p2=nan
t=    8.380s  vehicle_command_ack                          cmd=22 result=0
t=    8.392s  vehicle_status.nav_state                     AUTO_TAKEOFF
t=   23.164s  vehicle_status.nav_state                     AUTO_LOITER
t=   28.180s  vehicle_command                              cmd=3000 p1=4 p2=0
t=   28.184s  vtol_vehicle_status.vehicle_vtol_state       TRANSITION_TO_FW
t=   28.192s  vehicle_status.in_transition_mode            1
t=   28.192s  vehicle_status.in_transition_to_fw           1
t=   29.000s  vehicle_command                              cmd=176 p1=1 p2=4
t=   29.008s  vehicle_command_ack                          cmd=176 result=0
t=   29.020s  vehicle_status.nav_state                     AUTO_RTL
t=   29.024s  vtol_vehicle_status.vehicle_vtol_state       MC
t=   29.032s  vehicle_status.in_transition_mode            0
t=   29.032s  vehicle_status.in_transition_to_fw           0
t=   56.128s  vehicle_status.arming_state                  DISARMED
t=   56.128s  vehicle_status.nav_state                     AUTO_LOITER

vtol_vehicle_status: 59 msgs, publish interval min=0.052s median=1.000s max=1.004s (1 Hz heartbeat + immediate on change)
airspeed_validated present: True
```

</details>

`vtol_vehicle_status.vehicle_vtol_state` values (msg/versioned/VtolVehicleStatus.msg): 0 UNDEFINED, 1 TRANSITION_TO_FW, 2 TRANSITION_TO_MC, 3 MC, 4 FW. `vtol_att_control` publishes immediately on a state or `fixed_wing_system_failure` change and otherwise at 1 Hz (`vtol_att_control_main.cpp` lines 457 to 466; observed median interval 1.000 s). Commander copies it into `vehicle_status` on its next cycle (`Commander.cpp` lines 2182 to 2213): `vehicle_type` FIXED_WING only when the VTOL state is 4, otherwise ROTARY_WING; `in_transition_mode` true for states 1 and 2; `in_transition_to_fw` true only for state 1.

Observed sequence in `vtol_transition.ulg`:

| t (s) | vtol_vehicle_status.vehicle_vtol_state | vehicle_status (in_transition_mode, in_transition_to_fw, vehicle_type) | meaning |
|---|---|---|---|
| 0.100 / 0.116 | 3 MC | 0, 0, ROTARY_WING | initial |
| 27.484 | | | `vehicle_command` 3000 DO_VTOL_TRANSITION param1 4 (to FW), no ack |
| 27.488 / 27.500 | 1 TRANSITION_TO_FW | 1, 1, ROTARY_WING | front transition START |
| 30.504 / 30.512 | 4 FW | 0, 0, FIXED_WING | front transition END (3.016 s) |
| 56.156 | | | `vehicle_command` 3000 param1 3 (to MC), no ack |
| 56.160 / 56.172 | 2 TRANSITION_TO_MC | 1, 0, ROTARY_WING | back transition START (vehicle_type is already ROTARY_WING) |
| 56.760 / 56.772 | 3 MC | 0, 0, ROTARY_WING | back transition END (0.600 s) |

Observed sequence in `vtol_transition_abort.ulg`: 28.180 command 3000 param1 4; 28.184 / 28.192 state 1, vehicle_status (1, 1, ROTARY_WING) = START; 29.000 `DO_SET_MODE` to AUTO_RTL, ack 0 at 29.008; 29.020 nav_state AUTO_RTL; 29.024 / 29.032 state 3 MC, vehicle_status (0, 0, ROTARY_WING) = ABORT. State 4 never appears.

**Precise observable definitions for these v1.17.0 logs** (use `vtol_vehicle_status.vehicle_vtol_state` as the primary source; `vehicle_status` gives the same edges 8 to 12 ms later and is the fallback):

- **VTOL_TRANSITION_START (direction to FW)**: vehicle_vtol_state changes to 1 from any other value (seen from 3). Equivalent: `vehicle_status.in_transition_mode` false to true with `in_transition_to_fw` true.
- **VTOL_TRANSITION_START (direction to MC)**: vehicle_vtol_state changes to 2 (seen from 4). Equivalent: `in_transition_mode` false to true with `in_transition_to_fw` false; `vehicle_type` turns ROTARY_WING at the START of the back transition, not at its end.
- **VTOL_TRANSITION_END**: an open transition to FW (state 1) is followed by state 4 (FW); an open transition to MC (state 2) is followed by state 3 (MC). Equivalent: `in_transition_mode` true to false with `vehicle_type` FIXED_WING (to FW) or ROTARY_WING (to MC).
- **VTOL_TRANSITION_ABORT**: an open transition to FW (state 1) is followed by state 3 (MC) without passing through 4 (observed). From the code, also: state 1 followed by 3 with `fixed_wing_system_failure` becoming true (quad-chute, including `VT_TRANS_TIMEOUT` expiry, `vtol_type.cpp` lines 327 to 370 and `standard.cpp` lines 74 to 77), and state 2 followed by 1 (back transition reversed into a front transition, `standard.cpp` lines 120 to 126; not observed). With `vehicle_status` alone, an abort to MC looks like `in_transition_mode` true to false while `vehicle_type` stays ROTARY_WING after a to-FW transition, which a parser can distinguish from a completed to-MC transition only by remembering `in_transition_to_fw` at the start.
- `vtol_vehicle_status` is absent in non-VTOL logs (no format, no data); `vehicle_status.is_vtol` is false there and true in both VTOL logs (and `MAV_TYPE` is 2 versus 22), which is a reliable N/A test for R6.

### 5. In-flight parameter changes and dropouts

- **Dropouts**: none in any of the six logs (`ulog_info`: `No Dropouts`; pyulog `dropouts` empty). Nothing here exercises LOG_DROPOUT.
- **A real in-flight change**: `failsafe_battery_empty.ulg` has `COM_DISARM_LAND` 2.0 to 3.0 at 18.232 s (armed since 4.664 s, airborne since 8.468 s). pyulog returns it in `ULog.changed_parameters` as `(18232000, 'COM_DISARM_LAND', 3.0)`; `ulog_params` (default mode) prints it as `COM_DISARM_LAND,2.0,3.0`; the initial value is in `ULog.initial_parameters`. In the file it is a ULog parameter message (P) in the data section, timestamped by the next data message.
- **A same-value `param set`** (`param set SYS_FAILURE_EN 1` in failsafe_gps_loss at 17.70 s, value already 1) leaves no record.
- **Parameter messages PX4 writes itself after log start** (in every log, not pilot changes): (a) first-boot logs (fresh rootfs: mc_flight_1, both VTOL logs, both failsafe logs) re-log the autoconfig parameters with UNCHANGED values right after log start (mc_flight_1: 17 entries at 0.992 s: `CAL_ACC0..2_ID`, `CAL_GYRO0..2_ID`, `CAL_MAG0..1_ID/PRIO`, `CAL_BARO0_ID/OFF/PRIO`, `SENS_BOARD_X_OFF`, `SENS_DPRES_OFF`, `SYS_AUTOCONFIG`, `SYS_AUTOSTART`); (b) every log re-logs `CAL_BARO0_ID` and `CAL_BARO0_PRIO` unchanged together with a new `CAL_BARO0_OFF` 5.3 to 5.8 s after boot (`SENS_BAR_AUTOCAL`). In five of the six logs (b) fell inside the armed interval but before takeoff (landed), because the scripts armed 3.9 to 4.8 s after boot; in vtol_transition_abort arming came at 5.488 s, just after the calibration at 5.412 s. The SFR extractor therefore needs (1) old to new comparison so that same-value re-logs are dropped, and (2) a definition of "in flight" (armed versus in air from `vehicle_land_detected.landed`), and the volatile ignore list should include `CAL_BARO*_OFF` while `SENS_BAR_AUTOCAL` is 1.
- Parameters saved with `commit_no_notification` (`COM_FLIGHT_UUID`, `LND_FLIGHT_T_*`, `EKF2_MAG_DECL`) are never logged as changes; they only show up in the next boot's initial set (item 5).

### 6. Other observations relevant to SPEC B1.5 and B1.6

- **COMMAND without ack**: in these logs `vehicle_command_ack` is missing for `DO_VTOL_TRANSITION` (3000; `vtol_att_control` acks only when `from_external` is true, `vtol_att_control_main.cpp` lines 171 to 181), `DO_GIMBAL_MANAGER_CONFIGURE` (1001) and `DO_GIMBAL_MANAGER_PITCHYAW` (1000), which navigator publishes at RTL and LAND entry (`navigator_main.cpp` lines 1548 to 1651), and `INJECT_FAILURE` for gps under SIH (no handler). Acked: 211, 400, 22, 176, 21, 420 (battery). So `NO_ACK` is a normal outcome for internal commands. Two acks can exist for one command (211: IN_PROGRESS 5, then ACCEPTED 0).
- **Garbage source fields**: the boot-time `DO_GRIPPER` (211) command from `payload_deliverer` is built from an uninitialized `vehicle_command_s vcmd;` (`payload_deliverer.cpp` line 239), so its `source_system`, `source_component`, `target_*`, `param1` and `param3` are random and differ between runs (191/46144, 51/37952, 17/13376, 72/37952, ...). `INJECT_FAILURE` from the `failure` tool has source and target 0/0. Shell `commander` commands have source 1/1, `from_external` false.
- **`commander takeoff` sends two commands**: `NAV_TAKEOFF` (22), then `COMPONENT_ARM_DISARM` (400) even when already armed; both are acked 0.
- **failsafe_flags in headless SITL** (relevant to R4): `manual_control_signal_lost`, `gcs_connection_lost`, `offboard_control_signal_lost` and `auto_mission_missing` are true for the whole log in every scenario, yet `vehicle_status.failsafe` stays false (no failsafe action is configured for them in these modes). Position, velocity and attitude invalid flags are true at boot until the EKF converges (about 1 to 4 s, disarmed). `mode_req_*` fields are uint32 bitmasks, and `battery_warning` is a uint8 level. A rule that fires on any true boolean in `failsafe_flags` would FAIL every one of these logs; `vehicle_status.failsafe` (and `failsafe_and_user_took_over`) is the clean signal, with the specific `failsafe_flags` fields as the cause.
- **Arm and disarm**: every log has exactly one ARM and one DISARM, and with SDLOG_MODE 1 the log ends 0.996 to 1.000 s after DISARM. `latest_arming_reason` is 3 and `latest_disarming_reason` is 6 in every log, while px4 printed `Disarmed by landing`. **Enum mismatch**: Commander writes these fields by casting the generated events enum `arm_disarm_reason_t` (`Commander.cpp` lines 623 and 668; `build/px4_sitl_default/events/events_generated.h` line 158: 3 `command_internal`, 6 `auto_disarm_land`, 7 `auto_disarm_preflight`, 8 `kill_switch`, ... 14 `failsafe`), but the constants in `msg/versioned/VehicleStatus.msg` lines 16 to 29 differ from value 6 upward (6 `SAFETY_BUTTON`, 7 `AUTO_DISARM_LAND`, 8 `AUTO_DISARM_PREFLIGHT`, ...). A decoder that labels reasons from the `.msg` constants mislabels disarm-by-landing as safety button; use the events enum. On disarm, nav_state reverts to AUTO_LOITER in the same `vehicle_status` message, so a NAV_STATE_CHANGE coincides with every DISARM.
- **Vehicle type sources**: `MAV_TYPE` parameter (2 quadrotor, 22 VTOL), `vehicle_status.vehicle_type` (changes during VTOL flight), `vehicle_status.is_vtol`.
- **Determinism**: two flights with identical commands produce different file sizes and contents (sensor noise, wall-clock-dependent command timing, random gripper fields, `boot_time_utc_us`), so golden-log tests must pin the exact file bytes (SHA-256 above), not regenerate logs.

### 7. Files

- Logs: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/{mc_flight_1,mc_flight_2,vtol_transition,vtol_transition_abort,failsafe_gps_loss,failsafe_battery_empty}.ulg`
- Per log: `.sh` (script as run), `.cmd.log` (commands, waits and listener status with UTC times), `.px4.log` (px4 stdout and stderr), `.ulog_info.txt`, `.ulog_messages.txt`, `.analysis.txt`; mc logs also `.params.txt`, `.params_initial.txt`, `.params_changed_t.txt`; VTOL logs `.item6_timeline.txt`; `item5_param_diff.txt`, `item5_ulog_params_initial.diff`.
- Tools: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/tools/{nsrun.sh,analyze_ulog.py,param_diff.py,vtol_timeline.py}`; report generator `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/make_report.py`.
- Superseded first B1 attempt: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.17.0/superseded/mc_flight_1_attempt1.{ulg,cmd.log,px4.log,sh}`.
- Run working directories (rootfs with parameters.bson, dataman, log/): `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_runs/v1.17.0/{mc_rootfs,vtol_rootfs,vtol_abort_rootfs,fs_gps_rootfs,fs_bat_rootfs}`.

<details><summary>tools/nsrun.sh</summary>

```bash
#!/bin/bash
# nsrun.sh <scenario script> [args...]
# Runs one PX4 SITL scenario in a private mount + network namespace. PX4 posix hard-codes the
# daemon socket /tmp/px4-sock-<instance> and lock /tmp/px4_lock-<instance>, and instance 0 binds
# UDP 18570/14580/14280/13030/19450. Another agent flies a different PX4 tree on the same host,
# so this keeps instance 0 (MAV_SYS_ID 1, default config) without any collision:
# a private tmpfs on /tmp (with only /tmp/claude-0 bound back in) and a private loopback.
exec unshare -m -n --propagation private bash -c '
set -e
mkdir -p /run/sfr_v117_origtmp
mount --bind /tmp /run/sfr_v117_origtmp
mount -t tmpfs tmpfs /tmp
mkdir -p /tmp/claude-0
mount --bind /run/sfr_v117_origtmp/claude-0 /tmp/claude-0
python3 -I -c "
import socket, fcntl, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
name = b\"lo\".ljust(16, b\"\\0\")
flags = struct.unpack(\"H\", fcntl.ioctl(s, 0x8913, name + b\"\\0\" * 24)[16:18])[0]
fcntl.ioctl(s, 0x8914, name + struct.pack(\"H\", flags | 1) + b\"\\0\" * 22)
s.sendto(b\"x\", (\"127.0.0.1\", 9))
print(\"nsrun: private /tmp and loopback up\")
"
exec "$@"
' nsrun "$@"
```

</details>


### 3.2 PX4 v1.14.4 log (3d, oldest supported schema)

Diagnostic item 3 part d. Evidence only. Nothing under `/home/user/Sealed_Flight_Recorder-` was modified. No third-party logs were used: the log below was produced on this machine from a PX4 v1.14.4 source build.

Context from `docs/SPEC.md` B1.5: the record needs log identity (hashes, size, firmware version and git hash from the ULog header, vehicle type), the parameter set at log start, and a timeline of ARM, DISARM, NAV_STATE_CHANGE, FAILSAFE_SET/CLEAR (from `failsafe_flags`), COMMAND (with matching `vehicle_command_ack` or NO_ACK), VTOL_TRANSITION_*, PARAM_CHANGED_IN_FLIGHT, LOG_MESSAGE (warning or above) and LOG_DROPOUT, with boot-time microseconds and UTC when GPS time is available.

### 1. Result at a glance

| Item | Value |
|---|---|
| PX4 tag | `v1.14.4` (`git describe --tags --always`) |
| PX4 commit | `1555f2bd2229544c43966ab5f94879c41d8e1e01` (`git rev-parse HEAD`) |
| Tree state | tag checkout plus two local build patches (section 3); NuttX submodule tags fetched |
| Build | `px4_sitl_default`, GCC 13.3.0, CMake 3.28.3, Python 3.13.16 |
| Airframe | `10040_sihsim_quadx` (SYS_AUTOSTART 10040), SIH simulator built into px4, SIH_VEHICLE_TYPE 0 (quadcopter) |
| Instance | 3 (MAV_SYS_ID 4), chosen so it cannot collide with the v1.17.0 SITL on instance 0 |
| Scenario | boot, arm, takeoff, hover, mode auto:rtl, mode auto:loiter, hover, land, disarm, shutdown |
| Log | `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.14.4/mc_flight.ulg` |
| Log size / SHA-256 | 30,583,745 bytes / `9324d50388738054afdcee8cb09e3a44e1956c64003978e6aa401be16f09a254` |
| Log span | boot t = 0.244 s to 145.160 s (2 min 25 s, pyulog "duration: 0:02:24"); armed 9.780 s to 144.164 s (2 min 14 s) |
| Wall clock | launch 2026-10-18T11:18:25.233Z, disarm confirmed 11:20:52.785Z |
| ULog | file version byte 1, no appended data, no compat/incompat flags, no dropouts, `file_corruption` False |
| Warnings | none: PX4 stdout has no WARN or ERROR line; all 22 logged strings are INFO |

Deliverables (all in `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.14.4/`):

| File | SHA-256 |
|---|---|
| `mc_flight.ulg` | `9324d50388738054afdcee8cb09e3a44e1956c64003978e6aa401be16f09a254` |
| `mc_flight.px4.log` (px4 stdout and stderr) | `fe54810915f35ab9b09a8190a52faeb7eb2d0d5ff8adf6d7cd415509b70dd62f` |
| `mc_flight.sh` (the command script) | `7b089bc4305245f54d4c61c93ca90653fd20bf4fbcc50745412b004fdbb02e00` |
| `mc_flight.commands.log` (wall-clock command and confirmation log, extra) | `ef0b05431084570488c6c0eb43642cb008cf030fae987b58f2859b9f10b33cda` |

Tool outputs (ulog_info, ulog_info -v, ulog_messages, ulog_params, ulog2csv CSVs, analysis) are in `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/analysis/`. The analysis script is `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/analyze_ulog.py` and the collection script is `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/collect.sh`.

### 2. Findings that matter for the record format (B1.5)

1. **Header info fields** (exact pyulog `msg_info_dict`, section 7): `metadata_events_sha256`, `sys_name`, `sys_os_name`, `sys_os_ver_release`, `sys_toolchain`, `sys_toolchain_ver`, `time_ref_utc`, `ver_data_format`, `ver_hw`, `ver_sw`, `ver_sw_release`, `ver_vendor_sw_release`. Twelve keys, no others.
   - `ver_sw` is the 40-hex git hash, not a version string. The version is packed in `ver_sw_release` = 17695999 = 0x010E04FF = 1.14.4, type byte 0xFF (release). pyulog `ulog_info` derives "SW Version: v1.14.4" from that integer.
   - Keys the v1.14 logger can write but did not, and why (src/modules/logger/logger.cpp 2038 to 2115): `sys_os_ver` (only on NuttX; `px4_os_version_string()` returns NULL on Linux, src/lib/version/version.c 288 to 295), `ver_sw_branch` (empty `PX4_GIT_BRANCH_NAME` because the tree is a detached tag checkout), `ver_hw_subtype`, `ver_oem`, `sys_lib_ecl_ver`, `sys_mcu` (no MCU on posix), `sys_uuid` (`BOARD_HAS_NO_UUID` in platforms/posix/include/system_config.h:55, even though SDLOG_UUID is 1), `replay`, `log_type` (Mission logs only). A parser must treat every one of these as optional.
   - `sys_os_ver_release` = 101854463 = 0x06122CFF = host kernel 6.18.44. `time_ref_utc` = 0 (SDLOG_UTC_OFFSET 0). `ver_vendor_sw_release` = 255.
2. **Vehicle type**: `vehicle_status.vehicle_type` = 1 (VEHICLE_TYPE_ROTARY_WING), `is_vtol` = 0, `system_id` 4, `component_id` 1; parameters MAV_TYPE 2 (quadrotor), SYS_AUTOSTART 10040, CA_AIRFRAME 0. `ver_hw` = `PX4_SITL`.
3. **UTC is never available in SIH logs on v1.14.4.** `time_utc_usec` is 0 in every sample of both `vehicle_gps_position` (1161 msgs) and `sensor_gps` (144 msgs), even with fix_type 3, because `sensor_gps_sim` hard-codes `sensor_gps.time_utc_usec = 0` (src/modules/simulation/sensor_gps_sim/SensorGpsSim.cpp:154). Events from this log can only carry boot time. The log file name `log/2026-10-18/11_18_25.ulg` comes from the host clock and is not inside the file.
4. **Parameters**: 882 initial parameters. pyulog also reports 662 `changed_parameters`, all at the first logged timestamp (244000 us) and **all equal to their initial values** (0 differ). These are the logger re-emitting parameters right after the header, not changes. The same happened in run 1 (662 at 260000 us, 0 differ). A PARAM_CHANGED detector must ignore them (or compare values). The log also has 'Q' default-parameter records: 55 system defaults, 14 airframe (current setup) defaults (`ulog_params -d system|current_setup`). No real in-flight parameter change happened, so PARAM_CHANGED_IN_FLIGHT has no positive sample here.
5. **`failsafe_flags` is present (271 msgs, 38 fields); `vehicle_status_flags` is absent.** v1.14.4 has no `VehicleStatusFlags.msg` at all (it already uses `FailsafeFlags.msg`). Of the 38 fields, 13 are `mode_req_*` uint32 bitmasks (non-zero in every sample, for example `mode_req_manual_control` 33799), not flags; the other 25 are booleans. In this clean flight the booleans start set and clear at boot (`local_altitude_invalid` at 0.920 s, `attitude_invalid` 6.504 s, `local_position_invalid`, `local_position_invalid_relaxed`, `local_velocity_invalid`, `global_position_invalid` at 7.584 s). Four stay set for the whole log because no GCS, RC or mission exists in headless SITL: `auto_mission_missing`, `offboard_control_signal_lost`, `manual_control_signal_lost`, `gcs_connection_lost`. `vehicle_status.failsafe` stays 0 throughout. So a FAILSAFE_SET/CLEAR stream built from raw flags will show boot-time SET for those four plus six boot-time CLEARs, with no failsafe actually active.
6. **Commands**: `vehicle_command` 8 msgs, `vehicle_command_ack` 7 msgs. All have `from_external` 0 and source 4/1 (= MAV_SYS_ID/component 1; the commander CLI sends as the vehicle itself). The one without an ack is `1001` (VEHICLE_CMD_DO_GIMBAL_MANAGER_CONFIGURE, p1 -3, p2 -3, p3 -1, p4 -1) published internally at t = 0.088 s, a natural NO_ACK sample. `commander takeoff` produces two commands: 22 (NAV_TAKEOFF) and then 400 (ARM, accepted although already armed). Mode changes are 176 (DO_SET_MODE) with p1 1, p2 4 (PX4 main mode AUTO), p3 5 (sub mode RTL) or p3 3 (sub mode LOITER). Each ack follows its command by 4 to 12 ms and every result is 0 (ACCEPTED). No DENIED sample exists in this log.
7. **Arm and disarm reasons use the events enum, not the msg constants.** `vehicle_status.latest_arming_reason` and `latest_disarming_reason` are written as `(uint8_t)calling_reason` from `arm_disarm_reason_t` (src/modules/commander/Arming/ArmStateMachine/ArmStateMachine.cpp:97 and 100), whose values come from src/lib/events/enums.json: 0 transition_to_standby, 1 rc_stick, 2 rc_switch, 3 command_internal, 4 command_external, 5 mission_start, 6 auto_disarm_land, 7 auto_disarm_preflight, 8 kill_switch, 9 lockdown, 10 failure_detector, 11 shutdown, 12 unit_test, 13 rc_button, 14 failsafe. `msg/VehicleStatus.msg` has `ARM_DISARM_REASON_*` constants that agree only up to 5 (it says 6 SAFETY_BUTTON, 7 AUTO_DISARM_LAND, and so on). Run 2 shows the value 6 for a disarm that PX4 printed as "Disarmed by landing". Here both reasons are 3 (command_internal).
8. **`vtol_vehicle_status` is absent** because the logger listed it in `excluded_optional_topics` (no publisher on a quadcopter). That info-multiple list has 40 entries (section 7) and is evidence of which optional topics were dropped. VTOL_TRANSITION_* has no sample in this log by design.
9. **`log_message` is not a logged topic.** Flight-stack text arrives as 22 ULog logged-string ('L') records, all level 54 = ASCII '6' = INFO in pyulog's mapping. There are no tagged ('C') records. A clean flight therefore yields no LOG_MESSAGE events at warning or above. Run 2 has level 52 = '4' = WARNING records ("Preflight Fail: No valid data from Baro 0", "Failsafe: blind land", "Failsafe activated").
10. **`event` topic (36 msgs) carries PX4 events** (fields `id`, `event_sequence`, `log_levels`, `arguments[0..24]`). pyulog `ulog_messages` merges these, decoded with the embedded `metadata_events`, into its message list. That is why it prints "RTL activated" and "Armed by internal command" without a module prefix next to the 'L' strings.
11. **Other topics**: `vehicle_land_detected` 152, `battery_status` 1 instance 725 msgs (simulated battery, remaining 1.000 to 0.783, warning 0), `estimator_status_flags` 154 msgs (68 fields), `home_position` 529, `actuator_armed` 298. All single instance (multi_id 0) except `telemetry_status` (4 instances).
12. **Boot time and wall clock drift.** In lockstep SIH, boot time ran about 2.2% slower than wall time under this machine's load: wall minus boot time was 11:18:25.675 at arm and 11:18:28.607 at disarm (section 5). Boot-time microseconds in the record are simulation time.
13. **Land detector**: `landed` 1 at 0.144 s, 0 at 11.516 s (PX4 "Takeoff detected" at 11.520 s), 1 again at 143.980 s ("Landing detected" 143.984 s). `maybe_landed` and `ground_contact` lead `landed` by 1 s and 2 s on touchdown.

### 3. Building PX4 v1.14.4 with GCC 13 / Python 3.13

Toolchain on this machine: Ubuntu 24.04, GCC/G++ 13.3.0, CMake 3.28.3, Python 3.13.16, empy 3.3.4 installed by hand as `em.py` (not reinstalled), pyulog 1.2.4, 4 CPUs. Three fixes were needed; all live in the scratch tree only. None was a Python 3.13 issue and no Python module was missing.

1. **NuttX tags (applied by the coordinator).** The build first failed on missing `nuttx-*` tags in the NuttX submodule. The coordinator fetched the tags into `platforms/nuttx/NuttX/nuttx` (the first line of the original task output reads `nuttx tags now: 146`; the submodule now has 146 tags). Builds then ran with `PX4_NO_GIT_CHECK=1`.
2. **`uint8_t` undeclared in pxh.cpp (GCC 13 no longer pulls in `<cstdint>` transitively).** Error: `platforms/posix/src/px4/common/px4_daemon/pxh.cpp:208:25: error: 'uint8_t' was not declared in this scope`. Fix: add `#include <cstdint>` at the top. The coordinator and I both added it; I removed my duplicate so the tree carries a single line.
3. **GCC 13 `-Werror=array-bounds` false positive.** Error (in `local_position_estimator/sensors/lidar.cpp`, `sonar.cpp`, `baro.cpp`): `src/lib/matrix/matrix/Matrix.hpp:96:29: error: array subscript 1 is above array bounds of 'float [1][1]' [-Werror=array-bounds=]`. Fix: add `-Wno-array-bounds` to the module's `COMPILE_FLAGS` in `src/modules/local_position_estimator/CMakeLists.txt`. Editing a CMakeLists.txt re-runs CMake automatically, so no clean reconfigure was needed. The coordinator's alternative recipe (delete the build directory and export `CFLAGS`/`CXXFLAGS` with `-Wno-error=...` flags) was **not** used: `CMAKE_C_FLAGS` and `CMAKE_CXX_FLAGS` are empty in `build/px4_sitl_default/CMakeCache.txt`.

Build attempts:

| Log | Result |
|---|---|
| `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/tasks/b30scic78.output` | `build exit=2`, pxh.cpp `uint8_t` |
| `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/build_v1.14.4_rebuild.log` | `build exit=2`, Matrix.hpp array-bounds (pxh.cpp now compiles) |
| `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/v1.14.4_build.log` (coordinator) | `build exit=2`, same array-bounds error |
| `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/v1.14.4_build_attempt3.log` | `build exit=0`, 344 steps, `build/px4_sitl_default/bin/px4` linked 03:02 UTC |

Build command for attempt 3: `cd <v1.14.4 tree> && PX4_NO_GIT_CHECK=1 make px4_sitl_default -j4`.

<details><summary>git diff of the v1.14.4 tree (both source patches)</summary>

```diff
diff --git a/platforms/posix/src/px4/common/px4_daemon/pxh.cpp b/platforms/posix/src/px4/common/px4_daemon/pxh.cpp
index c17bbda..9bcf026 100644
--- a/platforms/posix/src/px4/common/px4_daemon/pxh.cpp
+++ b/platforms/posix/src/px4/common/px4_daemon/pxh.cpp
@@ -40,6 +40,7 @@
  * @author Julian Oes <julian@oes.ch>
  */
 
+#include <cstdint>
 #include <string>
 #include <sstream>
 #include <vector>
diff --git a/src/modules/local_position_estimator/CMakeLists.txt b/src/modules/local_position_estimator/CMakeLists.txt
index aafaecd..b9ffac6 100644
--- a/src/modules/local_position_estimator/CMakeLists.txt
+++ b/src/modules/local_position_estimator/CMakeLists.txt
@@ -34,6 +34,7 @@ px4_add_module(
 	MODULE modules__local_position_estimator
 	MAIN local_position_estimator
 	COMPILE_FLAGS
+		-Wno-array-bounds
 	STACK_MAIN 5700
 	STACK_MAX 3700
 	SRCS
```
</details>

### 4. How SIH is selected and launched in v1.14.4

- `platforms/posix/cmake/sitl_target.cmake` does not exist in v1.14.4. The SIH run targets are defined in `src/modules/simulation/simulator_sih/CMakeLists.txt` (lines 52 to 57): `add_custom_target(sihsim_${model} COMMAND ${CMAKE_COMMAND} -E env PX4_SIM_MODEL=sihsim_${model} PX4_SIMULATOR=sihsim $<TARGET_FILE:px4> WORKING_DIRECTORY ${SITL_WORKING_DIR} ...)` for models airplane, quadx and xvert. `SITL_WORKING_DIR` is `${PX4_BINARY_DIR}/rootfs` (`platforms/posix/CMakeLists.txt:120`). So `make px4_sitl sihsim_quadx` runs `env PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim build/px4_sitl_default/bin/px4` in `build/px4_sitl_default/rootfs`.
- The airframe named in the brief, `1100_rc_quad_x_sih`, does not exist in v1.14.4. The `sihsim_*` airframes already exist there: `10040_sihsim_quadx`, `10041_sihsim_airplane`, `10042_sihsim_xvert` in `ROMFS/px4fmu_common/init.d-posix/airframes/`.
- `ROMFS/px4fmu_common/init.d-posix/rcS` lines 37 to 62: when `PX4_SIM_MODEL` is set (and neither `shell` nor `none`, and `PX4_SYS_AUTOSTART` is unset), it looks for an airframe file named `<digits>_${PX4_SIM_MODEL}` and sets `SYS_AUTOSTART` to the digits (here 10040). The airframe sources `rc.mc_defaults`, defaults `PX4_SIMULATOR=sihsim` and `PX4_SIM_MODEL=quadx`, enables `SENS_EN_GPSSIM`, `SENS_EN_BAROSIM` and `SENS_EN_MAGSIM`, sets the CA_ROTOR geometry and `SIH_VEHICLE_TYPE 0`.
- `ROMFS/px4fmu_common/init.d-posix/px4-rc.simulator` line 7: `if [ "$PX4_SIMULATOR" = "sihsim" ] || [ "$(param show -q SYS_AUTOSTART)" -eq "0" ]` prints `SIH simulator`, runs `simulator_sih start`, then `sensor_baro_sim`, `sensor_gps_sim` and `sensor_mag_sim` per the SENS_EN_* parameters.
- rcS line 178: `param set-default SDLOG_MODE 1` (log from boot until first disarm), `SDLOG_PROFILE 131`. The logger opened `./log/2026-10-18/11_18_25.ulg` 0.244 s after boot and closed it at disarm (`closed logfile, bytes written: 30583745`).
- px4 arguments (`platforms/posix/src/px4/common/main.cpp`): `-d` daemon mode without the pxh shell, `-i N` instance, `-w DIR` working directory, positional data path. With no arguments px4 defaults to data path `<build>/etc` and working dir `<build>/rootfs` (lines 263 to 272). With `-w` the data path must be passed explicitly so px4 symlinks `etc` into the new directory.
- Instance 3 changes only instance-keyed resources: client socket `/tmp/px4-sock-3`, lock `/tmp/px4_lock-3`, MAVLink UDP ports 18573, 14583, 14283, 13033 and 19453, and through rcS line 131 `MAV_SYS_ID` = 4 (and `UXRCE_DDS_KEY` 4). The other agent's v1.17.0 SITL used instance 0.
- Arming works without RC or a GCS because the default user intention is AUTO_LOITER (`src/modules/commander/UserModeIntention.hpp:76`). Manual control is only a requirement of manual modes (`HealthAndArmingChecks/checks/modeCheck.cpp` 146 to 163). Manual-control loss that already existed at arming does not trigger the RC-loss failsafe (`failsafe/failsafe.cpp` 342 to 354).

### 5. Reproducible procedure

```bash
S=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad
T=$S/px4/PX4-Autopilot-v1.14.4          # git checkout v1.14.4 (1555f2bd2229544c43966ab5f94879c41d8e1e01)
BUILD=$T/build/px4_sitl_default
# build (after the fixes in section 3)
cd $T && PX4_NO_GIT_CHECK=1 make px4_sitl_default -j4
# fly: make sure no other px4 SITL is competing for CPU (see run 2), then
$S/sitl_logs/v1.14.4/mc_flight.sh $S/sitl_run/v1.14.4_mc_run3     # fresh working directory as argument
# collect and analyse
$S/sitl_run/collect.sh $S/sitl_run/v1.14.4_mc_run3
```

What `mc_flight.sh` does (full script in section 9):

```bash
WD=$S/sitl_run/v1.14.4_mc_run3; mkdir -p $WD; cd $WD
PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim $BUILD/bin/px4 -d -i 3 -w $WD $BUILD/etc > $WD/px4.stdout.log 2>&1 < /dev/null &
# every step is confirmed by polling: $BUILD/bin/px4-listener --instance 3 <topic> -n 1   (fields print as "    name: value")
#   wait vehicle_status.pre_flight_checks_pass == True
$BUILD/bin/px4-commander --instance 3 arm               # wait arming_state == 2
$BUILD/bin/px4-commander --instance 3 takeoff           # wait nav_state == 17, then nav_state == 4 (takeoff complete)
sleep 70
$BUILD/bin/px4-commander --instance 3 mode auto:rtl     # wait nav_state == 5; leave RTL once below 1.2 m above ground (max 8 s)
$BUILD/bin/px4-commander --instance 3 mode auto:loiter  # wait nav_state == 4
sleep 45
$BUILD/bin/px4-commander --instance 3 land              # wait nav_state == 18, then vehicle_land_detected.landed == True
$BUILD/bin/px4-commander --instance 3 disarm            # sent immediately on landed (auto disarm COM_DISARM_LAND is 2 s); wait arming_state == 1
sleep 4; $BUILD/bin/px4-shutdown --instance 3
# log: $WD/log/<YYYY-MM-DD>/<HH_MM_SS>.ulg
```

Why RTL is short: the vehicle is within RTL_MIN_DIST (10 m) of home, so v1.14 RTL goes straight to "RTL: land at destination" and descends. PX4 printed "climb to 35 m (2 m above destination)", which is AMSL; home altitude is 32.36 m. The script switches to loiter about 1.6 s into RTL, at about 1.0 m above ground, so that the explicit `commander land` and `commander disarm` steps stay part of the scenario.

### 6. The flight (run 3, the delivered log)

#### 6.1 Ordered commands with wall-clock times

Wall clock is UTC from the driver; boot time is from the log. "Confirmed" is the `px4-listener` poll result.

| # | Wall clock (UTC) | Command | Logged `vehicle_command` (boot s, id, params) | `vehicle_command_ack` (boot s, result) | Confirmed |
|---|---|---|---|---|---|
| 0 | 11:18:25.233 | launch px4 (above) | 0.088 cmd 1001 (internal, no ack) | none | `Startup script returned successfully`; `pre_flight_checks_pass` True at 11:18:33.395 |
| 1 | 11:18:35.447 | `px4-commander --instance 3 arm` | 9.772 cmd 400 p1 1 p2 0 | 9.780 ACCEPTED (0) | arming_state 2 at 11:18:35.463 |
| 2 | 11:18:35.517 | `px4-commander --instance 3 takeoff` | 9.844 cmd 22; 9.856 cmd 400 p1 1 | 9.852 ACCEPTED; 9.864 ACCEPTED | nav_state 17 at 11:18:35.549; nav_state 4 at 11:18:42.818 (z -2.48 m, ground z0 -0.53 m) |
| 3 | 11:19:52.908 | `px4-commander --instance 3 mode auto:rtl` | 85.284 cmd 176 p1 1 p2 4 p3 5 | 85.288 ACCEPTED | nav_state 5 at 11:19:53.437 |
| 4 | 11:19:54.536 | `px4-commander --instance 3 mode auto:loiter` | 86.888 cmd 176 p1 1 p2 4 p3 3 | 86.896 ACCEPTED | nav_state 4 at 11:19:55.064 |
| 5 | 11:20:40.171 | `px4-commander --instance 3 land` | 131.716 cmd 21 | 131.720 ACCEPTED | nav_state 18 at 11:20:40.714; landed True at 11:20:52.689 |
| 6 | 11:20:52.759 | `px4-commander --instance 3 disarm` | 144.152 cmd 400 p1 0 p2 0 | 144.164 ACCEPTED | arming_state 1 at 11:20:52.785; latest_disarming_reason 3 |
| 7 | 11:20:56.847 | `px4-shutdown --instance 3` | (log already closed at disarm) | none | px4 exited 11:20:56.865 |

Wall minus boot time: 11:18:25.675 (arm), 11:18:25.673 (takeoff), 11:18:27.624 (rtl), 11:18:27.648 (loiter), 11:18:28.455 (land), 11:18:28.607 (disarm).

#### 6.2 vehicle_status arming_state and nav_state sequence (298 msgs)

| Boot time (s) | arming_state | nav_state | nav_state_user_intention | Note |
|---|---|---|---|---|
| 0.092 | 1 STANDBY | 4 AUTO_LOITER | 4 | first sample; failsafe 0, vehicle_type 1, system_id 4 |
| 9.780 | 2 ARMED | 4 | 4 | latest_arming_reason 0 to 3 (command_internal) |
| 9.864 | 2 | 17 AUTO_TAKEOFF | 17 | |
| 16.476 | 2 | 4 AUTO_LOITER | 4 | takeoff complete |
| 85.300 | 2 | 5 AUTO_RTL | 5 | |
| 86.908 | 2 | 4 AUTO_LOITER | 4 | |
| 131.732 | 2 | 18 AUTO_LAND | 18 | |
| 144.164 | 1 STANDBY | 18 | 18 | latest_disarming_reason 0 to 3 (command_internal) |
| 144.176 | 1 | 4 | 4 | commander resets the intention after disarm |

NAV_STATE_CHANGE pairs: 4 to 17, 17 to 4, 4 to 5, 5 to 4, 4 to 18, 18 to 4 (six changes; four distinct nav states). `failsafe` stays 0.

#### 6.3 Requested topics

| Topic | Present | Instances | Messages |
|---|---|---|---|
| vehicle_status | yes | 0 | 298 |
| failsafe_flags | yes | 0 | 271 |
| vehicle_status_flags | **no** (no such msg in v1.14.4) | | |
| vehicle_command | yes | 0 | 8 |
| vehicle_command_ack | yes | 0 | 7 |
| vtol_vehicle_status | **no** (listed in `excluded_optional_topics`) | | |
| vehicle_land_detected | yes | 0 | 152 |
| vehicle_gps_position | yes | 0 | 1161 (time_utc_usec always 0) |
| sensor_gps | yes | 0 | 144 (time_utc_usec always 0) |
| battery_status | yes | 0 | 725 |
| estimator_status_flags | yes | 0 | 154 |
| log_message | **no** (not in the logger topic list) | | |
| ULog logged strings ('L') | yes | | 22, all INFO; 0 tagged ('C') |
| event (PX4 events, for reference) | yes | 0 | 36 |

### 7. Header info fields exactly as pyulog reports them

```
metadata_events_sha256 = '5d37a2bac6b8708e530d741cd0d8af9c1f1f71d9f21540994ea8300d0a813314'
sys_name = 'PX4'
sys_os_name = 'Linux'
sys_os_ver_release = 101854463
sys_toolchain = 'GNU GCC'
sys_toolchain_ver = '13.3.0'
time_ref_utc = 0
ver_data_format = 1
ver_hw = 'PX4_SITL'
ver_sw = '1555f2bd2229544c43966ab5f94879c41d8e1e01'
ver_sw_release = 17695999
ver_vendor_sw_release = 255
```

Info-multiple keys: `excluded_optional_topics` (40 entries), `metadata_events` (1 list of 14 chunks), `perf_counter_preflight` (81 items), `perf_counter_postflight` (83 items). No `boot_console_output`.

`excluded_optional_topics`: `actuator_controls_status_0`, `airspeed_validated`, `airspeed_wind`, `camera_capture`, `camera_trigger`, `esc_status`, `estimator_aid_src_airspeed`, `estimator_aid_src_gnss_yaw`, `external_ins_attitude`, `external_ins_global_position`, `external_ins_local_position`, `flaps_setpoint`, `follow_target`, `follow_target_estimator`, `follow_target_status`, `generator_status`, `gimbal_controls`, `gps_dump`, `gripper`, `heater_status`, `internal_combustion_engine_status`, `iridiumsbd_status`, `irlock_report`, `landing_gear_wheel`, `landing_target_pose`, `launch_detection_status`, `magnetometer_bias_estimate`, `pps_capture`, `px4io_status`, `rpm`, `sensor_correction`, `sensor_hygrometer`, `spoilers_setpoint`, `tecs_status`, `tiltrotor_extra_controls`, `vehicle_thrust_setpoint_virtual_fw`, `vehicle_thrust_setpoint_virtual_mc`, `vehicle_torque_setpoint_virtual_fw`, `vehicle_torque_setpoint_virtual_mc`, `vtol_vehicle_status`

Not present (all optional, see finding 1): `sys_os_ver`, `ver_sw_branch`, `ver_hw_subtype`, `ver_oem`, `sys_lib_ecl_ver`, `sys_mcu`, `sys_uuid`, `replay`, `log_type`.

### 8. Other runs (not delivered)

Three flights of the same scenario were made, each in its own fresh working directory. Only run 3 is delivered.

| Run | Working dir | Log, size, SHA-256 | Outcome |
|---|---|---|---|
| 1 | `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run1` | `log/2026-10-18/11_10_48.ulg`, 21,044,637 bytes, `2190caf0c7b9a32ba0d61db9124362b36bf9bcf1285b62d1127176b051e1c4f9` | Complete and clean, same command and nav sequence, but only 99.7 s of log (under the 2-minute floor). RTL was left at about 0.35 m above ground because the first script compared raw z instead of z relative to ground. Superseded. |
| 2 | `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run2` | `log/2026-10-18/11_13_40.ulg`, 4,063,994 bytes, `05ff8ecc0e34be58e65a11347f5d8b20b3b43197436f82a8f88338a7c9a223b5` | Started 2 s after the other agent's v1.17.0 SITL, with a CPU-heavy fuzzer also running. During takeoff PX4 reported "No valid data from Compass 0" and "No valid data from Baro 0", then "Failsafe: blind land" and "Battery unhealthy". nav_state 17 to 12 (DESCEND) at 14.812 s, failsafe 0 to 1, failsafe_flags `local_velocity_invalid`, `local_position_invalid`, `global_position_invalid` and `battery_unhealthy` set. It landed and auto-disarmed with latest_disarming_reason 6 (auto_disarm_land), 19.8 s of log, and the script aborted. Probable cause is CPU contention (not proven). It is a genuine v1.14 failsafe sample (FAILSAFE_SET, WARNING-level strings, reason 6) if one is wanted. |
| 3 | `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3` | delivered as `mc_flight.ulg` | Started after no px4 process had run for 15 s (load 3.14 at start). Clean. |

Run 1 to run 3 script change: record ground z0 before arming, leave RTL when `z - z0 > -1.2`, hovers 70 s and 45 s instead of 40 s and 30 s. The pre-change script is kept as `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/mc_flight.sh.run1`.

### 9. Raw outputs

<details><summary>Driver command log with wall-clock times, run 3 (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/commands.log</code>)</summary>

```text
2026-10-18T11:18:25.229Z PX4 tree: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.14.4 (v1.14.4 1555f2bd2229544c43966ab5f94879c41d8e1e01)
2026-10-18T11:18:25.233Z LAUNCH: cd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3 && PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.14.4/build/px4_sitl_default/bin/px4 -d -i 3 -w /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3 /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.14.4/build/px4_sitl_default/etc > /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/px4.stdout.log 2>&1 < /dev/null &
2026-10-18T11:18:25.237Z px4 pid 23576
2026-10-18T11:18:33.395Z OK: vehicle_status.pre_flight_checks_pass == True
2026-10-18T11:18:35.435Z STATE[preflight_ok]: arming_state=1 nav_state=4 user_intention=4 failsafe=False landed=True z=-0.53372
2026-10-18T11:18:35.443Z ground reference z0=-0.53280 (vehicle_local_position.z before arming)
2026-10-18T11:18:35.447Z CMD: px4-commander --instance 3 arm
2026-10-18T11:18:35.463Z OK: vehicle_status.arming_state == 2
2026-10-18T11:18:35.509Z STATE[armed]: arming_state=2 nav_state=4 user_intention=4 failsafe=False landed=True z=-0.51568
2026-10-18T11:18:35.517Z CMD: px4-commander --instance 3 takeoff
2026-10-18T11:18:35.549Z OK: vehicle_status.nav_state == 17
2026-10-18T11:18:35.581Z STATE[takeoff]: arming_state=2 nav_state=17 user_intention=17 failsafe=False landed=True z=-0.49648
2026-10-18T11:18:42.818Z OK: vehicle_status.nav_state == 4
2026-10-18T11:18:42.874Z STATE[takeoff_done]: arming_state=2 nav_state=4 user_intention=4 failsafe=False landed=False z=-2.47935
2026-10-18T11:19:52.905Z STATE[hover]: arming_state=2 nav_state=4 user_intention=4 failsafe=False landed=False z=-2.12931
2026-10-18T11:19:52.908Z CMD: px4-commander --instance 3 mode auto:rtl
2026-10-18T11:19:53.437Z OK: vehicle_status.nav_state == 5
2026-10-18T11:19:53.469Z STATE[rtl]: arming_state=2 nav_state=5 user_intention=5 failsafe=False landed=False z=-2.12347
2026-10-18T11:19:54.499Z RTL descending below 1.2 m above ground (z=-1.57612, z0=-0.53280), leaving RTL
2026-10-18T11:19:54.533Z STATE[rtl_end]: arming_state=2 nav_state=5 user_intention=5 failsafe=False landed=False z=-1.55776
2026-10-18T11:19:54.536Z CMD: px4-commander --instance 3 mode auto:loiter
2026-10-18T11:19:55.064Z OK: vehicle_status.nav_state == 4
2026-10-18T11:19:55.099Z STATE[loiter]: arming_state=2 nav_state=4 user_intention=4 failsafe=False landed=False z=-1.28555
2026-10-18T11:20:40.165Z STATE[loiter_end]: arming_state=2 nav_state=4 user_intention=4 failsafe=False landed=False z=-1.54253
2026-10-18T11:20:40.171Z CMD: px4-commander --instance 3 land
2026-10-18T11:20:40.714Z OK: vehicle_status.nav_state == 18
2026-10-18T11:20:40.790Z STATE[land]: arming_state=2 nav_state=18 user_intention=18 failsafe=False landed=False z=-1.46335
2026-10-18T11:20:52.689Z OK: vehicle_land_detected.landed == True
2026-10-18T11:20:52.750Z STATE[landed]: arming_state=2 nav_state=18 user_intention=18 failsafe=False landed=True z=-0.29260
2026-10-18T11:20:52.759Z CMD: px4-commander --instance 3 disarm
2026-10-18T11:20:52.785Z OK: vehicle_status.arming_state == 1
2026-10-18T11:20:52.830Z STATE[disarmed]: arming_state=1 nav_state=4 user_intention=4 failsafe=False landed=True z=-0.29436
2026-10-18T11:20:52.839Z latest_disarming_reason=3
2026-10-18T11:20:56.847Z CMD: px4-shutdown --instance 3 
2026-10-18T11:20:56.865Z px4 exited
2026-10-18T11:20:56.881Z ULOG: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/log/2026-10-18/11_18_25.ulg 
```
</details>

<details><summary>px4 stdout and stderr, run 3 (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.14.4/mc_flight.px4.log</code>)</summary>

```text
INFO  [px4] instance: 3

______  __   __    ___ 
| ___ \ \ \ / /   /   |
| |_/ /  \ V /   / /| |
|  __/   /   \  / /_| |
| |     / /^\ \ \___  |
\_|     \/   \/     |_/

px4 starting.

INFO  [px4] startup script: /bin/sh etc/init.d-posix/rcS 3
INFO  [init] found model autostart file as SYS_AUTOSTART=10040
INFO  [param] selected parameter default file parameters.bson
INFO  [param] selected parameter backup file parameters_backup.bson
  SYS_AUTOCONFIG: curr: 0 -> new: 1
* MAV_SYS_ID: curr: 1 -> new: 4
* UXRCE_DDS_KEY: curr: 1 -> new: 4
  SYS_AUTOSTART: curr: 0 -> new: 10040
  CAL_ACC0_ID: curr: 0 -> new: 1310988
  CAL_GYRO0_ID: curr: 0 -> new: 1310988
  CAL_ACC1_ID: curr: 0 -> new: 1310996
  CAL_GYRO1_ID: curr: 0 -> new: 1310996
  CAL_ACC2_ID: curr: 0 -> new: 1311004
  CAL_GYRO2_ID: curr: 0 -> new: 1311004
  CAL_MAG0_ID: curr: 0 -> new: 197388
  CAL_MAG0_PRIO: curr: -1 -> new: 50
  CAL_MAG1_ID: curr: 0 -> new: 197644
  CAL_MAG1_PRIO: curr: -1 -> new: 50
* SENS_BOARD_X_OFF: curr: 0.0000 -> new: 0.0000
* SENS_DPRES_OFF: curr: 0.0000 -> new: 0.0010
INFO  [dataman] data manager file './dataman' size is 7866640 bytes
INFO  [init] SIH simulator
INFO  [simulator_sih] Simulation loop with 250 Hz (4000 us sim time interval)
INFO  [simulator_sih] Simulation with 1.0x speedup. Loop with (4000 us wall time interval)
INFO  [lockstep_scheduler] setting initial absolute time to 4000 us
INFO  [commander] LED: open /dev/led0 failed (22)
INFO  [mavlink] mode: Normal, data rate: 4000000 B/s on udp port 18573 remote port 14550
INFO  [tone_alarm] home set
INFO  [mavlink] mode: Onboard, data rate: 4000000 B/s on udp port 14583 remote port 14543
INFO  [mavlink] mode: Onboard, data rate: 4000 B/s on udp port 14283 remote port 14033
INFO  [mavlink] mode: Gimbal, data rate: 400000 B/s on udp port 13033 remote port 13283
INFO  [mavlink] mode: Custom, data rate: 400000 B/s on udp port 19453 remote port 19413
INFO  [logger] logger started (mode=all)
INFO  [logger] Start file log (type: full)
INFO  [logger] [logger] ./log/2026-10-18/11_18_25.ulg	
INFO  [logger] Opened full log file: ./log/2026-10-18/11_18_25.ulg
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
INFO  [px4] Startup script returned successfully
INFO  [commander] <ESC>[32mReady for takeoff!<ESC>[0m
INFO  [commander] Armed by internal command	
INFO  [tone_alarm] arming warning
INFO  [navigator] Using minimum takeoff altitude: 2.50 m	
INFO  [commander] Takeoff detected	
INFO  [navigator] RTL HOME activated	
INFO  [navigator] RTL: landing at home position.	
INFO  [navigator] RTL: climb to 35 m (2 m above destination)	
INFO  [navigator] RTL: return at 35 m (2 m above destination)	
INFO  [navigator] RTL: descend to 35 m (2 m above destination)	
INFO  [navigator] RTL: land at destination	
INFO  [commander] Landing at current position	
INFO  [commander] Landing detected	
INFO  [commander] Disarmed by internal command	
INFO  [tone_alarm] notify neutral
INFO  [logger] closed logfile, bytes written: 30583745
Exiting NOW.
```
</details>

<details><summary>ulog_info (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/analysis/ulog_info.txt</code>)</summary>

```text
Logging start time: 0:00:00, duration: 0:02:24
No Dropouts
SW Version: v1.14.4
Info Messages:
 metadata_events_sha256: 5d37a2bac6b8708e530d741cd0d8af9c1f1f71d9f21540994ea8300d0a813314
 sys_name: PX4
 sys_os_name: Linux
 sys_os_ver_release: 101854463
 sys_toolchain: GNU GCC
 sys_toolchain_ver: 13.3.0
 time_ref_utc: 0
 ver_data_format: 1
 ver_hw: PX4_SITL
 ver_sw: 1555f2bd2229544c43966ab5f94879c41d8e1e01
 ver_sw_release: 17695999
 ver_vendor_sw_release: 255
Info Multiple Messages: [excluded_optional_topics: 40], [metadata_events: 1], [perf_counter_postflight: 1], [perf_counter_preflight: 1]

Name (multi id, message size in bytes)    number of data points, total bytes
 actuator_armed (0, 15)                       298       4470
 actuator_motors (0, 66)                     1451      95766
 actuator_outputs (0, 76)                    1451     110276
 battery_status (0, 167)                      725     121075
 control_allocator_status (0, 52)             725      37700
 cpuload (0, 16)                              290       4640
 distance_sensor (0, 55)                     7247     398585
 ekf2_timestamps (0, 20)                    36225     724500
 estimator_aid_src_baro_hgt (0, 52)          2155     112060
 estimator_aid_src_fake_hgt (0, 52)             4        208
 estimator_aid_src_fake_pos (0, 72)            31       2232
 estimator_aid_src_gnss_hgt (0, 52)          1161      60372
 estimator_aid_src_gnss_pos (0, 72)          1161      83592
 estimator_aid_src_gnss_vel (0, 92)          1161     106812
 estimator_aid_src_rng_hgt (0, 52)           7202     374504
 estimator_attitude (0, 49)                   279      13671
 estimator_baro_bias (0, 40)                 1643      65720
 estimator_event_flags (0, 53)                146       7738
 estimator_global_position (0, 60)            140       8400
 estimator_gps_status (0, 39)                1161      45279
 estimator_innovation_test_ratios (0, 152)   18114    2753328
 estimator_innovation_variances (0, 152)    18114    2753328
 estimator_innovations (0, 152)             18114    2753328
 estimator_local_position (0, 167)            289      48263
 estimator_rng_hgt_bias (0, 40)              4211     168440
 estimator_selector_status (0, 153)           144      22032
 estimator_sensor_bias (0, 118)              1567     184906
 estimator_states (0, 209)                  18114    3785826
 estimator_status (0, 114)                  18114    2064996
 estimator_status_flags (0, 91)               154      14014
 event (0, 40)                                 36       1440
 failsafe_flags (0, 85)                       271      23035
 failure_detector_status (0, 22)              298       6556
 home_position (0, 48)                        529      25392
 hover_thrust_estimate (0, 41)               1287      52767
 landing_gear (0, 9)                            5         45
 manual_control_setpoint (0, 63)                1         63
 mission_result (0, 30)                        11        330
 parameter_update (0, 34)                       1         34
 position_setpoint_triplet (0, 224)            65      14560
 rate_ctrl_status (0, 24)                     725      17400
 rtl_time_estimate (0, 17)                    143       2431
 sensor_accel (0, 44)                         144       6336
 sensor_baro (0, 32)                          144       4608
 sensor_combined (0, 48)                    31145    1494960
 sensor_gps (0, 124)                          144      17856
 sensor_gyro (0, 44)                          144       6336
 sensor_gyro_fft (0, 100)                      50       5000
 sensor_mag (0, 40)                           144       5760
 sensor_selection (0, 16)                       1         16
 sensors_status_imu (0, 96)                   725      69600
 takeoff_status (0, 13)                        11        143
 telemetry_status (0, 86)                     144      12384
 telemetry_status (1, 86)                     144      12384
 telemetry_status (2, 86)                     144      12384
 telemetry_status (3, 86)                     144      12384
 trajectory_setpoint (0, 64)                  725      46400
 transponder_report (0, 78)                     1         78
 vehicle_acceleration (0, 28)                2900      81200
 vehicle_air_data (0, 37)                    2156      79772
 vehicle_angular_velocity (0, 40)           14493     579720
 vehicle_angular_velocity_groundtruth (0, 40)   14493     579720
 vehicle_attitude (0, 49)                   28079    1375871
 vehicle_attitude_groundtruth (0, 49)       14493     710157
 vehicle_attitude_setpoint (0, 54)           2900     156600
 vehicle_command (0, 54)                        8        432
 vehicle_command_ack (0, 21)                    7        147
 vehicle_constraints (0, 17)                  144       2448
 vehicle_control_mode (0, 21)                 298       6258
 vehicle_global_position (0, 60)            17329    1039740
 vehicle_global_position_groundtruth (0, 60)    1451      87060
 vehicle_gps_position (0, 124)               1161     143964
 vehicle_imu (0, 56)                          290      16240
 vehicle_imu_status (0, 132)                  145      19140
 vehicle_land_detected (0, 20)                152       3040
 vehicle_local_position (0, 167)            18114    3025038
 vehicle_local_position_groundtruth (0, 167)    7247    1210249
 vehicle_local_position_setpoint (0, 64)     1451      92864
 vehicle_magnetometer (0, 33)                2058      67914
 vehicle_rates_setpoint (0, 33)              6933     228789
 vehicle_status (0, 66)                       298      19668
 vehicle_thrust_setpoint (0, 28)             7247     202916
 vehicle_torque_setpoint (0, 28)             7247     202916
```
</details>

<details><summary>ulog_messages (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/analysis/ulog_messages.txt</code>)</summary>

```text
0:00:00.244 INFO: logging: opening log file 2026-10-18/11_18_25.ulg
0:00:00.244 INFO: [logger] logger started (mode=all)
0:00:00.244 INFO: [logger] Start file log (type: full)
0:00:00.244 INFO: [logger] Opened full log file: ./log/2026-10-18/11_18_25.ulg
0:00:00.248 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.248 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.248 INFO: [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
0:00:00.252 INFO: [px4] Startup script returned successfully
0:00:07.584 INFO: [commander] <ESC>[32mReady for takeoff!<ESC>[0m
0:00:09.780 INFO: Armed by internal command
0:00:09.780 INFO: [tone_alarm] arming warning
0:00:09.864 INFO: Using minimum takeoff altitude: 2.50 m
0:00:11.520 INFO: Takeoff detected
0:01:25.300 INFO: RTL activated
0:01:25.300 INFO: RTL: landing at home position
0:01:25.300 INFO: RTL: climb to 35 m (2 m above destination)
0:01:25.400 INFO: RTL: return at 35 m (2 m above destination)
0:01:25.456 INFO: RTL: descend to 35 m (2 m above destination)
0:01:25.552 INFO: RTL: land at destination
0:02:11.720 INFO: Landing at current position
0:02:23.984 INFO: Landing detected
0:02:24.164 INFO: Disarmed by internal command
0:02:24.164 INFO: [tone_alarm] notify neutral
```
</details>

<details><summary>analyze_ulog.py output (identity, info, parameters, topics, transitions, commands, failsafe flags, land detector, GPS, logged strings) (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/analysis/analysis.txt</code>)</summary>

```text
== file
path: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.14.4/mc_flight.ulg
size_bytes: 30583745
sha256: 9324d50388738054afdcee8cb09e3a44e1956c64003978e6aa401be16f09a254
ulog file version (header byte 7): 1
start_timestamp_us: 244000  last_timestamp_us: 145160000  duration_s: 144.916
file_corruption: False
has_data_appended: 0
compat_flags: []  incompat_flags: []
appended_offsets: None

== info (msg_info_dict), exact keys and values as pyulog reports them
metadata_events_sha256 = '5d37a2bac6b8708e530d741cd0d8af9c1f1f71d9f21540994ea8300d0a813314'
sys_name = 'PX4'
sys_os_name = 'Linux'
sys_os_ver_release = 101854463
sys_toolchain = 'GNU GCC'
sys_toolchain_ver = '13.3.0'
time_ref_utc = 0
ver_data_format = 1
ver_hw = 'PX4_SITL'
ver_sw = '1555f2bd2229544c43966ab5f94879c41d8e1e01'
ver_sw_release = 17695999
ver_vendor_sw_release = 255

== info multiple (msg_info_multiple_dict) keys
excluded_optional_topics: 40 list(s), first list 1 item(s)
metadata_events: 1 list(s), first list 14 item(s)
perf_counter_postflight: 1 list(s), first list 83 item(s)
perf_counter_preflight: 1 list(s), first list 81 item(s)

== dropouts
count: 0  total_ms: 0

== parameters
initial parameter count: 882
changed_parameters (timestamp, name, value): 662
   (244000, 'ASPD_SCALE_1', 1.0)
   (244000, 'BAT1_CAPACITY', -1.0)
   (244000, 'BAT1_N_CELLS', 4)
   (244000, 'BAT1_R_INTERNAL', 0.004999999888241291)
   (244000, 'BAT1_SOURCE', 0)
   (244000, 'BAT1_V_CHARGED', 4.050000190734863)
   (244000, 'BAT1_V_EMPTY', 3.5999999046325684)
   (244000, 'BAT1_V_LOAD_DROP', 0.10000000149011612)
   (244000, 'BAT_AVRG_CURRENT', 15.0)
   (244000, 'BAT_CRIT_THR', 0.07000000029802322)
   (244000, 'BAT_EMERGEN_THR', 0.05000000074505806)
   (244000, 'BAT_LOW_THR', 0.15000000596046448)
   (244000, 'BAT_N_CELLS', 3)
   (244000, 'BAT_V_CHARGED', 4.050000190734863)
   (244000, 'BAT_V_EMPTY', 3.5999999046325684)
   (244000, 'BAT_V_LOAD_DROP', 0.30000001192092896)
   (244000, 'CAL_ACC0_ID', 1310988)
   (244000, 'CAL_ACC1_ID', 1310996)
   (244000, 'CAL_ACC2_ID', 1311004)
   (244000, 'CAL_GYRO0_ID', 1310988)
   (244000, 'CAL_GYRO1_ID', 1310996)
   (244000, 'CAL_GYRO2_ID', 1311004)
   (244000, 'CAL_MAG0_ID', 197388)
   (244000, 'CAL_MAG0_PRIO', 50)
   (244000, 'CAL_MAG1_ID', 197644)
   (244000, 'CAL_MAG1_PRIO', 50)
   (244000, 'CA_AIRFRAME', 0)
   (244000, 'CA_FAILURE_MODE', 0)
   (244000, 'CA_METHOD', 2)
   (244000, 'CA_R0_SLEW', 0.0)
   (244000, 'CA_R10_SLEW', 0.0)
   (244000, 'CA_R11_SLEW', 0.0)
   (244000, 'CA_R1_SLEW', 0.0)
   (244000, 'CA_R2_SLEW', 0.0)
   (244000, 'CA_R3_SLEW', 0.0)
   (244000, 'CA_R4_SLEW', 0.0)
   (244000, 'CA_R5_SLEW', 0.0)
   (244000, 'CA_R6_SLEW', 0.0)
   (244000, 'CA_R7_SLEW', 0.0)
   (244000, 'CA_R8_SLEW', 0.0)
   (244000, 'CA_R9_SLEW', 0.0)
   (244000, 'CA_ROTOR0_AX', 0.0)
   (244000, 'CA_ROTOR0_AY', 0.0)
   (244000, 'CA_ROTOR0_AZ', -1.0)
   (244000, 'CA_ROTOR0_CT', 6.5)
   (244000, 'CA_ROTOR0_KM', 0.05000000074505806)
   (244000, 'CA_ROTOR0_PX', 0.15000000596046448)
   (244000, 'CA_ROTOR0_PY', 0.15000000596046448)
   (244000, 'CA_ROTOR0_PZ', 0.0)
   (244000, 'CA_ROTOR10_AX', 0.0)
   (244000, 'CA_ROTOR10_AY', 0.0)
   (244000, 'CA_ROTOR10_AZ', -1.0)
   (244000, 'CA_ROTOR10_CT', 6.5)
   (244000, 'CA_ROTOR10_KM', 0.05000000074505806)
   (244000, 'CA_ROTOR10_PX', 0.0)
   (244000, 'CA_ROTOR10_PY', 0.0)
   (244000, 'CA_ROTOR10_PZ', 0.0)
   (244000, 'CA_ROTOR11_AX', 0.0)
   (244000, 'CA_ROTOR11_AY', 0.0)
   (244000, 'CA_ROTOR11_AZ', -1.0)
   (244000, 'CA_ROTOR11_CT', 6.5)
   (244000, 'CA_ROTOR11_KM', 0.05000000074505806)
   (244000, 'CA_ROTOR11_PX', 0.0)
   (244000, 'CA_ROTOR11_PY', 0.0)
   (244000, 'CA_ROTOR11_PZ', 0.0)
   (244000, 'CA_ROTOR1_AX', 0.0)
   (244000, 'CA_ROTOR1_AY', 0.0)
   (244000, 'CA_ROTOR1_AZ', -1.0)
   (244000, 'CA_ROTOR1_CT', 6.5)
   (244000, 'CA_ROTOR1_KM', 0.05000000074505806)
   (244000, 'CA_ROTOR1_PX', -0.15000000596046448)
   (244000, 'CA_ROTOR1_PY', -0.15000000596046448)
   (244000, 'CA_ROTOR1_PZ', 0.0)
   (244000, 'CA_ROTOR2_AX', 0.0)
   (244000, 'CA_ROTOR2_AY', 0.0)
   (244000, 'CA_ROTOR2_AZ', -1.0)
   (244000, 'CA_ROTOR2_CT', 6.5)
   (244000, 'CA_ROTOR2_KM', -0.05000000074505806)
   (244000, 'CA_ROTOR2_PX', 0.15000000596046448)
   (244000, 'CA_ROTOR2_PY', -0.15000000596046448)
   (244000, 'CA_ROTOR2_PZ', 0.0)
   (244000, 'CA_ROTOR3_AX', 0.0)
   (244000, 'CA_ROTOR3_AY', 0.0)
   (244000, 'CA_ROTOR3_AZ', -1.0)
   (244000, 'CA_ROTOR3_CT', 6.5)
   (244000, 'CA_ROTOR3_KM', -0.05000000074505806)
   (244000, 'CA_ROTOR3_PX', -0.15000000596046448)
   (244000, 'CA_ROTOR3_PY', 0.15000000596046448)
   (244000, 'CA_ROTOR3_PZ', 0.0)
   (244000, 'CA_ROTOR4_AX', 0.0)
   (244000, 'CA_ROTOR4_AY', 0.0)
   (244000, 'CA_ROTOR4_AZ', -1.0)
   (244000, 'CA_ROTOR4_CT', 6.5)
   (244000, 'CA_ROTOR4_KM', 0.05000000074505806)
   (244000, 'CA_ROTOR4_PX', 0.0)
   (244000, 'CA_ROTOR4_PY', 0.0)
   (244000, 'CA_ROTOR4_PZ', 0.0)
   (244000, 'CA_ROTOR5_AX', 0.0)
   (244000, 'CA_ROTOR5_AY', 0.0)
   (244000, 'CA_ROTOR5_AZ', -1.0)
   (244000, 'CA_ROTOR5_CT', 6.5)
   (244000, 'CA_ROTOR5_KM', 0.05000000074505806)
   (244000, 'CA_ROTOR5_PX', 0.0)
   (244000, 'CA_ROTOR5_PY', 0.0)
   (244000, 'CA_ROTOR5_PZ', 0.0)
   (244000, 'CA_ROTOR6_AX', 0.0)
   (244000, 'CA_ROTOR6_AY', 0.0)
   (244000, 'CA_ROTOR6_AZ', -1.0)
   (244000, 'CA_ROTOR6_CT', 6.5)
   (244000, 'CA_ROTOR6_KM', 0.05000000074505806)
   (244000, 'CA_ROTOR6_PX', 0.0)
   (244000, 'CA_ROTOR6_PY', 0.0)
   (244000, 'CA_ROTOR6_PZ', 0.0)
   (244000, 'CA_ROTOR7_AX', 0.0)
   (244000, 'CA_ROTOR7_AY', 0.0)
   (244000, 'CA_ROTOR7_AZ', -1.0)
   (244000, 'CA_ROTOR7_CT', 6.5)
   (244000, 'CA_ROTOR7_KM', 0.05000000074505806)
   (244000, 'CA_ROTOR7_PX', 0.0)
   (244000, 'CA_ROTOR7_PY', 0.0)
   (244000, 'CA_ROTOR7_PZ', 0.0)
   (244000, 'CA_ROTOR8_AX', 0.0)
   (244000, 'CA_ROTOR8_AY', 0.0)
   (244000, 'CA_ROTOR8_AZ', -1.0)
   (244000, 'CA_ROTOR8_CT', 6.5)
   (244000, 'CA_ROTOR8_KM', 0.05000000074505806)
   (244000, 'CA_ROTOR8_PX', 0.0)
   (244000, 'CA_ROTOR8_PY', 0.0)
   (244000, 'CA_ROTOR8_PZ', 0.0)
   (244000, 'CA_ROTOR9_AX', 0.0)
   (244000, 'CA_ROTOR9_AY', 0.0)
   (244000, 'CA_ROTOR9_AZ', -1.0)
   (244000, 'CA_ROTOR9_CT', 6.5)
   (244000, 'CA_ROTOR9_KM', 0.05000000074505806)
   (244000, 'CA_ROTOR9_PX', 0.0)
   (244000, 'CA_ROTOR9_PY', 0.0)
   (244000, 'CA_ROTOR9_PZ', 0.0)
   (244000, 'CA_ROTOR_COUNT', 4)
   (244000, 'CA_R_REV', 0)
   (244000, 'CA_SV0_SLEW', 0.0)
   (244000, 'CA_SV1_SLEW', 0.0)
   (244000, 'CA_SV2_SLEW', 0.0)
   (244000, 'CA_SV3_SLEW', 0.0)
   (244000, 'CA_SV4_SLEW', 0.0)
   (244000, 'CA_SV5_SLEW', 0.0)
   (244000, 'CA_SV6_SLEW', 0.0)
   (244000, 'CA_SV7_SLEW', 0.0)
   (244000, 'CBRK_AIRSPD_CHK', 0)
   (244000, 'CBRK_BUZZER', 0)
   (244000, 'CBRK_FLIGHTTERM', 121212)
   (244000, 'CBRK_IO_SAFETY', 22027)
   (244000, 'CBRK_SUPPLY_CHK', 894281)
   (244000, 'CBRK_USB_CHK', 197848)
   (244000, 'CBRK_VTOLARMING', 0)
   (244000, 'COM_ACT_FAIL_ACT', 0)
   (244000, 'COM_ARM_ARSP_EN', 1)
   (244000, 'COM_ARM_AUTH_ID', 10)
   (244000, 'COM_ARM_AUTH_MET', 0)
   (244000, 'COM_ARM_AUTH_REQ', 0)
   (244000, 'COM_ARM_AUTH_TO', 1.0)
   (244000, 'COM_ARM_CHK_ESCS', 0)
   (244000, 'COM_ARM_EKF_HGT', 1.0)
   (244000, 'COM_ARM_EKF_POS', 0.5)
   (244000, 'COM_ARM_EKF_VEL', 0.5)
   (244000, 'COM_ARM_EKF_YAW', 0.5)
   (244000, 'COM_ARM_HFLT_CHK', 1)
   (244000, 'COM_ARM_IMU_ACC', 0.699999988079071)
   (244000, 'COM_ARM_IMU_GYR', 0.25)
   (244000, 'COM_ARM_MAG_ANG', 60)
   (244000, 'COM_ARM_MAG_STR', 2)
   (244000, 'COM_ARM_MIS_REQ', 0)
   (244000, 'COM_ARM_SDCARD', 1)
   (244000, 'COM_ARM_SWISBTN', 0)
   (244000, 'COM_ARM_WO_GPS', 1)
   (244000, 'COM_CPU_MAX', -1.0)
   (244000, 'COM_DISARM_LAND', 2.0)
   (244000, 'COM_DISARM_PRFLT', 10.0)
   (244000, 'COM_DL_LOSS_T', 10)
   (244000, 'COM_FAIL_ACT_T', 5.0)
   (244000, 'COM_FLT_PROFILE', 0)
   (244000, 'COM_FLT_TIME_MAX', -1)
   (244000, 'COM_FORCE_SAFETY', 0)
   (244000, 'COM_HLDL_LOSS_T', 120)
   (244000, 'COM_HLDL_REG_T', 0)
   (244000, 'COM_HOME_EN', 1)
   (244000, 'COM_HOME_IN_AIR', 0)
   (244000, 'COM_IMB_PROP_ACT', 0)
   (244000, 'COM_KILL_DISARM', 5.0)
   (244000, 'COM_LKDOWN_TKO', 3.0)
   (244000, 'COM_LOW_BAT_ACT', 2)
   (244000, 'COM_MOT_TEST_EN', 1)
   (244000, 'COM_OBC_LOSS_T', 5.0)
   (244000, 'COM_OBL_RC_ACT', 0)
   (244000, 'COM_OBS_AVOID', 0)
   (244000, 'COM_OF_LOSS_T', 1.0)
   (244000, 'COM_PARACHUTE', 0)
   (244000, 'COM_POSCTL_NAVL', 0)
   (244000, 'COM_POS_FS_DELAY', 1)
   (244000, 'COM_POS_FS_EPH', 5.0)
   (244000, 'COM_POS_LOW_EPH', -1.0)
   (244000, 'COM_POWER_COUNT', 1)
   (244000, 'COM_PREARM_MODE', 0)
   (244000, 'COM_QC_ACT', 0)
   (244000, 'COM_RCL_EXCEPT', 0)
   (244000, 'COM_RC_ARM_HYST', 1000)
   (244000, 'COM_RC_IN_MODE', 1)
   (244000, 'COM_RC_LOSS_T', 0.5)
   (244000, 'COM_RC_OVERRIDE', 1)
   (244000, 'COM_RC_STICK_OV', 30.0)
   (244000, 'COM_SPOOLUP_TIME', 1.0)
   (244000, 'COM_TAKEOFF_ACT', 0)
   (244000, 'COM_VEL_FS_EVH', 1.0)
   (244000, 'COM_WIND_MAX', -1.0)
   (244000, 'COM_WIND_WARN', -1.0)
   (244000, 'CP_DELAY', 0.4000000059604645)
   (244000, 'CP_DIST', -1.0)
   (244000, 'CP_GO_NO_DATA', 0)
   (244000, 'CP_GUIDE_ANG', 30.0)
   (244000, 'EKF2_ABIAS_INIT', 0.20000000298023224)
   (244000, 'EKF2_ABL_ACCLIM', 25.0)
   (244000, 'EKF2_ABL_GYRLIM', 3.0)
   (244000, 'EKF2_ABL_LIM', 0.4000000059604645)
   (244000, 'EKF2_ABL_TAU', 0.5)
   (244000, 'EKF2_ACC_B_NOISE', 0.003000000026077032)
   (244000, 'EKF2_ACC_NOISE', 0.3499999940395355)
   (244000, 'EKF2_AID_MASK', 0)
   (244000, 'EKF2_ANGERR_INIT', 0.10000000149011612)
   (244000, 'EKF2_ARSP_THR', 0.0)
   (244000, 'EKF2_ASPD_MAX', 20.0)
   (244000, 'EKF2_ASP_DELAY', 100.0)
   (244000, 'EKF2_AVEL_DELAY', 5.0)
   (244000, 'EKF2_BARO_CTRL', 1)
   (244000, 'EKF2_BARO_DELAY', 0.0)
   (244000, 'EKF2_BARO_GATE', 5.0)
   (244000, 'EKF2_BARO_NOISE', 3.5)
   (244000, 'EKF2_BCOEF_X', 100.0)
   (244000, 'EKF2_BCOEF_Y', 100.0)
   (244000, 'EKF2_BETA_GATE', 5.0)
   (244000, 'EKF2_BETA_NOISE', 0.30000001192092896)
   (244000, 'EKF2_DECL_TYPE', 7)
   (244000, 'EKF2_DRAG_CTRL', 0)
   (244000, 'EKF2_DRAG_NOISE', 2.5)
   (244000, 'EKF2_EAS_NOISE', 1.399999976158142)
   (244000, 'EKF2_EVA_NOISE', 0.10000000149011612)
   (244000, 'EKF2_EVP_GATE', 5.0)
   (244000, 'EKF2_EVP_NOISE', 0.10000000149011612)
   (244000, 'EKF2_EVV_GATE', 3.0)
   (244000, 'EKF2_EVV_NOISE', 0.10000000149011612)
   (244000, 'EKF2_EV_CTRL', 15)
   (244000, 'EKF2_EV_DELAY', 0.0)
   (244000, 'EKF2_EV_NOISE_MD', 0)
   (244000, 'EKF2_EV_POS_X', 0.0)
   (244000, 'EKF2_EV_POS_Y', 0.0)
   (244000, 'EKF2_EV_POS_Z', 0.0)
   (244000, 'EKF2_EV_QMIN', 0)
   (244000, 'EKF2_FUSE_BETA', 0)
   (244000, 'EKF2_GBIAS_INIT', 0.10000000149011612)
   (244000, 'EKF2_GND_EFF_DZ', 4.0)
   (244000, 'EKF2_GND_MAX_HGT', 0.5)
   (244000, 'EKF2_GPS_CHECK', 245)
   (244000, 'EKF2_GPS_CTRL', 7)
   (244000, 'EKF2_GPS_DELAY', 110.0)
   (244000, 'EKF2_GPS_POS_X', 0.0)
   (244000, 'EKF2_GPS_POS_Y', 0.0)
   (244000, 'EKF2_GPS_POS_Z', 0.0)
   (244000, 'EKF2_GPS_P_GATE', 5.0)
   (244000, 'EKF2_GPS_P_NOISE', 0.5)
   (244000, 'EKF2_GPS_V_GATE', 5.0)
   (244000, 'EKF2_GPS_V_NOISE', 0.30000001192092896)
   (244000, 'EKF2_GRAV_NOISE', 1.0)
   (244000, 'EKF2_GSF_TAS', 15.0)
   (244000, 'EKF2_GYR_B_LIM', 0.15000000596046448)
   (244000, 'EKF2_GYR_B_NOISE', 0.0010000000474974513)
   (244000, 'EKF2_GYR_NOISE', 0.014999999664723873)
   (244000, 'EKF2_HDG_GATE', 2.5999999046325684)
   (244000, 'EKF2_HEAD_NOISE', 0.30000001192092896)
   (244000, 'EKF2_HGT_REF', 1)
   (244000, 'EKF2_IMU_CTRL', 3)
   (244000, 'EKF2_IMU_POS_X', 0.0)
   (244000, 'EKF2_IMU_POS_Y', 0.0)
   (244000, 'EKF2_IMU_POS_Z', 0.0)
   (244000, 'EKF2_MAG_ACCLIM', 0.5)
   (244000, 'EKF2_MAG_B_NOISE', 9.999999747378752e-05)
   (244000, 'EKF2_MAG_CHECK', 1)
   (244000, 'EKF2_MAG_DECL', 0.0)
   (244000, 'EKF2_MAG_DELAY', 0.0)
   (244000, 'EKF2_MAG_E_NOISE', 0.0010000000474974513)
   (244000, 'EKF2_MAG_GATE', 3.0)
   (244000, 'EKF2_MAG_NOISE', 0.05000000074505806)
   (244000, 'EKF2_MAG_TYPE', 0)
   (244000, 'EKF2_MAG_YAWLIM', 0.20000000298023224)
   (244000, 'EKF2_MCOEF', 0.15000000596046448)
   (244000, 'EKF2_MIN_RNG', 0.10000000149011612)
   (244000, 'EKF2_MULTI_IMU', 3)
   (244000, 'EKF2_NOAID_NOISE', 10.0)
   (244000, 'EKF2_NOAID_TOUT', 5000000)
   (244000, 'EKF2_OF_CTRL', 0)
   (244000, 'EKF2_OF_DELAY', 20.0)
   (244000, 'EKF2_OF_GATE', 3.0)
   (244000, 'EKF2_OF_N_MAX', 0.5)
   (244000, 'EKF2_OF_N_MIN', 0.15000000596046448)
   (244000, 'EKF2_OF_POS_X', 0.0)
   (244000, 'EKF2_OF_POS_Y', 0.0)
   (244000, 'EKF2_OF_POS_Z', 0.0)
   (244000, 'EKF2_OF_QMIN', 1)
   (244000, 'EKF2_OF_QMIN_GND', 0)
   (244000, 'EKF2_PCOEF_XN', 0.0)
   (244000, 'EKF2_PCOEF_XP', 0.0)
   (244000, 'EKF2_PCOEF_YN', 0.0)
   (244000, 'EKF2_PCOEF_YP', 0.0)
   (244000, 'EKF2_PCOEF_Z', 0.0)
   (244000, 'EKF2_PREDICT_US', 10000)
   (244000, 'EKF2_REQ_EPH', 3.0)
   (244000, 'EKF2_REQ_EPV', 5.0)
   (244000, 'EKF2_REQ_GPS_H', 0.5)
   (244000, 'EKF2_REQ_HDRIFT', 0.10000000149011612)
   (244000, 'EKF2_REQ_NSATS', 6)
   (244000, 'EKF2_REQ_PDOP', 2.5)
   (244000, 'EKF2_REQ_SACC', 0.5)
   (244000, 'EKF2_REQ_VDRIFT', 0.20000000298023224)
   (244000, 'EKF2_RNG_A_HMAX', 5.0)
   (244000, 'EKF2_RNG_A_IGATE', 1.0)
   (244000, 'EKF2_RNG_A_VMAX', 1.0)
   (244000, 'EKF2_RNG_CTRL', 1)
   (244000, 'EKF2_RNG_DELAY', 5.0)
   (244000, 'EKF2_RNG_GATE', 5.0)
   (244000, 'EKF2_RNG_K_GATE', 1.0)
   (244000, 'EKF2_RNG_NOISE', 0.10000000149011612)
   (244000, 'EKF2_RNG_PITCH', 0.0)
   (244000, 'EKF2_RNG_POS_X', 0.0)
   (244000, 'EKF2_RNG_POS_Y', 0.0)
   (244000, 'EKF2_RNG_POS_Z', 0.0)
   (244000, 'EKF2_RNG_QLTY_T', 1.0)
   (244000, 'EKF2_RNG_SFE', 0.05000000074505806)
   (244000, 'EKF2_SEL_ERR_RED', 0.20000000298023224)
   (244000, 'EKF2_SEL_IMU_ACC', 1.0)
   (244000, 'EKF2_SEL_IMU_ANG', 15.0)
   (244000, 'EKF2_SEL_IMU_RAT', 7.0)
   (244000, 'EKF2_SEL_IMU_VEL', 2.0)
   (244000, 'EKF2_SYNT_MAG_Z', 0)
   (244000, 'EKF2_TAS_GATE', 3.0)
   (244000, 'EKF2_TAU_POS', 0.25)
   (244000, 'EKF2_TAU_VEL', 0.25)
   (244000, 'EKF2_TERR_GRAD', 0.5)
   (244000, 'EKF2_TERR_MASK', 3)
   (244000, 'EKF2_TERR_NOISE', 5.0)
   (244000, 'EKF2_WIND_NSD', 0.009999999776482582)
   (244000, 'FD_ACT_EN', 1)
   (244000, 'FD_ACT_MOT_C2T', 2.0)
   (244000, 'FD_ACT_MOT_THR', 0.20000000298023224)
   (244000, 'FD_ACT_MOT_TOUT', 100)
   (244000, 'FD_ESCS_EN', 1)
   (244000, 'FD_EXT_ATS_EN', 0)
   (244000, 'FD_EXT_ATS_TRIG', 1900)
   (244000, 'FD_FAIL_P', 60)
   (244000, 'FD_FAIL_P_TTRI', 0.30000001192092896)
   (244000, 'FD_FAIL_R', 60)
   (244000, 'FD_FAIL_R_TTRI', 0.30000001192092896)
   (244000, 'FD_IMB_PROP_THR', 30)
   (244000, 'FLW_TGT_ALT_M', 0)
   (244000, 'FLW_TGT_DST', 8.0)
   (244000, 'FLW_TGT_FA', 180.0)
   (244000, 'FLW_TGT_HT', 8.0)
   (244000, 'FLW_TGT_MAX_VEL', 5.0)
   (244000, 'FLW_TGT_RS', 0.10000000149011612)
   (244000, 'FW_AIRSPD_MAX', 20.0)
   (244000, 'FW_AIRSPD_TRIM', 15.0)
   (244000, 'FW_ARSP_MODE', 0)
   (244000, 'FW_PSP_OFF', 0.0)
   (244000, 'FW_T_CLMB_R_SP', 3.0)
   (244000, 'FW_T_SINK_R_SP', 2.0)
   (244000, 'GF_ACTION', 2)
   (244000, 'GF_ALTMODE', 0)
   (244000, 'GF_COUNT', -1)
   (244000, 'GF_MAX_HOR_DIST', 0.0)
   (244000, 'GF_MAX_VER_DIST', 0.0)
   (244000, 'GF_PREDICT', 0)
   (244000, 'GF_SOURCE', 0)
   (244000, 'GND_SPEED_THR_SC', 1.0)
   (244000, 'GPS_UBX_DYNMODEL', 6)
   (244000, 'HTE_ACC_GATE', 3.0)
   (244000, 'HTE_HT_ERR_INIT', 0.10000000149011612)
   (244000, 'HTE_HT_NOISE', 0.003599999938160181)
   (244000, 'HTE_THR_RANGE', 0.20000000298023224)
   (244000, 'HTE_VXY_THR', 10.0)
   (244000, 'HTE_VZ_THR', 2.0)
   (244000, 'IMU_ACCEL_CUTOFF', 30.0)
   (244000, 'IMU_DGYRO_CUTOFF', 30.0)
   (244000, 'IMU_GYRO_CAL_EN', 1)
   (244000, 'IMU_GYRO_CUTOFF', 40.0)
   (244000, 'IMU_GYRO_DNF_BW', 15.0)
   (244000, 'IMU_GYRO_DNF_EN', 0)
   (244000, 'IMU_GYRO_DNF_HMC', 3)
   (244000, 'IMU_GYRO_DNF_MIN', 25.0)
   (244000, 'IMU_GYRO_FFT_EN', 1)
   (244000, 'IMU_GYRO_FFT_LEN', 512)
   (244000, 'IMU_GYRO_FFT_MAX', 150.0)
   (244000, 'IMU_GYRO_FFT_MIN', 30.0)
   (244000, 'IMU_GYRO_FFT_SNR', 10.0)
   (244000, 'IMU_GYRO_NF0_BW', 20.0)
   (244000, 'IMU_GYRO_NF0_FRQ', 0.0)
   (244000, 'IMU_GYRO_NF1_BW', 20.0)
   (244000, 'IMU_GYRO_NF1_FRQ', 0.0)
   (244000, 'IMU_GYRO_RATEMAX', 800)
   (244000, 'IMU_INTEG_RATE', 250)
   (244000, 'LNDMC_ALT_GND', 2.0)
   (244000, 'LNDMC_ALT_MAX', -1.0)
   (244000, 'LNDMC_ROT_MAX', 20.0)
   (244000, 'LNDMC_TRIG_TIME', 1.0)
   (244000, 'LNDMC_XY_VEL_MAX', 1.5)
   (244000, 'LNDMC_Z_VEL_MAX', 0.25)
   (244000, 'MAN_ARM_GESTURE', 1)
   (244000, 'MAV_COMP_ID', 1)
   (244000, 'MAV_FWDEXTSP', 1)
   (244000, 'MAV_HASH_CHK_EN', 1)
   (244000, 'MAV_HB_FORW_EN', 1)
   (244000, 'MAV_PROTO_VER', 2)
   (244000, 'MAV_RADIO_TOUT', 5)
   (244000, 'MAV_SIK_RADIO_ID', 0)
   (244000, 'MAV_SYS_ID', 4)
   (244000, 'MAV_TYPE', 2)
   (244000, 'MAV_USEHILGPS', 0)
   (244000, 'MC_ACRO_EXPO', 0.6899999976158142)
   (244000, 'MC_ACRO_EXPO_Y', 0.6899999976158142)
   (244000, 'MC_ACRO_P_MAX', 720.0)
   (244000, 'MC_ACRO_R_MAX', 720.0)
   (244000, 'MC_ACRO_SUPEXPO', 0.699999988079071)
   (244000, 'MC_ACRO_SUPEXPOY', 0.699999988079071)
   (244000, 'MC_ACRO_Y_MAX', 540.0)
   (244000, 'MC_AIRMODE', 0)
   (244000, 'MC_AT_APPLY', 1)
   (244000, 'MC_AT_EN', 1)
   (244000, 'MC_AT_RISE_TIME', 0.14000000059604645)
   (244000, 'MC_AT_START', 0)
   (244000, 'MC_AT_SYSID_AMP', 0.699999988079071)
   (244000, 'MC_BAT_SCALE_EN', 0)
   (244000, 'MC_MAN_TILT_TAU', 0.0)
   (244000, 'MC_ORBIT_RAD_MAX', 1000.0)
   (244000, 'MC_PITCHRATE_D', 0.003000000026077032)
   (244000, 'MC_PITCHRATE_FF', 0.0)
   (244000, 'MC_PITCHRATE_I', 0.20000000298023224)
   (244000, 'MC_PITCHRATE_K', 1.0)
   (244000, 'MC_PITCHRATE_MAX', 220.0)
   (244000, 'MC_PITCHRATE_P', 0.15000000596046448)
   (244000, 'MC_PITCH_P', 6.5)
   (244000, 'MC_PR_INT_LIM', 0.30000001192092896)
   (244000, 'MC_ROLLRATE_D', 0.003000000026077032)
   (244000, 'MC_ROLLRATE_FF', 0.0)
   (244000, 'MC_ROLLRATE_I', 0.20000000298023224)
   (244000, 'MC_ROLLRATE_K', 1.0)
   (244000, 'MC_ROLLRATE_MAX', 220.0)
   (244000, 'MC_ROLLRATE_P', 0.15000000596046448)
   (244000, 'MC_ROLL_P', 6.5)
   (244000, 'MC_RR_INT_LIM', 0.30000001192092896)
   (244000, 'MC_YAWRATE_D', 0.0)
   (244000, 'MC_YAWRATE_FF', 0.0)
   (244000, 'MC_YAWRATE_I', 0.10000000149011612)
   (244000, 'MC_YAWRATE_K', 1.0)
   (244000, 'MC_YAWRATE_MAX', 200.0)
   (244000, 'MC_YAWRATE_P', 0.20000000298023224)
   (244000, 'MC_YAW_P', 2.799999952316284)
   (244000, 'MC_YAW_WEIGHT', 0.4000000059604645)
   (244000, 'MC_YR_INT_LIM', 0.30000001192092896)
   (244000, 'MIS_DIST_1WP', 900.0)
   (244000, 'MIS_LND_ABRT_ALT', 30)
   (244000, 'MIS_MNT_YAW_CTL', 0)
   (244000, 'MIS_PD_TO', 5.0)
   (244000, 'MIS_TAKEOFF_ALT', 2.5)
   (244000, 'MIS_TKO_LAND_REQ', 0)
   (244000, 'MIS_YAW_ERR', 12.0)
   (244000, 'MIS_YAW_TMT', -1.0)
   (244000, 'MNT_MODE_IN', -1)
   (244000, 'MOT_SLEW_MAX', 0.0)
   (244000, 'MPC_ACC_DOWN_MAX', 3.0)
   (244000, 'MPC_ACC_HOR', 3.0)
   (244000, 'MPC_ACC_HOR_MAX', 5.0)
   (244000, 'MPC_ACC_UP_MAX', 4.0)
   (244000, 'MPC_ALT_MODE', 0)
   (244000, 'MPC_HOLD_DZ', 0.10000000149011612)
   (244000, 'MPC_HOLD_MAX_XY', 0.800000011920929)
   (244000, 'MPC_HOLD_MAX_Z', 0.6000000238418579)
   (244000, 'MPC_JERK_AUTO', 4.0)
   (244000, 'MPC_JERK_MAX', 8.0)
   (244000, 'MPC_LAND_ALT1', 10.0)
   (244000, 'MPC_LAND_ALT2', 5.0)
   (244000, 'MPC_LAND_ALT3', 1.0)
   (244000, 'MPC_LAND_CRWL', 0.30000001192092896)
   (244000, 'MPC_LAND_RADIUS', 1000.0)
   (244000, 'MPC_LAND_RC_HELP', 0)
   (244000, 'MPC_LAND_SPEED', 0.699999988079071)
   (244000, 'MPC_MANTHR_MIN', 0.07999999821186066)
   (244000, 'MPC_MAN_TILT_MAX', 35.0)
   (244000, 'MPC_MAN_Y_MAX', 150.0)
   (244000, 'MPC_MAN_Y_TAU', 0.07999999821186066)
   (244000, 'MPC_POS_MODE', 4)
   (244000, 'MPC_THR_CURVE', 0)
   (244000, 'MPC_THR_HOVER', 0.5)
   (244000, 'MPC_THR_MAX', 1.0)
   (244000, 'MPC_THR_MIN', 0.11999999731779099)
   (244000, 'MPC_THR_XY_MARG', 0.30000001192092896)
   (244000, 'MPC_TILTMAX_AIR', 45.0)
   (244000, 'MPC_TILTMAX_LND', 12.0)
   (244000, 'MPC_TKO_RAMP_T', 3.0)
   (244000, 'MPC_TKO_SPEED', 1.5)
   (244000, 'MPC_USE_HTE', 1)
   (244000, 'MPC_VELD_LP', 5.0)
   (244000, 'MPC_VEL_MANUAL', 10.0)
   (244000, 'MPC_VEL_MAN_BACK', -1.0)
   (244000, 'MPC_VEL_MAN_SIDE', -1.0)
   (244000, 'MPC_XY_CRUISE', 5.0)
   (244000, 'MPC_XY_ERR_MAX', 2.0)
   (244000, 'MPC_XY_MAN_EXPO', 0.6000000238418579)
   (244000, 'MPC_XY_P', 0.949999988079071)
   (244000, 'MPC_XY_TRAJ_P', 0.5)
   (244000, 'MPC_XY_VEL_ALL', -10.0)
   (244000, 'MPC_XY_VEL_D_ACC', 0.20000000298023224)
   (244000, 'MPC_XY_VEL_I_ACC', 0.4000000059604645)
   (244000, 'MPC_XY_VEL_MAX', 12.0)
   (244000, 'MPC_XY_VEL_P_ACC', 1.7999999523162842)
   (244000, 'MPC_YAWRAUTO_MAX', 45.0)
   (244000, 'MPC_YAW_EXPO', 0.6000000238418579)
   (244000, 'MPC_YAW_MODE', 0)
   (244000, 'MPC_Z_MAN_EXPO', 0.6000000238418579)
   (244000, 'MPC_Z_P', 1.0)
   (244000, 'MPC_Z_VEL_ALL', -3.0)
   (244000, 'MPC_Z_VEL_D_ACC', 0.0)
   (244000, 'MPC_Z_VEL_I_ACC', 2.0)
   (244000, 'MPC_Z_VEL_MAX_DN', 1.5)
   (244000, 'MPC_Z_VEL_MAX_UP', 3.0)
   (244000, 'MPC_Z_VEL_P_ACC', 4.0)
   (244000, 'MPC_Z_V_AUTO_DN', 1.5)
   (244000, 'MPC_Z_V_AUTO_UP', 3.0)
   (244000, 'NAV_ACC_RAD', 2.0)
   (244000, 'NAV_DLL_ACT', 0)
   (244000, 'NAV_FORCE_VT', 1)
   (244000, 'NAV_FW_ALTL_RAD', 5.0)
   (244000, 'NAV_FW_ALT_RAD', 10.0)
   (244000, 'NAV_LOITER_RAD', 80.0)
   (244000, 'NAV_MC_ALT_RAD', 0.800000011920929)
   (244000, 'NAV_MIN_LTR_ALT', -1.0)
   (244000, 'NAV_RCL_ACT', 2)
   (244000, 'NAV_TRAFF_AVOID', 1)
   (244000, 'NAV_TRAFF_A_HOR', 500.0)
   (244000, 'NAV_TRAFF_A_VER', 500.0)
   (244000, 'NAV_TRAFF_COLL_T', 60)
   (244000, 'PD_GRIPPER_EN', 0)
   (244000, 'PLD_BTOUT', 5.0)
   (244000, 'PLD_FAPPR_ALT', 0.10000000149011612)
   (244000, 'PLD_HACC_RAD', 0.20000000298023224)
   (244000, 'PLD_MAX_SRCH', 3)
   (244000, 'PLD_SRCH_ALT', 10.0)
   (244000, 'PLD_SRCH_TOUT', 10.0)
   (244000, 'PWM_MAIN_FUNC1', 101)
   (244000, 'PWM_MAIN_FUNC10', 0)
   (244000, 'PWM_MAIN_FUNC11', 0)
   (244000, 'PWM_MAIN_FUNC12', 0)
   (244000, 'PWM_MAIN_FUNC13', 0)
   (244000, 'PWM_MAIN_FUNC14', 0)
   (244000, 'PWM_MAIN_FUNC15', 0)
   (244000, 'PWM_MAIN_FUNC16', 0)
   (244000, 'PWM_MAIN_FUNC2', 102)
   (244000, 'PWM_MAIN_FUNC3', 103)
   (244000, 'PWM_MAIN_FUNC4', 104)
   (244000, 'PWM_MAIN_FUNC5', 0)
   (244000, 'PWM_MAIN_FUNC6', 0)
   (244000, 'PWM_MAIN_FUNC7', 0)
   (244000, 'PWM_MAIN_FUNC8', 0)
   (244000, 'PWM_MAIN_FUNC9', 0)
   (244000, 'PWM_MAIN_REV', 0)
   (244000, 'RTL_CONE_ANG', 45)
   (244000, 'RTL_DESCEND_ALT', 10.0)
   (244000, 'RTL_HDG_MD', 0)
   (244000, 'RTL_LAND_DELAY', 0.0)
   (244000, 'RTL_LOITER_RAD', 80.0)
   (244000, 'RTL_MIN_DIST', 10.0)
   (244000, 'RTL_PLD_MD', 0)
   (244000, 'RTL_RETURN_ALT', 30.0)
   (244000, 'RTL_TIME_FACTOR', 1.100000023841858)
   (244000, 'RTL_TIME_MARGIN', 100)
   (244000, 'RTL_TYPE', 0)
   (244000, 'SDLOG_BOOT_BAT', 0)
   (244000, 'SDLOG_DIRS_MAX', 7)
   (244000, 'SDLOG_MISSION', 0)
   (244000, 'SDLOG_MODE', 1)
   (244000, 'SDLOG_PROFILE', 131)
   (244000, 'SDLOG_UTC_OFFSET', 0)
   (244000, 'SDLOG_UUID', 1)
   (244000, 'SENS_BARO_QNH', 1013.25)
   (244000, 'SENS_BARO_RATE', 20.0)
   (244000, 'SENS_BOARD_ROT', 0)
   (244000, 'SENS_BOARD_X_OFF', 9.999999974752427e-07)
   (244000, 'SENS_BOARD_Y_OFF', 0.0)
   (244000, 'SENS_BOARD_Z_OFF', 0.0)
   (244000, 'SENS_DPRES_OFF', 0.0010000000474974513)
   (244000, 'SENS_EN_BAROSIM', 1)
   (244000, 'SENS_EN_GPSSIM', 1)
   (244000, 'SENS_EN_MAGSIM', 1)
   (244000, 'SENS_GPS_MASK', 7)
   (244000, 'SENS_GPS_PRIME', 0)
   (244000, 'SENS_GPS_TAU', 10.0)
   (244000, 'SENS_IMU_AUTOCAL', 1)
   (244000, 'SENS_IMU_MODE', 0)
   (244000, 'SENS_MAG_AUTOCAL', 1)
   (244000, 'SENS_MAG_AUTOROT', 1)
   (244000, 'SENS_MAG_MODE', 1)
   (244000, 'SENS_MAG_RATE', 15.0)
   (244000, 'SENS_MAG_SIDES', 63)
   (244000, 'SIH_DISTSNSR_MAX', 100.0)
   (244000, 'SIH_DISTSNSR_MIN', 0.0)
   (244000, 'SIH_DISTSNSR_OVR', -1.0)
   (244000, 'SIH_IXX', 0.02500000037252903)
   (244000, 'SIH_IXY', 0.0)
   (244000, 'SIH_IXZ', 0.0)
   (244000, 'SIH_IYY', 0.02500000037252903)
   (244000, 'SIH_IYZ', 0.0)
   (244000, 'SIH_IZZ', 0.029999999329447746)
   (244000, 'SIH_KDV', 1.0)
   (244000, 'SIH_KDW', 0.02500000037252903)
   (244000, 'SIH_LOC_H0', 32.34000015258789)
   (244000, 'SIH_LOC_LAT0', 454671160)
   (244000, 'SIH_LOC_LON0', -737578370)
   (244000, 'SIH_L_PITCH', 0.20000000298023224)
   (244000, 'SIH_L_ROLL', 0.20000000298023224)
   (244000, 'SIH_MASS', 1.0)
   (244000, 'SIH_Q_MAX', 0.10000000149011612)
   (244000, 'SIH_T_MAX', 5.0)
   (244000, 'SIH_T_TAU', 0.05000000074505806)
   (244000, 'SIH_VEHICLE_TYPE', 0)
   (244000, 'SIM_BARO_OFF_P', 0.0)
   (244000, 'SIM_BARO_OFF_T', 0.0)
   (244000, 'SIM_BAT_DRAIN', 60.0)
   (244000, 'SIM_BAT_MIN_PCT', 50.0)
   (244000, 'SIM_GPS_USED', 10)
   (244000, 'SIM_MAG_OFFSET_X', 0.0)
   (244000, 'SIM_MAG_OFFSET_Y', 0.0)
   (244000, 'SIM_MAG_OFFSET_Z', 0.0)
   (244000, 'SYS_AUTOCONFIG', 0)
   (244000, 'SYS_AUTOSTART', 10040)
   (244000, 'SYS_CAL_TDEL', 24)
   (244000, 'SYS_CAL_TMAX', 10)
   (244000, 'SYS_CAL_TMIN', 5)
   (244000, 'SYS_FAC_CAL_MODE', 0)
   (244000, 'SYS_FAILURE_EN', 1)
   (244000, 'SYS_HAS_BARO', 1)
   (244000, 'SYS_HAS_GPS', 1)
   (244000, 'SYS_HAS_MAG', 1)
   (244000, 'SYS_HAS_NUM_DIST', 0)
   (244000, 'SYS_HITL', 0)
   (244000, 'SYS_MC_EST_GROUP', 2)
   (244000, 'SYS_STCK_EN', 1)
   (244000, 'SYS_VEHICLE_RESP', -0.4000000059604645)
   (244000, 'THR_MDL_FAC', 0.0)
   (244000, 'TRIG_INTERFACE', 3)
   (244000, 'TRIG_MODE', 0)
   (244000, 'UXRCE_DDS_DOM_ID', 0)
   (244000, 'UXRCE_DDS_KEY', 4)
   (244000, 'VTO_LOITER_ALT', 80.0)
   (244000, 'VT_B_DEC_MSS', 2.0)
   (244000, 'WV_EN', 0)
   (244000, 'WV_GAIN', 1.0)
   (244000, 'WV_ROLL_MIN', 1.0)
   (244000, 'WV_YRATE_MAX', 90.0)
default parameters (msg_info default params) available: True
  SYS_AUTOSTART = 10040
  MAV_SYS_ID = 4
  MAV_TYPE = 2
  SDLOG_MODE = 1
  SDLOG_PROFILE = 131
  COM_DISARM_LAND = 2.0
  MIS_TAKEOFF_ALT = 2.5
  SIH_VEHICLE_TYPE = 0
  CA_AIRFRAME = 0
  SYS_HITL = 0

== all logged topics (name: [multi_id:count])
actuator_armed: 0:298
actuator_motors: 0:1451
actuator_outputs: 0:1451
battery_status: 0:725
control_allocator_status: 0:725
cpuload: 0:290
distance_sensor: 0:7247
ekf2_timestamps: 0:36225
estimator_aid_src_baro_hgt: 0:2155
estimator_aid_src_fake_hgt: 0:4
estimator_aid_src_fake_pos: 0:31
estimator_aid_src_gnss_hgt: 0:1161
estimator_aid_src_gnss_pos: 0:1161
estimator_aid_src_gnss_vel: 0:1161
estimator_aid_src_rng_hgt: 0:7202
estimator_attitude: 0:279
estimator_baro_bias: 0:1643
estimator_event_flags: 0:146
estimator_global_position: 0:140
estimator_gps_status: 0:1161
estimator_innovation_test_ratios: 0:18114
estimator_innovation_variances: 0:18114
estimator_innovations: 0:18114
estimator_local_position: 0:289
estimator_rng_hgt_bias: 0:4211
estimator_selector_status: 0:144
estimator_sensor_bias: 0:1567
estimator_states: 0:18114
estimator_status: 0:18114
estimator_status_flags: 0:154
event: 0:36
failsafe_flags: 0:271
failure_detector_status: 0:298
home_position: 0:529
hover_thrust_estimate: 0:1287
landing_gear: 0:5
manual_control_setpoint: 0:1
mission_result: 0:11
parameter_update: 0:1
position_setpoint_triplet: 0:65
rate_ctrl_status: 0:725
rtl_time_estimate: 0:143
sensor_accel: 0:144
sensor_baro: 0:144
sensor_combined: 0:31145
sensor_gps: 0:144
sensor_gyro: 0:144
sensor_gyro_fft: 0:50
sensor_mag: 0:144
sensor_selection: 0:1
sensors_status_imu: 0:725
takeoff_status: 0:11
telemetry_status: 0:144, 1:144, 2:144, 3:144
trajectory_setpoint: 0:725
transponder_report: 0:1
vehicle_acceleration: 0:2900
vehicle_air_data: 0:2156
vehicle_angular_velocity: 0:14493
vehicle_angular_velocity_groundtruth: 0:14493
vehicle_attitude: 0:28079
vehicle_attitude_groundtruth: 0:14493
vehicle_attitude_setpoint: 0:2900
vehicle_command: 0:8
vehicle_command_ack: 0:7
vehicle_constraints: 0:144
vehicle_control_mode: 0:298
vehicle_global_position: 0:17329
vehicle_global_position_groundtruth: 0:1451
vehicle_gps_position: 0:1161
vehicle_imu: 0:290
vehicle_imu_status: 0:145
vehicle_land_detected: 0:152
vehicle_local_position: 0:18114
vehicle_local_position_groundtruth: 0:7247
vehicle_local_position_setpoint: 0:1451
vehicle_magnetometer: 0:2058
vehicle_rates_setpoint: 0:6933
vehicle_status: 0:298
vehicle_thrust_setpoint: 0:7247
vehicle_torque_setpoint: 0:7247

== requested topics: present? instances and message counts
vehicle_status           PRESENT  instance 0: 298 msgs
failsafe_flags           PRESENT  instance 0: 271 msgs
vehicle_status_flags     ABSENT
vehicle_command          PRESENT  instance 0: 8 msgs
vehicle_command_ack      PRESENT  instance 0: 7 msgs
vtol_vehicle_status      ABSENT
vehicle_land_detected    PRESENT  instance 0: 152 msgs
vehicle_gps_position     PRESENT  instance 0: 1161 msgs
sensor_gps               PRESENT  instance 0: 144 msgs
battery_status           PRESENT  instance 0: 725 msgs
estimator_status_flags   PRESENT  instance 0: 154 msgs
log_message              ABSENT
home_position            PRESENT  instance 0: 529 msgs
commander_state          ABSENT
actuator_armed           PRESENT  instance 0: 298 msgs
event                    PRESENT  instance 0: 36 msgs
parameter_update         PRESENT  instance 0: 1 msgs
vehicle_global_position  PRESENT  instance 0: 17329 msgs
vehicle_local_position   PRESENT  instance 0: 18114 msgs

== vehicle_status fields: ['armed_time', 'arming_state', 'avoidance_system_required', 'avoidance_system_valid', 'calibration_enabled', 'component_id', 'failsafe', 'failsafe_and_user_took_over', 'failure_detector_status', 'gcs_connection_lost', 'gcs_connection_lost_counter', 'high_latency_data_link_lost', 'hil_state', 'in_transition_mode', 'in_transition_to_fw', 'is_vtol', 'is_vtol_tailsitter', 'latest_arming_reason', 'latest_disarming_reason', 'nav_state', 'nav_state_timestamp', 'nav_state_user_intention', 'open_drone_id_system_healthy', 'open_drone_id_system_present', 'parachute_system_healthy', 'parachute_system_present', 'power_input_valid', 'pre_flight_checks_pass', 'rc_calibration_in_progress', 'safety_button_available', 'safety_off', 'system_id', 'system_type', 'takeoff_time', 'timestamp', 'usb_connected', 'vehicle_type']

== vehicle_status arming_state / nav_state transitions (boot us, field, old -> new)
  t=92000 us  arming_state: None -> 1
  t=9780000 us  arming_state: 1 -> 2
  t=144164000 us  arming_state: 2 -> 1
  t=92000 us  nav_state: None -> 4
  t=9864000 us  nav_state: 4 -> 17
  t=16476000 us  nav_state: 17 -> 4
  t=85300000 us  nav_state: 4 -> 5
  t=86908000 us  nav_state: 5 -> 4
  t=131732000 us  nav_state: 4 -> 18
  t=144176000 us  nav_state: 18 -> 4
  t=92000 us  nav_state_user_intention: None -> 4
  t=9864000 us  nav_state_user_intention: 4 -> 17
  t=16476000 us  nav_state_user_intention: 17 -> 4
  t=85300000 us  nav_state_user_intention: 4 -> 5
  t=86908000 us  nav_state_user_intention: 5 -> 4
  t=131732000 us  nav_state_user_intention: 4 -> 18
  t=144176000 us  nav_state_user_intention: 18 -> 4
  t=92000 us  failsafe: None -> 0
  t=92000 us  latest_arming_reason: None -> 0
  t=9780000 us  latest_arming_reason: 0 -> 3
  t=92000 us  latest_disarming_reason: None -> 0
  t=144164000 us  latest_disarming_reason: 0 -> 3
  t=92000 us  vehicle_type: None -> 1
  t=92000 us  is_vtol: None -> 0
  t=92000 us  system_id: None -> 4
  t=92000 us  component_id: None -> 1

== vehicle_command fields: ['command', 'confirmation', 'from_external', 'param1', 'param2', 'param3', 'param4', 'param5', 'param6', 'param7', 'source_component', 'source_system', 'target_component', 'target_system', 'timestamp']
  t=88000 cmd=1001 p1=-3 p2=-3 p3=-1 p4=-1 src=4/1 tgt=4/1 from_external=0
  t=9772000 cmd=400 p1=1 p2=0 p3=nan p4=nan src=4/1 tgt=4/1 from_external=0
  t=9844000 cmd=22 p1=nan p2=nan p3=nan p4=nan src=4/1 tgt=4/1 from_external=0
  t=9856000 cmd=400 p1=1 p2=0 p3=nan p4=nan src=4/1 tgt=4/1 from_external=0
  t=85284000 cmd=176 p1=1 p2=4 p3=5 p4=nan src=4/1 tgt=4/1 from_external=0
  t=86888000 cmd=176 p1=1 p2=4 p3=3 p4=nan src=4/1 tgt=4/1 from_external=0
  t=131716000 cmd=21 p1=nan p2=nan p3=nan p4=nan src=4/1 tgt=4/1 from_external=0
  t=144152000 cmd=400 p1=0 p2=0 p3=nan p4=nan src=4/1 tgt=4/1 from_external=0

== vehicle_command_ack fields: ['command', 'from_external', 'result', 'result_param1', 'result_param2', 'target_component', 'target_system', 'timestamp']
  t=9780000 cmd=400 result=0 result_param1=0 result_param2=0 target=4/1 from_external=0
  t=9852000 cmd=22 result=0 result_param1=0 result_param2=0 target=4/1 from_external=0
  t=9864000 cmd=400 result=0 result_param1=0 result_param2=0 target=4/1 from_external=0
  t=85288000 cmd=176 result=0 result_param1=0 result_param2=0 target=4/1 from_external=0
  t=86896000 cmd=176 result=0 result_param1=0 result_param2=0 target=4/1 from_external=0
  t=131720000 cmd=21 result=0 result_param1=0 result_param2=0 target=4/1 from_external=0
  t=144164000 cmd=400 result=0 result_param1=0 result_param2=0 target=4/1 from_external=0

== failsafe_flags: 38 fields
  fields: ['mode_req_angular_velocity', 'mode_req_attitude', 'mode_req_local_alt', 'mode_req_local_position', 'mode_req_local_position_relaxed', 'mode_req_global_position', 'mode_req_mission', 'mode_req_offboard_signal', 'mode_req_home_position', 'mode_req_wind_and_flight_time_compliance', 'mode_req_prevent_arming', 'mode_req_manual_control', 'mode_req_other', 'angular_velocity_invalid', 'attitude_invalid', 'local_altitude_invalid', 'local_position_invalid', 'local_position_invalid_relaxed', 'local_velocity_invalid', 'global_position_invalid', 'auto_mission_missing', 'offboard_control_signal_lost', 'home_position_invalid', 'manual_control_signal_lost', 'gcs_connection_lost', 'battery_warning', 'battery_low_remaining_time', 'battery_unhealthy', 'primary_geofence_breached', 'mission_failure', 'vtol_fixed_wing_system_failure', 'wind_limit_exceeded', 'flight_time_limit_exceeded', 'local_position_accuracy_low', 'fd_critical_failure', 'fd_esc_arming_failure', 'fd_imbalanced_prop', 'fd_motor_failure']
  transitions of any field (t, field, old -> new):
    t=6504000 attitude_invalid: 1 -> 0
    t=920000 local_altitude_invalid: 1 -> 0
    t=7584000 local_position_invalid: 1 -> 0
    t=7584000 local_position_invalid_relaxed: 1 -> 0
    t=7584000 local_velocity_invalid: 1 -> 0
    t=7584000 global_position_invalid: 1 -> 0

== vehicle_land_detected landed / maybe_landed transitions
  t=144000 landed: None -> 1
  t=11516000 landed: 1 -> 0
  t=143980000 landed: 0 -> 1
  t=144000 maybe_landed: None -> 1
  t=11516000 maybe_landed: 1 -> 0
  t=142980000 maybe_landed: 0 -> 1
  t=144000 ground_contact: None -> 1
  t=11716000 ground_contact: 1 -> 0
  t=141980000 ground_contact: 0 -> 1

== vehicle_gps_position: fields include time_utc_usec=True; first non-zero time_utc_usec=None at t=None; fix_type first/last=3/3

== sensor_gps: fields include time_utc_usec=True; first non-zero time_utc_usec=None at t=None; fix_type first/last=3/3

== ULog logged-string messages ('L' records): 22
  t=244000 level=54(INFO) [logger] logger started (mode=all)
  t=244000 level=54(INFO) [logger] Start file log (type: full)
  t=244000 level=54(INFO) [logger] Opened full log file: ./log/2026-10-18/11_18_25.ulg
  t=248000 level=54(INFO) [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
  t=248000 level=54(INFO) [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
  t=248000 level=54(INFO) [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
  t=252000 level=54(INFO) [px4] Startup script returned successfully
  t=7584000 level=54(INFO) [commander] <ESC>[32mReady for takeoff!<ESC>[0m
  t=9780000 level=54(INFO) [commander] Armed by internal command	
  t=9780000 level=54(INFO) [tone_alarm] arming warning
  t=9864000 level=54(INFO) [navigator] Using minimum takeoff altitude: 2.50 m	
  t=11520000 level=54(INFO) [commander] Takeoff detected	
  t=85300000 level=54(INFO) [navigator] RTL HOME activated	
  t=85300000 level=54(INFO) [navigator] RTL: landing at home position.	
  t=85300000 level=54(INFO) [navigator] RTL: climb to 35 m (2 m above destination)	
  t=85400000 level=54(INFO) [navigator] RTL: return at 35 m (2 m above destination)	
  t=85456000 level=54(INFO) [navigator] RTL: descend to 35 m (2 m above destination)	
  t=85552000 level=54(INFO) [navigator] RTL: land at destination	
  t=131720000 level=54(INFO) [commander] Landing at current position	
  t=143984000 level=54(INFO) [commander] Landing detected	
  t=144164000 level=54(INFO) [commander] Disarmed by internal command	
  t=144164000 level=54(INFO) [tone_alarm] notify neutral

== tagged logged-string messages ('C' records): 0

== failsafe_flags values at first and last sample (non-zero only)
  first t=164000: ['mode_req_angular_velocity', 'mode_req_attitude', 'mode_req_local_alt', 'mode_req_local_position', 'mode_req_local_position_relaxed', 'mode_req_global_position', 'mode_req_mission', 'mode_req_offboard_signal', 'mode_req_home_position', 'mode_req_wind_and_flight_time_compliance', 'mode_req_prevent_arming', 'mode_req_manual_control', 'attitude_invalid', 'local_altitude_invalid', 'local_position_invalid', 'local_position_invalid_relaxed', 'local_velocity_invalid', 'global_position_invalid', 'auto_mission_missing', 'offboard_control_signal_lost', 'manual_control_signal_lost', 'gcs_connection_lost']
  last t=144824000: ['mode_req_angular_velocity', 'mode_req_attitude', 'mode_req_local_alt', 'mode_req_local_position', 'mode_req_local_position_relaxed', 'mode_req_global_position', 'mode_req_mission', 'mode_req_offboard_signal', 'mode_req_home_position', 'mode_req_wind_and_flight_time_compliance', 'mode_req_prevent_arming', 'mode_req_manual_control', 'auto_mission_missing', 'offboard_control_signal_lost', 'manual_control_signal_lost', 'gcs_connection_lost']

== event topic fields: ['arguments[0]', 'arguments[10]', 'arguments[11]', 'arguments[12]', 'arguments[13]', 'arguments[14]', 'arguments[15]', 'arguments[16]', 'arguments[17]', 'arguments[18]', 'arguments[19]', 'arguments[1]', 'arguments[20]', 'arguments[21]', 'arguments[22]', 'arguments[23]', 'arguments[24]', 'arguments[2]', 'arguments[3]', 'arguments[4]', 'arguments[5]', 'arguments[6]', 'arguments[7]', 'arguments[8]', 'arguments[9]', 'event_sequence', 'id', 'log_levels', 'timestamp']
```
</details>

<details><summary>vehicle_command CSV (ulog2csv) (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/analysis/csv/mc_flight_vehicle_command_0.csv</code>)</summary>

```text
timestamp,param5,param6,param1,param2,param3,param4,param7,command,target_system,target_component,source_system,source_component,confirmation,from_external
88000,0.0,0.0,-3.0,-3.0,-1.0,-1.0,0.0,1001,4,1,4,1,0,0
9772000,nan,nan,1.0,0.0,nan,nan,nan,400,4,1,4,1,0,0
9844000,nan,nan,nan,nan,nan,nan,nan,22,4,1,4,1,0,0
9856000,nan,nan,1.0,0.0,nan,nan,nan,400,4,1,4,1,0,0
85284000,nan,nan,1.0,4.0,5.0,nan,nan,176,4,1,4,1,0,0
86888000,nan,nan,1.0,4.0,3.0,nan,nan,176,4,1,4,1,0,0
131716000,nan,nan,nan,nan,nan,nan,nan,21,4,1,4,1,0,0
144152000,nan,nan,0.0,0.0,nan,nan,nan,400,4,1,4,1,0,0
```
</details>

<details><summary>vehicle_command_ack CSV (ulog2csv) (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/analysis/csv/mc_flight_vehicle_command_ack_0.csv</code>)</summary>

```text
timestamp,command,result_param2,result,result_param1,target_system,target_component,from_external
9780000,400,0,0,0,4,1,0
9852000,22,0,0,0,4,1,0
9864000,400,0,0,0,4,1,0
85288000,176,0,0,0,4,1,0
86896000,176,0,0,0,4,1,0
131720000,21,0,0,0,4,1,0
144164000,400,0,0,0,4,1,0
```
</details>

<details><summary>ulog_params (name, initial value, value re-emitted at 244000 us) (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/analysis/ulog_params.txt</code>)</summary>

```text
ASPD_SCALE_1,1.0,1.0
BAT1_CAPACITY,-1.0,-1.0
BAT1_N_CELLS,4,4
BAT1_R_INTERNAL,0.004999999888241291,0.004999999888241291
BAT1_SOURCE,0,0
BAT1_V_CHARGED,4.050000190734863,4.050000190734863
BAT1_V_EMPTY,3.5999999046325684,3.5999999046325684
BAT1_V_LOAD_DROP,0.10000000149011612,0.10000000149011612
BAT_AVRG_CURRENT,15.0,15.0
BAT_CRIT_THR,0.07000000029802322,0.07000000029802322
BAT_EMERGEN_THR,0.05000000074505806,0.05000000074505806
BAT_LOW_THR,0.15000000596046448,0.15000000596046448
BAT_N_CELLS,3,3
BAT_V_CHARGED,4.050000190734863,4.050000190734863
BAT_V_EMPTY,3.5999999046325684,3.5999999046325684
BAT_V_LOAD_DROP,0.30000001192092896,0.30000001192092896
CAL_ACC0_ID,1310988,1310988
CAL_ACC0_PRIO,-1
CAL_ACC0_ROT,-1
CAL_ACC0_XOFF,0.0
CAL_ACC0_XSCALE,1.0
CAL_ACC0_YOFF,0.0
CAL_ACC0_YSCALE,1.0
CAL_ACC0_ZOFF,0.0
CAL_ACC0_ZSCALE,1.0
CAL_ACC1_ID,1310996,1310996
CAL_ACC1_PRIO,-1
CAL_ACC1_ROT,-1
CAL_ACC1_XOFF,0.0
CAL_ACC1_XSCALE,1.0
CAL_ACC1_YOFF,0.0
CAL_ACC1_YSCALE,1.0
CAL_ACC1_ZOFF,0.0
CAL_ACC1_ZSCALE,1.0
CAL_ACC2_ID,1311004,1311004
CAL_ACC2_PRIO,-1
CAL_ACC2_ROT,-1
CAL_ACC2_XOFF,0.0
CAL_ACC2_XSCALE,1.0
CAL_ACC2_YOFF,0.0
CAL_ACC2_YSCALE,1.0
CAL_ACC2_ZOFF,0.0
CAL_ACC2_ZSCALE,1.0
CAL_ACC3_ID,0
CAL_AIR_CMODEL,0
CAL_AIR_TUBED_MM,1.5
CAL_AIR_TUBELEN,0.20000000298023224
CAL_BARO0_ID,0
CAL_BARO1_ID,0
CAL_BARO2_ID,0
CAL_BARO3_ID,0
CAL_GYRO0_ID,1310988,1310988
CAL_GYRO0_PRIO,-1
CAL_GYRO0_ROT,-1
CAL_GYRO0_XOFF,0.0
CAL_GYRO0_YOFF,0.0
CAL_GYRO0_ZOFF,0.0
CAL_GYRO1_ID,1310996,1310996
CAL_GYRO1_PRIO,-1
CAL_GYRO1_ROT,-1
CAL_GYRO1_XOFF,0.0
CAL_GYRO1_YOFF,0.0
CAL_GYRO1_ZOFF,0.0
CAL_GYRO2_ID,1311004,1311004
CAL_GYRO2_PRIO,-1
CAL_GYRO2_ROT,-1
CAL_GYRO2_XOFF,0.0
CAL_GYRO2_YOFF,0.0
CAL_GYRO2_ZOFF,0.0
CAL_GYRO3_ID,0
CAL_MAG0_ID,197388,197388
CAL_MAG0_PRIO,50,50
CAL_MAG0_ROT,-1
CAL_MAG0_XCOMP,0.0
CAL_MAG0_XODIAG,0.0
CAL_MAG0_XOFF,0.0
CAL_MAG0_XSCALE,1.0
CAL_MAG0_YCOMP,0.0
CAL_MAG0_YODIAG,0.0
CAL_MAG0_YOFF,0.0
CAL_MAG0_YSCALE,1.0
CAL_MAG0_ZCOMP,0.0
CAL_MAG0_ZODIAG,0.0
CAL_MAG0_ZOFF,0.0
CAL_MAG0_ZSCALE,1.0
CAL_MAG1_ID,197644,197644
CAL_MAG1_PRIO,50,50
CAL_MAG1_ROT,-1
CAL_MAG1_XCOMP,0.0
CAL_MAG1_XODIAG,0.0
CAL_MAG1_XOFF,0.0
CAL_MAG1_XSCALE,1.0
CAL_MAG1_YCOMP,0.0
CAL_MAG1_YODIAG,0.0
CAL_MAG1_YOFF,0.0
CAL_MAG1_YSCALE,1.0
CAL_MAG1_ZCOMP,0.0
CAL_MAG1_ZODIAG,0.0
CAL_MAG1_ZOFF,0.0
CAL_MAG1_ZSCALE,1.0
CAL_MAG2_ID,0
CAL_MAG2_ROT,-1
CAL_MAG3_ID,0
CAL_MAG3_ROT,-1
CAL_MAG_COMP_TYP,0
CAL_MAG_SIDES,63
CA_AIRFRAME,0,0
CA_FAILURE_MODE,0,0
CA_METHOD,2,2
CA_R0_SLEW,0.0,0.0
CA_R10_SLEW,0.0,0.0
CA_R11_SLEW,0.0,0.0
CA_R1_SLEW,0.0,0.0
CA_R2_SLEW,0.0,0.0
CA_R3_SLEW,0.0,0.0
CA_R4_SLEW,0.0,0.0
CA_R5_SLEW,0.0,0.0
CA_R6_SLEW,0.0,0.0
CA_R7_SLEW,0.0,0.0
CA_R8_SLEW,0.0,0.0
CA_R9_SLEW,0.0,0.0
CA_ROTOR0_AX,0.0,0.0
CA_ROTOR0_AY,0.0,0.0
CA_ROTOR0_AZ,-1.0,-1.0
CA_ROTOR0_CT,6.5,6.5
CA_ROTOR0_KM,0.05000000074505806,0.05000000074505806
CA_ROTOR0_PX,0.15000000596046448,0.15000000596046448
CA_ROTOR0_PY,0.15000000596046448,0.15000000596046448
CA_ROTOR0_PZ,0.0,0.0
CA_ROTOR10_AX,0.0,0.0
CA_ROTOR10_AY,0.0,0.0
CA_ROTOR10_AZ,-1.0,-1.0
CA_ROTOR10_CT,6.5,6.5
CA_ROTOR10_KM,0.05000000074505806,0.05000000074505806
CA_ROTOR10_PX,0.0,0.0
CA_ROTOR10_PY,0.0,0.0
CA_ROTOR10_PZ,0.0,0.0
CA_ROTOR11_AX,0.0,0.0
CA_ROTOR11_AY,0.0,0.0
CA_ROTOR11_AZ,-1.0,-1.0
CA_ROTOR11_CT,6.5,6.5
CA_ROTOR11_KM,0.05000000074505806,0.05000000074505806
CA_ROTOR11_PX,0.0,0.0
CA_ROTOR11_PY,0.0,0.0
CA_ROTOR11_PZ,0.0,0.0
CA_ROTOR1_AX,0.0,0.0
CA_ROTOR1_AY,0.0,0.0
CA_ROTOR1_AZ,-1.0,-1.0
CA_ROTOR1_CT,6.5,6.5
CA_ROTOR1_KM,0.05000000074505806,0.05000000074505806
CA_ROTOR1_PX,-0.15000000596046448,-0.15000000596046448
CA_ROTOR1_PY,-0.15000000596046448,-0.15000000596046448
CA_ROTOR1_PZ,0.0,0.0
CA_ROTOR2_AX,0.0,0.0
CA_ROTOR2_AY,0.0,0.0
CA_ROTOR2_AZ,-1.0,-1.0
CA_ROTOR2_CT,6.5,6.5
CA_ROTOR2_KM,-0.05000000074505806,-0.05000000074505806
CA_ROTOR2_PX,0.15000000596046448,0.15000000596046448
CA_ROTOR2_PY,-0.15000000596046448,-0.15000000596046448
CA_ROTOR2_PZ,0.0,0.0
CA_ROTOR3_AX,0.0,0.0
CA_ROTOR3_AY,0.0,0.0
CA_ROTOR3_AZ,-1.0,-1.0
CA_ROTOR3_CT,6.5,6.5
CA_ROTOR3_KM,-0.05000000074505806,-0.05000000074505806
CA_ROTOR3_PX,-0.15000000596046448,-0.15000000596046448
CA_ROTOR3_PY,0.15000000596046448,0.15000000596046448
CA_ROTOR3_PZ,0.0,0.0
CA_ROTOR4_AX,0.0,0.0
CA_ROTOR4_AY,0.0,0.0
CA_ROTOR4_AZ,-1.0,-1.0
CA_ROTOR4_CT,6.5,6.5
CA_ROTOR4_KM,0.05000000074505806,0.05000000074505806
CA_ROTOR4_PX,0.0,0.0
CA_ROTOR4_PY,0.0,0.0
CA_ROTOR4_PZ,0.0,0.0
CA_ROTOR5_AX,0.0,0.0
CA_ROTOR5_AY,0.0,0.0
CA_ROTOR5_AZ,-1.0,-1.0
CA_ROTOR5_CT,6.5,6.5
CA_ROTOR5_KM,0.05000000074505806,0.05000000074505806
CA_ROTOR5_PX,0.0,0.0
CA_ROTOR5_PY,0.0,0.0
CA_ROTOR5_PZ,0.0,0.0
CA_ROTOR6_AX,0.0,0.0
CA_ROTOR6_AY,0.0,0.0
CA_ROTOR6_AZ,-1.0,-1.0
CA_ROTOR6_CT,6.5,6.5
CA_ROTOR6_KM,0.05000000074505806,0.05000000074505806
CA_ROTOR6_PX,0.0,0.0
CA_ROTOR6_PY,0.0,0.0
CA_ROTOR6_PZ,0.0,0.0
CA_ROTOR7_AX,0.0,0.0
CA_ROTOR7_AY,0.0,0.0
CA_ROTOR7_AZ,-1.0,-1.0
CA_ROTOR7_CT,6.5,6.5
CA_ROTOR7_KM,0.05000000074505806,0.05000000074505806
CA_ROTOR7_PX,0.0,0.0
CA_ROTOR7_PY,0.0,0.0
CA_ROTOR7_PZ,0.0,0.0
CA_ROTOR8_AX,0.0,0.0
CA_ROTOR8_AY,0.0,0.0
CA_ROTOR8_AZ,-1.0,-1.0
CA_ROTOR8_CT,6.5,6.5
CA_ROTOR8_KM,0.05000000074505806,0.05000000074505806
CA_ROTOR8_PX,0.0,0.0
CA_ROTOR8_PY,0.0,0.0
CA_ROTOR8_PZ,0.0,0.0
CA_ROTOR9_AX,0.0,0.0
CA_ROTOR9_AY,0.0,0.0
CA_ROTOR9_AZ,-1.0,-1.0
CA_ROTOR9_CT,6.5,6.5
CA_ROTOR9_KM,0.05000000074505806,0.05000000074505806
CA_ROTOR9_PX,0.0,0.0
CA_ROTOR9_PY,0.0,0.0
CA_ROTOR9_PZ,0.0,0.0
CA_ROTOR_COUNT,4,4
CA_R_REV,0,0
CA_SV0_SLEW,0.0,0.0
CA_SV1_SLEW,0.0,0.0
CA_SV2_SLEW,0.0,0.0
CA_SV3_SLEW,0.0,0.0
CA_SV4_SLEW,0.0,0.0
CA_SV5_SLEW,0.0,0.0
CA_SV6_SLEW,0.0,0.0
CA_SV7_SLEW,0.0,0.0
CBRK_AIRSPD_CHK,0,0
CBRK_BUZZER,0,0
CBRK_FLIGHTTERM,121212,121212
CBRK_IO_SAFETY,22027,22027
CBRK_SUPPLY_CHK,894281,894281
CBRK_USB_CHK,197848,197848
CBRK_VTOLARMING,0,0
COM_ACT_FAIL_ACT,0,0
COM_ARM_ARSP_EN,1,1
COM_ARM_AUTH_ID,10,10
COM_ARM_AUTH_MET,0,0
COM_ARM_AUTH_REQ,0,0
COM_ARM_AUTH_TO,1.0,1.0
COM_ARM_CHK_ESCS,0,0
COM_ARM_EKF_HGT,1.0,1.0
COM_ARM_EKF_POS,0.5,0.5
COM_ARM_EKF_VEL,0.5,0.5
COM_ARM_EKF_YAW,0.5,0.5
COM_ARM_HFLT_CHK,1,1
COM_ARM_IMU_ACC,0.699999988079071,0.699999988079071
COM_ARM_IMU_GYR,0.25,0.25
COM_ARM_MAG_ANG,60,60
COM_ARM_MAG_STR,2,2
COM_ARM_MIS_REQ,0,0
COM_ARM_SDCARD,1,1
COM_ARM_SWISBTN,0,0
COM_ARM_WO_GPS,1,1
COM_CPU_MAX,-1.0,-1.0
COM_DISARM_LAND,2.0,2.0
COM_DISARM_PRFLT,10.0,10.0
COM_DL_LOSS_T,10,10
COM_FAIL_ACT_T,5.0,5.0
COM_FLIGHT_UUID,0
COM_FLTMODE1,-1
COM_FLTMODE2,-1
COM_FLTMODE3,-1
COM_FLTMODE4,-1
COM_FLTMODE5,-1
COM_FLTMODE6,-1
COM_FLT_PROFILE,0,0
COM_FLT_TIME_MAX,-1,-1
COM_FORCE_SAFETY,0,0
COM_HLDL_LOSS_T,120,120
COM_HLDL_REG_T,0,0
COM_HOME_EN,1,1
COM_HOME_IN_AIR,0,0
COM_IMB_PROP_ACT,0,0
COM_KILL_DISARM,5.0,5.0
COM_LKDOWN_TKO,3.0,3.0
COM_LOW_BAT_ACT,2,2
COM_MOT_TEST_EN,1,1
COM_OBC_LOSS_T,5.0,5.0
COM_OBL_RC_ACT,0,0
COM_OBS_AVOID,0,0
COM_OF_LOSS_T,1.0,1.0
COM_PARACHUTE,0,0
COM_POSCTL_NAVL,0,0
COM_POS_FS_DELAY,1,1
COM_POS_FS_EPH,5.0,5.0
COM_POS_LOW_EPH,-1.0,-1.0
COM_POWER_COUNT,1,1
COM_PREARM_MODE,0,0
COM_QC_ACT,0,0
COM_RCL_EXCEPT,0,0
COM_RC_ARM_HYST,1000,1000
COM_RC_IN_MODE,1,1
COM_RC_LOSS_T,0.5,0.5
COM_RC_OVERRIDE,1,1
COM_RC_STICK_OV,30.0,30.0
COM_SPOOLUP_TIME,1.0,1.0
COM_TAKEOFF_ACT,0,0
COM_VEL_FS_EVH,1.0,1.0
COM_WIND_MAX,-1.0,-1.0
COM_WIND_WARN,-1.0,-1.0
CP_DELAY,0.4000000059604645,0.4000000059604645
CP_DIST,-1.0,-1.0
CP_GO_NO_DATA,0,0
CP_GUIDE_ANG,30.0,30.0
EKF2_ABIAS_INIT,0.20000000298023224,0.20000000298023224
EKF2_ABL_ACCLIM,25.0,25.0
EKF2_ABL_GYRLIM,3.0,3.0
EKF2_ABL_LIM,0.4000000059604645,0.4000000059604645
EKF2_ABL_TAU,0.5,0.5
EKF2_ACC_B_NOISE,0.003000000026077032,0.003000000026077032
EKF2_ACC_NOISE,0.3499999940395355,0.3499999940395355
EKF2_AID_MASK,0,0
EKF2_ANGERR_INIT,0.10000000149011612,0.10000000149011612
EKF2_ARSP_THR,0.0,0.0
EKF2_ASPD_MAX,20.0,20.0
EKF2_ASP_DELAY,100.0,100.0
EKF2_AVEL_DELAY,5.0,5.0
EKF2_BARO_CTRL,1,1
EKF2_BARO_DELAY,0.0,0.0
EKF2_BARO_GATE,5.0,5.0
EKF2_BARO_NOISE,3.5,3.5
EKF2_BCOEF_X,100.0,100.0
EKF2_BCOEF_Y,100.0,100.0
EKF2_BETA_GATE,5.0,5.0
EKF2_BETA_NOISE,0.30000001192092896,0.30000001192092896
EKF2_DECL_TYPE,7,7
EKF2_DRAG_CTRL,0,0
EKF2_DRAG_NOISE,2.5,2.5
EKF2_EAS_NOISE,1.399999976158142,1.399999976158142
EKF2_EVA_NOISE,0.10000000149011612,0.10000000149011612
EKF2_EVP_GATE,5.0,5.0
EKF2_EVP_NOISE,0.10000000149011612,0.10000000149011612
EKF2_EVV_GATE,3.0,3.0
EKF2_EVV_NOISE,0.10000000149011612,0.10000000149011612
EKF2_EV_CTRL,15,15
EKF2_EV_DELAY,0.0,0.0
EKF2_EV_NOISE_MD,0,0
EKF2_EV_POS_X,0.0,0.0
EKF2_EV_POS_Y,0.0,0.0
EKF2_EV_POS_Z,0.0,0.0
EKF2_EV_QMIN,0,0
EKF2_FUSE_BETA,0,0
EKF2_GBIAS_INIT,0.10000000149011612,0.10000000149011612
EKF2_GND_EFF_DZ,4.0,4.0
EKF2_GND_MAX_HGT,0.5,0.5
EKF2_GPS_CHECK,245,245
EKF2_GPS_CTRL,7,7
EKF2_GPS_DELAY,110.0,110.0
EKF2_GPS_POS_X,0.0,0.0
EKF2_GPS_POS_Y,0.0,0.0
EKF2_GPS_POS_Z,0.0,0.0
EKF2_GPS_P_GATE,5.0,5.0
EKF2_GPS_P_NOISE,0.5,0.5
EKF2_GPS_V_GATE,5.0,5.0
EKF2_GPS_V_NOISE,0.30000001192092896,0.30000001192092896
EKF2_GRAV_NOISE,1.0,1.0
EKF2_GSF_TAS,15.0,15.0
EKF2_GYR_B_LIM,0.15000000596046448,0.15000000596046448
EKF2_GYR_B_NOISE,0.0010000000474974513,0.0010000000474974513
EKF2_GYR_NOISE,0.014999999664723873,0.014999999664723873
EKF2_HDG_GATE,2.5999999046325684,2.5999999046325684
EKF2_HEAD_NOISE,0.30000001192092896,0.30000001192092896
EKF2_HGT_REF,1,1
EKF2_IMU_CTRL,3,3
EKF2_IMU_POS_X,0.0,0.0
EKF2_IMU_POS_Y,0.0,0.0
EKF2_IMU_POS_Z,0.0,0.0
EKF2_MAG_ACCLIM,0.5,0.5
EKF2_MAG_B_NOISE,9.999999747378752e-05,9.999999747378752e-05
EKF2_MAG_CHECK,1,1
EKF2_MAG_DECL,0.0,0.0
EKF2_MAG_DELAY,0.0,0.0
EKF2_MAG_E_NOISE,0.0010000000474974513,0.0010000000474974513
EKF2_MAG_GATE,3.0,3.0
EKF2_MAG_NOISE,0.05000000074505806,0.05000000074505806
EKF2_MAG_TYPE,0,0
EKF2_MAG_YAWLIM,0.20000000298023224,0.20000000298023224
EKF2_MCOEF,0.15000000596046448,0.15000000596046448
EKF2_MIN_RNG,0.10000000149011612,0.10000000149011612
EKF2_MULTI_IMU,3,3
EKF2_NOAID_NOISE,10.0,10.0
EKF2_NOAID_TOUT,5000000,5000000
EKF2_OF_CTRL,0,0
EKF2_OF_DELAY,20.0,20.0
EKF2_OF_GATE,3.0,3.0
EKF2_OF_N_MAX,0.5,0.5
EKF2_OF_N_MIN,0.15000000596046448,0.15000000596046448
EKF2_OF_POS_X,0.0,0.0
EKF2_OF_POS_Y,0.0,0.0
EKF2_OF_POS_Z,0.0,0.0
EKF2_OF_QMIN,1,1
EKF2_OF_QMIN_GND,0,0
EKF2_PCOEF_XN,0.0,0.0
EKF2_PCOEF_XP,0.0,0.0
EKF2_PCOEF_YN,0.0,0.0
EKF2_PCOEF_YP,0.0,0.0
EKF2_PCOEF_Z,0.0,0.0
EKF2_PREDICT_US,10000,10000
EKF2_REQ_EPH,3.0,3.0
EKF2_REQ_EPV,5.0,5.0
EKF2_REQ_GPS_H,0.5,0.5
EKF2_REQ_HDRIFT,0.10000000149011612,0.10000000149011612
EKF2_REQ_NSATS,6,6
EKF2_REQ_PDOP,2.5,2.5
EKF2_REQ_SACC,0.5,0.5
EKF2_REQ_VDRIFT,0.20000000298023224,0.20000000298023224
EKF2_RNG_A_HMAX,5.0,5.0
EKF2_RNG_A_IGATE,1.0,1.0
EKF2_RNG_A_VMAX,1.0,1.0
EKF2_RNG_CTRL,1,1
EKF2_RNG_DELAY,5.0,5.0
EKF2_RNG_GATE,5.0,5.0
EKF2_RNG_K_GATE,1.0,1.0
EKF2_RNG_NOISE,0.10000000149011612,0.10000000149011612
EKF2_RNG_PITCH,0.0,0.0
EKF2_RNG_POS_X,0.0,0.0
EKF2_RNG_POS_Y,0.0,0.0
EKF2_RNG_POS_Z,0.0,0.0
EKF2_RNG_QLTY_T,1.0,1.0
EKF2_RNG_SFE,0.05000000074505806,0.05000000074505806
EKF2_SEL_ERR_RED,0.20000000298023224,0.20000000298023224
EKF2_SEL_IMU_ACC,1.0,1.0
EKF2_SEL_IMU_ANG,15.0,15.0
EKF2_SEL_IMU_RAT,7.0,7.0
EKF2_SEL_IMU_VEL,2.0,2.0
EKF2_SYNT_MAG_Z,0,0
EKF2_TAS_GATE,3.0,3.0
EKF2_TAU_POS,0.25,0.25
EKF2_TAU_VEL,0.25,0.25
EKF2_TERR_GRAD,0.5,0.5
EKF2_TERR_MASK,3,3
EKF2_TERR_NOISE,5.0,5.0
EKF2_WIND_NSD,0.009999999776482582,0.009999999776482582
FD_ACT_EN,1,1
FD_ACT_MOT_C2T,2.0,2.0
FD_ACT_MOT_THR,0.20000000298023224,0.20000000298023224
FD_ACT_MOT_TOUT,100,100
FD_ESCS_EN,1,1
FD_EXT_ATS_EN,0,0
FD_EXT_ATS_TRIG,1900,1900
FD_FAIL_P,60,60
FD_FAIL_P_TTRI,0.30000001192092896,0.30000001192092896
FD_FAIL_R,60,60
FD_FAIL_R_TTRI,0.30000001192092896,0.30000001192092896
FD_IMB_PROP_THR,30,30
FLW_TGT_ALT_M,0,0
FLW_TGT_DST,8.0,8.0
FLW_TGT_FA,180.0,180.0
FLW_TGT_HT,8.0,8.0
FLW_TGT_MAX_VEL,5.0,5.0
FLW_TGT_RS,0.10000000149011612,0.10000000149011612
FW_AIRSPD_MAX,20.0,20.0
FW_AIRSPD_TRIM,15.0,15.0
FW_ARSP_MODE,0,0
FW_PSP_OFF,0.0,0.0
FW_T_CLMB_R_SP,3.0,3.0
FW_T_SINK_R_SP,2.0,2.0
GF_ACTION,2,2
GF_ALTMODE,0,0
GF_COUNT,-1,-1
GF_MAX_HOR_DIST,0.0,0.0
GF_MAX_VER_DIST,0.0,0.0
GF_PREDICT,0,0
GF_SOURCE,0,0
GND_SPEED_THR_SC,1.0,1.0
GPS_UBX_DYNMODEL,6,6
HTE_ACC_GATE,3.0,3.0
HTE_HT_ERR_INIT,0.10000000149011612,0.10000000149011612
HTE_HT_NOISE,0.003599999938160181,0.003599999938160181
HTE_THR_RANGE,0.20000000298023224,0.20000000298023224
HTE_VXY_THR,10.0,10.0
HTE_VZ_THR,2.0,2.0
IMU_ACCEL_CUTOFF,30.0,30.0
IMU_DGYRO_CUTOFF,30.0,30.0
IMU_GYRO_CAL_EN,1,1
IMU_GYRO_CUTOFF,40.0,40.0
IMU_GYRO_DNF_BW,15.0,15.0
IMU_GYRO_DNF_EN,0,0
IMU_GYRO_DNF_HMC,3,3
IMU_GYRO_DNF_MIN,25.0,25.0
IMU_GYRO_FFT_EN,1,1
IMU_GYRO_FFT_LEN,512,512
IMU_GYRO_FFT_MAX,150.0,150.0
IMU_GYRO_FFT_MIN,30.0,30.0
IMU_GYRO_FFT_SNR,10.0,10.0
IMU_GYRO_NF0_BW,20.0,20.0
IMU_GYRO_NF0_FRQ,0.0,0.0
IMU_GYRO_NF1_BW,20.0,20.0
IMU_GYRO_NF1_FRQ,0.0,0.0
IMU_GYRO_RATEMAX,800,800
IMU_INTEG_RATE,250,250
LNDMC_ALT_GND,2.0,2.0
LNDMC_ALT_MAX,-1.0,-1.0
LNDMC_ROT_MAX,20.0,20.0
LNDMC_TRIG_TIME,1.0,1.0
LNDMC_XY_VEL_MAX,1.5,1.5
LNDMC_Z_VEL_MAX,0.25,0.25
LND_FLIGHT_T_HI,0
LND_FLIGHT_T_LO,0
MAN_ARM_GESTURE,1,1
MAV_COMP_ID,1,1
MAV_FWDEXTSP,1,1
MAV_HASH_CHK_EN,1,1
MAV_HB_FORW_EN,1,1
MAV_PROTO_VER,2,2
MAV_RADIO_TOUT,5,5
MAV_SIK_RADIO_ID,0,0
MAV_SYS_ID,4,4
MAV_TYPE,2,2
MAV_USEHILGPS,0,0
MC_ACRO_EXPO,0.6899999976158142,0.6899999976158142
MC_ACRO_EXPO_Y,0.6899999976158142,0.6899999976158142
MC_ACRO_P_MAX,720.0,720.0
MC_ACRO_R_MAX,720.0,720.0
MC_ACRO_SUPEXPO,0.699999988079071,0.699999988079071
MC_ACRO_SUPEXPOY,0.699999988079071,0.699999988079071
MC_ACRO_Y_MAX,540.0,540.0
MC_AIRMODE,0,0
MC_AT_APPLY,1,1
MC_AT_EN,1,1
MC_AT_RISE_TIME,0.14000000059604645,0.14000000059604645
MC_AT_START,0,0
MC_AT_SYSID_AMP,0.699999988079071,0.699999988079071
MC_BAT_SCALE_EN,0,0
MC_MAN_TILT_TAU,0.0,0.0
MC_ORBIT_RAD_MAX,1000.0,1000.0
MC_PITCHRATE_D,0.003000000026077032,0.003000000026077032
MC_PITCHRATE_FF,0.0,0.0
MC_PITCHRATE_I,0.20000000298023224,0.20000000298023224
MC_PITCHRATE_K,1.0,1.0
MC_PITCHRATE_MAX,220.0,220.0
MC_PITCHRATE_P,0.15000000596046448,0.15000000596046448
MC_PITCH_P,6.5,6.5
MC_PR_INT_LIM,0.30000001192092896,0.30000001192092896
MC_ROLLRATE_D,0.003000000026077032,0.003000000026077032
MC_ROLLRATE_FF,0.0,0.0
MC_ROLLRATE_I,0.20000000298023224,0.20000000298023224
MC_ROLLRATE_K,1.0,1.0
MC_ROLLRATE_MAX,220.0,220.0
MC_ROLLRATE_P,0.15000000596046448,0.15000000596046448
MC_ROLL_P,6.5,6.5
MC_RR_INT_LIM,0.30000001192092896,0.30000001192092896
MC_YAWRATE_D,0.0,0.0
MC_YAWRATE_FF,0.0,0.0
MC_YAWRATE_I,0.10000000149011612,0.10000000149011612
MC_YAWRATE_K,1.0,1.0
MC_YAWRATE_MAX,200.0,200.0
MC_YAWRATE_P,0.20000000298023224,0.20000000298023224
MC_YAW_P,2.799999952316284,2.799999952316284
MC_YAW_WEIGHT,0.4000000059604645,0.4000000059604645
MC_YR_INT_LIM,0.30000001192092896,0.30000001192092896
MIS_DIST_1WP,900.0,900.0
MIS_LND_ABRT_ALT,30,30
MIS_MNT_YAW_CTL,0,0
MIS_PD_TO,5.0,5.0
MIS_TAKEOFF_ALT,2.5,2.5
MIS_TKO_LAND_REQ,0,0
MIS_YAW_ERR,12.0,12.0
MIS_YAW_TMT,-1.0,-1.0
MNT_MODE_IN,-1,-1
MOT_SLEW_MAX,0.0,0.0
MPC_ACC_DOWN_MAX,3.0,3.0
MPC_ACC_HOR,3.0,3.0
MPC_ACC_HOR_MAX,5.0,5.0
MPC_ACC_UP_MAX,4.0,4.0
MPC_ALT_MODE,0,0
MPC_HOLD_DZ,0.10000000149011612,0.10000000149011612
MPC_HOLD_MAX_XY,0.800000011920929,0.800000011920929
MPC_HOLD_MAX_Z,0.6000000238418579,0.6000000238418579
MPC_JERK_AUTO,4.0,4.0
MPC_JERK_MAX,8.0,8.0
MPC_LAND_ALT1,10.0,10.0
MPC_LAND_ALT2,5.0,5.0
MPC_LAND_ALT3,1.0,1.0
MPC_LAND_CRWL,0.30000001192092896,0.30000001192092896
MPC_LAND_RADIUS,1000.0,1000.0
MPC_LAND_RC_HELP,0,0
MPC_LAND_SPEED,0.699999988079071,0.699999988079071
MPC_MANTHR_MIN,0.07999999821186066,0.07999999821186066
MPC_MAN_TILT_MAX,35.0,35.0
MPC_MAN_Y_MAX,150.0,150.0
MPC_MAN_Y_TAU,0.07999999821186066,0.07999999821186066
MPC_POS_MODE,4,4
MPC_THR_CURVE,0,0
MPC_THR_HOVER,0.5,0.5
MPC_THR_MAX,1.0,1.0
MPC_THR_MIN,0.11999999731779099,0.11999999731779099
MPC_THR_XY_MARG,0.30000001192092896,0.30000001192092896
MPC_TILTMAX_AIR,45.0,45.0
MPC_TILTMAX_LND,12.0,12.0
MPC_TKO_RAMP_T,3.0,3.0
MPC_TKO_SPEED,1.5,1.5
MPC_USE_HTE,1,1
MPC_VELD_LP,5.0,5.0
MPC_VEL_MANUAL,10.0,10.0
MPC_VEL_MAN_BACK,-1.0,-1.0
MPC_VEL_MAN_SIDE,-1.0,-1.0
MPC_XY_CRUISE,5.0,5.0
MPC_XY_ERR_MAX,2.0,2.0
MPC_XY_MAN_EXPO,0.6000000238418579,0.6000000238418579
MPC_XY_P,0.949999988079071,0.949999988079071
MPC_XY_TRAJ_P,0.5,0.5
MPC_XY_VEL_ALL,-10.0,-10.0
MPC_XY_VEL_D_ACC,0.20000000298023224,0.20000000298023224
MPC_XY_VEL_I_ACC,0.4000000059604645,0.4000000059604645
MPC_XY_VEL_MAX,12.0,12.0
MPC_XY_VEL_P_ACC,1.7999999523162842,1.7999999523162842
MPC_YAWRAUTO_MAX,45.0,45.0
MPC_YAW_EXPO,0.6000000238418579,0.6000000238418579
MPC_YAW_MODE,0,0
MPC_Z_MAN_EXPO,0.6000000238418579,0.6000000238418579
MPC_Z_P,1.0,1.0
MPC_Z_VEL_ALL,-3.0,-3.0
MPC_Z_VEL_D_ACC,0.0,0.0
MPC_Z_VEL_I_ACC,2.0,2.0
MPC_Z_VEL_MAX_DN,1.5,1.5
MPC_Z_VEL_MAX_UP,3.0,3.0
MPC_Z_VEL_P_ACC,4.0,4.0
MPC_Z_V_AUTO_DN,1.5,1.5
MPC_Z_V_AUTO_UP,3.0,3.0
NAV_ACC_RAD,2.0,2.0
NAV_DLL_ACT,0,0
NAV_FORCE_VT,1,1
NAV_FW_ALTL_RAD,5.0,5.0
NAV_FW_ALT_RAD,10.0,10.0
NAV_LOITER_RAD,80.0,80.0
NAV_MC_ALT_RAD,0.800000011920929,0.800000011920929
NAV_MIN_LTR_ALT,-1.0,-1.0
NAV_RCL_ACT,2,2
NAV_TRAFF_AVOID,1,1
NAV_TRAFF_A_HOR,500.0,500.0
NAV_TRAFF_A_VER,500.0,500.0
NAV_TRAFF_COLL_T,60,60
PD_GRIPPER_EN,0,0
PLD_BTOUT,5.0,5.0
PLD_FAPPR_ALT,0.10000000149011612,0.10000000149011612
PLD_HACC_RAD,0.20000000298023224,0.20000000298023224
PLD_MAX_SRCH,3,3
PLD_SRCH_ALT,10.0,10.0
PLD_SRCH_TOUT,10.0,10.0
PWM_MAIN_FUNC1,101,101
PWM_MAIN_FUNC10,0,0
PWM_MAIN_FUNC11,0,0
PWM_MAIN_FUNC12,0,0
PWM_MAIN_FUNC13,0,0
PWM_MAIN_FUNC14,0,0
PWM_MAIN_FUNC15,0,0
PWM_MAIN_FUNC16,0,0
PWM_MAIN_FUNC2,102,102
PWM_MAIN_FUNC3,103,103
PWM_MAIN_FUNC4,104,104
PWM_MAIN_FUNC5,0,0
PWM_MAIN_FUNC6,0,0
PWM_MAIN_FUNC7,0,0
PWM_MAIN_FUNC8,0,0
PWM_MAIN_FUNC9,0,0
PWM_MAIN_REV,0,0
RC10_DZ,0.0
RC10_MAX,2000.0
RC10_MIN,1000.0
RC10_REV,1.0
RC10_TRIM,1500.0
RC11_DZ,0.0
RC11_MAX,2000.0
RC11_MIN,1000.0
RC11_REV,1.0
RC11_TRIM,1500.0
RC12_DZ,0.0
RC12_MAX,2000.0
RC12_MIN,1000.0
RC12_REV,1.0
RC12_TRIM,1500.0
RC13_DZ,0.0
RC13_MAX,2000.0
RC13_MIN,1000.0
RC13_REV,1.0
RC13_TRIM,1500.0
RC14_DZ,0.0
RC14_MAX,2000.0
RC14_MIN,1000.0
RC14_REV,1.0
RC14_TRIM,1500.0
RC15_DZ,0.0
RC15_MAX,2000.0
RC15_MIN,1000.0
RC15_REV,1.0
RC15_TRIM,1500.0
RC16_DZ,0.0
RC16_MAX,2000.0
RC16_MIN,1000.0
RC16_REV,1.0
RC16_TRIM,1500.0
RC17_DZ,0.0
RC17_MAX,2000.0
RC17_MIN,1000.0
RC17_REV,1.0
RC17_TRIM,1500.0
RC18_DZ,0.0
RC18_MAX,2000.0
RC18_MIN,1000.0
RC18_REV,1.0
RC18_TRIM,1500.0
RC1_DZ,10.0
RC1_MAX,2000.0
RC1_MIN,1000.0
RC1_REV,1.0
RC1_TRIM,1500.0
RC2_DZ,10.0
RC2_MAX,2000.0
RC2_MIN,1000.0
RC2_REV,1.0
RC2_TRIM,1500.0
RC3_DZ,10.0
RC3_MAX,2000.0
RC3_MIN,1000.0
RC3_REV,1.0
RC3_TRIM,1500.0
RC4_DZ,10.0
RC4_MAX,2000.0
RC4_MIN,1000.0
RC4_REV,1.0
RC4_TRIM,1500.0
RC5_DZ,10.0
RC5_MAX,2000.0
RC5_MIN,1000.0
RC5_REV,1.0
RC5_TRIM,1500.0
RC6_DZ,10.0
RC6_MAX,2000.0
RC6_MIN,1000.0
RC6_REV,1.0
RC6_TRIM,1500.0
RC7_DZ,10.0
RC7_MAX,2000.0
RC7_MIN,1000.0
RC7_REV,1.0
RC7_TRIM,1500.0
RC8_DZ,10.0
RC8_MAX,2000.0
RC8_MIN,1000.0
RC8_REV,1.0
RC8_TRIM,1500.0
RC9_DZ,0.0
RC9_MAX,2000.0
RC9_MIN,1000.0
RC9_REV,1.0
RC9_TRIM,1500.0
RC_ARMSWITCH_TH,0.75
RC_CHAN_CNT,0
RC_ENG_MOT_TH,0.75
RC_FAILS_THR,0
RC_GEAR_TH,0.75
RC_KILLSWITCH_TH,0.75
RC_LOITER_TH,0.75
RC_MAP_ACRO_SW,0
RC_MAP_ARM_SW,0
RC_MAP_AUX1,0
RC_MAP_AUX2,0
RC_MAP_AUX3,0
RC_MAP_AUX4,0
RC_MAP_AUX5,0
RC_MAP_AUX6,0
RC_MAP_ENG_MOT,0
RC_MAP_FAILSAFE,0
RC_MAP_FLAPS,0
RC_MAP_FLTMODE,0
RC_MAP_FLTM_BTN,0
RC_MAP_GEAR_SW,0
RC_MAP_KILL_SW,0
RC_MAP_LOITER_SW,0
RC_MAP_MAN_SW,0
RC_MAP_MODE_SW,0
RC_MAP_OFFB_SW,0
RC_MAP_PARAM1,0
RC_MAP_PARAM2,0
RC_MAP_PARAM3,0
RC_MAP_PITCH,0
RC_MAP_POSCTL_SW,0
RC_MAP_RATT_SW,0
RC_MAP_RETURN_SW,0
RC_MAP_ROLL,0
RC_MAP_STAB_SW,0
RC_MAP_THROTTLE,0
RC_MAP_TRANS_SW,0
RC_MAP_YAW,0
RC_OFFB_TH,0.75
RC_RETURN_TH,0.75
RC_TRANS_TH,0.75
RTL_CONE_ANG,45,45
RTL_DESCEND_ALT,10.0,10.0
RTL_HDG_MD,0,0
RTL_LAND_DELAY,0.0,0.0
RTL_LOITER_RAD,80.0,80.0
RTL_MIN_DIST,10.0,10.0
RTL_PLD_MD,0,0
RTL_RETURN_ALT,30.0,30.0
RTL_TIME_FACTOR,1.100000023841858,1.100000023841858
RTL_TIME_MARGIN,100,100
RTL_TYPE,0,0
SDLOG_BOOT_BAT,0,0
SDLOG_DIRS_MAX,7,7
SDLOG_MISSION,0,0
SDLOG_MODE,1,1
SDLOG_PROFILE,131,131
SDLOG_UTC_OFFSET,0,0
SDLOG_UUID,1,1
SENS_BARO_QNH,1013.25,1013.25
SENS_BARO_RATE,20.0,20.0
SENS_BOARD_ROT,0,0
SENS_BOARD_X_OFF,9.999999974752427e-07,9.999999974752427e-07
SENS_BOARD_Y_OFF,0.0,0.0
SENS_BOARD_Z_OFF,0.0,0.0
SENS_DPRES_OFF,0.0010000000474974513,0.0010000000474974513
SENS_EN_BAROSIM,1,1
SENS_EN_GPSSIM,1,1
SENS_EN_MAGSIM,1,1
SENS_GPS_MASK,7,7
SENS_GPS_PRIME,0,0
SENS_GPS_TAU,10.0,10.0
SENS_IMU_AUTOCAL,1,1
SENS_IMU_MODE,0,0
SENS_MAG_AUTOCAL,1,1
SENS_MAG_AUTOROT,1,1
SENS_MAG_MODE,1,1
SENS_MAG_RATE,15.0,15.0
SENS_MAG_SIDES,63,63
SIH_DISTSNSR_MAX,100.0,100.0
SIH_DISTSNSR_MIN,0.0,0.0
SIH_DISTSNSR_OVR,-1.0,-1.0
SIH_IXX,0.02500000037252903,0.02500000037252903
SIH_IXY,0.0,0.0
SIH_IXZ,0.0,0.0
SIH_IYY,0.02500000037252903,0.02500000037252903
SIH_IYZ,0.0,0.0
SIH_IZZ,0.029999999329447746,0.029999999329447746
SIH_KDV,1.0,1.0
SIH_KDW,0.02500000037252903,0.02500000037252903
SIH_LOC_H0,32.34000015258789,32.34000015258789
SIH_LOC_LAT0,454671160,454671160
SIH_LOC_LON0,-737578370,-737578370
SIH_L_PITCH,0.20000000298023224,0.20000000298023224
SIH_L_ROLL,0.20000000298023224,0.20000000298023224
SIH_MASS,1.0,1.0
SIH_Q_MAX,0.10000000149011612,0.10000000149011612
SIH_T_MAX,5.0,5.0
SIH_T_TAU,0.05000000074505806,0.05000000074505806
SIH_VEHICLE_TYPE,0,0
SIM_BARO_OFF_P,0.0,0.0
SIM_BARO_OFF_T,0.0,0.0
SIM_BAT_DRAIN,60.0,60.0
SIM_BAT_MIN_PCT,50.0,50.0
SIM_GPS_USED,10,10
SIM_MAG_OFFSET_X,0.0,0.0
SIM_MAG_OFFSET_Y,0.0,0.0
SIM_MAG_OFFSET_Z,0.0,0.0
SYS_AUTOCONFIG,0,0
SYS_AUTOSTART,10040,10040
SYS_CAL_TDEL,24,24
SYS_CAL_TMAX,10,10
SYS_CAL_TMIN,5,5
SYS_FAC_CAL_MODE,0,0
SYS_FAILURE_EN,1,1
SYS_HAS_BARO,1,1
SYS_HAS_GPS,1,1
SYS_HAS_MAG,1,1
SYS_HAS_NUM_DIST,0,0
SYS_HITL,0,0
SYS_MC_EST_GROUP,2,2
SYS_STCK_EN,1,1
SYS_VEHICLE_RESP,-0.4000000059604645,-0.4000000059604645
THR_MDL_FAC,0.0,0.0
TRIG_INTERFACE,3,3
TRIG_MODE,0,0
UXRCE_DDS_DOM_ID,0,0
UXRCE_DDS_KEY,4,4
VTO_LOITER_ALT,80.0,80.0
VT_B_DEC_MSS,2.0,2.0
WV_EN,0,0
WV_GAIN,1.0,1.0
WV_ROLL_MIN,1.0,1.0
WV_YRATE_MAX,90.0,90.0
```
</details>

<details><summary>mc_flight.sh, the command script (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_logs/v1.14.4/mc_flight.sh</code>)</summary>

```bash
#!/bin/bash
# mc_flight.sh: one headless SIH multicopter flight on PX4 v1.14.4 SITL.
# Equivalent of `make px4_sitl sihsim_quadx` (target defined in
# src/modules/simulation/simulator_sih/CMakeLists.txt:
#   env PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim <build>/bin/px4, cwd <build>/rootfs)
# but run without make, daemon mode (-d, no pxh shell), in a fresh working dir,
# on a non-zero instance so it cannot collide with another SITL on instance 0.
# Usage: mc_flight.sh [working_dir]
set -u
S=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad
T=$S/px4/PX4-Autopilot-v1.14.4
BUILD=$T/build/px4_sitl_default
B=$BUILD/bin
I=${PX4_INSTANCE_ID:-3}
WD=${1:-$S/sitl_run/v1.14.4_mc_$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$WD"
OUT=$WD/px4.stdout.log
CMDLOG=$WD/commands.log
: > "$CMDLOG"

ts()  { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
log() { echo "$(ts) $*" | tee -a "$CMDLOG"; }
cli() { local m=$1; shift; "$B/px4-$m" --instance "$I" "$@"; }
run() { log "CMD: px4-$1 --instance $I ${*:2}"; cli "$@" 2>&1 | sed 's/^/    | /' | tee -a "$CMDLOG"; }
field() { cli listener "$1" -n 1 2>/dev/null | awk -v f="$2" '$1==f":"{print $2; exit}'; }
snapshot() {
  log "STATE[$1]: arming_state=$(field vehicle_status arming_state) nav_state=$(field vehicle_status nav_state)" \
      "user_intention=$(field vehicle_status nav_state_user_intention) failsafe=$(field vehicle_status failsafe)" \
      "landed=$(field vehicle_land_detected landed) z=$(field vehicle_local_position z)"
}
wait_field() { # topic field value timeout_s
  local end=$(( $(date +%s) + $4 )) v=""
  while [ "$(date +%s)" -lt "$end" ]; do
    v=$(field "$1" "$2")
    if [ "$v" = "$3" ]; then log "OK: $1.$2 == $3"; return 0; fi
    sleep 0.5
  done
  log "TIMEOUT: $1.$2 != $3 after $4 s (last: '$v')"; return 1
}
abort() { log "ABORT: $*"; snapshot abort; cli shutdown >/dev/null 2>&1; sleep 3; kill -INT "$PX4_PID" 2>/dev/null; exit 1; }

cd "$WD" || exit 1
log "PX4 tree: $T ($(git -C "$T" describe --tags --always) $(git -C "$T" rev-parse HEAD))"
log "LAUNCH: cd $WD && PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim $B/px4 -d -i $I -w $WD $BUILD/etc > $OUT 2>&1 < /dev/null &"
PX4_SIM_MODEL=sihsim_quadx PX4_SIMULATOR=sihsim "$B/px4" -d -i "$I" -w "$WD" "$BUILD/etc" > "$OUT" 2>&1 < /dev/null &
PX4_PID=$!
log "px4 pid $PX4_PID"

# 1. boot: wait until arming checks pass in the boot mode (default user intention AUTO_LOITER)
wait_field vehicle_status pre_flight_checks_pass True 180 || abort "preflight checks never passed"
sleep 2
snapshot preflight_ok
Z0=$(field vehicle_local_position z); log "ground reference z0=$Z0 (vehicle_local_position.z before arming)"

# 2. arm
run commander arm
wait_field vehicle_status arming_state 2 10 || abort "arm failed"
snapshot armed

# 3. takeoff (NAV_TAKEOFF, then an ARM command that is a no-op since already armed)
run commander takeoff
wait_field vehicle_status nav_state 17 10 || abort "no AUTO_TAKEOFF"
snapshot takeoff
wait_field vehicle_status nav_state 4 60 || abort "takeoff did not complete into AUTO_LOITER"
snapshot takeoff_done
sleep 70
snapshot hover

# 4. mode change 1: auto:rtl (nav_state 5)
run commander mode auto:rtl
wait_field vehicle_status nav_state 5 10 || abort "no AUTO_RTL"
snapshot rtl
for k in $(seq 1 16); do   # stay in RTL up to 8 s, leave early once below 1.2 m above ground (z0)
  z=$(field vehicle_local_position z)
  awk -v z="$z" -v z0="$Z0" 'BEGIN{exit !((z - z0) > -1.2)}' && { log "RTL descending below 1.2 m above ground (z=$z, z0=$Z0), leaving RTL"; break; }
  sleep 0.5
done
snapshot rtl_end

# 5. mode change 2: auto:loiter (nav_state 4)
run commander mode auto:loiter
wait_field vehicle_status nav_state 4 10 || abort "no AUTO_LOITER"
snapshot loiter
sleep 45
snapshot loiter_end

# 6. land (nav_state 18)
run commander land
wait_field vehicle_status nav_state 18 10 || abort "no AUTO_LAND"
snapshot land
wait_field vehicle_land_detected landed True 120 || abort "never landed"
snapshot landed

# 7. disarm, sent as soon as landed is detected (auto disarm COM_DISARM_LAND is 2 s)
run commander disarm
wait_field vehicle_status arming_state 1 10 || log "WARN: still armed after disarm"
snapshot disarmed
log "latest_disarming_reason=$(field vehicle_status latest_disarming_reason)"

# 8. let the logger close the file (SDLOG_MODE 1 stops at disarm), then shut down
sleep 4
run shutdown
for k in $(seq 1 30); do kill -0 "$PX4_PID" 2>/dev/null || break; sleep 1; done
kill -0 "$PX4_PID" 2>/dev/null && { log "px4 still running, sending SIGINT"; kill -INT "$PX4_PID"; sleep 3; }
log "px4 exited"
log "ULOG: $(find "$WD/log" -name '*.ulg' 2>/dev/null | sort | tr '\n' ' ')"
```
</details>

<details><summary>Script change from run 1 to run 3 (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/mc_flight_run1_to_run3.diff</code>)</summary>

```diff
52a53
> Z0=$(field vehicle_local_position z); log "ground reference z0=$Z0 (vehicle_local_position.z before arming)"
65c66
< sleep 40
---
> sleep 70
72c73
< for k in $(seq 1 16); do   # stay in RTL up to 8 s, leave early if it gets low
---
> for k in $(seq 1 16); do   # stay in RTL up to 8 s, leave early once below 1.2 m above ground (z0)
74c75
<   awk -v z="$z" 'BEGIN{exit !(z > -1.0)}' && { log "RTL descending below 1 m (z=$z), leaving RTL early"; break; }
---
>   awk -v z="$z" -v z0="$Z0" 'BEGIN{exit !((z - z0) > -1.2)}' && { log "RTL descending below 1.2 m above ground (z=$z, z0=$Z0), leaving RTL"; break; }
83c84
< sleep 30
---
> sleep 45
```
</details>

<details><summary>analyze_ulog.py (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/analyze_ulog.py</code>)</summary>

```python
"""Summarise one PX4 ULog for the Sealed Flight Record diagnostic (evidence only)."""
import sys, hashlib
from pyulog import ULog

path = sys.argv[1]
raw = open(path, 'rb').read()
u = ULog(path)

print("== file")
print("path:", path)
print("size_bytes:", len(raw))
print("sha256:", hashlib.sha256(raw).hexdigest())
print("ulog file version (header byte 7):", raw[7])
print("start_timestamp_us:", u.start_timestamp, " last_timestamp_us:", u.last_timestamp,
      " duration_s: %.3f" % ((u.last_timestamp - u.start_timestamp) / 1e6))
print("file_corruption:", u.file_corruption)
print("has_data_appended:", getattr(u, 'has_data_appended', None))
print("compat_flags:", list(getattr(u, 'compat_flags', [])), " incompat_flags:", list(getattr(u, 'incompat_flags', [])))
print("appended_offsets:", getattr(u, 'appended_offsets', None))

print("\n== info (msg_info_dict), exact keys and values as pyulog reports them")
for k in sorted(u.msg_info_dict):
    print("%s = %r" % (k, u.msg_info_dict[k]))
print("\n== info multiple (msg_info_multiple_dict) keys")
for k in sorted(u.msg_info_multiple_dict):
    v = u.msg_info_multiple_dict[k]
    print("%s: %d list(s), first list %d item(s)" % (k, len(v), len(v[0]) if v else 0))

print("\n== dropouts")
print("count:", len(u.dropouts), " total_ms:", sum(d.duration for d in u.dropouts))
for d in u.dropouts:
    print("  t=%d us duration=%d ms" % (d.timestamp, d.duration))

print("\n== parameters")
print("initial parameter count:", len(u.initial_parameters))
print("changed_parameters (timestamp, name, value):", len(u.changed_parameters))
for c in u.changed_parameters:
    print("  ", c)
print("default parameters (msg_info default params) available:", bool(getattr(u, 'initial_parameters_default', None) or getattr(u, '_default_parameters', None)))
for key in ('SYS_AUTOSTART', 'MAV_SYS_ID', 'MAV_TYPE', 'SDLOG_MODE', 'SDLOG_PROFILE', 'COM_DISARM_LAND', 'MIS_TAKEOFF_ALT', 'SIH_VEHICLE_TYPE', 'CA_AIRFRAME', 'SYS_HITL'):
    print("  %s = %r" % (key, u.initial_parameters.get(key)))

topics = {}
for d in u.data_list:
    topics.setdefault(d.name, []).append((d.multi_id, len(d.data['timestamp']), d))
print("\n== all logged topics (name: [multi_id:count])")
for n in sorted(topics):
    print("%s: %s" % (n, ", ".join("%d:%d" % (m, c) for m, c, _ in sorted(topics[n], key=lambda x: x[0]))))

want = ['vehicle_status', 'failsafe_flags', 'vehicle_status_flags', 'vehicle_command', 'vehicle_command_ack',
        'vtol_vehicle_status', 'vehicle_land_detected', 'vehicle_gps_position', 'sensor_gps', 'battery_status',
        'estimator_status_flags', 'log_message', 'home_position', 'commander_state', 'actuator_armed',
        'event', 'parameter_update', 'vehicle_global_position', 'vehicle_local_position']
print("\n== requested topics: present? instances and message counts")
for n in want:
    if n in topics:
        print("%-24s PRESENT  %s" % (n, ", ".join("instance %d: %d msgs" % (m, c) for m, c, _ in sorted(topics[n], key=lambda x: x[0]))))
    else:
        print("%-24s ABSENT" % n)

def first(n):
    return sorted(topics[n], key=lambda x: x[0])[0][2] if n in topics else None

vs = first('vehicle_status')
if vs:
    d = vs.data
    print("\n== vehicle_status fields:", sorted(k for k in d.keys()))
    print("\n== vehicle_status arming_state / nav_state transitions (boot us, field, old -> new)")
    for f in ('arming_state', 'nav_state', 'nav_state_user_intention', 'failsafe', 'latest_arming_reason',
              'latest_disarming_reason', 'vehicle_type', 'is_vtol', 'system_id', 'component_id'):
        if f not in d:
            print("  (no field %s)" % f); continue
        prev = None
        for i in range(len(d['timestamp'])):
            v = int(d[f][i])
            if v != prev:
                print("  t=%d us  %s: %s -> %s" % (d['timestamp'][i], f, prev, v))
                prev = v

for n in ('vehicle_command', 'vehicle_command_ack'):
    t = first(n)
    if not t: continue
    d = t.data
    print("\n== %s fields:" % n, sorted(d.keys()))
    for i in range(len(d['timestamp'])):
        if n == 'vehicle_command':
            print("  t=%d cmd=%d p1=%g p2=%g p3=%g p4=%g src=%d/%d tgt=%d/%d from_external=%d" % (
                d['timestamp'][i], d['command'][i], d['param1'][i], d['param2'][i], d['param3'][i], d['param4'][i],
                d['source_system'][i], d['source_component'][i], d['target_system'][i], d['target_component'][i],
                d['from_external'][i]))
        else:
            print("  t=%d cmd=%d result=%d result_param1=%d result_param2=%d target=%d/%d from_external=%d" % (
                d['timestamp'][i], d['command'][i], d['result'][i], d['result_param1'][i], d['result_param2'][i],
                d['target_system'][i], d['target_component'][i], d['from_external'][i]))

ff = first('failsafe_flags')
if ff:
    d = ff.data
    flags = [k for k in d.keys() if k not in ('timestamp',)]
    print("\n== failsafe_flags: %d fields" % len(flags))
    print("  fields:", flags)
    print("  transitions of any field (t, field, old -> new):")
    for f in flags:
        prev = None
        for i in range(len(d['timestamp'])):
            v = int(d[f][i])
            if prev is not None and v != prev:
                print("    t=%d %s: %s -> %s" % (d['timestamp'][i], f, prev, v))
            prev = v

ld = first('vehicle_land_detected')
if ld:
    d = ld.data
    print("\n== vehicle_land_detected landed / maybe_landed transitions")
    for f in ('landed', 'maybe_landed', 'ground_contact'):
        prev = None
        for i in range(len(d['timestamp'])):
            v = int(d[f][i])
            if v != prev:
                print("  t=%d %s: %s -> %s" % (d['timestamp'][i], f, prev, v)); prev = v

for n in ('vehicle_gps_position', 'sensor_gps'):
    t = first(n)
    if t:
        d = t.data
        tu = d.get('time_utc_usec')
        print("\n== %s: fields include time_utc_usec=%s; first non-zero time_utc_usec=%s at t=%s; fix_type first/last=%s/%s" % (
            n, 'time_utc_usec' in d,
            next((int(x) for x in tu if x), None) if tu is not None else None,
            next((int(d['timestamp'][i]) for i, x in enumerate(tu) if x), None) if tu is not None else None,
            int(d['fix_type'][0]), int(d['fix_type'][-1])))

lm = first('log_message')
if lm:
    d = lm.data
    print("\n== log_message topic entries (t, severity, text)")
    for i in range(len(d['timestamp'])):
        txt = bytes(int(d['text[%d]' % j][i]) for j in range(127) if 'text[%d]' % j in d).split(b'\0')[0].decode('utf-8', 'replace')
        print("  t=%d sev=%d %s" % (d['timestamp'][i], d['severity'][i], txt))

print("\n== ULog logged-string messages ('L' records): %d" % len(u.logged_messages))
for m in u.logged_messages:
    print("  t=%d level=%s(%s) %s" % (m.timestamp, m.log_level, m.log_level_str(), m.message))
tagged = getattr(u, 'logged_messages_tagged', {})
print("\n== tagged logged-string messages ('C' records):", sum(len(v) for v in tagged.values()) if tagged else 0)

ff = first('failsafe_flags')
if ff:
    d = ff.data
    print("\n== failsafe_flags values at first and last sample (non-zero only)")
    for idx, lab in ((0, 'first'), (-1, 'last')):
        nz = [k for k in d if k != 'timestamp' and int(d[k][idx]) != 0]
        print("  %s t=%d: %s" % (lab, d['timestamp'][idx], nz))
ev = first('event')
if ev:
    print("\n== event topic fields:", sorted(ev.data.keys()))
```
</details>

<details><summary>collect.sh (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/collect.sh</code>)</summary>

```bash
#!/bin/bash
# collect.sh <run_dir>: copy the flight deliverables and capture pyulog tool outputs.
set -eu
S=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad
RUN=$1
DST=$S/sitl_logs/v1.14.4
OUTD=$RUN/analysis
mkdir -p "$DST" "$OUTD"
ULG=$(find "$RUN/log" -name '*.ulg' | sort | tail -1)
echo "source ulog: $ULG"
cp "$ULG" "$DST/mc_flight.ulg"
cp "$RUN/px4.stdout.log" "$DST/mc_flight.px4.log"
cp "$S/sitl_run/mc_flight.sh" "$DST/mc_flight.sh"
cp "$RUN/commands.log" "$DST/mc_flight.commands.log"
F=$DST/mc_flight.ulg
ulog_info "$F" > "$OUTD/ulog_info.txt" 2>&1
ulog_info -v "$F" > "$OUTD/ulog_info_v.txt" 2>&1
ulog_messages "$F" > "$OUTD/ulog_messages.txt" 2>&1
ulog_params "$F" > "$OUTD/ulog_params.txt" 2>&1
ulog2csv -m vehicle_status,vehicle_command,vehicle_command_ack,failsafe_flags,vehicle_land_detected -o "$OUTD/csv" "$F" > "$OUTD/ulog2csv.txt" 2>&1
python3 -I "$S/sitl_run/analyze_ulog.py" "$F" > "$OUTD/analysis.txt" 2>&1
sha256sum "$DST"/mc_flight.* > "$OUTD/sha256.txt"
ls -la "$DST" "$OUTD" "$OUTD/csv"
```
</details>

<details><summary>Build error excerpts (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/build_errors_excerpt.txt</code>)</summary>

```text
/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.14.4/platforms/posix/src/px4/common/px4_daemon/pxh.cpp:208:25: error: 'uint8_t' was not declared in this scope
  208 |                         uint8_t buffer[512];
      |                         ^~~~~~~
compilation terminated due to -Wfatal-errors.
...
build exit=2

--- build_v1.14.4_rebuild.log
FAILED: src/modules/local_position_estimator/CMakeFiles/modules__local_position_estimator.dir/sensors/sonar.cpp.o 
FAILED: src/modules/local_position_estimator/CMakeFiles/modules__local_position_estimator.dir/sensors/baro.cpp.o 
FAILED: src/modules/local_position_estimator/CMakeFiles/modules__local_position_estimator.dir/sensors/lidar.cpp.o 
/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/px4/PX4-Autopilot-v1.14.4/src/lib/matrix/matrix/Matrix.hpp:96:29: error: array subscript 1 is above array bounds of 'float [1][1]' [-Werror=array-bounds=]
   96 |                 return _data[i][j];
      |                        ~~~~~^
compilation terminated due to -Wfatal-errors.
cc1plus: all warnings being treated as errors
build exit=2

--- v1.14.4_build_attempt3.log (tail)
[343/344] Building CXX object src/examples/dyn_hello/CMakeFiles/examples__dyn_hello.dir/hello.cpp.o
[344/344] Linking CXX shared library src/examples/dyn_hello/examples__dyn_hello.px4mod
build exit=0
```
</details>

<details><summary>Run 2 (failsafe under CPU contention) excerpt: px4 warnings, state transitions, failsafe flag transitions, logged strings (<code>/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/run2_excerpt.txt</code>)</summary>

```text
56:WARN  [health_and_arming_checks] Preflight Fail: No valid data from Compass 0
58:WARN  [health_and_arming_checks] Preflight Fail: No valid data from Baro 0
59:WARN  [health_and_arming_checks] Preflight Fail: No valid data from Compass 0
60:WARN  [mc_pos_control] invalid setpoints
61:WARN  [mc_pos_control] Failsafe: blind land
62:WARN  [failsafe] Failsafe activated	
64:WARN  [health_and_arming_checks] Preflight Fail: No valid data from Baro 0
65:WARN  [health_and_arming_checks] Preflight Fail: No valid data from Compass 0
66:WARN  [health_and_arming_checks] Preflight Fail: Battery unhealthy
67:WARN  [failsafe] Failsafe activated	
68:INFO  [commander] Landing detected	
69:INFO  [commander] Disarmed by landing	
71:WARN  [health_and_arming_checks] Preflight Fail: No valid data from Baro 0
72:WARN  [health_and_arming_checks] Preflight Fail: No valid data from Compass 0
73:WARN  [health_and_arming_checks] Preflight Fail: Battery unhealthy
75:WARN  [health_and_arming_checks] Preflight Fail: No valid data from Baro 0
76:WARN  [health_and_arming_checks] Preflight Fail: No valid data from Compass 0
77:WARN  [health_and_arming_checks] Preflight Fail: Battery unhealthy

== vehicle_status arming_state / nav_state transitions (boot us, field, old -> new)
  t=96000 us  arming_state: None -> 1
  t=9808000 us  arming_state: 1 -> 2
  t=19108000 us  arming_state: 2 -> 1
  t=96000 us  nav_state: None -> 4
  t=10372000 us  nav_state: 4 -> 17
  t=14812000 us  nav_state: 17 -> 12
  t=19108000 us  nav_state: 12 -> 17
  t=96000 us  nav_state_user_intention: None -> 4
  t=10372000 us  nav_state_user_intention: 4 -> 17
  t=96000 us  failsafe: None -> 0
  t=14812000 us  failsafe: 0 -> 1
  t=19108000 us  failsafe: 1 -> 0
  t=96000 us  latest_arming_reason: None -> 0
  t=9808000 us  latest_arming_reason: 0 -> 3
  t=96000 us  latest_disarming_reason: None -> 0
  t=19108000 us  latest_disarming_reason: 0 -> 6
  t=96000 us  vehicle_type: None -> 1
  t=96000 us  is_vtol: None -> 0
  t=96000 us  system_id: None -> 4
  t=96000 us  component_id: None -> 1

== vehicle_command fields: ['command', 'confirmation', 'from_external', 'param1', 'param2', 'param3', 'param4', 'param5', 'param6', 'param7', 'source_component', 'source_system', 'target_component', 'target_system', 'timestamp']
  transitions of any field (t, field, old -> new):
    t=6508000 attitude_invalid: 1 -> 0
    t=916000 local_altitude_invalid: 1 -> 0
    t=7588000 local_position_invalid: 1 -> 0
    t=14800000 local_position_invalid: 0 -> 1
    t=7588000 local_position_invalid_relaxed: 1 -> 0
    t=14800000 local_position_invalid_relaxed: 0 -> 1
    t=7588000 local_velocity_invalid: 1 -> 0
    t=14152000 local_velocity_invalid: 0 -> 1
    t=7588000 global_position_invalid: 1 -> 0
    t=14800000 global_position_invalid: 0 -> 1
    t=14920000 battery_unhealthy: 0 -> 1

== vehicle_land_detected landed / maybe_landed transitions
== ULog logged-string messages ('L' records): 29
  t=256000 level=54(INFO) [logger] logger started (mode=all)
  t=256000 level=54(INFO) [logger] Start file log (type: full)
  t=256000 level=54(INFO) [logger] [logger] ./log/2026-10-18/11_13_40.ulg	
  t=260000 level=54(INFO) [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
  t=260000 level=54(INFO) [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
  t=260000 level=54(INFO) [mavlink] MAVLink only on localhost (set param MAV_{i}_BROADCAST = 1 to enable network)
  t=260000 level=54(INFO) [px4] Startup script returned successfully
  t=7588000 level=54(INFO) [commander] <ESC>[32mReady for takeoff!<ESC>[0m
  t=9808000 level=54(INFO) [commander] Armed by internal command	
  t=9808000 level=54(INFO) [tone_alarm] arming warning
  t=10372000 level=54(INFO) [navigator] Using minimum takeoff altitude: 2.50 m	
  t=10804000 level=52(WARNING) [health_and_arming_checks] Preflight Fail: No valid data from Compass 0
  t=11452000 level=54(INFO) [commander] Takeoff detected	
  t=12856000 level=52(WARNING) [health_and_arming_checks] Preflight Fail: No valid data from Baro 0
  t=12856000 level=52(WARNING) [health_and_arming_checks] Preflight Fail: No valid data from Compass 0
  t=14776000 level=52(WARNING) [mc_pos_control] invalid setpoints
  t=14776000 level=52(WARNING) [mc_pos_control] Failsafe: blind land
  t=14812000 level=52(WARNING) [failsafe] Failsafe activated	
  t=14812000 level=54(INFO) [tone_alarm] battery warning (fast)
  t=14920000 level=52(WARNING) [health_and_arming_checks] Preflight Fail: No valid data from Baro 0
  t=14920000 level=52(WARNING) [health_and_arming_checks] Preflight Fail: No valid data from Compass 0
  t=14920000 level=52(WARNING) [health_and_arming_checks] Preflight Fail: Battery unhealthy
  t=14932000 level=52(WARNING) [failsafe] Failsafe activated	
  t=17104000 level=54(INFO) [commander] Landing detected	
  t=19108000 level=54(INFO) [commander] Disarmed by landing	
  t=19108000 level=54(INFO) [tone_alarm] notify neutral
  t=19864000 level=52(WARNING) [health_and_arming_checks] Preflight Fail: No valid data from Baro 0
  t=19864000 level=52(WARNING) [health_and_arming_checks] Preflight Fail: No valid data from Compass 0
  t=19864000 level=52(WARNING) [health_and_arming_checks] Preflight Fail: Battery unhealthy

== tagged logged-string messages ('C' records): 0

== failsafe_flags values at first and last sample (non-zero only)
  first t=168000: ['mode_req_angular_velocity', 'mode_req_attitude', 'mode_req_local_alt', 'mode_req_local_position', 'mode_req_local_position_relaxed', 'mode_req_global_position', 'mode_req_mission', 'mode_req_offboard_signal', 'mode_req_home_position', 'mode_req_wind_and_flight_time_compliance', 'mode_req_prevent_arming', 'mode_req_manual_control', 'attitude_invalid', 'local_altitude_invalid', 'local_position_invalid', 'local_position_invalid_relaxed', 'local_velocity_invalid', 'global_position_invalid', 'auto_mission_missing', 'offboard_control_signal_lost', 'manual_control_signal_lost', 'gcs_connection_lost']
  last t=19864000: ['mode_req_angular_velocity', 'mode_req_attitude', 'mode_req_local_alt', 'mode_req_local_position', 'mode_req_local_position_relaxed', 'mode_req_global_position', 'mode_req_mission', 'mode_req_offboard_signal', 'mode_req_home_position', 'mode_req_wind_and_flight_time_compliance', 'mode_req_prevent_arming', 'mode_req_manual_control', 'local_position_invalid', 'local_position_invalid_relaxed', 'local_velocity_invalid', 'global_position_invalid', 'auto_mission_missing', 'offboard_control_signal_lost', 'manual_control_signal_lost', 'gcs_connection_lost', 'battery_unhealthy']

== event topic fields: ['arguments[0]', 'arguments[10]', 'arguments[11]', 'arguments[12]', 'arguments[13]', 'arguments[14]', 'arguments[15]', 'arguments[16]', 'arguments[17]', 'arguments[18]', 'arguments[19]', 'arguments[1]', 'arguments[20]', 'arguments[21]', 'arguments[22]', 'arguments[23]', 'arguments[24]', 'arguments[2]', 'arguments[3]', 'arguments[4]', 'arguments[5]', 'arguments[6]', 'arguments[7]', 'arguments[8]', 'arguments[9]', 'event_sequence', 'id', 'log_levels', 'timestamp']
```
</details>

The verbose `ulog_info -v` output (perf counters, all info-multiple content) is at `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/analysis/ulog_info_v.txt`; per-topic CSVs for vehicle_status, failsafe_flags and vehicle_land_detected are in `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/sitl_run/v1.14.4_mc_run3/analysis/csv/`.


## 4. Field map (PX4 v1.14 through v1.17), with item 5 (volatile parameters, source part) and item 6 (VTOL transition semantics, source part)

### 4.0 Evidence base and verdict legend

All paths below are relative to the scratchpad `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/`.

| Tag | Source tree | Commit |
|---|---|---|
| P14 | `work/fieldmap/px4-v1.14.4` (shallow clone, tag v1.14.4, no submodules) | 1555f2bd2229544c43966ab5f94879c41d8e1e01 |
| P15 | `work/fieldmap/px4-v1.15.4` (shallow clone, tag v1.15.4) | tag v1.15.4 |
| P16 | `work/fieldmap/px4-v1.16.2` (shallow clone, tag v1.16.2) | tag v1.16.2 |
| P17 | `px4/PX4-Autopilot-v1.17.0` (read only, build/ untouched) | d6f12ad1c4f70ad3230afd7d86e971421e02fef4 |
| P13 | `work/fieldmap/sparse-v1.13.3` (msg/ only, for rename history) | tag v1.13.3 |

| Tag | Log | sha256 | What it is |
|---|---|---|---|
| L17 | `sitl_logs/v1.17.0/superseded/mc_flight_1_attempt1.ulg` (was `sitl_logs/v1.17.0/mc_flight_1.ulg`; moved by another step at 11:10 while this item ran; same 9,158,705 bytes) | 4578b6e9f0a10dff1a1ce3ca64269fde01c66d60b5a09bc864da5127412d56e0 | v1.17.0 SITL, SIH quadx (SYS_AUTOSTART 10040), arm, takeoff, loiter, RTL, auto disarm on landing. SDLOG_PROFILE 131, SDLOG_MODE 1 |
| L14 | `sitl_run/v1.14.4_mc_run1/log/2026-10-18/11_10_48.ulg` (copy: `work/fieldmap/v1.14.4_mc_run1_11_10_48.ulg`) | 2190caf0c7b9a32ba0d61db9124362b36bf9bcf1285b62d1127176b051e1c4f9 | v1.14.4 SITL, SIH quadx, instance 3 (MAV_SYS_ID 4), arm, takeoff, hover, RTL, loiter, land, commanded disarm |
| S15 | `dl/pyulog/test/sample_px4_events.ulg` | n/a | SITL, ver_sw_release 0x010F0000 (v1.15 development), QGC attached |
| S13 | `dl/pyulog/test/sample_logging_tagged_and_default_params.ulg` | n/a | SITL, ver_sw_release 0x010D0000 (v1.13 development), contains a 'C' message |
| S00 | `dl/pyulog/test/sample.ulg` | n/a | old hardware log (AUAV_X21), has 'O' dropouts and 'P' changes in the data section |

Scripts (reproducible, run with `python3 -I`): `work/fieldmap/verify_v117.py <log> <msgdir>` (field sets against .msg, state changes, command and ack pairing, P/L/C/O, events), `verify_v117b.py` (GPS UTC, event groups), `verify_v117c.py` (excluded optional topics, instances). Outputs: `work/fieldmap/verify_v117.out`, `work/fieldmap/verify_v114.out`.

Verdicts used per row: **V17** = confirmed in L17; **V14** = confirmed in L14; **VS** = confirmed only in an older pyulog sample (S00, S13, S15); **SRC** = SOURCE-ONLY (read from the tag named, not seen in a log). v1.15 and v1.16 are SRC everywhere (no log of those tags exists yet).

Field-set check result: for every topic below that is present in L17 and L14, the set of field names in the log's 'F' format equals the set of non-constant fields parsed from that tag's .msg file (padding excluded). Zero differences in either direction. Topics checked: vehicle_status, failsafe_flags, vehicle_command, vehicle_command_ack, sensor_gps, vehicle_gps_position, vehicle_land_detected, parameter_update, battery_status, vehicle_imu_status, estimator_status_flags, estimator_status, event, actuator_armed. Absent from both logs: vtol_vehicle_status (multicopter, optional topic) and log_message (never logged as a topic, see 4.6).

### 4.1 Topic naming and default logging

**Naming rule.** The ULog topic name (the 'A' message `message_name`, as printed by `ulog_info`) is the uORB topic name. The default topic name is the .msg file name converted from PascalCase to snake_case by two regexes: `(.)([A-Z][a-z]+)` to `\1_\2`, then `([a-z0-9])([A-Z])` to `\1_\2`, then lower case (P14 and P17 `msg/CMakeLists.txt` lines 252 to 254 and 304 to 306). A `# TOPICS a b` line in a .msg defines extra topic names that share one struct (`Tools/msg/px_generate_uorb_topic_files.py`: TOPICS_TOKEN line 78 in P14, line 77 in P17). Example: `msg/SensorGps.msg` ends with `# TOPICS sensor_gps vehicle_gps_position` (P14 line 58, P17 line 90). Since v1.16 some .msg files live in `msg/versioned/` and carry `uint32 MESSAGE_VERSION`; the file location and that constant do not change the topic name, and the constant is not a field in the log (V17: no `MESSAGE_VERSION` field in any format). Multi-instance topics carry the instance in the 'A' message `multi_id`. V17, V14.

**Profiles.** `SDLOG_PROFILE` is a bitmask: bit 0 default set, 1 estimator replay, 2 thermal calibration, 3 system identification, 4 high rate, 5 debug, 6 sensor comparison, 7 vision and avoidance, 8 and 9 raw FIFO IMU, 10 MAVLink tunnel, 11 high rate sensors (bit 11 only in v1.17). Default value 1 (P14 `src/modules/logger/params.c` lines 109 to 147; P17 `src/modules/logger/module.yaml` lines 71 to 101; mask enum P17 `logged_topics.h` lines 46 to 59). The SITL startup script sets `SDLOG_PROFILE 131` (bits 0, 1, 7) and `SDLOG_MODE 1` (boot until disarm) as defaults (`ROMFS/px4fmu_common/init.d-posix/rcS` P14 lines 178 and 180, P15 173/175, P16 181/183, P17 180/182). On hardware the defaults are SDLOG_PROFILE 1 and SDLOG_MODE 0 (arm until disarm). A file `etc/logging/logger_topics.txt` on the SD card replaces the profiles entirely (`initialize_logged_topics`, P17 `logged_topics.cpp` lines 531 to 543). Interval 0 means every publication is logged; a non-zero interval means at most one sample per interval (uORB SubscriptionInterval keeps only the latest, so intermediate samples are dropped).

| Topic | Logged in default profile? | Interval ms v1.14 / v1.15 / v1.16 / v1.17 | logged_topics.cpp line P14 / P15 / P16 / P17 | Verdict |
|---|---|---|---|---|
| vehicle_status | yes, required | 0 / 0 / 0 / 0 | 129 / 137 / 150 / 150 | V17 V14 |
| actuator_armed | yes | 0 all | 49 / 49 / 50 / 49 | V17 V14 |
| vehicle_land_detected | yes | 0 all | 123 / 131 / 144 / 144 | V17 V14 |
| failsafe_flags | yes | 0 all | 64 / 68 / 69 / 69 | V17 V14 |
| vehicle_command | yes | 0 all | 117 / 125 / 138 / 138 | V17 V14 |
| vehicle_command_ack | yes | 0 all | 118 / 126 / 139 / 139 | V17 V14 |
| parameter_update | yes | 0 all | 93 / 98 / 102 / 101 | V17 V14 |
| vtol_vehicle_status | yes but optional (only if advertised, i.e. VTOL airframes) | 200 all | 130 / 138 / 151 / 151 | SRC (absent in MC logs as expected) |
| vehicle_gps_position | yes | 500 / 100 / 100 / 100 | 122 / 130 / 143 / 143 | V17 V14 for presence; the interval is SRC (both SITL logs use profile 131, whose replay set logs it at interval 0; L17 median spacing 124 ms is the SIH publish rate) |
| sensor_gps | yes, multi up to 2 | 1000 all | 211 / 220 / 192 / 199 | V17 V14 (1 instance) |
| battery_status | yes, multi | 200, up to 2 / 2 / 2 / 3 instances | 206 / 215 / 187 / 194 | V17 V14 |
| vehicle_imu_status | yes, multi up to 4 | 1000 all | 218 / 227 / 199 / 206 | V17 V14 |
| estimator_status | instance 0 always plus optional multi (v1.14, v1.15); optional multi only (v1.16, v1.17) | 200 all | 167 and 183 / 176 and 192 / 182 / 189 | V17 V14 |
| estimator_status_flags | as above | 0 (v1.14, v1.15) / 10 (v1.16, v1.17) | 168 and 184 / 177 and 193 / 183 / 190 | V17 V14 |
| event | always, independent of profile (separate subscription in logger.cpp, written even if not in the topic list) | 0 | logger.cpp 390 and 1840 (P17) | V17 V14 |
| log_message | never as a topic; converted to 'L' messages | n/a | logger.cpp 803 to 821 (P17) | V17 V14 (absent as topic) |
| vehicle_status_flags | does not exist in v1.14 to v1.17 (existed up to v1.13) | n/a | n/a | V14 (absent), VS (present in S13, v1.13 dev) |

The estimator replay profile (bit 1) re-adds vehicle_status, vehicle_gps_position, vehicle_land_detected and others at interval 0 (P17 lines 302 to 321). Profiles are applied in bit order and the last one wins (line 548), so SITL logs (profile 131) record every vehicle_gps_position publication, while hardware logs with the default profile 1 use the 500 ms (v1.14) or 100 ms (v1.15+) interval.

`excluded_optional_topics` (an 'M' message) lists optional topics that were not advertised, but it is capped at 40 entries (`MAX_EXCLUDED_OPTIONAL_TOPICS_NUM = 40`, P14 and P17 `logged_topics.h` line 80/81). V17: the list holds exactly 40 names and stops at `spoilers_setpoint`, so `vtol_vehicle_status` is absent from both the data and the exclusion list. A parser must not infer anything from absence in that list.

### 4.2 Item 1: arming state

Topic `vehicle_status`, field `arming_state` (uint8). Numeric values 1 and 2 mean the same thing in every version: 2 is armed, 1 is not armed.

| Constant | v1.14.4 | v1.15.4 | v1.16.2 | v1.17.0 |
|---|---|---|---|---|
| ARMING_STATE_INIT | 0 | removed | removed | removed |
| ARMING_STATE_STANDBY | 1 | renamed ARMING_STATE_DISARMED = 1 | DISARMED = 1 | DISARMED = 1 |
| ARMING_STATE_ARMED | 2 | 2 | 2 | 2 |
| ARMING_STATE_STANDBY_ERROR | 3 | removed | removed | removed |
| ARMING_STATE_SHUTDOWN | 4 | removed | removed | removed |
| ARMING_STATE_IN_AIR_RESTORE | 5 | removed | removed | removed |
| ARMING_STATE_MAX | 6 | removed | removed | removed |

Sources: P14 `msg/VehicleStatus.msg` lines 8 to 15; P15 `msg/VehicleStatus.msg` lines 8 to 10; P16 and P17 `msg/versioned/VehicleStatus.msg` lines 10 to 12 (MESSAGE_VERSION 1 at line 3). Writers: P14 `src/modules/commander/Arming/ArmStateMachine/ArmStateMachine.cpp` lines 96 to 110 (armed_time set at arm, 0 at disarm), published at `Commander.cpp` 1804 to 1806. P17 `Commander.cpp` 621 to 623 (arm) and 666 to 669 (disarm), no ArmStateMachine. Observed values: {1, 2} in L17 and L14. V17 V14.

Other fields:

| Field | Type | Meaning | Verdict |
|---|---|---|---|
| vehicle_status.armed_time | uint64 | boot time (us) of the last arm, 0 while disarmed | V17 V14 (equals the timestamp of the first armed row) |
| vehicle_status.takeoff_time | uint64 | boot time of takeoff detection, 0 when disarmed | V17 V14 |
| vehicle_status.latest_arming_reason, latest_disarming_reason | uint8 | value of the events enum `arm_disarm_reason_t`, see below | V17 V14 |
| vehicle_status.nav_state_timestamp | uint64 | time the current nav_state became active | V17 V14 |
| actuator_armed.armed | bool | output-level armed flag; fields differ by version (v1.14 has manual_lockdown, force_failsafe; v1.17 has kill, termination) | V17 V14 |
| vehicle_land_detected.landed, maybe_landed, ground_contact, freefall | bool | land detector stages; same 12 bool fields in v1.14 and v1.17 (v1.16+ versioned, MESSAGE_VERSION 0) | V17 V14 |

**Correction to the .msg constants.** Commander writes `latest_arming_reason`/`latest_disarming_reason` as `(uint8_t)calling_reason` where the type is `events::px4::enums::arm_disarm_reason_t` (P17 `Commander.hpp` line 95, P14 `ArmStateMachine.hpp` line 49). That enum (P17 `src/lib/events/enums.json` line 441; P14 line 401) is: 0 transition_to_standby, 1 stick_gesture (v1.14: rc_stick), 2 rc_switch, 3 command_internal, 4 command_external, 5 mission_start, 6 auto_disarm_land, 7 auto_disarm_preflight, 8 kill_switch, 9 lockdown, 10 failure_detector, 11 shutdown, 12 unit_test, 13 rc_button, 14 failsafe. The ARM_DISARM_REASON_* constants in VehicleStatus.msg disagree from 6 upward (the .msg says 6 SAFETY_BUTTON, 7 AUTO_DISARM_LAND). L17 confirms: "Disarmed by landing" with latest_disarming_reason = 6. Decode with enums.json, not with the .msg constants. V17 (value 6), V14 (value 3, commanded disarm).

ARM and DISARM events: rising and falling edges of `arming_state == 2` in vehicle_status (published on change and at least every 500 ms; median row spacing 504 ms in both logs). Observed L17: ARM at 4,784,000 us, DISARM at 39,536,000 us; L14: ARM 9,628,000, DISARM 98,976,000. Takeoff and landing are available from `vehicle_land_detected.landed` edges and `vehicle_status.takeoff_time`.

### 4.3 Item 2: navigation state

Topic `vehicle_status`, fields `nav_state` (uint8, active mode) and `nav_state_user_intention` (uint8, mode the user selected; differs from nav_state during a failsafe). NAV_STATE_CHANGE events are edges of `nav_state`.

| Value | v1.14.4 | v1.15.4 | v1.16.2 | v1.17.0 |
|---|---|---|---|---|
| 0 | MANUAL | MANUAL | MANUAL | MANUAL |
| 1 | ALTCTL | ALTCTL | ALTCTL | ALTCTL |
| 2 | POSCTL | POSCTL | POSCTL | POSCTL |
| 3 | AUTO_MISSION | AUTO_MISSION | AUTO_MISSION | AUTO_MISSION |
| 4 | AUTO_LOITER | AUTO_LOITER | AUTO_LOITER | AUTO_LOITER |
| 5 | AUTO_RTL | AUTO_RTL | AUTO_RTL | AUTO_RTL |
| 6 | (not defined) | POSITION_SLOW | POSITION_SLOW | POSITION_SLOW |
| 7 | (not defined) | FREE5 | FREE5 | FREE5 |
| 8 | UNUSED3 | FREE4 | FREE4 | ALTITUDE_CRUISE |
| 9 | UNUSED | FREE3 | FREE3 | FREE3 |
| 10 | ACRO | ACRO | ACRO | ACRO |
| 11 | UNUSED1 | FREE2 | FREE2 | FREE2 |
| 12 | DESCEND | DESCEND | DESCEND | DESCEND |
| 13 | TERMINATION | TERMINATION | TERMINATION | TERMINATION |
| 14 | OFFBOARD | OFFBOARD | OFFBOARD | OFFBOARD |
| 15 | STAB | STAB | STAB | STAB |
| 16 | UNUSED2 | FREE1 | FREE1 | FREE1 |
| 17 | AUTO_TAKEOFF | AUTO_TAKEOFF | AUTO_TAKEOFF | AUTO_TAKEOFF |
| 18 | AUTO_LAND | AUTO_LAND | AUTO_LAND | AUTO_LAND |
| 19 | AUTO_FOLLOW_TARGET | AUTO_FOLLOW_TARGET | AUTO_FOLLOW_TARGET | AUTO_FOLLOW_TARGET |
| 20 | AUTO_PRECLAND | AUTO_PRECLAND | AUTO_PRECLAND | AUTO_PRECLAND |
| 21 | ORBIT | ORBIT | ORBIT | ORBIT |
| 22 | AUTO_VTOL_TAKEOFF | AUTO_VTOL_TAKEOFF | AUTO_VTOL_TAKEOFF | AUTO_VTOL_TAKEOFF |
| 23 | MAX | EXTERNAL1 | EXTERNAL1 | EXTERNAL1 |
| 24 to 30 | (not defined) | EXTERNAL2 to EXTERNAL8 | EXTERNAL2 to EXTERNAL8 | EXTERNAL2 to EXTERNAL8 |
| MAX | 23 | 31 | 31 | 31 |

Sources: P14 `msg/VehicleStatus.msg` lines 38 to 60; P15 `msg/VehicleStatus.msg` lines 33 to 65; P16 `msg/versioned/VehicleStatus.msg` lines 35 to 67; P17 `msg/versioned/VehicleStatus.msg` lines 35 to 67. New fields since v1.15: `executor_in_charge` (uint8, 0 = autopilot), `valid_nav_states_mask` and `can_set_nav_states_mask` (uint32 bitmasks indexed by nav_state). Observed: L17 nav_state {4, 5, 17}; L14 {4, 5, 17, 18}. V17 V14 for values 4, 5, 17, 18 and for the table shape; other values SRC.

Mode commands map to nav_state through PX4 custom modes in `DO_SET_MODE` (param1 base mode with bit 0 = custom mode, param2 custom main mode, param3 custom sub mode; P17 `Commander.cpp` 800 to 870, `src/modules/commander/px4_custom_mode.h` lines 45 to 68). Observed: param1 1, param2 4 (AUTO), param3 3 (LOITER) gave nav_state 4; param3 5 (RTL) gave nav_state 5. V17 V14.

### 4.4 Item 3: vehicle type and VTOL

| Field (vehicle_status) | Type | v1.14.4 | v1.15.4 | v1.16.2 | v1.17.0 | Verdict |
|---|---|---|---|---|---|---|
| vehicle_type | uint8 | UNKNOWN 0, ROTARY_WING 1, FIXED_WING 2, ROVER 3, AIRSHIP 4 | same as v1.14 | ROTARY_WING 1, FIXED_WING 2, ROVER 3 (0 and 4 removed) | UNSPECIFIED 0, ROTARY_WING 1, FIXED_WING 2, ROVER 3 | V17 V14 (value 1) |
| is_vtol | bool | yes | yes | yes | yes | V17 V14 (0) |
| is_vtol_tailsitter | bool | yes | yes | yes | yes | V17 V14 |
| in_transition_mode | bool | yes | yes | yes | yes | V17 V14 (0) |
| in_transition_to_fw | bool | yes | yes | yes | yes | V17 V14 (0) |
| system_type | uint8 (MAVLink MAV_TYPE) | yes | yes | yes | yes | V17 V14 (2 = quadrotor) |

Sources: P14 VehicleStatus.msg 79 to 84, 95 to 98, 101; P15 89 to 94, 110 to 113; P16 91 to 94, 110 to 113; P17 91 to 95, 111 to 114, 117. `vehicle_type` is the current locomotion, not the airframe: for a VTOL it is ROTARY_WING except when vehicle_vtol_state is FW (P17 `Commander.cpp` 2187 to 2190; P14 2038 to 2043), so it stays ROTARY_WING during both transitions. `is_vtol` comes from `system_type` being one of the MAV_TYPE VTOL values (P17 `commander_helper.cpp` 99 to 106). For log identity use `system_type` plus `is_vtol`; for R6 "not VTOL" use `is_vtol == 0` for the whole log.

Topic `vtol_vehicle_status` (published by vtol_att_control, optional in the logger, 200 ms interval):

| Field / constant | v1.13.3 (out of scope, for parsers) | v1.14.4 | v1.15.4 | v1.16.2 | v1.17.0 |
|---|---|---|---|---|---|
| file | `msg/vtol_vehicle_status.msg` | `msg/VtolVehicleStatus.msg` | same | `msg/versioned/VtolVehicleStatus.msg`, MESSAGE_VERSION 0 | same as v1.16 |
| VEHICLE_VTOL_STATE_UNDEFINED / TRANSITION_TO_FW / TRANSITION_TO_MC / MC / FW | 0 / 1 / 2 / 3 / 4 (constants only) | 0 / 1 / 2 / 3 / 4 | same | same | same |
| state field | none: bools `vtol_in_rw_mode`, `vtol_in_trans_mode`, `in_transition_to_fw` | `uint8 vehicle_vtol_state` | same | same | same |
| failure field | `vtol_transition_failsafe` | `bool fixed_wing_system_failure` (set by quadchute) | same | same | same |
| other | `fw_permanent_stab` | removed | | | |

Sources: P13 `msg/vtol_vehicle_status.msg` lines 10 to 14; P14 `msg/VtolVehicleStatus.msg` lines 2 to 12; P17 `msg/versioned/VtolVehicleStatus.msg` lines 3 to 15. In v1.13 `vehicle_status` also carried `vtol_fw_permanent_stab`, removed in v1.14. All SRC (no VTOL log yet).

#### 4.4.1 Item 6: VTOL transition semantics (source part)

vtol_att_control keeps an internal mode per airframe type and maps it to the published state (P17 `src/modules/vtol_att_control/vtol_att_control_main.cpp` 405 to 440; P14 385 to 420):

| Internal mode | Published vehicle_vtol_state |
|---|---|
| MC_MODE | 3 MC |
| TRANSITION_TO_FW (standard), TRANSITION_FRONT_P1 and TRANSITION_FRONT_P2 (tiltrotor), TRANSITION_FRONT_P1 (tailsitter) | 1 TRANSITION_TO_FW |
| TRANSITION_TO_MC (standard), TRANSITION_BACK (tiltrotor, tailsitter) | 2 TRANSITION_TO_MC |
| FW_MODE | 4 FW |

The state is initialised to MC (line 63 in both); UNDEFINED (0) is never published. Publication: v1.14 every control cycle (P14 lines 437 to 439); v1.16 and v1.17 immediately on a change of state or of fixed_wing_system_failure, else at 1 Hz (P17 lines 457 to 466). Requested direction comes from `_transition_command`, set by DO_VTOL_TRANSITION (param1 3 MC or 4 FW, param2 immediate; P17 lines 141 to 169), by action_request (RC switch; lines 114 to 139), and forced to MC when RTL starts during a front transition (lines 105 to 109; P14 124 to 127). DO_VTOL_TRANSITION to FW is rejected (TEMPORARILY_REJECTED) in AUTO_TAKEOFF, AUTO_LAND, AUTO_RTL and ORBIT (P17 lines 152 to 159).

Transition code paths (line numbers identical in P14 and P17 for standard.cpp; tiltrotor and tailsitter cited at P17):

| Observable sequence of vehicle_vtol_state | Meaning | Proposed event | Source lines |
|---|---|---|---|
| 3 to 1 | front transition starts | VTOL_TRANSITION_START (to_fw) | standard.cpp 120 to 125; tiltrotor.cpp 125 to 126; tailsitter.cpp 108 to 109 |
| 1 to 4 | front transition completed | VTOL_TRANSITION_END (to_fw) | standard.cpp 132 to 139 (isFrontTransitionCompleted); tiltrotor.cpp 133 to 136 (P1 to P2, still state 1) then 142 to 146 (P2 to FW); tailsitter.cpp 115 to 119 |
| 1 to 3 (never reached 4) | front transition aborted: FW no longer requested (MC command, RTL, or quadchute) | VTOL_TRANSITION_ABORT (to_fw) | standard.cpp 92 to 96; tiltrotor.cpp 86 to 93; tailsitter.cpp 87 to 89; quadchute path standard.cpp 74 to 77, tiltrotor.cpp 70 to 72, tailsitter.cpp 68 to 74 |
| 4 to 2 | back transition starts | VTOL_TRANSITION_START (to_mc) | standard.cpp 87 to 90; tiltrotor.cpp 82 to 83; tailsitter.cpp 83 to 84 |
| 2 to 3 | back transition completed (speed below MPC_XY_CRUISE, or VT_B_TRANS_DUR elapsed, or on ground) | VTOL_TRANSITION_END (to_mc) | standard.cpp 98 to 115; tiltrotor.cpp 96 to 114 (also needs tilt back to VT_TILT_MC); tailsitter.cpp 92 to 97 |
| 2 to 1 (standard) or 2 to 4 (tiltrotor, tailsitter) | back transition reversed because FW was requested again | VTOL_TRANSITION_ABORT (to_mc) | standard.cpp 120 to 125; tiltrotor.cpp 152 to 154; tailsitter.cpp 125 to 128 |
| 4 to 3 directly, with fixed_wing_system_failure becoming true | quadchute from fixed-wing flight: MC motors engaged immediately, no TRANSITION_TO_MC state | not a START/END pair; proposed VTOL_TRANSITION_ABORT (to_mc, reason quadchute); decision needed | standard.cpp 74 to 77 (any mode goes to MC_MODE when fixed_wing_system_failure) |
| log ends in 1 or 2 | transition never finished | START without END, R6 FAIL | n/a |

Quadchute: `VtolType::check_quadchute_condition` (P17 `vtol_type.cpp` 386 to 397; P14 393 to 403) evaluates `getQuadchuteReason` (P17 344 to 370: MinimumAltBreached, UncommandedDescent, TransitionAltitudeLoss, MaximumPitchExceeded, MaximumRollExceeded, TransitionTimeout) and the external command path (373 to 383), and calls `VtolAttitudeControl::quadchute` (P17 main.cpp 187 to 236; P14 206 to 258) which sets `fixed_wing_system_failure = true` once. Transition timeout (P17 `vtol_type.cpp` 327 to 342) fires when time since transition start exceeds the front transition timeout, or (v1.17) when calibrated airspeed is still below blend airspeed after the open-loop time. The flag is cleared only when a new transition to FW is commanded (P17 main.cpp 130 to 133 and 165 to 168). It is mirrored into `failsafe_flags.vtol_fixed_wing_system_failure`. Text evidence: v1.14 publishes a per-reason `mavlink_log_critical("Quadchute: <reason>")` (becomes an 'L' message at level '4') plus an event; v1.15 to v1.17 publish only a generic "Quad-chute triggered" 'L' message plus a per-reason event `vtol_att_ctrl_quadchute_*` at log level Critical (P17 main.cpp 191 to 226).

Command acks for transitions: commander lists DO_VTOL_TRANSITION among commands it ignores (P17 `Commander.cpp` 1510, P14 1385), navigator only adjusts cruise speed (P17 `navigator_main.cpp` 752 to 757), and vtol_att_control acks only commands with `from_external == true` (P17 main.cpp 171 to 181, P14 190 to 199). Internally issued transitions (mission items, VTOL takeoff, RC switch through commander line 359) therefore get no vehicle_command_ack. A COMMAND event for an internal DO_VTOL_TRANSITION with result NO_ACK is expected behaviour, not a fault.

Sampling caveat and recommendation: vtol_vehicle_status is logged at a 200 ms interval, so a state that lasts less than 200 ms can be missing from the log. vehicle_status is logged at interval 0 and commander copies the VTOL state into it on every change (P17 `Commander.cpp` 2184 to 2211; P14 2035 to 2059): `in_transition_mode && in_transition_to_fw` = state 1, `in_transition_mode && !in_transition_to_fw` = state 2, `!in_transition_mode && vehicle_type == 2` = state 4, `!in_transition_mode && vehicle_type == 1` = state 3. Deriving the transition timeline from vehicle_status and using vtol_vehicle_status (when present) for fixed_wing_system_failure and cross-checking is the more robust choice. All of 4.4.1 is SRC pending the VTOL golden log.

### 4.5 Item 4: failsafe flags

Topic `failsafe_flags`, published by commander HealthAndArmingChecks on change and at least every 500 ms (P14 `HealthAndArmingChecks.cpp` 103 to 105; P17 109 to 111). Plain .msg in all four versions (`msg/FailsafeFlags.msg`, not versioned). Field count: v1.14.4 39 (timestamp, 13 mode_req, 25 flags), v1.17.0 42 (timestamp, 14 mode_req, 27 flags). V17 V14 (exact field sets).

| Field | Type | Meaning | 1.14 | 1.15 | 1.16 | 1.17 |
|---|---|---|---|---|---|---|
| timestamp | uint64 | boot time us | y | y | y | y |
| mode_req_angular_velocity | uint32 | bitmask of nav_states (bit = 1 << nav_state) that need a valid angular velocity | y | y | y | y |
| mode_req_attitude | uint32 | modes needing attitude | y | y | y | y |
| mode_req_local_alt | uint32 | modes needing local altitude | y | y | y | y |
| mode_req_local_position | uint32 | modes needing local position | y | y | y | y |
| mode_req_local_position_relaxed | uint32 | modes needing reduced-accuracy local position | y | y | y | y |
| mode_req_global_position | uint32 | modes needing global position | y | y | y | y |
| mode_req_global_position_relaxed | uint32 | modes needing reduced-accuracy global position | n | n | n | y |
| mode_req_mission | uint32 | modes needing a mission | y | y | y | y |
| mode_req_offboard_signal | uint32 | modes needing offboard setpoints | y | y | y | y |
| mode_req_home_position | uint32 | modes needing home | y | y | y | y |
| mode_req_wind_and_flight_time_compliance | uint32 | modes blocked when wind or flight time limit exceeded | y | y | y | y |
| mode_req_prevent_arming | uint32 | modes in which arming is not allowed | y | y | y | y |
| mode_req_manual_control | uint32 | modes needing RC or joystick | y | y | y | y |
| mode_req_other | uint32 | other requirements (external modes) | y | y | y | y |
| angular_velocity_invalid | bool | angular velocity invalid | y | y | y | y |
| attitude_invalid | bool | attitude invalid | y | y | y | y |
| local_altitude_invalid | bool | local altitude invalid | y | y | y | y |
| local_position_invalid | bool | local position invalid | y | y | y | y |
| local_position_invalid_relaxed | bool | reduced-accuracy local position invalid | y | y | y | y |
| local_velocity_invalid | bool | local velocity invalid | y | y | y | y |
| global_position_invalid | bool | global position invalid | y | y | y | y |
| global_position_invalid_relaxed | bool | reduced-accuracy global position invalid | n | n | n | y |
| auto_mission_missing | bool | no mission available | y | y | y | y |
| offboard_control_signal_lost | bool | offboard signal lost | y | y | y | y |
| home_position_invalid | bool | no home position | y | y | y | y |
| manual_control_signal_lost | bool | RC or joystick lost | y | y | y | y |
| gcs_connection_lost | bool | GCS link lost | y | y | y | y |
| battery_warning | uint8 | battery warning level (battery_status warning values) | y | y | y | y |
| battery_low_remaining_time | bool | low remaining flight time | y | y | y | y |
| battery_unhealthy | bool | battery unhealthy | y | y | y | y |
| primary_geofence_breached | bool | primary geofence breached | y | renamed | | |
| geofence_breached | bool | one or more geofences breached | n | y | y | y |
| mission_failure | bool | mission failure | y | y | y | y |
| vtol_fixed_wing_system_failure | bool | quadchute happened | y | y | y | y |
| wind_limit_exceeded | bool | wind limit exceeded | y | y | y | y |
| flight_time_limit_exceeded | bool | max flight time exceeded | y | y | y | y |
| local_position_accuracy_low | bool | local position accuracy below threshold but still valid | y | y | y | renamed |
| position_accuracy_low | bool | position accuracy below threshold but still valid | n | n | n | y |
| navigator_failure | bool | navigator failed to execute a mode | n | n | y | y |
| fd_critical_failure | bool | attitude or altitude limit exceeded, or external ATS | y | y | y | y |
| fd_esc_arming_failure | bool | ESC failed to arm | y | y | y | y |
| fd_imbalanced_prop | bool | imbalanced propeller | y | y | y | y |
| fd_motor_failure | bool | motor failure | y | y | y | y |

Sources: P14 `msg/FailsafeFlags.msg` lines 6 to 57; P17 lines 6 to 60; diffs v1.14 to v1.15 (line 46 rename), v1.15 to v1.16 (navigator_failure added), v1.16 to v1.17 (two _relaxed fields added, accuracy rename). Mode requirement bitmask semantics: `setRequirement(nav_state, mask)` does `mask |= 1u << nav_state` (P14 and P17 `src/modules/commander/ModeUtil/mode_requirements.cpp` lines 40 to 42). V17 values: mode_req_manual_control 0x8547 (nav_states 0, 1, 2, 6, 8, 10, 15), mode_req_mission 0x8 (nav_state 3), mode_req_offboard_signal 0x4000 (nav_state 14).

**How vehicle_status.failsafe relates.** `vehicle_status.failsafe = _failsafe.inFailsafe()` and `failsafe_and_user_took_over = _failsafe.userTakeoverActive()` (P14 `Commander.cpp` 2232 to 2233; P17 2388 to 2389). `inFailsafe()` is `selected action != None` in v1.14 (P14 `failsafe/framework.h` 149) and `!= None && != Warn` in v1.15 to v1.17 (P17 line 150). The flags are inputs to the failsafe state machine; whether a flag causes an action depends on the mode requirement for the current mode and on parameters (for example NAV_DLL_ACT, NAV_RCL_ACT, COM_RCL_EXCEPT; P17 `failsafe/failsafe.cpp` 460 to 538 and 659 to 699). v1.15 added `failsafe_defer_state` (uint8, FAILSAFE_DEFER_STATE_DISABLED 0, ENABLED 1, WOULD_FAILSAFE 2; P17 VehicleStatus.msg 97 to 103).

**Observed in both SITL logs (matters for R4).** `auto_mission_missing`, `offboard_control_signal_lost`, `manual_control_signal_lost` and `gcs_connection_lost` were true from the first row to the last, through the whole armed flight, while `vehicle_status.failsafe` stayed 0. L17: NAV_DLL_ACT 0 (disabled), NAV_RCL_ACT 2, and the flown modes (4, 5, 17) are not in mode_req_manual_control. Estimator flags (attitude_invalid, local_* and global_*) were true at boot and cleared before arming (L17 last clear at 4,244,000 us; L14 at 7,588,000 us). A rule that fails on "any failsafe_flags bool true while armed" would fail every normal SITL flight. Options for the decision: (a) R4 fails on `vehicle_status.failsafe == 1` while armed, and FAILSAFE_SET/CLEAR events report flag edges (false to true, true to false) for explanation only; (b) R4 fails on a flag that is true while its mode_req bit for the current nav_state is set. The flag-to-mode_req mapping is by name (angular_velocity, attitude, local_alt, local_position, local_position_relaxed, global_position, global_position_relaxed, mission, offboard_signal, home_position, manual_control, wind_and_flight_time_compliance); non-mode flags (gcs, battery, geofence, fd_*, mission_failure, navigator_failure, vtol) need (a). FAILSAFE_SET should not be emitted for the initial value of a flag at log start without saying so. V17 V14.

`vehicle_status_flags` existed up to v1.13 (P13 `msg/vehicle_status_flags.msg`, present in S13 with fields such as `auto_mission_available`, `global_position_valid`, `offboard_control_signal_lost`, `battery_healthy`). It does not exist in v1.14 to v1.17; its role moved to `failsafe_flags` (inputs, inverted sense: names end in _invalid, _lost, _missing) and to the health and arming checks. V14 (absent), VS.

### 4.6 Item 5: commands and acknowledgements

`vehicle_command` fields (all versions; 15 fields in the log):

| Field | v1.14.4 type | v1.15.4 to v1.17.0 type | Notes |
|---|---|---|---|
| timestamp | uint64 | uint64 | publish time |
| param1, param2, param3, param4, param7 | float32 | float32 | NaN common for unused |
| param5, param6 | float64 | float64 | lat/lon |
| command | uint32 | uint32 | VEHICLE_CMD_* value |
| target_system | uint8 | uint8 | |
| target_component | uint8 | uint8 | 0 = all |
| source_system | uint8 | uint8 | |
| source_component | uint8 | **uint16** (component or mode executor) | changed in v1.15 |
| confirmation | uint8 | uint8 | 0 first send, 1 to 255 retransmissions |
| from_external | bool | bool | true when it came from MAVLink or DDS |

Sources: P14 `msg/VehicleCommand.msg` 165 to 178 (ORB_QUEUE_LENGTH 8 at 163); P15 178 to 184; P16 `msg/versioned/VehicleCommand.msg` 189 to 195 (MESSAGE_VERSION 0 at line 4); P17 `msg/versioned/VehicleCommand.msg` 183 to 196 (MESSAGE_VERSION 0 at line 4). V17 V14 (field sets; source_component width per format).

`vehicle_command_ack` fields (8 fields in the log):

| Field | v1.14.4 type | v1.15.4 to v1.17.0 type | Notes |
|---|---|---|---|
| timestamp | uint64 | uint64 | |
| command | uint32 | uint32 | command being acknowledged |
| result | uint8 | uint8 | VEHICLE_CMD_RESULT_* |
| result_param1 | uint8 | uint8 | progress percent or denial reason |
| result_param2 | int32 | int32 | |
| target_system | uint8 | uint8 | = source_system of the command |
| target_component | uint8 | **uint16** | = source_component of the command; changed in v1.15 |
| from_external | bool | bool | false for acks published by commander and navigator |

Sources: P14 `msg/VehicleCommandAck.msg` 5 to 33 (ORB_QUEUE_LENGTH 4); P15 26 to 33; P16 and P17 `msg/versioned/VehicleCommandAck.msg` 5 to 35 (MESSAGE_VERSION 0). V17 V14.

VEHICLE_CMD_RESULT_*: ACCEPTED 0, TEMPORARILY_REJECTED 1, DENIED 2, UNSUPPORTED 3, FAILED 4, IN_PROGRESS 5, CANCELLED 6 (same in all versions; P14 lines 8 to 14, P17 10 to 16). Observed: 0 and 5 (V17), 0 (V14).

VEHICLE_CMD_* values that matter for a flight (same values in v1.14 and v1.17 unless noted):

| Constant | Value | Params | Line P14 / P17 | Seen |
|---|---|---|---|---|
| NAV_RETURN_TO_LAUNCH | 20 | none | 13 / 15 | SRC |
| NAV_LAND | 21 | yaw, lat, lon, alt | 14 / 16 | V14 (commander land) |
| NAV_TAKEOFF | 22 | yaw, lat, lon, alt | 15 / 17 | V17 V14 |
| NAV_VTOL_TAKEOFF | 84 | | 20 / 23 | SRC |
| NAV_VTOL_LAND | 85 | | 21 / 24 | SRC |
| DO_SET_MODE | 176 | p1 base mode, p2 custom main, p3 custom sub | 32 / 35 | V17 V14 |
| DO_CHANGE_SPEED | 178 | | 34 / 37 | SRC |
| DO_FLIGHTTERMINATION | 185 | p1 > 0.5 | 40 / 43 | SRC |
| DO_LAND_START | 189 | | 43 / 46 | SRC |
| DO_REPOSITION | 192 | speed, bitmask, radius, yaw, lat, lon, alt | 45 / 48 | SRC |
| MISSION_START | 300 | | 75 / 79 | SRC |
| COMPONENT_ARM_DISARM | 400 | p1 1 arm, 0 disarm; p2 21196 force | 78 / 82 | V17 V14 (arm and disarm) |
| RUN_PREARM_CHECKS | 401 | | 79 / 83 | VS (S15, from QGC) |
| DO_VTOL_TRANSITION | 3000 | p1 target state 3 MC or 4 FW, p2 immediate | 95 / 101 | SRC |
| ARM_AUTHORIZATION_REQUEST | 3001 | | 96 / 102 | SRC |
| SET_NAV_STATE | 100001 | p1 nav_state | absent / 114 (also in v1.15, v1.16) | SRC |
| DO_FIGUREEIGHT | 35 | | absent / present | SRC |

There is no separate `VEHICLE_CMD_ARM_DISARM`; arming uses COMPONENT_ARM_DISARM 400 in every version. Other commands seen in the logs: 1000 DO_GIMBAL_MANAGER_PITCHYAW and 1001 DO_GIMBAL_MANAGER_CONFIGURE (navigator, at RTL start and at boot), 211 DO_GRIPPER (payload_deliverer at boot, V17), 512 REQUEST_MESSAGE (from QGC, VS), 0 CUSTOM_0 (V17 at 37,540,000 us; publisher not identified; commander ignores it, P17 `Commander.cpp` 1500).

**Who publishes acks, and which fields are filled.**

| Publisher | Fields set | Source (P17; P14 where different) |
|---|---|---|
| Commander::answer_command | timestamp, command, result, target_system = cmd.source_system, target_component = cmd.source_component; result_param1/2 = 0, from_external = false (zero init) | `Commander.cpp` 2642 to 2681 (fields 2675 to 2680); P14 2441 to 2475 (2469 to 2474) |
| Commander::handle_command | acks every handled command except: UNSUPPORTED is acked once in the default case; commands in the ignore list (DO_VTOL_TRANSITION, CUSTOM_0, gimbal, REQUEST_MESSAGE, DO_GRIPPER, DO_WINCH and others) are not acked by commander | `Commander.cpp` 1500 to 1554; P14 1375 to 1426 |
| Navigator::publish_vehicle_command_ack | timestamp, command, target = cmd.source, from_external false, result, result_param1/2 = 0 | `navigator_main.cpp` 1520 to 1534; P14 1438 to 1452 |
| MavlinkReceiver::acknowledge | timestamp, command, result, target = MAVLink sender sysid/compid, result_param1 = progress (commands rejected or handled inside the mavlink module; no vehicle_command is published for some of them) | `mavlink_receiver.cpp` 122 to 134; P14 111 to 123 |
| VtolAttitudeControl (DO_VTOL_TRANSITION) | only if cmd.from_external; target = cmd.source | `vtol_att_control_main.cpp` 171 to 181; P14 190 to 199 |
| payload_deliverer (DO_GRIPPER) | IN_PROGRESS then ACCEPTED; its helper takes `uint8_t target_component` | `payload_deliverer.cpp` 226 to 263 |
| Logger::ack_vehicle_command | logging start/stop commands | `logger.cpp` 2398 to 2409 |

**Pairing rule (no request id exists).** For each vehicle_command row C, the ack is the first not-yet-used vehicle_command_ack row A with A.command == C.command, A.timestamp >= C.timestamp, A.target_system == C.source_system and A.target_component == C.source_component, preferring a final result (result != 5 IN_PROGRESS; IN_PROGRESS rows are intermediate). Result: in L17 and L14 every commander-handled command paired with dt 0 to 12 ms (ARM 400, TAKEOFF 22, LAND 21, DO_SET_MODE 176, DISARM 400); dt 0 was observed (L17 400 at 7,760,000), so use `>=`. NO_ACK in L17 and L14 for 1000/1001 (gimbal, ignored by commander, no gimbal module), 0 (ignored). Limitations, all observed or source-evident: (1) acks carry no unique request id, so two commands with the same id from the same source before an ack are ambiguous; take the earliest command first. (2) Internal publishers can leave fields uninitialised: payload_deliverer declares `vehicle_command_s vcmd;` without `{}` (P17 `payload_deliverer.cpp` 239 to 244), so L17 has DO_GRIPPER with target_system 187, target_component 199, source_system 178, source_component 5184, confirmation 85 and garbage params, and its acks have target_component 64 (5184 truncated to uint8 by the helper at line 248), so the strict match gives NO_ACK although an IN_PROGRESS and an ACCEPTED ack exist. (3) Acks without any logged command exist (S15: about 28 acks for 512 REQUEST_MESSAGE that were never published as vehicle_command). (4) from_external on the ack is false even for external commands (S15), so it cannot be used for matching. (5) A command can legitimately receive no ack (internal DO_VTOL_TRANSITION, gimbal, CUSTOM_0). V17 V14 VS.

### 4.7 Item 6: logged messages ('L', 'C', events)

ULog message types are identical in P14 and P17 (`src/modules/logger/messages.h` lines 38 to 51): 'F' format, 'D' data, 'I' info, 'M' info multiple, 'P' parameter, 'Q' default parameter, 'A' add logged (subscription), 'R' remove, 'S' sync, 'O' dropout, 'L' logging, 'C' logging tagged, 'B' flag bits. pyulog `core.py` lines 35 to 47 use the same codes. PX4's own spec: P17 `docs/en/dev_log/ulog_file_format.md` ('L' 363 to 389, 'C' 390 to 433, 'O' 447 to 459, 'P' 258 to 274, 'Q' 275 to 300).

| Mechanism | How it reaches the ULog | Level encoding | Carries warnings and errors? | Verdict |
|---|---|---|---|---|
| `log_message` uORB topic | never logged as topic data; the logger reads it and writes an 'L' message (P17 `logger.cpp` 803 to 821, P14 797 to 815) | n/a | n/a | V17 V14 (topic absent) |
| 'L' logged string | `{uint8 log_level, uint64 timestamp, char message[]}`, message up to 127 chars; `log_level = severity + '0'` (P17 line 815), i.e. ASCII '0' to '7' (RFC 5424 / Linux kernel: 0 EMERG, 1 ALERT, 2 CRIT, 3 ERR, 4 WARNING, 5 NOTICE, 6 INFO, 7 DEBUG) | PX4_INFO 6, PX4_WARN 4, PX4_ERR 3, PX4_PANIC 0; PX4_DEBUG is never published (P14 and P17 `platforms/common/px4_log.cpp` 181 to 203, table 185 to 191). mavlink_log_info/warning/critical/emergency call PX4_INFO/PX4_WARN/PX4_WARN/PX4_ERR (P17 `src/lib/systemlib/mavlink_log.h` 82 to 122), so a "critical" mavlink message lands in 'L' as '4' | yes: '0', '3', '4' | V17 V14 (only '6' occurred; 15 and 22 messages), VS ('3' in S00, '4' in S15) |
| 'C' tagged string | `{uint8 log_level, uint16 tag, uint64 timestamp, char message[]}` | same characters | never written by the PX4 logger (no use of LOGGING_TAGGED in P14 or P17 logger.cpp); only third-party writers | V17 V14 (none), VS (S13 has tag 1 "tagged message test") |
| events | uORB `event` topic logged as 'D' data: id uint32, event_sequence uint16, arguments uint8[25], log_levels uint8 (high nibble internal level, low nibble external; 0 to 7 as above, 8 protocol, 9 disabled). Decoding needs 'M' `metadata_events` (xz JSON) and 'I' `metadata_events_sha256` (`logger.cpp` 2379 to 2396). The logger drops events whose internal level is Disabled and shifts event_sequence (967 to 1007 P14, 975 to 1015 P17) | levels as above | yes, and in v1.15+ some details exist only as events (quadchute reason, arming check failures) | V17 V14 VS |

Observed in L17 and L14: 31 and 36 event rows. pyulog decodes only group "default" (8 in L17, 13 in L14, all INFO, the same texts as the 'L' messages). The other rows are group arming_check and health: in L17, before arming, "No valid attitude estimate" (internal level 2 Critical), "Navigation error: No valid position estimate" (3 Error), "No offboard signal" (3), "No manual control input" (4 Warning), plus summaries at level 8 Protocol. A LOG_MESSAGE rule "warning or above" that includes events must decide whether to include the arming_check and health groups and whether to restrict to the armed interval. event_sequence wrapped in L17 (65526 to 65535, then 0), so it must not be used for ordering. V17 V14.

### 4.8 Item 7: in-flight parameter changes

| Fact | Evidence | Verdict |
|---|---|---|
| A change during logging appears as a 'P' message in the data section with the same layout as the definitions-section 'P' ("int32_t NAME" or "float NAME" key, value 4 bytes); only int32 and float exist | `messages.h` struct ulog_message_parameter_s 242 to 248; P17 `logger.cpp` 2308 to 2377 (P14 2282 to 2351); spec 258 to 274 and 466 to 467 | V17 V14 VS |
| 'P' carries no timestamp; its time is its position in the stream (pyulog assigns the last data timestamp seen, `core.py` line 1066) | pyulog source; S00 shows P at 158,196,367 us | V17 V14 VS |
| The logger writes 'P' when the `parameter_update` topic updates, and it writes every used parameter whose value is unsaved (`param_value_unsaved`), not just the one that changed | P17 `logger.cpp` 738 to 747 and 2326; P14 734 to 741 and 2300 | V17 V14 |
| The first logger loop writes a batch of all unsaved parameters at log start, with values equal to the definitions-section 'P' | L17: 17 'P' at 292,000 us all equal to initial; L14: 662 'P' at 260,000 us all equal to initial | V17 V14 |
| Changes made with `param_set_no_notification` or `commit_no_notification` do not publish parameter_update, so they appear only with the next notifying change, or never | P17 `src/lib/parameters/parameters.cpp` 404 to 481 (notify at 477 to 478), 496 to 504; param_notify_changes 156 to 180 | SRC |
| No 'P' is recorded after a stop is requested at disarm | P17 `logger.cpp` line 739 | SRC |
| parameter_update is logged by default (fields timestamp, instance, get_count, set_count, find_count, export_count, active, changed, custom_default; same in v1.14 and v1.17) | logged_topics lines in 4.1; L17 2 rows, L14 1 row | V17 V14 |
| Real in-flight change by the flight stack: CAL_BARO0_OFF 0.0 to -12.207 at 5,408,000 us, 624 ms after arming, from GNSS-based baro auto-calibration (SENS_BAR_AUTOCAL, default 1) which calls `ParametersSave` and `param_notify_changes` | L17; P17 `src/modules/sensors/vehicle_air_data/VehicleAirData.cpp` 257 to 261, 475 to 562 (save 553 to 558); relative multi-baro calibration 335 to 356 (exists in v1.16 and v1.17); SENS_BAR_AUTOCAL in P17 `vehicle_air_data/params.c` 57 to 67, absent in v1.14 to v1.16 | V17 |

Consequence for PARAM_CHANGED_IN_FLIGHT: emit only when a 'P' value differs from the last known value of that name (definitions-section 'P' then later data-section 'P'), and only between ARM and DISARM; otherwise the start-of-log batch produces hundreds of false events (662 in L14). 'Q' default parameters: S13, L17 and L14 carry 'Q' with default_types bit 0 (system) and bit 1 (current setup); L17 54 and 14 entries.

### 4.9 Item 8: dropouts

'O' message: `{uint16 duration}` in milliseconds, no timestamp (P14 and P17 `messages.h` 160 to 165). The logger marks the start of a dropout when a write into the log buffer fails because the buffer is full (`Logger::write_message`, P17 `logger.cpp` 1201 to 1226, P14 1190 to 1215); on the next successful write the writer first inserts an 'O' with `duration = (now - dropout_start) / 1000` truncated to uint16 (P17 `log_writer_file.cpp` 496 to 503 and 553 to 557; P14 508 to 515 and 565 to 569). The duration therefore measures the time messages were being lost, and its position in the stream (pyulog assigns the last data timestamp, `core.py` 1093 to 1098) gives the time. Observed: none in L17 and L14; S00 has 4 (0, 26, 31, 62 ms; a 0 ms dropout is possible). V17 V14 (absence), VS (format and values).

### 4.10 Item 9: GPS UTC time

| Fact | v1.14.4 | v1.15.4 / v1.16.2 | v1.17.0 | Verdict |
|---|---|---|---|---|
| Struct | `sensor_gps_s` from `msg/SensorGps.msg`, `# TOPICS sensor_gps vehicle_gps_position` | same | same | V17 V14 |
| vehicle_gps_position | selected or blended receiver (sensors/vehicle_gps_position module), logged at 500 ms (profile 1) | 100 ms | 100 ms | V17 V14 (presence; intervals SRC) |
| sensor_gps | per receiver, multi-instance up to 2, 1000 ms | same | same (high-rate-sensors profile: 4 instances at 0 ms) | V17 V14 |
| time_utc_usec | uint64, UTC us from the receiver, 0 when unavailable | same | same | V17 V14 |
| position fields | int32 lat, lon (1e-7 deg), int32 alt, alt_ellipsoid (mm) | float64 latitude_deg, longitude_deg, altitude_msl_m, altitude_ellipsoid_m | same as v1.15 | V17 V14 |
| fix_type | uint8, no constants | FIX_TYPE_* constants (NONE 1, 2D 2, 3D 3, RTCM 4, RTK float 5, RTK fixed 6, extrapolated 8) | same | V17 V14 |
| 'I' boot_time_utc_us | absent | absent | uint64, written at log start (`logger.cpp` 2130 to 2134) | V17 |

Mapping boot time to UTC: take the first sample (vehicle_gps_position, else sensor_gps instance 0) with `fix_type >= 2` and `time_utc_usec` after the GPS epoch, compute `offset = time_utc_usec - timestamp`, then `utc = boot_us + offset`. This is source-based; no log here has GPS UTC: the SIH simulator leaves `time_utc_usec = 0` on every row in both L17 (323 and 40 rows) and L14 (799 and 99 rows), with fix_type 3. v1.17 `boot_time_utc_us` is computed by `util::get_log_time` (P17 `src/modules/logger/util.cpp` 75 to 105): GPS time if fix >= 2 and valid, otherwise CLOCK_REALTIME, then minus boot time. In L17 it came from the host clock (1792293021672950 = 2026-10-18 03:10:21.673 UTC, matching the run start). It is a fallback whose source cannot be told from the log. `time_ref_utc` ('I', int32) is SDLOG_UTC_OFFSET in seconds (local time offset), not a UTC reference (P17 `logger.cpp` 2128). Recommendation for the record: emit UTC only from GPS time_utc_usec; label boot_time_utc_us as clock-derived if used.

### 4.11 Item 10: header identity

Written by `Logger::write_version` (P14 `logger.cpp` 2036 to 2117; P15 from 2042; P16 from 2056; P17 2061 to 2143). File header: magic "ULog" 0x01 0x12 0x35, version byte 1, uint64 start timestamp; 'B' flag bits right after (compat_flags[0] bit 0 = default parameters present; incompat flags 0; P17 2033 to 2059).

| Info key | Type | Content | Present | L17 | L14 |
|---|---|---|---|---|---|
| ver_sw | string | firmware git hash | always | d6f12ad1c4f70ad3230afd7d86e971421e02fef4 (= tag commit) | 1555f2bd2229544c43966ab5f94879c41d8e1e01 (= tag commit) |
| ver_sw_release | uint32 | 0xAABBCCTT major, minor, patch, type (255 release, 192 rc, 128 beta, 64 alpha, 0 dev; P17 `src/lib/version/version.c` 53 to 58, 159 to 161) | always | 17891583 = 0x011100FF = 1.17.0 release | 17695999 = 0x010E04FF = 1.14.4 release |
| ver_vendor_sw_release | uint32 | vendor version | if > 0 | 255 | 255 |
| ver_hw | string | board name | always | PX4_SITL | PX4_SITL |
| ver_hw_subtype | string | board sub type | if set | absent | absent |
| sys_name | string | "PX4" | always | PX4 | PX4 |
| sys_os_name | string | OS | always | Linux | Linux |
| ver_sw_branch | string | git branch | if known | absent (tag checkout) | absent |
| sys_os_ver | string | OS git hash (NuttX) | if known | absent | absent |
| ver_oem | string | OEM version | if set | absent | absent |
| sys_os_ver_release | uint32 | OS version | always | 101854463 | 101854463 |
| sys_toolchain, sys_toolchain_ver | string | compiler | always | GNU GCC, 13.3.0 | GNU GCC, 13.3.0 |
| sys_lib_ecl_ver | string | ECL library hash | v1.14 only, if set | n/a | absent |
| sys_mcu | string | MCU and revision | if available | absent | absent |
| ver_data_format | uint32 | 1 in v1.14, 2 in v1.15+ (lat/lon became double) | always | 2 | 1 |
| sys_uuid | string | board GUID | if SDLOG_UUID == 1 and the board has one | absent (SITL has none) | absent |
| time_ref_utc | int32 | SDLOG_UTC_OFFSET * 60 | always | 0 | 0 |
| boot_time_utc_us | uint64 | see 4.10 | v1.17 only | present | absent |
| replay | string | replayed file | replay only | absent | absent |
| log_type | string | "mission" | mission log only | absent | absent |
| metadata_events_sha256 ('I'), metadata_events ('M') | | events metadata | if the build has it | present | present |

Firmware for R2: compare `ver_sw` (hash) and `ver_sw_release` (decoded) against the baseline. V17 V14 for every row marked present or absent above.

### 4.12 Item 11: topics for the optional extended rules

| Rule input | Topic, field (type) | Version notes | Verdict |
|---|---|---|---|
| Minimum battery | battery_status.remaining (float32, 0 to 1, -1 unknown), voltage_v (float32), warning (uint8), connected (bool) | warning constants BATTERY_WARNING_NONE 0, LOW 1, CRITICAL 2, EMERGENCY 3, FAILED 4 (v1.14, v1.15) renamed WARNING_NONE to WARNING_FAILED with the same values (v1.16+); voltage_filtered_v and current_filtered_a removed in v1.16; versioned since v1.16 (MESSAGE_VERSION 0 in v1.16, 1 in v1.17); up to 3 instances in v1.17 (2 before). Also failsafe_flags.battery_warning | V17 V14 (fields; remaining 0.50 to 1.00, warning 0 in L17) |
| GPS fix at arm | vehicle_gps_position.fix_type (uint8), satellites_used (uint8), eph, epv (float32) at the ARM time | see 4.10 | V17 V14 |
| Estimator fault flags | estimator_status_flags: fs_bad_* (fault), reject_* (innovation rejection), cs_* (control status) bools; estimator_status.filter_fault_flags (uint32), control_mode_flags (uint64) | v1.16 renamed cs_gps to cs_gnss_pos, cs_gps_yaw to cs_gnss_yaw, cs_gps_yaw_fault to cs_gnss_yaw_fault; fs_bad_vel_n/e/d and fs_bad_pos_n/e/d removed in v1.15; fs_bad_acc_bias removed in v1.16; v1.17 adds cs_gnss_fault and others (74 fields vs 68 in v1.14). Multi-instance; the active estimator is estimator_selector_status.primary_instance (optional topic). Only instance 0 in both SITL logs | V17 V14 |
| Accelerometer clipping | vehicle_imu_status.accel_clipping[3] (uint32 per axis, cumulative since boot; use differences), gyro_clipping[3] | unchanged v1.14 to v1.17; multi-instance up to 4 at 1000 ms; match the primary IMU via accel_device_id against sensor_selection.accel_device_id; also estimator_status_flags.fs_bad_acc_clipping | V17 V14 |
| Vibration | vehicle_imu_status.accel_vibration_metric (m/s^2), gyro_vibration_metric (rad/s), delta_angle_coning_metric | unchanged v1.14 to v1.17 (estimator_status.vibe[] exists only in very old logs such as S00) | V17 V14 |
| Total dropout time | sum of 'O' durations | see 4.9 | VS |

### 4.13 Item 12: volatile parameters (item 5, source part)

PX4 marks parameters volatile in two ways: `volatile: true` in YAML parameter files and `@volatile` in legacy `*_params.c` comments. Search over `src/` and `boards/` of all four trees (script `work/fieldmap/volatile_yaml.py`).

| Parameter | Marked in | 1.14 | 1.15 | 1.16 | 1.17 | Purpose and who writes it |
|---|---|---|---|---|---|---|
| COM_FLIGHT_UUID | `commander_params.c` @volatile (P14 753, P15 615, P16 557, P17 564) | y | y | y | y | next flight number; incremented at disarm with commit_no_notification (P17 `Commander.cpp` 686 to 688; P14 1772 to 1775) |
| LND_FLIGHT_T_HI, LND_FLIGHT_T_LO | `land_detector_params.c` @volatile (lines 41 and 55 in all four) | y | y | y | y | total flight time (us, high and low 32 bits); updated at disarm after a takeoff with commit_no_notification (P17 `LandDetector.cpp` 185 to 200) |
| EKF2_MAG_DECL | P14 `ekf2_params_volatile.c` line 38 @volatile; P15 to P17 `src/modules/ekf2/params_volatile.yaml` volatile: true | y | y | y | y | magnetic declination learned from GPS position once per boot when it differs by more than 0.1 deg; commit_no_notification (P17 `EKF2.cpp` 2750 to 2762) |
| ASPD_SCALE_1, ASPD_SCALE_2, ASPD_SCALE_3 | `airspeed_selector_params.c` @volatile (100, 114, 128) | y | y | y | y | airspeed scale estimated in flight when enabled; commit_no_notification (P17 `airspeed_selector_main.cpp` 446 to 464) |
| SENS_DPRES_OFF | `sensor_params.c` @volatile (86) | y | y | y | y | differential pressure offset, set by airspeed calibration (P17 `commander/airspeed_calibration.cpp` 125 to 219) |
| CAL_ACCn_XOFF/YOFF/ZOFF, CAL_ACCn_XSCALE/YSCALE/ZSCALE | `sensors/module.yaml` volatile: true, n = 0 to 3 | y | y | y | y | accelerometer calibration (calibration command) |
| CAL_GYROn_XOFF/YOFF/ZOFF | same file, n = 0 to 3 | y | y | y | y | gyro calibration |
| CAL_MAGn_XOFF/YOFF/ZOFF, XSCALE/YSCALE/ZSCALE, XODIAG/YODIAG/ZODIAG, XCOMP/YCOMP/ZCOMP | same file, n = 0 to 3 | y | y | y | y | magnetometer calibration and current compensation |
| CAL_BAROn_OFF | same file, n = 0 to 3 | y | y | y | y | baro offset: calibration command; v1.16+ relative multi-baro calibration at startup; v1.17 GNSS auto-calibration (seen in flight in L17, 4.8) |
| COM_MODEn_HASH | `commander/module.yaml` volatile: true, n = 0 to 7 | n | y | y | y | identifier of external modes, written when a mode registers (P17 `ModeManagement.cpp` 165 to 173) |

Other parameters the flight stack writes at runtime (not marked volatile; from `param_set`, `param_set_no_notification`, `ParamX::commit` and `commit_no_notification` calls in `src/modules`, `src/lib`, `src/drivers` of P14 and P17):

| Group | Parameters | When | Ignore-list candidate? |
|---|---|---|---|
| Calibration routines | CAL_*_ID, CAL_*_PRIO, CAL_*_ROT and the volatile CAL_* above (`src/lib/sensor_calibration/Utilities.cpp` 67 to 198), SENS_BOARD_X_OFF and SENS_BOARD_Y_OFF (level calibration, `level_calibration.cpp` 165 to 166), TRIM_ROLL, TRIM_PITCH, TRIM_YAW (`rc_calibration.cpp` 89 to 97), TC_* (thermal calibration), CAL_MAG_SIDES (copied from SENS_MAG_SIDES, `VehicleMagnetometer.cpp` 109 to 111) | only on a calibration command, or automatically on first boot (SITL px4.log shows CAL_*_ID and CAL_*_PRIO set at startup) | no for R3 (a calibration change is a configuration change worth reporting); yes for learned values only |
| Autotune | MC_ROLLRATE_P/K/I/D, MC_ROLL_P, pitch and yaw equivalents, MC_AT_START; FW_RR_*, FW_R_TC, FW_PR_*, FW_P_TC, FW_YR_*, FW_AT_START | only when autotune runs (`mc_autotune_attitude_control.cpp` 552 to 584, `fw_autotune_attitude_control.cpp` 544 to 683) | no |
| Sanity clamps at startup or on parameter update | IMU_INTEG_RATE, IMU_GYRO_RATEMAX, LNDMC_Z_VEL_MAX, MPC_TILTMAX_AIR, MPC_TILTMAX_LND, MPC_XY_CRUISE, MPC_VEL_MANUAL, MPC_VEL_MAN_BACK, MPC_VEL_MAN_SIDE, MPC_Z_V_AUTO_UP, MPC_Z_V_AUTO_DN, MPC_THR_HOVER, MPC_POS_MODE, IMU_GYRO_FFT_LEN, EKF2_MULTI_IMU, EKF2_MULTI_MAG, SENS_MAG_MODE, EKF2_MAG_TYPE (v1.17), MAV_TYPE, MAV_SIK_RADIO_ID, MAN_ARM_GESTURE, MC_AIRMODE, CA_SV_CSn_TRIM and PWM centre (v1.17); v1.14 also migrates EKF2_AID_MASK into EKF2_GPS_CTRL, EKF2_EV_CTRL, EKF2_IMU_CTRL, EKF2_DRAG_CTRL, EKF2_OF_CTRL (P14 `EKF2.cpp` 737 to 900) | only when the stored value is invalid | no (a clamp means the configured value was invalid; report it) |
| Drivers | RC_INPUT_PROTO, BAT_SOURCE, BAT1_SOURCE, BAT1_N_CELLS (smart battery), DSHOT, camera trigger (TRIG_*), Sagetech transponder, px4io and PWM timer config | at driver start | no |
| Pilot tuning in flight | parameters mapped to RC_MAP_PARAMn (rc_update.cpp 284 to 295, `param_set` with notification) | continuously while the RC knob moves | no: this is a genuine in-flight change |
| Replay | any (replay module) | replay only | n/a |

Source-based default ignore list proposal (to be confirmed by the two-flight step): COM_FLIGHT_UUID, LND_FLIGHT_T_HI, LND_FLIGHT_T_LO (per-flight identifier and accumulators: change on every disarm and are autosaved, because `param_set_internal` calls `param_autosave()` for any change, P17 `parameters.cpp` 449 to 450, so the next flight's initial values differ), EKF2_MAG_DECL (learned from position), CAL_BARO*_OFF (learned at startup and in flight from v1.16/v1.17; L17 shows an in-flight change), ASPD_SCALE_1 to 3 (learned in flight when scale estimation is enabled), COM_MODE*_HASH (assigned when external modes register). Within a single log COM_FLIGHT_UUID and LND_FLIGHT_T_* do not appear as data-section 'P' (no notification; logging stops at disarm in SDLOG_MODE 0 and 1). V17 shows them constant (0) at log start. Note for the two-flight confirmation: both SITL runs used a fresh rootfs (L17 cmd.log "rootfs contents before start:" empty, `keep=no`), so COM_FLIGHT_UUID and LND_FLIGHT_T_* were 0 in both. The second flight must reuse the first flight's `parameters.bson` to see them change.

### 4.14 Confirmation status summary

| Item | v1.17 | v1.14 | v1.15 / v1.16 |
|---|---|---|---|
| 4.1 naming, default topics, rates | VERIFIED (names, presence, sensor_gps 1 s); default-profile intervals SOURCE-ONLY (logs use profile 131) | VERIFIED (same caveat) | SOURCE-ONLY |
| 4.2 arming fields and values | VERIFIED (1, 2, armed_time, reason 3 and 6) | VERIFIED (1, 2, reason 3) | SOURCE-ONLY |
| 4.3 nav_state table | VERIFIED for 4, 5, 17; rest SOURCE-ONLY | VERIFIED for 4, 5, 17, 18; rest SOURCE-ONLY | SOURCE-ONLY |
| 4.4 vehicle type fields | VERIFIED (MC values) | VERIFIED (MC values) | SOURCE-ONLY |
| 4.4 vtol_vehicle_status, 4.4.1 transitions | SOURCE-ONLY (no VTOL log) | SOURCE-ONLY | SOURCE-ONLY |
| 4.5 failsafe_flags fields and behaviour | VERIFIED | VERIFIED | SOURCE-ONLY |
| 4.6 command and ack fields, pairing | VERIFIED | VERIFIED | SOURCE-ONLY |
| 4.7 'L', events | VERIFIED (only level '6' seen in 'L'; warning levels seen in events) | VERIFIED (same) | SOURCE-ONLY ('4' seen in S15, v1.15 dev) |
| 4.7 'C' | VERIFIED absent | VERIFIED absent | format VS (S13) |
| 4.8 'P' in data section | VERIFIED (start batch and CAL_BARO0_OFF change) | VERIFIED (start batch) | SOURCE-ONLY |
| 4.9 'O' | not present | not present | format VS (S00) |
| 4.10 GPS UTC | fields VERIFIED; UTC mapping SOURCE-ONLY (SIH has no UTC); boot_time_utc_us VERIFIED | fields VERIFIED; mapping SOURCE-ONLY | SOURCE-ONLY |
| 4.11 header info | VERIFIED | VERIFIED | SOURCE-ONLY |
| 4.12 extended-rule topics | VERIFIED (fields) | VERIFIED (fields) | SOURCE-ONLY |
| 4.13 volatile list | SOURCE-ONLY except CAL_BARO0_OFF in-flight write (VERIFIED) | SOURCE-ONLY | SOURCE-ONLY |

### 4.15 Differences between v1.14 and v1.17

| Area | v1.14.4 | v1.15.4 | v1.16.2 | v1.17.0 | Impact |
|---|---|---|---|---|---|
| Message files | all in `msg/` | all in `msg/` | VehicleStatus, VtolVehicleStatus, VehicleCommand, VehicleCommandAck, VehicleLandDetected, BatteryStatus in `msg/versioned/` with MESSAGE_VERSION | as v1.16, plus Event versioned | none on topic names; MESSAGE_VERSION is not a log field |
| arming_state constants | INIT 0, STANDBY 1, ARMED 2, STANDBY_ERROR 3, SHUTDOWN 4, IN_AIR_RESTORE 5 | DISARMED 1, ARMED 2 | same | same | test `== 2` for armed |
| arming reason values | events enum (6 = auto_disarm_land); 1 = rc_stick | same | 1 renamed stick_gesture | same | decode with enums.json, not .msg constants |
| nav_state | 6, 7 undefined; 8, 9, 11, 16 UNUSED; MAX 23 | 6 POSITION_SLOW; 23 to 30 EXTERNAL1 to 8; MAX 31 | same as v1.15 | 8 ALTITUDE_CRUISE | per-version name table |
| vehicle_status new fields | none | executor_in_charge, valid_nav_states_mask, can_set_nav_states_mask, failsafe_defer_state | same | same | optional fields |
| vehicle_status removed | n/a | none | avoidance_system_required, avoidance_system_valid | same | none |
| vehicle_type constants | UNKNOWN 0 ... AIRSHIP 4 | same | 0 and 4 removed | UNSPECIFIED 0 | values 1, 2, 3 stable |
| vtol_vehicle_status publish rate | every control cycle | same | on change or 1 Hz | same | logged at 200 ms anyway |
| quadchute text | per-reason 'L' text plus event | generic 'L' text, reason only in event | same | same | reason needs event decoding from v1.15 |
| failsafe_flags | primary_geofence_breached, local_position_accuracy_low | geofence_breached | navigator_failure added | mode_req_global_position_relaxed, global_position_invalid_relaxed added; position_accuracy_low | per-version field list |
| vehicle_status.failsafe | action != None | action != None and != Warn | same | same | Warn-only actions no longer set failsafe |
| vehicle_command.source_component, ack target_component | uint8 | uint16 | uint16 | uint16 | compare as integers |
| new commands | n/a | SET_NAV_STATE 100001 | same | DO_FIGUREEIGHT 35 and others | none for core rules |
| GPS position fields | int32 lat, lon, alt (scaled) | float64 latitude_deg, longitude_deg, altitude_msl_m | same | same | not used by core rules |
| vehicle_gps_position log interval | 500 ms | 100 ms | 100 ms | 100 ms | finer UTC anchor |
| ver_data_format | 1 | 2 | 2 | 2 | none |
| boot_time_utc_us info | absent | absent | absent | present | optional UTC fallback (clock-derived) |
| sys_lib_ecl_ver info | possible | absent | absent | absent | none |
| battery_status | BATTERY_WARNING_*, voltage_filtered_v | same | WARNING_*, filtered fields removed | MESSAGE_VERSION 1, up to 3 instances | extended rule only |
| estimator_status_flags | cs_gps, cs_gps_yaw, fs_bad_vel_*, fs_bad_acc_bias | fs_bad_vel/pos removed | cs_gnss_* renames, fs_bad_acc_bias removed; logged at 10 ms | more cs_ fields | extended rule only |
| CAL_BAROn_OFF runtime writes | calibration only | calibration only | plus relative multi-baro at startup | plus GNSS auto-calibration (SENS_BAR_AUTOCAL 1), seen in flight | ignore-list candidate |
| COM_MODEn_HASH | absent | present, volatile | same | same | ignore-list candidate |
| EKF2_MAG_DECL volatile marker | params.c @volatile | params_volatile.yaml | same | same | none |

### 4.16 Notes for the coordinator

1. `diag/09_corrections.md`, row "Volatile parameters change every flight", says volatile is marked "in module.yaml files under commander, sensors, ekf2, land_detector and others". Source shows: YAML `volatile: true` only in `sensors/module.yaml`, `commander/module.yaml` (COM_MODEn_HASH, v1.15+) and `ekf2/params_volatile.yaml` (v1.15+). land_detector, commander (COM_FLIGHT_UUID), airspeed_selector and sensors (SENS_DPRES_OFF) use legacy `@volatile` in `*_params.c`. Its "41 fields" for FailsafeFlags at v1.17.0 matches this item if timestamp is excluded (42 with timestamp).
2. The L17 log was moved to `sitl_logs/v1.17.0/superseded/` during this item; the hash above identifies the file checked.
3. No VTOL log and no log with GPS UTC was available, so 4.4.1 and the UTC mapping remain SOURCE-ONLY.


## 5. Volatile parameters and the default ignore list

**Experiment (VERIFIED).** Two PX4 v1.17.0 SIH multicopter flights in the same working directory, so the parameter file persisted and no configuration was changed between them (`mc_flight_1.ulg`, `mc_flight_2.ulg`, procedure in item 3). Initial parameter values that differ:

| Parameter | Flight 1 | Flight 2 | Why it changes |
|---|---|---|---|
| `COM_FLIGHT_UUID` | 0 | 1 | Per-flight counter written by commander |
| `LND_FLIGHT_T_LO` | 0 | 29256000 | Accumulated flight time, written by land detector |
| `EKF2_MAG_DECL` | 0.0 | 3.4056 | Declination learned from position, saved by EKF2 |
| `CAL_BARO0_OFF` | 0.0 | 7.32 | Baro offset rewritten by GNSS auto-calibration (`SENS_BAR_AUTOCAL`, on by default in v1.17) |

`CAL_BARO1_ID`, `CAL_BARO2_ID` and `CAL_BARO3_ID` exist only in the first-boot log (901 parameters versus 898). No ULog info field differs except `boot_time_utc_us` and the perf-counter blobs.

**Source (SOURCE-ONLY, item 4).** PX4 marks these volatile in v1.14 through v1.17: `COM_FLIGHT_UUID`, `LND_FLIGHT_T_HI`, `LND_FLIGHT_T_LO`, `EKF2_MAG_DECL`, `ASPD_SCALE_1` to `_3`, `SENS_DPRES_OFF`, and the `CAL_ACC*`, `CAL_GYRO*`, `CAL_MAG*`, `CAL_BARO*` offset and scale families. `COM_MODE0_HASH` to `COM_MODE7_HASH` are volatile from v1.15.

**Decision proposed for founder approval: default ignore list.**

```toml
# rules.default.toml (Chunk 2). Patterns: * matches any run of characters.
ignore_parameters = [
  "COM_FLIGHT_UUID",   # per-flight identifier
  "LND_FLIGHT_T_HI",   # flight-time accumulator
  "LND_FLIGHT_T_LO",   # flight-time accumulator
  "EKF2_MAG_DECL",     # learned from position each flight
  "CAL_BARO*_OFF",     # rewritten by GNSS baro auto-calibration (v1.17)
  "ASPD_SCALE_*",      # airspeed scale learned in flight
  "COM_MODE*_HASH",    # external mode registration hashes (v1.15+)
]
```

Deliberately **not** on the default list, although PX4 marks them volatile: the accelerometer, gyro and magnetometer offsets and scales, and `SENS_DPRES_OFF`. A changed sensor calibration changes how the aircraft flies, so R3 should show it. A flight-test lead who recalibrates every flight can add those patterns to their rules file. R3 must also define how it treats a parameter present in the baseline and absent from the log (the `CAL_BARO*_ID` case); proposed: report it as a difference, with "absent" as the flown value.


## 6. VTOL transition semantics (rule R6)

**Evidence.** Standard VTOL SIH flights in PX4 v1.17.0 (item 3): `vtol_transition.ulg` (both transitions complete) and `vtol_transition_abort.ulg` (forward transition aborted by an RTL command). States are `vtol_vehicle_status.vehicle_vtol_state`: 1 TRANSITION_TO_FW, 2 TRANSITION_TO_MC, 3 MC, 4 FW.

| Log | Observed sequence (boot time, s) | Status |
|---|---|---|
| `vtol_transition.ulg` | 3 MC, 1 at 27.488, 4 FW at 30.504, 2 at 56.160, 3 MC at 56.760 | VERIFIED |
| `vtol_transition_abort.ulg` | 3 MC, 1 at 28.184, 3 MC at 29.024 (RTL at 29.020), never 4 | VERIFIED |

**Definitions proposed for founder approval.**

| Event | Definition | Status |
|---|---|---|
| VTOL_TRANSITION_START | state becomes 1 (direction forward) or 2 (direction back) | VERIFIED |
| VTOL_TRANSITION_END | 1 followed by 4 (forward), or 2 followed by 3 (back) | VERIFIED |
| VTOL_TRANSITION_ABORT | 1 followed by 3 without reaching 4 | VERIFIED |
| VTOL_TRANSITION_ABORT | 2 followed by 1 (standard VTOL), or 2 followed by 4 (tiltrotor, tailsitter) | SOURCE-ONLY |

**Signal choice.** `vtol_vehicle_status` is logged at 200 ms, so a short state can be missed. `vehicle_status.in_transition_mode` and `in_transition_to_fw` are logged on every change and mirror the states 8 to 12 ms later. Chunk 2 derives events from `vehicle_status` and cross-checks against `vtol_vehicle_status` when present. `vehicle_type` turns ROTARY_WING at the start of a back transition, not its end, so it is not used for END.

**R6 N/A** is decided from `vehicle_status.is_vtol`, not from the presence of `vtol_vehicle_status`: the logger's excluded-topics list stops at 40 entries and can omit it.

**Open decision.** A quadchute from fixed wing goes straight 4 to 3 with `failsafe_flags.vtol_fixed_wing_system_failure` set and no transition START. Proposed: R6 does not count it (no transition was started); R4 reports it as a failsafe.


## 7. Build check (musl, aarch64 musl, wasm32)

Diagnostic item 7. Evidence only; nothing under `/home/user/Sealed_Flight_Recorder-` was modified (`git status --short` is empty after the run). Scratch workspace: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/`.

Inputs read: `docs/SPEC.md` B1.7 (record format: SHA-256 Merkle leaves and nodes, Ed25519 over `SFR-RECORD-V1`, log `sha256` and `blake3`) and B1.10 (gates: static binaries via `ldd` "not a dynamic executable" for x86_64 and aarch64 musl; no network deny list; cargo-deny; crypto limited to `sha2`, `blake3`, `ed25519-dalek`; 100 MB seal under 2 s on x86_64 and under 4 s on real aarch64 hardware), `rust-toolchain.toml` (1.97.0, three targets), `deny-list.txt`, `deny.toml`.

### Verdict

* All five crates (sha2 0.11.1, blake3 1.8.7, ed25519-dalek 3.0.0, serde 1.0.229 + serde_json 1.0.154, toml 0.9.12) build with `--locked` on rustc 1.97.0 for x86_64-unknown-linux-musl, aarch64-unknown-linux-musl (cargo-zigbuild) and wasm32-unknown-unknown. Unit tests (SHA-256 "abc", BLAKE3 empty input, RFC 8032 section 7.1 TEST 1 sign plus verify_strict, serde JSON and TOML round trip) pass natively on x86_64 musl and under qemu-aarch64-static on aarch64 musl, for both blake3 backends.
* blake3 C on aarch64: **the NEON C intrinsics (`c/blake3_neon.c`) compile and link under zig cc 0.17.0**; the `pure` fallback was not needed (it also builds). blake3 has no aarch64 assembly; its assembly files are x86_64 only.
* Two findings against the literal SPEC B1.10 static-binary gate (details in "ldd and the static-binary gate"):
  1. Plain `cargo build --target x86_64-unknown-linux-musl` makes a static-pie binary, and the host `ldd` (glibc 2.39) prints `statically linked`, **not** `not a dynamic executable`. Both `cargo zigbuild` and `-C relocation-model=static` make a non-PIE static binary that prints `not a dynamic executable`.
  2. On an x86_64 host, `ldd` prints `not a dynamic executable` for **any** aarch64 binary, including a dynamically linked glibc one (probe below). So the aarch64 `ldd` gate passes whatever the binary is. The aarch64 builds here really are static (no dynamic section, no `PT_INTERP`, no `NEEDED`), but CI needs `readelf` or `file` to prove it.
* With plain `cargo build`, blake3 on x86_64 musl silently loses its assembly backends. cc-rs finds no `x86_64-linux-musl-gcc`, and blake3 falls back to Rust SSE2/SSE4.1/AVX2 intrinsics and drops AVX-512. That costs about half of blake3 throughput (1852 to 2442 MiB/s, against 3783 to 4370 MiB/s with assembly), but either way it is a small part of the 2 s budget.
* Supply chain: 0 deny-list hits (50 crate names, all targets, all features). `cargo deny check licenses advisories bans sources` with the repo `deny.toml`: `advisories ok, bans ok, licenses ok, sources ok` for both probe crates. The only warnings are duplicates (syn 2/3 when `wasm_js` is on; winnow 0.7/1.0 through toml 0.9.12).

### Environment

| Item | Value |
|---|---|
| rustc | 1.97.0 (2d8144b78 2026-07-07), LLVM 22.1.6. The scratch crates sit outside the repo, so `rust-toolchain.toml` did not apply and the `stable` toolchain ran; `rustup run stable rustc -vV` and `rustup run 1.97.0 rustc -vV` both report commit-hash 2d8144b7880597b6e6d3dfd63a9a9efae3f533d3, so it is the pinned compiler |
| Targets installed (1.97.0 and stable) | aarch64-unknown-linux-musl, wasm32-unknown-unknown, x86_64-unknown-linux-gnu, x86_64-unknown-linux-musl |
| cargo-zigbuild | 0.23.4 (`cargo-zigbuild --version`; `cargo zigbuild --version` is not a valid flag) |
| zig | 0.17.0 via `python3 -m ziglang` (PyPI `ziglang`, already present when checked; cargo-zigbuild invokes it as `/usr/bin/python3 -m ziglang`) |
| qemu | qemu-aarch64-static 8.2.2 (Ubuntu `qemu-user-static`, installed for this item with `apt-get install -y qemu-user-static`; no binfmt registration, it is called explicitly) |
| cargo-deny | 0.20.2, advisory-db commit 999ec89d5d3f (2026-10-17) |
| Host | Intel Xeon @ 2.10GHz, 4 vCPU, flags include avx2, avx512f, sha_ni; host cc is gcc 13.3.0 (glibc), no musl cross gcc; ldd from glibc 2.39 |
| Load | The machine was shared. Run 1 (02:59 to 03:06 UTC) ran next to a PX4 build (load average 1.7 to 6.6). The container then restarted. Run 2 (11:09 to 11:12 UTC), the clean confirmation pass, ran entirely under `nice -n 10` while a PX4 SITL `px4` instance was flying (load average 1.8 to 4.9) |

Note on the restart: every build sequence launched in run 1 had finished before the restart; the logs end with their `done` markers at 03:00:37, 03:00:57, 03:01:10 and 03:05:59 UTC. After the restart, I ran a complete fresh-target-dir confirmation pass under `nice -n 10` (`scripts/final_pass.sh`). Its results match run 1. The fresh x86_64 `cargo build` even reproduced the same ELF BuildID (`20b532b66a23a8ddcdf63948e547720c171e365e`) from a different target directory.

### Build matrix

Each cell is one `cargo` invocation on the probe crate. `cryptocheck` holds sha2 + blake3 + ed25519-dalek; `fmtcheck` holds serde + serde_json + toml. cargo compiles each dependency as its own unit and names any unit that fails, so a PASS means that crate compiled for that target.

| Crate (version, features) | x86_64-unknown-linux-musl `cargo build --release --locked` | aarch64-unknown-linux-musl `cargo zigbuild --release --locked` | wasm32-unknown-unknown `cargo build --release --locked --lib` |
|---|---|---|---|
| sha2 0.11.1 (default: alloc, oid) | PASS | PASS | PASS |
| blake3 1.8.7 (default: std) | PASS. Backend: Rust SSE2/SSE4.1/AVX2 intrinsics (`blake3_sse2_rust`, `blake3_sse41_rust`, `blake3_avx2_rust`); no assembly, no AVX-512; build warning `No C compiler "x86_64-linux-musl-gcc" detected.` | PASS. Backend: NEON C intrinsics compiled by zig cc (`blake3_neon`, links static lib `blake3_neon`) | PASS. Backend: portable Rust (build script emits no cfg, no C compiler invoked); `pure` not needed |
| blake3 1.8.7 + `pure` | PASS (same Rust intrinsics as above; on x86 `pure` only means "no C or assembly", binary is byte-size identical to default here) | PASS (portable Rust only, no NEON) | PASS |
| blake3 1.8.7 default with a C compiler for the musl target (`cargo zigbuild`, or `CC_x86_64_unknown_linux_musl=cc`) | PASS. Backend: assembly `blake3_sse2_sse41_avx2_assembly` + `blake3_avx512_assembly` (`*_ffi` cfgs) | n/a | n/a |
| blake3 1.8.7 + `wasm32_simd` | n/a | n/a | PASS, with and without `-C target-feature=+simd128` |
| ed25519-dalek 3.0.0 (default: fast, zeroize) | PASS | PASS | PASS |
| ed25519-dalek 3.0.0 + `rand_core`, getrandom 0.4.3 + `sys_rng` (probe feature `keygen`) | PASS; `SigningKey::generate` via `SysRng` ran OK | PASS | **FAIL** without `wasm_js`: getrandom `compile_error!` "The wasm32/64-unknown-unknown are not supported by default; you may need to enable the "wasm_js" crate feature." |
| same + getrandom `wasm_js` | PASS | PASS | PASS (feature alone is enough; adding `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'` also builds but has no effect in 0.4.3) |
| serde 1.0.229 (derive) | PASS | PASS | PASS |
| serde_json 1.0.154 | PASS | PASS | PASS |
| toml 0.9.12+spec-1.1.0 (newest 0.x; toml 1.1.8 is the current major, not tested) | PASS | PASS | PASS |
| Unit tests | `cargo test --release --target x86_64-unknown-linux-musl --locked`: 3/3 + 1/1 pass (native) | `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64-static cargo-zigbuild test --release --target aarch64-unknown-linux-musl --locked`: 3/3 (default), 3/3 (`blake3-pure`), 1/1 (fmtcheck) | build only (not executed) |
| `ldd` on `hashbench` | `statically linked` (static-pie) with `cargo build`; `not a dynamic executable` with `cargo zigbuild` or `-C relocation-model=static` | `not a dynamic executable` (no dynamic section, no INTERP, 0 NEEDED; but see the probe) | n/a |

Informational, outside the matrix:

| Variant | Result |
|---|---|
| aarch64 musl with plain `cargo build` (no zig), default features | FAIL in blake3 build script: `error occurred in cc-rs: failed to find tool "aarch64-linux-musl-gcc"` |
| aarch64 musl with plain `cargo build`, `blake3-pure` | Compiles; FAILS at link: host `/usr/bin/ld` rejects aarch64 `crt1.o` ("file in wrong format"). An aarch64 linker is needed whatever blake3 does; zigbuild provides it |
| CI setting `RUSTFLAGS="-D warnings"` + `cargo zigbuild` (aarch64) | PASS. zigbuild emits `warning: linker stderr: ignoring deprecated linker optimization setting "1"` (lint `linker_messages`); rustc notes "the `linker_messages` lint ignores `-D warnings`". `-A linker_messages` silences it |
| `RUSTFLAGS="-D warnings"` + `cargo build` x86_64 musl and wasm32 `--lib` | PASS (blake3's `cargo::warning` from its build script is not a rustc lint and does not fail the build; blake3 only turns it into an error when env `BLAKE3_CI` is set) |
| Whole `cryptocheck` package incl. `hashbench` bin for wasm32 | PASS (compiles; not run) |

### Exact Cargo.toml used

`cryptocheck/Cargo.toml` (versions pinned with `=` so the probe tests exactly the briefed versions):

```toml
[package]
name = "cryptocheck"
version = "0.1.0"
edition = "2021"
publish = false

[lib]
path = "src/lib.rs"

[[bin]]
name = "hashbench"
path = "src/main.rs"

[dependencies]
sha2 = "=0.11.1"
blake3 = "=1.8.7"
ed25519-dalek = "=3.0.0"
# Only pulled in by the `keygen` feature (OS RNG for key generation; sealing itself uses no randomness).
getrandom = { version = "0.4", optional = true, features = ["sys_rng"] }

[features]
default = []
# Key generation from the OS RNG via getrandom 0.4 SysRng (rand_core 0.10 CryptoRng adapter).
keygen = ["ed25519-dalek/rand_core", "dep:getrandom"]
# Needed on wasm32-unknown-unknown for getrandom (pulls wasm-bindgen + js-sys).
wasm_js = ["getrandom/wasm_js"]
# Force blake3 to its portable pure-Rust backend (no C, no assembly).
blake3-pure = ["blake3/pure"]
# Opt-in blake3 WebAssembly SIMD (Rust intrinsics, no C).
blake3-wasm-simd = ["blake3/wasm32_simd"]

[profile.release]
opt-level = 3
lto = false
codegen-units = 16
```

`fmtcheck/Cargo.toml`:

```toml
[package]
name = "fmtcheck"
version = "0.1.0"
edition = "2021"
publish = false

[dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.9"

[profile.release]
opt-level = 3
```

Resolved (Cargo.lock): getrandom 0.4.3, rand_core 0.10.1, curve25519-dalek 5.0.0, ed25519 3.0.0, signature 3.0.0, digest 0.11.3, cc 1.8.0 (build dep), wasm-bindgen 0.2.129, js-sys 0.3.106; serde/serde_core 1.0.229, serde_json 1.0.154, toml 0.9.12+spec-1.1.0, toml_parser 1.1.5, winnow 0.7.15 and 1.0.4.

Both probe crates carry `#![forbid(unsafe_code)]` in lib.rs and main.rs and compile with it.

#### What each crate needs (features)

* **ed25519-dalek 3.0.0**: default features (`fast`, `zeroize`) are enough for `SigningKey::from_bytes(&[u8; 32])`, `Signer::sign`, `VerifyingKey::from_bytes`, `VerifyingKey::verify_strict` and `Signature::from_bytes`/`to_bytes`. **`rand_core` is not required** for signing or verifying; the only thing it gates is `SigningKey::generate<R: rand_core::CryptoRng>` (and `batch`). With the default features, the graph has no `rand_core` and no `getrandom` on any target (see dependency lists). Signing is deterministic (RFC 8032); the same seed and message gave the same signature on every build (below). ed25519-dalek depends on sha2 0.11 itself, which unifies with the direct sha2 0.11.1 (one copy).
* **Keygen**: `getrandom = { version = "0.4", features = ["sys_rng"] }` plus `ed25519-dalek/rand_core`. `getrandom::SysRng` implements rand_core 0.10 `TryRng`; `SigningKey::generate(&mut UnwrapErr(SysRng))` is the upstream doc example. The probe first calls `try_fill_bytes` once, so an RNG failure comes back as an `Err`, not a panic.
  * musl (both arches): no extra features or cfg needed (Linux `getrandom` syscall backend; adds `libc`). Keygen ran successfully in the x86_64 musl static binary.
  * wasm32-unknown-unknown: getrandom 0.4.3 hits a `compile_error!` unless the `wasm_js` feature is enabled. **Confirmed: in getrandom 0.4.3 (and since 0.3.4) the `wasm_js` feature alone selects the backend.** The `--cfg getrandom_backend="wasm_js"` RUSTFLAGS form was needed only for getrandom 0.3.0 to 0.3.3. In 0.4.3, `wasm_js` is no longer a `getrandom_backend` value (its check-cfg list is custom, efi_rng, rdrand, rndr, linux_getrandom, linux_raw, windows_legacy, unsupported, extern_impl), so the flag does nothing. `wasm_js` adds wasm-bindgen 0.2.129, its macro/support/shared crates, bumpalo, once_cell and syn 3 (wasm32 normal deps grow from 17 to 29). getrandom's README advises against enabling `wasm_js` in library crates.
* **blake3 1.8.7**: features `std` (default), `pure`, `neon`, `no_neon`, `prefer_intrinsics`, `no_sse2`, `no_sse41`, `no_avx2`, `no_avx512`, `wasm32_simd`, `rayon`, `mmap`, `digest`, `traits-preview`, `serde`, `zeroize`. The fallback feature is named exactly `pure`. Build-script behaviour (from `build.rs`, confirmed by its emitted cfgs):
  * x86_64: with a working C compiler for the target, assembly for SSE2/SSE4.1/AVX2 plus AVX-512. With no compiler, or with `pure` or `prefer_intrinsics`, it uses Rust intrinsics for SSE2/SSE4.1/AVX2 and drops AVX-512. Either way, runtime CPU detection goes through `cpufeatures`.
  * aarch64 little-endian: compiles `c/blake3_neon.c` unless `pure` or `no_neon` is set; with either, portable Rust only.
  * wasm32: portable Rust by default; `wasm32_simd` adds Rust simd128 intrinsics. `platform.rs` then returns `Platform::WASM32_SIMD` unconditionally, so the module needs a SIMD-capable runtime.
* **sha2 0.11.1**: default features; uses `cpufeatures` for runtime detection (SHA-NI on x86_64, the SHA2 extension on aarch64 via `libc` getauxval); no C.
* **serde 1 / serde_json 1 / toml 0.9**: defaults plus `serde/derive`; pure Rust, no build-time C, same 18-crate tree on all three targets.

### ldd and the static-binary gate

Commands: `ldd <bin>`, `file <bin>`, `readelf -d <bin>`, `readelf -lW <bin> | grep -c INTERP`.

| Binary | Link mode | `ldd` | `file` | dynamic section / INTERP / NEEDED |
|---|---|---|---|---|
| x86_64 musl, `cargo build` (default and `keygen`) | static-pie (Rust default for this target) | `statically linked` | `ELF 64-bit LSB pie executable, x86-64, ..., static-pie linked` | 20 entries (RELA, FLAGS_1 NOW PIE, no NEEDED) / 0 / 0 |
| x86_64 musl, `RUSTFLAGS="-C relocation-model=static" cargo build` | static, non-PIE | `not a dynamic executable` | `ELF 64-bit LSB executable, x86-64, ..., statically linked` | none / 0 / 0 |
| x86_64 musl, `cargo zigbuild` | static, non-PIE, stripped | `not a dynamic executable` | `ELF 64-bit LSB executable, x86-64, ..., statically linked, stripped` | none / 0 / 0 |
| aarch64 musl, `cargo zigbuild` (default, `blake3-pure`, `keygen`) | static, non-PIE, stripped | `not a dynamic executable` | `ELF 64-bit LSB executable, ARM aarch64, ..., statically linked, stripped` | none / 0 / 0 |
| Probe: `zig cc -target aarch64-linux-gnu hello.c` (deliberately DYNAMIC) | dynamic, interpreter `/lib/ld-linux-aarch64.so.1` | **`not a dynamic executable`** | `... ARM aarch64 ... dynamically linked, interpreter /lib/ld-linux-aarch64.so.1` | present / 1 / 1 |
| Probe: `zig cc -target x86_64-linux-gnu hello.c` (dynamic, control) | dynamic | lists `libc.so.6`, `ld-linux-x86-64.so.2` | `dynamically linked` | present / 1 / 1 |

Exact ldd output, x86_64 musl `cargo build`:
```
$ ldd .../final/cc-x86_64-unknown-linux-musl/x86_64-unknown-linux-musl/release/hashbench
	statically linked
```
Exact ldd output, x86_64 musl `cargo zigbuild`, and aarch64 musl `cargo zigbuild`:
```
$ ldd .../final/cc-x86_64-unknown-linux-musl-zig/x86_64-unknown-linux-musl/release/hashbench
	not a dynamic executable
$ ldd .../final/cc-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/hashbench
	not a dynamic executable
```

What this means for the gate (evidence, not a decision): a binary-exact check for the string `not a dynamic executable` fails the default Rust x86_64 musl output. And on an x86_64 runner, the same check proves nothing for aarch64. Robust checks that hold on both: `readelf -lW` shows no `INTERP` program header and `readelf -d` shows no `NEEDED` entry, or `file` reports `statically linked`/`static-pie linked`. Building both musl targets with `cargo zigbuild` yields the literal `not a dynamic executable` on x86_64, and it also brings blake3's assembly back on x86_64.

### Throughput (100 MiB, single thread, measured under load)

**These numbers were measured on a shared 4-vCPU VM under load, not on an idle machine.** Run 1 ran beside a concurrent PX4 build. Run 2 ran under `nice -n 10` while a PX4 SITL flight was running; load average was 4.6 to 4.9 at the time. Treat them as lower bounds for this host, not as gate measurements.

Binary: `cryptocheck/src/main.rs` (`hashbench`). It fills a 100 MiB (104,857,600 byte) buffer from a fixed LCG, then reports the best of 3 runs of `blake3::hash(&buf)` (single thread, no rayon) and of `Sha256::digest(&buf)`. It then signs the SHA-256 digest with a fixed seed (`[0x42; 32]`) and runs `verify_strict`, once each.

Commands:
```
# run 2 (authoritative, after restart):
nice -n 10 scripts/final_pass.sh      # builds, then:
raw/bin-final/hashbench-x86_64-unknown-linux-musl-cargo-default 100
raw/bin-final/hashbench-x86_64-unknown-linux-musl-zigbuild-default 100
qemu-aarch64-static raw/bin-final/hashbench-aarch64-unknown-linux-musl-zigbuild-default 100
qemu-aarch64-static raw/bin-final/hashbench-aarch64-unknown-linux-musl-zigbuild-pure 100
# run 1 (before restart, not niced):
raw/bin/hashbench-x86_64-unknown-linux-musl-default 100
raw/bin/hashbench-x86_64-unknown-linux-musl-blake3pure 100
CC_x86_64_unknown_linux_musl=cc cargo build --release --target x86_64-unknown-linux-musl --locked; .../hashbench 100
cargo zigbuild --release --target x86_64-unknown-linux-musl --locked; .../hashbench 100
```
(paths relative to the scratch workspace above)

| Run | Build | blake3 backend | load avg (1 min) | blake3 | sha256 | ed25519 sign / verify_strict (single shot) |
|---|---|---|---|---|---|---|
| 1 | x86_64 `cargo build` default | Rust SSE2/SSE4.1/AVX2 intrinsics | 3.85 | 0.041 s, 2441.5 MiB/s | 0.090 s, 1110.3 MiB/s | 80.5 us / 106.0 us |
| 1 | x86_64 `cargo build` `blake3-pure` | same Rust intrinsics | 3.85 | 0.041 s, 2427.8 MiB/s | 0.090 s, 1114.4 MiB/s | 78.9 us / 91.2 us |
| 1 | x86_64 `CC_x86_64_unknown_linux_musl=cc cargo build` | asm SSE2..AVX2 + AVX-512 | 2.30 | 0.023 s, 4315.1 MiB/s | 0.091 s, 1103.8 MiB/s | 84.0 us / 91.7 us |
| 1 | x86_64 `cargo zigbuild` | asm SSE2..AVX2 + AVX-512 | 2.81 | 0.023 s, 4369.9 MiB/s | 0.096 s, 1043.9 MiB/s | 77.8 us / 108.7 us |
| 2 | x86_64 `cargo build` default, `nice -n 10` | Rust intrinsics | 4.58 | 0.054 s, 1852.2 MiB/s | 0.088 s, 1137.2 MiB/s | 82.1 us / 283.7 us |
| 2 | x86_64 `cargo zigbuild`, `nice -n 10` | asm incl. AVX-512 | 4.86 | 0.026 s, 3782.8 MiB/s | 0.091 s, 1098.3 MiB/s | 74.4 us / 99.0 us |
| 2 | aarch64 `cargo zigbuild` default under qemu-aarch64-static, `nice -n 10` | NEON C (emulated) | 4.86 | 1.169 s, 85.6 MiB/s | 2.519 s, 39.7 MiB/s | 8316.7 us / 7446.5 us |
| 2 | aarch64 `cargo zigbuild` `blake3-pure` under qemu, `nice -n 10` | portable Rust (emulated) | 4.26 | 0.506 s, 197.5 MiB/s | 2.739 s, 36.5 MiB/s | 8129.0 us / 6885.4 us |

Readings:
* x86_64: hashing a 100 MiB log with both SHA-256 and BLAKE3 costs about 0.11 to 0.15 s under load, roughly 6 to 8 percent of the 2 s seal gate, whichever blake3 backend is used. The assembly backend is about 1.8x to 2x faster than the Rust-intrinsics fallback. SHA-256 (sha2 with SHA-NI detected at run time) runs at about 1.1 GiB/s.
* aarch64 under qemu: with NEON, blake3 was **2.3x slower** than portable (85.6 against 197.5 MiB/s). That is an artifact of qemu TCG emulating NEON vector instructions and the opposite of what real hardware is expected to show. qemu numbers carry no information about the SPEC's "under 4 s on real aarch64 hardware" gate or about NEON against `pure`. **The aarch64 speed difference between blake3's NEON C backend and `pure` must be measured on real hardware in Chunk 5.**
* Determinism across builds: every build printed the same values, on x86_64 (intrinsics, assembly, pure) and on aarch64 (NEON, pure): BLAKE3 `e5a4b0c1d147d5dac9c1f6944874256a9c3019ef1a0ff18ebc330163c264525b`, SHA-256 `b301edcc039911eabd0e6e2aa15a180223599c4271373d9808f6544078f2326e`, Ed25519 signature `c6a07872...6f560a540e` (full value in raw output). The wasm32 build was compiled but not executed, so wasm parity is not shown here.

### Dependency trees (`cargo tree -e normal --locked --target <t>`)

Unique crates excluding the probe crate itself; `[pm]` marks a proc-macro (host-side, still listed by `-e normal`).

| Probe / features | Target | Count | Crates |
|---|---|---|---|
| cryptocheck default | x86_64-unknown-linux-musl | 23 | arrayvec 0.7.8, blake3 1.8.7, block-buffer 0.12.1, cfg-if 1.0.5, const-oid 0.10.2, constant_time_eq 0.4.2, cpufeatures 0.3.1, crypto-common 0.2.2, curve25519-dalek 5.0.0, curve25519-dalek-derive 0.1.1[pm], digest 0.11.3, ed25519 3.0.0, ed25519-dalek 3.0.0, hybrid-array 0.4.15, proc-macro2 1.0.107, quote 1.0.47, sha2 0.11.1, signature 3.0.0, subtle 2.6.1, syn 2.0.119, typenum 1.20.1, unicode-ident 1.0.27, zeroize 1.9.1 |
| cryptocheck default | aarch64-unknown-linux-musl | 19 | arrayvec, blake3, block-buffer, cfg-if, const-oid, constant_time_eq, cpufeatures, crypto-common, curve25519-dalek, digest, ed25519, ed25519-dalek, hybrid-array, libc 0.2.191, sha2, signature, subtle, typenum, zeroize (no proc-macro: curve25519-dalek's derive is only for its x86_64 SIMD backend) |
| cryptocheck default | wasm32-unknown-unknown | 17 | arrayvec, blake3, block-buffer, cfg-if, const-oid, constant_time_eq, crypto-common, curve25519-dalek, digest, ed25519, ed25519-dalek, hybrid-array, sha2, signature, subtle, typenum, zeroize |
| cryptocheck keygen,wasm_js | x86_64-unknown-linux-musl | 26 | default set + getrandom 0.4.3, libc 0.2.191, rand_core 0.10.1 |
| cryptocheck keygen,wasm_js | aarch64-unknown-linux-musl | 21 | default set + getrandom 0.4.3, rand_core 0.10.1 |
| cryptocheck keygen,wasm_js | wasm32-unknown-unknown | 29 | default set + bumpalo 3.20.3, getrandom 0.4.3, once_cell 1.21.4, proc-macro2, quote, rand_core 0.10.1, syn 3.0.9, unicode-ident, wasm-bindgen 0.2.129, wasm-bindgen-macro 0.2.129[pm], wasm-bindgen-macro-support 0.2.129, wasm-bindgen-shared 0.2.129 |
| fmtcheck | all three (identical trees) | 18 | itoa 1.0.18, memchr 2.8.3, proc-macro2 1.0.107, quote 1.0.47, serde 1.0.229, serde_core 1.0.229, serde_derive 1.0.229[pm], serde_json 1.0.154, serde_spanned 1.1.2, syn 3.0.9, toml 0.9.12+spec-1.1.0, toml_datetime 0.7.5+spec-1.1.0, toml_parser 1.1.5+spec-1.1.0, toml_writer 1.1.3+spec-1.1.0, unicode-ident 1.0.27, winnow 0.7.15, winnow 1.0.4, zmij 1.0.23 |

**Deny-list check:** I took the union of `cargo tree -e normal --target all --all-features` for both probes: 50 unique crate names. Intersecting it with the 67 names in `deny-list.txt` gives **0 hits**. No async runtime, HTTP, TLS, DNS or socket crate appears; wasm-bindgen/js-sys (only with `wasm_js`) are not networking crates.

**cargo-deny** (`cargo deny --all-features check licenses advisories bans sources`, repo `deny.toml` copied into each probe crate):
* cryptocheck: `advisories ok, bans ok, licenses ok, sources ok`; 1 warning `duplicate` for syn (2.0.119 via curve25519-dalek-derive, 3.0.9 via wasm-bindgen-macro-support).
* fmtcheck: `advisories ok, bans ok, licenses ok, sources ok`; 1 warning `duplicate` for winnow (0.7.15 direct from toml 0.9.12, 1.0.4 via toml_parser).
* Licenses of the three crypto crates: sha2 `MIT OR Apache-2.0`; blake3 `CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception`; ed25519-dalek `BSD-3-Clause` (also curve25519-dalek and subtle). Other expressions worth noting: constant_time_eq `CC0-1.0 OR MIT-0 OR Apache-2.0`; memchr `Unlicense OR MIT`; unicode-ident `(MIT OR Apache-2.0) AND Unicode-3.0`; r-efi `MIT OR Apache-2.0 OR LGPL-2.1-or-later`. r-efi is a UEFI-only dependency of getrandom, present only in the all-targets graph; deny passes it through the permissive alternatives.

**Unsafe census (informational):** I grepped non-test `.rs` sources of every registry crate in both probes' `cargo metadata --all-features` (all targets, build deps and proc-macros included) for the token `unsafe`, after removing `//` comments. Result: **59 registry crates; 40 contain `unsafe`, 19 do not.** The three crypto crates: sha2 39 tokens in 14 of 25 files (SIMD and SHA-extension intrinsics); blake3 232 in 13 of 19 (SIMD intrinsics, FFI to C/asm); curve25519-dalek 33 in 4 of 57; ed25519-dalek 0. Crates declaring `#![forbid(unsafe_code)]`: crypto-common, digest, ed25519, signature, typenum, serde_spanned, toml, toml_datetime, toml_writer. The SPEC B1.10 "No unsafe" gate applies to Inquiro crates only, and the probes compile with `#![forbid(unsafe_code)]`. Full table in the raw section.

### Notes for later chunks (evidence-based, no decision taken here)

1. Building both musl targets with `cargo zigbuild` gives one C toolchain for both, keeps blake3's x86_64 assembly, and makes the x86_64 `ldd` string match the gate literally. Setting `CC_x86_64_unknown_linux_musl` would also restore the assembly, but the binary stays static-pie (`statically linked`).
2. The aarch64 static-binary check in CI needs `readelf`/`file` (or `ldd` run on aarch64 hardware), because x86_64 `ldd` returns "not a dynamic executable" for any aarch64 binary.
3. The record and seal path needs ed25519-dalek default features only, with no RNG crates in the graph. Keygen can sit behind a CLI-only feature (`ed25519-dalek/rand_core` + `getrandom` with `sys_rng`), which keeps sfr-core and sfr-wasm free of getrandom. If browser keygen is ever needed, enable `getrandom/wasm_js` only in the sfr-wasm leaf crate.
4. The SPEC performance gate for aarch64 (100 MB seal under 4 s) and the choice between blake3 NEON and `pure` must be measured on real aarch64 hardware (Chunk 5); qemu inverts the ratio.
5. toml: 0.9.12 is the newest 0.x and works on all targets; toml 1.1.8 is the current major and was not built here. serde_json formats floats with `zmij` 1.0.23 (MIT). Whether serde_json output meets RFC 8785 number canonicalization (B1.7) was not part of this item.

### Raw outputs

Raw logs are under `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/raw/`; the scripts that produced them are under `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/scripts/`. The sections below are those logs with `Compiling`/`Downloaded` lines and blake3 build-script environment-probe noise (`rerun-if`, `check-cfg`, `= None`, `PATH =`) removed. Nothing else was edited.

<details><summary>Environment (env.txt)</summary>

```
date: Sun Oct 18 02:59:56 UTC 2026
rustc 1.97.0 (2d8144b78 2026-07-07)
binary: rustc
commit-hash: 2d8144b7880597b6e6d3dfd63a9a9efae3f533d3
commit-date: 2026-07-07
host: x86_64-unknown-linux-gnu
release: 1.97.0
LLVM version: 22.1.6
cargo 1.97.0 (c980f4866 2026-06-30)
cargo-zigbuild: cargo-zigbuild 0.23.4
zig: 0.17.0
cargo-deny: cargo-deny 0.20.2
qemu: qemu-aarch64 version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)
cc: cc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
nproc: 4
model name	: Intel(R) Xeon(R) Processor @ 2.10GHz
avx2 avx512f sha_ni sse4_1 
```

</details>

<details><summary>Run 2: final confirmation pass under nice -n 10 (final_pass.log, scripts/final_pass.sh)</summary>

```
rustc: rustc 1.97.0 (2d8144b78 2026-07-07)  cargo-zigbuild: cargo-zigbuild 0.23.4  zig: 0.17.0  qemu: qemu-aarch64 version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18)

################ 1a cryptocheck x86_64-unknown-linux-musl cargo build (default features) ################
2026-10-18T11:09:41Z
loadavg: 1.80 0.69 0.26 1/130 2233  niceness: 10

+ cargo build --release --target x86_64-unknown-linux-musl --locked
    Finished `release` profile [optimized] target(s) in 20.89s
[exit=0, wall=21 s]
--- blake3 build-script decisions ---
cargo::rustc-cfg=blake3_avx2_rust
cargo::rustc-cfg=blake3_sse2_rust
cargo::rustc-cfg=blake3_sse41_rust
cargo::warning=No C compiler "x86_64-linux-musl-gcc" detected.
--- ldd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/final/cc-x86_64-unknown-linux-musl/x86_64-unknown-linux-musl/release/hashbench ---
	statically linked
--- file ---
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, BuildID[sha1]=20b532b66a23a8ddcdf63948e547720c171e365e, not stripped
--- readelf: NEEDED entries=0, INTERP segments=0, dynamic section:  Dynamic section at offset 0xa1430 contains 20 entries: 

################ 1b cryptocheck x86_64-unknown-linux-musl cargo test (runs natively) ################
2026-10-18T11:10:02Z
loadavg: 2.27 0.90 0.34 1/131 3154  niceness: 10
test tests::blake3_empty ... ok
test tests::sha256_abc ... ok
test tests::ed25519_rfc8032_test1 ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

################ 1c cryptocheck x86_64-unknown-linux-musl cargo zigbuild (default features) ################
2026-10-18T11:10:03Z
loadavg: 2.27 0.90 0.34 2/133 3242  niceness: 10

+ cargo zigbuild --release --target x86_64-unknown-linux-musl --locked
warning: linker stderr: ignoring deprecated linker optimization setting "1"
  |
  = note: `#[warn(linker_messages)]` on by default

warning: `cryptocheck` (bin "hashbench") generated 1 warning
    Finished `release` profile [optimized] target(s) in 7.59s
[exit=0, wall=9 s]
--- blake3 build-script decisions ---
CC_x86_64_unknown_linux_musl = Some(/root/.cache/cargo-zigbuild/0.23.4/wrappers/c4e1/zigcc-x86_64-unknown-linux-musl-e859.sh)
cargo::rustc-cfg=blake3_avx2_ffi
cargo::rustc-cfg=blake3_avx512_ffi
cargo::rustc-cfg=blake3_sse2_ffi
cargo::rustc-cfg=blake3_sse41_ffi
cargo:rustc-link-lib=static=blake3_avx512_assembly
cargo:rustc-link-lib=static=blake3_sse2_sse41_avx2_assembly
--- ldd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/final/cc-x86_64-unknown-linux-musl-zig/x86_64-unknown-linux-musl/release/hashbench ---
	not a dynamic executable
--- file ---
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
--- readelf: NEEDED entries=0, INTERP segments=0, dynamic section:  There is no dynamic section in this file. 

################ 1d fmtcheck x86_64-unknown-linux-musl cargo build + test ################
2026-10-18T11:10:12Z
loadavg: 2.45 0.98 0.38 1/141 4156  niceness: 10

+ cargo build --release --target x86_64-unknown-linux-musl --locked
    Finished `release` profile [optimized] target(s) in 15.88s
[exit=0, wall=16 s]
test tests::round_trip ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

################ 2a cryptocheck aarch64-unknown-linux-musl cargo zigbuild (default features: blake3 NEON C via zig cc) ################
2026-10-18T11:10:30Z
loadavg: 3.60 1.31 0.50 3/154 5453  niceness: 10

+ cargo zigbuild --release --target aarch64-unknown-linux-musl --locked
warning: linker stderr: ignoring deprecated linker optimization setting "1"
  |
  = note: `#[warn(linker_messages)]` on by default

warning: `cryptocheck` (bin "hashbench") generated 1 warning
    Finished `release` profile [optimized] target(s) in 11.76s
[exit=0, wall=12 s]
--- blake3 build-script decisions ---
CC_aarch64_unknown_linux_musl = Some(/root/.cache/cargo-zigbuild/0.23.4/wrappers/c4e1/zigcc-aarch64-unknown-linux-musl-5d3b.sh)
cargo::rustc-cfg=blake3_neon
cargo:rustc-link-lib=static=blake3_neon
--- ldd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/final/cc-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/hashbench ---
	not a dynamic executable
--- file ---
ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
--- readelf: NEEDED entries=0, INTERP segments=0, dynamic section:  There is no dynamic section in this file. 

################ 2b cryptocheck aarch64-unknown-linux-musl cargo-zigbuild test under qemu-aarch64-static (default) ################
2026-10-18T11:10:42Z
loadavg: 4.02 1.52 0.58 2/137 6389  niceness: 10
     Running unittests src/lib.rs (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/final/cc-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/deps/cryptocheck-cef6e735d57f80cd)
test tests::blake3_empty ... ok
test tests::sha256_abc ... ok
test tests::ed25519_rfc8032_test1 ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
     Running unittests src/main.rs (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/final/cc-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/deps/hashbench-d10c6ce0c6703367)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

################ 2c cryptocheck aarch64-unknown-linux-musl cargo zigbuild --features blake3-pure ################
2026-10-18T11:10:43Z
loadavg: 4.02 1.52 0.58 1/137 6560  niceness: 10

+ cargo zigbuild --release --target aarch64-unknown-linux-musl --locked --features blake3-pure
warning: linker stderr: ignoring deprecated linker optimization setting "1"
  |
  = note: `#[warn(linker_messages)]` on by default

warning: `cryptocheck` (bin "hashbench") generated 1 warning
    Finished `release` profile [optimized] target(s) in 4.39s
[exit=0, wall=5 s]
--- blake3 build-script decisions ---
(empty list above = no C, no NEON cfg: portable Rust only)
--- ldd /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/final/cc-aarch64-unknown-linux-musl-pure/aarch64-unknown-linux-musl/release/hashbench ---
	not a dynamic executable
--- file ---
ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
--- readelf: NEEDED entries=0, INTERP segments=0, dynamic section:  There is no dynamic section in this file. 

################ 2d cryptocheck aarch64-unknown-linux-musl cargo-zigbuild test under qemu (blake3-pure) ################
2026-10-18T11:10:48Z
loadavg: 4.10 1.58 0.60 1/170 7551  niceness: 10
     Running unittests src/lib.rs (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/final/cc-aarch64-unknown-linux-musl-pure/aarch64-unknown-linux-musl/release/deps/cryptocheck-1ff081d8fe3f356b)
test tests::blake3_empty ... ok
test tests::sha256_abc ... ok
test tests::ed25519_rfc8032_test1 ... ok
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
     Running unittests src/main.rs (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/final/cc-aarch64-unknown-linux-musl-pure/aarch64-unknown-linux-musl/release/deps/hashbench-3fb8e7759b21f5f1)
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

################ 2e fmtcheck aarch64-unknown-linux-musl cargo zigbuild + test under qemu ################
2026-10-18T11:10:49Z
loadavg: 4.10 1.58 0.60 1/170 7703  niceness: 10

+ cargo zigbuild --release --target aarch64-unknown-linux-musl --locked
    Finished `release` profile [optimized] target(s) in 8.60s
[exit=0, wall=9 s]
test tests::round_trip ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.05s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

################ 3a cryptocheck wasm32-unknown-unknown cargo build --lib (default features) ################
2026-10-18T11:11:00Z
loadavg: 4.23 1.69 0.65 1/169 8555  niceness: 10

+ cargo build --release --target wasm32-unknown-unknown --locked --lib
    Finished `release` profile [optimized] target(s) in 6.55s
[exit=0, wall=7 s]
--- blake3 build-script decisions ---
(empty list above = blake3 portable Rust, no C compiler invoked)

################ 3b cryptocheck wasm32-unknown-unknown cargo build --lib --features keygen,wasm_js ################
2026-10-18T11:11:07Z
loadavg: 4.03 1.74 0.68 1/175 9164  niceness: 10

+ cargo build --release --target wasm32-unknown-unknown --locked --lib --features keygen,wasm_js
    Finished `release` profile [optimized] target(s) in 16.49s
[exit=0, wall=16 s]

################ 3c fmtcheck wasm32-unknown-unknown cargo build --lib ################
2026-10-18T11:11:23Z
loadavg: 4.63 1.99 0.78 1/203 10434  niceness: 10

+ cargo build --release --target wasm32-unknown-unknown --locked --lib
    Finished `release` profile [optimized] target(s) in 7.77s
[exit=0, wall=8 s]

################ 4 throughput, 100 MiB, best of 3, single thread, all under nice -n 10 ################
2026-10-18T11:11:31Z
loadavg: 4.58 2.02 0.79 2/202 10913  niceness: 10

loadavg before: 4.58 2.02 0.79 3/202 10917

+ /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/raw/bin-final/hashbench-x86_64-unknown-linux-musl-cargo-default 100
buffer: 100 MiB, best of 3 runs, single thread
blake3     0.054 s     1852.2 MiB/s  e5a4b0c1d147d5dac9c1f6944874256a9c3019ef1a0ff18ebc330163c264525b
sha256     0.088 s     1137.2 MiB/s  b301edcc039911eabd0e6e2aa15a180223599c4271373d9808f6544078f2326e
ed25519 sign 82.1 us, verify_strict 283.7 us, ok=true sig=c6a0787217dfbf478b4f1ec82850bfe3dde902e08e4608f7511dfd6cbe60c4015bbfd61a031adb2419736ca640757a9179255b67265bfeb9cb669d6f560a540e
[exit=0, wall=1 s]

loadavg before: 4.86 2.12 0.83 3/200 10927

+ /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/raw/bin-final/hashbench-x86_64-unknown-linux-musl-zigbuild-default 100
buffer: 100 MiB, best of 3 runs, single thread
blake3     0.026 s     3782.8 MiB/s  e5a4b0c1d147d5dac9c1f6944874256a9c3019ef1a0ff18ebc330163c264525b
sha256     0.091 s     1098.3 MiB/s  b301edcc039911eabd0e6e2aa15a180223599c4271373d9808f6544078f2326e
ed25519 sign 74.4 us, verify_strict 99.0 us, ok=true sig=c6a0787217dfbf478b4f1ec82850bfe3dde902e08e4608f7511dfd6cbe60c4015bbfd61a031adb2419736ca640757a9179255b67265bfeb9cb669d6f560a540e
[exit=0, wall=0 s]

loadavg before: 4.86 2.12 0.83 1/200 10937

+ qemu-aarch64-static /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/raw/bin-final/hashbench-aarch64-unknown-linux-musl-zigbuild-default 100
buffer: 100 MiB, best of 3 runs, single thread
blake3     1.169 s       85.6 MiB/s  e5a4b0c1d147d5dac9c1f6944874256a9c3019ef1a0ff18ebc330163c264525b
sha256     2.519 s       39.7 MiB/s  b301edcc039911eabd0e6e2aa15a180223599c4271373d9808f6544078f2326e
ed25519 sign 8316.7 us, verify_strict 7446.5 us, ok=true sig=c6a0787217dfbf478b4f1ec82850bfe3dde902e08e4608f7511dfd6cbe60c4015bbfd61a031adb2419736ca640757a9179255b67265bfeb9cb669d6f560a540e
[exit=0, wall=12 s]

loadavg before: 4.26 2.09 0.84 1/206 11122

+ qemu-aarch64-static /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/raw/bin-final/hashbench-aarch64-unknown-linux-musl-zigbuild-pure 100
buffer: 100 MiB, best of 3 runs, single thread
blake3     0.506 s      197.5 MiB/s  e5a4b0c1d147d5dac9c1f6944874256a9c3019ef1a0ff18ebc330163c264525b
sha256     2.739 s       36.5 MiB/s  b301edcc039911eabd0e6e2aa15a180223599c4271373d9808f6544078f2326e
ed25519 sign 8129.0 us, verify_strict 6885.4 us, ok=true sig=c6a0787217dfbf478b4f1ec82850bfe3dde902e08e4608f7511dfd6cbe60c4015bbfd61a031adb2419736ca640757a9179255b67265bfeb9cb669d6f560a540e
[exit=0, wall=11 s]

################ final pass done ################
2026-10-18T11:11:55Z
loadavg: 3.92 2.08 0.85 4/185 11535  niceness: 10
```

</details>

<details><summary>Run 1: x86_64-unknown-linux-musl builds (x86_64_musl_build.log)</summary>

```

################ cryptocheck default features, x86_64-unknown-linux-musl ################
2026-10-18T02:59:56Z
 02:59:56 up 41 min,  0 user,  load average: 2.01, 1.52, 0.90

+ cargo build --release --target x86_64-unknown-linux-musl --locked
    Finished `release` profile [optimized] target(s) in 16.58s
[exit=0]
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl/x86_64-unknown-linux-musl/release/build/blake3-1d77260f9390890e/output ---
cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "x86_64-linux-musl-gcc": No such file or directory (os error 2)
cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "x86_64-linux-musl-gcc": No such file or directory (os error 2)
Error { kind: IOError, message: "No such file or directory (os error 2)" }
cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "x86_64-linux-musl-gcc": No such file or directory (os error 2)
cargo::warning=No C compiler "x86_64-linux-musl-gcc" detected.
cargo::rustc-cfg=blake3_sse2_rust
cargo::rustc-cfg=blake3_sse41_rust
cargo::rustc-cfg=blake3_avx2_rust
--- ldd ---
	statically linked
--- file ---
/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl/x86_64-unknown-linux-musl/release/hashbench: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, BuildID[sha1]=20b532b66a23a8ddcdf63948e547720c171e365e, not stripped
--- readelf -d ---

Dynamic section at offset 0xa1430 contains 20 entries:
  Tag        Type                         Name/Value
--- INTERP segment ---
0
--- size ---
798960 bytes

################ cryptocheck --features keygen, x86_64-unknown-linux-musl ################
2026-10-18T03:00:12Z
 03:00:12 up 42 min,  0 user,  load average: 4.87, 2.18, 1.13

+ cargo build --release --target x86_64-unknown-linux-musl --locked --features keygen
    Finished `release` profile [optimized] target(s) in 6.17s
[exit=0]
--- ldd ---
	statically linked
--- file ---
/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl/x86_64-unknown-linux-musl/release/hashbench: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, BuildID[sha1]=56188ccba50c16fab59749a8142612e8c584ef0b, not stripped
--- readelf -d ---

Dynamic section at offset 0xa1410 contains 20 entries:
  Tag        Type                         Name/Value
--- INTERP segment ---
0
--- size ---
801248 bytes

+ /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl/x86_64-unknown-linux-musl/release/hashbench 1
buffer: 1 MiB, best of 3 runs, single thread
blake3     0.000 s     3114.6 MiB/s  1513e0b184fc321a05776f8074eed4d930ed78e97c2cdc52b3a0f01d85cb58c8
sha256     0.001 s     1485.2 MiB/s  b9a56eb486a3f0de877bfc5063efc387683db561edd38f0273fcc3078153980a
ed25519 sign 85.3 us, verify_strict 101.1 us, ok=true sig=7d164810555aee762e8182a9151495c71e50822fad171053309e691a66296b7c31950f784ee13791b4d53b18ab09bc957c5c7a0d240c12b588a0f0f1489dc10e
keygen via getrandom SysRng ok, pk=38d00bd8d3a9ef79e4b634dd3789020299d68d9913f84a2e947544e4b754ebed
[exit=0]

################ cryptocheck --features blake3-pure, x86_64-unknown-linux-musl ################
2026-10-18T03:00:19Z
 03:00:19 up 42 min,  0 user,  load average: 5.74, 2.45, 1.23

+ cargo build --release --target x86_64-unknown-linux-musl --locked --features blake3-pure
    Finished `release` profile [optimized] target(s) in 2.03s
[exit=0]
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl/x86_64-unknown-linux-musl/release/build/blake3-1d77260f9390890e/output ---
cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "x86_64-linux-musl-gcc": No such file or directory (os error 2)
cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "x86_64-linux-musl-gcc": No such file or directory (os error 2)
Error { kind: IOError, message: "No such file or directory (os error 2)" }
cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "x86_64-linux-musl-gcc": No such file or directory (os error 2)
cargo::warning=No C compiler "x86_64-linux-musl-gcc" detected.
cargo::rustc-cfg=blake3_sse2_rust
cargo::rustc-cfg=blake3_sse41_rust
cargo::rustc-cfg=blake3_avx2_rust
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl/x86_64-unknown-linux-musl/release/build/blake3-3cf19e8c2d956bf7/output ---
cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "x86_64-linux-musl-gcc": No such file or directory (os error 2)
cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "x86_64-linux-musl-gcc": No such file or directory (os error 2)
Error { kind: IOError, message: "No such file or directory (os error 2)" }
cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "x86_64-linux-musl-gcc": No such file or directory (os error 2)
cargo::warning=No C compiler "x86_64-linux-musl-gcc" detected.
cargo::rustc-cfg=blake3_sse2_rust
cargo::rustc-cfg=blake3_sse41_rust
cargo::rustc-cfg=blake3_avx2_rust
--- ldd ---
	statically linked
--- file ---
/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl/x86_64-unknown-linux-musl/release/hashbench: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, BuildID[sha1]=104e5573f3055616be46f308fb95e4e180980551, not stripped
--- readelf -d ---

Dynamic section at offset 0xa1430 contains 20 entries:
  Tag        Type                         Name/Value
--- INTERP segment ---
0
--- size ---
798960 bytes

################ fmtcheck, x86_64-unknown-linux-musl ################
2026-10-18T03:00:21Z
 03:00:21 up 42 min,  0 user,  load average: 5.74, 2.45, 1.23

+ cargo build --release --target x86_64-unknown-linux-musl --locked
    Finished `release` profile [optimized] target(s) in 16.49s
[exit=0]

################ done x86_64-unknown-linux-musl ################
2026-10-18T03:00:37Z
 03:00:37 up 42 min,  0 user,  load average: 6.62, 2.81, 1.36
```

</details>

<details><summary>Run 1: aarch64-unknown-linux-musl zigbuild builds plus plain cargo build attempts (aarch64_musl_build.log)</summary>

```
cargo-zigbuild: cargo-zigbuild 0.23.4  zig: 0.17.0

################ cryptocheck default features (blake3 NEON C intrinsics), aarch64-unknown-linux-musl, cargo zigbuild ################
2026-10-18T02:59:56Z
 02:59:56 up 41 min,  0 user,  load average: 2.01, 1.52, 0.90

+ cargo zigbuild --release --target aarch64-unknown-linux-musl --locked
warning: linker stderr: ignoring deprecated linker optimization setting "1"
  |
  = note: `#[warn(linker_messages)]` on by default

warning: `cryptocheck` (bin "hashbench") generated 1 warning
    Finished `release` profile [optimized] target(s) in 56.22s
[exit=0]
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/build/blake3-7bcd40957758c981/output ---
cargo::rustc-cfg=blake3_neon
CC_aarch64_unknown_linux_musl = Some(/root/.cache/cargo-zigbuild/0.23.4/wrappers/c4e1/zigcc-aarch64-unknown-linux-musl-5d3b.sh)
AR_aarch64_unknown_linux_musl = Some(/root/.cache/cargo-zigbuild/0.23.4/wrappers/c4e1/ar)
AR_aarch64_unknown_linux_musl = Some(/root/.cache/cargo-zigbuild/0.23.4/wrappers/c4e1/ar)
cargo:rustc-link-lib=static=blake3_neon
cargo:rustc-link-search=native=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/build/blake3-7bcd40957758c981/out
--- ldd ---
	not a dynamic executable
--- file ---
/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/hashbench: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
--- readelf -d ---

There is no dynamic section in this file.
--- INTERP segment ---
0
--- size ---
500632 bytes

################ cryptocheck --features blake3-pure, aarch64-unknown-linux-musl, cargo zigbuild ################
2026-10-18T03:00:53Z
 03:00:53 up 42 min,  0 user,  load average: 6.06, 2.87, 1.41

+ cargo zigbuild --release --target aarch64-unknown-linux-musl --locked --features blake3-pure
warning: linker stderr: ignoring deprecated linker optimization setting "1"
  |
  = note: `#[warn(linker_messages)]` on by default

warning: `cryptocheck` (bin "hashbench") generated 1 warning
    Finished `release` profile [optimized] target(s) in 1.29s
[exit=0]
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/build/blake3-7bcd40957758c981/output ---
cargo::rustc-cfg=blake3_neon
CC_aarch64_unknown_linux_musl = Some(/root/.cache/cargo-zigbuild/0.23.4/wrappers/c4e1/zigcc-aarch64-unknown-linux-musl-5d3b.sh)
AR_aarch64_unknown_linux_musl = Some(/root/.cache/cargo-zigbuild/0.23.4/wrappers/c4e1/ar)
AR_aarch64_unknown_linux_musl = Some(/root/.cache/cargo-zigbuild/0.23.4/wrappers/c4e1/ar)
cargo:rustc-link-lib=static=blake3_neon
cargo:rustc-link-search=native=/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/build/blake3-7bcd40957758c981/out
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/build/blake3-ca5ca938cddfefe3/output ---
--- ldd ---
	not a dynamic executable
--- file ---
/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/hashbench: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
--- readelf -d ---

There is no dynamic section in this file.
--- INTERP segment ---
0
--- size ---
494144 bytes

################ cryptocheck --features keygen, aarch64-unknown-linux-musl, cargo zigbuild ################
2026-10-18T03:00:54Z
 03:00:54 up 42 min,  0 user,  load average: 6.06, 2.92, 1.43

+ cargo zigbuild --release --target aarch64-unknown-linux-musl --locked --features keygen
warning: linker stderr: ignoring deprecated linker optimization setting "1"
  |
  = note: `#[warn(linker_messages)]` on by default

warning: `cryptocheck` (bin "hashbench") generated 1 warning
    Finished `release` profile [optimized] target(s) in 3.47s
[exit=0]
--- ldd ---
	not a dynamic executable
--- file ---
/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl/aarch64-unknown-linux-musl/release/hashbench: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, stripped
--- readelf -d ---

There is no dynamic section in this file.
--- INTERP segment ---
0
--- size ---
503936 bytes

################ fmtcheck, aarch64-unknown-linux-musl, cargo zigbuild ################
2026-10-18T03:00:58Z
 03:00:58 up 42 min,  0 user,  load average: 5.97, 2.95, 1.45

+ cargo zigbuild --release --target aarch64-unknown-linux-musl --locked
    Finished `release` profile [optimized] target(s) in 6.62s
[exit=0]

################ INFORMATIONAL: plain cargo build (no zig) for aarch64-unknown-linux-musl, default features ################
2026-10-18T03:01:05Z
 03:01:05 up 42 min,  0 user,  load average: 5.81, 2.97, 1.46
  process didn't exit successfully: `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl-nozig/release/build/blake3-567f9c9f89c7f89a/build-script-build` (exit status: 1)
  --- stdout
  cargo::rustc-cfg=blake3_neon
  cargo:warning=Compiler family detection failed due to error: ToolNotFound: failed to find tool "aarch64-linux-musl-gcc": No such file or directory (os error 2)

  --- stderr


  error occurred in cc-rs: failed to find tool "aarch64-linux-musl-gcc": No such file or directory (os error 2)


warning: build failed, waiting for other jobs to finish...
[exit=101]

################ INFORMATIONAL: plain cargo build (no zig) for aarch64-unknown-linux-musl, --features blake3-pure ################
2026-10-18T03:01:08Z
 03:01:08 up 43 min,  0 user,  load average: 5.43, 2.94, 1.46

+ cargo build --release --target aarch64-unknown-linux-musl --locked --features blake3-pure
error: linking with `cc` failed: exit status: 1
  |
  = note:  "cc" "<sysroot>/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crt1.o" "<sysroot>/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crti.o" "<sysroot>/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crtbegin.o" "/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl-nozig/aarch64-unknown-linux-musl/release/deps/rustcOM9qq1/symbols.o" "<7 object files omitted>" "-Wl,--as-needed" "-Wl,-Bstatic" "/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl-nozig/aarch64-unknown-linux-musl/release/deps/{libcryptocheck-5a28c68f89a03e10,libblake3-15a50ba7671fa91d,libconstant_time_eq-5409de7380d301a7,libarrayvec-7368e36e3d1c0568,libed25519_dalek-de2a79353204a9f9,libsha2-a99308dab5066404,libcpufeatures-2198c05566c41fa5,liblibc-4e7aa384cd6f19a8,libcurve25519_dalek-91e65e90902e38fe,libzeroize-495a3adc51c141d6,libsubtle-f581ae0986a2ee55,libcfg_if-01e5aa1a8f8b80fa,libdigest-c6aeed7a7228bf1c,libconst_oid-7ccbf82dd1fcf8ae,libcrypto_common-1231c10d067d3df9,libblock_buffer-0a8ef59dfad76797,libhybrid_array-aad6c274b18c1be6,libtypenum-8b8b452430266f56,libed25519-edd18d47bc7f04b5,libsignature-e972c4c3533d35d3}.rlib" "<sysroot>/lib/rustlib/aarch64-unknown-linux-musl/lib/{libstd-*,libpanic_unwind-*,libobject-*,libmemchr-*,libaddr2line-*,libgimli-*,libcfg_if-*,librustc_demangle-*,libstd_detect-*,libhashbrown-*,librustc_std_workspace_alloc-*,libminiz_oxide-*,libadler2-*,libunwind-*}.rlib" "-lunwind" "<sysroot>/lib/rustlib/aarch64-unknown-linux-musl/lib/liblibc-*.rlib" "-lc" "<sysroot>/lib/rustlib/aarch64-unknown-linux-musl/lib/{librustc_std_workspace_core-*,liballoc-*,libcore-*,libcompiler_builtins-*}.rlib" "-L" "/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl-nozig/aarch64-unknown-linux-musl/release/deps/rustcOM9qq1/raw-dylibs" "-Wl,-Bdynamic" "-Wl,--eh-frame-hdr" "-Wl,-z,noexecstack" "-nostartfiles" "-L" "<sysroot>/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained" "-L" "<sysroot>/lib/rustlib/aarch64-unknown-linux-musl/lib" "-o" "/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-aarch64-unknown-linux-musl-nozig/aarch64-unknown-linux-musl/release/deps/hashbench-17440d327a37e4e7" "-Wl,--gc-sections" "-static" "-no-pie" "-Wl,-z,relro,-z,now" "-Wl,-O1" "-Wl,--strip-debug" "-nodefaultlibs" "<sysroot>/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crtend.o" "<sysroot>/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crtn.o"
  = note: some arguments are omitted. use `--verbose` to show all linker arguments
  = note: /usr/bin/ld: /root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crt1.o: Relocations in generic ELF (EM: 183)
          /usr/bin/ld: /root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crt1.o: Relocations in generic ELF (EM: 183)
          /usr/bin/ld: /root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crt1.o: Relocations in generic ELF (EM: 183)
          /usr/bin/ld: /root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crt1.o: Relocations in generic ELF (EM: 183)
          /usr/bin/ld: /root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crt1.o: Relocations in generic ELF (EM: 183)
          /usr/bin/ld: /root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crt1.o: Relocations in generic ELF (EM: 183)
          /usr/bin/ld: /root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crt1.o: Relocations in generic ELF (EM: 183)
          /usr/bin/ld: /root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-musl/lib/self-contained/crt1.o: error adding symbols: file in wrong format
          collect2: error: ld returned 1 exit status
          

error: could not compile `cryptocheck` (bin "hashbench") due to 1 previous error
[exit=101]

################ done aarch64-unknown-linux-musl ################
2026-10-18T03:01:10Z
 03:01:10 up 43 min,  0 user,  load average: 5.43, 2.94, 1.46
```

</details>

<details><summary>Run 1: wasm32-unknown-unknown builds incl. getrandom with and without wasm_js (wasm32_build.log)</summary>

```

################ cryptocheck lib, default features, wasm32-unknown-unknown ################
2026-10-18T02:59:56Z
 02:59:56 up 41 min,  0 user,  load average: 2.01, 1.52, 0.90

+ cargo build --release --target wasm32-unknown-unknown --locked --lib
    Finished `release` profile [optimized] target(s) in 10.85s
[exit=0]
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-wasm32-unknown-unknown/wasm32-unknown-unknown/release/build/blake3-867442f620d987d3/output ---
-rw-r--r-- 2 root root 27896 Oct 18 03:00 /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-wasm32-unknown-unknown/wasm32-unknown-unknown/release/libcryptocheck.rlib

################ cryptocheck lib, --features keygen (no wasm_js): expect getrandom compile_error, wasm32-unknown-unknown ################
2026-10-18T03:00:07Z
 03:00:07 up 42 min,  0 user,  load average: 4.34, 2.03, 1.07

+ cargo build --release --target wasm32-unknown-unknown --locked --lib --features keygen
error: The wasm32/64-unknown-unknown are not supported by default; you may need to enable the "wasm_js" crate feature. For more information see: https://docs.rs/getrandom/0.4.3/#webassembly-support
   --> /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/getrandom-0.4.3/src/backends.rs:176:17
    |
176 | /                 compile_error!(concat!(
177 | |                     "The wasm32/64-unknown-unknown are not supported by default; \
178 | |                     you may need to enable the \"wasm_js\" crate feature. \
179 | |                     For more information see: \
180 | |                     https://docs.rs/getrandom/", env!("CARGO_PKG_VERSION"), "/#webassembly-support"
181 | |                 ));
    | |__________________^

error: could not compile `getrandom` (lib) due to 1 previous error
warning: build failed, waiting for other jobs to finish...
[exit=101]

################ cryptocheck lib, --features keygen,wasm_js, wasm32-unknown-unknown ################
2026-10-18T03:00:09Z
 03:00:09 up 42 min,  0 user,  load average: 4.87, 2.18, 1.13

+ cargo build --release --target wasm32-unknown-unknown --locked --lib --features keygen,wasm_js
    Finished `release` profile [optimized] target(s) in 14.93s
[exit=0]

################ cryptocheck lib, --features keygen,wasm_js with RUSTFLAGS --cfg getrandom_backend=wasm_js (getrandom 0.3 style), wasm32-unknown-unknown ################
2026-10-18T03:00:24Z
 03:00:24 up 42 min,  0 user,  load average: 5.92, 2.54, 1.26

+ cargo build --release --target wasm32-unknown-unknown --locked --lib --features keygen,wasm_js --target-dir /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-wasm32-unknown-unknown-cfg
    Finished `release` profile [optimized] target(s) in 17.53s
[exit=0]

################ cryptocheck lib, --features blake3-pure, wasm32-unknown-unknown ################
2026-10-18T03:00:41Z
 03:00:41 up 42 min,  0 user,  load average: 6.33, 2.81, 1.37

+ cargo build --release --target wasm32-unknown-unknown --locked --lib --features blake3-pure
    Finished `release` profile [optimized] target(s) in 0.69s
[exit=0]
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-wasm32-unknown-unknown/wasm32-unknown-unknown/release/build/blake3-70dc2485f21e69ca/output ---
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-wasm32-unknown-unknown/wasm32-unknown-unknown/release/build/blake3-867442f620d987d3/output ---

################ cryptocheck lib, --features blake3-wasm-simd (no target-feature flag), wasm32-unknown-unknown ################
2026-10-18T03:00:42Z
 03:00:42 up 42 min,  0 user,  load average: 6.33, 2.81, 1.37

+ cargo build --release --target wasm32-unknown-unknown --locked --lib --features blake3-wasm-simd
    Finished `release` profile [optimized] target(s) in 0.91s
[exit=0]
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-wasm32-unknown-unknown/wasm32-unknown-unknown/release/build/blake3-7016cc0515194525/output ---
cargo::rustc-cfg=blake3_wasm32_simd
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-wasm32-unknown-unknown/wasm32-unknown-unknown/release/build/blake3-70dc2485f21e69ca/output ---
--- blake3 build script output: /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-wasm32-unknown-unknown/wasm32-unknown-unknown/release/build/blake3-867442f620d987d3/output ---

################ cryptocheck lib, --features blake3-wasm-simd with RUSTFLAGS -C target-feature=+simd128, wasm32-unknown-unknown ################
2026-10-18T03:00:43Z
 03:00:43 up 42 min,  0 user,  load average: 6.07, 2.81, 1.38

+ cargo build --release --target wasm32-unknown-unknown --locked --lib --features blake3-wasm-simd --target-dir /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-wasm32-unknown-unknown-simd
    Finished `release` profile [optimized] target(s) in 4.54s
[exit=0]

################ INFORMATIONAL: cryptocheck whole package incl. hashbench bin, default, wasm32-unknown-unknown ################
2026-10-18T03:00:48Z
 03:00:48 up 42 min,  0 user,  load average: 6.06, 2.87, 1.41

+ cargo build --release --target wasm32-unknown-unknown --locked
    Finished `release` profile [optimized] target(s) in 0.19s
[exit=0]

################ fmtcheck lib, wasm32-unknown-unknown ################
2026-10-18T03:00:48Z
 03:00:48 up 42 min,  0 user,  load average: 6.06, 2.87, 1.41

+ cargo build --release --target wasm32-unknown-unknown --locked --lib
    Finished `release` profile [optimized] target(s) in 9.34s
[exit=0]

################ done wasm32-unknown-unknown ################
2026-10-18T03:00:57Z
 03:00:57 up 42 min,  0 user,  load average: 6.06, 2.92, 1.43
```

</details>

<details><summary>Run 1: experiments A to F (CC override, x86_64 zigbuild, non-PIE, -D warnings) (experiments.log)</summary>

```

################ EXP A: CC_x86_64_unknown_linux_musl=cc (host gcc 13 as the C compiler for the musl target), default features ################
2026-10-18T03:04:28Z
 03:04:28 up 46 min,  0 user,  load average: 1.71, 2.98, 1.82

+ cargo build --release --target x86_64-unknown-linux-musl --locked
    Finished `release` profile [optimized] target(s) in 7.39s
[exit=0]
--- blake3 rustc-cfg lines ---
CC_x86_64_unknown_linux_musl = Some(cc)
cargo::rustc-cfg=blake3_avx2_ffi
cargo::rustc-cfg=blake3_avx512_ffi
cargo::rustc-cfg=blake3_sse2_ffi
cargo::rustc-cfg=blake3_sse41_ffi
cargo:rustc-link-lib=static=blake3_avx512_assembly
cargo:rustc-link-lib=static=blake3_sse2_sse41_avx2_assembly
--- ldd ---
	statically linked
--- file ---
/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl-cc/x86_64-unknown-linux-musl/release/hashbench: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), static-pie linked, BuildID[sha1]=32f5cd54d250b0bdb1bf750a866036adea24cc2e, not stripped
--- readelf -d ---

Dynamic section at offset 0xa7418 contains 20 entries:
  Tag        Type                         Name/Value
--- INTERP segment ---
0
--- size ---
826480 bytes
load: 2.30 3.08 1.86 2/142 11340

+ /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl-cc/x86_64-unknown-linux-musl/release/hashbench 100
buffer: 100 MiB, best of 3 runs, single thread
blake3     0.023 s     4315.1 MiB/s  e5a4b0c1d147d5dac9c1f6944874256a9c3019ef1a0ff18ebc330163c264525b
sha256     0.091 s     1103.8 MiB/s  b301edcc039911eabd0e6e2aa15a180223599c4271373d9808f6544078f2326e
ed25519 sign 84.0 us, verify_strict 91.7 us, ok=true sig=c6a0787217dfbf478b4f1ec82850bfe3dde902e08e4608f7511dfd6cbe60c4015bbfd61a031adb2419736ca640757a9179255b67265bfeb9cb669d6f560a540e
[exit=0]

################ EXP B: cargo zigbuild for x86_64-unknown-linux-musl (zig cc as C compiler and linker), default features ################
2026-10-18T03:04:36Z
 03:04:36 up 46 min,  0 user,  load average: 2.30, 3.08, 1.86

+ cargo zigbuild --release --target x86_64-unknown-linux-musl --locked
warning: linker stderr: ignoring deprecated linker optimization setting "1"
  |
  = note: `#[warn(linker_messages)]` on by default

warning: `cryptocheck` (bin "hashbench") generated 1 warning
    Finished `release` profile [optimized] target(s) in 35.72s
[exit=0]
--- blake3 rustc-cfg lines ---
CC_x86_64_unknown_linux_musl = Some(/root/.cache/cargo-zigbuild/0.23.4/wrappers/c4e1/zigcc-x86_64-unknown-linux-musl-e859.sh)
cargo::rustc-cfg=blake3_avx2_ffi
cargo::rustc-cfg=blake3_avx512_ffi
cargo::rustc-cfg=blake3_sse2_ffi
cargo::rustc-cfg=blake3_sse41_ffi
cargo:rustc-link-lib=static=blake3_avx512_assembly
cargo:rustc-link-lib=static=blake3_sse2_sse41_avx2_assembly
--- ldd ---
	not a dynamic executable
--- file ---
/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl-zig/x86_64-unknown-linux-musl/release/hashbench: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
--- readelf -d ---

There is no dynamic section in this file.
--- INTERP segment ---
0
--- size ---
625376 bytes
load: 2.81 3.13 1.93 3/150 14482

+ /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl-zig/x86_64-unknown-linux-musl/release/hashbench 100
buffer: 100 MiB, best of 3 runs, single thread
blake3     0.023 s     4369.9 MiB/s  e5a4b0c1d147d5dac9c1f6944874256a9c3019ef1a0ff18ebc330163c264525b
sha256     0.096 s     1043.9 MiB/s  b301edcc039911eabd0e6e2aa15a180223599c4271373d9808f6544078f2326e
ed25519 sign 77.8 us, verify_strict 108.7 us, ok=true sig=c6a0787217dfbf478b4f1ec82850bfe3dde902e08e4608f7511dfd6cbe60c4015bbfd61a031adb2419736ca640757a9179255b67265bfeb9cb669d6f560a540e
[exit=0]

################ EXP C: RUSTFLAGS=-C relocation-model=static (non-PIE static) for x86_64-unknown-linux-musl, default features: what does ldd print ################
2026-10-18T03:05:13Z
 03:05:13 up 47 min,  0 user,  load average: 2.81, 3.13, 1.93

+ cargo build --release --target x86_64-unknown-linux-musl --locked
    Finished `release` profile [optimized] target(s) in 12.16s
[exit=0]
--- ldd ---
	not a dynamic executable
--- file ---
/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/target-x86_64-unknown-linux-musl-nopie/x86_64-unknown-linux-musl/release/hashbench: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, BuildID[sha1]=c280953ab0c0d40b0af1832aad57bf6af97e743f, not stripped
--- readelf -d ---

There is no dynamic section in this file.
--- INTERP segment ---
0
--- size ---
777920 bytes

################ EXP D: RUSTFLAGS='-D warnings' (CI setting) with cargo zigbuild for aarch64-unknown-linux-musl, default features ################
2026-10-18T03:05:25Z
 03:05:25 up 47 min,  0 user,  load average: 3.22, 3.21, 1.97

+ cargo zigbuild --release --target aarch64-unknown-linux-musl --locked
warning: linker stderr: ignoring deprecated linker optimization setting "1"
  |
  = note: `#[warn(linker_messages)]` on by default
  = note: the `linker_messages` lint ignores `-D warnings`

warning: `cryptocheck` (bin "hashbench") generated 1 warning
    Finished `release` profile [optimized] target(s) in 7.01s
[exit=0]

################ EXP D2: RUSTFLAGS='-D warnings -A linker_messages' with cargo zigbuild for aarch64-unknown-linux-musl ################
2026-10-18T03:05:32Z
 03:05:32 up 47 min,  0 user,  load average: 3.45, 3.26, 1.99

+ cargo zigbuild --release --target aarch64-unknown-linux-musl --locked
    Finished `release` profile [optimized] target(s) in 7.44s
[exit=0]

################ EXP E: RUSTFLAGS='-D warnings' with plain cargo build for x86_64-unknown-linux-musl (control) ################
2026-10-18T03:05:40Z
 03:05:40 up 47 min,  0 user,  load average: 3.77, 3.33, 2.03

+ cargo build --release --target x86_64-unknown-linux-musl --locked
    Finished `release` profile [optimized] target(s) in 12.22s
[exit=0]

################ EXP F: RUSTFLAGS='-D warnings' with plain cargo build for wasm32-unknown-unknown --lib (control) ################
2026-10-18T03:05:52Z
 03:05:52 up 47 min,  0 user,  load average: 4.26, 3.45, 2.08

+ cargo build --release --target wasm32-unknown-unknown --locked --lib
    Finished `release` profile [optimized] target(s) in 6.20s
[exit=0]

################ done experiments ################
2026-10-18T03:05:59Z
 03:05:59 up 47 min,  0 user,  load average: 4.85, 3.60, 2.15
```

</details>

<details><summary>Run 1: x86_64 throughput, default and blake3-pure (bench_x86_64_musl_run1.txt)</summary>

```
date: 2026-10-18T03:03:25Z
load before: 3.85 3.53 1.90 1/132 7566
cpu:  Intel(R) Xeon(R) Processor @ 2.10GHz

+ /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/raw/bin/hashbench-x86_64-unknown-linux-musl-default 100   # (default: blake3 cfgs blake3_sse2_rust+sse41_rust+avx2_rust, no asm, no avx512 (cc fallback))
buffer: 100 MiB, best of 3 runs, single thread
blake3     0.041 s     2441.5 MiB/s  e5a4b0c1d147d5dac9c1f6944874256a9c3019ef1a0ff18ebc330163c264525b
sha256     0.090 s     1110.3 MiB/s  b301edcc039911eabd0e6e2aa15a180223599c4271373d9808f6544078f2326e
ed25519 sign 80.5 us, verify_strict 106.0 us, ok=true sig=c6a0787217dfbf478b4f1ec82850bfe3dde902e08e4608f7511dfd6cbe60c4015bbfd61a031adb2419736ca640757a9179255b67265bfeb9cb669d6f560a540e

+ /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/raw/bin/hashbench-x86_64-unknown-linux-musl-blake3pure 100   # (blake3pure: blake3 feature pure: same Rust intrinsics cfgs on x86_64)
buffer: 100 MiB, best of 3 runs, single thread
blake3     0.041 s     2427.8 MiB/s  e5a4b0c1d147d5dac9c1f6944874256a9c3019ef1a0ff18ebc330163c264525b
sha256     0.090 s     1114.4 MiB/s  b301edcc039911eabd0e6e2aa15a180223599c4271373d9808f6544078f2326e
ed25519 sign 78.9 us, verify_strict 91.2 us, ok=true sig=c6a0787217dfbf478b4f1ec82850bfe3dde902e08e4608f7511dfd6cbe60c4015bbfd61a031adb2419736ca640757a9179255b67265bfeb9cb669d6f560a540e

load after: 3.85 3.53 1.90 1/133 7575
```

</details>

<details><summary>ldd probe: foreign-arch dynamic binary and static-pie (ldd_probe.txt)</summary>

```
+ zig cc -target aarch64-linux-gnu (dynamic glibc) hello.c
+ zig cc -target x86_64-linux-gnu (dynamic glibc) hello.c
+ zig cc -target x86_64-linux-musl (static, non-pie) hello.c

=== hello-aarch64-dynamic ===
ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 2.0.0, with debug_info, not stripped
ldd => 	not a dynamic executable|
readelf NEEDED => 1 entries; INTERP segments => 1

=== hello-x86_64-dynamic ===
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.0.0, with debug_info, not stripped
ldd => 	linux-vdso.so.1 (0x00007fdfbe8f5000)|	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fdfbe600000)|	/lib64/ld-linux-x86-64.so.2 (0x00007fdfbe8f7000)|
readelf NEEDED => 1 entries; INTERP segments => 1

=== hello-x86_64-musl-static ===
ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, with debug_info, not stripped
ldd => 	not a dynamic executable|
readelf NEEDED => 0 entries; INTERP segments => 0

=== x86_64 musl static-pie hashbench (Rust default): dynamic section entries ===

Dynamic section at offset 0xa1430 contains 20 entries:
  Tag        Type                         Name/Value
 0x000000000000000c (INIT)               0x5000
 0x000000000000000d (FINI)               0x7a613
 0x0000000000000019 (INIT_ARRAY)         0x9fff0
 0x000000000000001b (INIT_ARRAYSZ)       8 (bytes)
 0x000000000000001a (FINI_ARRAY)         0x9fff8
 0x000000000000001c (FINI_ARRAYSZ)       8 (bytes)
 0x000000006ffffef5 (GNU_HASH)           0x298
 0x0000000000000005 (STRTAB)             0x2d0
 0x0000000000000006 (SYMTAB)             0x2b8
 0x000000000000000a (STRSZ)              1 (bytes)
 0x000000000000000b (SYMENT)             24 (bytes)
 0x0000000000000015 (DEBUG)              0x0
 0x0000000000000003 (PLTGOT)             0xa25b0
 0x0000000000000007 (RELA)               0x2d8
 0x0000000000000008 (RELASZ)             18720 (bytes)
 0x0000000000000009 (RELAENT)            24 (bytes)
 0x000000000000001e (FLAGS)              BIND_NOW
 0x000000006ffffffb (FLAGS_1)            Flags: NOW PIE
 0x000000006ffffff9 (RELACOUNT)          780
 0x0000000000000000 (NULL)               0x0
NEEDED count: 0

=== ldd version ===
ldd (Ubuntu GLIBC 2.39-0ubuntu8.9) 2.39
```

</details>

<details><summary>cargo tree -e normal, per probe, feature set and target</summary>

```
===== tree_cryptocheck_default_x86_64-unknown-linux-musl  (cargo tree -e normal --locked --target <t> [--features keygen,wasm_js])
cryptocheck v0.1.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck)
├── blake3 v1.8.7
│   ├── arrayvec v0.7.8
│   ├── cfg-if v1.0.5
│   ├── constant_time_eq v0.4.2
│   └── cpufeatures v0.3.1
├── ed25519-dalek v3.0.0
│   ├── curve25519-dalek v5.0.0
│   │   ├── cfg-if v1.0.5
│   │   ├── cpufeatures v0.3.1
│   │   ├── curve25519-dalek-derive v0.1.1 (proc-macro)
│   │   │   ├── proc-macro2 v1.0.107
│   │   │   │   └── unicode-ident v1.0.27
│   │   │   ├── quote v1.0.47
│   │   │   │   └── proc-macro2 v1.0.107 (*)
│   │   │   └── syn v2.0.119
│   │   │       ├── proc-macro2 v1.0.107 (*)
│   │   │       ├── quote v1.0.47 (*)
│   │   │       └── unicode-ident v1.0.27
│   │   ├── digest v0.11.3
│   │   │   ├── block-buffer v0.12.1
│   │   │   │   └── hybrid-array v0.4.15
│   │   │   │       └── typenum v1.20.1
│   │   │   ├── const-oid v0.10.2
│   │   │   └── crypto-common v0.2.2
│   │   │       └── hybrid-array v0.4.15 (*)
│   │   ├── subtle v2.6.1
│   │   └── zeroize v1.9.1
│   ├── ed25519 v3.0.0
│   │   └── signature v3.0.0
│   ├── sha2 v0.11.1
│   │   ├── cfg-if v1.0.5
│   │   ├── cpufeatures v0.3.1
│   │   └── digest v0.11.3 (*)
│   ├── subtle v2.6.1
│   └── zeroize v1.9.1
└── sha2 v0.11.1 (*)

===== tree_cryptocheck_default_aarch64-unknown-linux-musl  (cargo tree -e normal --locked --target <t> [--features keygen,wasm_js])
cryptocheck v0.1.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck)
├── blake3 v1.8.7
│   ├── arrayvec v0.7.8
│   ├── cfg-if v1.0.5
│   └── constant_time_eq v0.4.2
├── ed25519-dalek v3.0.0
│   ├── curve25519-dalek v5.0.0
│   │   ├── cfg-if v1.0.5
│   │   ├── digest v0.11.3
│   │   │   ├── block-buffer v0.12.1
│   │   │   │   └── hybrid-array v0.4.15
│   │   │   │       └── typenum v1.20.1
│   │   │   ├── const-oid v0.10.2
│   │   │   └── crypto-common v0.2.2
│   │   │       └── hybrid-array v0.4.15 (*)
│   │   ├── subtle v2.6.1
│   │   └── zeroize v1.9.1
│   ├── ed25519 v3.0.0
│   │   └── signature v3.0.0
│   ├── sha2 v0.11.1
│   │   ├── cfg-if v1.0.5
│   │   ├── cpufeatures v0.3.1
│   │   │   └── libc v0.2.191
│   │   └── digest v0.11.3 (*)
│   ├── subtle v2.6.1
│   └── zeroize v1.9.1
└── sha2 v0.11.1 (*)

===== tree_cryptocheck_default_wasm32-unknown-unknown  (cargo tree -e normal --locked --target <t> [--features keygen,wasm_js])
cryptocheck v0.1.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck)
├── blake3 v1.8.7
│   ├── arrayvec v0.7.8
│   ├── cfg-if v1.0.5
│   └── constant_time_eq v0.4.2
├── ed25519-dalek v3.0.0
│   ├── curve25519-dalek v5.0.0
│   │   ├── cfg-if v1.0.5
│   │   ├── digest v0.11.3
│   │   │   ├── block-buffer v0.12.1
│   │   │   │   └── hybrid-array v0.4.15
│   │   │   │       └── typenum v1.20.1
│   │   │   ├── const-oid v0.10.2
│   │   │   └── crypto-common v0.2.2
│   │   │       └── hybrid-array v0.4.15 (*)
│   │   ├── subtle v2.6.1
│   │   └── zeroize v1.9.1
│   ├── ed25519 v3.0.0
│   │   └── signature v3.0.0
│   ├── sha2 v0.11.1
│   │   ├── cfg-if v1.0.5
│   │   └── digest v0.11.3 (*)
│   ├── subtle v2.6.1
│   └── zeroize v1.9.1
└── sha2 v0.11.1 (*)

===== tree_cryptocheck_keygen-wasm_js_x86_64-unknown-linux-musl  (cargo tree -e normal --locked --target <t> [--features keygen,wasm_js])
cryptocheck v0.1.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck)
├── blake3 v1.8.7
│   ├── arrayvec v0.7.8
│   ├── cfg-if v1.0.5
│   ├── constant_time_eq v0.4.2
│   └── cpufeatures v0.3.1
├── ed25519-dalek v3.0.0
│   ├── curve25519-dalek v5.0.0
│   │   ├── cfg-if v1.0.5
│   │   ├── cpufeatures v0.3.1
│   │   ├── curve25519-dalek-derive v0.1.1 (proc-macro)
│   │   │   ├── proc-macro2 v1.0.107
│   │   │   │   └── unicode-ident v1.0.27
│   │   │   ├── quote v1.0.47
│   │   │   │   └── proc-macro2 v1.0.107 (*)
│   │   │   └── syn v2.0.119
│   │   │       ├── proc-macro2 v1.0.107 (*)
│   │   │       ├── quote v1.0.47 (*)
│   │   │       └── unicode-ident v1.0.27
│   │   ├── digest v0.11.3
│   │   │   ├── block-buffer v0.12.1
│   │   │   │   └── hybrid-array v0.4.15
│   │   │   │       └── typenum v1.20.1
│   │   │   ├── const-oid v0.10.2
│   │   │   └── crypto-common v0.2.2
│   │   │       ├── hybrid-array v0.4.15 (*)
│   │   │       └── rand_core v0.10.1
│   │   ├── rand_core v0.10.1
│   │   ├── subtle v2.6.1
│   │   └── zeroize v1.9.1
│   ├── ed25519 v3.0.0
│   │   └── signature v3.0.0
│   │       └── rand_core v0.10.1
│   ├── rand_core v0.10.1
│   ├── sha2 v0.11.1
│   │   ├── cfg-if v1.0.5
│   │   ├── cpufeatures v0.3.1
│   │   └── digest v0.11.3 (*)
│   ├── signature v3.0.0 (*)
│   ├── subtle v2.6.1
│   └── zeroize v1.9.1
├── getrandom v0.4.3
│   ├── cfg-if v1.0.5
│   ├── libc v0.2.191
│   └── rand_core v0.10.1
└── sha2 v0.11.1 (*)

===== tree_cryptocheck_keygen-wasm_js_aarch64-unknown-linux-musl  (cargo tree -e normal --locked --target <t> [--features keygen,wasm_js])
cryptocheck v0.1.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck)
├── blake3 v1.8.7
│   ├── arrayvec v0.7.8
│   ├── cfg-if v1.0.5
│   └── constant_time_eq v0.4.2
├── ed25519-dalek v3.0.0
│   ├── curve25519-dalek v5.0.0
│   │   ├── cfg-if v1.0.5
│   │   ├── digest v0.11.3
│   │   │   ├── block-buffer v0.12.1
│   │   │   │   └── hybrid-array v0.4.15
│   │   │   │       └── typenum v1.20.1
│   │   │   ├── const-oid v0.10.2
│   │   │   └── crypto-common v0.2.2
│   │   │       ├── hybrid-array v0.4.15 (*)
│   │   │       └── rand_core v0.10.1
│   │   ├── rand_core v0.10.1
│   │   ├── subtle v2.6.1
│   │   └── zeroize v1.9.1
│   ├── ed25519 v3.0.0
│   │   └── signature v3.0.0
│   │       └── rand_core v0.10.1
│   ├── rand_core v0.10.1
│   ├── sha2 v0.11.1
│   │   ├── cfg-if v1.0.5
│   │   ├── cpufeatures v0.3.1
│   │   │   └── libc v0.2.191
│   │   └── digest v0.11.3 (*)
│   ├── signature v3.0.0 (*)
│   ├── subtle v2.6.1
│   └── zeroize v1.9.1
├── getrandom v0.4.3
│   ├── cfg-if v1.0.5
│   ├── libc v0.2.191
│   └── rand_core v0.10.1
└── sha2 v0.11.1 (*)

===== tree_cryptocheck_keygen-wasm_js_wasm32-unknown-unknown  (cargo tree -e normal --locked --target <t> [--features keygen,wasm_js])
cryptocheck v0.1.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck)
├── blake3 v1.8.7
│   ├── arrayvec v0.7.8
│   ├── cfg-if v1.0.5
│   └── constant_time_eq v0.4.2
├── ed25519-dalek v3.0.0
│   ├── curve25519-dalek v5.0.0
│   │   ├── cfg-if v1.0.5
│   │   ├── digest v0.11.3
│   │   │   ├── block-buffer v0.12.1
│   │   │   │   └── hybrid-array v0.4.15
│   │   │   │       └── typenum v1.20.1
│   │   │   ├── const-oid v0.10.2
│   │   │   └── crypto-common v0.2.2
│   │   │       ├── hybrid-array v0.4.15 (*)
│   │   │       └── rand_core v0.10.1
│   │   ├── rand_core v0.10.1
│   │   ├── subtle v2.6.1
│   │   └── zeroize v1.9.1
│   ├── ed25519 v3.0.0
│   │   └── signature v3.0.0
│   │       └── rand_core v0.10.1
│   ├── rand_core v0.10.1
│   ├── sha2 v0.11.1
│   │   ├── cfg-if v1.0.5
│   │   └── digest v0.11.3 (*)
│   ├── signature v3.0.0 (*)
│   ├── subtle v2.6.1
│   └── zeroize v1.9.1
├── getrandom v0.4.3
│   ├── cfg-if v1.0.5
│   ├── rand_core v0.10.1
│   └── wasm-bindgen v0.2.129
│       ├── cfg-if v1.0.5
│       ├── once_cell v1.21.4
│       ├── wasm-bindgen-macro v0.2.129 (proc-macro)
│       │   ├── quote v1.0.47
│       │   │   └── proc-macro2 v1.0.107
│       │   │       └── unicode-ident v1.0.27
│       │   └── wasm-bindgen-macro-support v0.2.129
│       │       ├── bumpalo v3.20.3
│       │       ├── proc-macro2 v1.0.107 (*)
│       │       ├── quote v1.0.47 (*)
│       │       ├── syn v3.0.9
│       │       │   ├── proc-macro2 v1.0.107 (*)
│       │       │   ├── quote v1.0.47 (*)
│       │       │   └── unicode-ident v1.0.27
│       │       └── wasm-bindgen-shared v0.2.129
│       │           └── unicode-ident v1.0.27
│       └── wasm-bindgen-shared v0.2.129
│           └── unicode-ident v1.0.27
└── sha2 v0.11.1 (*)

===== tree_fmtcheck_default_x86_64-unknown-linux-musl  (cargo tree -e normal --locked --target <t> [--features keygen,wasm_js])
fmtcheck v0.1.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/fmtcheck)
├── serde v1.0.229
│   ├── serde_core v1.0.229
│   └── serde_derive v1.0.229 (proc-macro)
│       ├── proc-macro2 v1.0.107
│       │   └── unicode-ident v1.0.27
│       ├── quote v1.0.47
│       │   └── proc-macro2 v1.0.107 (*)
│       └── syn v3.0.9
│           ├── proc-macro2 v1.0.107 (*)
│           ├── quote v1.0.47 (*)
│           └── unicode-ident v1.0.27
├── serde_json v1.0.154
│   ├── itoa v1.0.18
│   ├── memchr v2.8.3
│   ├── serde_core v1.0.229
│   └── zmij v1.0.23
└── toml v0.9.12+spec-1.1.0
    ├── serde_core v1.0.229
    ├── serde_spanned v1.1.2
    │   └── serde_core v1.0.229
    ├── toml_datetime v0.7.5+spec-1.1.0
    │   └── serde_core v1.0.229
    ├── toml_parser v1.1.5+spec-1.1.0
    │   └── winnow v1.0.4
    ├── toml_writer v1.1.3+spec-1.1.0
    └── winnow v0.7.15

===== tree_fmtcheck_default_aarch64-unknown-linux-musl  (cargo tree -e normal --locked --target <t> [--features keygen,wasm_js])
fmtcheck v0.1.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/fmtcheck)
├── serde v1.0.229
│   ├── serde_core v1.0.229
│   └── serde_derive v1.0.229 (proc-macro)
│       ├── proc-macro2 v1.0.107
│       │   └── unicode-ident v1.0.27
│       ├── quote v1.0.47
│       │   └── proc-macro2 v1.0.107 (*)
│       └── syn v3.0.9
│           ├── proc-macro2 v1.0.107 (*)
│           ├── quote v1.0.47 (*)
│           └── unicode-ident v1.0.27
├── serde_json v1.0.154
│   ├── itoa v1.0.18
│   ├── memchr v2.8.3
│   ├── serde_core v1.0.229
│   └── zmij v1.0.23
└── toml v0.9.12+spec-1.1.0
    ├── serde_core v1.0.229
    ├── serde_spanned v1.1.2
    │   └── serde_core v1.0.229
    ├── toml_datetime v0.7.5+spec-1.1.0
    │   └── serde_core v1.0.229
    ├── toml_parser v1.1.5+spec-1.1.0
    │   └── winnow v1.0.4
    ├── toml_writer v1.1.3+spec-1.1.0
    └── winnow v0.7.15

===== tree_fmtcheck_default_wasm32-unknown-unknown  (cargo tree -e normal --locked --target <t> [--features keygen,wasm_js])
fmtcheck v0.1.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/fmtcheck)
├── serde v1.0.229
│   ├── serde_core v1.0.229
│   └── serde_derive v1.0.229 (proc-macro)
│       ├── proc-macro2 v1.0.107
│       │   └── unicode-ident v1.0.27
│       ├── quote v1.0.47
│       │   └── proc-macro2 v1.0.107 (*)
│       └── syn v3.0.9
│           ├── proc-macro2 v1.0.107 (*)
│           ├── quote v1.0.47 (*)
│           └── unicode-ident v1.0.27
├── serde_json v1.0.154
│   ├── itoa v1.0.18
│   ├── memchr v2.8.3
│   ├── serde_core v1.0.229
│   └── zmij v1.0.23
└── toml v0.9.12+spec-1.1.0
    ├── serde_core v1.0.229
    ├── serde_spanned v1.1.2
    │   └── serde_core v1.0.229
    ├── toml_datetime v0.7.5+spec-1.1.0
    │   └── serde_core v1.0.229
    ├── toml_parser v1.1.5+spec-1.1.0
    │   └── winnow v1.0.4
    ├── toml_writer v1.1.3+spec-1.1.0
    └── winnow v0.7.15

```

</details>

<details><summary>Deny-list cross check</summary>

```
deny-list names (67), from deny-list.txt:
actix actix-rt actix-web async-executor async-global-executor async-io async-std async-tungstenite attohttpc axum curl curl-sys futures-executor glommio grpcio h2 h3 hickory-dns hickory-resolver http http-body hyper hyper-rustls hyper-tls hyper-util isahc lapin libp2p may minreq mio monoio native-tls nats net2 openssl openssl-sys paho-mqtt polling quinn redis reqwest rocket rumqttc rustls rustls-native-certs s2n-quic smol smoltcp socket2 surf tide tokio tokio-stream tokio-tungstenite tokio-util tonic tower tower-http trust-dns-resolver tungstenite ureq warp webpki-roots websocket ws zmq 

union of crate names, both probes, cargo tree -e normal --target all --all-features (50):
arrayvec blake3 block-buffer bumpalo cfg-if const-oid constant_time_eq cpufeatures crypto-common cryptocheck curve25519-dalek curve25519-dalek-derive digest ed25519 ed25519-dalek fiat-crypto fmtcheck getrandom hybrid-array itoa js-sys libc memchr once_cell proc-macro2 quote r-efi rand_core serde serde_core serde_derive serde_json serde_spanned sha2 signature subtle syn toml toml_datetime toml_parser toml_writer typenum unicode-ident wasm-bindgen wasm-bindgen-macro wasm-bindgen-macro-support wasm-bindgen-shared winnow zeroize zmij 

comm -12 (hits): 0
```

</details>

<details><summary>cargo deny output (repo deny.toml)</summary>

```
+ (cryptocheck) cargo deny --all-features check licenses advisories bans sources
warning[duplicate]: found 2 duplicate entries for crate 'syn'
   ┌─ /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/cryptocheck/Cargo.lock:35:1
   │  
35 │ ╭ syn 2.0.119 registry+https://github.com/rust-lang/crates.io-index
36 │ │ syn 3.0.9 registry+https://github.com/rust-lang/crates.io-index
   │ ╰───────────────────────────────────────────────────────────────┘ lock entries
   │  
   ├ syn v2.0.119
     └── curve25519-dalek-derive v0.1.1
         └── curve25519-dalek v5.0.0
             └── ed25519-dalek v3.0.0
                 └── cryptocheck v0.1.0
   ├ syn v3.0.9
     └── wasm-bindgen-macro-support v0.2.129
         └── wasm-bindgen-macro v0.2.129
             └── wasm-bindgen v0.2.129
                 ├── getrandom v0.4.3
                 │   └── cryptocheck v0.1.0
                 └── js-sys v0.3.106
                     └── getrandom v0.4.3 (*)

advisories ok, bans ok, licenses ok, sources ok

real	0m1.052s
user	0m0.406s
sys	0m0.311s

+ (fmtcheck) cargo deny --all-features check licenses advisories bans sources
warning[duplicate]: found 2 duplicate entries for crate 'winnow'
   ┌─ /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/crypto/fmtcheck/Cargo.lock:17:1
   │  
17 │ ╭ winnow 0.7.15 registry+https://github.com/rust-lang/crates.io-index
18 │ │ winnow 1.0.4 registry+https://github.com/rust-lang/crates.io-index
   │ ╰──────────────────────────────────────────────────────────────────┘ lock entries
   │  
   ├ winnow v0.7.15
     └── toml v0.9.12+spec-1.1.0
         └── fmtcheck v0.1.0
   ├ winnow v1.0.4
     └── toml_parser v1.1.5+spec-1.1.0
         └── toml v0.9.12+spec-1.1.0
             └── fmtcheck v0.1.0

advisories ok, bans ok, licenses ok, sources ok

real	0m1.136s
user	0m0.378s
sys	0m0.119s
```

</details>

<details><summary>Unsafe census (unsafe_census.txt)</summary>

```
crate                        files unsafe_files unsafe_tok  forbid  deny   license                                    used_by
arrayvec 0.7.8                   7            4         52  False   False  MIT OR Apache-2.0                          cryptocheck
blake3 1.8.7                    19           13        232  False   False  CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception cryptocheck
block-buffer 0.12.1              3            3         21  False   False  MIT OR Apache-2.0                          cryptocheck
bumpalo 3.20.3                  10            7        185  False   False  MIT OR Apache-2.0                          cryptocheck
cc 1.8.0                        17            5         21  False   False  MIT OR Apache-2.0                          cryptocheck
cfg-if 1.0.5                     1            0          0  False   False  MIT OR Apache-2.0                          cryptocheck
const-oid 0.10.2                10            1          1  False   True   Apache-2.0 OR MIT                          cryptocheck
constant_time_eq 0.4.2           6            5         54  False   False  CC0-1.0 OR MIT-0 OR Apache-2.0             cryptocheck
cpufeatures 0.3.1                5            3         11  False   False  MIT OR Apache-2.0                          cryptocheck
crypto-common 0.2.2              3            0          0  True    False  MIT OR Apache-2.0                          cryptocheck
curve25519-dalek 5.0.0          57            4         33  False   False  BSD-3-Clause                               cryptocheck
curve25519-dalek-derive 0.1.1     1            1          5  False   False  MIT/Apache-2.0                             cryptocheck
digest 0.11.3                   16            0          0  True    False  MIT OR Apache-2.0                          cryptocheck
ed25519 3.0.0                    3            0          0  True    False  Apache-2.0 OR MIT                          cryptocheck
ed25519-dalek 3.0.0             11            0          0  False   False  BSD-3-Clause                               cryptocheck
equivalent 1.0.3                 1            0          0  False   False  Apache-2.0 OR MIT                          fmtcheck
fiat-crypto 0.3.0               33            0          0  False   False  MIT OR Apache-2.0 OR BSD-1-Clause          cryptocheck
find-msvc-tools 0.1.14          11            6         55  False   False  MIT OR Apache-2.0                          cryptocheck
getrandom 0.4.3                 36           28        109  False   False  MIT OR Apache-2.0                          cryptocheck
hashbrown 0.17.1                28           18        454  False   False  MIT OR Apache-2.0                          fmtcheck
hybrid-array 0.4.15              7            5         37  False   False  MIT OR Apache-2.0                          cryptocheck
indexmap 2.14.2                 27            4         12  False   False  Apache-2.0 OR MIT                          fmtcheck
itoa 1.0.18                      2            1         13  False   False  MIT OR Apache-2.0                          fmtcheck
js-sys 0.3.106                  10            5         36  False   False  MIT OR Apache-2.0                          cryptocheck
libc 0.2.191                   443           68        800  False   False  MIT OR Apache-2.0                          cryptocheck
memchr 2.8.3                    37           20        333  False   False  Unlicense OR MIT                           fmtcheck
once_cell 1.21.4                 5            5         47  False   False  MIT OR Apache-2.0                          cryptocheck
proc-macro2 1.0.107             16            3          6  False   False  MIT OR Apache-2.0                          cryptocheck,fmtcheck
quote 1.0.47                     8            0          0  False   False  MIT OR Apache-2.0                          cryptocheck,fmtcheck
r-efi 6.0.0                     55           46        325  False   False  MIT OR Apache-2.0 OR LGPL-2.1-or-later     cryptocheck
rand_core 0.10.1                 6            0          0  False   False  MIT OR Apache-2.0                          cryptocheck
rustc_version 0.4.1              1            0          0  False   False  MIT OR Apache-2.0                          cryptocheck
rustversion 1.0.23              15            1          1  False   False  MIT OR Apache-2.0                          cryptocheck
semver 1.0.28                    8            2         47  False   False  MIT OR Apache-2.0                          cryptocheck
serde 1.0.229                   25            2          2  False   False  MIT OR Apache-2.0                          fmtcheck
serde_core 1.0.229              20            2          2  False   False  MIT OR Apache-2.0                          fmtcheck
serde_derive 1.0.229            28            0          0  False   False  MIT OR Apache-2.0                          fmtcheck
serde_json 1.0.154              38            4         13  False   False  MIT OR Apache-2.0                          fmtcheck
serde_spanned 1.1.2              3            0          0  True    False  MIT OR Apache-2.0                          fmtcheck
sha2 0.11.1                     25           14         39  False   False  MIT OR Apache-2.0                          cryptocheck
shlex 2.0.1                      2            1          6  False   False  MIT OR Apache-2.0                          cryptocheck
signature 3.0.0                  7            0          0  True    False  Apache-2.0 OR MIT                          cryptocheck
subtle 2.6.1                     1            1          2  False   False  BSD-3-Clause                               cryptocheck
syn 2.0.119                     55           12         71  False   False  MIT OR Apache-2.0                          cryptocheck
syn 3.0.9                       55           12         81  False   False  MIT OR Apache-2.0                          cryptocheck,fmtcheck
toml 0.9.12+spec-1.1.0          36            0          0  True    False  MIT OR Apache-2.0                          fmtcheck
toml_datetime 0.7.5+spec-1.1.0     4            0          0  True    False  MIT OR Apache-2.0                          fmtcheck
toml_parser 1.1.5+spec-1.1.0    15            6        130  False   False  MIT OR Apache-2.0                          fmtcheck
toml_writer 1.1.3+spec-1.1.0     6            0          0  True    False  MIT OR Apache-2.0                          fmtcheck
typenum 1.20.1                  14            0          0  True    False  MIT OR Apache-2.0                          cryptocheck
unicode-ident 1.0.27             2            1          2  False   False  (MIT OR Apache-2.0) AND Unicode-3.0        cryptocheck,fmtcheck
wasm-bindgen 0.2.129            19           10        112  False   False  MIT OR Apache-2.0                          cryptocheck
wasm-bindgen-macro 0.2.129       1            0          0  False   False  MIT OR Apache-2.0                          cryptocheck
wasm-bindgen-macro-support 0.2.129     8            3         54  False   False  MIT OR Apache-2.0                          cryptocheck
wasm-bindgen-shared 0.2.129      5            0          0  False   False  MIT OR Apache-2.0                          cryptocheck
winnow 0.7.15                   61            9         46  False   False  MIT                                        fmtcheck
winnow 1.0.4                    63            8         44  False   False  MIT                                        fmtcheck
zeroize 1.9.1                    5            4         17  False   False  Apache-2.0 OR MIT                          cryptocheck
zmij 1.0.23                      5            2         70  False   False  MIT                                        fmtcheck

registry crates: 59; containing the token `unsafe` in non-test .rs sources: 40; unsafe-free: 19
note: token count is a textual grep (excludes // comments, includes `unsafe fn`, `unsafe impl`, `unsafe {` blocks and the word inside doc strings); informational only.
```

</details>

<details><summary>Host-triple sanity tests (before the target matrix)</summary>

```
+ cargo test --release --locked (host x86_64-unknown-linux-gnu, cryptocheck)
    Finished `release` profile [optimized] target(s) in 6.19s
     Running unittests src/lib.rs (target/release/deps/cryptocheck-afb36dfb2754f732)

running 3 tests
test tests::blake3_empty ... ok
test tests::sha256_abc ... ok
test tests::ed25519_rfc8032_test1 ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src/main.rs (target/release/deps/hashbench-faa11868dcd3f9da)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests cryptocheck

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


real	0m6.619s
user	0m13.936s
sys	0m2.370s

+ cargo test --locked (host, fmtcheck)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 6.14s
     Running unittests src/lib.rs (target/debug/deps/fmtcheck-d245f23436f2e5fb)

running 1 test
test tests::round_trip ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

   Doc-tests fmtcheck

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


real	0m6.223s
user	0m13.719s
sys	0m2.510s
```

</details>

<details><summary>Probe sources</summary>

```
===== cryptocheck/src/lib.rs
#![forbid(unsafe_code)]
//! Build-matrix probe for the three SPEC B1.10 crypto crates.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// BLAKE3 digest of `data`.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// Leaf hash as in SPEC B1.7: SHA-256(0x00 || leaf).
pub fn leaf_hash(leaf: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(leaf);
    h.finalize().into()
}

/// Node hash as in SPEC B1.7: SHA-256(0x01 || left || right).
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Deterministic signing key from 32 raw secret bytes (no RNG involved).
pub fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey {
    SigningKey::from_bytes(seed)
}

/// Ed25519 signature over `msg` with the key derived from `seed`.
pub fn sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    signing_key_from_seed(seed).sign(msg).to_bytes()
}

/// Strict verification (rejects small-order and non-canonical points).
pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pk) else {
        return false;
    };
    let sig = Signature::from_bytes(sig);
    vk.verify_strict(msg, &sig).is_ok()
}

/// Public key bytes for a seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    signing_key_from_seed(seed).verifying_key().to_bytes()
}

/// Generate a fresh key from the OS RNG (getrandom 0.4 SysRng). Only for `sfr keygen`.
#[cfg(feature = "keygen")]
pub fn generate_key() -> Result<SigningKey, getrandom::Error> {
    use getrandom::rand_core::{TryRng, UnwrapErr};
    let mut rng = getrandom::SysRng;
    // Probe the RNG once so a missing backend surfaces as an Err instead of a panic.
    let mut probe = [0u8; 1];
    rng.try_fill_bytes(&mut probe)?;
    Ok(SigningKey::generate(&mut UnwrapErr(rng)))
}

/// Hex encoding without any extra dependency.
pub fn hex(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(T[(b >> 4) as usize] as char);
        s.push(T[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_abc() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn blake3_empty() {
        assert_eq!(
            hex(&blake3_hash(b"")),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn ed25519_rfc8032_test1() {
        // RFC 8032 section 7.1 TEST 1 (empty message).
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        assert_eq!(
            hex(&public_key(&seed)),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let sig = sign(&seed, b"");
        assert_eq!(
            hex(&sig),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
        assert!(verify(&public_key(&seed), b"", &sig));
        assert!(!verify(&public_key(&seed), b"x", &sig));
    }
}

===== cryptocheck/src/main.rs
#![forbid(unsafe_code)]
//! Hash throughput probe: 100 MB buffer through blake3 and sha2 (single thread).

use std::time::Instant;

fn main() {
    let mb: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let n = mb * 1024 * 1024;
    // Deterministic, non-trivial content (a simple LCG) so the result is checkable across targets.
    let mut buf = vec![0u8; n];
    let mut x: u32 = 0x1234_5678;
    for b in buf.iter_mut() {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }

    let reps = 3;
    let mut best_b3 = f64::MAX;
    let mut h_b3 = [0u8; 32];
    for _ in 0..reps {
        let t = Instant::now();
        h_b3 = cryptocheck::blake3_hash(&buf);
        best_b3 = best_b3.min(t.elapsed().as_secs_f64());
    }
    let mut best_sha = f64::MAX;
    let mut h_sha = [0u8; 32];
    for _ in 0..reps {
        let t = Instant::now();
        h_sha = cryptocheck::sha256(&buf);
        best_sha = best_sha.min(t.elapsed().as_secs_f64());
    }
    let mib = n as f64 / (1024.0 * 1024.0);
    println!("buffer: {} MiB, best of {} runs, single thread", mb, reps);
    println!(
        "blake3  {:>8.3} s  {:>9.1} MiB/s  {}",
        best_b3,
        mib / best_b3,
        cryptocheck::hex(&h_b3)
    );
    println!(
        "sha256  {:>8.3} s  {:>9.1} MiB/s  {}",
        best_sha,
        mib / best_sha,
        cryptocheck::hex(&h_sha)
    );

    // Deterministic Ed25519 round trip over the digest (fixed seed, no RNG).
    let seed = [0x42u8; 32];
    let t = Instant::now();
    let sig = cryptocheck::sign(&seed, &h_sha);
    let sign_us = t.elapsed().as_secs_f64() * 1e6;
    let t = Instant::now();
    let ok = cryptocheck::verify(&cryptocheck::public_key(&seed), &h_sha, &sig);
    let verify_us = t.elapsed().as_secs_f64() * 1e6;
    println!(
        "ed25519 sign {:.1} us, verify_strict {:.1} us, ok={} sig={}",
        sign_us,
        verify_us,
        ok,
        cryptocheck::hex(&sig)
    );
    #[cfg(feature = "keygen")]
    {
        match cryptocheck::generate_key() {
            Ok(k) => println!(
                "keygen via getrandom SysRng ok, pk={}",
                cryptocheck::hex(&k.verifying_key().to_bytes())
            ),
            Err(e) => println!("keygen via getrandom SysRng FAILED: {e}"),
        }
    }
}

===== fmtcheck/src/lib.rs
#![forbid(unsafe_code)]
//! Build-matrix probe for the candidate record-format dependencies.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub schema_version: u32,
    pub status: String,
    pub params: BTreeMap<String, i64>,
}

pub fn to_json(r: &Record) -> Result<String, serde_json::Error> {
    serde_json::to_string(r)
}

pub fn from_json(s: &str) -> Result<Record, serde_json::Error> {
    serde_json::from_str(s)
}

pub fn to_toml(r: &Record) -> Result<String, toml::ser::Error> {
    toml::to_string(r)
}

pub fn from_toml(s: &str) -> Result<Record, toml::de::Error> {
    toml::from_str(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let mut params = BTreeMap::new();
        params.insert("MPC_XY_P".to_string(), 1);
        let r = Record { schema_version: 1, status: "PASS".into(), params };
        assert_eq!(from_json(&to_json(&r).unwrap()).unwrap(), r);
        assert_eq!(from_toml(&to_toml(&r).unwrap()).unwrap(), r);
    }
}
```

</details>


## 8. Canonicalization

Diagnostic item 8 for the Sealed Flight Record. Evidence only: nothing under `/home/user/Sealed_Flight_Recorder-` was modified. Inputs read from the repository: `docs/SPEC.md` B1.7 (record format, `leaf hash = SHA-256(0x00 || JCS(leaf))`) and B1.10 (gates), `deny-list.txt`, `deny.toml`, `rust-toolchain.toml`, `CLAUDEME.md` section 5.

Date: 2026-10-18. Toolchain: rustc 1.97.0 (the pinned toolchain), cargo-deny 0.20.2, node 22.22.0. Host: 4 CPUs shared with PX4 SITL flights; cargo ran under `nice -n 10`, and the timing runs saw load average 4.78, so absolute times are inflated and only the ratios should be compared.

### 1. Recommendation

**Write a minimal in-house JCS serializer in `sfr-core`, limited to the record's types, and take the ES6 shortest-digit generation for floats from `ryu-js =1.0.3`. Do not use Rust's std float formatting.**

Reasons, each backed by a measurement below:

1. **Correctness is equal.** The in-house prototype (86 code lines) passes all 6 official RFC 8785 vectors byte for byte and 1,000,000 of the 1,000,000 official ES6 number vectors, the same result as the two best crates.
2. **It fails closed where the crates fail silently.**
   * The two conformant crates map distinct u64 values to identical bytes. For example, 9007199254740992 and 9007199254740993 produce the same output, and so do 18446744073709550615 and 18446744073709551615.
   * The crates also write nested NaN or infinity as `null`.
   * The in-house version returns a named error in each case (sections 3.1 and 3.4).
3. **It is 4 to 8 times faster at verify scale.** The workload was 10,000 event leaves plus a 1,200-parameter config leaf.
   * In-house: 8 to 12 ms (median).
   * serde_json_canonicalizer: 64 to 73 ms. serde_jcs: 45 to 74 ms.
   * The SPEC gate for standalone verify of 10,000 events is 10 ms in total (section 5).
4. **The canonical form becomes part of the record format, frozen with `schema_version` 1, instead of riding on a dependency.**
   * The leading crate changed behaviour in its last release: duplicate keys now raise an error.
   * Its previous version, 0.4.0, was yanked the same day it was published.
   * A canonicalizer whose output changes on a version bump would make old records fail verification.
5. **It adds one leaf crate to the graph instead of two or more.** `ryu-js` is `no_std`, has no runtime dependencies, is licensed `Apache-2.0 OR BSL-1.0` (allowed by `deny.toml`), and is maintained by the Boa JavaScript engine team. Its contract is exactly ECMAScript `Number::toString`.

Runner-up, if the team prefers not to own the code: `serde_json_canonicalizer =0.4.1`. It is fully conformant and actively maintained, and it is the right choice as a **dev-dependency differential oracle** for the in-house code. Used in production, it needs findings F1, F4 and F5 handled by types and by the verifier, and it costs roughly 50 to 60 ms per 10,000-event verify.

### 2. Findings

| # | Finding | Evidence | Consequence for the record format |
|---|---|---|---|
| F1 | **u64 values above 2^53 cannot be JSON numbers under JCS.** JCS restricts input to I-JSON (RFC 7493, cited in the reference repository README line 12), where numbers are IEEE-754 doubles. Both conformant crates round such integers to the nearest double, so distinct values collide. | Probe P1: `serde_json_canonicalizer` and `serde_jcs` give identical bytes for 9007199254740992 and 9007199254740993, and for 18446744073709550615 and 18446744073709551615 (true, true, true). | **Encode every u64-typed field as a JSON string of decimal digits** (boot-time and UTC microseconds, sequence numbers, file size). Realistic values fit below 2^53: 2^53 µs is about 285 years, and UTC µs in 2026 is about 1.76e15, below 9.007e15 until about year 2255. But the ULog types are u64, and a malformed or adversarial log can carry any value (for example an all-ones uninitialised GPS time). Rejecting such logs would conflict with "a failing flight is still sealed", so strings are better than an error. Keep i32 and u32 values as numbers. |
| F2 | **Rust std float formatting is not ES6.** `{}`, `{:?}` and `{:e}` all choose the wrong digit when two shortest round-trip candidates are equally close to the exact value; ES6 (ECMA-262 Number::toString) requires the even one. | In-house prototype with std `{:e}`: 999,747 of 1,000,000 pass, 253 mismatches, for example 1424953923781206.3 vs ES6 1424953923781206.2. Exact value 1424953923781206.25; both candidates round-trip at distance 0.05 (Python `Decimal`). `{}` gives the same digits (`stdfmt.txt`). | The brief's assumption that `{}` already provides the right digits holds except for ties, which occur about 1 in 4,000 random doubles. Use ryu-js (1,000,000 of 1,000,000) or zmij (1,000,000 of 1,000,000). |
| F3 | **serde_json's default float parser is not correctly rounded.** The verifier must enable `serde_json/float_roundtrip`. | In-house prototype on default serde_json fails `values.json`: `333333333.33333329` parses to the double printed as `333333333.33333325` instead of `333333333.3333333`. Passes with `float_roundtrip` or `arbitrary_precision`. | `sfr-core` must depend on `serde_json` with `features = ["float_roundtrip"]`; otherwise verify can re-canonicalize a sealed float into different bytes. All three serde-based crates enable it, so it unifies today, but the in-house option must set it explicitly. |
| F4 | **Nested NaN and infinity become `null` silently in every crate.** The crates' NaN check runs only for a top-level value. Nested floats go through serde_json's own `Serializer::serialize_f64`, which writes `null` (serde_json 1.0.154 `src/ser.rs` lines 169 to 174). `serde_json::Value::from(f64::NAN)` is also `null`. | Probe P2 and `probe.nan.txt`: top-level NaN gives `Err` in serde_json_canonicalizer and serde_jcs, but `[NaN]` gives `[null]`; struct field NaN gives `{"v":null}` in all three crates. | A float32 parameter that is NaN in a malformed log would be sealed as `null`. The record needs a finite-float type that refuses NaN and infinity at construction (or encodes them as strings), whichever canonicalizer is chosen. |
| F5 | **JCS normalizes one-byte edits, so the tamper gate requires a canonical-file rule.** If verify hashes `JCS(parse(file))`, edits that keep the parsed value unchanged go undetected. | Probe P4, each edit one byte: `1e+30` to `1E+30`, `1e+30` to `1e030`, `4.50` to `4.5 `, and indent space to tab all canonicalize to identical bytes. P5: duplicate keys parse last-wins (`{"status":"FAIL","status":"PASS"}` gives `{"status":"PASS"}`). | Recommend for the record-format item: write the `.sfr` as the JCS bytes of the whole record, and have `verify` reject any file whose bytes differ from `JCS(parse(file))`, naming the first differing offset. Every byte flip then either breaks parsing, changes a hashed value, or breaks canonical form. This also catches the F1 collision on the verify side and duplicate keys. Human readability comes from `.sfr.md`. |
| F6 | **The 10 ms standalone-verify gate is at risk regardless of the canonicalizer.** | Probe perf (section 5): a serde_json parse of a 1.77 MB, 10,000-event record took 15.6 to 27.4 ms on the loaded host; canonicalizing the leaves took 8 to 12 ms in-house and 32 to 74 ms with the crates. | Measure on an unloaded x86_64 host in the Chunk 3 gate. The canonicalizer choice moves the result by 35 to 60 ms. A single-pass canonical-form checker that hashes leaf byte ranges directly from the canonical file would be the fast path if needed. |
| F7 | **`canonical_json` 0.7.0 is not RFC 8785.** It implements gibson042's Canonical JSON spec (README: "This library follows gibson's Canonical JSON spec"): capital-E exponents, `\u` escapes for all non-ASCII. | 1 of 6 vectors, 4 of 20 tricky numbers, 0 of 100,000 ES6 numbers (for example `1E0` for 1.0, `5.6E1` for 56). | Reject. |
| F8 | **`json-canon` 0.1.3 is unsuitable.** It panics on `i64::MIN` in builds with overflow checks (`value.abs()` at `src/ser.rs:153`), which cargo-fuzz builds enable. In release it emits `-9223372036854775808`, contradicting its own 2^53 check. It passes number text through verbatim when `serde_json/arbitrary_precision` is enabled anywhere in the graph (Cargo feature unification). It has not been released since 2023-05-13. | Probe P3: `PANIC` in debug. AP run: 4 of 6 vectors, 989,146 of 1,000,000 numbers. Note: its strict rejection of integers at or above 2^53 is the behaviour F1 wants. | Reject. |
| F9 | **float32 parameters.** Widening f32 to f64 and printing per ES6 is exact and round-trips (0.1f32 gives `0.10000000149011612`). `json-canon` alone prints f32 with shortest-f32 digits (`0.1`), so implementations disagree for the same Rust value. | Probe P2 `f32 0.1` row; tricky case `f32 0.1 widened`. | RECORD_FORMAT must state the rule: widen f32 to f64, then ES6. The Markdown report can display shortest-f32 text. |
| F10 | Outside item 8, for the record-format item: B1.7 lists leaves (log identity, config, baseline, rules, results, events), and the signed payload covers `schema_version` and the Merkle root. **`tool` and `seal` (seal time, key label) are neither leaves nor signed**, so a value change there that keeps canonical form passes verification and would fail the 1,000-flip tamper gate. | Reading of SPEC B1.7 only; not tested. | Hand to the record-format item. |

### 3. Candidates

#### 3.1 Metadata

| | serde_json_canonicalizer 0.4.1 | serde_jcs 0.2.0 | json-canon 0.1.3 | canonical_json 0.7.0 | in-house + ryu-js 1.0.3 |
|---|---|---|---|---|---|
| Claims RFC 8785 | yes | yes | yes | **no** (gibson042 Canonical JSON) | yes (record subset) |
| License | MIT | MIT OR Apache-2.0 | Apache-2.0 | MIT | ryu-js: Apache-2.0 OR BSL-1.0 |
| Repository | github.com/evik42/serde-json-canonicalizer | github.com/l1h3r/serde_jcs | github.com/ahdinosaur/json-canon | github.com/mozilla-services/canonicaljson-rs | github.com/boa-dev/ryu-js |
| Release date (crates.io) | 2026-10-13 (0.4.0 yanked the same day, "version/code mismatch") | 2026-03-25 (previous: 0.1.0, 2020-11-13) | 2023-05-13 | 2026-04-28 | ryu-js 1.0.3: 2026-07-10 |
| Git tag for this version | v0.4.1 (2026-10-13); last commit 47e1a6b 2026-10-13 | v0.2.0 (2026-03-25); last commit 2026-03-25 | rust-json-canon-0.1.3 (2023-05-13); last commit 2023-05-23 | 0.7.0 (2026-04-28); last commit 2026-10-08 | v1.0.3 (2026-07-10) |
| Commits, contributors | 22, 4 | 21, 2 | 22, 2 | 35, 5 | 257, 12 |
| Downloads (all time) | 12.4 M | 5.3 M | 0.63 M | 0.89 M | 43.4 M |
| Direct deps | ryu-js ^1.0.1 (1.0.3), serde 1, serde_json 1 (float_roundtrip) | ryu-js ^0.2 (0.2.2, from 2021), serde 1, serde_json 1 (std, float_roundtrip) | ryu-js ^0.2.2 (0.2.2), serde, serde_json (std, float_roundtrip) | hex, regex, serde (derive), serde_json, thiserror 2 | ryu-js (no runtime deps; optional no-panic) |
| Crates added beyond serde_json's own graph | 3 (itself, ryu-js, serde) | 3 | 3 | 14 (regex stack, serde_derive, syn, thiserror and others) | 1 (ryu-js) |
| Deny-list hits (`deny-list.txt`) | 0 | 0 | 0 | 0 | 0 |
| cargo-deny licenses, bans, sources (project `deny.toml`) | ok | ok | ok | ok | ok |
| cargo-deny advisories | ok | ok | ok | ok | ok |
| `unsafe` in crate src | 1 (`String::from_utf8_unchecked` in `to_string`) | 1 (same) | 2 (`from_utf8_unchecked` twice) | 0 | 0 (`sfr-core` forbids it); ryu-js 1.0.3 has 43 occurrences |
| Panic paths in non-test code | none found | none found | `i64::abs()` overflow (F8) | `Regex::new(..).unwrap()` on a constant | none (prototype) |
| Builds for wasm32, x86_64-musl, aarch64-musl | yes, yes, yes (`cargo check`) | yes, yes, yes | not checked | not checked | yes, yes, yes |
| Upstream number testing | nightly CI generates and runs the 100 M ES6 file (`.github/workflows/nightly.yml`) | RFC test data only | fuzz and number tests | gibson042 suite | ryu-js upstream tests |

`unsafe` occurrences in transitive crates that any serde_json-based option inherits: serde_json 16, serde_core 2, itoa 13, memchr 340, zmij 70. B1.10 "No unsafe" applies to the project's own crates, so none of these blocks the gate.

#### 3.2 Test results

Expected strings are ECMAScript `Number::toString` / `JSON.stringify`. The 20 tricky cases are the brief's list (`100` tested as both f64 and u64, so 11 cases) plus 9 boundary cases. For u64 above 2^53, "expected" is what ES6 prints for the nearest double. An error there counts as not-pass, but erroring is the behaviour this report recommends (F1).

| Implementation | RFC 8785 vectors (6, byte compare) | Brief's 11 cases | All 20 tricky | ES6 number vectors | Same, with serde_json `arbitrary_precision` |
|---|---|---|---|---|---|
| serde_json_canonicalizer 0.4.1 | **6/6** | 11/11 | 20/20 | **1,000,000 / 1,000,000** | 6/6, 20/20, 1,000,000 / 1,000,000 |
| serde_jcs 0.2.0 | **6/6** | 11/11 | 20/20 | **1,000,000 / 1,000,000** | 6/6, 20/20, 1,000,000 / 1,000,000 |
| json-canon 0.1.3 | 6/6 | 9/11 (2 errors, u64 at or above 2^53) | 16/20 | 1,000,000 / 1,000,000 | **4/6, 10/20, 989,146 / 1,000,000** |
| canonical_json 0.7.0 | **1/6** | 1/11 | 4/20 | **0 / 100,000** | 1/6, 10/20, 9,871 / 10,000 |
| in-house, std `{:e}`, serde_json default | 5/6 (`values.json`, F3) | 9/11 (2 deliberate errors) | 17/20 | 999,747 / 1,000,000 (F2) | 6/6, 17/20, 999,747 |
| in-house, std `{:e}`, `float_roundtrip` | 6/6 | 9/11 | 17/20 | 999,747 / 1,000,000 (F2) | 6/6, 17/20, 999,747 |
| **in-house + ryu-js 1.0.3** | **6/6** | 9/11 (2 deliberate errors) | 17/20 | **1,000,000 / 1,000,000** | 6/6, 17/20, 1,000,000 / 1,000,000 |
| in-house + zmij 1.0.23 | 6/6 | 9/11 | 17/20 | 1,000,000 / 1,000,000 | 6/6, 17/20, 1,000,000 / 1,000,000 |

ES6 vectors: the first 1,000,000 lines of `es6testfile100m.txt` were generated locally with a port of the reference `testdata/numgen.js`. The SHA-256 of the first 1,000 / 10,000 / 100,000 / 1,000,000 lines matched the reference table (`be18b62b...`, `b9f7a8e7...`, `22776e6d...`, `49415fee...`), so the corpus is the official one. canonical_json ran on 100,000 lines (10,000 with arbitrary_precision) because its regex-per-number path takes 15 s per 100,000.

#### 3.3 Integers beyond 2^53 and `arbitrary_precision`

| Input | serde_json_canonicalizer | serde_jcs | json-canon | canonical_json | in-house |
|---|---|---|---|---|---|
| u64 9007199254740993 | `9007199254740992` (silent) | `9007199254740992` (silent) | error | `9007199254740993` (not JCS) | error |
| u64 18446744073709551615 | `18446744073709552000` (silent) | same | error | raw digits | error |
| u64 9007199254740992 (exactly 2^53) | `9007199254740992` | same | error (limit is 2^53 minus 1) | raw | `9007199254740992` |
| i64::MIN | `-9223372036854776000` | same | **panic** (debug), raw digits (release) | not tested | error |
| JSON text `123456789012345678901234567890` | `1.2345678901234568e+29` | same | same; raw text under AP | `1.2345678901234568E29` | same as first column |
| JSON text `1e400` | parse error (default); "NaN and +/-Infinity" error (AP) | parse error; "invalid float value" (AP) | parse error; `1e+400` (AP) | parse error; `1e+400` (AP) | parse error; error (AP) |
| `arbitrary_precision` on | unchanged (re-parses number text to f64) | unchanged | **breaks: emits number text verbatim** | breaks | unchanged |

### 4. The in-house option

**Scope.** null, bool, i64/u64 within 2^53 (anything larger is an error; u64 fields travel as strings per F1), finite f64 (f32 widened per F9), strings, arrays, objects with members sorted by UTF-16 code units (RFC 8785 section 3.2.3). String escaping per RFC 8785 section 3.2.2.2: `\"`, `\\`, `\b \f \n \r \t`, lowercase `\u00xx` for the other controls below U+0020, and everything else literal UTF-8 (including `/`, U+007F and non-ASCII). Floats per section 3.2.2.3 (ES6 `Number::toString`), with `-0` printed as `0`.

**Size.** The prototype `inhouse-ryujs/src/adapter.rs` covers all of the above in **86 non-blank, non-comment lines** (102 total). It passes every test in section 3.2 except the deliberate errors. A production version adds a named error enum (no string errors, per CLAUDEME section 5), a `Vec<u8>` writer, an entry point for the record's own types, a u64-as-decimal-string newtype, and the verifier's canonical-form check with first-difference offset (F5). **Estimate: 150 to 200 lines of code.**

Writing the shortest-digit algorithm itself is not in scope: Ryu and Schubfach are 2,000 to 3,000 lines with tables, so ryu-js (2,808 lines) is the right dependency. Std formatting is out (F2). zmij also passes and is already in serde_json 1.0.154's graph, but its contract is shortest round-trip, not ES6 tie-breaking. serde_json also changed float backends inside the 1.x series, so relying on zmij transitively is fragile; ryu-js states the ES6 contract.

**Test burden** (about 250 to 400 lines of tests plus about 0.4 MB of fixtures):

1. The 6 official input/output pairs (1.1 KB, Apache-2.0, WebPKI.org), with a license notice under `testdata/`.
2. The ES6 corpus: commit the first 10,000 lines (399,022 bytes) and assert their SHA-256 against the published `b9f7a8e7...`, which makes the fixture self-authenticating. A nightly job generates 1,000,000 or 100,000,000 lines with `numgen.js` or `numgen.go` (needs node or go in CI); checking 1,000,000 lines takes 0.2 to 0.5 s in release.
3. About 25 boundary numbers: plus and minus 0, 5e-324, the subnormal and normal boundary, 1e21 and 1e-6/1e-7 switch points, 2^53 plus and minus 1, f32 widening, i32 extremes.
4. Escaping: all 32 C0 controls, U+007F, `/`, U+2028 and U+2029, astral characters.
5. Key order: UTF-16 versus UTF-8 order. Covered by `weird.json`, plus an empty key and prefix keys.
6. Error cases: u64 above 2^53, NaN, infinity, each with its named error.
7. Property tests: idempotence `JCS(parse(JCS(v))) == JCS(v)`, plus a differential test against `serde_json_canonicalizer` as a dev-dependency on in-domain values (MIT, no deny-list hits).
8. A fuzz target: arbitrary bytes, then parse, then canonicalize; no panic, and idempotent.
9. Running items 1 to 3 on x86_64-musl, aarch64-musl and wasm32.

Items 1, 2, 3 and 9 are needed for the B1.10 "Deterministic" gate whichever option is chosen. The extra burden of going in-house is items 4 to 8, about 150 to 250 lines.

### 5. Performance at verify scale

Workload (probe `perf`): one config leaf with 1,200 parameters (alternating int32 and float32-widened values) plus 10,000 event leaves of about 175 bytes each (seq, kind, boot_us, utc_us, nested data with a string and a float). The record text is 1,768,773 bytes, and each leaf is canonicalized from a parsed `serde_json::Value`, as the verifier would. Release build, 7 iterations per implementation, two runs, host load average 4.78 on 4 CPUs.

| Implementation | Run 1 median / min | Run 2 median / min |
|---|---|---|
| serde_json_canonicalizer 0.4.1 | 73.27 / 48.36 ms | 64.07 / 55.66 ms |
| serde_jcs 0.2.0 | 73.78 / 59.15 ms | 44.75 / 42.50 ms |
| json-canon 0.1.3 | 44.08 / 33.95 ms | 31.54 / 30.18 ms |
| **in-house + ryu-js** | **12.33 / 8.80 ms** | **10.96 / 9.14 ms** |
| in-house + zmij | 12.06 / 9.62 ms | 8.46 / 7.89 ms |
| serde_json::to_vec (not JCS, floor) | 4.15 / 3.82 ms | 3.90 / 3.85 ms |
| serde_json parse of the whole record | 15.57 ms | 27.35 ms |

All implementations produced the same 1,753,751 canonical bytes. The crates are slow because they buffer every nested value and re-parse every object key through `serde_json::from_slice::<Value>` to build the UTF-16 sort key (`serde_json_canonicalizer` `src/jcs.rs` lines 20 to 33, and the same pattern in `serde_jcs` `Utf16Key::new`).

### 6. How to reproduce

All work is under `/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/`:

* `dl/crates/<crate>/` holds the `.crate` archives from static.crates.io and their extracted sources. `dl/repo-*` are blob-less clones of the five repositories, for tags and history. `dl/repo-json-canonicalization/testdata` is the official vectors directory (checked out from the reference repository HEAD 32a4819, 2026-10-11). `dl/api/*.json` are the crates.io API responses.
* `work/jcs/gen/numgen.js` ports the reference generator: `node numgen.js <lines>` writes to stdout.
* `work/jcs/vectors/es6-{1000,10000,100000,1000000}.txt` hold the generated corpora (hashes match the reference table).
* `work/jcs/harness/main.rs` is the shared harness (sections A to D of the raw outputs). Each `work/jcs/<impl>/` is a scratch cargo project with `src/adapter.rs`. Run it with `cargo run --release [--features ap] -- <testdata dir> <numbers file>`.
* `work/jcs/probe/` holds probes P1 to P5 (run the debug build for overflow checks), plus `perf` and `nan`.
* `work/jcs/stdfmt/fmt.rs` checks std `{}` formatting on the tie cases.
* `work/jcs/results/` holds every raw output quoted below.

Not done: the RFC 8785 text itself could not be fetched (rfc-editor.org, ietf.org and datatracker.ietf.org are refused by the session proxy). Section numbers 3.2.2.2, 3.2.2.3 and 3.2.3 are cited from the RFC's structure. The I-JSON constraint is confirmed by the reference repository README. The full 100,000,000-line corpus (4.04 GB) was not run; serde_json_canonicalizer's own nightly CI runs it.

### 7. Raw outputs

<details>
<summary>Corpus checksums (match the reference testdata/README.md table)</summary>

`results/vectors.checksums.txt`

```text
es6-1000.txt lines=1000 bytes=37967 sha256=be18b62b6f69cdab33a7e0dae0d9cfa869fda80ddc712221570f9f40a5878687
es6-10000.txt lines=10000 bytes=399022 sha256=b9f7a8e75ef22a835685a52ccba7f7d6bdc99e34b010992cbc5864cd12be6892
es6-100000.txt lines=100000 bytes=4031728 sha256=22776e6d4b49fa294a0d0f349268e5c28808fe7e0cb2bcbe28f63894e494d4c7
es6-1000000.txt lines=1000000 bytes=40357417 sha256=49415fee2c56c77864931bd3624faad425c3c577d6d74e89a83bc725506dad16
```

</details>

<details>
<summary>crates.io metadata and git tags</summary>

`results/metadata.txt`

```text
== serde_json_canonicalizer (crates.io API)
max=0.4.1 created=2023-05-22T16:45:37.254535Z updated=2026-10-13T13:21:54.286318Z downloads=12407281 repo=https://github.com/evik42/serde-json-canonicalizer
  0.4.1  2026-10-13T13:21:54.286318Z  yanked=false license=MIT rust_version=null
  0.4.0  2026-10-13T13:12:41.425422Z  yanked=true license=MIT rust_version=null
  0.3.2  2026-02-03T08:38:15.415263Z  yanked=false license=MIT rust_version=null
  0.3.1  2025-08-10T21:06:56.602523Z  yanked=false license=MIT rust_version=null
  0.3.0  2024-09-17T18:10:32.886769Z  yanked=false license=MIT rust_version=null
  0.2.0  2023-06-29T14:51:48.147458Z  yanked=false license=MIT rust_version=null
  0.1.0  2023-05-22T16:45:37.254535Z  yanked=true license=non-standard rust_version=null
== serde_jcs (crates.io API)
max=0.2.0 created=2020-11-13T07:12:47.840914Z updated=2026-03-25T20:27:37.338647Z downloads=5302847 repo=https://github.com/l1h3r/serde_jcs
  0.2.0  2026-03-25T20:27:37.338647Z  yanked=false license=MIT OR Apache-2.0 rust_version=1.85
  0.1.0  2020-11-13T07:12:47.840914Z  yanked=false license=MIT OR Apache-2.0 rust_version=null
== json-canon (crates.io API)
max=0.1.3 created=2023-05-11T03:21:34.219897Z updated=2023-05-13T09:42:13.014727Z downloads=629968 repo=https://github.com/ahdinosaur/json-canon
  0.1.3  2023-05-13T09:42:13.014727Z  yanked=false license=Apache-2.0 rust_version=null
  0.1.2  2023-05-12T10:05:24.054687Z  yanked=false license=Apache-2.0 rust_version=null
  0.1.1  2023-05-11T05:05:29.170527Z  yanked=false license=Apache-2.0 rust_version=null
  0.1.0  2023-05-11T03:21:34.219897Z  yanked=false license=Apache-2.0 rust_version=null
== canonical_json (crates.io API)
max=0.7.0 created=2020-08-17T14:17:18.670664Z updated=2026-04-28T14:28:48.941428Z downloads=891232 repo=https://github.com/mozilla-services/canonicaljson-rs
  0.7.0  2026-04-28T14:28:48.941428Z  yanked=false license=MIT rust_version=null
  0.6.0  2026-04-17T16:18:22.829043Z  yanked=false license=MIT rust_version=null
  0.5.0  2022-12-27T11:56:40.211468Z  yanked=false license=MIT rust_version=null
  0.4.0  2021-03-22T09:46:58.901399Z  yanked=false license=MIT rust_version=null
  0.3.0  2020-11-03T09:19:08.120789Z  yanked=false license=MIT rust_version=null
  0.2.0  2020-08-31T12:59:53.732439Z  yanked=false license=MIT rust_version=null
  0.1.0  2020-08-17T14:17:18.670664Z  yanked=false license=MPL-2.0 rust_version=null
== ryu-js (crates.io API)
max=1.0.3 created=2020-07-13T18:25:02.184333Z updated=2026-07-10T21:05:46.645363Z downloads=43446369 repo=https://github.com/boa-dev/ryu-js
  1.0.3  2026-07-10T21:05:46.645363Z  yanked=false license=Apache-2.0 OR BSL-1.0 rust_version=1.71
  1.0.2  2025-02-16T15:30:32.901280Z  yanked=false license=Apache-2.0 OR BSL-1.0 rust_version=1.64
  1.0.1  2024-03-03T18:41:39.100107Z  yanked=false license=Apache-2.0 OR BSL-1.0 rust_version=1.64
  1.0.0  2023-10-05T18:05:37.096612Z  yanked=false license=Apache-2.0 OR BSL-1.0 rust_version=1.64
  0.2.2  2021-12-16T09:22:08.743925Z  yanked=false license=Apache-2.0 OR BSL-1.0 rust_version=1.36
  0.2.1  2020-09-11T14:09:25.038042Z  yanked=false license=Apache-2.0 OR BSL-1.0 rust_version=null
  0.2.0  2020-07-14T21:53:34.501853Z  yanked=false license=Apache-2.0 OR BSL-1.0 rust_version=null
  0.1.0  2020-07-13T18:25:02.184333Z  yanked=false license=Apache-2.0 OR BSL-1.0 rust_version=null
== git serde-json-canonicalizer: 2026-10-13 15:21:08 +0200 47e1a6b Fix version/code mismatch; commits=22 contributors=4
  2026-10-13 v0.3.2
  2026-10-13 v0.3.1
  2026-10-13 v0.3.0
  2026-10-13 v0.4.1
  2023-06-29 v0.2.0
  2023-06-29 v0.1.0
== git serde_jcs: 2026-03-25 13:32:44 -0700 4695b4d Update README.md; commits=21 contributors=2
  2026-03-25 v0.2.0
  2020-11-12 v0.1.0
== git json-canon: 2023-05-23 19:54:01 +1200 05458a5 use mutable reference to entries before sort (#9); commits=22 contributors=2
  2023-05-13 rust-json-canon-0.1.3
  2023-05-12 js-json-canon-1.0.1
  2023-05-12 rust-json-canon-0.1.2
  2023-05-12 js-json-canon-fuzz-0.1.0
  2023-05-11 rust-json-canon-0.1.1
  2023-05-11 rust-json-canon-0.1.0
== git canonicaljson-rs: 2026-10-08 10:17:24 +0200 8b4a655 Set code owners to @mozilla-services/remote-settings-dev; commits=35 contributors=5
  2026-04-28 0.7.0
  2026-04-17 0.5.0
  2026-04-17 0.6.0
  2021-03-22 0.4.0
  2020-11-03 v0.3.0
  2020-08-31 v0.2.0
== git ryu-js: 2026-07-10 06:46:36 +0000 f8d6626 Release `v1.0.3` (#64); commits=257 contributors=12
  2026-07-10 v1.0.3
  2025-02-16 v1.0.2
  2024-03-03 v1.0.1
  2023-10-05 v1.0.0
  2021-12-16 v0.2.2
  2020-09-11 v0.2.1
```

</details>

<details>
<summary>Dependency trees, deny-list and cargo-deny results</summary>

`results/deps.trees.txt`

```text
===== serde_json_canonicalizer: cargo tree -e normal
jcs-serde_json_canonicalizer v0.0.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/serde_json_canonicalizer)
├── serde_json v1.0.154
│   ├── itoa v1.0.18
│   ├── memchr v2.8.3
│   ├── serde_core v1.0.229
│   └── zmij v1.0.23
└── serde_json_canonicalizer v0.4.1
    ├── ryu-js v1.0.3
    ├── serde v1.0.229
    │   └── serde_core v1.0.229
    └── serde_json v1.0.154 (*)
deny-list hits: 0
cargo deny check licenses bans sources: bans ok, licenses ok, sources ok

===== serde_jcs: cargo tree -e normal
jcs-serde_jcs v0.0.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/serde_jcs)
├── serde_jcs v0.2.0
│   ├── ryu-js v0.2.2
│   ├── serde v1.0.229
│   │   └── serde_core v1.0.229
│   └── serde_json v1.0.154
│       ├── itoa v1.0.18
│       ├── memchr v2.8.3
│       ├── serde_core v1.0.229
│       └── zmij v1.0.23
└── serde_json v1.0.154 (*)
deny-list hits: 0
cargo deny check licenses bans sources: bans ok, licenses ok, sources ok

===== json-canon: cargo tree -e normal
jcs-json-canon v0.0.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/json-canon)
├── json-canon v0.1.3
│   ├── ryu-js v0.2.2
│   ├── serde v1.0.229
│   │   └── serde_core v1.0.229
│   └── serde_json v1.0.154
│       ├── itoa v1.0.18
│       ├── memchr v2.8.3
│       ├── serde_core v1.0.229
│       └── zmij v1.0.23
└── serde_json v1.0.154 (*)
deny-list hits: 0
cargo deny check licenses bans sources: bans ok, licenses ok, sources ok

===== canonical_json: cargo tree -e normal
jcs-canonical_json v0.0.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/canonical_json)
├── canonical_json v0.7.0
│   ├── hex v0.4.3
│   ├── regex v1.13.1
│   │   ├── aho-corasick v1.1.5
│   │   │   └── memchr v2.8.3
│   │   ├── memchr v2.8.3
│   │   ├── regex-automata v0.4.18
│   │   │   ├── aho-corasick v1.1.5 (*)
│   │   │   ├── memchr v2.8.3
│   │   │   └── regex-syntax v0.8.11
│   │   └── regex-syntax v0.8.11
│   ├── serde v1.0.229
│   │   ├── serde_core v1.0.229
│   │   └── serde_derive v1.0.229 (proc-macro)
│   │       ├── proc-macro2 v1.0.107
│   │       │   └── unicode-ident v1.0.27
│   │       ├── quote v1.0.47
│   │       │   └── proc-macro2 v1.0.107 (*)
│   │       └── syn v3.0.9
│   │           ├── proc-macro2 v1.0.107 (*)
│   │           ├── quote v1.0.47 (*)
│   │           └── unicode-ident v1.0.27
│   ├── serde_json v1.0.154
│   │   ├── itoa v1.0.18
│   │   ├── memchr v2.8.3
│   │   ├── serde_core v1.0.229
│   │   └── zmij v1.0.23
│   └── thiserror v2.0.21
│       └── thiserror-impl v2.0.21 (proc-macro)
│           ├── proc-macro2 v1.0.107 (*)
│           ├── quote v1.0.47 (*)
│           └── syn v3.0.9 (*)
└── serde_json v1.0.154 (*)
deny-list hits: 0
cargo deny check licenses bans sources: bans ok, licenses ok, sources ok

===== inhouse-ryujs: cargo tree -e normal
jcs-inhouse-ryujs v0.0.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/inhouse-ryujs)
├── ryu-js v1.0.3
└── serde_json v1.0.154
    ├── itoa v1.0.18
    ├── memchr v2.8.3
    ├── serde_core v1.0.229
    └── zmij v1.0.23
deny-list hits: 0
cargo deny check licenses bans sources: bans ok, licenses ok, sources ok

===== inhouse-zmij: cargo tree -e normal
jcs-inhouse-zmij v0.0.0 (/tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/inhouse-zmij)
├── serde_json v1.0.154
│   ├── itoa v1.0.18
│   ├── memchr v2.8.3
│   ├── serde_core v1.0.229
│   └── zmij v1.0.23
└── zmij v1.0.23
deny-list hits: 0
cargo deny check licenses bans sources: bans ok, licenses ok, sources ok
```

`results/advisories.txt`

```text
===== probe: cargo deny check advisories
advisories ok
===== canonical_json: cargo deny check advisories
advisories ok
```

</details>

<details>
<summary>serde_json_canonicalizer 0.4.1: harness output (default, then arbitrary_precision)</summary>

`results/serde_json_canonicalizer.default.txt`

```text
# implementation: serde_json_canonicalizer 0.4.1
# serde_json arbitrary_precision feature: false

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  PASS  9007199254740993 (u64)             -> 9007199254740992
  PASS  18446744073709551615 (u64)         -> 18446744073709552000
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  PASS  -9007199254740993 (i64)            -> -9007199254740992
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 20 pass, 0 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> 18446744073709552000
                  9007199254740993 -> 9007199254740992
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> PARSE ERROR number out of range at line 1 column 5

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
numbers: 1000000 pass, 0 mismatch, 0 error, 1000000 lines, 135.52ms
```

`results/serde_json_canonicalizer.ap.txt`

```text
# implementation: serde_json_canonicalizer 0.4.1
# serde_json arbitrary_precision feature: true

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  PASS  9007199254740993 (u64)             -> 9007199254740992
  PASS  18446744073709551615 (u64)         -> 18446744073709552000
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  PASS  -9007199254740993 (i64)            -> -9007199254740992
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 20 pass, 0 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> 18446744073709552000
                  9007199254740993 -> 9007199254740992
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> ERROR NaN and +/-Infinity are not permitted in JSON

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
numbers: 1000000 pass, 0 mismatch, 0 error, 1000000 lines, 211.91ms
```

</details>

<details>
<summary>serde_jcs 0.2.0: harness output</summary>

`results/serde_jcs.default.txt`

```text
# implementation: serde_jcs 0.2.0
# serde_json arbitrary_precision feature: false

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  PASS  9007199254740993 (u64)             -> 9007199254740992
  PASS  18446744073709551615 (u64)         -> 18446744073709552000
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  PASS  -9007199254740993 (i64)            -> -9007199254740992
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 20 pass, 0 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> 18446744073709552000
                  9007199254740993 -> 9007199254740992
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> PARSE ERROR number out of range at line 1 column 5

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
numbers: 1000000 pass, 0 mismatch, 0 error, 1000000 lines, 143.32ms
```

`results/serde_jcs.ap.txt`

```text
# implementation: serde_jcs 0.2.0
# serde_json arbitrary_precision feature: true

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  PASS  9007199254740993 (u64)             -> 9007199254740992
  PASS  18446744073709551615 (u64)         -> 18446744073709552000
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  PASS  -9007199254740993 (i64)            -> -9007199254740992
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 20 pass, 0 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> 18446744073709552000
                  9007199254740993 -> 9007199254740992
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> ERROR invalid float value

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
numbers: 1000000 pass, 0 mismatch, 0 error, 1000000 lines, 203.95ms
```

</details>

<details>
<summary>json-canon 0.1.3: harness output</summary>

`results/json-canon.default.txt`

```text
# implementation: json-canon 0.1.3
# serde_json arbitrary_precision feature: false

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  ERROR 9007199254740993 (u64)             -> u64 must be less than JSON max safe integer (expected 9007199254740992)
  ERROR 18446744073709551615 (u64)         -> u64 must be less than JSON max safe integer (expected 18446744073709552000)
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  ERROR -9007199254740993 (i64)            -> i64.abs() must be less than JSON max safe integer (expected -9007199254740992)
  ERROR 9007199254740992 (u64, 2^53)       -> u64 must be less than JSON max safe integer (expected 9007199254740992)
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 16 pass, 4 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> ERROR u64 must be less than JSON max safe integer
                  9007199254740993 -> ERROR u64 must be less than JSON max safe integer
                  9007199254740992 -> ERROR u64 must be less than JSON max safe integer
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> PARSE ERROR number out of range at line 1 column 5

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
numbers: 1000000 pass, 0 mismatch, 0 error, 1000000 lines, 129.27ms
```

`results/json-canon.ap.txt`

```text
# implementation: json-canon 0.1.3
# serde_json arbitrary_precision feature: true

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: FAIL
  got:      {"":"empty","1":{"\n":56.0,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}
  expected: {"":"empty","1":{"\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}
unicode: PASS (30 bytes)
values: FAIL
  got:      {"literals":[null,true,false],"numbers":[333333333.33333329,1e+30,4.50,2e-3,0.000000000000000000000000001],"string":"€$\u000f\nA'B\"\\\\\"/"}
  expected: {"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}
weird: PASS (214 bytes)
vectors: 4 pass, 2 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  FAIL  100 (f64)                          -> got 100.0 expected 100
  PASS  100 (u64)                          -> 100
  FAIL  1.0 (f64)                          -> got 1.0 expected 1
  FAIL  -0.0 (f64)                         -> got -0.0 expected 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  FAIL  9007199254740993 (u64)             -> got 9007199254740993 expected 9007199254740992
  FAIL  18446744073709551615 (u64)         -> got 18446744073709551615 expected 18446744073709552000
  FAIL  18446744073709551615 (f64)         -> got 1.8446744073709552e+19 expected 18446744073709552000
  FAIL  -9007199254740993 (i64)            -> got -9007199254740993 expected -9007199254740992
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  FAIL  1e-6 (f64)                         -> got 1e-6 expected 0.000001
  FAIL  1.2345678901234568e20 (f64)        -> got 1.2345678901234568e+20 expected 123456789012345680000
  FAIL  0.000001234 (f64)                  -> got 1.234e-6 expected 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 10 pass, 10 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> 18446744073709551615
                  9007199254740993 -> 9007199254740993
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1.0
                               100 -> 100
                            0.1000 -> 0.1000
                333333333.33333329 -> 333333333.33333329
                              1e21 -> 1e+21
                                -0 -> -0
                              -0.0 -> -0.0
                               0.0 -> 0.0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 123456789012345678901234567890
                             1e400 -> 1e+400

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
  MISMATCH 0: got 0.0 expected 0
  MISMATCH 8000000000000000: got -0.0 expected 0
  MISMATCH c43211ede4974a35: got -3.333333333333333e+20 expected -333333333333333300000
  MISMATCH c3fce97ca0f21056: got -3.3333333333333336e+19 expected -33333333333333336000
  MISMATCH c3c7213080c1a6ac: got -3.333333333333334e+18 expected -3333333333333334000
  MISMATCH c39280f39a348556: got -3.333333333333334e+17 expected -333333333333333400
  MISMATCH c35d9b1f5d20d557: got -3.333333333333334e+16 expected -33333333333333340
  MISMATCH c327af4c4a80aaac: got -3333333333333334.0 expected -3333333333333334
  MISMATCH becbf647612f3696: got -3.3333333333333333e-6 expected -0.0000033333333333333333
  MISMATCH 443211ede4974a35: got 3.333333333333333e+20 expected 333333333333333300000
numbers: 989146 pass, 10854 mismatch, 0 error, 1000000 lines, 106.41ms
```

</details>

<details>
<summary>canonical_json 0.7.0: harness output (100,000 numbers default, 10,000 with AP)</summary>

`results/canonical_json.default.txt`

```text
# implementation: canonical_json 0.7.0 (gibson042 Canonical JSON, not RFC 8785)
# serde_json arbitrary_precision feature: false

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: FAIL
  got:      {"peach":"This sorting order","p\u00e9ch\u00e9":"is wrong according to French","p\u00eache":"but canonicalization MUST","sin":"ignore locale"}
  expected: {"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"ignore locale"}
structures: FAIL
  got:      {"":"empty","1":{"\n":5.6E1,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}
  expected: {"":"empty","1":{"\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}
unicode: FAIL
  got:      {"Unnormalized Unicode":"A\u030a"}
  expected: {"Unnormalized Unicode":"Å"}
values: FAIL
  got:      {"literals":[null,true,false],"numbers":[3.3333333333333325E8,1E30,4.5E0,2E-3,1E-27],"string":"\u20ac$\u000f\nA'B\"\\\\\"/"}
  expected: {"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}
weird: FAIL
  got:      {"\n":"Newline","\r":"Carriage Return","1":"One","</script>":"Browser Challenge","\u0080":"Control\u007f","\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign","\ufb33":"Hebrew Letter Dalet With Dagesh","\ud83d\ude02":"Smiley"}
  expected: {"\n":"Newline","\r":"Carriage Return","1":"One","</script>":"Browser Challenge","":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😂":"Smiley","דּ":"Hebrew Letter Dalet With Dagesh"}
vectors: 1 pass, 5 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  FAIL  1e21 (f64)                         -> got 1E21 expected 1e+21
  FAIL  1e-7 (f64)                         -> got 1E-7 expected 1e-7
  FAIL  0.1 (f64)                          -> got 1E-1 expected 0.1
  FAIL  100 (f64)                          -> got 1E2 expected 100
  PASS  100 (u64)                          -> 100
  FAIL  1.0 (f64)                          -> got 1E0 expected 1
  FAIL  -0.0 (f64)                         -> got -0E0 expected 0
  FAIL  5e-324 (f64)                       -> got 5E-324 expected 5e-324
  FAIL  1.7976931348623157e308 (f64)       -> got 1.7976931348623157E308 expected 1.7976931348623157e+308
  FAIL  9007199254740993 (u64)             -> got 9007199254740993 expected 9007199254740992
  FAIL  18446744073709551615 (u64)         -> got 18446744073709551615 expected 18446744073709552000
  FAIL  18446744073709551615 (f64)         -> got 1.8446744073709552E19 expected 18446744073709552000
  FAIL  -9007199254740993 (i64)            -> got -9007199254740993 expected -9007199254740992
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  FAIL  1e-6 (f64)                         -> got 1E-6 expected 0.000001
  FAIL  1.2345678901234568e20 (f64)        -> got 1.2345678901234568E20 expected 123456789012345680000
  FAIL  0.000001234 (f64)                  -> got 1.234E-6 expected 0.000001234
  FAIL  f32 0.1 widened (f64)              -> got 1.0000000149011612E-1 expected 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 4 pass, 16 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> 18446744073709551615
                  9007199254740993 -> 9007199254740993
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1E30
                               1.0 -> 1E0
                               100 -> 100
                            0.1000 -> 1E-1
                333333333.33333329 -> 3.3333333333333325E8
                              1e21 -> 1E21
                                -0 -> -0E0
                              -0.0 -> -0E0
                               0.0 -> 0E0
                            1.5e-7 -> 1.5E-7
    123456789012345678901234567890 -> 1.2345678901234568E29
                             1e400 -> PARSE ERROR number out of range at line 1 column 5

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-100000.txt
  MISMATCH 0: got 0E0 expected 0
  MISMATCH 8000000000000000: got -0E0 expected 0
  MISMATCH 1: got 5E-324 expected 5e-324
  MISMATCH 8000000000000001: got -5E-324 expected -5e-324
  MISMATCH c46696695dbd1cc3: got -3.3333333333333335E21 expected -3.3333333333333335e+21
  MISMATCH c43211ede4974a35: got -3.333333333333333E20 expected -333333333333333300000
  MISMATCH c3fce97ca0f21056: got -3.3333333333333336E19 expected -33333333333333336000
  MISMATCH c3c7213080c1a6ac: got -3.333333333333334E18 expected -3333333333333334000
  MISMATCH c39280f39a348556: got -3.333333333333334E17 expected -333333333333333400
  MISMATCH c35d9b1f5d20d557: got -3.333333333333334E16 expected -33333333333333340
numbers: 0 pass, 100000 mismatch, 0 error, 100000 lines, 15.37s
```

`results/canonical_json.ap.txt`

```text
# implementation: canonical_json 0.7.0 (gibson042 Canonical JSON, not RFC 8785)
# serde_json arbitrary_precision feature: true

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: FAIL
  got:      {"peach":"This sorting order","p\u00e9ch\u00e9":"is wrong according to French","p\u00eache":"but canonicalization MUST","sin":"ignore locale"}
  expected: {"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST","sin":"ignore locale"}
structures: FAIL
  got:      {"":"empty","1":{"\n":56.0,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}
  expected: {"":"empty","1":{"\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}
unicode: FAIL
  got:      {"Unnormalized Unicode":"A\u030a"}
  expected: {"Unnormalized Unicode":"Å"}
values: FAIL
  got:      {"literals":[null,true,false],"numbers":[333333333.33333329,1e+30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000f\nA'B\"\\\\\"/"}
  expected: {"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}
weird: FAIL
  got:      {"\n":"Newline","\r":"Carriage Return","1":"One","</script>":"Browser Challenge","\u0080":"Control\u007f","\u00f6":"Latin Small Letter O With Diaeresis","\u20ac":"Euro Sign","\ufb33":"Hebrew Letter Dalet With Dagesh","\ud83d\ude02":"Smiley"}
  expected: {"\n":"Newline","\r":"Carriage Return","1":"One","</script>":"Browser Challenge","":"Control","ö":"Latin Small Letter O With Diaeresis","€":"Euro Sign","😂":"Smiley","דּ":"Hebrew Letter Dalet With Dagesh"}
vectors: 1 pass, 5 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  FAIL  100 (f64)                          -> got 100.0 expected 100
  PASS  100 (u64)                          -> 100
  FAIL  1.0 (f64)                          -> got 1.0 expected 1
  FAIL  -0.0 (f64)                         -> got -0.0 expected 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  FAIL  9007199254740993 (u64)             -> got 9007199254740993 expected 9007199254740992
  FAIL  18446744073709551615 (u64)         -> got 18446744073709551615 expected 18446744073709552000
  FAIL  18446744073709551615 (f64)         -> got 1.8446744073709552e+19 expected 18446744073709552000
  FAIL  -9007199254740993 (i64)            -> got -9007199254740993 expected -9007199254740992
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  FAIL  1e-6 (f64)                         -> got 1e-6 expected 0.000001
  FAIL  1.2345678901234568e20 (f64)        -> got 1.2345678901234568e+20 expected 123456789012345680000
  FAIL  0.000001234 (f64)                  -> got 1.234e-6 expected 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 10 pass, 10 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> 18446744073709551615
                  9007199254740993 -> 9007199254740993
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1.0
                               100 -> 100
                            0.1000 -> 0.1000
                333333333.33333329 -> 333333333.33333329
                              1e21 -> 1e+21
                                -0 -> -0
                              -0.0 -> -0.0
                               0.0 -> 0.0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 123456789012345678901234567890
                             1e400 -> 1e+400

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-10000.txt
  MISMATCH 0: got 0.0 expected 0
  MISMATCH 8000000000000000: got -0.0 expected 0
  MISMATCH c43211ede4974a35: got -3.333333333333333e+20 expected -333333333333333300000
  MISMATCH c3fce97ca0f21056: got -3.3333333333333336e+19 expected -33333333333333336000
  MISMATCH c3c7213080c1a6ac: got -3.333333333333334e+18 expected -3333333333333334000
  MISMATCH c39280f39a348556: got -3.333333333333334e+17 expected -333333333333333400
  MISMATCH c35d9b1f5d20d557: got -3.333333333333334e+16 expected -33333333333333340
  MISMATCH c327af4c4a80aaac: got -3333333333333334.0 expected -3333333333333334
  MISMATCH becbf647612f3696: got -3.3333333333333333e-6 expected -0.0000033333333333333333
  MISMATCH 443211ede4974a35: got 3.333333333333333e+20 expected 333333333333333300000
numbers: 9871 pass, 129 mismatch, 0 error, 10000 lines, 1.22ms
```

</details>

<details>
<summary>In-house, std {:e}, serde_json default features</summary>

`results/inhouse.default.txt`

```text
# implementation: inhouse prototype (std only, no dependencies beyond serde_json::Value as input)
# serde_json arbitrary_precision feature: false

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: FAIL
  got:      {"literals":[null,true,false],"numbers":[333333333.33333325,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}
  expected: {"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}
weird: PASS (214 bytes)
vectors: 5 pass, 1 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  ERROR 9007199254740993 (u64)             -> integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 9007199254740992)
  ERROR 18446744073709551615 (u64)         -> integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 18446744073709552000)
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  ERROR -9007199254740993 (i64)            -> integer -9007199254740993 exceeds 2^53 in magnitude; encode it as a string (expected -9007199254740992)
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 17 pass, 3 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> ERROR integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740993 -> ERROR integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.33333325
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> PARSE ERROR number out of range at line 1 column 5

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
  MISMATCH 43143ff3c1cb0959: got 1424953923781206.3 expected 1424953923781206.2
  MISMATCH c300ce90f2d10fca: got -591340196471289.3 expected -591340196471289.2
  MISMATCH 431b9180a34a8f19: got 1939951513150406.3 expected 1939951513150406.2
  MISMATCH c2dbfec8a2081be8: got -123124406820975.63 expected -123124406820975.62
  MISMATCH c2e88b4b042ad344: got -215892304680602.13 expected -215892304680602.12
  MISMATCH 427fb72bdcfed480: got 2179473461229.2813 expected 2179473461229.2812
  MISMATCH 431590d36426317d: got 1517553025911903.3 expected 1517553025911903.2
  MISMATCH 42e1b79eb95e91a4: got 155842717086861.13 expected 155842717086861.12
  MISMATCH 430e55ee35352f32: got 1067341360571878.3 expected 1067341360571878.2
  MISMATCH c2e7610c89197994: got -205644716624844.63 expected -205644716624844.62
numbers: 999747 pass, 253 mismatch, 0 error, 1000000 lines, 389.33ms
```

`results/inhouse.ap.txt`

```text
# implementation: inhouse prototype (std only, no dependencies beyond serde_json::Value as input)
# serde_json arbitrary_precision feature: true

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  ERROR 9007199254740993 (u64)             -> integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 9007199254740992)
  ERROR 18446744073709551615 (u64)         -> integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 18446744073709552000)
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  ERROR -9007199254740993 (i64)            -> integer -9007199254740993 exceeds 2^53 in magnitude; encode it as a string (expected -9007199254740992)
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 17 pass, 3 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> ERROR integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740993 -> ERROR integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> ERROR number 1e+400 is not representable as u64, i64 or f64

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
  MISMATCH 43143ff3c1cb0959: got 1424953923781206.3 expected 1424953923781206.2
  MISMATCH c300ce90f2d10fca: got -591340196471289.3 expected -591340196471289.2
  MISMATCH 431b9180a34a8f19: got 1939951513150406.3 expected 1939951513150406.2
  MISMATCH c2dbfec8a2081be8: got -123124406820975.63 expected -123124406820975.62
  MISMATCH c2e88b4b042ad344: got -215892304680602.13 expected -215892304680602.12
  MISMATCH 427fb72bdcfed480: got 2179473461229.2813 expected 2179473461229.2812
  MISMATCH 431590d36426317d: got 1517553025911903.3 expected 1517553025911903.2
  MISMATCH 42e1b79eb95e91a4: got 155842717086861.13 expected 155842717086861.12
  MISMATCH 430e55ee35352f32: got 1067341360571878.3 expected 1067341360571878.2
  MISMATCH c2e7610c89197994: got -205644716624844.63 expected -205644716624844.62
numbers: 999747 pass, 253 mismatch, 0 error, 1000000 lines, 497.61ms
```

</details>

<details>
<summary>In-house, std {:e}, serde_json float_roundtrip</summary>

`results/inhouse-std-rt.default.txt`

```text
# implementation: inhouse prototype, std {:e} formatting, serde_json float_roundtrip on
# serde_json arbitrary_precision feature: false

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  ERROR 9007199254740993 (u64)             -> integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 9007199254740992)
  ERROR 18446744073709551615 (u64)         -> integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 18446744073709552000)
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  ERROR -9007199254740993 (i64)            -> integer -9007199254740993 exceeds 2^53 in magnitude; encode it as a string (expected -9007199254740992)
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 17 pass, 3 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> ERROR integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740993 -> ERROR integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> PARSE ERROR number out of range at line 1 column 5

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
  MISMATCH 43143ff3c1cb0959: got 1424953923781206.3 expected 1424953923781206.2
  MISMATCH c300ce90f2d10fca: got -591340196471289.3 expected -591340196471289.2
  MISMATCH 431b9180a34a8f19: got 1939951513150406.3 expected 1939951513150406.2
  MISMATCH c2dbfec8a2081be8: got -123124406820975.63 expected -123124406820975.62
  MISMATCH c2e88b4b042ad344: got -215892304680602.13 expected -215892304680602.12
  MISMATCH 427fb72bdcfed480: got 2179473461229.2813 expected 2179473461229.2812
  MISMATCH 431590d36426317d: got 1517553025911903.3 expected 1517553025911903.2
  MISMATCH 42e1b79eb95e91a4: got 155842717086861.13 expected 155842717086861.12
  MISMATCH 430e55ee35352f32: got 1067341360571878.3 expected 1067341360571878.2
  MISMATCH c2e7610c89197994: got -205644716624844.63 expected -205644716624844.62
numbers: 999747 pass, 253 mismatch, 0 error, 1000000 lines, 415.11ms
```

`results/inhouse-std-rt.ap.txt`

```text
# implementation: inhouse prototype, std {:e} formatting, serde_json float_roundtrip on
# serde_json arbitrary_precision feature: true

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  ERROR 9007199254740993 (u64)             -> integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 9007199254740992)
  ERROR 18446744073709551615 (u64)         -> integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 18446744073709552000)
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  ERROR -9007199254740993 (i64)            -> integer -9007199254740993 exceeds 2^53 in magnitude; encode it as a string (expected -9007199254740992)
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 17 pass, 3 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> ERROR integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740993 -> ERROR integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> ERROR number 1e+400 is not representable as u64, i64 or f64

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
  MISMATCH 43143ff3c1cb0959: got 1424953923781206.3 expected 1424953923781206.2
  MISMATCH c300ce90f2d10fca: got -591340196471289.3 expected -591340196471289.2
  MISMATCH 431b9180a34a8f19: got 1939951513150406.3 expected 1939951513150406.2
  MISMATCH c2dbfec8a2081be8: got -123124406820975.63 expected -123124406820975.62
  MISMATCH c2e88b4b042ad344: got -215892304680602.13 expected -215892304680602.12
  MISMATCH 427fb72bdcfed480: got 2179473461229.2813 expected 2179473461229.2812
  MISMATCH 431590d36426317d: got 1517553025911903.3 expected 1517553025911903.2
  MISMATCH 42e1b79eb95e91a4: got 155842717086861.13 expected 155842717086861.12
  MISMATCH 430e55ee35352f32: got 1067341360571878.3 expected 1067341360571878.2
  MISMATCH c2e7610c89197994: got -205644716624844.63 expected -205644716624844.62
numbers: 999747 pass, 253 mismatch, 0 error, 1000000 lines, 505.06ms
```

</details>

<details>
<summary>In-house + ryu-js 1.0.3 (recommended shape)</summary>

`results/inhouse-ryujs.default.txt`

```text
# implementation: inhouse prototype + ryu-js 1.0.3 for f64 (serde_json float_roundtrip on)
# serde_json arbitrary_precision feature: false

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  ERROR 9007199254740993 (u64)             -> integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 9007199254740992)
  ERROR 18446744073709551615 (u64)         -> integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 18446744073709552000)
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  ERROR -9007199254740993 (i64)            -> integer -9007199254740993 exceeds 2^53 in magnitude; encode it as a string (expected -9007199254740992)
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 17 pass, 3 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> ERROR integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740993 -> ERROR integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> PARSE ERROR number out of range at line 1 column 5

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
numbers: 1000000 pass, 0 mismatch, 0 error, 1000000 lines, 168.60ms
```

`results/inhouse-ryujs.ap.txt`

```text
# implementation: inhouse prototype + ryu-js 1.0.3 for f64 (serde_json float_roundtrip on)
# serde_json arbitrary_precision feature: true

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  ERROR 9007199254740993 (u64)             -> integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 9007199254740992)
  ERROR 18446744073709551615 (u64)         -> integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 18446744073709552000)
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  ERROR -9007199254740993 (i64)            -> integer -9007199254740993 exceeds 2^53 in magnitude; encode it as a string (expected -9007199254740992)
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 17 pass, 3 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> ERROR integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740993 -> ERROR integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> ERROR number 1e+400 is not representable as u64, i64 or f64

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
numbers: 1000000 pass, 0 mismatch, 0 error, 1000000 lines, 208.54ms
```

`results/inhouse-ryujs.targets.txt`

```text
  wasm32-unknown-unknown exit=0
  x86_64-unknown-linux-musl exit=0
  aarch64-unknown-linux-musl exit=0
```

</details>

<details>
<summary>In-house + zmij 1.0.23</summary>

`results/inhouse-zmij.default.txt`

```text
# implementation: inhouse prototype + zmij digits (already a serde_json dependency), serde_json float_roundtrip on
# serde_json arbitrary_precision feature: false

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  ERROR 9007199254740993 (u64)             -> integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 9007199254740992)
  ERROR 18446744073709551615 (u64)         -> integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 18446744073709552000)
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  ERROR -9007199254740993 (i64)            -> integer -9007199254740993 exceeds 2^53 in magnitude; encode it as a string (expected -9007199254740992)
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 17 pass, 3 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> ERROR integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740993 -> ERROR integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> PARSE ERROR number out of range at line 1 column 5

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
numbers: 1000000 pass, 0 mismatch, 0 error, 1000000 lines, 211.94ms
```

`results/inhouse-zmij.ap.txt`

```text
# implementation: inhouse prototype + zmij digits (already a serde_json dependency), serde_json float_roundtrip on
# serde_json arbitrary_precision feature: true

## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)
arrays: PASS (32 bytes)
french: PASS (130 bytes)
structures: PASS (98 bytes)
unicode: PASS (30 bytes)
values: PASS (118 bytes)
weird: PASS (214 bytes)
vectors: 6 pass, 0 fail

## B. Tricky numbers (expected = ES6 Number::toString)
  PASS  1e21 (f64)                         -> 1e+21
  PASS  1e-7 (f64)                         -> 1e-7
  PASS  0.1 (f64)                          -> 0.1
  PASS  100 (f64)                          -> 100
  PASS  100 (u64)                          -> 100
  PASS  1.0 (f64)                          -> 1
  PASS  -0.0 (f64)                         -> 0
  PASS  5e-324 (f64)                       -> 5e-324
  PASS  1.7976931348623157e308 (f64)       -> 1.7976931348623157e+308
  ERROR 9007199254740993 (u64)             -> integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 9007199254740992)
  ERROR 18446744073709551615 (u64)         -> integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string (expected 18446744073709552000)
  PASS  18446744073709551615 (f64)         -> 18446744073709552000
  ERROR -9007199254740993 (i64)            -> integer -9007199254740993 exceeds 2^53 in magnitude; encode it as a string (expected -9007199254740992)
  PASS  9007199254740992 (u64, 2^53)       -> 9007199254740992
  PASS  4294967295 (u32 max as u64)        -> 4294967295
  PASS  1e-6 (f64)                         -> 0.000001
  PASS  1.2345678901234568e20 (f64)        -> 123456789012345680000
  PASS  0.000001234 (f64)                  -> 0.000001234
  PASS  f32 0.1 widened (f64)              -> 0.10000000149011612
  PASS  i32 min (i64)                      -> -2147483648
tricky: 17 pass, 3 fail or error

## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)
              18446744073709551615 -> ERROR integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740993 -> ERROR integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
                  9007199254740992 -> 9007199254740992
                              1E30 -> 1e+30
                               1.0 -> 1
                               100 -> 100
                            0.1000 -> 0.1
                333333333.33333329 -> 333333333.3333333
                              1e21 -> 1e+21
                                -0 -> 0
                              -0.0 -> 0
                               0.0 -> 0
                            1.5e-7 -> 1.5e-7
    123456789012345678901234567890 -> 1.2345678901234568e+29
                             1e400 -> ERROR number 1e+400 is not representable as u64, i64 or f64

## D. ES6 number vectors from /tmp/claude-0/-home-user/b7365ea0-3216-568f-9836-831840fbb145/scratchpad/work/jcs/vectors/es6-1000000.txt
numbers: 1000000 pass, 0 mismatch, 0 error, 1000000 lines, 310.28ms
```

</details>

<details>
<summary>Probe P1 to P5 (debug build, overflow checks on)</summary>

`results/probe.debug.txt`

```text
build profile: debug (overflow checks on)

## P1. Distinct u64 values, typed struct, do they canonicalize to the same bytes?
  serde_json_canonicalizer 0.4.1   t_utc_us=9007199254740992      {"seq":1,"t_utc_us":9007199254740992}
  serde_jcs 0.2.0                  t_utc_us=9007199254740992      {"seq":1,"t_utc_us":9007199254740992}
  json-canon 0.1.3                 t_utc_us=9007199254740992      ERROR u64 must be less than JSON max safe integer
  serde_json::to_value then inhouse t_utc_us=9007199254740992      {"seq":1,"t_utc_us":9007199254740992}
  serde_json_canonicalizer 0.4.1   t_utc_us=9007199254740993      {"seq":1,"t_utc_us":9007199254740992}
  serde_jcs 0.2.0                  t_utc_us=9007199254740993      {"seq":1,"t_utc_us":9007199254740992}
  json-canon 0.1.3                 t_utc_us=9007199254740993      ERROR u64 must be less than JSON max safe integer
  serde_json::to_value then inhouse t_utc_us=9007199254740993      ERROR integer 9007199254740993 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
  => identical JCS bytes for 9007199254740992 and 9007199254740993: serde_json_canonicalizer=true serde_jcs=true

  serde_json_canonicalizer 0.4.1   t_utc_us=18446744073709551614  {"seq":1,"t_utc_us":18446744073709552000}
  serde_jcs 0.2.0                  t_utc_us=18446744073709551614  {"seq":1,"t_utc_us":18446744073709552000}
  json-canon 0.1.3                 t_utc_us=18446744073709551614  ERROR u64 must be less than JSON max safe integer
  serde_json::to_value then inhouse t_utc_us=18446744073709551614  ERROR integer 18446744073709551614 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
  serde_json_canonicalizer 0.4.1   t_utc_us=18446744073709551615  {"seq":1,"t_utc_us":18446744073709552000}
  serde_jcs 0.2.0                  t_utc_us=18446744073709551615  {"seq":1,"t_utc_us":18446744073709552000}
  json-canon 0.1.3                 t_utc_us=18446744073709551615  ERROR u64 must be less than JSON max safe integer
  serde_json::to_value then inhouse t_utc_us=18446744073709551615  ERROR integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
  => identical JCS bytes for 18446744073709551614 and 18446744073709551615: serde_json_canonicalizer=true serde_jcs=true

  serde_json_canonicalizer 0.4.1   t_utc_us=18446744073709550615  {"seq":1,"t_utc_us":18446744073709552000}
  serde_jcs 0.2.0                  t_utc_us=18446744073709550615  {"seq":1,"t_utc_us":18446744073709552000}
  json-canon 0.1.3                 t_utc_us=18446744073709550615  ERROR u64 must be less than JSON max safe integer
  serde_json::to_value then inhouse t_utc_us=18446744073709550615  ERROR integer 18446744073709550615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
  serde_json_canonicalizer 0.4.1   t_utc_us=18446744073709551615  {"seq":1,"t_utc_us":18446744073709552000}
  serde_jcs 0.2.0                  t_utc_us=18446744073709551615  {"seq":1,"t_utc_us":18446744073709552000}
  json-canon 0.1.3                 t_utc_us=18446744073709551615  ERROR u64 must be less than JSON max safe integer
  serde_json::to_value then inhouse t_utc_us=18446744073709551615  ERROR integer 18446744073709551615 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
  => identical JCS bytes for 18446744073709550615 and 18446744073709551615: serde_json_canonicalizer=true serde_jcs=true

## P2. NaN and infinity
  serde_json_canonicalizer 0.4.1   f64 NaN                        {"v":null}
  serde_jcs 0.2.0                  f64 NaN                        {"v":null}
  json-canon 0.1.3                 f64 NaN                        {"v":null}
  serde_json::to_value then inhouse f64 NaN                        {"v":null}
  serde_json_canonicalizer 0.4.1   f64 +inf                       {"v":null}
  serde_jcs 0.2.0                  f64 +inf                       {"v":null}
  json-canon 0.1.3                 f64 +inf                       {"v":null}
  serde_json::to_value then inhouse f64 +inf                       {"v":null}
  serde_json_canonicalizer 0.4.1   f32 NaN                        {"v":null}
  serde_jcs 0.2.0                  f32 NaN                        {"v":null}
  json-canon 0.1.3                 f32 NaN                        {"v":null}
  serde_json::to_value then inhouse f32 NaN                        {"v":null}
  serde_json_canonicalizer 0.4.1   f32 0.1                        {"v":0.10000000149011612}
  serde_jcs 0.2.0                  f32 0.1                        {"v":0.10000000149011612}
  json-canon 0.1.3                 f32 0.1                        {"v":0.1}
  serde_json::to_value then inhouse f32 0.1                        {"v":0.10000000149011612}
  serde_json::Value::from(f64::NAN) = null  json!(f64::INFINITY) = null  (Value silently turns NaN and inf into null)

## P3. i64 extremes (typed struct; a PANIC here is a fuzz-gate failure)
  serde_json_canonicalizer 0.4.1   i64::MIN                       {"v":-9223372036854776000}
  serde_jcs 0.2.0                  i64::MIN                       {"v":-9223372036854776000}
  json-canon 0.1.3                 i64::MIN                       PANIC
  serde_json::to_value then inhouse i64::MIN                       ERROR integer -9223372036854775808 exceeds 2^53 in magnitude; encode it as a string
  serde_json_canonicalizer 0.4.1   i64::MAX                       {"v":9223372036854776000}
  serde_jcs 0.2.0                  i64::MAX                       {"v":9223372036854776000}
  json-canon 0.1.3                 i64::MAX                       ERROR i64.abs() must be less than JSON max safe integer
  serde_json::to_value then inhouse i64::MAX                       ERROR integer 9223372036854775807 exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string
  serde_json_canonicalizer 0.4.1   -(2^53)                        {"v":-9007199254740992}
  serde_jcs 0.2.0                  -(2^53)                        {"v":-9007199254740992}
  json-canon 0.1.3                 -(2^53)                        ERROR i64.abs() must be less than JSON max safe integer
  serde_json::to_value then inhouse -(2^53)                        {"v":-9007199254740992}

## P4. One-byte edits of a record that JCS maps to the same bytes as the original
  original               file bytes differ from original: false  JCS identical to original: true   file == JCS(parse(file)): false
  'e' -> 'E' in 1e+30    file bytes differ from original: true   JCS identical to original: true   file == JCS(parse(file)): false
  '+' -> '0' in 1e+30    file bytes differ from original: true   JCS identical to original: true   file == JCS(parse(file)): false
  '0' -> ' ' in 4.50     file bytes differ from original: true   JCS identical to original: true   file == JCS(parse(file)): false
  indent ' ' -> '\t'     file bytes differ from original: true   JCS identical to original: true   file == JCS(parse(file)): false
  JCS of all five: {"numbers":[1e+30,4.5],"status":"PASS"}

## P5. Duplicate keys in a parsed record
  serde_json::from_str({"status":"FAIL","status":"PASS"}) -> {"status":"PASS"}  ; JCS -> {"status":"PASS"}
  serde_json_canonicalizer::pipe({"status":"FAIL","status":"PASS"}) -> Ok("{\"status\":\"PASS\"}")
```

`results/probe.nan.txt`

```text
  top-level f64 NaN: serde_json_canonicalizer=Err("NaN and +/-Infinity are not permitted in JSON") serde_jcs=Err("invalid float value") json-canon=Ok("null") serde_json=Ok("null")
  nested [NaN] via Vec<f64>: serde_json_canonicalizer=Ok("[null]") serde_jcs=Ok("[null]")
```

</details>

<details>
<summary>Probe perf (release, two runs)</summary>

`results/probe.perf.txt`

```text
workload: 1 config leaf with 1,200 params + 10,000 event leaves; record text 1768773 bytes
  serde_json parse of whole record: 15.57ms
  serde_json_canonicalizer 0.4.1           median   73.27ms  min   48.36ms  (1753751 canonical bytes)
  serde_jcs 0.2.0                          median   73.78ms  min   59.15ms  (1753751 canonical bytes)
  json-canon 0.1.3                         median   44.08ms  min   33.95ms  (1753751 canonical bytes)
  inhouse + ryu-js                         median   12.33ms  min    8.80ms  (1753751 canonical bytes)
  inhouse + zmij                           median   12.06ms  min    9.62ms  (1753751 canonical bytes)
  serde_json::to_vec (not JCS, baseline)   median    4.15ms  min    3.82ms  (1758751 canonical bytes)
workload: 1 config leaf with 1,200 params + 10,000 event leaves; record text 1768773 bytes
  serde_json parse of whole record: 27.35ms
  serde_json_canonicalizer 0.4.1           median   64.07ms  min   55.66ms  (1753751 canonical bytes)
  serde_jcs 0.2.0                          median   44.75ms  min   42.50ms  (1753751 canonical bytes)
  json-canon 0.1.3                         median   31.54ms  min   30.18ms  (1753751 canonical bytes)
  inhouse + ryu-js                         median   10.96ms  min    9.14ms  (1753751 canonical bytes)
  inhouse + zmij                           median    8.46ms  min    7.89ms  (1753751 canonical bytes)
  serde_json::to_vec (not JCS, baseline)   median    3.90ms  min    3.85ms  (1758751 canonical bytes)
```

</details>

<details>
<summary>Rust std formatting on ES6 tie cases</summary>

`results/stdfmt.txt`

```text
43143ff3c1cb0959  Display {} = 1424953923781206.3  LowerExp {:e} = 1.4249539237812063e15  Debug {:?} = 1424953923781206.3
c2dbfec8a2081be8  Display {} = -123124406820975.63  LowerExp {:e} = -1.2312440682097563e14  Debug {:?} = -123124406820975.63
427fb72bdcfed480  Display {} = 2179473461229.2813  LowerExp {:e} = 2.1794734612292813e12  Debug {:?} = 2179473461229.2813
```

</details>

<details>
<summary>Prototype source: in-house + ryu-js (`work/jcs/inhouse-ryujs/src/adapter.rs`, 86 code lines)</summary>

```rust
//! Prototype in-house RFC 8785 (JCS) serializer limited to the record's value types:
//! null, bool, integers within 2^53, finite f64, strings, arrays, objects with sorted keys.
//! Written only to size the in-house option and to measure Rust's `{:e}` against ES6 formatting.
use serde_json::{Number, Value};
use std::fmt::Write as _;

pub const NAME: &str = "inhouse prototype + ryu-js 1.0.3 for f64 (serde_json float_roundtrip on)";

/// Largest integer that RFC 8785 (via I-JSON, RFC 7493) allows as a JSON number: 2^53.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_992;

pub fn canon(v: &Value) -> Result<Vec<u8>, String> {
    let mut out = String::with_capacity(128);
    write_value(v, &mut out)?;
    Ok(out.into_bytes())
}

fn write_value(v: &Value, out: &mut String) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 section 3.2.3: sort members by the UTF-16 code units of the unescaped key.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push('{');
            for (i, (key, value)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(value, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(n: &Number, out: &mut String) -> Result<(), String> {
    if let Some(u) = n.as_u64() {
        if u > MAX_SAFE_INTEGER {
            return Err(format!("integer {u} exceeds 2^53; RFC 8785 cannot represent it as a JSON number, encode it as a string"));
        }
        write!(out, "{u}").map_err(|e| e.to_string())
    } else if let Some(i) = n.as_i64() {
        if i.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(format!("integer {i} exceeds 2^53 in magnitude; encode it as a string"));
        }
        write!(out, "{i}").map_err(|e| e.to_string())
    } else if let Some(f) = n.as_f64() {
        write_f64(f, out)
    } else {
        Err(format!("number {n} is not representable as u64, i64 or f64"))
    }
}

/// ES6 Number::toString via ryu-js (shortest round-trip digits, ties to even, ES6 layout).
fn write_f64(f: f64, out: &mut String) -> Result<(), String> {
    if !f.is_finite() {
        return Err("NaN and Infinity are not representable in JSON".to_string());
    }
    let mut buffer = ryu_js::Buffer::new();
    out.push_str(buffer.format_finite(f));
    Ok(())
}

/// RFC 8785 section 3.2.2.2: escape only `"`, `\`, and control characters below U+0020
/// (with the short forms for backspace, form feed, newline, carriage return, tab, and
/// lowercase `\u00xx` for the rest). Everything else, including U+007F and non-ASCII, is literal UTF-8.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
```

</details>

<details>
<summary>Harness source (`work/jcs/harness/main.rs`)</summary>

```rust
//! Shared JCS evaluation harness. Each scratch project pairs this file with an adapter.rs that
//! exposes `NAME` and `canon(&serde_json::Value) -> Result<Vec<u8>, String>`.
mod adapter;
use serde_json::Value;
use std::fs;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let testdata = &args[1];
    let numbers = &args[2];
    println!("# implementation: {}", adapter::NAME);
    println!("# serde_json arbitrary_precision feature: {}", cfg!(feature = "ap"));

    println!("\n## A. RFC 8785 official test vectors (testdata/input -> testdata/output, byte compare)");
    let (mut pass, mut fail) = (0, 0);
    for name in ["arrays", "french", "structures", "unicode", "values", "weird"] {
        let input = fs::read_to_string(format!("{testdata}/input/{name}.json")).unwrap();
        let expected = fs::read(format!("{testdata}/output/{name}.json")).unwrap();
        let value: Value = match serde_json::from_str(&input) {
            Ok(v) => v,
            Err(e) => { println!("{name}: PARSE ERROR {e}"); fail += 1; continue; }
        };
        match adapter::canon(&value) {
            Ok(out) if out == expected => { println!("{name}: PASS ({} bytes)", out.len()); pass += 1; }
            Ok(out) => {
                println!("{name}: FAIL\n  got:      {}\n  expected: {}", String::from_utf8_lossy(&out), String::from_utf8_lossy(&expected));
                fail += 1;
            }
            Err(e) => { println!("{name}: ERROR {e}"); fail += 1; }
        }
    }
    println!("vectors: {pass} pass, {fail} fail");

    println!("\n## B. Tricky numbers (expected = ES6 Number::toString)");
    let cases: Vec<(&str, Value, &str)> = vec![
        ("1e21 (f64)", Value::from(1e21f64), "1e+21"),
        ("1e-7 (f64)", Value::from(1e-7f64), "1e-7"),
        ("0.1 (f64)", Value::from(0.1f64), "0.1"),
        ("100 (f64)", Value::from(100.0f64), "100"),
        ("100 (u64)", Value::from(100u64), "100"),
        ("1.0 (f64)", Value::from(1.0f64), "1"),
        ("-0.0 (f64)", Value::from(-0.0f64), "0"),
        ("5e-324 (f64)", Value::from(5e-324f64), "5e-324"),
        ("1.7976931348623157e308 (f64)", Value::from(f64::MAX), "1.7976931348623157e+308"),
        ("9007199254740993 (u64)", Value::from(9007199254740993u64), "9007199254740992"),
        ("18446744073709551615 (u64)", Value::from(u64::MAX), "18446744073709552000"),
        ("18446744073709551615 (f64)", Value::from(u64::MAX as f64), "18446744073709552000"),
        ("-9007199254740993 (i64)", Value::from(-9007199254740993i64), "-9007199254740992"),
        ("9007199254740992 (u64, 2^53)", Value::from(9007199254740992u64), "9007199254740992"),
        ("4294967295 (u32 max as u64)", Value::from(u32::MAX as u64), "4294967295"),
        ("1e-6 (f64)", Value::from(1e-6f64), "0.000001"),
        ("1.2345678901234568e20 (f64)", Value::from(1.2345678901234568e20f64), "123456789012345680000"),
        ("0.000001234 (f64)", Value::from(0.000001234f64), "0.000001234"),
        ("f32 0.1 widened (f64)", Value::from(0.1f32 as f64), "0.10000000149011612"),
        ("i32 min (i64)", Value::from(i32::MIN as i64), "-2147483648"),
    ];
    let (mut tpass, mut tfail) = (0, 0);
    for (label, value, expected) in &cases {
        match adapter::canon(value) {
            Ok(out) if out == expected.as_bytes() => { println!("  PASS  {label:<34} -> {expected}"); tpass += 1; }
            Ok(out) => { println!("  FAIL  {label:<34} -> got {} expected {expected}", String::from_utf8_lossy(&out)); tfail += 1; }
            Err(e) => { println!("  ERROR {label:<34} -> {e} (expected {expected})"); tfail += 1; }
        }
    }
    println!("tricky: {tpass} pass, {tfail} fail or error");

    println!("\n## C. Numbers parsed from JSON text (shows u64 and arbitrary_precision behaviour)");
    for text in ["18446744073709551615", "9007199254740993", "9007199254740992", "1E30", "1.0", "100", "0.1000", "333333333.33333329", "1e21", "-0", "-0.0", "0.0", "1.5e-7", "123456789012345678901234567890", "1e400"] {
        match serde_json::from_str::<Value>(text) {
            Ok(v) => match adapter::canon(&v) {
                Ok(out) => println!("  {text:>32} -> {}", String::from_utf8_lossy(&out)),
                Err(e) => println!("  {text:>32} -> ERROR {e}"),
            },
            Err(e) => println!("  {text:>32} -> PARSE ERROR {e}"),
        }
    }

    println!("\n## D. ES6 number vectors from {numbers}");
    let data = fs::read_to_string(numbers).unwrap();
    let t = Instant::now();
    let (mut npass, mut nfail, mut nerr) = (0usize, 0usize, 0usize);
    let mut shown = 0;
    for line in data.lines() {
        let (hex, expected) = line.split_once(',').unwrap();
        let f = f64::from_bits(u64::from_str_radix(hex, 16).unwrap());
        match adapter::canon(&Value::from(f)) {
            Ok(out) if out == expected.as_bytes() => npass += 1,
            Ok(out) => { nfail += 1; if shown < 10 { println!("  MISMATCH {hex}: got {} expected {expected}", String::from_utf8_lossy(&out)); shown += 1; } }
            Err(e) => { nerr += 1; if shown < 10 { println!("  ERROR {hex}: {e} (expected {expected})"); shown += 1; } }
        }
    }
    println!("numbers: {npass} pass, {nfail} mismatch, {nerr} error, {} lines, {:.2?}", npass + nfail + nerr, t.elapsed());
}
```

</details>

<details>
<summary>Probe source (`work/jcs/probe/src/main.rs`)</summary>

```rust
//! Probes for the record-specific risks: u64 above 2^53, NaN, i64::MIN, one-byte flips that
//! JCS normalizes away, duplicate keys, and canonicalization cost at verify scale.
#[path = "../../inhouse-ryujs/src/adapter.rs"]
mod inhouse_ryujs;
#[path = "../../inhouse-zmij/src/adapter.rs"]
mod inhouse_zmij;

use serde::Serialize;
use serde_json::{json, Value};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

type Canon = fn(&Value) -> Result<Vec<u8>, String>;
fn sjc(v: &Value) -> Result<Vec<u8>, String> { serde_json_canonicalizer::to_vec(v).map_err(|e| e.to_string()) }
fn jcs(v: &Value) -> Result<Vec<u8>, String> { serde_jcs::to_vec(v).map_err(|e| e.to_string()) }
fn jc(v: &Value) -> Result<Vec<u8>, String> { json_canon::to_vec(v).map_err(|e| e.to_string()) }
fn plain(v: &Value) -> Result<Vec<u8>, String> { serde_json::to_vec(v).map_err(|e| e.to_string()) }
const IMPLS: [(&str, Canon); 5] = [
    ("serde_json_canonicalizer 0.4.1", sjc),
    ("serde_jcs 0.2.0", jcs),
    ("json-canon 0.1.3", jc),
    ("inhouse + ryu-js", inhouse_ryujs::canon),
    ("inhouse + zmij", inhouse_zmij::canon),
];

fn show(r: &Result<Vec<u8>, String>) -> String {
    match r { Ok(b) => String::from_utf8_lossy(b).into_owned(), Err(e) => format!("ERROR {e}") }
}

/// Serialize a typed struct directly through each crate (no serde_json::Value in between).
macro_rules! typed {
    ($label:expr, $val:expr) => {{
        let v = $val;
        let run = |name: &str, f: &dyn Fn() -> Result<Vec<u8>, String>| {
            match catch_unwind(AssertUnwindSafe(|| f())) {
                Ok(r) => println!("  {:<32} {:<30} {}", name, $label, show(&r)),
                Err(_) => println!("  {:<32} {:<30} PANIC", name, $label),
            }
        };
        run("serde_json_canonicalizer 0.4.1", &|| serde_json_canonicalizer::to_vec(&v).map_err(|e| e.to_string()));
        run("serde_jcs 0.2.0", &|| serde_jcs::to_vec(&v).map_err(|e| e.to_string()));
        run("json-canon 0.1.3", &|| json_canon::to_vec(&v).map_err(|e| e.to_string()));
        run("serde_json::to_value then inhouse", &|| serde_json::to_value(&v).map_err(|e| e.to_string()).and_then(|x| inhouse_zmij::canon(&x)));
    }};
}

#[derive(Serialize)]
struct Ev { seq: u64, t_utc_us: u64 }
#[derive(Serialize)]
struct F64 { v: f64 }
#[derive(Serialize)]
struct F32 { v: f32 }
#[derive(Serialize)]
struct I64 { v: i64 }

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    if mode == "perf" { perf(); return; }
    if mode == "nan" { nan_top_level(); return; }
    println!("build profile: {}", if cfg!(debug_assertions) { "debug (overflow checks on)" } else { "release" });

    println!("\n## P1. Distinct u64 values, typed struct, do they canonicalize to the same bytes?");
    for (a, b) in [(9_007_199_254_740_992u64, 9_007_199_254_740_993u64), (u64::MAX - 1, u64::MAX), (u64::MAX - 1000, u64::MAX)] {
        typed!(format!("t_utc_us={a}"), Ev { seq: 1, t_utc_us: a });
        typed!(format!("t_utc_us={b}"), Ev { seq: 1, t_utc_us: b });
        let x = serde_json_canonicalizer::to_vec(&Ev { seq: 1, t_utc_us: a }).unwrap();
        let y = serde_json_canonicalizer::to_vec(&Ev { seq: 1, t_utc_us: b }).unwrap();
        let p = serde_jcs::to_vec(&Ev { seq: 1, t_utc_us: a }).unwrap();
        let q = serde_jcs::to_vec(&Ev { seq: 1, t_utc_us: b }).unwrap();
        println!("  => identical JCS bytes for {a} and {b}: serde_json_canonicalizer={} serde_jcs={}\n", x == y, p == q);
    }

    println!("## P2. NaN and infinity");
    typed!("f64 NaN", F64 { v: f64::NAN });
    typed!("f64 +inf", F64 { v: f64::INFINITY });
    typed!("f32 NaN", F32 { v: f32::NAN });
    typed!("f32 0.1", F32 { v: 0.1 });
    println!("  serde_json::Value::from(f64::NAN) = {}  json!(f64::INFINITY) = {}  (Value silently turns NaN and inf into null)", Value::from(f64::NAN), json!(f64::INFINITY));

    println!("\n## P3. i64 extremes (typed struct; a PANIC here is a fuzz-gate failure)");
    typed!("i64::MIN", I64 { v: i64::MIN });
    typed!("i64::MAX", I64 { v: i64::MAX });
    typed!("-(2^53)", I64 { v: -9_007_199_254_740_992 });

    println!("\n## P4. One-byte edits of a record that JCS maps to the same bytes as the original");
    let base = "{\n  \"numbers\": [1e+30, 4.50],\n  \"status\": \"PASS\"\n}";
    let edits: [(&str, String); 5] = [
        ("original", base.to_string()),
        ("'e' -> 'E' in 1e+30", base.replacen("1e+30", "1E+30", 1)),
        ("'+' -> '0' in 1e+30", base.replacen("1e+30", "1e030", 1)),
        ("'0' -> ' ' in 4.50", base.replacen("4.50", "4.5 ", 1)),
        ("indent ' ' -> '\\t'", base.replacen("\n  \"status\"", "\n \t\"status\"", 1)),
    ];
    let canon0 = sjc(&serde_json::from_str(base).unwrap()).unwrap();
    for (label, text) in &edits {
        let v: Value = serde_json::from_str(text).unwrap();
        let c = sjc(&v).unwrap();
        println!("  {label:<22} file bytes differ from original: {:<5}  JCS identical to original: {:<5}  file == JCS(parse(file)): {}",
            text.as_bytes() != base.as_bytes(), c == canon0, text.as_bytes() == c.as_slice());
    }
    println!("  JCS of all five: {}", String::from_utf8_lossy(&canon0));

    println!("\n## P5. Duplicate keys in a parsed record");
    let dup = r#"{"status":"FAIL","status":"PASS"}"#;
    let v: Value = serde_json::from_str(dup).unwrap();
    println!("  serde_json::from_str({dup}) -> {}  ; JCS -> {}", v, show(&sjc(&v)));
    println!("  serde_json_canonicalizer::pipe({dup}) -> {:?}", serde_json_canonicalizer::pipe(dup).map_err(|e| e.to_string()));
}

/// A record-shaped workload: 1,200 parameters (PX4-like, int32 and float32) as one config leaf,
/// plus 10,000 event leaves, each canonicalized separately as the verifier would.
fn perf() {
    let mut params = serde_json::Map::new();
    for i in 0..1200u32 {
        let name = format!("PARAM_{:04}_{}", (i * 7919) % 1200, ["MC", "FW", "EKF2", "COM", "NAV", "SENS"][(i % 6) as usize]);
        let value = if i % 2 == 0 { json!(i as i32 - 600) } else { json!((i as f32 * 0.137f32) as f64) };
        params.insert(name, value);
    }
    let config = json!({"firmware": "v1.15.4 0123456789abcdef", "params": Value::Object(params)});
    let kinds = ["ARM", "NAV_STATE_CHANGE", "FAILSAFE_SET", "COMMAND", "LOG_MESSAGE", "PARAM_CHANGED_IN_FLIGHT"];
    let events: Vec<Value> = (0..10_000u64).map(|i| json!({
        "seq": i, "kind": kinds[(i % 6) as usize], "boot_us": 1_000_000 + i * 2_500,
        "utc_us": 1_760_000_000_000_000u64 + i * 2_500,
        "data": {"old": "POSCTL", "new": "AUTO_MISSION", "text": format!("event {i} \u{00b0} \"quoted\""), "value": (i as f32 * 0.25f32) as f64}
    })).collect();
    let record_text = serde_json::to_string(&json!({"config": config, "events": events})).unwrap();
    println!("workload: 1 config leaf with 1,200 params + 10,000 event leaves; record text {} bytes", record_text.len());
    let t = Instant::now();
    let parsed: Value = serde_json::from_str(&record_text).unwrap();
    println!("  serde_json parse of whole record: {:.2?}", t.elapsed());
    let leaves: Vec<&Value> = std::iter::once(&parsed["config"]).chain(parsed["events"].as_array().unwrap().iter()).collect();
    let mut all: Vec<(&str, Canon)> = IMPLS.to_vec();
    all.push(("serde_json::to_vec (not JCS, baseline)", plain));
    for (name, f) in all {
        let mut times = Vec::new();
        let mut total = 0usize;
        for _ in 0..7 {
            let t = Instant::now();
            total = 0;
            for leaf in &leaves { total += f(leaf).unwrap().len(); }
            times.push(t.elapsed());
        }
        times.sort();
        println!("  {name:<40} median {:>9.2?}  min {:>9.2?}  ({} canonical bytes)", times[3], times[0], total);
    }
}

#[allow(dead_code)]
pub fn nan_top_level() {
    println!("  top-level f64 NaN: serde_json_canonicalizer={:?} serde_jcs={:?} json-canon={:?} serde_json={:?}",
        serde_json_canonicalizer::to_string(&f64::NAN).map_err(|e| e.to_string()),
        serde_jcs::to_string(&f64::NAN).map_err(|e| e.to_string()),
        json_canon::to_string(&f64::NAN).map_err(|e| e.to_string()),
        serde_json::to_string(&f64::NAN).map_err(|e| e.to_string()));
    println!("  nested [NaN] via Vec<f64>: serde_json_canonicalizer={:?} serde_jcs={:?}",
        serde_json_canonicalizer::to_string(&vec![f64::NAN]).map_err(|e| e.to_string()),
        serde_jcs::to_string(&vec![f64::NAN]).map_err(|e| e.to_string()));
}
```

</details>


## 9. Corrections to the build plan and to SPEC

### 9.1 Reviewer claims re-checked

| Build plan statement | Finding in this session | Verdict |
|---|---|---|
| "lib.rs shows `px4-ulog` 0.1.1, last release Dec 2018, 2 releases. CONTRADICTED." | The crates.io index lists px4-ulog 0.1.0, 0.1.1, 0.5.0, 0.6.0, 0.6.1. The 0.6.1 tarball declares MIT and `repository = "https://github.com/PX4/px4-ulog-rs"`; that repository tags v0.5.0 (2026-06-19), v0.6.0 and v0.6.1 (2026-06-24). The reviewer was right; the rebuttal used a stale registry mirror. | CORRECTED. px4-ulog was evaluated on its merits in item 2 (and rejected for crashes). |
| "`yule_log` 0.4.0, MIT, Nov 2025, streaming, supports `multi_id`. VERIFIED. Leading candidate." | Dates and license confirmed. Item 2 found 1 panic, 2 allocation aborts and 1 stack overflow on crafted input, and silently invented records on 8 of 19 truncations. | CORRECTED. Not adopted (item 2). |
| "PX4 current stable is v1.17." | Newest tag on PX4/PX4-Autopilot is v1.17.0; the v1.14 to v1.17 scope covers v1.14.0 to v1.14.4, v1.15.1 to v1.15.4, v1.16.0 to v1.16.2, v1.17.0. | VERIFIED. |
| "`FailsafeFlags` uORB message exists." | `msg/FailsafeFlags.msg` exists at v1.14.4 and v1.17.0 and is logged by default. Its fields differ per version (item 4). | VERIFIED. |
| "`vehicle_command` logs requests; `vehicle_command_ack` confirms result." | Both logged by default. Acks carry no request id; internal commands are never acked (item 4). | VERIFIED, with pairing limits. |
| "Volatile parameters change every flight." | Confirmed by the two-flight experiment (item 5). In source, YAML `volatile: true` appears only in sensors, commander and ekf2 (`params_volatile.yaml`); land_detector, `COM_FLIGHT_UUID`, `ASPD_SCALE_*` and `SENS_DPRES_OFF` use legacy `@volatile` comments in `*_params.c`. | VERIFIED; an earlier draft of this table named land_detector's YAML wrongly. |
| "Sample logs in PX4/pyulog are BSD-3-Clause." | pyulog `LICENSE.md`: BSD-3-Clause, Copyright (c) 2016, PX4 Pro Drone Autopilot. | VERIFIED. |
| "`blake3` cross-compiling to aarch64 musl can fail on C/ASM features." | With cargo-zigbuild its NEON C code compiles and links; `pure` is not needed. Without zig there is no aarch64 musl C compiler at all (item 7). | CORRECTED. |

### 9.2 SPEC statements that the evidence contradicts or leaves undefined

Each row needs a founder decision before the chunk that implements it. None of these is changed in `docs/SPEC.md` by Chunk 1.

| SPEC line | Finding | Proposed resolution | Needed by |
|---|---|---|---|
| B1.5 "firmware version and git hash from the ULog header" | They come from ULog info messages (`ver_sw`, `ver_sw_release`), not the 16-byte file header. | Reword to "from the ULog info messages `ver_sw` and `ver_sw_release`". | Chunk 2 |
| B1.5 "UTC microseconds when GPS time is available" | SIH writes `time_utc_usec = 0` on every GPS sample; v1.17's `boot_time_utc_us` falls back to the host clock. | UTC only from a nonzero GPS `time_utc_usec`; never from `boot_time_utc_us`. | Chunk 2 |
| B1.5 PARAM_CHANGED_IN_FLIGHT | The logger writes a batch of unchanged 'P' messages at log start (17 in v1.17, 662 in v1.14), and firmware rewrites `CAL_BARO0_OFF` after arming on the ground. | Compare against the last known value; define "in flight" as between ARM and DISARM; report firmware-written changes like any other. | Chunk 2 |
| B1.6 R4 "No failsafe raised during flight" with flags from `failsafe_flags` | Four flags are true for the whole of every headless flight while `vehicle_status.failsafe` stays false; `mode_req_*` fields are bitmasks, not flags. | R4 triggers on `vehicle_status.failsafe`; it names the `failsafe_flags` booleans that are true at that moment and required by the current mode. | Chunk 2 |
| B1.7 numbers in JCS | u64 values above 2^53 lose precision as JSON numbers; non-finite floats serialize silently as null. | Encode u64 as decimal strings; refuse non-finite floats. | Chunk 3 |
| B1.7 tamper property | Non-canonical spellings of the same JSON (`1E+30`, tabs, duplicate keys) hash identically, so some byte flips cannot be detected. | Store the record as its canonical bytes; verify rejects any file that differs from `JCS(parse(file))`. | Chunk 3 |
| B1.7 `tool` and `seal` blocks | Neither is a Merkle leaf nor in the signed payload, so they can be edited without breaking verification. | Add a first leaf covering `tool` and `seal`. Applied by the security patch (item 11). | Chunk 3 |
| B1.10 "`ldd` reports not a dynamic executable" | x86_64 musl output is static-pie and `ldd` prints "statically linked"; on an x86_64 host `ldd` says "not a dynamic executable" for any aarch64 binary, even a dynamic one. | Gate on `readelf`: no INTERP program header and no NEEDED entries. Applied by the security patch (item 11). | Chunk 5 |
| B1.10 standalone verify under 10 ms at 10,000 events | JSON parsing alone took 15 to 27 ms under load (item 8). | Measure in Chunk 3 on an idle machine; if missed, report the number and cause without moving the gate. | Chunk 3 |

Toolchain used for every claim above: Rust 1.97.0, cargo-deny 0.20.2, cargo-zigbuild 0.23.4, zig 0.17.0, Python 3.13.16, GCC 13.3.0, pyulog 1.2.4, PX4 built from the tags named.


## 10. Decisions the founder must approve before Chunk 2

**Status: all nine decisions approved by the founder on 2026-10-18.** Binding rulings recorded with the approval:

- **Optimization tax.** The validated profile compiles the FIPS module exactly per its security policy, with no optimization flags. If it misses the 2 s (x86_64) or 4 s (aarch64) gate in Chunk 5, the delta is documented as the compliance tax; the gate and the build stay as they are.
- **Native aarch64 releases.** Cross-compiling and qemu are acceptable for CI feature branches; release artifacts are built on native ARM64 hardware.
- **Hardware tokens.** Sandbox and hardware-in-the-loop work uses `--evaluation-only` file keys. The MVP is not blocked on finding a token whose certificate approves Ed25519; `--token-cert` holds the v1 boundary.
- **WASM split.** `crypto-portable` (ed25519-dalek) for the browser sandbox, `crypto-fips` for the CLI, as designed.

| # | Decision | Recommendation | Evidence |
|---|---|---|---|
| 1 | ULog parser | Write a small in-house parser in `sfr-core` behind `FlightLogIngestor`; keep px4-ulog 0.6.1 only as a test-time cross-check. All three crates fail the zero-panic fuzz gate as published. | Item 2 |
| 2 | Canonicalization | In-house RFC 8785 serializer limited to the record's types, with `ryu-js =1.0.3` for float digits; u64 values as decimal strings; non-finite floats refused; the `.sfr` stored as its canonical bytes. | Item 8 |
| 3 | Default volatile ignore list | The seven patterns in item 5. Sensor calibrations stay visible to R3. | Item 5 |
| 4 | VTOL START, END, ABORT | The definitions in item 6; a quadchute is a failsafe (R4), not a transition abort (R6). | Item 6 |
| 5 | R4 trigger | `vehicle_status.failsafe`, naming the mode-relevant `failsafe_flags`. | Item 9.2 |
| 6 | SPEC wording fixes | The B1.5 and B1.7 rows in item 9.2 (firmware from info messages, GPS-only UTC, in-flight parameter window, JCS number rules, canonical bytes). | Item 9.2 |
| 7 | FIPS module version | Pin the newest AWS-LC-FIPS version that holds an active CMVP certificate (item 11.3), with the matching rustls-webpki. | Item 11 |
| 8 | Key custody model | `pkcs11-token` for operations, `tpm-sealed` where no token fits, `file-evaluation` for demos only; offline certificate chain and CRL checks in `verify`. Applied to `docs/SPEC.md` in this chunk for review. | Item 11 |
| 9 | OpenSSL license | Allow `OpenSSL` in `deny.toml`; the AWS-LC module requires it. Its advertising clause applies to product documentation that mentions the cryptography. | Item 11 |
| 10 | Validated-profile build settings | Build the #5314 module exactly per its security policy (no build type, so no `-O`), and measure the seal gates with it; build aarch64 natively on aarch64 for releases. Any departure (an optimization flag, cross-compiling) goes to the assessor first. | Item 11.5 |

**Inputs the founder provides**

1. **Existing Rust code to audit (item 1).** None exists in the AIFlightRecorder repository. If dual-hash, Merkle, or Ed25519 Rust code exists elsewhere, point to it and item 1 is re-run. Until then the decision is REPLACE.
2. **aarch64 hardware for Chunk 5.** Cross builds and qemu runs are verified here; the under-4-second seal gate must be measured on real aarch64 hardware.
3. **A token for hardware tests, optional.** CI uses SoftHSM and swtpm. A YubiKey on firmware with PIV Ed25519 support (item 11.3) or an HSM would confirm the `pkcs11-token` path on real hardware.

**Notes**

- The five required golden logs plus three extras are in `testdata/` (item 3). v1.15 and v1.16 logs can be generated the same way if one log per supported series is wanted; item 4 notes where those versions differ.
- SIH never writes GPS UTC (`time_utc_usec` is 0), so the UTC path needs a real-vehicle log or a synthetic test log in Chunk 2.
- Building PX4 v1.14.4 needed three local fixes on GCC 13 (item 3). They affect only log generation, never the product.
- The FIPS module makes CI heavier: release and test jobs need CMake, Go, Perl, `musl-tools`, and for aarch64 the GCC cross compiler plus a musl build (item 11.1).


## 11. Cryptographic module boundary and key custody (security audit before Chunk 2)

**Scope.** Founder rulings, not reopened: the dual-hash architecture stays (SHA-256 anchors trust under FIPS 180-4; BLAKE3 is supplementary and non-approved), and Ed25519 stays (EdDSA is approved in FIPS 186-5). Two gaps were closed: the module boundary (ed25519-dalek and sha2 are pure Rust with no FIPS 140 certificate) and key custody (file keys only). Every claim below was reproduced in this session unless marked otherwise.

### 11.1 Module choice: aws-lc-rs with the `fips` feature

| Question | Evidence | Status |
|---|---|---|
| Which module does aws-lc-rs `fips` link? | aws-lc-rs 1.17.x requires aws-lc-fips-sys 0.13.x, which vendors a snapshot of the 3.x FIPS line (branch `fips-2024-09-27`, library string 3.6.0). aws-lc-rs 1.18.x requires aws-lc-fips-sys 0.14.x, which vendors the 4.x line (library string 4.2.0, commit `fa57b95`). The 0.14.3 README still says 3.0.x; the vendored source and the aws-lc-rs README say 4.x. **Neither is the validated source** (11.3). | VERIFIED (crate sources, index, git) |
| Is Ed25519 inside the module boundary? | In both versions `crypto/fipsmodule/bcm.c` includes `curve25519/curve25519.c`; the service indicator marks EVP_PKEY_ED25519 signing and verification approved, citing FIPS 186-5 sections 7.6 and 7.7. The Ed25519 known-answer test is not in the power-on set: `curve25519.c` calls `boringssl_ensure_eddsa_self_test()` before each Ed25519 key generation, signature and verification, which runs the test once per process (`self_check.c`) and aborts on failure. (Corrected at the Chunk 3 gate; this row first said the power-on self-tests include it.) | VERIFIED (source) |
| What happens if a self-test fails? | `BORINGSSL_FIPS_abort()` calls `abort()` (`bcm.c`). The process dies; no exit code from `sfr` is possible. SPEC B1.4 now says so. | VERIFIED (source) |
| Does it run as a static musl binary? | A probe calling `try_fips_mode()`, RFC 8032 section 7.1 TEST 1, a tampered-signature rejection, FIPS 180-4 SHA-256("abc") and DRBG key generation passes on every combination below. | VERIFIED |
| Licenses | aws-lc-fips-sys: `ISC AND (Apache-2.0 OR ISC) AND OpenSSL`. cargo-deny rejected `OpenSSL` until it was added to the allow list. No deny-list hit; advisories, bans, sources clean. | VERIFIED |

**Build matrix for the FIPS probe** (Rust 1.97.0, release, fat LTO):

| Module | Target | Toolchain | Result | Static check (`readelf`) |
|---|---|---|---|---|
| 3.0 (aws-lc-rs 1.17.4) | x86_64 musl | cargo-zigbuild 0.23.4, zig 0.17.0 | FAIL: delocate "parse error near Unknown" | n/a |
| 3.0 | aarch64 musl | cargo-zigbuild | FAIL: same | n/a |
| 3.0 | x86_64 musl | `musl-gcc` (musl 1.2.4, GCC 13.3) | PASS, probe runs | static-pie, 0 NEEDED, 0 INTERP |
| 3.0 | aarch64 musl | `aarch64-linux-gnu-gcc` 13.3 + musl 1.2.5 `musl-gcc` wrapper | PASS, probe runs under qemu-aarch64 | static EXEC, 0 NEEDED, 0 INTERP |
| 4.x (aws-lc-rs 1.18.2) | x86_64 musl | `musl-gcc` | PASS, probe runs | static-pie, 0 NEEDED, 0 INTERP |
| 4.x | aarch64 musl | GCC cross + musl `musl-gcc` | PASS, probe runs under qemu-aarch64 | static EXEC, 0 NEEDED, 0 INTERP |

**Why zig fails.** The FIPS build compiles `bcm.c` with `-S` and expects assembly text in `libbcm_c_generated_asm.a`, which Go's delocate tool rewrites so the module can check its own integrity. Under cargo-zigbuild the archive member is an ELF object (`ar p` shows an ELF header), so delocate cannot parse it. This is a toolchain incompatibility, not a configuration error. zig stays usable for crates without the FIPS module; the release build of `sfr` uses GCC.

**Exact build process for Chunk 5 (replaces cargo-zigbuild for `sfr`).**

```bash
# Both architectures. Kernel headers: musl-gcc ships none, the module needs linux/random.h.
mkdir -p kh/x86_64 kh/aarch64
ln -s /usr/include/linux kh/x86_64/linux; ln -s /usr/include/asm-generic kh/x86_64/asm-generic
ln -s /usr/include/x86_64-linux-gnu/asm kh/x86_64/asm
for d in linux asm asm-generic; do ln -s /usr/aarch64-linux-gnu/include/$d kh/aarch64/$d; done

# x86_64: apt-get install musl-tools cmake golang perl
CC_x86_64_unknown_linux_musl=musl-gcc \
CFLAGS_x86_64_unknown_linux_musl="-isystem $PWD/kh/x86_64" \
  cargo build -p sfr --release --locked --target x86_64-unknown-linux-musl

# aarch64 on an x86_64 host: apt-get install gcc-aarch64-linux-gnu, then musl 1.2.5 built once:
#   CC=aarch64-linux-gnu-gcc AR=aarch64-linux-gnu-ar RANLIB=aarch64-linux-gnu-ranlib \
#   ./configure --target=aarch64-linux-musl --prefix=$MUSL_AA64 --enable-wrapper=gcc --disable-shared
#   make AR=aarch64-linux-gnu-ar RANLIB=aarch64-linux-gnu-ranlib && make install
CC_aarch64_unknown_linux_musl=$MUSL_AA64/bin/musl-gcc \
AR_aarch64_unknown_linux_musl=aarch64-linux-gnu-ar \
CFLAGS_aarch64_unknown_linux_musl="-isystem $PWD/kh/aarch64" \
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=$MUSL_AA64/bin/musl-gcc \
  cargo build -p sfr --release --locked --target aarch64-unknown-linux-musl

# Gate (SPEC B1.10 Static binaries), both targets:
test "$(readelf -lW target/*/release/sfr | grep -c INTERP)" -eq 0
test "$(readelf -dW target/*/release/sfr 2>/dev/null | grep -c NEEDED)" -eq 0
```

Fallback if the cross toolchain is unavailable: build natively on an arm64 runner with that runner's `musl-gcc` (the same commands without the cross variables); aws-lc-fips-sys maps Alpine's `aarch64-alpine-linux-musl` to the Rust target, so a native Alpine build also works. Not tested here: Docker was not running and the Alpine mirror was blocked.

### 11.2 Key custody: what works with Ed25519, measured

| Path | Evidence | Status |
|---|---|---|
| PKCS#11 v3.0 token (SoftHSM 2.6.1) | Token lists `EC-EDWARDS-KEY-PAIR-GEN` and `EDDSA`. Key generated in the token: private object "sensitive, always sensitive, never extractable, local". The prototype helper signed the 50-byte SFR payload with CKM_EDDSA (pure Ed25519); OpenSSL verified it independently; a one-bit flip was rejected; repeat signing gave identical bytes, as Ed25519 is deterministic. | VERIFIED |
| PKCS#11 inside a static `sfr` | A static musl program calling `dlopen` on `libsofthsm2.so` gets "Dynamic loading not supported"; a glibc control loads it. Hence the separate helper process, the same split OpenSSH makes with `ssh-pkcs11-helper`. | VERIFIED |
| TPM 2.0 native EdDSA | swtpm 0.7.3 on libtpms 0.9.3 lists no `eddsa` algorithm and only NIST, BN and SM2 curves; `tpm2_create -G ecc_eddsa` fails. | VERIFIED for libtpms; real chips: see 11.3 |
| TPM 2.0 sealed seed | A 32-byte seed sealed with `fixedtpm\|fixedparent\|userwithauth\|noda` round-trips through `tpm2_unseal`; loading the same blobs into a second TPM fails. | VERIFIED |

**Helper prototype** (`sfr-pkcs11-helper`, to land in Chunk 3): Rust, `#![forbid(unsafe_code)]`, `cryptoki =0.12.1` (Apache-2.0; graph clean under deny.toml and the deny list). It accepts an RFC 7512 `pkcs11:` URI with `token`, `serial`, `object`, `id`, `type=private` and the query attributes `module-path` and `pin-source` (`file:` or `env:`). It refuses `pin-value`, unknown attributes, and anything that matches more than one token or key pair. It reads the payload as hex on stdin and checks its `SFR-RECORD-V1` prefix and 50-byte length. It writes one JSON line with the public key, the signature and the token label, serial and model, and exits 4 on any failure. Tested against SoftHSM: a good signature, wrong PIN, `pin-value`, a non-SFR payload, and no such key. Source: `scratchpad/sec/helper/src/main.rs` in this session, carried into Chunk 3 with its tests.

**Certificates (PKI)** with rustls-webpki (`aws-lc-rs-fips` feature) against a generated Ed25519 CA, using both module versions in static musl builds: a code-signing leaf verifies; a server-auth-only leaf fails with RequiredEkuNotFound; a CRL-revoked leaf fails with CertRevoked; the record signature verifies through the signer certificate's own key, and fails through another certificate's key (InvalidSignatureForPublicKey). Pairing: aws-lc-rs 1.17.x needs rustls-webpki `=0.103.13` (0.103.14 and later require aws-lc-rs 1.18). cargo-deny advisories are clean for both pairings today.

### 11.3 Facts from primary sources

**The central finding: the `fips` feature does not by itself give a CMVP-validated module.** A certificate covers one module version, built from one source archive in the way its security policy prescribes, on the operational environments it lists. aws-lc-fips-sys builds a different snapshot, with a symbol prefix (`BORINGSSL_PREFIX`), so its output is AWS-LC FIPS module code running in approved mode with its self-tests, but not the validated module. SPEC B1.10 therefore defines two build profiles (development and validated); only the validated profile may name a certificate.

| # | Fact | Status | Source |
|---|---|---|---|
| 1 | AWS-LC FIPS 140-3 certificates reported Active: #4631 (1.0.2 and 1.1.0), #4816 (2.0.0 static), #4759 and #5429 (2.0.0 dynamic), #5146 (1.29.1, NetOS), #5298 (3.1.0 dynamic), #5314 (3.1.0 static). Tested environments: Amazon Linux 2 and 2023, Ubuntu 20.04 and 22.04 on EC2 Intel Xeon and Graviton2/3/4, and NetOS; no libc is named. No certificate lists a musl environment. | Security policies VERIFIED (AWS-hosted copies in `aws/aws-lc` `crypto/fipsmodule/policydocs`); status and dates SECONDARY (csrc.nist.gov was blocked) | `aws/aws-lc` FIPS.md; csrc.nist.gov certificate pages |
| 2 | Ed25519 KeyGen, SigGen and SigVer are approved in the 3.1.0 policies only. #5298 Table 5, p. 9: "EDDSA SigGen ... Curve - ED-25519 ... FIPS 186-5"; #5314 Table 5 has the same rows. The 1.x and 2.0.0 policies have no EdDSA entry. Ed25519ph is not in 3.1.0. | VERIFIED | 140sp5298.pdf, 140sp5314.pdf |
| 3 | The 4.x line has no certificate; AWS lists "AWS-LC-FIPS v4.0 (static): Review" and "(dynamic): Review". The version submitted is 4.0.0, not the 4.2.0 that aws-lc-fips-sys 0.14.3 vendors. | VERIFIED (vendor statement); NIST list SECONDARY | `aws/aws-lc` FIPS.md |
| 4 | #5314 section 11.1: the source is the `AWS-LC-FIPS-3.1.0` archive, sha256 `fe408fa438850786396faf79eba9ea4116c3802e60f3a95865f0dd2adb64c9f1`; "There shall be no additions, deletions, or alterations of this set as used during module build"; build with `cmake3 -DFIPS=1 ..` and `make`; `bssl isfips` must print 1. | VERIFIED | 140sp5314.pdf p. 72 |
| 5 | Running on an environment the certificate does not list is governed by the CMVP Management Manual section 7.9 (vendor and user affirmation). The AWS-LC policies list vendor-affirmed environments as "N/A" and carry the statement that the CMVP makes no statement on correct operation "when so ported". The manual's exact conditions could not be read. | Section SECONDARY; conditions NOT FOUND; policy text VERIFIED | CMVP Management Manual; 140sp5314.pdf |
| 6 | FIPS 186-5, published February 3, 2023: section 1 approves EdDSA; section 7 defines it and refers to SP 800-186 for the curves; sections 7.1 and 7.6 make signatures deterministic; appendix A.2.3 requires an approved DRBG (SP 800-90A) for the private key; section 7.8 covers HashEdDSA, and 7.8.3 notes that hash collisions can forge HashEdDSA signatures but not EdDSA ones. | VERIFIED (mirror whose PDF metadata carries DOI 10.6028/NIST.FIPS.186-5) | NIST.FIPS.186-5.pdf |
| 7 | PKCS#11 v3.0 (15 June 2020) adds CKK_EC_EDWARDS (0x40), CKM_EC_EDWARDS_KEY_PAIR_GEN (0x1055) and CKM_EDDSA (0x1057). | Constants VERIFIED; section numbers SECONDARY | `oasis-tcs/pkcs11` headers |
| 8 | YubiKey PIV Ed25519 needs firmware 5.7.0 or later; ykcs11 signs with CKM_EDDSA from yubico-piv-tool 2.6.0 and lists it in C_GetMechanismList from 2.7.2. The YubiKey 5 FIPS Series (firmware 5.7.4) reportedly holds CMVP #5291; **whether Ed25519 is an approved service on it was not found**. A FIPS token that offers Ed25519 only as a non-approved service does not put the signature inside a validated boundary. | Firmware and ykcs11 VERIFIED; #5291 SECONDARY; approval NOT FOUND | `Yubico/yubico-piv-tool` NEWS and history |
| 9 | TPM 2.0: the TCG reference code first defines TPM_ALG_EDDSA (0x0060) and TPM_ECC_CURVE_25519 (0x0040) in Library specification 1.83 (March 2024), disabled by default. No shipping TPM with EdDSA was found; tpm2-tss and tpm2-tools have no EdDSA support. | Code VERIFIED; shipping chips NOT FOUND | `TrustedComputingGroup/TPM` tag V183 |
| 10 | musl `src/ldso/dlopen.c`: a static program's `dlopen` is a stub that sets "Dynamic loading not supported" and returns 0. | VERIFIED (mirror), and reproduced in 11.2 | musl 1.2.5 source |
| 11 | OpenSSH loads PKCS#11 providers in `ssh-pkcs11-helper`; the commit history gives the reason as "providing better isolation between modules and reliability if a single module misbehaves". | VERIFIED | `openssh/openssh-portable` history |
| 12 | SoftHSM v2 enables CKM_EDDSA by default from 2.6.0 (2020-03-17); the CI token should be 2.6.0 or later. | VERIFIED | `opendnssec/SoftHSMv2` NEWS |

**Consequences for the patch.**

- **Pin.** The development profile pins aws-lc-rs `=1.17.4` and aws-lc-fips-sys `=0.13.17` (the 3.x line, nearest to validated 3.1.0), with rustls-webpki `=0.103.13`. It does not pin the 4.x line, which has no certificate.
- **Update at the Chunk 3 gate (founder decision): rustls-webpki removed.** No source used it yet. Its `aws-lc-rs-fips` feature is written `aws-lc-rs/fips`, and Cargo's `dep/feature` syntax also turns on rustls-webpki's own `aws-lc-rs` feature, which enables aws-lc-rs's `aws-lc-sys` feature. Every build therefore compiled the non-FIPS AWS-LC (`aws-lc-sys` 0.45.0) beside the module, although no symbol from it was linked into the release binary. With rustls-webpki gone, `cargo tree -p sfr` and the release unit graph hold no `aws-lc-sys`, and aws-lc-rs builds with only `alloc` and `fips`. The library for certificate path validation (SPEC B1.3 `--trust-anchor`) is chosen when that feature is built, and must not bring in a second AWS-LC.
- **Validated profile.** This profile builds AWS-LC FIPS 3.1.0 from the archive in fact 4 and links it through aws-lc-fips-sys system-library mode (`AWS_LC_FIPS_SYS_USE_SYSTEM`, `AWS_LC_FIPS_SYS_SYSTEM_DIR`). Item 11.5 records whether that link works.
- **Names in records.** `seal.crypto_module` names the profile, the module version string, and the certificate number or `none`.
- **Hardware paths.** `pkcs11-token` puts the signature inside the token's own boundary only when the token's certificate lists EdDSA as approved. The founder checks this per token before procurement. `tpm-sealed` signs in the AWS-LC module, because no shipping TPM signs Ed25519.

### 11.4 Residual risks the patch does not remove

- **tpm-sealed is hardware-bound, not hardware-resident.** The seed is in `sfr`'s memory for one signature, and a discrete TPM's bus can be sniffed during unseal. Mitigation for Chunk 3: use a salted HMAC session for parameter encryption on `tpm2_unseal`, and zeroize the seed after signing. Use `pkcs11-token` wherever a token can be fitted.
- **Custody is self-declared.** Hardware custody is proven only by the operator's CA issuing certificates to keys it has seen in hardware. Attestation (PIV attestation, TPM2_Certify) is out of scope (SPEC B1.11).
- **A validated module is not a validated product.** The certificate covers the module in the operational environments it lists. A static musl build on an unlisted environment rests on the CMVP's operational-environment porting rules (11.3). The operator's assessor decides whether that applies to their system.
- **The sandbox is not validated.** The wasm32 build uses `crypto-portable`, names it in every record, and exists for evaluation only.


### 11.5 Does aws-lc-rs 1.17.x ship the #5314 module? Measured

**What AWS states (VERIFIED, aws-lc-rs v1.18.0 release notes, 7 Aug 2026):** "The FIPS v3 module shipped in aws-lc-rs v1.17.x is FIPS 140-3 validated (Certificate #5314 static, Certificate #5298 dynamic)." Consumers who need the 3.x module "should pin `aws-lc-rs` to `<1.18.0`".

**What the security policy requires (VERIFIED, #5314 section 11.1):** the complete, unaltered file set of the `AWS-LC-FIPS-3.1.0` archive, built with `-DFIPS=1`, separately per processor and operating system, with `bssl isfips` printing 1 and the version string "AWS-LC FIPS 3.1.0".

**Comparison of `crypto/fipsmodule`, tag `AWS-LC-FIPS-3.1.0` (commit `ae0cd62f`) against the tree aws-lc-fips-sys 0.13.17 vendors:**

| Module code `sfr` uses | Identical to the 3.1.0 tag? |
|---|---|
| `bcm.c` (the module's single compilation unit) | Yes |
| `curve25519/` (Ed25519) | Yes |
| `sha/`, `digest/` (SHA-256) | Yes |
| `rand/` (DRBG, key generation) | Yes |
| `self_check/` (power-on self-tests) | Yes |
| `delocate.h` (integrity check) | Yes |
| `service_indicator/service_indicator.c` | Yes (only its test file differs) |

Five other module source files differ: `cipher/cipher.c`, `cipher/e_aesccm.c`, `dh/dh.c`, `evp/p_hkdf.c` and `evp/p_kem.c`. Across them and two test files, 71 lines are added or removed. The crate also omits the tag's test vectors and policy documents, compiles with a symbol prefix (`BORINGSSL_PREFIX`), and reports library version 3.6.0, not 3.1.0.

**Conclusion.** The code paths `sfr` exercises are byte-identical to the validated module source, and AWS states the 1.17.x module is the #5314 module. Against the letter of section 11.1, though, the crate's file set and build differ. That is why SPEC B1.10 keeps two profiles:

- **Development profile:** aws-lc-rs 1.17.4 with its vendored module. It is the module AWS labels #5314, but the build is not the security policy's exact build.
- **Validated profile:** the 3.1.0 archive built exactly per the security policy and linked through aws-lc-fips-sys system-library mode. It is the only profile that removes the difference, and the build result follows below.

**Validated-profile build: it works, no blocker (VERIFIED, both architectures; key results re-checked independently).**

| Check | x86_64 musl | aarch64 musl |
|---|---|---|
| Source archive sha256 equals the security policy's `fe408fa4...c9f1` | Yes | Yes (same archive) |
| Source tree unchanged after the build (9038 files, manifest diff empty) | Yes | Yes |
| `./tool/bssl isfips` | 1 | 1 (under qemu) |
| `awslc_version_string()` | "AWS-LC FIPS 3.1.0" | "AWS-LC FIPS 3.1.0" |
| Module test suite (`crypto_test`) | 3083 of 3083 passed | not run (qemu time) |
| Probe through aws-lc-rs 1.17.4 system mode: FIPS mode, RFC 8032 TEST 1, tamper rejection, SHA-256, keygen | Pass | Pass (under qemu) |
| "AWS-LC FIPS 3.1.0" in the probe / "3.6.0" / crate-prefixed symbols | 2 / 0 / 0 | 2 / 0 / 0 |
| Module text of the built `bcm.o` present verbatim in the probe, HMAC once | Yes | Yes |
| One flipped module byte | "FIPS integrity test failed", abort (134) | not run |
| `readelf`: NEEDED / INTERP | 0 / 0 (static-pie) | 0 / 0 (static EXEC) |

**Exact validated-profile build (Chunk 5 release job).**

```bash
# 1. Source: the archive named in the #5314 security policy, verified by hash.
#    (Here the URL was proxy-blocked, so the archive was rebuilt from tag AWS-LC-FIPS-3.1.0,
#    commit ae0cd62f, with: TZ=America/Los_Angeles git archive --format=zip
#    --prefix=aws-lc-AWS-LC-FIPS-3.1.0/ AWS-LC-FIPS-3.1.0 ; the sha256 matched exactly.)
echo "fe408fa438850786396faf79eba9ea4116c3802e60f3a95865f0dd2adb64c9f1  AWS-LC-FIPS-3.1.0.zip" | sha256sum -c
unzip -q AWS-LC-FIPS-3.1.0.zip && cd aws-lc-AWS-LC-FIPS-3.1.0 && mkdir build && cd build

# 2. The security policy's build, one per processor: cmake -DFIPS=1 .. && make
#    x86_64 (C++ is needed only for bssl and tests, never for module code):
cmake -DFIPS=1 -DCMAKE_C_COMPILER=musl-gcc -DCMAKE_C_FLAGS="-isystem $KH_X86_64" \
      -DCMAKE_CXX_COMPILER=$ZIGCXX_X86_64 -DCMAKE_CXX_FLAGS=-Wno-error=uninitialized-const-pointer ..
#    aarch64 adds: -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=aarch64
#      -DCMAKE_AR=aarch64-linux-gnu-ar -DCMAKE_RANLIB=aarch64-linux-gnu-ranlib, with the aarch64 musl-gcc
make
./tool/bssl isfips                        # must print 1 (qemu-aarch64-static on aarch64)
cmake --install . --prefix $PREFIX

# 3. Rust bindings: 3.1.0 installs none. Generate them from the installed headers with bindgen
#    =0.72.1 and the crate's own options (Appendix A, bindgen-gen). They match the crate's
#    3.6.0 bindings except three version constants: same 2553 functions, same layouts.
bindgen-gen <aws-lc-fips-sys-0.13.17>/include $PREFIX/include bindings-<target>-3.1.0.rs \
  -nostdinc -isystem <clang resource include> -isystem <musl include> -isystem $KH_<arch>

# 4. Link sfr against the installed module (system-library mode; no vendored build runs).
AWS_LC_FIPS_SYS_SYSTEM_DIR_<target_underscored>=$PREFIX \
AWS_LC_FIPS_SYS_SYSTEM_BINDINGS_<target_underscored>=bindings-<target>-3.1.0.rs \
AWS_LC_FIPS_SYS_STATIC=1 CC_<target_underscored>=<musl-gcc for that target> \
  cargo build -p sfr --release --locked --target <target>
# The build script runs its own FIPS link probe and adds a constructor that aborts if FIPS_mode() is 0.
# aarch64 also needs CFLAGS_<target>="... -static", the linker variable, and a qemu runner for the probe.
```

**Deviations from security policy section 11.1, for the assessor.**
1. Build host: Ubuntu 24.04 with musl, not Amazon Linux 2023 with glibc. Run target: not a tested environment (no vendor-affirmed environments exist).
2. aarch64 was cross-compiled on x86_64 and run under qemu, not built and run on the target processor. For a release, the aarch64 build should run natively on aarch64.
3. Tools: `cmake` 3.28.3 (not `cmake3`), Go 1.24.7, GCC 13.3.0 through `musl-gcc`; kernel UAPI headers through `-isystem` (headers only).
4. C++ for bssl and tests was zig 0.17.0 c++ (Clang 22.1.8). It needed `-Wno-error=uninitialized-const-pointer` for one test file; `bcm.o`, `libcrypto.a`, `libssl.a` and `bssl` were byte-identical with and without the flag.
5. After the policy's steps: `cmake --install`, generated bindings, the crate's runtime FIPS-mode constructor, and rustc's musl C runtime in the final link. No module source or object changes.
6. **Performance consequence:** the policy's literal steps set no build type, so the module compiles without `-O`. Chunk 5 must measure the 2 s and 4 s seal gates with this build; adding a build type would depart from the policy's steps, which is the assessor's call.

**On crates.io**, only aws-lc-fips-sys 0.13.11 vendors 3.1.0, and it is not the policy's file set: `go.mod` altered, 7654 files removed including `tool/`, built with a symbol prefix. aws-lc-rs 1.17.4 requires `^0.13.17` regardless. System-library mode is the only route that meets section 11.1.


## Appendix A. Item 11 test programs

These are the exact sources behind the item 11 evidence, kept here because the scratch environment that ran them is temporary. Each is reproducible with the build commands in 11.1.

<details><summary>FIPS probe (aws-lc-rs fips): power-on self-test, RFC 8032, SHA-256, keygen</summary>

```rust
use aws_lc_rs::digest;
use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    // Power-on self-tests and the module integrity check must pass, or nothing else runs.
    aws_lc_rs::try_fips_mode().expect("module not in FIPS mode");
    // RFC 8032 section 7.1, TEST 1.
    let seed = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let pk = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let kp = Ed25519KeyPair::from_seed_and_public_key(&seed, &pk).expect("key");
    assert_eq!(hex(kp.public_key().as_ref()), hex(&pk));
    let sig = kp.sign(b"");
    assert_eq!(
        hex(sig.as_ref()),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    let vk = UnparsedPublicKey::new(&signature::ED25519, &pk);
    vk.verify(b"", sig.as_ref()).expect("verify");
    let mut bad = sig.as_ref().to_vec();
    bad[0] ^= 1;
    assert!(vk.verify(b"", &bad).is_err(), "tampered signature verified");
    // FIPS 180-4 SHA-256("abc").
    assert_eq!(
        hex(digest::digest(&digest::SHA256, b"abc").as_ref()),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // Key generation through the module's DRBG.
    let generated = Ed25519KeyPair::generate().expect("generate");
    let s2 = generated.sign(b"x");
    UnparsedPublicKey::new(&signature::ED25519, generated.public_key().as_ref())
        .verify(b"x", s2.as_ref())
        .expect("verify generated");
    println!("FIPS mode ok; RFC 8032 TEST 1 ok; tamper rejected; SHA-256 abc ok; keygen ok");
}
```

</details>

<details><summary>PKCS#11 helper prototype (cryptoki 0.12.1, CKM_EDDSA)</summary>

```rust
//! sfr-pkcs11-helper: one Ed25519 signature from a PKCS#11 v3.0 token, then exit.
//!
//! Protocol (SPEC B1.3, hardware key sources). `sfr seal` spawns
//!   sfr-pkcs11-helper sign <RFC 7512 pkcs11: URI>
//! writes the 50-byte signed payload as lowercase hex plus "\n" to stdin, and reads one JSON
//! line from stdout: {"public_key":hex32,"signature":hex64,"token_label":..,"token_serial":..,
//! "token_model":..,"object_label":..}. Any failure: nothing on stdout, a message on stderr,
//! exit 4. sfr verifies the signature with its FIPS module before it writes anything, so this
//! process cannot substitute a signature or a key.
//!
//! The URI query carries `module-path` (required) and `pin-source` (`file:/path` or `env:VAR`).
//! `pin-value` is refused: a PIN in argv is visible to every user through /proc.
#![forbid(unsafe_code)]

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;
use std::io::{BufRead, Write};
use std::process::ExitCode;

const PAYLOAD_LEN: usize = 13 + 1 + 4 + 32; // "SFR-RECORD-V1" || 0x00 || u32 BE || root

struct Uri {
    token: Option<String>,
    serial: Option<String>,
    object: Option<String>,
    id: Option<Vec<u8>>,
    module_path: String,
    pin_source: String,
}

fn pct_decode(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = s.get(i + 1..i + 3).ok_or_else(|| format!("bad percent escape in {s:?}"))?;
            out.push(u8::from_str_radix(h, 16).map_err(|_| format!("bad percent escape in {s:?}"))?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn utf8(v: Vec<u8>, what: &str) -> Result<String, String> {
    String::from_utf8(v).map_err(|_| format!("{what} is not UTF-8"))
}

/// Parses the subset of RFC 7512 this helper uses. Unknown path attributes are refused rather
/// than ignored, so a typo cannot silently select a different key.
fn parse_uri(uri: &str) -> Result<Uri, String> {
    let rest = uri.strip_prefix("pkcs11:").ok_or("key URI must start with pkcs11:")?;
    let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
    let mut u = Uri { token: None, serial: None, object: None, id: None, module_path: String::new(), pin_source: String::new() };
    for attr in path.split(';').filter(|a| !a.is_empty()) {
        let (k, v) = attr.split_once('=').ok_or_else(|| format!("URI attribute without value: {attr}"))?;
        match k {
            "token" => u.token = Some(utf8(pct_decode(v)?, "token")?),
            "serial" => u.serial = Some(utf8(pct_decode(v)?, "serial")?),
            "object" => u.object = Some(utf8(pct_decode(v)?, "object")?),
            "id" => u.id = Some(pct_decode(v)?),
            "type" if v == "private" => {}
            other => return Err(format!("unsupported pkcs11 URI path attribute: {other}")),
        }
    }
    for attr in query.split('&').filter(|a| !a.is_empty()) {
        let (k, v) = attr.split_once('=').ok_or_else(|| format!("URI query attribute without value: {attr}"))?;
        match k {
            "module-path" => u.module_path = utf8(pct_decode(v)?, "module-path")?,
            "pin-source" => u.pin_source = utf8(pct_decode(v)?, "pin-source")?,
            "pin-value" => return Err("pin-value is refused: a PIN on the command line is visible in /proc; use pin-source=file:... or env:...".into()),
            other => return Err(format!("unsupported pkcs11 URI query attribute: {other}")),
        }
    }
    if u.module_path.is_empty() { return Err("pkcs11 URI needs ?module-path=/path/to/vendor-module.so".into()); }
    if u.object.is_none() && u.id.is_none() { return Err("pkcs11 URI needs object= or id= to select exactly one key".into()); }
    Ok(u)
}

fn read_pin(source: &str) -> Result<AuthPin, String> {
    let pin = if let Some(path) = source.strip_prefix("file:") {
        std::fs::read_to_string(path).map_err(|e| format!("{path}: cannot read PIN file: {e}"))?
    } else if let Some(var) = source.strip_prefix("env:") {
        std::env::var(var).map_err(|_| format!("PIN environment variable {var} is not set"))?
    } else {
        return Err("pin-source must be file:/path or env:VAR".into());
    };
    Ok(AuthPin::new(pin.trim_end_matches(['\r', '\n']).into()))
}

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.trim().chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// CKA_EC_POINT for CKK_EC_EDWARDS is a DER OCTET STRING (0x04 0x20 || 32 bytes) in PKCS#11
/// v3.0 tokens; some tokens return the raw 32 bytes. Accept exactly those two encodings.
fn ed25519_point(ec_point: &[u8]) -> Result<[u8; 32], String> {
    let raw = match ec_point {
        [0x04, 0x20, rest @ ..] if rest.len() == 32 => rest,
        raw if raw.len() == 32 => raw,
        _ => return Err(format!("public key CKA_EC_POINT is not an Ed25519 point ({} bytes)", ec_point.len())),
    };
    let mut pk = [0u8; 32];
    pk.copy_from_slice(raw);
    Ok(pk)
}

fn run() -> Result<String, String> {
    let args: Vec<String> = std::env::args().collect();
    let uri = match args.as_slice() {
        [_, cmd, uri] if cmd == "sign" => parse_uri(uri)?,
        _ => return Err("usage: sfr-pkcs11-helper sign '<pkcs11: URI>'  (payload hex on stdin)".into()),
    };
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).map_err(|e| format!("stdin: {e}"))?;
    let payload = unhex(line.trim()).ok_or("stdin is not lowercase hex")?;
    if payload.len() != PAYLOAD_LEN || !payload.starts_with(b"SFR-RECORD-V1\0") {
        return Err(format!("stdin is not an SFR signed payload ({} bytes)", payload.len()));
    }

    let p11 = Pkcs11::new(&uri.module_path).map_err(|e| format!("{}: cannot load PKCS#11 module: {e}", uri.module_path))?;
    p11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).map_err(|e| format!("C_Initialize: {e}"))?;
    let mut chosen = None;
    for slot in p11.get_slots_with_token().map_err(|e| format!("C_GetSlotList: {e}"))? {
        let info = p11.get_token_info(slot).map_err(|e| format!("C_GetTokenInfo: {e}"))?;
        let label_ok = uri.token.as_deref().is_none_or(|t| info.label().trim() == t);
        let serial_ok = uri.serial.as_deref().is_none_or(|s| info.serial_number().trim() == s);
        if label_ok && serial_ok {
            if chosen.is_some() { return Err("pkcs11 URI matches more than one token; add serial=".into()); }
            chosen = Some((slot, info));
        }
    }
    let (slot, info) = chosen.ok_or("no token matches the pkcs11 URI")?;
    let session = p11.open_ro_session(slot).map_err(|e| format!("C_OpenSession: {e}"))?;
    session.login(UserType::User, Some(&read_pin(&uri.pin_source)?)).map_err(|e| format!("C_Login: {e}"))?;

    let mut tmpl = vec![Attribute::KeyType(KeyType::EC_EDWARDS)];
    if let Some(o) = &uri.object { tmpl.push(Attribute::Label(o.as_bytes().to_vec())); }
    if let Some(i) = &uri.id { tmpl.push(Attribute::Id(i.clone())); }
    let find = |class| {
        let mut t = tmpl.clone();
        t.push(Attribute::Class(class));
        session.find_objects(&t).map_err(|e| format!("C_FindObjects: {e}"))
    };
    let privs = find(ObjectClass::PRIVATE_KEY)?;
    let pubs = find(ObjectClass::PUBLIC_KEY)?;
    let (key, pubkey) = match (privs.as_slice(), pubs.as_slice()) {
        ([k], [p]) => (*k, *p),
        (k, p) => return Err(format!("pkcs11 URI must select exactly one Ed25519 key pair; found {} private and {} public objects", k.len(), p.len())),
    };
    let attrs = session.get_attributes(pubkey, &[AttributeType::EcPoint]).map_err(|e| format!("C_GetAttributeValue: {e}"))?;
    let pk = match attrs.as_slice() {
        [Attribute::EcPoint(p)] => ed25519_point(p)?,
        _ => return Err("token returned no CKA_EC_POINT for the public key".into()),
    };
    // PKCS#11 v3.0 CKM_EDDSA with no parameters is pure Ed25519 (RFC 8032), as FIPS 186-5 section 7 approves.
    let sig = session
        .sign(&Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)), key, &payload)
        .map_err(|e| format!("C_Sign (CKM_EDDSA): {e}"))?;
    if sig.len() != 64 { return Err(format!("token returned a {}-byte signature, expected 64", sig.len())); }
    Ok(format!(
        "{{\"public_key\":\"{}\",\"signature\":\"{}\",\"token_label\":{},\"token_serial\":{},\"token_model\":{},\"object_label\":{}}}",
        hex(&pk), hex(&sig), json_str(info.label()), json_str(info.serial_number()), json_str(info.model()),
        json_str(uri.object.as_deref().unwrap_or(""))
    ))
}

fn main() -> ExitCode {
    match run() {
        Ok(json) => {
            let mut out = std::io::stdout().lock();
            match writeln!(out, "{json}") {
                Ok(()) => ExitCode::SUCCESS,
                // A signature that cannot be delivered is a failed seal; sfr sees exit 4 (SPEC B1.4).
                Err(_) => ExitCode::from(4),
            }
        }
        Err(msg) => {
            let mut err = std::io::stderr().lock();
            match writeln!(err, "sfr-pkcs11-helper: {msg}") {
                // Exit 4 either way: the message is best effort, the exit code is the contract.
                Ok(()) | Err(_) => ExitCode::from(4),
            }
        }
    }
}
```

</details>

<details><summary>PKI test (rustls-webpki, aws-lc-rs-fips): chain, EKU, CRL, signature through the certificate key</summary>

```rust
use aws_lc_rs::signature::Ed25519KeyPair;
use pki_types::{CertificateDer, UnixTime};
use webpki::{BorrowedCertRevocationList, CertRevocationList, EndEntityCert, KeyUsage, RevocationOptionsBuilder};

// id-kp-codeSigning, 1.3.6.1.5.5.7.3.3, DER contents without tag and length.
const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

fn read(p: &str) -> Vec<u8> {
    std::fs::read(format!("{}/{p}", std::env::args().nth(1).unwrap())).unwrap()
}

fn check(name: &str, ca: &[u8], crl: &CertRevocationList<'_>) -> Result<(), webpki::Error> {
    let anchor = webpki::anchor_from_trusted_cert(&CertificateDer::from(ca)).unwrap().to_owned();
    let leaf_der = read(&format!("{name}.der"));
    let leaf_c = CertificateDer::from(leaf_der.as_slice());
    let ee = EndEntityCert::try_from(&leaf_c)?;
    let crls = [crl];
    let rev = RevocationOptionsBuilder::new(&crls).unwrap().build();
    ee.verify_for_usage(&[webpki::aws_lc_rs::ED25519], &[anchor], &[], UnixTime::now(),
        KeyUsage::required(CODE_SIGNING), Some(rev), None)?;
    Ok(())
}

fn main() {
    aws_lc_rs::try_fips_mode().expect("FIPS mode");
    let ca = read("ca.der");
    let crl_der = read("ca.crl.der");
    let crl = CertRevocationList::from(BorrowedCertRevocationList::from_der(&crl_der).unwrap());
    println!("signer   (codeSigning, valid): {:?}", check("signer", &ca, &crl));
    println!("wrongeku (serverAuth only):    {:?}", check("wrongeku", &ca, &crl));
    println!("revoked  (on CRL):             {:?}", check("revoked", &ca, &crl));
    // The record signature verifies through the certificate's own key, binding cert and signature.
    let payload = b"SFR-RECORD-V1\0\0\0\0\x01RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR";
    let kp = Ed25519KeyPair::from_seed_unchecked(&read("signer.seed")).unwrap();
    let sig = kp.sign(payload);
    let leaf = read("signer.der");
    let leaf_c = CertificateDer::from(leaf.as_slice());
    let ee = EndEntityCert::try_from(&leaf_c).unwrap();
    println!("signature via signer cert key: {:?}", ee.verify_signature(webpki::aws_lc_rs::ED25519, payload, sig.as_ref()));
    let rk = read("revoked.der");
    let rk_c = CertificateDer::from(rk.as_slice());
    let other = EndEntityCert::try_from(&rk_c).unwrap();
    println!("same signature via other cert:  {:?}", other.verify_signature(webpki::aws_lc_rs::ED25519, payload, sig.as_ref()));
}
```

</details>

<details><summary>Test PKI generation (OpenSSL)</summary>

```ini
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = .
database = $dir/db/index.txt
new_certs_dir = $dir/db
serial = $dir/db/serial
crlnumber = $dir/db/crlnumber
default_md = default
default_days = 365
default_crl_days = 30
policy = policy_any
copy_extensions = none
[ policy_any ]
commonName = supplied
[ v3_ca ]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ v3_signer ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning
authorityKeyIdentifier = keyid
subjectKeyIdentifier = hash
[ v3_wrong_eku ]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
authorityKeyIdentifier = keyid
```

</details>

<details><summary>Test PKI commands</summary>

```bash
openssl genpkey -algorithm ed25519 -out ca.key
openssl req -x509 -new -key ca.key -subj '/CN=Test Flight Records CA' -days 365 -config ca.cnf -extensions v3_ca -out ca.pem
for n in signer wrongeku revoked; do
  openssl genpkey -algorithm ed25519 -out $n.key
  openssl req -new -key $n.key -subj "/CN=sfr-$n" -out $n.csr
  ext=v3_signer; [ $n = wrongeku ] && ext=v3_wrong_eku
  openssl ca -batch -config ca.cnf -cert ca.pem -keyfile ca.key -extensions $ext -in $n.csr -out $n.pem -notext
done
openssl ca -config ca.cnf -cert ca.pem -keyfile ca.key -revoke revoked.pem
openssl ca -config ca.cnf -cert ca.pem -keyfile ca.key -gencrl -out ca.crl.pem
```

</details>

<details><summary>bindgen-gen: unprefixed bindings for a system AWS-LC 3.1.0 install (bindgen =0.72.1)</summary>

```toml
[package]
name = "bindgen-gen"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
bindgen = "=0.72.1"
```

```rust
// Generates unprefixed Rust bindings for a system AWS-LC install, using the same
// bindgen options as aws-lc-fips-sys 0.13.17 builder/sys_bindgen.rs
// (prepare_bindings_builder, all-bindings mode as used by the FIPS crate,
// disable_prelude = true and build_prefix = None as in main.rs generate_bindings).
// Usage: bindgen-gen <rust_wrapper.h dir> <aws-lc include dir> <out.rs> [extra clang args...]
const COPYRIGHT: &str = r"
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC
";
fn main() {
    let a: Vec<String> = std::env::args().collect();
    let (wrapper_dir, inc, out) = (&a[1], &a[2], &a[3]);
    let mut clang_args = vec!["-I".to_string(), wrapper_dir.clone(), "-I".to_string(), inc.clone()];
    clang_args.extend(a[4..].iter().cloned());
    let b = bindgen::Builder::default()
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .allowlist_file(r".*(/|\\)rust_wrapper\.h")
        .rustified_enum(r"point_conversion_form_t")
        .rust_target(bindgen::RustTarget::stable(70, 0).unwrap())
        .default_macro_constant_type(bindgen::MacroTypeVariation::Signed)
        .generate_comments(true)
        .fit_macro_constants(false)
        .size_t_is_usize(true)
        .layout_tests(true)
        .prepend_enum_name(true)
        .formatter(bindgen::Formatter::Rustfmt)
        .clang_args(clang_args)
        .raw_line(COPYRIGHT)
        .header(format!("{wrapper_dir}/rust_wrapper.h"))
        .allowlist_file(r".*(/|\\)openssl((/|\\)[^/\\]+)+\.h");
    b.generate().expect("Unable to generate bindings.").write_to_file(out).expect("write");
}
```

</details>

<details><summary>Module identity check: awslc_version_string() and FIPS_mode()</summary>

```c
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/service_indicator.h>
/* Calls the SP "Show Version" and "Show Status" services. */
int main(void) {
  printf("awslc_version_string: %s\n", awslc_version_string());
  printf("FIPS_mode: %d\n", FIPS_mode());
  return FIPS_mode() ? 0 : 1;
}
```

C++ wrapper used for the non-module C++ (bssl, tests):

```sh
#!/bin/sh
exec /usr/local/lib/python3.13/dist-packages/ziglang/zig c++ -target x86_64-linux-musl "$@"
```

</details>
