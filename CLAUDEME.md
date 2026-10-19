# CLAUDEME v3.1-sfr: Self-Describing Execution Standard (Rust edition)

```json
{
  "glyph_type": "anchor",
  "id": "claudeme-v3.1-sfr",
  "derived_from": "CLAUDEME v3.1 (AIFlightRecorder/CLAUDEME.md)",
  "governs": "Sealed Flight Record (this repository)",
  "precedence": "docs/SPEC.md is the contract. Where this file and SPEC disagree on anything, SPEC wins.",
  "not_carried_over": "v3.1 section 2 STORE (PostgreSQL, pgvector, RabbitMQ, S3), section 12 (AI Flight Recorder v2.2 runtime patterns) and section 13 (pilot HTTP server rules): this is an offline binary with no storage service, no agent runtime, and no server.",
  "hash": "COMPUTE_ON_READ",
  "verification": "If you can read this, the standard is active."
}
```

> **Read top-to-bottom. Type code. Ship.**
>
> Every statement is a schema, signature, assertion, or gate.
> No prose survives. No exceptions.

---

# §0 LAWS (3)

```rust
const LAW_1: &str = "No receipt -> not real";   // here: no claim without an artifact a script in this repo produced
const LAW_2: &str = "No test -> not shipped";
const LAW_3: &str = "No gate -> not alive";
```

These three statements govern all that follows. In this repository the receipts are the `.sfr` record, the `.sfr.md` report, CI output, and each chunk's gate report.

---

# §1 THE PIPELINE

```
┌────────┐   ┌─────────────────┐   ┌──────────────┐   ┌───────────────────┐   ┌─────────────────┐
│ INPUT  │──▶│ INGEST          │──▶│ EVENTS       │──▶│ RECORD            │──▶│ OUTPUT          │
│ .ulg   │   │ FlightLogIngestor│  │ CONFIG       │   │ JCS (RFC 8785)    │   │ <name>.sfr      │
│ bytes  │   │ dual hash       │   │ RULES R1..R6 │   │ Merkle (SHA-256)  │   │ <name>.sfr.md   │
└────────┘   └─────────────────┘   └──────────────┘   │ Ed25519 signature │   │ exit code 0..4  │
                                                      └───────────────────┘   └─────────────────┘
```

Your code fits ONE place. Know where before you type. `verify` walks the same pipeline backwards and must reproduce every byte.

---

# §2 THE STACK

```rust
// LANGUAGES
// Rust:  everything that ships (sfr-core, sfr, sfr-wasm). #![forbid(unsafe_code)] in every crate.
// Shell: scripts/ (demo, benchmark, README numbers, release, validation).
// JS:    crates/sfr-wasm/js/ (the engine bundle's API module and worker) and site/ (its test
//        harness page). No third-party scripts. No CDN. No analytics.
//        tests/browser/: the headless browser gate for site/ (Playwright, pinned by its
//        package-lock.json). A test tool: never shipped, never served.
// Python: offline tooling only, never in the runtime path, never shipped.

// STORAGE: none. Files on disk. No database, no server, no upload, no fleet store.

// NETWORK: none. No networking or async-runtime crate anywhere in the dependency graph.
//          deny-list.txt + scripts/check_deny_list.sh fail CI if one appears.

// CRYPTO (SPEC B1.7, B1.10). Two v3.1 rules are narrowed by the build plan's decision record:
//   v3.1 "HASH = SHA256 + BLAKE3, ALWAYS dual-hash" now applies to the raw log bytes only;
//   v3.1 "MERKLE = BLAKE3" is replaced by SHA-256 with domain separation, inside the tree and for rules.sha256.
const LOG_DIGEST:  &str = "SHA-256 + BLAKE3 over the raw log bytes";  // dual hash, always both, never one
const MERKLE:      &str = "SHA-256, leaf = H(0x00 || JCS(leaf)), node = H(0x01 || left || right), RFC 6962 odd nodes";
const SIGNATURE:   &str = "Ed25519 over b\"SFR-RECORD-V1\" || 0x00 || schema_version (u32 BE) || merkle_root";
// One crypto stack on every target (SPEC B1.10 Crypto; founder ruling, Change Order 01): the same
// crates and versions, pinned in Cargo.lock, so a record is byte-identical wherever it is sealed.
// BLAKE3 is supplementary, never trust. No CMVP-validated module; none is claimed.
const CRYPTO_CRATES: [&str; 3] = ["sha2", "ed25519-dalek", "blake3"];  // CLI, sandbox, every target
// Keys: pkcs11-token (sfr-pkcs11-helper, separate process), tpm-sealed (tpm2-tools), file-evaluation (demo only).
```

---

# §3 GATES

## Gate 0: pre-commit (every commit)
```bash
scripts/validate.sh   # RUN THIS OR DO NOT COMMIT
```
It runs what CI runs: forbid(unsafe_code) present, rustfmt, clippy with warnings as errors, tests with `--locked`, the deny-list check and its self-test, the language check and its self-test, cargo-deny.

## Gate N: chunk gate (every chunk)
Each chunk in the build plan ends with a gate. The executor reports every gate line as PASS or FAIL with evidence: command output, file path, hash, or CI run link. The next chunk starts only after the founder confirms in writing. Work lands on branch `chunk-N`. The executor never opens a pull request and never merges.

## Gate P: production gates (release)
The table in `docs/SPEC.md` B1.10. All binary. All enforced in CI unless the table marks one founder-run. A missed gate is reported with the number and the cause; the gate is never quietly moved.

---

# §4 THE UNIT PATTERN

> **Pattern:** Every unit = SCHEMA + EMIT + TEST + STOPRULE

```rust
// --- SCHEMA --- a documented type. `missing_docs` is a warning and warnings are errors.
/// One readiness rule result (SPEC B1.7, `results`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuleResult {
    /// Rule id, for example "R3".
    pub id: String,
    /// PASS, FAIL, or N/A.
    pub status: Status,
    /// What the rule expected.
    pub expected: String,
    /// What the log showed.
    pub found: String,
    /// Human-readable detail. Empty when status is PASS.
    pub detail: String,
}

// --- EMIT --- a function that returns Result. The error names the file, topic, field, or parameter.
pub fn evaluate(rule: &Rule, flight: &Flight) -> Result<RuleResult, Error> { /* ... */ }

// --- TEST --- asserts the schema, the pass path, and the failure path.
#[test]
fn r3_names_the_differing_parameter_with_both_values() {
    let r = evaluate(&r3(), &flight_with("MC_ROLL_P", "0.2")).unwrap();
    assert_eq!(r.status, Status::Fail);
    assert!(r.detail.contains("MC_ROLL_P"), "{}", r.detail);
    assert!(r.detail.contains("baseline 0.15") && r.detail.contains("flown 0.2"), "{}", r.detail);
}

// --- STOPRULE --- an error variant, never a panic, never a silent default.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{file}: required topic missing: {topic}")]
    MissingTopic { file: String, topic: String },          // exit 2
    #[error("{file}: malformed at byte {offset}: {reason}")]
    Malformed { file: String, offset: u64, reason: String }, // exit 3
}
```

A failing flight is still sealed. The failure is the evidence. No flag turns FAIL into PASS.

---

# §5 ANTI-PATTERNS (Hard Blocks)

| If you write... | Stop. Write this instead... |
|---|---|
| `unwrap()` or `expect()` on anything derived from input | `?` with a named error variant |
| `let _ = fallible();` or `.ok();` that drops an error | handle it, propagate it, or `match` it with a comment saying why every outcome leads to the same result |
| `panic!`, `unreachable!`, `todo!`, `unimplemented!` in sfr-core, sfr, or sfr-wasm | an error variant; fuzzing must find zero panics, and a panic in the browser build is a trap in the sandbox |
| `unsafe` | nothing; it is forbidden at the crate root |
| `std::net`, tokio, reqwest, any networking or async-runtime crate | nothing; the deny list fails CI |
| `SystemTime::now()` inside sealing with no way to inject the time | take the seal time as an input (`--seal-time`) |
| randomness or `HashMap` iteration order anywhere in sealing, verifying, or report output | `BTreeMap`, sorted, deterministic; the only randomness in the tool is the OS CSPRNG in `sfr keygen` (and the sandbox's ephemeral evaluation key) |
| hashing a JSON value before canonicalizing it | JCS (RFC 8785) first, then hash |
| one hash over the log bytes | SHA-256 and BLAKE3, both, always |
| a second crypto implementation (AWS-LC, ring, OpenSSL), or different crypto on different platforms | `sha2`, `ed25519-dalek`, `blake3` everywhere; `scripts/check_crypto_graph.sh` and `scripts/check_same_records.sh` |
| loading a PKCS#11 module, or any shared library, inside `sfr` | `sfr-pkcs11-helper` in its own process; `sfr` verifies what it returns |
| a seal with a key file and no `--evaluation-only` | refuse with exit 4; file keys are for evaluation only |
| a Merkle hash without the 0x00 or 0x01 prefix | the domain-separated form in SPEC B1.7 |
| a verifier that guesses an unknown `schema_version` | reject it, name the version |
| a flag, option, or environment variable that turns FAIL into PASS | none; the failure is the evidence |
| a rule threshold presented as correct for any aircraft | label it "set by your flight-test lead" |
| a number in a doc that no script in this repo produced | write it between README markers from `scripts/regen_readme_numbers.sh` |
| PX4 topic or field names from memory | `docs/DIAGNOSTIC.md`, confirmed against the golden logs |
| a target company, aircraft, customer name, or internal codename | nothing; keep them in the local, git-ignored `.forbidden-terms` and run `scripts/check_language.sh` |
| a compliance claim, including "FIPS compliant", "FIPS validated", or an IL or NIST SP 800-171 status | a description of what the tool does and does not prove; no FIPS, validated, or compliant claim anywhere (founder ruling, Change Order 01) |
| an em-dash in any doc, page, or script text | a period, comma, or colon |
| `println!` left in for debugging | remove it; CLI output is the results table or `--json` only |
| a third-party action in CI pinned to a tag, a branch, or an annotated tag object | pin to the full commit SHA (`git ls-remote` shows it on the `^{}` line for annotated tags) with the version in a comment |
| a gate that prints WARN or SKIP and exits 0 when its tool is missing | fail; a missing tool is a failed gate (v3.1 section 13.2: hard dependencies fail the build) |
| a dependency added without a `--locked` lockfile update in the same commit | update `Cargo.lock`, run `scripts/validate.sh` |
| a test without `assert` | an assertion against the spec line it proves |

---

# §6 SLO TABLE

| SLO | Threshold (SPEC B1.10) | Test assertion | Stoprule |
|---|---|---|---|
| Seal 100 MB, x86_64 | under 2 s | `assert!(elapsed < 2s)` in `scripts/benchmark.sh` | report the miss and the cause; never move the gate |
| Seal 100 MB, real aarch64 | under 4 s | same, on hardware the founder names | same |
| Standalone verify, 10,000 events | under 10 ms | measured and reported in the chunk gate that delivers `verify` | same |
| Determinism | byte-identical `.sfr` and `.sfr.md` | seal twice, `cmp` | halt; a non-deterministic seal is a bug, not a flake |
| Tamper property | 1,000 flips in `.sfr` and 1,000 in `.ulg` each fail verification | property test, 100 percent | halt |
| Fuzzing | 60 s per CI run, 10 min nightly | zero panics, hangs, out-of-memory | halt |
| Static binaries | `ldd`: not a dynamic executable | release job | halt |

---

# §7 FILE STRUCTURE (SPEC B1.2, plus the files later chunks add)

```
sealed-flight-record/
├── CLAUDEME.md               # this file
├── README.md                 # numbers only between regen markers
├── Cargo.toml                # workspace; fuzz/ excluded
├── Cargo.lock                # committed; every build --locked
├── rust-toolchain.toml       # pinned channel, components, musl and wasm32 targets
├── deny.toml                 # cargo-deny: licenses, advisories, bans, sources
├── deny-list.txt             # networking and async-runtime crates that fail CI
├── .github/workflows/ci.yml  # the CI gates; scripts/validate.sh is their local superset
├── crates/
│   ├── sfr-core/             # engine: ingest, events, rules, record, Merkle, signing, verify
│   ├── sfr/                  # CLI: seal, verify, keygen
│   └── sfr-wasm/             # browser build of the same engine; js/ holds the bundle's API (scripts/build_engine.sh)
├── fuzz/                     # cargo-fuzz targets: ULog parser, .sfr reader
├── site/                     # test harness page for the engine bundle (scripts/build_site.sh); not deployed
├── tests/browser/            # headless browser gate: same records as the CLI; user files never sent
├── scripts/                  # validate, check_deny_list, check_language, run_demo, benchmark, regen_readme_numbers, release
├── testdata/                 # golden logs with license notices; expected/ records
├── examples/                 # added with the rules engine: rules.extended.toml (SPEC B1.6) and the default rules and baseline the demo uses
└── docs/                     # SPEC B1.2 list: SPEC, THREAT_MODEL, RECORD_FORMAT, RULES, INTEGRATION_NOTES, DIAGNOSTIC; plus SANDBOX with the sandbox
```

---

# §8 COMMIT FORMAT

```
<type>(<scope>): <description, 50 characters or fewer>

<optional body: what and why, no how>

Receipt: <artifact this commit produces, or none>
SLO: <gate affected, or none>
Gate: <chunk-N | post>
```

**Types:** `feat` | `fix` | `refactor` | `test` | `docs` | `ci` | `chore`

**Example:**
```
feat(record): domain-separated SHA-256 Merkle tree

Leaf = H(0x00 || JCS(leaf)), node = H(0x01 || l || r), RFC 6962 odd-node rule.

Receipt: .sfr merkle.root
SLO: Deterministic
Gate: chunk-3
```

No model names, session identifiers, or vendor names in commit titles or bodies beyond the attribution trailers the executor's harness requires.

---

# §9 VALIDATION SCRIPT

`scripts/validate.sh` is the pre-commit gate. It must stay a superset of what CI checks, so that a green local run predicts a green CI run.

```bash
#!/usr/bin/env bash
# The real script lives at scripts/validate.sh. This is its contract.
forbid_unsafe_in_every_crate_root
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
scripts/check_deny_list.sh --self-test && scripts/check_deny_list.sh
scripts/check_language.sh --self-test && scripts/check_language.sh
cargo deny --all-features check licenses advisories bans sources
```

Every check script ships with a `--self-test` that runs the real scanning code against a fixture it builds, and proves the check catches what it exists to catch. A check that cannot fail is not a gate. A missing tool fails the gate; it is never a WARN.

---

# §10 EXECUTOR RULES

1. Read `CLAUDEME.md`, then `docs/SPEC.md`, before every chunk. Once `docs/DIAGNOSTIC.md` exists, read it too. The founder's build plan lives outside this repository; each chunk's prompt is pasted at the start of that chunk and defines its task and gate.
2. Commit to branch `chunk-N`. Never open a pull request. Never merge. Stop after the gate report.
3. Every gate line is PASS or FAIL with evidence. A FAIL is reported, never hidden, never reworded.
4. The spec is the contract. The tests are the proof. Code that the spec does not ask for is not written.
5. If a reviewer's claim and a primary source disagree (the package registry, the upstream repository, the PX4 source at the tag in question, a real log), the primary source wins. Verify before adopting.
6. Nothing in this repository names a target company, aircraft, or customer.

---

# §11 REVIEW BUDGET

Independent checks cost time and money; spend them where a mistake would change what a record proves.

| Tier | What | Independent check |
|---|---|---|
| A | the record format, signing, verification, parsing, anything in `sfr-core` | one check on the diff only (`git diff main...HEAD` plus the SPEC sections it touches); one pass; no sub-agent per finding; 15 minutes wall-clock at most |
| B | scripts, CI, docs, `site/`, the wasm glue (`crates/sfr-wasm`) | none: CI plus the executor's own checklist |

1. A finding counts only with a failing test or a concrete input that triggers it. A finding without one is a wording note: all wording notes go into one commit, with no re-review.
2. A fix commit is not re-reviewed: its regression test runs instead. It is checked again only if the fix touches Tier A code.
3. When a class of finding recurs, it becomes a CI check, once, instead of being found again.
4. An independent check runs in parallel with CI, not after it.
5. Each gate report states how long each check took and roughly what it cost, and proposes any further efficiencies in one paragraph.

---

# CHEF'S KISS: This Document IS the Standard

```rust
// This CLAUDEME file is itself compliant:
// - It has a schema (the JSON at the top)
// - It emits a receipt (when you read it, you know the version and what supersedes what)
// - It has tests (scripts/validate.sh and the chunk gates)
// - It has stoprules (the anti-patterns)
// - It ships one chunk at a time, each behind a gate
//
// The record is the receipt. The Merkle root is the state. The signature is the truth.
assert!(understand(CLAUDEME), "Re-read from §0");
```

---

**Derived from:** CLAUDEME v3.1 (sections 0 to 11). Sections 12 and 13 of the source document, and its section 2 storage stack, are not carried over; see `not_carried_over` in the header.
**Version:** 3.1-sfr
**Status:** ACTIVE

*No receipt, not real. No test, not shipped. No gate, not alive.*
