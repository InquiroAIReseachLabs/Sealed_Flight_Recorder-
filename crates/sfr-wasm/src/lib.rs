//! Browser build of `sfr-core` for the sandbox (SPEC B1.2, `crates/sfr-wasm`).
//!
//! Thin wrapper. [`seal`], [`verify`] (standalone, or with the log) and [`evaluation_key`] take
//! the steps of the `sfr` command line, in its order, with its `sfr-core` calls and its
//! messages, so the sandbox's records and reports are byte-identical to the CLI's for the same
//! inputs (SPEC B1.10 Sandbox) and its output text is the CLI's. `crates/sfr/tests/sandbox.rs`
//! holds the two to that on every golden log. Nothing here performs I/O, reads a clock, or draws
//! randomness: the page passes the files in, and gives the seal time and the seed of the
//! in-browser evaluation key (drawn from the browser's CSPRNG). The `wasm32` bindings the page
//! calls are in `bindings.rs`.
#![forbid(unsafe_code)]

use sfr_core::crypto::rustcrypto::{FileKey, RustCrypto};
use sfr_core::crypto::{CryptoBackend, Custody, Signer};
use sfr_core::evaluate::{Evaluation, Status, evaluate};
use sfr_core::exit_code;
use sfr_core::ingest::{FlightLogIngestor, IngestError, Ingested, Px4Ingestor};
use sfr_core::json;
use sfr_core::keys::{fingerprint, parse_public_key_pem, pem_decode, public_key_pem};
use sfr_core::params::{Baseline, parse_baseline};
use sfr_core::rules::{Compare, Rules, parse_rules};
use sfr_core::seal::{SealParams, parse_seal_time, this_tool};
use sfr_core::verify::{VerifyError, check_record_size};
use std::io::{self, Read};
use std::path::Path;
use zeroize::Zeroizing;

#[cfg(target_arch = "wasm32")]
mod bindings;
pub mod result;

pub use result::{Mismatch, parse_mismatch};

pub use sfr_core::SCHEMA_VERSION;

/// Largest log or record the sandbox reads: 100 MiB (docs/LIMITS.md, "The sandbox's limit").
/// Larger files are refused before they are read; the `sfr` command line has no such limit on
/// the log.
pub const MAX_SANDBOX_FILE_BYTES: u64 = 100 * 1024 * 1024;

/// Largest rules file, baseline, key file or public key: the CLI's limit (SPEC B1.4).
pub const MAX_TEXT_BYTES: u64 = 16 * 1024 * 1024;

/// The first line of every output for a record sealed with an evaluation key (SPEC B1.3).
pub const EVALUATION_LINE: &str = sfr_core::report::EVALUATION_LINE;

/// The `trust` line of a verification against a given public key, as `sfr verify --pubkey`
/// prints it.
pub const TRUST_PUBKEY: &str = sfr_core::verify::TRUST_PUBKEY;

/// `seal.key_label` of a record sealed with the in-browser evaluation key.
pub const SANDBOX_KEY_LABEL: &str = "EVALUATION KEY (sandbox, in-browser)";

/// File name the messages give the baseline the sandbox uses when the page is given none.
pub const NO_BASELINE_NAME: &str = "no-baseline.params";

/// The baseline the sandbox uses when the page is given none: no parameters and firmware
/// `none`, so R2 and R3 fail and name what they found; nothing is assumed. Sealing with this
/// text as the baseline file gives the same record with the CLI.
pub const NO_BASELINE: &str = "# The sandbox was given no baseline file, so R2 and R3 have nothing to compare with.\n# Firmware: none\n";

/// A command that ended with a SPEC B1.4 exit code other than a result, and its message, which
/// is the CLI's (`sfr` prints it after `sfr: `).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// SPEC B1.4 exit code: 3 for an input the engine cannot use, 4 for usage, key and I/O.
    pub code: i32,
    /// What went wrong, naming the file.
    pub message: String,
}

fn fail(code: i32, message: impl Into<String>) -> Failure {
    Failure {
        code,
        message: message.into(),
    }
}

/// A file the page read whole: its name and bytes.
#[derive(Debug, Clone, Copy)]
pub struct Input<'a> {
    /// File name, without a directory (a browser gives no path).
    pub name: &'a str,
    /// The bytes; for a text input, at most one byte more than [`MAX_TEXT_BYTES`] is needed.
    pub bytes: &'a [u8],
}

/// A file the engine reads as a stream: the log.
pub struct Stream<'a> {
    /// File name, without a directory.
    pub name: &'a str,
    /// Size in bytes, as the browser reports it; checked against [`MAX_SANDBOX_FILE_BYTES`]
    /// before any byte is read.
    pub size: u64,
    /// The bytes.
    pub reader: &'a mut dyn Read,
}

/// The key a seal signs with. Both are evaluation keys (custody `file-evaluation`).
#[derive(Debug, Clone, Copy)]
pub enum Key<'a> {
    /// The in-browser evaluation key: the 32-byte Ed25519 seed the page drew from the
    /// browser's CSPRNG for this session.
    Seed(&'a [u8]),
    /// An evaluation key file, as `sfr seal --key <file> --evaluation-only` reads it.
    File(Input<'a>),
}

/// `sfr seal <log> --rules <rules> --baseline <baseline> --key <key> --evaluation-only
/// --seal-time <time>`.
pub struct SealRequest<'a> {
    /// The log.
    pub log: Stream<'a>,
    /// The rules file.
    pub rules: Input<'a>,
    /// The baseline; `None` seals with [`NO_BASELINE`].
    pub baseline: Option<Input<'a>>,
    /// The signing key.
    pub key: Key<'a>,
    /// RFC 3339 seal time; the page gives the current time when the person sets none.
    pub seal_time: &'a str,
    /// `--allow-untested-version`: seal a log whose PX4 version sfr is not tested on, and say so
    /// in the record and report.
    pub allow_untested_version: bool,
}

/// What `sfr seal` writes and prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealOutput {
    /// SPEC B1.4: 0 all rules PASS or N/A, 1 a rule FAIL, 2 a required topic missing. The
    /// record and the report are written in each case.
    pub exit_code: i32,
    /// The record's canonical bytes (`<name>.sfr`).
    pub record: Vec<u8>,
    /// The Markdown report rendered from those bytes (`<name>.sfr.md`).
    pub report: String,
    /// `<log stem>.sfr`.
    pub record_name: String,
    /// `<log stem>.sfr.md`.
    pub report_name: String,
    /// What `sfr seal` prints on standard output, with the file names in place of paths.
    pub text: String,
    /// What `sfr seal` prints on standard error besides a failure: warnings, such as a firmware
    /// sfr is not tested on, sealed under `allow_untested_version`.
    pub notes: Vec<String>,
    /// PASS or FAIL.
    pub status: String,
    /// The Merkle root, lowercase hex.
    pub merkle_root: String,
    /// The number of Merkle leaves.
    pub leaf_count: usize,
    /// The signing key's fingerprint.
    pub key_fingerprint: String,
    /// `file-evaluation`.
    pub key_custody: String,
    /// `seal.key_label`.
    pub key_label: String,
    /// The seal time, UTC, as the record holds it.
    pub sealed_utc: String,
    /// The number of events.
    pub event_count: usize,
    /// Each rule's result, in rule-id order, as the record holds them.
    pub results: Vec<RuleSummary>,
    /// The log's identity.
    pub log: LogSummary,
}

/// One rule's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSummary {
    /// R1 to R7, X1 to X5.
    pub id: String,
    /// Short name.
    pub name: String,
    /// PASS, FAIL or N/A.
    pub status: String,
    /// What the rule expects.
    pub expected: String,
    /// What the log shows.
    pub found: String,
    /// One line per finding.
    pub detail: Vec<String>,
}

/// The log's identity, as the results table prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSummary {
    /// File name.
    pub file_name: String,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256, lowercase hex.
    pub sha256: String,
    /// BLAKE3, lowercase hex (supplementary).
    pub blake3: String,
    /// Firmware version and git hash, or `unknown`.
    pub firmware: String,
}

/// What a successful verification established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSummary {
    /// The signing key's fingerprint.
    pub fingerprint: String,
    /// The crypto crates and their crate versions, as one line.
    pub crypto_crates: String,
    /// The seal time, UTC.
    pub sealed_utc: String,
    /// The sealed overall status.
    pub status: String,
    /// The ids of the rules whose sealed result is FAIL.
    pub failed_rules: Vec<String>,
    /// The number of events.
    pub events: usize,
}

/// `sfr verify <record> --pubkey <pub> [--ulog <log>]`.
pub struct VerifyRequest<'a> {
    /// The record.
    pub record: Input<'a>,
    /// The public key (`sfr.pub`).
    pub public_key: Input<'a>,
    /// The log, for the deep check.
    pub log: Option<Stream<'a>>,
    /// The report (`.sfr.md`), checked against the one the record renders (`sfr verify
    /// --report`).
    pub report: Option<Input<'a>>,
}

/// What `sfr verify` prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutput {
    /// SPEC B1.4: 0 VERIFIED, 1 verification failed.
    pub exit_code: i32,
    /// `Integrity: VERIFIED (record)`, `Integrity: VERIFIED (record and log)`, or
    /// `Integrity: FAILED: <first mismatch>`.
    pub headline: String,
    /// What `sfr verify` prints on standard output, with the file name in place of the path.
    pub text: String,
    /// Whether the log was given (`--ulog`).
    pub deep: bool,
    /// The key custody: the record's when it verified, what it claims when it did not (if it
    /// could be read).
    pub custody: Option<String>,
    /// What the record says, when it verified.
    pub verified: Option<VerifiedSummary>,
    /// Every mismatch, the first first, split into its parts; empty when it verified.
    pub mismatches: Vec<Mismatch>,
}

/// The in-browser evaluation key's public half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluationKey {
    /// `sfr.pub`: PEM `PUBLIC KEY` (RFC 8410), the file `sfr verify --pubkey` reads.
    pub public_key_pem: String,
    /// `sha256:` and the lowercase hex SHA-256 of the SubjectPublicKeyInfo DER.
    pub fingerprint: String,
}

/// The public key and fingerprint of the evaluation key with this 32-byte seed.
pub fn evaluation_key(seed: &[u8]) -> Result<EvaluationKey, Failure> {
    let key = seed_key(seed)?;
    let public = key.public_key();
    Ok(EvaluationKey {
        public_key_pem: public_key_pem(&public),
        fingerprint: fingerprint(&RustCrypto, &public),
    })
}

/// `sfr --version`: the tool, its build, and the crypto crates with their crate versions.
pub fn version_text() -> String {
    let tool = this_tool();
    format!(
        "{} {} (build {})\ncrypto: {}\n",
        tool.name,
        tool.version,
        tool.build_commit,
        crates_line(&RustCrypto)
    )
}

fn seed_key(seed: &[u8]) -> Result<FileKey, Failure> {
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed.try_into().map_err(|_| {
        fail(
            exit_code::USAGE,
            format!(
                "the in-browser evaluation key seed must be 32 bytes, not {}",
                seed.len()
            ),
        )
    })?);
    Ok(FileKey::from_seed(&seed, SANDBOX_KEY_LABEL))
}

/// A UTF-8 text input of at most [`MAX_TEXT_BYTES`]; content errors exit with `code` (3 for
/// rules and baseline, 4 for keys), as the CLI's `read_text`.
fn text<'a>(input: &Input<'a>, what: &str, code: i32) -> Result<&'a str, Failure> {
    if input.bytes.len() as u64 > MAX_TEXT_BYTES {
        return Err(fail(
            code,
            format!(
                "{what} {}: {}",
                input.name,
                sfr_core::limit_exceeded("the file", MAX_TEXT_BYTES, "bytes")
            ),
        ));
    }
    std::str::from_utf8(input.bytes).map_err(|e| {
        fail(
            code,
            format!(
                "{what} {}: not UTF-8 at byte offset {}",
                input.name,
                e.valid_up_to()
            ),
        )
    })
}

/// Refuses a log or record over [`MAX_SANDBOX_FILE_BYTES`] before it is read.
pub fn check_sandbox_size(what: &str, name: &str, size: u64) -> Result<(), Failure> {
    if size > MAX_SANDBOX_FILE_BYTES {
        return Err(fail(
            exit_code::USAGE,
            format!(
                "{what} {name}: {size} bytes is over the sandbox's limit of {MAX_SANDBOX_FILE_BYTES} \
                 bytes (100 MiB) for one file; use the sfr command line, which has no limit on the \
                 log (docs/LIMITS.md)"
            ),
        ));
    }
    Ok(())
}

/// Reads at most [`MAX_SANDBOX_FILE_BYTES`] bytes, so a log whose reported size was too small
/// still stops at the limit.
struct Capped<'a> {
    inner: &'a mut dyn Read,
    left: u64,
}

impl Read for Capped<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            // One byte past the limit tells a longer file from one exactly at it.
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::other(format!(
                    "the file is over the sandbox's limit of {MAX_SANDBOX_FILE_BYTES} bytes \
                     (100 MiB); use the sfr command line (docs/LIMITS.md)"
                ))),
            };
        }
        let want = usize::try_from(self.left).map_or(buf.len(), |l| l.min(buf.len()));
        let chunk = buf
            .get_mut(..want)
            .ok_or_else(|| io::Error::other("read past buffer"))?;
        let n = self.inner.read(chunk)?;
        self.left = self.left.saturating_sub(n as u64);
        Ok(n)
    }
}

/// The CLI's `file_name`: the last component of a path, else the text itself.
fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map_or_else(|| path.to_string(), |n| n.to_string_lossy().into_owned())
}

/// The crypto crates and their crate versions, as `seal.crypto_crates` names them.
fn crates_line(crypto: &dyn CryptoBackend) -> String {
    let names: Vec<String> = crypto
        .crates()
        .iter()
        .map(|c| format!("{} {}", c.name, c.version))
        .collect();
    format!("{} (crate versions)", names.join(", "))
}

/// The transition tuning section, as `sfr seal` prints it (SPEC B1.8): the VTOL type and each
/// watched parameter with its baseline and flown values. Empty for a vehicle that is not VTOL.
fn transition_tuning(ing: &Ingested, rules: &Rules, baseline: &Baseline) -> String {
    let Some(vtol) = &ing.identity.vehicle.vtol_type else {
        return String::new();
    };
    let mut out = format!("transition tuning (VTOL type {})\n", vtol.name);
    if rules.watched.is_empty() {
        out.push_str("  no [watched_parameters] in the rules file\n");
        return out;
    }
    let show =
        |v: Option<&sfr_core::ulog::ParamValue>| v.map_or("absent".to_string(), |v| v.to_string());
    out.push_str(&format!(
        "  {:<18}{:<16}{:<16}{}\n",
        "PARAMETER", "BASELINE", "FLOWN", "R3"
    ));
    for name in &rules.watched {
        let b = baseline.params.get(name);
        let l = ing.config.params.get(name);
        // As R3 and the report (sfr_core::report::watched_mark): R3 compares a parameter only
        // when the baseline has it, or with compare = "all" when the log has it.
        let mark = match (b, l) {
            (None, None) => "not compared",
            (None, _) if rules.compare == Compare::Baseline => "not compared",
            (Some(b), Some(l)) if b.same_as(l) => "MATCH",
            _ => "DIFF",
        };
        out.push_str(&format!(
            "  {name:<18}{:<16}{:<16}{mark}\n",
            show(b),
            show(l)
        ));
    }
    out
}

/// The results table `sfr seal` prints.
/// The firmware as the results table prints it.
fn firmware_text(ing: &Ingested) -> String {
    let fw = &ing.identity.firmware;
    match (&fw.version, &fw.git) {
        (Some(v), Some(g)) => format!("{v} ({g})"),
        (Some(v), None) => v.clone(),
        (None, Some(g)) => format!("unknown version ({g})"),
        (None, None) => "unknown".into(),
    }
}

fn table(ing: &Ingested, eval: &Evaluation, rules: &Rules, baseline: &Baseline) -> String {
    let id = &ing.identity;
    let mut out = String::new();
    let firmware = firmware_text(ing);
    for (k, v) in [
        ("log", format!("{} ({} bytes)", id.file_name, id.size)),
        ("sha256", sfr_core::hex(&id.sha256)),
        ("blake3", sfr_core::hex(&id.blake3)),
        ("firmware", firmware),
        ("crypto", crates_line(&RustCrypto)),
    ] {
        out.push_str(&format!("{k:<10}{v}\n"));
    }
    out.push('\n');
    out.push_str(&format!(
        "{:<6}{:<8}{:<30}{}\n",
        "RULE", "STATUS", "NAME", "FOUND"
    ));
    for r in &eval.results {
        out.push_str(&format!(
            "{:<6}{:<8}{:<30}{}\n",
            r.id,
            r.status.as_str(),
            r.name,
            r.found
        ));
        if r.status == Status::Fail {
            for d in &r.detail {
                out.push_str(&format!("{:<14}- {d}\n", ""));
            }
        }
    }
    let tuning = transition_tuning(ing, rules, baseline);
    if !tuning.is_empty() {
        out.push('\n');
        out.push_str(&tuning);
    }
    out.push('\n');
    out.push_str(&format!("{:<10}{}\n", "events", ing.events.len()));
    out.push_str(&format!("{:<10}{}\n", "status", eval.status.as_str()));
    out
}

/// Seals a log as `sfr seal` does with an evaluation key: the same checks in the same order,
/// the same record and report bytes, the same messages and exit codes.
pub fn seal(req: SealRequest<'_>) -> Result<SealOutput, Failure> {
    let crypto = RustCrypto;
    // The key source is checked before any work, so a usage error costs nothing.
    let key = match req.key {
        Key::Seed(seed) => seed_key(seed)?,
        Key::File(input) => {
            let pem = Zeroizing::new(text(&input, "key file", exit_code::USAGE)?.to_string());
            let der =
                Zeroizing::new(pem_decode(&pem, "PRIVATE KEY").map_err(|e| {
                    fail(exit_code::USAGE, format!("key file {}: {e}", input.name))
                })?);
            FileKey::from_pkcs8_der(&der, &file_name(input.name))
                .map_err(|e| fail(exit_code::USAGE, format!("key file {}: {e}", input.name)))?
        }
    };
    let time_utc = parse_seal_time(req.seal_time).map_err(|e| fail(exit_code::USAGE, e))?;
    let log = req.log.name;
    let stem = Path::new(log).file_stem().map_or_else(
        || "record".to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
    let record_name = format!("{stem}.sfr");
    let report_name = format!("{stem}.{}", sfr_core::report::REPORT_EXTENSION);

    let rules_text = text(&req.rules, "rules file", exit_code::MALFORMED_INPUT)?;
    let rules: Rules = parse_rules(rules_text).map_err(|e| {
        let code = if e.usage {
            exit_code::USAGE
        } else {
            exit_code::MALFORMED_INPUT
        };
        fail(code, format!("rules file {}: {e}", req.rules.name))
    })?;
    let baseline_input = req.baseline.unwrap_or(Input {
        name: NO_BASELINE_NAME,
        bytes: NO_BASELINE.as_bytes(),
    });
    let baseline_text = text(&baseline_input, "baseline", exit_code::MALFORMED_INPUT)?;
    let baseline: Baseline = parse_baseline(baseline_text).map_err(|e| {
        fail(
            exit_code::MALFORMED_INPUT,
            format!("baseline {}: {e}", baseline_input.name),
        )
    })?;
    check_sandbox_size("log", log, req.log.size)?;
    let mut capped = Capped {
        inner: req.log.reader,
        left: MAX_SANDBOX_FILE_BYTES,
    };
    let ing = Px4Ingestor
        .ingest_sealing(&file_name(log), &mut capped, &crypto, &rules.sealed_topics)
        .map_err(|e| match e {
            IngestError::Malformed(m) => {
                fail(exit_code::MALFORMED_INPUT, format!("log {log}: {m}"))
            }
            IngestError::Io(m) => fail(exit_code::USAGE, format!("log {log}: {m}")),
            limit @ IngestError::Limit(_) => {
                fail(exit_code::MALFORMED_INPUT, format!("log {log}: {limit}"))
            }
        })?;
    let eval = evaluate(&ing, &rules, &baseline);
    let mut notes = Vec::new();
    if !sfr_core::events::tested_firmware(&ing.identity.firmware) {
        let (refusal, warning) =
            sfr_core::seal::untested_version_messages(log, &ing.identity.firmware);
        if !req.allow_untested_version {
            return Err(fail(exit_code::USAGE, refusal));
        }
        notes.push(warning);
    }

    let params = SealParams {
        time_utc,
        signer_certificate: None,
        certificate_chain: Vec::new(),
        allow_untested_version: req.allow_untested_version
            && !sfr_core::events::tested_firmware(&ing.identity.firmware),
    };
    let sealed = sfr_core::seal::seal(&ing, &eval, &rules, &baseline, &params, &crypto, &key)
        .map_err(|e| fail(exit_code::USAGE, e.to_string()))?;
    // A record verify would refuse is never written (SPEC B1.4 input limits).
    check_record_size(sealed.bytes.len()).map_err(|e| {
        fail(
            exit_code::MALFORMED_INPUT,
            format!("log {log}: the record it gives is refused: {e}"),
        )
    })?;
    // The report comes from the record alone (SPEC B1.8): the bytes just sealed, parsed back.
    let report = json::parse(&sealed.bytes)
        .map_err(|e| e.to_string())
        .and_then(|v| sfr_core::report::render(&v).map_err(|e| e.to_string()))
        .map_err(|e| fail(exit_code::USAGE, format!("cannot write the report: {e}")))?;
    let custody = key.custody();
    let mut t = String::new();
    if custody == Custody::FileEvaluation {
        t.push_str(EVALUATION_LINE);
        t.push('\n');
    }
    t.push_str(&table(&ing, &eval, &rules, &baseline));
    t.push_str(&format!(
        "\n{:<10}{}\n{:<10}{}\n{:<10}{}\n{:<10}{} ({})\n{:<10}{}\n",
        "record",
        record_name,
        "report",
        report_name,
        "merkle",
        sfr_core::hex(&sealed.root),
        "key",
        sealed.fingerprint,
        custody.as_str(),
        "sealed",
        params.time_utc
    ));
    let id = &ing.identity;
    Ok(SealOutput {
        exit_code: eval.exit_code,
        report,
        record_name,
        report_name,
        text: t,
        notes,
        status: eval.status.as_str().to_string(),
        merkle_root: sfr_core::hex(&sealed.root),
        leaf_count: sealed.leaf_count,
        key_fingerprint: sealed.fingerprint.clone(),
        key_custody: custody.as_str().to_string(),
        key_label: key.label(),
        sealed_utc: params.time_utc.clone(),
        event_count: ing.events.len(),
        results: eval
            .results
            .iter()
            .map(|r| RuleSummary {
                id: r.id.to_string(),
                name: r.name.to_string(),
                status: r.status.as_str().to_string(),
                expected: r.expected.clone(),
                found: r.found.clone(),
                detail: r.detail.clone(),
            })
            .collect(),
        log: LogSummary {
            file_name: id.file_name.clone(),
            size: id.size,
            sha256: sfr_core::hex(&id.sha256),
            blake3: sfr_core::hex(&id.blake3),
            firmware: firmware_text(&ing),
        },
        record: sealed.bytes,
    })
}

/// Verifies a record as `sfr verify --pubkey` does, standalone or, with the log, deep.
pub fn verify(req: VerifyRequest<'_>) -> Result<VerifyOutput, Failure> {
    let crypto = RustCrypto;
    let public = parse_public_key_pem(text(&req.public_key, "public key", exit_code::USAGE)?)
        .map_err(|e| {
            fail(
                exit_code::USAGE,
                format!("public key {}: {e}", req.public_key.name),
            )
        })?;
    let record_path = req.record.name;
    check_sandbox_size("record", record_path, req.record.bytes.len() as u64)?;
    let mut capped = None;
    if let Some(log) = req.log {
        check_sandbox_size("log", log.name, log.size)?;
        capped = Some(Capped {
            inner: log.reader,
            left: MAX_SANDBOX_FILE_BYTES,
        });
    }
    let deep = capped.is_some();
    let log: Option<&mut dyn Read> = capped.as_mut().map(|c| c as &mut dyn Read);
    let outcome = sfr_core::verify::verify(req.record.bytes, log, &crypto, &public);
    // A record that verified must also match its report, when one is given (as the CLI does).
    let outcome = match (outcome, &req.report) {
        (Ok(v), Some(report)) => match sfr_core::report::check(req.record.bytes, report.bytes) {
            Ok(()) => Ok((v, Some(report.name))),
            Err(e) => Err(VerifyError::Mismatch(sfr_core::verify::Mismatch {
                first: format!("report {}: {e}", report.name),
                also: Vec::new(),
                custody: Some(v.custody),
            })),
        },
        (Ok(v), None) => Ok((v, None)),
        (Err(e), _) => Err(e),
    };
    match outcome {
        Err(VerifyError::Io(e)) => Err(fail(exit_code::USAGE, format!("log: {e}"))),
        Ok((v, report)) => {
            let headline = sfr_core::verify::integrity_line(&v);
            let mut t = String::new();
            if v.custody == Custody::FileEvaluation {
                t.push_str(EVALUATION_LINE);
                t.push('\n');
            }
            t.push_str(&sfr_core::verify::verified_text(
                record_path,
                &v,
                TRUST_PUBKEY,
                // The page cannot check a certificate chain, so no custody is attested here.
                &sfr_core::verify::custody_text(
                    v.custody.as_str(),
                    &sfr_core::verify::Attestation::Unattested,
                ),
                &sfr_core::verify::report_line(report),
            ));
            Ok(VerifyOutput {
                exit_code: exit_code::OK,
                headline,
                text: t,
                deep,
                custody: Some(v.custody.as_str().to_string()),
                verified: Some(VerifiedSummary {
                    fingerprint: v.fingerprint,
                    crypto_crates: v.crypto_crates,
                    sealed_utc: v.time_utc,
                    status: v.status,
                    failed_rules: v.failed_rules,
                    events: v.events,
                }),
                mismatches: Vec::new(),
            })
        }
        Err(VerifyError::Mismatch(m)) => {
            // SPEC B1.3: a record sealed with an evaluation key says so first, verified or not
            // (the custody of a record that fails is only what it claims).
            let headline = sfr_core::verify::failed_line(&m);
            let mut t = String::new();
            if m.custody == Some(Custody::FileEvaluation) {
                t.push_str(EVALUATION_LINE);
                t.push('\n');
            }
            t.push_str(&sfr_core::verify::failed_text(
                &m,
                sfr_core::verify::claimed_seal(req.record.bytes).as_ref(),
            ));
            Ok(VerifyOutput {
                exit_code: exit_code::RULE_FAIL,
                headline,
                text: t,
                deep,
                custody: m.custody.map(|c| c.as_str().to_string()),
                verified: None,
                mismatches: std::iter::once(&m.first)
                    .chain(&m.also)
                    .map(|t| parse_mismatch(t))
                    .collect(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    // A panicking test is a failing test, so tests may use expect and unwrap.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
    use super::*;

    #[test]
    fn re_exports_the_engine_schema_version() {
        assert_eq!(super::SCHEMA_VERSION, sfr_core::SCHEMA_VERSION);
    }

    #[test]
    fn the_no_baseline_text_parses_and_names_no_firmware_and_no_parameter() {
        let b = parse_baseline(NO_BASELINE).unwrap();
        assert_eq!(b.firmware.version, "none");
        assert!(b.params.is_empty());
    }

    #[test]
    fn the_evaluation_key_needs_a_32_byte_seed_and_names_its_fingerprint() {
        let k = evaluation_key(&[7u8; 32]).unwrap();
        assert!(k.public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(k.fingerprint.starts_with("sha256:") && k.fingerprint.len() == 71);
        let e = evaluation_key(&[7u8; 31]).unwrap_err();
        assert_eq!(e.code, exit_code::USAGE);
        assert!(e.message.contains("32 bytes, not 31"), "{}", e.message);
    }

    #[test]
    fn a_log_over_the_sandbox_limit_is_refused_by_size_and_by_length() {
        let rules = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/rules.default.toml"
        ))
        .unwrap();
        let seed = [1u8; 32];
        let request = |size: u64, reader: &mut dyn Read| {
            seal(SealRequest {
                log: Stream {
                    name: "big.ulg",
                    size,
                    reader,
                },
                rules: Input {
                    name: "rules.default.toml",
                    bytes: &rules,
                },
                baseline: None,
                key: Key::Seed(&seed),
                seal_time: "2026-10-18T15:00:00Z",
                allow_untested_version: false,
            })
        };
        // The size the browser reports: refused before a byte is read.
        let e = request(MAX_SANDBOX_FILE_BYTES + 1, &mut io::empty()).unwrap_err();
        assert_eq!(e.code, exit_code::USAGE);
        assert!(
            e.message.starts_with("log big.ulg: 104857601 bytes is over the sandbox's limit of 104857600 bytes (100 MiB)"),
            "{}",
            e.message
        );
        // A reported size that is too small: the reader stops one byte past the limit, and a
        // file exactly at the limit is read whole.
        let read_all = |len: u64| {
            let mut source = io::repeat(0).take(len);
            let mut capped = Capped {
                inner: &mut source,
                left: MAX_SANDBOX_FILE_BYTES,
            };
            io::copy(&mut capped, &mut io::sink())
        };
        let e = read_all(MAX_SANDBOX_FILE_BYTES + 1).unwrap_err();
        assert!(
            e.to_string()
                .contains("over the sandbox's limit of 104857600 bytes"),
            "{e}"
        );
        assert_eq!(
            read_all(MAX_SANDBOX_FILE_BYTES).unwrap(),
            MAX_SANDBOX_FILE_BYTES
        );
    }

    #[test]
    fn text_inputs_keep_the_cli_limit_and_messages() {
        let big = vec![b'#'; MAX_TEXT_BYTES as usize + 1];
        let e = text(
            &Input {
                name: "r.toml",
                bytes: &big,
            },
            "rules file",
            3,
        )
        .unwrap_err();
        assert_eq!(
            e.message,
            "rules file r.toml: the file exceeds the input limit of 16777216 bytes (SPEC B1.4)"
        );
        let e = text(
            &Input {
                name: "b.params",
                bytes: b"ok\xff",
            },
            "baseline",
            3,
        )
        .unwrap_err();
        assert_eq!(e.message, "baseline b.params: not UTF-8 at byte offset 2");
    }
}
