//! The signed record (SPEC B1.7): fields, Merkle leaves, signed payload, signature.
//!
//! The record is a JSON object stored as its RFC 8785 canonical bytes. Its leaves, in this
//! fixed order, are: the seal context (`schema_version`, `tool`, `seal`), `log`, `config`,
//! `baseline`, `rules`, each result in rule-id order, each sealed topic digest in topic and
//! instance order, each event in sequence order. Each leaf is hashed with a one-byte tag for
//! its [`Section`], so it belongs to that section and no other. The signed payload is ASCII
//! `SFR-RECORD-V1`, 0x00, `schema_version` as 4-byte big-endian, the tree size and the eight
//! per-section leaf counts ([`TreeShape`]) as 8-byte big-endian, and the Merkle root; the
//! signature is Ed25519 over it.

use crate::crypto::{CrateVersion, CryptoBackend, Signer};
use crate::evaluate::Evaluation;
use crate::ingest::Ingested;
use crate::json::{Obj, Value, canonical};
use crate::keys::{base64_encode, fingerprint};
use crate::merkle;
use crate::params::Baseline;
use crate::record::{
    baseline_json, config_json, events_json, log_json, schema_for, sealed_topics_json,
};
use crate::rules::Rules;
use crate::{SCHEMA_VERSION_5, SIGNED_PAYLOAD_PREFIX, TOOL_NAME, hex};
use std::collections::BTreeMap;
use std::fmt;

/// Top-level fields of a record, in no particular order.
pub const RECORD_FIELDS: [&str; 13] = [
    "schema_version",
    "tool",
    "seal",
    "log",
    "config",
    "baseline",
    "rules",
    "results",
    "sealed_topics",
    "events",
    "status",
    "merkle",
    "signature",
];

/// The tool that sealed a record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tool {
    /// `sfr`.
    pub name: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Git commit of the build, from `SFR_BUILD_COMMIT` at build time, else `unknown`.
    pub build_commit: &'static str,
}

/// This build of the tool.
pub fn this_tool() -> Tool {
    Tool {
        name: TOOL_NAME,
        version: env!("CARGO_PKG_VERSION"),
        build_commit: option_env!("SFR_BUILD_COMMIT").unwrap_or("unknown"),
    }
}

/// Why a record could not be sealed (SPEC B1.4 exit 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealError(pub String);

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SealError {}

/// The section of a record a Merkle leaf belongs to. The tag byte of each is hashed into its
/// leaves (SPEC B1.7), so a leaf moved to another section changes the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// `schema_version`, `tool`, `seal`: tag 0x01, one leaf.
    SealContext,
    /// `log`: tag 0x02, one leaf.
    Log,
    /// `config`: tag 0x03, one leaf.
    Config,
    /// `baseline`: tag 0x04, one leaf.
    Baseline,
    /// `rules`: tag 0x05, one leaf.
    Rules,
    /// `results`: tag 0x06, one leaf per result.
    Result,
    /// `sealed_topics`: tag 0x07, one leaf per sealed topic digest.
    SealedTopic,
    /// `events`: tag 0x08, one leaf per event.
    Event,
}

impl Section {
    /// Every section, in leaf order.
    pub const ALL: [Section; 8] = [
        Section::SealContext,
        Section::Log,
        Section::Config,
        Section::Baseline,
        Section::Rules,
        Section::Result,
        Section::SealedTopic,
        Section::Event,
    ];

    /// The tag byte hashed in front of each leaf of this section.
    pub const fn tag(self) -> u8 {
        match self {
            Section::SealContext => 0x01,
            Section::Log => 0x02,
            Section::Config => 0x03,
            Section::Baseline => 0x04,
            Section::Rules => 0x05,
            Section::Result => 0x06,
            Section::SealedTopic => 0x07,
            Section::Event => 0x08,
        }
    }

    /// The name of the section in `merkle.sections`.
    pub const fn name(self) -> &'static str {
        match self {
            Section::SealContext => "seal_context",
            Section::Log => "log",
            Section::Config => "config",
            Section::Baseline => "baseline",
            Section::Rules => "rules",
            Section::Result => "results",
            Section::SealedTopic => "sealed_topics",
            Section::Event => "events",
        }
    }

    const fn index(self) -> usize {
        self.tag() as usize - 1
    }
}

/// How many leaves each section of a record holds, in [`Section::ALL`] order. The signature
/// covers it (with the total), so a leaf cannot be dropped, added, or moved between sections
/// without the signature failing, whatever the tree hashes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeShape {
    counts: [u64; 8],
}

impl TreeShape {
    /// A shape with the given leaf count for each section.
    pub fn new(counts: [u64; 8]) -> TreeShape {
        TreeShape { counts }
    }

    /// The shape of a record whose three variable sections hold these numbers of leaves: the
    /// five single-leaf sections hold one each.
    pub fn of_counts(results: usize, sealed_topics: usize, events: usize) -> TreeShape {
        TreeShape::new([
            1,
            1,
            1,
            1,
            1,
            results as u64,
            sealed_topics as u64,
            events as u64,
        ])
    }

    /// The number of leaves of a section.
    pub fn count(&self, section: Section) -> u64 {
        self.counts.get(section.index()).copied().unwrap_or(0)
    }

    /// The tree size: the total number of leaves.
    pub fn leaf_count(&self) -> u64 {
        self.counts.iter().sum()
    }

    /// `merkle.sections`: each section's name and leaf count.
    pub fn to_json(&self) -> Value {
        let mut o = Obj::new();
        for s in Section::ALL {
            o = o.field(s.name(), Value::count(self.count(s)));
        }
        o.build()
    }

    /// The bytes of the signed payload after the schema version: the tree size, then each count.
    fn payload_bytes(&self) -> Vec<u8> {
        let mut out = self.leaf_count().to_be_bytes().to_vec();
        for c in self.counts {
            out.extend_from_slice(&c.to_be_bytes());
        }
        out
    }
}

/// What a leaf holds, for naming a mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafKind {
    /// `schema_version`, `tool`, `seal`.
    SealContext,
    /// `log`.
    Log,
    /// `config`.
    Config,
    /// `baseline`.
    Baseline,
    /// `rules`.
    Rules,
    /// A result, with its rule id.
    Result(String),
    /// A sealed topic digest, with its topic and instance.
    SealedTopic(String, i64),
    /// An event, with its sequence number.
    Event(u64),
}

impl LeafKind {
    /// The section this leaf is hashed into.
    pub fn section(&self) -> Section {
        match self {
            LeafKind::SealContext => Section::SealContext,
            LeafKind::Log => Section::Log,
            LeafKind::Config => Section::Config,
            LeafKind::Baseline => Section::Baseline,
            LeafKind::Rules => Section::Rules,
            LeafKind::Result(_) => Section::Result,
            LeafKind::SealedTopic(..) => Section::SealedTopic,
            LeafKind::Event(_) => Section::Event,
        }
    }
}

impl fmt::Display for LeafKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LeafKind::SealContext => f.write_str("seal context"),
            LeafKind::Log => f.write_str("log"),
            LeafKind::Config => f.write_str("config"),
            LeafKind::Baseline => f.write_str("baseline"),
            LeafKind::Rules => f.write_str("rules"),
            LeafKind::Result(id) => write!(f, "result {id}"),
            LeafKind::SealedTopic(t, i) => write!(f, "sealed topic {t} instance {i}"),
            LeafKind::Event(seq) => write!(f, "event seq {seq}"),
        }
    }
}

/// The leaves of a record object, in the fixed order, each with its kind.
pub fn leaves(record: &BTreeMap<String, Value>) -> Result<Vec<(LeafKind, Value)>, String> {
    let get = |k: &str| record.get(k).ok_or_else(|| format!("missing field `{k}`"));
    let context = Obj::new()
        .field("schema_version", get("schema_version")?.clone())
        .field("tool", get("tool")?.clone())
        .field("seal", get("seal")?.clone())
        .build();
    let mut out = vec![
        (LeafKind::SealContext, context),
        (LeafKind::Log, get("log")?.clone()),
        (LeafKind::Config, get("config")?.clone()),
        (LeafKind::Baseline, get("baseline")?.clone()),
        (LeafKind::Rules, get("rules")?.clone()),
    ];
    let Value::Array(results) = get("results")? else {
        return Err("`results` is not an array".into());
    };
    for r in results {
        let id = match r {
            Value::Object(m) => match m.get("id") {
                Some(Value::Str(id)) => id.clone(),
                _ => "?".into(),
            },
            _ => "?".into(),
        };
        out.push((LeafKind::Result(id), r.clone()));
    }
    let Value::Array(sealed) = get("sealed_topics")? else {
        return Err("`sealed_topics` is not an array".into());
    };
    for d in sealed {
        let (topic, instance) = match d {
            Value::Object(m) => (
                match m.get("topic") {
                    Some(Value::Str(t)) => t.clone(),
                    _ => "?".into(),
                },
                match m.get("multi_id") {
                    Some(Value::Int(i)) => *i,
                    _ => -1,
                },
            ),
            _ => ("?".into(), -1),
        };
        out.push((LeafKind::SealedTopic(topic, instance), d.clone()));
    }
    let Value::Array(events) = get("events")? else {
        return Err("`events` is not an array".into());
    };
    for (i, e) in events.iter().enumerate() {
        out.push((LeafKind::Event(i as u64), e.clone()));
    }
    Ok(out)
}

/// The Merkle root over a record's leaves, and the shape of the tree.
pub fn merkle_root(
    crypto: &dyn CryptoBackend,
    record: &BTreeMap<String, Value>,
) -> Result<([u8; 32], TreeShape), String> {
    let leaves = leaves(record)?;
    let mut counts = [0u64; 8];
    let hashes: Vec<[u8; 32]> = leaves
        .iter()
        .map(|(kind, v)| {
            let section = kind.section();
            if let Some(c) = counts.get_mut(section.index()) {
                *c += 1;
            }
            merkle::tagged_leaf_hash(crypto, section.tag(), canonical(v).as_bytes())
        })
        .collect();
    let root = merkle::root(crypto, &hashes).ok_or_else(|| "a record has no leaves".to_string())?;
    Ok((root, TreeShape::new(counts)))
}

/// The bytes the signature covers.
pub fn signed_payload(schema_version: u32, shape: &TreeShape, root: &[u8; 32]) -> Vec<u8> {
    let mut p = SIGNED_PAYLOAD_PREFIX.to_vec();
    p.push(0x00);
    p.extend_from_slice(&schema_version.to_be_bytes());
    p.extend_from_slice(&shape.payload_bytes());
    p.extend_from_slice(root);
    p
}

/// `seal.crypto_crates`: the crates that computed the record, each named by its crate version.
pub fn crates_json(crates: &[CrateVersion]) -> Value {
    Value::Array(
        crates
            .iter()
            .map(|c| {
                Obj::new()
                    .field("name", Value::str(c.name))
                    .field("version", Value::str(c.version))
                    .build()
            })
            .collect(),
    )
}

/// Everything sealed besides the log analysis.
#[derive(Debug, Clone)]
pub struct SealParams {
    /// RFC 3339 UTC time, `YYYY-MM-DDTHH:MM:SSZ` (see [`parse_seal_time`]).
    pub time_utc: String,
    /// The signer's X.509 certificate (DER), given with `seal --cert`; it must hold the
    /// signing key. Recorded as `seal.signer_certificate`, base64.
    pub signer_certificate: Option<Vec<u8>>,
    /// Intermediate CA certificates (DER), given with `seal --chain`, nearest the signer first.
    /// Recorded as `seal.certificate_chain`, each base64; null when empty.
    pub certificate_chain: Vec<Vec<u8>>,
    /// True when the log's PX4 version is one `sfr` is not tested on (or cannot read) and it was
    /// sealed only because of `seal --allow-untested-version`. Recorded as
    /// `seal.allow_untested_version`.
    pub allow_untested_version: bool,
    /// True when the log's ULog file format version is above 1 and it was sealed only because
    /// of `seal --allow-untested-version`. Recorded as `seal.allow_untested_ulog_version`, in
    /// schema 5 only (a schema 4 record has no such log).
    pub allow_untested_ulog_version: bool,
    /// True when the rules file ignores every parameter (`ignore = ["*"]`) and was accepted
    /// only because of `seal --allow-ignore-all`. Recorded as `seal.allow_ignore_all`.
    pub allow_ignore_all: bool,
}

/// What `seal` says about a log whose PX4 version `sfr` is not tested on
/// ([`crate::events::tested_firmware`] false): the refusal without `--allow-untested-version`,
/// and the warning with it.
pub fn untested_version_messages(
    log: &str,
    firmware: &crate::ingest::Firmware,
) -> (String, String) {
    let what = firmware.version.as_deref().map_or_else(
        || "the log does not give a PX4 version sfr can read".to_string(),
        |v| format!("PX4 firmware {v} is outside v1.14 to v1.17"),
    );
    (
        format!(
            "log {log}: {what}, and sfr is tested on PX4 v1.14 to v1.17 only; nothing written. \
             To seal it anyway, add --allow-untested-version: the record and its report will say so, \
             and version-dependent names in its events are left empty"
        ),
        format!(
            "sfr: warning: log {log}: {what}, and sfr is tested on PX4 v1.14 to v1.17 only; \
             sealed under --allow-untested-version, and version-dependent names are null"
        ),
    )
}

/// What `seal` says about a log whose ULog file format version is above 1
/// ([`crate::ingest::LogIdentity::untested_ulog_version`]): the refusal without
/// `--allow-untested-version`, and the warning with it.
pub fn untested_ulog_version_messages(log: &str, version: u8) -> (String, String) {
    let what = format!(
        "ULog file format version {version}, and sfr is tested on versions 0 and 1 only (the ULog \
         specification gives the current file format version as 1)"
    );
    (
        format!(
            "log {log}: {what}; nothing written. To seal it anyway, add --allow-untested-version: \
             the record and its report will say so"
        ),
        format!(
            "sfr: warning: log {log}: {what}; read as version 1 and sealed under \
             --allow-untested-version"
        ),
    )
}

/// A sealed record.
#[derive(Debug, Clone)]
pub struct Sealed {
    /// The canonical bytes to write.
    pub bytes: Vec<u8>,
    /// The Merkle root.
    pub root: [u8; 32],
    /// The signing key fingerprint.
    pub fingerprint: String,
    /// Leaf count.
    pub leaf_count: usize,
}

/// Builds, signs, and self-checks a record. The signature is verified with `crypto` before
/// the bytes are returned (SPEC B1.3: a mismatch writes nothing).
pub fn seal(
    ing: &Ingested,
    eval: &Evaluation,
    rules: &Rules,
    baseline: &Baseline,
    params: &SealParams,
    crypto: &dyn CryptoBackend,
    signer: &dyn Signer,
) -> Result<Sealed, SealError> {
    let public = signer.public_key();
    let fp = fingerprint(crypto, &public);
    let tool = this_tool();
    // A log with an untested ULog file format version is sealed only with the flag, and the
    // record states it (SPEC B1.4).
    if params.allow_untested_ulog_version != ing.identity.untested_ulog_version() {
        return Err(SealError(format!(
            "seal.allow_untested_ulog_version is {} for a log of ULog file format version {}; nothing was written",
            params.allow_untested_ulog_version, ing.identity.ulog_version
        )));
    }
    let schema = schema_for(&ing.identity);
    let mut record = BTreeMap::new();
    record.insert("schema_version".to_string(), Value::Int(i64::from(schema)));
    record.insert(
        "tool".to_string(),
        Obj::new()
            .field("name", Value::str(tool.name))
            .field("version", Value::str(tool.version))
            .field("build_commit", Value::str(tool.build_commit))
            .build(),
    );
    let mut seal_obj = Obj::new();
    if schema == SCHEMA_VERSION_5 {
        seal_obj.set(
            "allow_untested_ulog_version",
            Value::Bool(params.allow_untested_ulog_version),
        );
    }
    record.insert(
        "seal".to_string(),
        seal_obj
            .field("time_utc", Value::str(params.time_utc.clone()))
            .field(
                "allow_untested_version",
                Value::Bool(params.allow_untested_version),
            )
            .field("allow_ignore_all", Value::Bool(params.allow_ignore_all))
            .field("key_fingerprint", Value::str(fp.clone()))
            .field("key_label", Value::str(signer.label()))
            .field("key_custody", Value::str(signer.custody().as_str()))
            .field("crypto_crates", crates_json(crypto.crates()))
            .field(
                "signer_certificate",
                params
                    .signer_certificate
                    .as_ref()
                    .map_or(Value::Null, |der| Value::str(base64_encode(der))),
            )
            .field(
                "certificate_chain",
                if params.certificate_chain.is_empty() {
                    Value::Null
                } else {
                    Value::Array(
                        params
                            .certificate_chain
                            .iter()
                            .map(|der| Value::str(base64_encode(der)))
                            .collect(),
                    )
                },
            )
            .build(),
    );
    record.insert("log".to_string(), log_json(&ing.identity));
    record.insert("config".to_string(), config_json(&ing.config, rules));
    record.insert("baseline".to_string(), baseline_json(baseline, rules));
    record.insert(
        "rules".to_string(),
        Obj::new()
            .field("text", Value::str(rules.text.clone()))
            .field(
                "sha256",
                Value::str(hex(&crypto.sha256(rules.text.as_bytes()))),
            )
            .build(),
    );
    record.insert(
        "results".to_string(),
        Value::Array(eval.results.iter().map(|r| r.to_json()).collect()),
    );
    record.insert("sealed_topics".to_string(), sealed_topics_json(ing));
    record.insert("events".to_string(), events_json(ing, rules));
    record.insert("status".to_string(), Value::str(eval.status.as_str()));

    let (root, shape) = merkle_root(crypto, &record).map_err(SealError)?;
    let payload = signed_payload(schema, &shape, &root);
    let signature = signer
        .sign(&payload)
        .map_err(|e| SealError(format!("signing failed: {e}")))?;
    if !crypto.ed25519_verify(&public, &payload, &signature) {
        return Err(SealError(
            "the signature does not verify against the signing public key; nothing was written"
                .into(),
        ));
    }
    record.insert(
        "merkle".to_string(),
        Obj::new()
            .field("algorithm", Value::str(merkle::ALGORITHM))
            .field("leaf_count", Value::count(shape.leaf_count()))
            .field("root", Value::str(hex(&root)))
            .field("sections", shape.to_json())
            .build(),
    );
    record.insert(
        "signature".to_string(),
        Obj::new()
            .field("algorithm", Value::str("ed25519"))
            .field("value", Value::str(hex(&signature)))
            .build(),
    );
    let bytes = canonical(&Value::Object(record)).into_bytes();
    Ok(Sealed {
        bytes,
        root,
        fingerprint: fp,
        leaf_count: usize::try_from(shape.leaf_count()).unwrap_or(usize::MAX),
    })
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Formats Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn format_utc(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let secs = unix_seconds.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Parses an RFC 3339 time with whole seconds and a `Z` or `+HH:MM` / `-HH:MM` offset, and
/// returns it as UTC `YYYY-MM-DDTHH:MM:SSZ` (the record's form). Years 1970 to 9999.
pub fn parse_seal_time(text: &str) -> Result<String, String> {
    parse_seal_time_seconds(text).map(format_utc)
}

/// The Unix time, in seconds, of an RFC 3339 time [`parse_seal_time`] accepts, such as a
/// record's `seal.time_utc`.
pub fn parse_seal_time_seconds(text: &str) -> Result<i64, String> {
    let bad =
        || format!("`{text}` is not an RFC 3339 time like 2026-10-18T14:00:00Z (whole seconds)");
    let b = text.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Result<i64, String> {
        let s = text.get(r).ok_or_else(bad)?;
        if s.bytes().all(|c| c.is_ascii_digit()) {
            s.parse::<i64>().map_err(|_| bad())
        } else {
            Err(bad())
        }
    };
    if b.len() < 20
        || b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || !matches!(b.get(10), Some(b'T' | b't'))
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
    {
        return Err(bad());
    }
    let (y, mo, d, h, mi, s) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    let offset = match text.get(19..) {
        Some("Z" | "z") => 0,
        Some(o)
            if o.len() == 6
                && matches!(o.as_bytes().first(), Some(b'+' | b'-'))
                && o.as_bytes().get(3) == Some(&b':') =>
        {
            let oh = num(20..22)?;
            let om = num(23..25)?;
            if oh > 23 || om > 59 {
                return Err(bad());
            }
            let sign = if o.starts_with('-') { -1 } else { 1 };
            sign * (oh * 3600 + om * 60)
        }
        _ => return Err(bad()),
    };
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let max_day = usize::try_from(mo - 1)
        .ok()
        .and_then(|i| mdays.get(i))
        .copied()
        .ok_or_else(bad)?;
    if !(1970..=9999).contains(&y) || d < 1 || d > max_day || h > 23 || mi > 59 || s > 59 {
        return Err(bad());
    }
    let unix = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - offset;
    if unix < 0 {
        return Err(bad());
    }
    Ok(unix)
}

/// How far a record's claimed seal time may lie after the verifier's time before `verify`
/// refuses it, in seconds: 5 minutes. Two clocks that both keep good time still differ by a
/// little, and a record sealed a moment ago on another machine must verify here.
pub const SEAL_TIME_SKEW_SECONDS: i64 = 300;

/// Checks a record's claimed seal time (`seal.time_utc`) against the verification time, both in
/// Unix seconds. The seal time is the sealer's own statement and decides nothing else in
/// `verify`; the one thing a verifier can say about it is that it is not in the verifier's
/// future. A claimed time more than [`SEAL_TIME_SKEW_SECONDS`] after `verification_time` is
/// refused. Returns the claimed time in Unix seconds.
pub fn check_seal_time(claimed: &str, verification_time: i64) -> Result<i64, String> {
    let secs = parse_seal_time_seconds(claimed)
        .map_err(|e| format!("seal time claimed by the record: {e}"))?;
    if secs > verification_time.saturating_add(SEAL_TIME_SKEW_SECONDS) {
        return Err(format!(
            "the seal time claimed by the sealer, {claimed}, is later than the verification time \
             {} by more than the {SEAL_TIME_SKEW_SECONDS} s of clock skew allowed; a record cannot \
             have been sealed in the future (--at sets the verification time)",
            format_utc(verification_time)
        ));
    }
    Ok(secs)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::crypto::test_backend::TestBackend;

    #[test]
    fn a_claimed_seal_time_may_not_lie_in_the_verifiers_future() {
        let now = parse_seal_time_seconds("2026-10-19T12:00:00Z").unwrap();
        // The past, now, and up to the skew allowance after now are accepted.
        for ok in [
            "2020-01-01T00:00:00Z",
            "2026-10-19T12:00:00Z",
            "2026-10-19T12:05:00Z",
        ] {
            assert_eq!(
                check_seal_time(ok, now),
                Ok(parse_seal_time_seconds(ok).unwrap()),
                "{ok}"
            );
        }
        // One second past the allowance is refused, and the reason names both times.
        let e = check_seal_time("2026-10-19T12:05:01Z", now).unwrap_err();
        assert!(
            e.contains("2026-10-19T12:05:01Z")
                && e.contains("2026-10-19T12:00:00Z")
                && e.contains("300 s")
                && e.contains("sealed in the future"),
            "{e}"
        );
        assert!(check_seal_time("2035-12-31T00:00:00Z", now).is_err());
        assert!(check_seal_time("not a time", now).is_err());
    }

    #[test]
    fn seal_time_parses_and_normalizes_to_utc() {
        assert_eq!(
            parse_seal_time("2026-10-18T14:00:00Z").unwrap(),
            "2026-10-18T14:00:00Z"
        );
        assert_eq!(
            parse_seal_time("2026-10-18T16:30:00+02:30").unwrap(),
            "2026-10-18T14:00:00Z"
        );
        assert_eq!(
            parse_seal_time("2026-12-31T23:30:00-01:00").unwrap(),
            "2027-01-01T00:30:00Z"
        );
        assert_eq!(
            parse_seal_time("2024-02-29T00:00:00Z").unwrap(),
            "2024-02-29T00:00:00Z"
        );
        for bad in [
            "2026-10-18 14:00:00Z",
            "2026-10-18T14:00:00",
            "2026-10-18T14:00:00.5Z",
            "2025-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "1969-12-31T23:59:59Z",
            "2026-10-18T24:00:00Z",
            "２026-10-18T14:00:00Z",
        ] {
            assert!(parse_seal_time(bad).is_err(), "{bad}");
        }
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(1_792_293_021), "2026-10-18T03:10:21Z");
    }

    #[test]
    fn the_same_bytes_hash_differently_in_every_section() {
        let mut seen = std::collections::BTreeSet::new();
        for section in Section::ALL {
            let h = merkle::tagged_leaf_hash(&TestBackend, section.tag(), b"{\"id\":\"R1\"}");
            assert!(seen.insert(h), "{section:?} hashes like another section");
        }
        assert!(
            !seen.contains(&merkle::leaf_hash(&TestBackend, b"{\"id\":\"R1\"}")),
            "a tagged leaf never hashes like an untagged one"
        );
        let tags: Vec<u8> = Section::ALL.iter().map(|s| s.tag()).collect();
        assert_eq!(tags, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn the_payload_differs_when_only_the_split_between_sections_differs() {
        let a = signed_payload(3, &TreeShape::of_counts(3, 0, 10), &[7; 32]);
        let b = signed_payload(3, &TreeShape::of_counts(2, 1, 10), &[7; 32]);
        assert_eq!(
            TreeShape::of_counts(3, 0, 10).leaf_count(),
            TreeShape::of_counts(2, 1, 10).leaf_count()
        );
        assert_ne!(a, b);
    }

    #[test]
    fn signed_payload_layout() {
        let shape = TreeShape::of_counts(3, 0, 10);
        let p = signed_payload(3, &shape, &[0xab; 32]);
        assert_eq!(&p[..13], b"SFR-RECORD-V1");
        assert_eq!(p[13], 0, "the separator byte");
        assert_eq!(&p[14..18], &[0, 0, 0, 3], "the schema version");
        assert_eq!(&p[18..26], &18u64.to_be_bytes(), "the tree size");
        let counts: Vec<u64> = p[26..90]
            .chunks(8)
            .map(|c| u64::from_be_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(
            counts,
            [1, 1, 1, 1, 1, 3, 0, 10],
            "the eight section counts"
        );
        assert_eq!(&p[90..], &[0xab; 32]);
        assert_eq!(p.len(), 122);
    }
}
