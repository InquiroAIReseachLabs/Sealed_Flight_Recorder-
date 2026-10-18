//! The signed record (SPEC B1.7): fields, Merkle leaves, signed payload, signature.
//!
//! The record is a JSON object stored as its RFC 8785 canonical bytes. Its leaves, in this
//! fixed order, are: the seal context (`schema_version`, `tool`, `seal`), `log`, `config`,
//! `baseline`, `rules`, each result in rule-id order, each sealed topic digest in topic and
//! instance order, each event in sequence order. The signed
//! payload is ASCII `SFR-RECORD-V1`, 0x00, `schema_version` as 4-byte big-endian, and the
//! Merkle root; the signature is Ed25519 over it.

use crate::crypto::{CrateVersion, CryptoBackend, Signer};
use crate::evaluate::{Evaluation, Status};
use crate::ingest::Ingested;
use crate::json::{Obj, Value, canonical};
use crate::keys::fingerprint;
use crate::merkle;
use crate::params::Baseline;
use crate::record::{baseline_json, config_json, events_json, log_json, sealed_topics_json};
use crate::rules::Rules;
use crate::{SCHEMA_VERSION, SIGNED_PAYLOAD_PREFIX, TOOL_NAME, hex};
use std::collections::BTreeMap;
use std::fmt;

/// Top-level fields of a schema 1 record, in no particular order.
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

/// The Merkle root over a record's leaves, and the leaf count.
pub fn merkle_root(
    crypto: &dyn CryptoBackend,
    record: &BTreeMap<String, Value>,
) -> Result<([u8; 32], usize), String> {
    let leaves = leaves(record)?;
    let hashes: Vec<[u8; 32]> = leaves
        .iter()
        .map(|(_, v)| merkle::leaf_hash(crypto, canonical(v).as_bytes()))
        .collect();
    let root = merkle::root(crypto, &hashes).ok_or_else(|| "a record has no leaves".to_string())?;
    Ok((root, hashes.len()))
}

/// The bytes the signature covers.
pub fn signed_payload(schema_version: u32, root: &[u8; 32]) -> Vec<u8> {
    let mut p = SIGNED_PAYLOAD_PREFIX.to_vec();
    p.push(0x00);
    p.extend_from_slice(&schema_version.to_be_bytes());
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
    /// CMVP certificate number of a PKCS#11 token, given with `--token-cert`.
    pub token_cmvp_certificate: Option<String>,
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
    let mut record = BTreeMap::new();
    record.insert(
        "schema_version".to_string(),
        Value::Int(i64::from(SCHEMA_VERSION)),
    );
    record.insert(
        "tool".to_string(),
        Obj::new()
            .field("name", Value::str(tool.name))
            .field("version", Value::str(tool.version))
            .field("build_commit", Value::str(tool.build_commit))
            .build(),
    );
    record.insert(
        "seal".to_string(),
        Obj::new()
            .field("time_utc", Value::str(params.time_utc.clone()))
            .field("key_fingerprint", Value::str(fp.clone()))
            .field("key_label", Value::str(signer.label()))
            .field("key_custody", Value::str(signer.custody().as_str()))
            .field(
                "token_cmvp_certificate",
                Value::opt_str(params.token_cmvp_certificate.clone()),
            )
            .field("crypto_crates", crates_json(crypto.crates()))
            .field("signer_certificate", Value::Null)
            .field("certificate_chain", Value::Null)
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
    let status = if eval.status == Status::Fail {
        "FAIL"
    } else {
        "PASS"
    };
    record.insert("status".to_string(), Value::str(status));

    let (root, leaf_count) = merkle_root(crypto, &record).map_err(SealError)?;
    let payload = signed_payload(SCHEMA_VERSION, &root);
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
            .field("leaf_count", Value::count(leaf_count as u64))
            .field("root", Value::str(hex(&root)))
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
        leaf_count,
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
    Ok(format_utc(unix))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

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
    fn signed_payload_layout() {
        let p = signed_payload(1, &[0xab; 32]);
        assert_eq!(&p[..13], b"SFR-RECORD-V1");
        assert_eq!(&p[13..18], &[0, 0, 0, 0, 1]);
        assert_eq!(&p[18..], &[0xab; 32]);
    }
}
