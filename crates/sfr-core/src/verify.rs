//! Record verification (SPEC B1.3 `verify`, B1.7).
//!
//! **Standalone:** the bytes must parse, carry a known `schema_version`, be exactly their own
//! canonical form, hold exactly the schema 1 fields, and their recomputed Merkle root, rules
//! digest, overall status, key fingerprint and Ed25519 signature must all check.
//! **Deep (with the log):** the log is re-read and re-analysed with the embedded rules and
//! baseline; configuration, events, and results must be identical to the sealed ones, and the
//! log digest must match. The first mismatch is named as precisely as the evidence allows: a
//! parameter with its sealed and found values, an event sequence number and field, a result
//! and field, or "log digest mismatch".

use crate::SCHEMA_VERSION;
use crate::crypto::{CryptoBackend, Custody, Sha256Stream};
use crate::evaluate::evaluate;
use crate::hex;
use crate::ingest::{FlightLogIngestor, IngestError, Px4Ingestor};
use crate::json::{Value, canonical, first_non_canonical_offset, parse, scan_canonical};
use crate::keys::{fingerprint, hex_decode};
use crate::merkle;
use crate::params::{Baseline, FirmwareSpec};
use crate::record::{config_json, events_json, log_json, sealed_topics_json};
use crate::rules::parse_rules;
use crate::seal::{RECORD_FIELDS, signed_payload};
use crate::ulog::ParamValue;
use std::collections::BTreeMap;
use std::io::{self, Read};

/// Largest record `verify` reads (a record of 1,000,000 events is about 250 MB).
pub const MAX_RECORD_BYTES: usize = 512 * 1024 * 1024;

/// What a successful verification established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// Declared key custody.
    pub custody: Custody,
    /// Key fingerprint.
    pub fingerprint: String,
    /// Seal time, UTC.
    pub time_utc: String,
    /// `seal.crypto_crates` as one line: each crate name and its crate version.
    pub crypto_crates: String,
    /// Sealed overall status.
    pub status: String,
    /// Number of events.
    pub events: usize,
    /// Number of Merkle leaves.
    pub leaf_count: usize,
    /// Whether the log was re-checked.
    pub deep: bool,
}

/// Why verification failed: the first mismatch, then any others found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// The first mismatch, named as precisely as possible.
    pub first: String,
    /// Further mismatches.
    pub also: Vec<String>,
    /// The key custody the record declares, when it could be read. The record did not
    /// verify, so this is only what it claims; `verify` still warns on an evaluation key.
    pub custody: Option<Custody>,
}

/// A verification outcome other than success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The record or log does not verify (SPEC B1.4 exit 1).
    Mismatch(Mismatch),
    /// The log could not be read (SPEC B1.4 exit 4).
    Io(String),
}

/// Refuses a record longer than [`MAX_RECORD_BYTES`]. `seal` applies the same check before it
/// writes, so it never writes a record that `verify` would refuse.
pub fn check_record_size(len: usize) -> Result<(), String> {
    if len > MAX_RECORD_BYTES {
        Err(crate::limit_exceeded(
            "the record",
            MAX_RECORD_BYTES,
            "bytes",
        ))
    } else {
        Ok(())
    }
}

/// The sort key of a rule id: its letter, then its number (`R2` < `R10` < `X1`).
fn rule_id_key(id: &str) -> Option<(char, u32)> {
    let mut chars = id.chars();
    let letter = chars.next().filter(char::is_ascii_uppercase)?;
    let digits = chars.as_str();
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.starts_with('0') {
        return None;
    }
    digits.parse().ok().map(|n| (letter, n))
}

fn fail(first: impl Into<String>) -> Mismatch {
    Mismatch {
        first: first.into(),
        also: Vec::new(),
        custody: None,
    }
}

type Map = BTreeMap<String, Value>;

fn obj<'a>(m: &'a Map, k: &str) -> Result<&'a Map, Mismatch> {
    match m.get(k) {
        Some(Value::Object(o)) => Ok(o),
        _ => Err(fail(format!("field `{k}` is missing or not an object"))),
    }
}

fn string<'a>(m: &'a Map, k: &str) -> Result<&'a str, Mismatch> {
    match m.get(k) {
        Some(Value::Str(s)) => Ok(s),
        _ => Err(fail(format!("field `{k}` is missing or not a string"))),
    }
}

fn array<'a>(m: &'a Map, k: &str) -> Result<&'a [Value], Mismatch> {
    match m.get(k) {
        Some(Value::Array(a)) => Ok(a),
        _ => Err(fail(format!("field `{k}` is missing or not an array"))),
    }
}

/// A parsed record whose structure is sound enough to compare against a log.
struct Parsed {
    /// Standalone failures that do not prevent a deep comparison (Merkle root, signature...).
    problems: Vec<String>,
    verified: Verified,
}

/// Parses one member's bytes (small members only; events are never parsed standalone).
fn member(bytes: &[u8], span: &std::ops::Range<usize>) -> Result<Value, Mismatch> {
    parse(bytes.get(span.clone()).unwrap_or(b""))
        .map_err(|e| fail(format!("record is not valid JSON at {e}")))
}

fn standalone(
    bytes: &[u8],
    crypto: &dyn CryptoBackend,
    public_key: &[u8; 32],
    require_hardware_key: bool,
) -> Result<Parsed, Mismatch> {
    check_record_size(bytes.len()).map_err(fail)?;
    let spans = match scan_canonical(bytes) {
        Ok(spans) => spans,
        Err(scan_error) => {
            // SPEC B1.7: an unknown schema_version is reported as such, never guessed at, even
            // when its record is not in this version's canonical form.
            if let Ok(Value::Object(m)) = parse(bytes) {
                match m.get("schema_version") {
                    Some(Value::Int(v)) if *v == i64::from(SCHEMA_VERSION) => {}
                    Some(other) => {
                        return Err(fail(format!(
                            "unknown schema_version {}; this verifier knows only {SCHEMA_VERSION}",
                            canonical(other)
                        )));
                    }
                    None => return Err(fail("record has no schema_version")),
                }
                let at = parse(bytes)
                    .ok()
                    .and_then(|v| first_non_canonical_offset(bytes, &v))
                    .unwrap_or(scan_error.offset);
                return Err(fail(format!(
                    "record is not in canonical form (RFC 8785); first difference at byte offset {at}"
                )));
            }
            return Err(fail(format!("record is not valid JSON at {scan_error}")));
        }
    };
    let find = |k: &str| spans.iter().find(|m| m.key == k);
    match find("schema_version")
        .map(|m| member(bytes, &m.value))
        .transpose()?
    {
        Some(Value::Int(v)) if v == i64::from(SCHEMA_VERSION) => {}
        Some(other) => {
            return Err(fail(format!(
                "unknown schema_version {}; this verifier knows only {SCHEMA_VERSION}",
                canonical(&other)
            )));
        }
        None => return Err(fail("record has no schema_version")),
    }
    for m in &spans {
        if !RECORD_FIELDS.contains(&m.key.as_str()) {
            return Err(fail(format!("unknown field `{}`", m.key)));
        }
    }
    for k in RECORD_FIELDS {
        if find(k).is_none() {
            return Err(fail(format!("missing field `{k}`")));
        }
    }
    let span = |k: &str| find(k).map(|m| m.value.clone()).unwrap_or(0..0);
    let slice = |r: std::ops::Range<usize>| bytes.get(r).unwrap_or(b"");
    // Small members, parsed; log, config, baseline and events are only hashed.
    let mut record = BTreeMap::new();
    for k in [
        "tool",
        "seal",
        "rules",
        "results",
        "sealed_topics",
        "status",
        "merkle",
        "signature",
    ] {
        record.insert(k.to_string(), member(bytes, &span(k))?);
    }
    let record = &record;

    // Leaves straight from the canonical bytes, in the fixed order (SPEC B1.7).
    let mut context = b"{\"schema_version\":".to_vec();
    context.extend_from_slice(slice(span("schema_version")));
    context.extend_from_slice(b",\"seal\":");
    context.extend_from_slice(slice(span("seal")));
    context.extend_from_slice(b",\"tool\":");
    context.extend_from_slice(slice(span("tool")));
    context.push(b'}');
    let mut hashes = vec![
        merkle::leaf_hash(crypto, &context),
        merkle::leaf_hash(crypto, slice(span("log"))),
        merkle::leaf_hash(crypto, slice(span("config"))),
        merkle::leaf_hash(crypto, slice(span("baseline"))),
        merkle::leaf_hash(crypto, slice(span("rules"))),
    ];
    for k in ["results", "sealed_topics", "events"] {
        let m = find(k).ok_or_else(|| fail(format!("missing field `{k}`")))?;
        if slice(m.value.clone()).first() != Some(&b'[') {
            return Err(fail(format!("field `{k}` is not an array")));
        }
        hashes.extend(merkle::leaf_hashes(
            crypto,
            m.elements.iter().map(|e| slice(e.clone())),
        ));
    }
    let leaf_count = hashes.len();
    let root = merkle::root(crypto, &hashes).ok_or_else(|| fail("a record has no leaves"))?;
    let event_count = find("events").map_or(0, |m| m.elements.len());

    let seal = obj(record, "seal")?;
    let merkle_obj = obj(record, "merkle")?;
    let signature_obj = obj(record, "signature")?;
    let rules = obj(record, "rules")?;
    let results = array(record, "results")?;

    let mut problems = Vec::new();

    // Leaf order (SPEC B1.7): results by rule id, events by sequence number.
    let mut last_id: Option<(char, u32)> = None;
    for r in results {
        let id = match r {
            Value::Object(m) => match m.get("id") {
                Some(Value::Str(s)) => s.as_str(),
                _ => "",
            },
            _ => "",
        };
        let Some(key) = rule_id_key(id) else {
            problems.push(format!("result id `{id}` is not a rule id"));
            break;
        };
        if last_id.is_some_and(|l| l >= key) {
            problems.push(format!(
                "results are not in rule-id order: {id} comes too late"
            ));
            break;
        }
        last_id = Some(key);
    }
    let mut last_topic: Option<(String, i64)> = None;
    for d in array(record, "sealed_topics")? {
        let key = match d {
            Value::Object(m) => match (m.get("topic"), m.get("multi_id")) {
                (Some(Value::Str(t)), Some(Value::Int(i))) => Some((t.clone(), *i)),
                _ => None,
            },
            _ => None,
        };
        let Some(key) = key else {
            problems.push("a sealed topic digest has no topic and multi_id".to_string());
            break;
        };
        if last_topic.as_ref().is_some_and(|l| *l >= key) {
            problems.push(format!(
                "sealed topics are not in topic and instance order: {} instance {} comes too late",
                key.0, key.1
            ));
            break;
        }
        last_topic = Some(key);
    }
    if let Some(m) = find("events") {
        for (i, seq) in m.seqs.iter().enumerate() {
            let text = seq.clone().map(&slice);
            if text != Some(i.to_string().as_bytes()) {
                let found = text.map_or("none".to_string(), |t| {
                    String::from_utf8_lossy(t).into_owned()
                });
                problems.push(format!(
                    "events are not in sequence order: the event at position {i} has seq {found}"
                ));
                break;
            }
        }
    }

    // Merkle root over the leaves.
    if merkle_obj
        .keys()
        .map(String::as_str)
        .ne(["algorithm", "leaf_count", "root"])
    {
        problems.push("field `merkle` must hold exactly algorithm, leaf_count, root".to_string());
    }
    let algorithm = string(merkle_obj, "algorithm")?;
    if algorithm != merkle::ALGORITHM {
        problems.push(format!("unknown Merkle algorithm `{algorithm}`"));
    }
    if merkle_obj.get("leaf_count") != Some(&Value::count(leaf_count as u64)) {
        problems.push(format!(
            "Merkle leaf count: recorded {}, found {leaf_count}",
            merkle_obj
                .get("leaf_count")
                .map(canonical)
                .unwrap_or_default()
        ));
    }
    let recorded_root = string(merkle_obj, "root")?;
    if recorded_root != hex(&root) {
        problems.push(format!(
            "Merkle root mismatch: a leaf changed after sealing (recorded {recorded_root}, computed {})",
            hex(&root)
        ));
    }

    // Embedded rules text and its digest.
    if hex(&crypto.sha256(string(rules, "text")?.as_bytes())) != string(rules, "sha256")? {
        problems.push("rules: the embedded text does not match its sha256".to_string());
    }

    // Overall status.
    let any_fail = results.iter().any(|r| match r {
        Value::Object(m) => m.get("status") == Some(&Value::str("FAIL")),
        _ => false,
    });
    let status = string(record, "status")?;
    let expected_status = if any_fail { "FAIL" } else { "PASS" };
    if status != expected_status {
        problems.push(format!(
            "status is {status} but the results say {expected_status}"
        ));
    }

    // Key and signature.
    let fp = fingerprint(crypto, public_key);
    let recorded_fp = string(seal, "key_fingerprint")?;
    if recorded_fp != fp {
        problems.push(format!(
            "signed by key {recorded_fp}, not by the given public key {fp}"
        ));
    }
    if signature_obj
        .keys()
        .map(String::as_str)
        .ne(["algorithm", "value"])
        || string(signature_obj, "algorithm")? != "ed25519"
    {
        problems
            .push("field `signature` must hold exactly algorithm `ed25519` and value".to_string());
    }
    let sig = hex_decode::<64>(string(signature_obj, "value")?);
    let signed_root = hex_decode::<32>(recorded_root);
    match (sig, signed_root) {
        (Some(sig), Some(r)) => {
            if !crypto.ed25519_verify(public_key, &signed_payload(SCHEMA_VERSION, &r), &sig) {
                problems.push("signature does not verify".to_string());
            }
        }
        _ => problems
            .push("signature or Merkle root is not lowercase hex of the right length".to_string()),
    }

    // Custody.
    let custody_text = string(seal, "key_custody")?;
    let custody = Custody::parse(custody_text)
        .ok_or_else(|| fail(format!("unknown key custody `{custody_text}`")))?;
    if require_hardware_key && custody == Custody::FileEvaluation {
        problems.push("sealed with an evaluation key (custody file-evaluation); --require-hardware-key refuses it".to_string());
    }

    let mut crates = Vec::new();
    for c in array(seal, "crypto_crates")? {
        let Value::Object(c) = c else {
            return Err(fail(
                "`seal.crypto_crates` holds something other than an object",
            ));
        };
        crates.push(format!("{} {}", string(c, "name")?, string(c, "version")?));
    }
    let verified = Verified {
        custody,
        fingerprint: recorded_fp.to_string(),
        time_utc: string(seal, "time_utc")?.to_string(),
        crypto_crates: crates.join(", "),
        status: status.to_string(),
        events: event_count,
        leaf_count,
        deep: false,
    };
    Ok(Parsed { problems, verified })
}

/// Hashes everything read through it, so a log that no longer parses still gets a digest.
struct Tee<'a> {
    inner: &'a mut dyn Read,
    sha: Box<dyn Sha256Stream>,
}

impl Read for Tee<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(chunk) = buf.get(..n) {
            self.sha.update(chunk);
        }
        Ok(n)
    }
}

fn baseline_from_record(b: &Map) -> Result<Baseline, String> {
    let firmware = match b.get("firmware") {
        Some(Value::Str(s)) => FirmwareSpec::parse(s)?,
        _ => return Err("baseline.firmware is missing".into()),
    };
    let Some(Value::Object(ps)) = b.get("parameters") else {
        return Err("baseline.parameters is missing".into());
    };
    let mut params = BTreeMap::new();
    for (k, v) in ps {
        let Value::Str(t) = v else {
            return Err(format!("baseline parameter {k} is not a typed string"));
        };
        let pv = ParamValue::from_typed(t)
            .ok_or_else(|| format!("baseline parameter {k}: `{t}` is not a typed value"))?;
        params.insert(k.clone(), pv);
    }
    Ok(Baseline { firmware, params })
}

/// The first key where two objects differ, with both values in canonical JSON.
fn first_field_difference(a: &Value, b: &Value) -> (String, String, String) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            let mut keys: Vec<&String> = x.keys().chain(y.keys()).collect();
            keys.sort();
            keys.dedup();
            for k in keys {
                let (va, vb) = (x.get(k), y.get(k));
                if va != vb {
                    let show = |v: Option<&Value>| v.map_or("absent".to_string(), canonical);
                    return (k.clone(), show(va), show(vb));
                }
            }
            (String::new(), canonical(a), canonical(b))
        }
        _ => (String::new(), canonical(a), canonical(b)),
    }
}

/// Compares sealed and re-derived content; returns the mismatches, most specific first.
fn compare(record: &Map, derived: &Map) -> Vec<String> {
    let mut out = Vec::new();
    let empty = BTreeMap::new();
    let get_obj = |m: &Map, k: &str| match m.get(k) {
        Some(Value::Object(o)) => o.clone(),
        _ => empty.clone(),
    };
    // Configuration, parameter by parameter.
    let (rc, dc) = (get_obj(record, "config"), get_obj(derived, "config"));
    let (rp, dp) = (get_obj(&rc, "parameters"), get_obj(&dc, "parameters"));
    let mut names: Vec<&String> = rp.keys().chain(dp.keys()).collect();
    names.sort();
    names.dedup();
    for n in names {
        let (a, b) = (rp.get(n), dp.get(n));
        if a != b {
            let show = |v: Option<&Value>| match v {
                Some(Value::Str(s)) => s.clone(),
                Some(other) => canonical(other),
                None => "absent".into(),
            };
            out.push(format!(
                "parameter {n}: sealed {}, found {}",
                show(a),
                show(b)
            ));
        }
    }
    let show_any = |v: Option<&Value>| match v {
        Some(Value::Str(s)) => s.clone(),
        Some(other) => canonical(other),
        None => "absent".into(),
    };
    if rc.get("firmware") != dc.get("firmware") {
        out.push(format!(
            "config firmware: sealed {}, found {}",
            show_any(rc.get("firmware")),
            show_any(dc.get("firmware"))
        ));
    }
    // Events, by sequence number.
    let arr = |m: &Map, k: &str| match m.get(k) {
        Some(Value::Array(a)) => a.clone(),
        _ => Vec::new(),
    };
    for (key, label) in [("events", "event"), ("results", "result")] {
        let (ra, da) = (arr(record, key), arr(derived, key));
        for (i, (a, b)) in ra.iter().zip(&da).enumerate() {
            if a != b {
                let (field, va, vb) = first_field_difference(a, b);
                let name = match (key, b) {
                    ("results", Value::Object(m)) => match m.get("id") {
                        Some(Value::Str(id)) => id.clone(),
                        _ => i.to_string(),
                    },
                    _ => format!("seq {i}"),
                };
                let kind = match b {
                    Value::Object(m) => match m.get("kind") {
                        Some(Value::Str(k)) => format!(" ({k})"),
                        _ => String::new(),
                    },
                    _ => String::new(),
                };
                out.push(format!(
                    "{label} {name}{kind} field `{field}`: sealed {va}, found {vb}"
                ));
            }
        }
        if ra.len() != da.len() {
            out.push(format!("{key}: sealed {}, found {}", ra.len(), da.len()));
        }
    }
    // Sealed topics, by topic and instance (before the log digest, which they narrow down).
    let name_of = |v: &Value| match v {
        Value::Object(m) => match (m.get("topic"), m.get("multi_id")) {
            (Some(Value::Str(t)), Some(i)) => format!("{t} instance {}", canonical(i)),
            _ => "?".to_string(),
        },
        _ => "?".to_string(),
    };
    let (rs, ds) = (arr(record, "sealed_topics"), arr(derived, "sealed_topics"));
    for (a, b) in rs.iter().zip(&ds) {
        if a != b {
            let (field, va, vb) = first_field_difference(a, b);
            out.push(format!(
                "sealed topic {} field `{field}`: sealed {va}, found {vb}",
                name_of(b)
            ));
        }
    }
    if rs.len() != ds.len() {
        let names = |v: &[Value]| v.iter().map(name_of).collect::<Vec<_>>().join(", ");
        out.push(format!(
            "sealed topic instances: sealed [{}], found [{}]",
            names(&rs),
            names(&ds)
        ));
    }
    if rc.get("watched_parameters") != dc.get("watched_parameters") {
        out.push(format!(
            "config watched_parameters: sealed {}, found {}",
            show_any(rc.get("watched_parameters")),
            show_any(dc.get("watched_parameters"))
        ));
    }
    // Log identity: digests and size.
    let (rl, dl) = (get_obj(record, "log"), get_obj(derived, "log"));
    for k in ["sha256", "blake3", "size"] {
        if rl.get(k) != dl.get(k) {
            let show = |v: Option<&Value>| v.map_or("absent".to_string(), canonical);
            out.push(format!(
                "log digest mismatch: {k} sealed {}, found {}",
                show(rl.get(k)),
                show(dl.get(k))
            ));
            break;
        }
    }
    for k in ["firmware", "vehicle"] {
        if rl.get(k) != dl.get(k) {
            out.push(format!(
                "log {k}: sealed {}, found {}",
                show_any(rl.get(k)),
                show_any(dl.get(k))
            ));
        }
    }
    out
}

/// Verifies a record, and with `log` also the log it was sealed from.
pub fn verify(
    record_bytes: &[u8],
    log: Option<&mut dyn Read>,
    crypto: &dyn CryptoBackend,
    public_key: &[u8; 32],
    require_hardware_key: bool,
) -> Result<Verified, VerifyError> {
    let parsed = standalone(record_bytes, crypto, public_key, require_hardware_key)
        .map_err(VerifyError::Mismatch)?;
    let custody = parsed.verified.custody;
    verify_parsed(parsed, record_bytes, log, crypto).map_err(|e| match e {
        VerifyError::Mismatch(mut m) => {
            m.custody.get_or_insert(custody);
            VerifyError::Mismatch(m)
        }
        other => other,
    })
}

/// Everything after the standalone checks: their verdict, or the deep comparison with `log`.
fn verify_parsed(
    parsed: Parsed,
    record_bytes: &[u8],
    log: Option<&mut dyn Read>,
    crypto: &dyn CryptoBackend,
) -> Result<Verified, VerifyError> {
    let Some(log) = log else {
        return match parsed.problems.split_first() {
            None => Ok(parsed.verified),
            Some((first, rest)) => Err(VerifyError::Mismatch(Mismatch {
                first: first.clone(),
                also: rest.to_vec(),
                custody: None,
            })),
        };
    };

    // The deep comparison needs every value; the bytes already passed the canonical scan.
    let full = parse(record_bytes)
        .map_err(|e| VerifyError::Mismatch(fail(format!("record is not valid JSON at {e}"))))?;
    let Value::Object(full) = full else {
        return Err(VerifyError::Mismatch(fail("record is not a JSON object")));
    };
    let record = &full;
    let mut tee = Tee {
        inner: log,
        sha: crypto.sha256_stream(),
    };
    let rules_text = obj(record, "rules")
        .and_then(|r| string(r, "text"))
        .map_err(VerifyError::Mismatch)?;
    let rules = parse_rules(rules_text)
        .map_err(|e| VerifyError::Mismatch(fail(format!("embedded rules no longer parse: {e}"))))?;
    let ingested = Px4Ingestor.ingest_sealing("log", &mut tee, crypto, &rules.sealed_topics);
    let mut deep: Vec<String> = Vec::new();
    match ingested {
        Err(IngestError::Io(e)) => return Err(VerifyError::Io(e)),
        Err(e) => {
            io::copy(&mut tee, &mut io::sink()).map_err(|e| VerifyError::Io(e.to_string()))?;
            let found = hex(&tee.sha.finish());
            let sealed = obj(record, "log")
                .ok()
                .and_then(|l| string(l, "sha256").ok())
                .unwrap_or("absent");
            deep.push(if found == sealed {
                format!("the log no longer parses ({e}) although its digest matches")
            } else {
                format!("log digest mismatch: sha256 sealed \"{sealed}\", found \"{found}\" (the log no longer parses: {e})")
            });
        }
        Ok(ing) => {
            let baseline = obj(record, "baseline")
                .map_err(VerifyError::Mismatch)
                .and_then(|b| {
                    baseline_from_record(b)
                        .map_err(|e| VerifyError::Mismatch(fail(format!("embedded {e}"))))
                })?;
            let eval = evaluate(&ing, &rules, &baseline);
            let mut derived = BTreeMap::new();
            derived.insert("config".to_string(), config_json(&ing.config, &rules));
            derived.insert("log".to_string(), log_json(&ing.identity));
            derived.insert("events".to_string(), events_json(&ing, &rules));
            derived.insert("sealed_topics".to_string(), sealed_topics_json(&ing));
            derived.insert(
                "results".to_string(),
                Value::Array(eval.results.iter().map(|r| r.to_json()).collect()),
            );
            deep = compare(record, &derived);
        }
    }
    let mut all = deep;
    all.extend(parsed.problems);
    match all.split_first() {
        None => Ok(Verified {
            deep: true,
            ..parsed.verified
        }),
        Some((first, rest)) => Err(VerifyError::Mismatch(Mismatch {
            first: first.clone(),
            also: rest.to_vec(),
            custody: None,
        })),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::crypto::Signer;
    use crate::crypto::test_backend::{TestBackend, TestKey};
    use crate::json::Obj;
    use crate::seal::{SealParams, seal};

    #[test]
    fn the_record_size_limit_is_exact_and_named() {
        assert_eq!(check_record_size(MAX_RECORD_BYTES), Ok(()));
        assert_eq!(
            check_record_size(MAX_RECORD_BYTES + 1),
            Err("the record exceeds the input limit of 536870912 bytes (SPEC B1.4)".to_string())
        );
    }

    /// Seals the shrunk mc_flight_1 seed with a test key; returns the log, record and key.
    fn sealed_seed() -> (Vec<u8>, Vec<u8>, TestKey) {
        let log = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fuzz/seeds/ulog_ingest/sitl_v1.17.0_mc_flight_1_shrunk.ulg"
        ))
        .unwrap();
        let ing = Px4Ingestor
            .ingest("x.ulg", &mut &log[..], &TestBackend)
            .unwrap();
        let rules = parse_rules(include_str!("../../../examples/rules.default.toml")).unwrap();
        let baseline = crate::params::parse_baseline("# Firmware: 1.17.0\n").unwrap();
        let eval = evaluate(&ing, &rules, &baseline);
        let key = TestKey::new(7);
        let params = SealParams {
            time_utc: "2026-10-18T15:00:00Z".into(),
            token_cmvp_certificate: None,
        };
        let sealed = seal(&ing, &eval, &rules, &baseline, &params, &TestBackend, &key).unwrap();
        (log, sealed.bytes, key)
    }

    /// Applies `edit` to a record and signs it again, as the key holder could.
    #[allow(clippy::panic)]
    fn resigned(bytes: &[u8], key: &TestKey, edit: impl FnOnce(&mut Map)) -> Vec<u8> {
        let Value::Object(mut r) = parse(bytes).unwrap() else {
            panic!("record is an object")
        };
        edit(&mut r);
        let (root, n) = crate::seal::merkle_root(&TestBackend, &r).unwrap();
        let sig = key
            .sign(&crate::seal::signed_payload(SCHEMA_VERSION, &root))
            .unwrap();
        let merkle = Obj::new()
            .field("algorithm", Value::str(merkle::ALGORITHM))
            .field("leaf_count", Value::count(n as u64))
            .field("root", Value::str(hex(&root)))
            .build();
        r.insert("merkle".into(), merkle);
        let signature = Obj::new()
            .field("algorithm", Value::str("ed25519"))
            .field("value", Value::str(hex(&sig)))
            .build();
        r.insert("signature".into(), signature);
        canonical(&Value::Object(r)).into_bytes()
    }

    #[allow(clippy::panic)]
    fn mismatch(r: Result<Verified, VerifyError>) -> Mismatch {
        match r {
            Err(VerifyError::Mismatch(m)) => m,
            other => panic!("expected a mismatch, got {other:?}"),
        }
    }

    #[test]
    fn leaves_must_be_in_rule_id_and_sequence_order() {
        let (_, bytes, key) = sealed_seed();
        let pk = key.public_key();
        // Signing again without a change still verifies, so the edits below are what fail.
        let same = resigned(&bytes, &key, |_| {});
        assert_eq!(same, bytes);
        let reverse = |k: &'static str| {
            move |r: &mut Map| {
                if let Some(Value::Array(a)) = r.get_mut(k) {
                    a.reverse();
                }
            }
        };
        let m = mismatch(verify(
            &resigned(&bytes, &key, reverse("events")),
            None,
            &TestBackend,
            &pk,
            false,
        ));
        assert!(
            m.first
                .starts_with("events are not in sequence order: the event at position 0 has seq "),
            "{m:?}"
        );
        let m = mismatch(verify(
            &resigned(&bytes, &key, reverse("results")),
            None,
            &TestBackend,
            &pk,
            false,
        ));
        assert_eq!(
            m.first,
            "results are not in rule-id order: R6 comes too late"
        );
        // The record still declares an evaluation key, so verify can still warn.
        assert_eq!(m.custody, Some(Custody::FileEvaluation));
        // Rule ids sort by letter, then number.
        assert!(rule_id_key("R2") < rule_id_key("R10"));
        assert!(rule_id_key("R10") < rule_id_key("X1"));
        assert_eq!(rule_id_key("R01"), None);
        assert_eq!(rule_id_key("r1"), None);
        // A record that cannot be read declares nothing.
        assert_eq!(
            mismatch(verify(b"{}", None, &TestBackend, &pk, false)).custody,
            None
        );
    }

    #[test]
    fn firmware_mismatches_name_both_values() {
        let (log, bytes, key) = sealed_seed();
        let pk = key.public_key();
        let edited = resigned(&bytes, &key, |r| {
            if let Some(Value::Object(c)) = r.get_mut("config") {
                c.insert("firmware".into(), Value::str("1.16.0"));
            }
        });
        let m = mismatch(verify(
            &edited,
            Some(&mut &log[..]),
            &TestBackend,
            &pk,
            false,
        ));
        assert_eq!(m.first, "config firmware: sealed 1.16.0, found 1.17.0");
        let edited = resigned(&bytes, &key, |r| {
            if let Some(Value::Object(l)) = r.get_mut("log")
                && let Some(Value::Object(f)) = l.get_mut("firmware")
            {
                f.insert("version".into(), Value::str("1.16.0"));
            }
        });
        let m = mismatch(verify(
            &edited,
            Some(&mut &log[..]),
            &TestBackend,
            &pk,
            false,
        ));
        assert!(
            m.first.starts_with("log firmware: sealed {")
                && m.first.contains("\"version\":\"1.16.0\"")
                && m.first.contains("found {")
                && m.first.contains("\"version\":\"1.17.0\""),
            "{m:?}"
        );
    }

    #[test]
    fn a_sealed_record_verifies_standalone_and_against_its_log() {
        let log = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fuzz/seeds/ulog_ingest/sitl_v1.17.0_mc_flight_1_shrunk.ulg"
        ))
        .unwrap();
        let ing = Px4Ingestor
            .ingest("x.ulg", &mut &log[..], &TestBackend)
            .unwrap();
        let rules = parse_rules(include_str!("../../../examples/rules.default.toml")).unwrap();
        let baseline = crate::params::parse_baseline("# Firmware: 1.17.0\n").unwrap();
        let eval = evaluate(&ing, &rules, &baseline);
        let key = TestKey::new(7);
        let params = SealParams {
            time_utc: "2026-10-18T15:00:00Z".into(),
            token_cmvp_certificate: None,
        };
        let sealed = seal(&ing, &eval, &rules, &baseline, &params, &TestBackend, &key).unwrap();
        let pk = key.public_key();
        let v = verify(&sealed.bytes, None, &TestBackend, &pk, false).unwrap();
        assert_eq!(
            (v.custody, v.events, v.leaf_count),
            (
                Custody::FileEvaluation,
                ing.events.len(),
                5 + 7 + ing.events.len()
            )
        );
        assert!(
            verify(&sealed.bytes, Some(&mut &log[..]), &TestBackend, &pk, false)
                .unwrap()
                .deep
        );
        // Sealing is deterministic for the same inputs and key.
        let again = seal(&ing, &eval, &rules, &baseline, &params, &TestBackend, &key).unwrap();
        assert_eq!(sealed.bytes, again.bytes);
        // A different key does not verify; nor does any record with one byte changed.
        let other = TestKey::new(8).public_key();
        assert!(verify(&sealed.bytes, None, &TestBackend, &other, false).is_err());
        let mut bad = sealed.bytes.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 0x20;
        assert!(verify(&bad, None, &TestBackend, &pk, false).is_err());
    }
}
