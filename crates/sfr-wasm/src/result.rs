//! Structured results for the JavaScript API (docs/SANDBOX.md, "JavaScript API"): a seal's
//! summary, a verification's outcome, and each mismatch `sfr verify` names, split into its
//! parts. The parts come from the mismatch text `sfr-core` writes; `parse_mismatch` reads
//! every form `sfr_core::verify` produces, and a text it does not know is kind `record` with the
//! text kept whole. The tests below and `crates/sfr/tests/sandbox.rs` hold each kind to the text
//! `sfr-core` really writes, so a change of wording there fails CI here.

use crate::{SealOutput, VerifyOutput};
use sfr_core::json::{Obj, Value, pretty};

/// One mismatch, split into its parts. `text` is always the whole line `sfr verify` prints
/// after `Integrity: FAILED: ` or `also: `; the other parts are set where the kind has them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mismatch {
    /// What changed (docs/SANDBOX.md, "Mismatch kinds"): `event`, `parameter`, `result`,
    /// `sealed_topic`, `count`, `sealed_topic_instances`, `config`, `log`, `log_digest`,
    /// `log_unparseable`, `merkle_root`, `merkle_leaf_count`, `key`, `signature`, `status`,
    /// `rules_digest`, `custody`, or `record` (the record's form, and any other text).
    pub kind: &'static str,
    /// The whole text.
    pub text: String,
    /// `event`: the event's sequence number.
    pub seq: Option<u64>,
    /// `event`: the event's kind, for example `COMMAND`.
    pub event_kind: Option<String>,
    /// `result`: the rule id, for example `R3`.
    pub rule: Option<String>,
    /// `parameter`: the parameter name.
    pub parameter: Option<String>,
    /// `sealed_topic`: the topic.
    pub topic: Option<String>,
    /// `sealed_topic`: the instance (`multi_id`).
    pub instance: Option<u64>,
    /// The field: of an event, result or sealed topic; `sha256`, `blake3` or `size` for
    /// `log_digest`; `events` or `results` for `count`; `firmware`, `watched_parameters` or
    /// `vehicle` for `config` and `log`.
    pub field: Option<String>,
    /// The value in the record, as `sfr verify` prints it.
    pub sealed: Option<String>,
    /// The value found: re-derived from the log, recomputed, or the given public key's
    /// fingerprint for `key`, as `sfr verify` prints it.
    pub found: Option<String>,
    /// Extra text in parentheses, such as why the log no longer parses.
    pub note: Option<String>,
}

impl Mismatch {
    fn new(kind: &'static str, text: &str) -> Mismatch {
        Mismatch {
            kind,
            text: text.to_string(),
            seq: None,
            event_kind: None,
            rule: None,
            parameter: None,
            topic: None,
            instance: None,
            field: None,
            sealed: None,
            found: None,
            note: None,
        }
    }

    fn with_values(mut self, (sealed, found): (String, String)) -> Mismatch {
        self.sealed = Some(sealed);
        self.found = Some(found);
        self
    }

    fn with_field(mut self, field: &str) -> Mismatch {
        self.field = Some(field.to_string());
        self
    }
}

/// Splits `sealed <a>, found <b>`. When `, found ` occurs more than once (a value that holds
/// the words), the split is the first at which both sides are JSON values, as event, result and
/// digest values are; otherwise the first.
fn sealed_found(values: &str) -> Option<(String, String)> {
    let rest = values.strip_prefix("sealed ")?;
    let sep = ", found ";
    let cuts: Vec<usize> = rest.match_indices(sep).map(|(i, _)| i).collect();
    let both_json = |i: usize| {
        rest.get(..i)
            .zip(rest.get(i + sep.len()..))
            .is_some_and(|(a, b)| {
                sfr_core::json::parse(a.as_bytes()).is_ok()
                    && sfr_core::json::parse(b.as_bytes()).is_ok()
            })
    };
    let cut = match cuts.as_slice() {
        [] => return None,
        [one] => *one,
        many => many
            .iter()
            .copied()
            .find(|&i| both_json(i))
            .or_else(|| many.first().copied())?,
    };
    Some((
        rest.get(..cut)?.to_string(),
        rest.get(cut + sep.len()..)?.to_string(),
    ))
}

/// `<head> field `<f>`: <values>` into its three parts.
fn item_field(rest: &str) -> Option<(&str, &str, &str)> {
    let (head, tail) = rest.split_once(" field `")?;
    let (field, values) = tail.split_once("`: ")?;
    Some((head, field, values))
}

/// Splits one mismatch text into its parts (see [`Mismatch`]).
pub fn parse_mismatch(text: &str) -> Mismatch {
    parse_known(text).unwrap_or_else(|| Mismatch::new("record", text))
}

fn parse_known(text: &str) -> Option<Mismatch> {
    if let Some(rest) = text.strip_prefix("parameter ") {
        let (name, values) = rest.split_once(": ")?;
        let mut m = Mismatch::new("parameter", text).with_values(sealed_found(values)?);
        m.parameter = Some(name.to_string());
        return Some(m);
    }
    if let Some(rest) = text.strip_prefix("event seq ") {
        let (head, field, values) = item_field(rest)?;
        let (seq, kind) = match head.split_once(" (") {
            Some((seq, kind)) => (seq, Some(kind.strip_suffix(')')?.to_string())),
            None => (head, None),
        };
        let mut m = Mismatch::new("event", text)
            .with_field(field)
            .with_values(sealed_found(values)?);
        m.seq = Some(seq.parse().ok()?);
        m.event_kind = kind;
        return Some(m);
    }
    if let Some(rest) = text.strip_prefix("result ") {
        let (rule, field, values) = item_field(rest)?;
        let mut m = Mismatch::new("result", text)
            .with_field(field)
            .with_values(sealed_found(values)?);
        m.rule = Some(rule.to_string());
        return Some(m);
    }
    for field in ["events", "results"] {
        if let Some(values) = text.strip_prefix(field).and_then(|r| r.strip_prefix(": ")) {
            return Some(
                Mismatch::new("count", text)
                    .with_field(field)
                    .with_values(sealed_found(values)?),
            );
        }
    }
    if let Some(values) = text.strip_prefix("sealed topic instances: ") {
        return Some(
            Mismatch::new("sealed_topic_instances", text).with_values(sealed_found(values)?),
        );
    }
    if let Some(rest) = text.strip_prefix("sealed topic ") {
        let (head, field, values) = item_field(rest)?;
        let (topic, instance) = head.split_once(" instance ")?;
        let mut m = Mismatch::new("sealed_topic", text)
            .with_field(field)
            .with_values(sealed_found(values)?);
        m.topic = Some(topic.to_string());
        m.instance = Some(instance.parse().ok()?);
        return Some(m);
    }
    if let Some(rest) = text.strip_prefix("log digest mismatch: ") {
        let (field, mut values) = rest.split_once(' ')?;
        let mut note = None;
        if let Some(i) = values.find(" (the log no longer parses: ") {
            note = values
                .get(i + 2..)
                .and_then(|n| n.strip_suffix(')'))
                .map(str::to_string);
            values = values.get(..i)?;
        }
        let mut m = Mismatch::new("log_digest", text)
            .with_field(field)
            .with_values(sealed_found(values)?);
        m.note = note;
        return Some(m);
    }
    if let Some(rest) = text.strip_prefix("the log no longer parses (") {
        let mut m = Mismatch::new("log_unparseable", text);
        m.note = Some(
            rest.strip_suffix(") although its digest matches")?
                .to_string(),
        );
        return Some(m);
    }
    for kind in ["config", "log"] {
        if let Some(rest) = text.strip_prefix(kind).and_then(|r| r.strip_prefix(' ')) {
            let (field, values) = rest.split_once(": ")?;
            return Some(
                Mismatch::new(kind, text)
                    .with_field(field)
                    .with_values(sealed_found(values)?),
            );
        }
    }
    if let Some(rest) = text.strip_prefix("Merkle root mismatch: a leaf changed after sealing (") {
        let (a, b) = rest
            .strip_prefix("recorded ")?
            .strip_suffix(')')?
            .split_once(", computed ")?;
        return Some(
            Mismatch::new("merkle_root", text).with_values((a.to_string(), b.to_string())),
        );
    }
    if let Some(rest) = text.strip_prefix("Merkle leaf count: recorded ") {
        let (a, b) = rest.split_once(", found ")?;
        return Some(
            Mismatch::new("merkle_leaf_count", text).with_values((a.to_string(), b.to_string())),
        );
    }
    if let Some(rest) = text.strip_prefix("signed by key ") {
        let (a, b) = rest.split_once(", not by the given public key ")?;
        return Some(Mismatch::new("key", text).with_values((a.to_string(), b.to_string())));
    }
    if let Some(rest) = text.strip_prefix("status is ") {
        let (a, b) = rest.split_once(" but the results say ")?;
        return Some(Mismatch::new("status", text).with_values((a.to_string(), b.to_string())));
    }
    if text.starts_with("signature") {
        return Some(Mismatch::new("signature", text));
    }
    if text.starts_with("rules: the embedded text does not match its sha256") {
        return Some(Mismatch::new("rules_digest", text));
    }
    if text.starts_with("refused: ") {
        return Some(Mismatch::new("custody", text));
    }
    None
}

fn opt_str(v: &Option<String>) -> Value {
    v.as_ref().map_or(Value::Null, |s| Value::str(s.clone()))
}

fn opt_count(v: Option<u64>) -> Value {
    v.map_or(Value::Null, Value::count)
}

fn strings(v: &[String]) -> Value {
    Value::Array(v.iter().map(|s| Value::str(s.clone())).collect())
}

/// A mismatch as the JavaScript API returns it: every part, `null` where the kind has none.
pub fn mismatch_json(m: &Mismatch) -> Value {
    Obj::new()
        .field("kind", Value::str(m.kind))
        .field("text", Value::str(m.text.clone()))
        .field("seq", opt_count(m.seq))
        .field("eventKind", opt_str(&m.event_kind))
        .field("rule", opt_str(&m.rule))
        .field("parameter", opt_str(&m.parameter))
        .field("topic", opt_str(&m.topic))
        .field("instance", opt_count(m.instance))
        .field("field", opt_str(&m.field))
        .field("sealed", opt_str(&m.sealed))
        .field("found", opt_str(&m.found))
        .field("note", opt_str(&m.note))
        .build()
}

/// A failed command (exit 3 or 4): its code, its message, and what `sfr` prints.
pub fn failure_json(code: i32, message: &str, sealing: bool) -> String {
    let mut o = Obj::new()
        .field("exitCode", Value::Int(i64::from(code)))
        .field("message", Value::str(message))
        .field("text", Value::str(format!("sfr: {message}\n")));
    if sealing {
        o = o.field("sealed", Value::Bool(false));
    } else {
        o = o
            .field("verified", Value::Bool(false))
            .field("mismatch", Value::Null)
            .field("mismatches", Value::Array(Vec::new()));
    }
    pretty(&o.build())
}

/// A seal's result (the record and report bytes travel beside it).
pub fn seal_json(s: &SealOutput) -> String {
    let results = s
        .results
        .iter()
        .map(|r| {
            Obj::new()
                .field("id", Value::str(r.id.clone()))
                .field("name", Value::str(r.name.clone()))
                .field("status", Value::str(r.status.clone()))
                .field("expected", Value::str(r.expected.clone()))
                .field("found", Value::str(r.found.clone()))
                .field("detail", strings(&r.detail))
                .build()
        })
        .collect();
    let log = Obj::new()
        .field("fileName", Value::str(s.log.file_name.clone()))
        .field("size", Value::count(s.log.size))
        .field("sha256", Value::str(s.log.sha256.clone()))
        .field("blake3", Value::str(s.log.blake3.clone()))
        .field("firmware", Value::str(s.log.firmware.clone()))
        .build();
    pretty(
        &Obj::new()
            .field("sealed", Value::Bool(true))
            .field("exitCode", Value::Int(i64::from(s.exit_code)))
            .field("status", Value::str(s.status.clone()))
            .field("recordName", Value::str(s.record_name.clone()))
            .field("reportName", Value::str(s.report_name.clone()))
            .field("text", Value::str(s.text.clone()))
            .field("notes", strings(&s.notes))
            .field("merkleRoot", Value::str(s.merkle_root.clone()))
            .field("leafCount", Value::count(s.leaf_count as u64))
            .field("keyFingerprint", Value::str(s.key_fingerprint.clone()))
            .field("keyCustody", Value::str(s.key_custody.clone()))
            .field("keyLabel", Value::str(s.key_label.clone()))
            .field("sealTimeClaimedUtc", Value::str(s.sealed_utc.clone()))
            .field("eventCount", Value::count(s.event_count as u64))
            .field("log", log)
            .field("results", Value::Array(results))
            .build(),
    )
}

/// A verification's result: VERIFIED with what the record says, or FAILED with every mismatch.
pub fn verify_json(v: &VerifyOutput) -> String {
    let summary = v.verified.as_ref();
    let s = |f: fn(&crate::VerifiedSummary) -> String| {
        summary.map_or(Value::Null, |x| Value::str(f(x)))
    };
    pretty(
        &Obj::new()
            .field("exitCode", Value::Int(i64::from(v.exit_code)))
            .field("verified", Value::Bool(v.exit_code == 0))
            .field(
                "checked",
                Value::str(if v.deep { "record and log" } else { "record" }),
            )
            .field("headline", Value::str(v.headline.clone()))
            .field("text", Value::str(v.text.clone()))
            .field("message", Value::Null)
            .field("keyCustody", opt_str(&v.custody))
            .field("keyFingerprint", s(|x| x.fingerprint.clone()))
            .field("cryptoCrates", s(|x| x.crypto_crates.clone()))
            .field("sealTimeClaimedUtc", s(|x| x.sealed_utc.clone()))
            .field("status", s(|x| x.status.clone()))
            .field(
                "failedRules",
                summary.map_or(Value::Null, |x| {
                    Value::Array(
                        x.failed_rules
                            .iter()
                            .map(|r| Value::str(r.clone()))
                            .collect(),
                    )
                }),
            )
            .field(
                "eventCount",
                summary.map_or(Value::Null, |x| Value::count(x.events as u64)),
            )
            .field(
                "mismatch",
                v.mismatches.first().map_or(Value::Null, mismatch_json),
            )
            .field(
                "mismatches",
                Value::Array(v.mismatches.iter().map(mismatch_json).collect()),
            )
            .build(),
    )
}

#[cfg(test)]
mod tests {
    // A panicking test is a failing test, so tests may use expect and unwrap.
    #![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
    use super::*;

    /// Kind, field, sealed value, found value.
    type Parts<'a> = (&'a str, Option<&'a str>, Option<&'a str>, Option<&'a str>);

    fn parts(m: &Mismatch) -> Parts<'_> {
        (
            m.kind,
            m.field.as_deref(),
            m.sealed.as_deref(),
            m.found.as_deref(),
        )
    }

    #[test]
    fn an_event_mismatch_gives_its_seq_kind_field_and_values() {
        let m = parse_mismatch("event seq 1 (COMMAND) field `command`: sealed 311, found 211");
        assert_eq!(
            parts(&m),
            ("event", Some("command"), Some("311"), Some("211"))
        );
        assert_eq!((m.seq, m.event_kind.as_deref()), (Some(1), Some("COMMAND")));
        let m = parse_mismatch("event seq 12 field `kind`: sealed \"ARM\", found absent");
        assert_eq!((m.kind, m.seq, m.event_kind), ("event", Some(12), None));
    }

    #[test]
    fn a_value_holding_the_separator_is_split_where_both_sides_are_json() {
        let m = parse_mismatch(
            "result R3 field `detail`: sealed [\"A: sealed 1, found 2\"], found [\"B, found it\"]",
        );
        assert_eq!(m.kind, "result");
        assert_eq!(m.rule.as_deref(), Some("R3"));
        assert_eq!(m.sealed.as_deref(), Some("[\"A: sealed 1, found 2\"]"));
        assert_eq!(m.found.as_deref(), Some("[\"B, found it\"]"));
    }

    #[test]
    fn every_kind_sfr_core_writes_is_named() {
        let cases: [(&str, Parts<'_>); 14] = [
            (
                "parameter MPC_XY_VEL_MAX: sealed f32:12, found f32:7",
                ("parameter", None, Some("f32:12"), Some("f32:7")),
            ),
            (
                "events: sealed 22, found 21",
                ("count", Some("events"), Some("22"), Some("21")),
            ),
            (
                "sealed topic instances: sealed [a instance 0], found []",
                (
                    "sealed_topic_instances",
                    None,
                    Some("[a instance 0]"),
                    Some("[]"),
                ),
            ),
            (
                "sealed topic custom_detection instance 1 field `message_count`: sealed 0, found 1",
                ("sealed_topic", Some("message_count"), Some("0"), Some("1")),
            ),
            (
                "config firmware: sealed 1.17.0, found 1.16.0",
                ("config", Some("firmware"), Some("1.17.0"), Some("1.16.0")),
            ),
            (
                "log vehicle: sealed {}, found {\"x\":1}",
                ("log", Some("vehicle"), Some("{}"), Some("{\"x\":1}")),
            ),
            (
                "log digest mismatch: sha256 sealed \"aa\", found \"bb\"",
                ("log_digest", Some("sha256"), Some("\"aa\""), Some("\"bb\"")),
            ),
            (
                "log digest mismatch: sha256 sealed \"aa\", found \"bb\" (the log no longer parses: truncated at byte 9)",
                ("log_digest", Some("sha256"), Some("\"aa\""), Some("\"bb\"")),
            ),
            (
                "Merkle root mismatch: a leaf changed after sealing (recorded 0a, computed 0b)",
                ("merkle_root", None, Some("0a"), Some("0b")),
            ),
            (
                "Merkle leaf count: recorded 30, found 31",
                ("merkle_leaf_count", None, Some("30"), Some("31")),
            ),
            (
                "signed by key sha256:aa, not by the given public key sha256:bb",
                ("key", None, Some("sha256:aa"), Some("sha256:bb")),
            ),
            (
                "status is PASS but the results say FAIL",
                ("status", None, Some("PASS"), Some("FAIL")),
            ),
            ("signature does not verify", ("signature", None, None, None)),
            (
                "rules: the embedded text does not match its sha256",
                ("rules_digest", None, None, None),
            ),
        ];
        for (text, want) in cases {
            let m = parse_mismatch(text);
            assert_eq!(parts(&m), want, "{text}");
            assert_eq!(m.text, text);
        }
        let m = parse_mismatch(
            "log digest mismatch: sha256 sealed \"aa\", found \"bb\" (the log no longer parses: truncated at byte 9)",
        );
        assert_eq!(
            m.note.as_deref(),
            Some("the log no longer parses: truncated at byte 9")
        );
        let m = parse_mismatch("the log no longer parses (bad magic) although its digest matches");
        assert_eq!(
            (m.kind, m.note.as_deref()),
            ("log_unparseable", Some("bad magic"))
        );
        let m = parse_mismatch(
            "sealed topic custom_detection instance 1 field `message_count`: sealed 0, found 1",
        );
        assert_eq!(
            (m.topic.as_deref(), m.instance),
            (Some("custom_detection"), Some(1))
        );
        let m = parse_mismatch("parameter MPC_XY_VEL_MAX: sealed f32:12, found f32:7");
        assert_eq!(m.parameter.as_deref(), Some("MPC_XY_VEL_MAX"));
    }

    #[test]
    fn any_other_text_is_kind_record_and_kept_whole() {
        for text in [
            "missing field `seal`",
            "record is not valid JSON at byte 3: bad escape",
            "event seq x (COMMAND) field `command`: sealed 1, found 2",
            "parameter X without values",
            "",
        ] {
            let m = parse_mismatch(text);
            assert_eq!((m.kind, m.text.as_str()), ("record", text));
            assert_eq!((m.sealed, m.found), (None, None));
        }
    }
}
