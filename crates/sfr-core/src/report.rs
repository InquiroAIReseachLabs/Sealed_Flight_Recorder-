//! The Markdown report (`<name>.sfr.md`, SPEC B1.8).
//!
//! Generated only from a sealed record: [`render`] reads the record's JSON and nothing else, so
//! the report cannot say anything the record does not. It is a pure function of the record
//! bytes, so the same record always gives the same report. Tables keep to a few short columns
//! so they render on GitHub and GitLab; every value from the record is escaped for Markdown.

use crate::json::Value;
use std::collections::BTreeMap;

/// First line of a report on a record sealed with an evaluation key (SPEC B1.8).
pub const EVALUATION_LINE: &str = "EVALUATION KEY: not for operational use";

/// Report file extension, appended to the record's file stem (SPEC B1.8).
pub const REPORT_EXTENSION: &str = "sfr.md";

/// Hex digits of a sealed topic digest shown in the report.
pub const DIGEST_PREFIX_LEN: usize = 16;

/// Why a record cannot be turned into a report: it lacks a field the report shows. A record
/// that `verify` accepts always has every one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportError(pub String);

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "the record has no {}", self.0)
    }
}

impl std::error::Error for ReportError {}

type Obj = BTreeMap<String, Value>;

fn obj<'a>(v: &'a Value, path: &str) -> Result<&'a Obj, ReportError> {
    match v {
        Value::Object(m) => Ok(m),
        _ => Err(ReportError(path.to_string())),
    }
}

fn get<'a>(o: &'a Obj, key: &str, path: &str) -> Result<&'a Value, ReportError> {
    o.get(key)
        .ok_or_else(|| ReportError(format!("{path}.{key}")))
}

fn arr<'a>(o: &'a Obj, key: &str, path: &str) -> Result<&'a [Value], ReportError> {
    match get(o, key, path)? {
        Value::Array(a) => Ok(a),
        _ => Err(ReportError(format!("{path}.{key}"))),
    }
}

fn sub<'a>(o: &'a Obj, key: &str, path: &str) -> Result<&'a Obj, ReportError> {
    obj(get(o, key, path)?, &format!("{path}.{key}"))
}

/// A scalar as plain text: strings as they are, numbers in decimal, `null` as "none".
pub fn text(v: &Value) -> String {
    match v {
        Value::Null => "none".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Str(s) => s.clone(),
        Value::Array(_) | Value::Object(_) => crate::json::canonical(v),
    }
}

fn s(o: &Obj, key: &str, path: &str) -> Result<String, ReportError> {
    get(o, key, path).map(text)
}

/// Escapes text for Markdown, in a table cell or in running text: control characters become
/// spaces, and the characters Markdown or HTML would interpret get a backslash.
pub fn escape(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    for c in t.chars() {
        match c {
            c if c.is_control() => out.push(' '),
            '\\' | '|' | '`' | '*' | '_' | '<' | '>' | '[' | ']' | '#' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

/// Boot time in seconds from a microsecond count in the record, exact to the microsecond.
pub fn seconds(us: &Value) -> String {
    let t = text(us);
    match t.parse::<u64>() {
        Ok(us) => format!("{}.{:06}", us / 1_000_000, us % 1_000_000),
        Err(_) => t,
    }
}

/// The fields of an event the timeline's detail column shows: every field except the ones in
/// their own columns or the event's position in the log.
pub const EVENT_OWN_COLUMNS: [&str; 8] = [
    "seq", "kind", "boot_us", "category", "utc_us", "topic", "instance", "index",
];

/// The timeline's detail text of one event: its other fields as `name value` pairs in key
/// order, separated by "; ".
pub fn event_detail(e: &Obj) -> String {
    e.iter()
        .filter(|(k, _)| !EVENT_OWN_COLUMNS.contains(&k.as_str()))
        .map(|(k, v)| format!("{k} {}", text(v)))
        .collect::<Vec<_>>()
        .join("; ")
}

/// One R3 detail line split into (parameter, baseline value, flown value). R3 writes
/// "NAME: baseline VALUE, flown VALUE"; parameter names never hold ": " and values never
/// hold ", ".
pub fn split_r3_line(line: &str) -> Option<(&str, &str, &str)> {
    let (name, rest) = line.split_once(": baseline ")?;
    let (b, f) = rest.split_once(", flown ")?;
    Some((name, b, f))
}

/// The record's file name for a log: the log's file stem plus `.sfr`, as `seal` writes it.
pub fn record_file_name(log_file_name: &str) -> String {
    let stem = std::path::Path::new(log_file_name).file_stem().map_or_else(
        || "record".to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
    format!("{stem}.{}", crate::RECORD_EXTENSION)
}

fn row(out: &mut String, cells: &[String]) {
    out.push('|');
    for c in cells {
        out.push(' ');
        out.push_str(c);
        out.push_str(" |");
    }
    out.push('\n');
}

fn header(out: &mut String, names: &[&str]) {
    row(
        out,
        &names.iter().map(|n| n.to_string()).collect::<Vec<_>>(),
    );
    out.push('|');
    for _ in names {
        out.push_str("---|");
    }
    out.push('\n');
}

fn item(out: &mut String, label: &str, value: &str) {
    out.push_str(&format!("- {label}: {value}\n"));
}

/// The report of a sealed record (SPEC B1.8), from the record's parsed JSON alone.
pub fn render(record: &Value) -> Result<String, ReportError> {
    let r = obj(record, "record")?;
    let seal = sub(r, "seal", "record")?;
    let log = sub(r, "log", "record")?;
    let fw = sub(log, "firmware", "log")?;
    let vehicle = sub(log, "vehicle", "log")?;
    let config = sub(r, "config", "record")?;
    let baseline = sub(r, "baseline", "record")?;
    let merkle = sub(r, "merkle", "record")?;
    let tool = sub(r, "tool", "record")?;
    let results = arr(r, "results", "record")?;
    let events = arr(r, "events", "record")?;
    let sealed_topics = arr(r, "sealed_topics", "record")?;
    let file_name = s(log, "file_name", "log")?;

    let mut out = String::new();
    if s(seal, "key_custody", "seal")? == "file-evaluation" {
        out.push_str(EVALUATION_LINE);
        out.push_str("\n\n");
    }
    out.push_str(&format!(
        "# Sealed flight record: {}\n\n",
        escape(&file_name)
    ));
    out.push_str(&format!(
        "**Status: {}**. Sealed {} by {} {}, v1.0 evaluation release. This report is generated \
         from the record {} alone.\n\n",
        escape(&s(r, "status", "record")?),
        escape(&s(seal, "time_utc", "seal")?),
        escape(&s(tool, "name", "tool")?),
        escape(&s(tool, "version", "tool")?),
        escape(&record_file_name(&file_name)),
    ));

    // Rules.
    out.push_str("## Rules\n\n");
    header(&mut out, &["Rule", "Status", "Name", "Found"]);
    let mut r3_lines: Vec<String> = Vec::new();
    let mut failed = Vec::new();
    for (i, res) in results.iter().enumerate() {
        let path = format!("results[{i}]");
        let res = obj(res, &path)?;
        let id = s(res, "id", &path)?;
        let status = s(res, "status", &path)?;
        row(
            &mut out,
            &[
                escape(&id),
                escape(&status),
                escape(&s(res, "name", &path)?),
                escape(&s(res, "found", &path)?),
            ],
        );
        let detail: Vec<String> = arr(res, "detail", &path)?.iter().map(text).collect();
        if id == "R3" {
            r3_lines = detail.clone();
        }
        if status == "FAIL" {
            failed.push((id, s(res, "expected", &path)?, detail));
        }
    }
    out.push('\n');
    for (id, expected, detail) in &failed {
        out.push_str(&format!("### {} FAIL\n\n", escape(id)));
        item(&mut out, "Expected", &escape(expected));
        for d in detail {
            out.push_str(&format!("- {}\n", escape(d)));
        }
        out.push('\n');
    }

    // Parameter differences (R3's detail lines).
    out.push_str("## Parameter differences\n\n");
    if r3_lines.is_empty() {
        out.push_str("R3 found no difference between the baseline and the flown parameters.\n\n");
    } else {
        header(&mut out, &["Parameter", "Baseline", "Flown"]);
        for line in &r3_lines {
            match split_r3_line(line) {
                Some((n, b, f)) => row(&mut out, &[escape(n), escape(b), escape(f)]),
                None => row(&mut out, &[escape(line), String::new(), String::new()]),
            }
        }
        out.push('\n');
    }

    // Transition tuning, when the vehicle is VTOL.
    if let Value::Object(vt) = get(vehicle, "vtol_type", "log.vehicle")? {
        out.push_str("## Transition tuning\n\n");
        item(
            &mut out,
            "VTOL type",
            &format!(
                "{} (VT_TYPE {})",
                escape(&s(vt, "name", "log.vehicle.vtol_type")?),
                escape(&s(vt, "value", "log.vehicle.vtol_type")?)
            ),
        );
        out.push('\n');
        let watched = arr(config, "watched_parameters", "config")?;
        if watched.is_empty() {
            out.push_str("The rules file watches no parameters.\n\n");
        } else {
            let flown = sub(config, "parameters", "config")?;
            let base = sub(baseline, "parameters", "baseline")?;
            header(&mut out, &["Parameter", "Baseline", "Flown", "R3"]);
            for w in watched {
                let name = text(w);
                let b = base.get(&name).map_or("absent".to_string(), text);
                let f = flown.get(&name).map_or("absent".to_string(), text);
                let mark = watched_mark(&name, base.contains_key(&name), &r3_lines);
                row(
                    &mut out,
                    &[escape(&name), escape(&b), escape(&f), mark.into()],
                );
            }
            out.push('\n');
        }
    }

    // Sealed topics.
    out.push_str("## Sealed topics\n\n");
    if sealed_topics.is_empty() {
        out.push_str("The rules file seals no topics.\n\n");
    } else {
        header(
            &mut out,
            &[
                "Topic",
                "Instance",
                "Messages",
                "Time span (s)",
                "Data digest",
            ],
        );
        for (i, t) in sealed_topics.iter().enumerate() {
            let path = format!("sealed_topics[{i}]");
            let t = obj(t, &path)?;
            let first = get(t, "first_timestamp_us", &path)?;
            let span = match first {
                Value::Null => "none".to_string(),
                _ => format!(
                    "{} to {}",
                    seconds(first),
                    seconds(get(t, "last_timestamp_us", &path)?)
                ),
            };
            let digest = s(t, "data_sha256", &path)?;
            row(
                &mut out,
                &[
                    escape(&s(t, "topic", &path)?),
                    escape(&s(t, "multi_id", &path)?),
                    escape(&s(t, "message_count", &path)?),
                    span,
                    format!("`{}`", digest.get(..DIGEST_PREFIX_LEN).unwrap_or(&digest)),
                ],
            );
        }
        out.push('\n');
    }

    // Event timeline.
    out.push_str("## Events\n\n");
    if events.is_empty() {
        out.push_str("The log has no events.\n\n");
    } else {
        header(
            &mut out,
            &["Seq", "Boot time (s)", "Kind", "Category", "Detail"],
        );
        for (i, e) in events.iter().enumerate() {
            let path = format!("events[{i}]");
            let e = obj(e, &path)?;
            let category = e.get("category").map(text).unwrap_or_default();
            row(
                &mut out,
                &[
                    escape(&s(e, "seq", &path)?),
                    seconds(get(e, "boot_us", &path)?),
                    escape(&s(e, "kind", &path)?),
                    escape(&category),
                    escape(&event_detail(e)),
                ],
            );
        }
        out.push('\n');
    }

    // Log identity and digests.
    out.push_str("## Log\n\n");
    item(&mut out, "File", &escape(&file_name));
    item(&mut out, "Size (bytes)", &escape(&s(log, "size", "log")?));
    item(
        &mut out,
        "Firmware",
        &format!(
            "{} (git {})",
            escape(&s(fw, "version", "log.firmware")?),
            escape(&s(fw, "git", "log.firmware")?)
        ),
    );
    item(
        &mut out,
        "SHA-256",
        &format!("`{}`", s(log, "sha256", "log")?),
    );
    item(
        &mut out,
        "BLAKE3 (supplementary)",
        &format!("`{}`", s(log, "blake3", "log")?),
    );
    item(
        &mut out,
        "VTOL",
        &escape(&s(vehicle, "is_vtol", "log.vehicle")?),
    );
    item(
        &mut out,
        "MAV_TYPE",
        &escape(&s(vehicle, "system_type", "log.vehicle")?),
    );
    out.push('\n');

    // Seal.
    out.push_str("## Seal\n\n");
    item(
        &mut out,
        "Sealed at",
        &escape(&s(seal, "time_utc", "seal")?),
    );
    item(
        &mut out,
        "Key fingerprint",
        &format!("`{}`", s(seal, "key_fingerprint", "seal")?),
    );
    item(
        &mut out,
        "Key custody",
        &escape(&s(seal, "key_custody", "seal")?),
    );
    let crates = arr(seal, "crypto_crates", "seal")?
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let path = format!("seal.crypto_crates[{i}]");
            let c = obj(c, &path)?;
            Ok(format!(
                "{} {}",
                escape(&s(c, "name", &path)?),
                escape(&s(c, "version", &path)?)
            ))
        })
        .collect::<Result<Vec<_>, ReportError>>()?;
    item(
        &mut out,
        "Crypto crates (crate versions)",
        &crates.join(", "),
    );
    item(
        &mut out,
        "Merkle root",
        &format!(
            "`{}` ({}, {} leaves)",
            s(merkle, "root", "merkle")?,
            escape(&s(merkle, "algorithm", "merkle")?),
            escape(&s(merkle, "leaf_count", "merkle")?)
        ),
    );
    item(
        &mut out,
        "Schema version",
        &escape(&s(r, "schema_version", "record")?),
    );
    out.push('\n');

    // How to verify.
    out.push_str("## Verify\n\n");
    out.push_str(&format!(
        "With the public key whose fingerprint is `{}` saved as `sfr.pub`, in the directory that \
         holds the record and the log:\n\n",
        s(seal, "key_fingerprint", "seal")?
    ));
    let command = format!(
        "sfr verify {} --pubkey sfr.pub --ulog {}",
        shell_word(&record_file_name(&file_name)),
        shell_word(&file_name)
    );
    let fence = "`".repeat(longest_backtick_run(&command).max(2) + 1);
    out.push_str(&format!("{fence}\n{command}\n{fence}\n\n"));
    out.push_str("Without `--ulog`, `sfr verify` checks the record alone.\n");
    Ok(out)
}

/// A file name as one shell word: unchanged when it holds only letters, digits, `.`, `_`, `-`,
/// and `/`, else in single quotes. Control characters become spaces so the command stays on
/// one line.
pub fn shell_word(name: &str) -> String {
    let name: String = name
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
    {
        name
    } else {
        format!("'{}'", name.replace('\'', "'\\''"))
    }
}

fn longest_backtick_run(t: &str) -> usize {
    t.split(|c| c != '`').map(str::len).max().unwrap_or(0)
}

/// The R3 column of a watched parameter, from the record: DIFF when R3 lists it, "not
/// compared" when R3 does not and the baseline lacks it (R3 compares only baseline parameters,
/// or the log lacks it too), else MATCH.
pub fn watched_mark(name: &str, in_baseline: bool, r3_lines: &[String]) -> &'static str {
    if r3_lines
        .iter()
        .any(|l| split_r3_line(l).is_some_and(|(n, _, _)| n == name))
    {
        "DIFF"
    } else if !in_baseline {
        "not compared"
    } else {
        "MATCH"
    }
}
