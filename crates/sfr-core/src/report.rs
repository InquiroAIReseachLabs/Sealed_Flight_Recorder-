//! The Markdown report (`<name>.sfr.md`, SPEC B1.8).
//!
//! Generated only from a sealed record: [`render`] reads the record's JSON and nothing else, so
//! the report cannot say anything the record does not. It is a pure function of the record
//! bytes, so the same record always gives the same report. Tables keep to at most five
//! columns so they render on GitHub and GitLab.
//!
//! Every value from the record goes through [`escape`]: each ASCII punctuation character gets a
//! backslash, which CommonMark defines as that character shown literally, so no value can form
//! a Markdown or HTML construct (emphasis, a link, an entity, a table cell, a list). A control
//! character becomes a space, and a character that hides or reorders text (a bidirectional
//! control such as U+202E, a zero-width character, any Unicode format character) is written out
//! as `<U+202E>`, so it shows. Digests and the key fingerprint are hexadecimal and shown in code
//! spans. The Merkle root and the key fingerprint come first, under the title, so a reader can
//! compare them with what `sfr verify` printed. A host that adds to
//! rendered text after Markdown (GitHub and GitLab turn `:name:` into an emoji, `@name` or
//! `#123` into a link) still does so; Markdown cannot escape that.

use crate::json::Value;
use std::collections::BTreeMap;

/// First line of a report on a record sealed with an evaluation key (SPEC B1.8).
pub const EVALUATION_LINE: &str = "EVALUATION KEY: not for operational use";

/// Report file extension, appended to the record's file stem (SPEC B1.8).
pub const REPORT_EXTENSION: &str = "sfr.md";

/// The report line of a record sealed with `--allow-untested-version` (`seal.allow_untested_version`).
pub const UNTESTED_VERSION_LINE: &str = "**Untested PX4 version.** Sealed with `--allow-untested-version`: \
sfr is tested on PX4 v1.14 to v1.17 logs only, and this log's version is outside them or could not be read.";

/// The report line of a record sealed with `--allow-ignore-all` (`seal.allow_ignore_all`).
pub const IGNORE_ALL_LINE: &str = "**R3 ignores every parameter.** Sealed with `--allow-ignore-all`: \
an ignore pattern in the rules file matches every parameter name, so R3 compared none.";

/// Hex digits of a sealed topic digest shown in the report.
pub const DIGEST_PREFIX_LEN: usize = 16;

/// The note under "Parameters changed in flight".
pub const PARAM_CHANGES_NOTE: &str = "R3 compares the parameters in effect at each ARM with the baseline; a change in flight of a parameter it does not ignore makes R3 WARN.";

/// The line under the rule checks heading: what the results rest on.
pub const RULE_CHECKS_NOTE: &str =
    "Results are computed from data the log declares about itself; see VALIDATION.md.";

/// The line under the status of a record whose log has no armed flight.
pub const NO_ARMED_FLIGHT_LINE: &str = "No armed flight: the log has no ARM and no DISARM, so the rules had no flight to check. This is not a PASS.";

/// "sealed with N skipped messages: ..." when the reader skipped anything, else `None`
/// (`log.skipped` in the record).
pub fn skipped_line(s: &crate::ulog::Summary) -> Option<String> {
    let n = s
        .unknown_records
        .saturating_add(s.orphan_data)
        .saturating_add(s.skipped_regions);
    (n > 0).then(|| {
        format!(
            "sealed with {n} skipped messages: {} of an unknown type, {} data records without a subscription, {} region(s) ({} bytes) before an appended-data offset",
            s.unknown_records, s.orphan_data, s.skipped_regions, s.skipped_bytes
        )
    })
}

/// [`skipped_line`] from a record's `log.skipped`.
fn skipped_line_of(log: &Obj) -> Result<Option<String>, ReportError> {
    let sk = sub(log, "skipped", "log")?;
    let n = |k: &str| -> Result<u64, ReportError> {
        s(sk, k, "log.skipped")?
            .parse()
            .map_err(|_| ReportError(format!("log.skipped.{k}")))
    };
    Ok(skipped_line(&crate::ulog::Summary {
        unknown_records: n("unknown_records")?,
        orphan_data: n("orphan_data_records")?,
        skipped_regions: n("regions")?,
        skipped_bytes: n("region_bytes")?,
        ..crate::ulog::Summary::default()
    }))
}

/// The legend under the event timeline when an event carries `initial` (docs/RECORD_FORMAT.md).
pub const INITIAL_LEGEND: &str = "`initial` (ARM, FAILSAFE_SET): true when the event comes from the log's first `vehicle_status` sample, because the log starts armed or in failsafe; false when it is a change between two samples.";

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

/// Escapes text for Markdown, in a table cell, a list item, or running text: control
/// characters become spaces, a character that hides or reorders text (a Unicode format character,
/// the line and paragraph separators) is written out as its marker, `<U+202E>`, and every ASCII
/// punctuation character, the marker's included, gets a backslash.
pub fn escape(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    for c in t.chars() {
        if c.is_control() {
            out.push(' ');
        } else if crate::display::is_hidden(c) {
            for m in crate::display::marker(c).chars() {
                if m.is_ascii_punctuation() {
                    out.push('\\');
                }
                out.push(m);
            }
        } else {
            if c.is_ascii_punctuation() {
                out.push('\\');
            }
            out.push(c);
        }
    }
    out
}

/// A hexadecimal value (a digest, a fingerprint) in a code span; anything else escaped.
fn code(t: &str) -> String {
    if !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || c == ':') {
        format!("`{t}`")
    } else {
        escape(t)
    }
}

/// Boot time in seconds from a microsecond count in the record, exact to the microsecond.
pub fn seconds(us: &Value) -> String {
    let t = text(us);
    match t.parse::<u64>() {
        Ok(us) => format!("{}.{:06}", us / 1_000_000, us % 1_000_000),
        Err(_) => escape(&t),
    }
}

/// The fields of an event the timeline's detail column leaves out: the ones in their own
/// columns, `utc_us` (the boot time column shows the time), and the event's position in the
/// log (`topic`, `instance`, `index`).
pub const EVENT_OWN_COLUMNS: [&str; 8] = [
    "seq", "kind", "boot_us", "category", "utc_us", "topic", "instance", "index",
];

/// The timeline's detail cell of one event: its other fields as `name value` pairs in key
/// order, each escaped, separated by "; ".
pub fn event_detail(e: &Obj) -> String {
    e.iter()
        .filter(|(k, _)| !EVENT_OWN_COLUMNS.contains(&k.as_str()))
        .map(|(k, v)| format!("{} {}", escape(k), escape(&text(v))))
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

/// Checks a report against its record: the report must be, byte for byte, the one [`render`]
/// gives from the record's bytes. On a difference, names the first line that differs and both
/// versions of it. Call it only for a record whose signature has been verified.
pub fn check(record_bytes: &[u8], report: &[u8]) -> Result<(), String> {
    let value = crate::json::parse(record_bytes).map_err(|e| format!("record: {e}"))?;
    let expected = render(&value).map_err(|e| format!("cannot render the record's report: {e}"))?;
    if expected.as_bytes() == report {
        return Ok(());
    }
    let found = String::from_utf8_lossy(report);
    let short = |line: &str| {
        let line = line.trim_end_matches('\r');
        if line.chars().count() > 120 {
            format!("{}...", line.chars().take(120).collect::<String>())
        } else {
            line.to_string()
        }
    };
    let mut want = expected.split('\n');
    let mut have = found.split('\n');
    let mut n = 0usize;
    loop {
        n += 1;
        match (want.next(), have.next()) {
            (Some(w), Some(h)) if w == h => {}
            (Some(w), Some(h)) => {
                return Err(format!(
                    "line {n} differs from the record: the record gives `{}`, the report has `{}`",
                    short(w),
                    short(h)
                ));
            }
            (Some(w), None) => {
                return Err(format!(
                    "the report ends before line {n}; the record gives `{}` there",
                    short(w)
                ));
            }
            (None, Some(h)) => {
                return Err(format!(
                    "the report has a line {n} that the record does not give: `{}`",
                    short(h)
                ));
            }
            (None, None) => {
                return Err(
                    "the report differs from the record in its bytes, not its lines".into(),
                );
            }
        }
    }
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
    // Under the title, where a reader checks them first against what `sfr verify` printed.
    item(
        &mut out,
        "Merkle root",
        &format!(
            "{} ({}, {} leaves)",
            code(&s(merkle, "root", "merkle")?),
            escape(&s(merkle, "algorithm", "merkle")?),
            escape(&s(merkle, "leaf_count", "merkle")?)
        ),
    );
    item(
        &mut out,
        "Key fingerprint",
        &code(&s(seal, "key_fingerprint", "seal")?),
    );
    out.push('\n');
    out.push_str(&format!(
        "**Status: {}**. Sealed (time claimed by the sealer) {} by {} {}. \
         This report is generated from the record {} alone.\n\n",
        escape(&s(r, "status", "record")?),
        escape(&s(seal, "time_utc", "seal")?),
        escape(&s(tool, "name", "tool")?),
        escape(&s(tool, "version", "tool")?),
        escape(&record_file_name(&file_name)),
    ));
    if s(r, "status", "record")? == "NO ARMED FLIGHT" {
        out.push_str(NO_ARMED_FLIGHT_LINE);
        out.push_str("\n\n");
    }
    // Schema 2: a log sealed although its PX4 version is one sfr is not tested on.
    if seal.get("allow_untested_version") == Some(&Value::Bool(true)) {
        out.push_str(UNTESTED_VERSION_LINE);
        out.push_str("\n\n");
    }
    if seal.get("allow_ignore_all") == Some(&Value::Bool(true)) {
        out.push_str(IGNORE_ALL_LINE);
        out.push_str("\n\n");
    }
    if let Some(line) = skipped_line_of(log)? {
        out.push_str(&format!("**Skipped.** {}.\n\n", escape(&line)));
    }

    // Rules.
    out.push_str("## Rule checks\n\n");
    out.push_str(RULE_CHECKS_NOTE);
    out.push_str("\n\n");
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
        if status == "FAIL" || status == "WARN" {
            failed.push((id, status, s(res, "expected", &path)?, detail));
        }
    }
    out.push('\n');
    for (id, status, expected, detail) in &failed {
        out.push_str(&format!("### {} {}\n\n", escape(id), escape(status)));
        item(&mut out, "Expected", &escape(expected));
        for d in detail {
            out.push_str(&format!("- {}\n", escape(d)));
        }
        out.push('\n');
    }

    // Parameter differences (R3's detail lines that name a difference).
    out.push_str("## Parameter differences\n\n");
    let r3_lines: Vec<String> = r3_lines
        .into_iter()
        .filter(|l| split_r3_line(l).is_some())
        .collect();
    if r3_lines.is_empty() {
        out.push_str("R3 found no difference between the baseline and the flown parameters.\n\n");
    } else {
        header(&mut out, &["Parameter", "Baseline", "Flown"]);
        for line in &r3_lines {
            if let Some((n, b, f)) = split_r3_line(line) {
                row(&mut out, &[escape(n), escape(b), escape(f)]);
            }
        }
        out.push('\n');
    }

    // Parameters changed in flight: the PARAM_CHANGED_IN_FLIGHT events, in timeline order.
    out.push_str("## Parameters changed in flight\n\n");
    out.push_str(PARAM_CHANGES_NOTE);
    out.push_str("\n\n");
    let mut changes = Vec::new();
    for (i, e) in events.iter().enumerate() {
        let path = format!("events[{i}]");
        let e = obj(e, &path)?;
        if s(e, "kind", &path)? == "PARAM_CHANGED_IN_FLIGHT" {
            changes.push((path, e));
        }
    }
    if changes.is_empty() {
        out.push_str("No parameter changed in flight.\n\n");
    } else {
        header(
            &mut out,
            &["Seq", "Boot time (s)", "Parameter", "Old", "New"],
        );
        for (path, e) in changes {
            row(
                &mut out,
                &[
                    escape(&s(e, "seq", &path)?),
                    seconds(get(e, "boot_us", &path)?),
                    escape(&s(e, "name", &path)?),
                    escape(&s(e, "old", &path)?),
                    escape(&s(e, "new", &path)?),
                ],
            );
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
        out.push_str("The record holds no sealed topic digests.\n\n");
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
                    code(digest.get(..DIGEST_PREFIX_LEN).unwrap_or(&digest)),
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
                    event_detail(e),
                ],
            );
        }
        out.push('\n');
        if events
            .iter()
            .any(|e| matches!(e, Value::Object(m) if m.contains_key("initial")))
        {
            out.push_str(INITIAL_LEGEND);
            out.push_str("\n\n");
        }
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
    item(&mut out, "SHA-256", &code(&s(log, "sha256", "log")?));
    item(
        &mut out,
        "BLAKE3 (checked by verify --ulog like SHA-256; adds no security beyond it)",
        &code(&s(log, "blake3", "log")?),
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
        "Seal time (claimed by the sealer, not proven)",
        &escape(&s(seal, "time_utc", "seal")?),
    );
    item(
        &mut out,
        "Key fingerprint",
        &code(&s(seal, "key_fingerprint", "seal")?),
    );
    item(
        &mut out,
        "Key custody (declared by the sealer; this report cannot attest it)",
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
            "{} ({}, {} leaves)",
            code(&s(merkle, "root", "merkle")?),
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
        "With the public key whose fingerprint is {} saved as `sfr.pub`, in the directory that \
         holds the record and the log:\n\n",
        code(&s(seal, "key_fingerprint", "seal")?)
    ));
    // A record that declares an evaluation key is accepted by `sfr verify` only when asked.
    let allow = if s(seal, "key_custody", "seal")? == "file-evaluation" {
        " --allow-evaluation-key"
    } else {
        ""
    };
    let command = format!(
        "sfr verify {} --pubkey sfr.pub{allow} --ulog {}",
        shell_word(&record_file_name(&file_name)),
        shell_word(&file_name)
    );
    let fence = "`".repeat(longest_backtick_run(&command).max(2) + 1);
    out.push_str(&format!("{fence}\n{command}\n{fence}\n\n"));
    out.push_str("Without `--ulog`, `sfr verify` checks the record alone.\n");
    Ok(out)
}

/// A file name as one shell word that `sfr` reads as that file: `./` in front of a name that
/// starts with `-` (else it would be read as an option); then unchanged when it holds only
/// letters, digits, `.`, `_`, `-`, and `/`; in `$'...'` with each byte of a control character
/// or of a character that hides or reorders text (a bidirectional control, a zero-width
/// character) as a three-digit octal escape when it holds one (POSIX dollar-single-quotes, as in
/// bash, zsh, and ksh), so the command stays on one line and shows what it holds; else in single
/// quotes.
pub fn shell_word(name: &str) -> String {
    let name = if name.starts_with('-') {
        format!("./{name}")
    } else {
        name.to_string()
    };
    let odd = |c: char| c.is_control() || crate::display::is_hidden(c);
    if name.chars().any(odd) {
        let mut w = String::from("$'");
        for c in name.chars() {
            match c {
                '\\' | '\'' => {
                    w.push('\\');
                    w.push(c);
                }
                c if odd(c) => {
                    let mut buf = [0u8; 4];
                    for b in c.encode_utf8(&mut buf).bytes() {
                        w.push_str(&format!("\\{b:03o}"));
                    }
                }
                c => w.push(c),
            }
        }
        w.push('\'');
        w
    } else if !name.is_empty()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_backslashes_every_ascii_punctuation_character_and_blanks_control_characters() {
        let punct: String = (0x21u8..0x7f)
            .map(char::from)
            .filter(char::is_ascii_punctuation)
            .collect();
        assert_eq!(punct.len(), 32);
        let escaped = escape(&punct);
        assert_eq!(escaped.len(), 64);
        assert!(
            escaped
                .chars()
                .collect::<Vec<_>>()
                .chunks(2)
                .all(|p| p[0] == '\\' && p[1].is_ascii_punctuation())
        );
        assert_eq!(escape("a\tb\nc\u{85}d e"), "a b c d e");
        // A format character is written out and escaped like any other punctuation, so a
        // Markdown viewer shows `<U+202E>` as text.
        assert_eq!(escape("PASS\u{202e}FAIL"), "PASS\\<U\\+202E\\>FAIL");
        assert_eq!(
            escape("a\u{200b}b\u{2028}c"),
            "a\\<U\\+200B\\>b\\<U\\+2028\\>c"
        );
        assert_eq!(escape("VT_TYPE 1.5"), "VT\\_TYPE 1\\.5");
        assert_eq!(escape("\u{e9}t\u{e9} 2"), "\u{e9}t\u{e9} 2");
    }

    #[test]
    fn shell_word_guards_options_quotes_and_control_characters() {
        assert_eq!(shell_word("flight_1.ulg"), "flight_1.ulg");
        assert_eq!(shell_word("-x.ulg"), "./-x.ulg");
        assert_eq!(shell_word("--ulog.sfr"), "./--ulog.sfr");
        assert_eq!(shell_word("a b's.ulg"), "'a b'\\''s.ulg'");
        assert_eq!(shell_word("$(id).ulg"), "'$(id).ulg'");
        assert_eq!(shell_word("a\tb'\\.ulg"), "$'a\\011b\\'\\\\.ulg'");
        assert_eq!(shell_word("-\n"), "$'./-\\012'");
        assert_eq!(shell_word("c\u{85}.ulg"), "$'c\\302\\205.ulg'");
        // A bidirectional override is written out, so the command shows it.
        assert_eq!(shell_word("a\u{202e}b.ulg"), "$'a\\342\\200\\256b.ulg'");
    }

    #[test]
    fn code_spans_only_hexadecimal_values() {
        assert_eq!(code("ab12"), "`ab12`");
        assert_eq!(code("sha256:ab12"), "`sha256:ab12`");
        assert_eq!(code("a`b"), "a\\`b");
        assert_eq!(code(""), "");
    }
}
