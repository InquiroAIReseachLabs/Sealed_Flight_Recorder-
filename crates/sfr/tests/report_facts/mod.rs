//! Chunk 4 gate: no content in the report that is absent from the record.
//!
//! [`check`] reads a report back line by line and compares every fact in it with the record
//! field it shows: each table row and list item, the status line, the findings of failed
//! rules, and the verify command. It shares no code with `sfr_core::report`: it unescapes
//! what the report shows and compares it with the record's values. Every line of the report
//! must be accounted for, so a line with content from anywhere else fails the check.

use sfr_core::json::Value;
use std::collections::BTreeMap;

type Obj = BTreeMap<String, Value>;

fn o<'a>(v: &'a Value, what: &str) -> &'a Obj {
    match v {
        Value::Object(m) => m,
        _ => panic!("record: {what} is not an object"),
    }
}

fn f<'a>(m: &'a Obj, k: &str) -> &'a Value {
    m.get(k).unwrap_or_else(|| panic!("record: no field {k}"))
}

fn a<'a>(m: &'a Obj, k: &str) -> &'a [Value] {
    match f(m, k) {
        Value::Array(v) => v,
        _ => panic!("record: {k} is not an array"),
    }
}

/// A record scalar as the report shows it once unescaped: control characters as spaces.
fn plain(v: &Value) -> String {
    let t = match v {
        Value::Null => "none".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Str(s) => s.clone(),
        other => sfr_core::json::canonical(other),
    };
    t.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// Removes Markdown backslash escapes.
fn unescape(t: &str) -> String {
    let mut out = String::new();
    let mut chars = t.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// The cells of a table row, split on unescaped `|` and unescaped.
fn cells(line: &str) -> Vec<String> {
    assert!(
        line.starts_with("| ") && line.ends_with(" |"),
        "not a table row: {line}"
    );
    let inner = &line[2..line.len() - 2];
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            cur.push(c);
            if let Some(n) = chars.next() {
                cur.push(n);
            }
        } else if c == '|' {
            out.push(unescape(cur.trim()));
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    out.push(unescape(cur.trim()));
    out
}

/// Seconds as the report shows them ("S.UUUUUU"), back to microseconds.
fn micros(t: &str) -> u64 {
    let (s, us) = t
        .split_once('.')
        .unwrap_or_else(|| panic!("not seconds: {t}"));
    assert_eq!(us.len(), 6, "six decimals: {t}");
    s.parse::<u64>().unwrap() * 1_000_000 + us.parse::<u64>().unwrap()
}

struct Lines<'a> {
    lines: Vec<&'a str>,
    at: usize,
}

impl<'a> Lines<'a> {
    fn next(&mut self) -> &'a str {
        let l = *self
            .lines
            .get(self.at)
            .unwrap_or_else(|| panic!("report ends early after line {}", self.at));
        self.at += 1;
        l
    }
    fn peek(&self) -> Option<&'a str> {
        self.lines.get(self.at).copied()
    }
    fn expect(&mut self, want: &str) {
        let at = self.at + 1;
        let got = self.next();
        assert_eq!(got, want, "report line {at}");
    }
    /// The rows of a table with this header, up to the blank line after it.
    fn table(&mut self, header: &[&str]) -> Vec<Vec<String>> {
        let head = format!("| {} |", header.join(" | "));
        self.expect(&head);
        self.expect(&format!("|{}", "---|".repeat(header.len())));
        let mut rows = Vec::new();
        while self.peek().is_some_and(|l| l.starts_with('|')) {
            let r = cells(self.next());
            assert_eq!(r.len(), header.len(), "row width under {head}");
            rows.push(r);
        }
        self.expect("");
        rows
    }
    /// A list item "- Label: value", unescaped value.
    fn item(&mut self, label: &str) -> String {
        let l = self.next();
        let v = l
            .strip_prefix(&format!("- {label}: "))
            .unwrap_or_else(|| panic!("expected item {label:?}, got {l:?}"));
        unescape(v)
    }
}

/// The R3 detail line split as R3 writes it: "NAME: baseline B, flown F".
fn r3_parts(line: &str) -> (String, String, String) {
    let (n, rest) = line.split_once(": baseline ").expect("R3 line");
    let (b, fl) = rest.split_once(", flown ").expect("R3 line");
    (n.to_string(), b.to_string(), fl.to_string())
}

/// Checks every fact of `md` against `record`. Panics with the first mismatch.
pub fn check(record: &Value, md: &str) {
    let r = o(record, "record");
    let seal = o(f(r, "seal"), "seal");
    let log = o(f(r, "log"), "log");
    let fw = o(f(log, "firmware"), "firmware");
    let vehicle = o(f(log, "vehicle"), "vehicle");
    let config = o(f(r, "config"), "config");
    let base = o(
        f(o(f(r, "baseline"), "baseline"), "parameters"),
        "parameters",
    );
    let flown = o(f(config, "parameters"), "parameters");
    let merkle = o(f(r, "merkle"), "merkle");
    let tool = o(f(r, "tool"), "tool");
    let file = plain(f(log, "file_name"));
    let stem = std::path::Path::new(&file)
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .into_owned();

    assert!(md.ends_with('\n'), "report ends with a newline");
    let mut l = Lines {
        lines: md[..md.len() - 1].split('\n').collect(),
        at: 0,
    };

    if plain(f(seal, "key_custody")) == "file-evaluation" {
        l.expect("EVALUATION KEY: not for operational use");
        l.expect("");
    }
    let title = l.next();
    assert_eq!(
        unescape(
            title
                .strip_prefix("# Sealed flight record: ")
                .expect("title")
        ),
        file
    );
    l.expect("");
    let status = unescape(l.next());
    assert_eq!(
        status,
        format!(
            "**Status: {}**. Sealed {} by {} {}, v1.0 evaluation release. This report is generated from the record {stem}.sfr alone.",
            plain(f(r, "status")),
            plain(f(seal, "time_utc")),
            plain(f(tool, "name")),
            plain(f(tool, "version"))
        )
    );
    l.expect("");

    // Rules: one row per result, in order; then the findings of each failed rule.
    l.expect("## Rules");
    l.expect("");
    let results = a(r, "results");
    let rows = l.table(&["Rule", "Status", "Name", "Found"]);
    assert_eq!(rows.len(), results.len(), "one row per rule");
    let mut r3 = Vec::new();
    for (row, res) in rows.iter().zip(results) {
        let res = o(res, "result");
        let want: Vec<String> = ["id", "status", "name", "found"]
            .iter()
            .map(|k| plain(f(res, k)))
            .collect();
        assert_eq!(row, &want, "rules row");
        if plain(f(res, "id")) == "R3" {
            r3 = a(res, "detail").iter().map(plain).collect();
        }
    }
    for res in results {
        let res = o(res, "result");
        if plain(f(res, "status")) != "FAIL" {
            continue;
        }
        l.expect(&format!("### {} FAIL", plain(f(res, "id"))));
        l.expect("");
        assert_eq!(l.item("Expected"), plain(f(res, "expected")));
        for d in a(res, "detail") {
            let line = l.next();
            assert_eq!(
                unescape(line.strip_prefix("- ").expect("detail item")),
                plain(d)
            );
        }
        l.expect("");
    }

    // Parameter differences: exactly R3's detail lines.
    l.expect("## Parameter differences");
    l.expect("");
    if r3.is_empty() {
        l.expect("R3 found no difference between the baseline and the flown parameters.");
        l.expect("");
    } else {
        let rows = l.table(&["Parameter", "Baseline", "Flown"]);
        let want: Vec<Vec<String>> = r3
            .iter()
            .map(|d| {
                let (n, b, fl) = r3_parts(d);
                vec![n, b, fl]
            })
            .collect();
        assert_eq!(rows, want, "parameter differences are R3's detail lines");
    }

    // Transition tuning, exactly when the record has a vtol_type.
    if let Value::Object(vt) = f(vehicle, "vtol_type") {
        l.expect("## Transition tuning");
        l.expect("");
        assert_eq!(
            l.item("VTOL type"),
            format!(
                "{} (VT_TYPE {})",
                plain(f(vt, "name")),
                plain(f(vt, "value"))
            )
        );
        l.expect("");
        let watched = a(config, "watched_parameters");
        if watched.is_empty() {
            l.expect("The rules file watches no parameters.");
            l.expect("");
        } else {
            let rows = l.table(&["Parameter", "Baseline", "Flown", "R3"]);
            assert_eq!(rows.len(), watched.len(), "one row per watched parameter");
            for (row, w) in rows.iter().zip(watched) {
                let name = plain(w);
                let b = base.get(&name).map_or("absent".into(), plain);
                let fl = flown.get(&name).map_or("absent".into(), plain);
                let listed = r3.iter().any(|d| r3_parts(d).0 == name);
                let mark = if listed {
                    "DIFF"
                } else if !base.contains_key(&name) {
                    "not compared"
                } else {
                    assert_eq!(b, fl, "{name}: R3 lists no difference");
                    "MATCH"
                };
                assert_eq!(row, &vec![name.clone(), b, fl, mark.to_string()]);
            }
        }
    } else {
        assert!(
            !md.contains("## Transition tuning"),
            "no tuning section without a VTOL type"
        );
    }

    // Sealed topics.
    l.expect("## Sealed topics");
    l.expect("");
    let sealed = a(r, "sealed_topics");
    if sealed.is_empty() {
        l.expect("The rules file seals no topics.");
        l.expect("");
    } else {
        let rows = l.table(&[
            "Topic",
            "Instance",
            "Messages",
            "Time span (s)",
            "Data digest",
        ]);
        assert_eq!(
            rows.len(),
            sealed.len(),
            "one row per sealed topic instance"
        );
        for (row, t) in rows.iter().zip(sealed) {
            let t = o(t, "sealed topic");
            assert_eq!(row[0], plain(f(t, "topic")));
            assert_eq!(row[1], plain(f(t, "multi_id")));
            assert_eq!(row[2], plain(f(t, "message_count")));
            match f(t, "first_timestamp_us") {
                Value::Null => assert_eq!(row[3], "none"),
                first => {
                    let (x, y) = row[3].split_once(" to ").expect("time span");
                    assert_eq!(micros(x).to_string(), plain(first));
                    assert_eq!(micros(y).to_string(), plain(f(t, "last_timestamp_us")));
                }
            }
            let digest = row[4].trim_matches('`');
            assert!(
                digest.len() >= 8 && plain(f(t, "data_sha256")).starts_with(digest),
                "digest prefix {digest}"
            );
        }
    }

    // Events: every event in order; the detail column holds exactly its other fields.
    l.expect("## Events");
    l.expect("");
    let events = a(r, "events");
    if events.is_empty() {
        l.expect("The log has no events.");
        l.expect("");
    } else {
        let rows = l.table(&["Seq", "Boot time (s)", "Kind", "Category", "Detail"]);
        assert_eq!(rows.len(), events.len(), "one row per event");
        for (row, e) in rows.iter().zip(events) {
            let e = o(e, "event");
            assert_eq!(row[0], plain(f(e, "seq")));
            assert_eq!(micros(&row[1]).to_string(), plain(f(e, "boot_us")));
            assert_eq!(row[2], plain(f(e, "kind")));
            assert_eq!(row[3], e.get("category").map(plain).unwrap_or_default());
            let own = [
                "seq", "kind", "boot_us", "category", "utc_us", "topic", "instance", "index",
            ];
            let want = e
                .iter()
                .filter(|(k, _)| !own.contains(&k.as_str()))
                .map(|(k, v)| format!("{k} {}", plain(v)))
                .collect::<Vec<_>>()
                .join("; ");
            assert_eq!(row[4], want.trim(), "event {} detail", row[0]);
        }
    }

    // Log identity and digests.
    l.expect("## Log");
    l.expect("");
    assert_eq!(l.item("File"), file);
    assert_eq!(l.item("Size (bytes)"), plain(f(log, "size")));
    assert_eq!(
        l.item("Firmware"),
        format!("{} (git {})", plain(f(fw, "version")), plain(f(fw, "git")))
    );
    assert_eq!(l.item("SHA-256"), format!("`{}`", plain(f(log, "sha256"))));
    assert_eq!(
        l.item("BLAKE3 (supplementary)"),
        format!("`{}`", plain(f(log, "blake3")))
    );
    assert_eq!(l.item("VTOL"), plain(f(vehicle, "is_vtol")));
    assert_eq!(l.item("MAV_TYPE"), plain(f(vehicle, "system_type")));
    l.expect("");

    // Seal.
    l.expect("## Seal");
    l.expect("");
    assert_eq!(l.item("Sealed at"), plain(f(seal, "time_utc")));
    let fp = plain(f(seal, "key_fingerprint"));
    assert_eq!(l.item("Key fingerprint"), format!("`{fp}`"));
    assert_eq!(l.item("Key custody"), plain(f(seal, "key_custody")));
    let crates: Vec<String> = a(seal, "crypto_crates")
        .iter()
        .map(|c| {
            let c = o(c, "crate");
            format!("{} {}", plain(f(c, "name")), plain(f(c, "version")))
        })
        .collect();
    assert_eq!(l.item("Crypto crates (crate versions)"), crates.join(", "));
    assert_eq!(
        l.item("Merkle root"),
        format!(
            "`{}` ({}, {} leaves)",
            plain(f(merkle, "root")),
            plain(f(merkle, "algorithm")),
            plain(f(merkle, "leaf_count"))
        )
    );
    assert_eq!(l.item("Schema version"), plain(f(r, "schema_version")));
    l.expect("");

    // The verify command: the record and log file names, and the record's key fingerprint.
    l.expect("## Verify");
    l.expect("");
    l.expect(&format!(
        "With the public key whose fingerprint is `{fp}` saved as `sfr.pub`, in the directory that holds the record and the log:"
    ));
    l.expect("");
    let fence = l.next();
    assert!(
        fence.len() >= 3 && fence.chars().all(|c| c == '`'),
        "code fence"
    );
    let command = l.next();
    let quote = |n: &str| {
        if n.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
        {
            n.to_string()
        } else {
            format!("'{}'", n.replace('\'', "'\\''"))
        }
    };
    assert_eq!(
        command,
        format!(
            "sfr verify {} --pubkey sfr.pub --ulog {}",
            quote(&format!("{stem}.sfr")),
            quote(&file)
        )
    );
    l.expect(fence);
    l.expect("");
    l.expect("Without `--ulog`, `sfr verify` checks the record alone.");
    assert_eq!(l.peek(), None, "nothing after the verify section");
}
