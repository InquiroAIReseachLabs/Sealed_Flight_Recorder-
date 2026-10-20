//! Report gate: no content in the report that is absent from the record.
//!
//! [`check`] reads a report back line by line and compares every fact in it with the record
//! field it shows: each table row and list item, the status line, the findings of failed
//! rules, and the verify command. It shares no code with `sfr_core::report`. It compares the
//! Markdown as written, not unescaped: a value from the record must appear with a backslash
//! before every ASCII punctuation character (CommonMark shows such a character literally), so
//! a value that would render as anything but its own text fails the check. Every line of the
//! report must be accounted for, so a line with content from anywhere else fails too.

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

/// A record scalar as text: `null` as "none".
fn plain(v: &Value) -> String {
    match v {
        Value::Null => "none".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Str(s) => s.clone(),
        other => sfr_core::json::canonical(other),
    }
}

/// Whether the report must write `c` out as `<U+XXXX>`: a Unicode format character (category
/// Cf, listed here from the Unicode database, not taken from the renderer), or the line and
/// paragraph separator.
fn hidden(c: char) -> bool {
    let c = c as u32;
    [
        (0xAD, 0xAD),
        (0x600, 0x605),
        (0x61C, 0x61C),
        (0x6DD, 0x6DD),
        (0x70F, 0x70F),
        (0x890, 0x891),
        (0x8E2, 0x8E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x2028, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x110BD, 0x110BD),
        (0x110CD, 0x110CD),
        (0x13430, 0x1343F),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0001, 0xE0001),
        (0xE0020, 0xE007F),
    ]
    .iter()
    .any(|&(a, b)| (a..=b).contains(&c))
}

/// Text as the report must write it: a control or hidden character as its marker, and a
/// backslash before every ASCII punctuation character (the marker's included).
pub fn esc(t: &str) -> String {
    let mut out = String::new();
    for c in t.chars() {
        let shown = if c.is_control() || hidden(c) {
            format!("<U+{:04X}>", c as u32)
        } else {
            c.to_string()
        };
        for d in shown.chars() {
            if d.is_ascii_punctuation() {
                out.push('\\');
            }
            out.push(d);
        }
    }
    out
}

/// A record scalar as the report must write it.
fn ev(v: &Value) -> String {
    esc(&plain(v))
}

/// A hexadecimal record value (a digest, or `sha256:` and a fingerprint) in a code span.
fn hex_span(v: &Value) -> String {
    let t = plain(v);
    let hex = t.strip_prefix("sha256:").unwrap_or(&t);
    assert!(
        !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        "not hexadecimal: {t}"
    );
    format!("`{t}`")
}

/// The cells of a table row, split on unescaped `|`, as written.
fn cells(line: &str) -> Vec<String> {
    assert!(
        line.starts_with("| ") && line.ends_with(" |"),
        "not a table row: {line}"
    );
    let inner = &line[2..line.len() - 2];
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            cur.push(c);
            if let Some(n) = chars.next() {
                cur.push(n);
            }
        } else if c == '|' {
            out.push(cur.trim().to_string());
            cur.clear();
        } else {
            cur.push(c);
        }
    }
    out.push(cur.trim().to_string());
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
    /// The value of a list item "- Label: value", as written.
    fn item(&mut self, label: &str) -> String {
        let l = self.next();
        l.strip_prefix(&format!("- {label}: "))
            .unwrap_or_else(|| panic!("expected item {label:?}, got {l:?}"))
            .to_string()
    }
}

/// The R3 detail line split as R3 writes it: "NAME: baseline B, flown F".
fn r3_parts(line: &str) -> (String, String, String) {
    let (n, rest) = line.split_once(": baseline ").expect("R3 line");
    let (b, fl) = rest.split_once(", flown ").expect("R3 line");
    (n.to_string(), b.to_string(), fl.to_string())
}

/// A file name as a shell argument `sfr` reads as that file in POSIX sh, bash and PowerShell,
/// built here independently of the renderer: `./` before a leading `-`; `None` when the name
/// holds a control or hidden character, an ASCII single quote, or one of the quotes PowerShell
/// also ends a string at (U+2018 to U+201B); bare when it starts with a letter or `./` and holds
/// only `[A-Za-z0-9._/-]`; else in single quotes.
pub fn shell_arg(name: &str) -> Option<String> {
    let mut n = name.to_string();
    if n.starts_with('-') {
        n.insert_str(0, "./");
    }
    if n.is_empty()
        || n.chars().any(|c| {
            c.is_control()
                || hidden(c)
                || ['\'', '\u{2018}', '\u{2019}', '\u{201a}', '\u{201b}'].contains(&c)
        })
    {
        return None;
    }
    let bare = n
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
        && (n.as_bytes()[0].is_ascii_alphabetic() || n.starts_with("./"));
    Some(if bare { n } else { format!("'{n}'") })
}

/// The two lines that set `record` and `log` in POSIX sh: `printf` with octal escapes for every
/// byte but `[A-Za-z0-9._/-]`, and a trailing `x` that keeps a final newline.
fn posix_lines(record: &str, log: &str) -> Vec<String> {
    [("record", record), ("log", log)]
        .iter()
        .map(|(v, n)| {
            let n = if n.starts_with('-') {
                format!("./{n}")
            } else {
                n.to_string()
            };
            let f: String = n
                .bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() || b"._/-".contains(&b) {
                        (b as char).to_string()
                    } else {
                        format!("\\{b:03o}")
                    }
                })
                .collect();
            format!("{v}=\"$(printf '{f}x')\"; {v}=\"${{{v}%x}}\"")
        })
        .collect()
}

/// The two lines that set `$record` and `$log` in PowerShell, from their UTF-8 bytes.
fn powershell_lines(record: &str, log: &str) -> Vec<String> {
    [("record", record), ("log", log)]
        .iter()
        .map(|(v, n)| {
            let n = if n.starts_with('-') {
                format!("./{n}")
            } else {
                n.to_string()
            };
            let b: Vec<String> = n.bytes().map(|b| format!("0x{b:02X}")).collect();
            format!(
                "${v} = [Text.Encoding]::UTF8.GetString([byte[]]({}))",
                b.join(", ")
            )
        })
        .collect()
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
    l.expect(&format!("# Sealed flight record: {}", esc(&file)));
    l.expect("");
    // The Merkle root and the key fingerprint come first, under the title.
    let merkle_top = o(f(r, "merkle"), "merkle");
    assert_eq!(
        l.item("Merkle root"),
        format!(
            "{} ({}, {} leaves)",
            hex_span(f(merkle_top, "root")),
            ev(f(merkle_top, "algorithm")),
            ev(f(merkle_top, "leaf_count"))
        )
    );
    assert_eq!(
        l.item("Key fingerprint"),
        hex_span(f(seal, "key_fingerprint"))
    );
    l.expect("");
    l.expect(&format!(
        "**Status: {}**. Sealed (time claimed by the sealer) {} by {} {}. This report is generated from the record {} alone.",
        ev(f(r, "status")),
        ev(f(seal, "time_utc")),
        ev(f(tool, "name")),
        ev(f(tool, "version")),
        esc(&format!("{stem}.sfr"))
    ));
    l.expect("");
    // Schema 4: a log with no armed flight says so under the status.
    if plain(f(r, "status")) == "NO ARMED FLIGHT" {
        l.expect(
            "No armed flight: the log has no ARM and no DISARM, so the rules had no flight to check. This is not a PASS.",
        );
        l.expect("");
    }
    // Schema 2: the untested-version line exactly when the record says the flag was given.
    if seal.get("allow_untested_version") == Some(&Value::Bool(true)) {
        l.expect(sfr_core::report::UNTESTED_VERSION_LINE);
        l.expect("");
    }
    // Schema 5: the untested ULog file version line exactly when the record says the flag was
    // given for it, naming the version the record states.
    if seal.get("allow_untested_ulog_version") == Some(&Value::Bool(true)) {
        let v = match log.get("ulog_version") {
            Some(Value::Int(v)) => *v,
            other => panic!("log.ulog_version: {other:?}"),
        };
        l.expect(&format!(
            "**Untested ULog file version.** Sealed with `--allow-untested-version`: this log's ULog file format version is {v}, and sfr is tested on versions 0 and 1 only (the ULog specification gives the current file format version as 1). It was read as version 1."
        ));
        l.expect("");
    }
    // Schema 4: the ignore-everything line exactly when the record says the flag was given.
    if seal.get("allow_ignore_all") == Some(&Value::Bool(true)) {
        l.expect(sfr_core::report::IGNORE_ALL_LINE);
        l.expect("");
    }
    // Schema 5: where a log that ends in the middle of a record stops, when it does.
    if let Some(Value::Object(t)) = log.get("truncated") {
        let (offset, trailing) = (plain(f(t, "offset")), plain(f(t, "trailing_bytes")));
        l.expect(&format!(
            "**Log ended mid-record.** log ended mid-record at byte {offset}; {trailing} trailing bytes not parsed. The digests and size cover every byte of the file; the rules read only the complete records before byte {offset}, and the unfinished record is discarded, as the ULog specification asks of a parser."
        ));
        l.expect("");
    }
    // Schema 4: what the reader skipped, when it skipped anything.
    let skipped = o(f(log, "skipped"), "skipped");
    let count = |k: &str| plain(f(skipped, k)).parse::<u64>().unwrap();
    let n = count("unknown_records") + count("orphan_data_records") + count("regions");
    if n > 0 {
        l.expect(&format!(
            "**Skipped.** {}.",
            esc(&format!(
                "sealed with {n} skipped messages: {} of an unknown type, {} data records without a subscription, {} region(s) ({} bytes) before an appended-data offset",
                count("unknown_records"),
                count("orphan_data_records"),
                count("regions"),
                count("region_bytes")
            ))
        ));
        l.expect("");
    }

    // Rules: one row per result, in order; then the findings of each failed rule.
    l.expect("## Rule checks");
    l.expect("");
    l.expect("Results are computed from data the log declares about itself; see VALIDATION.md.");
    l.expect("");
    let results = a(r, "results");
    let rows = l.table(&["Rule", "Status", "Name", "Found"]);
    assert_eq!(rows.len(), results.len(), "one row per rule");
    let mut r3 = Vec::new();
    for (row, res) in rows.iter().zip(results) {
        let res = o(res, "result");
        let want: Vec<String> = ["id", "status", "name", "found"]
            .iter()
            .map(|k| ev(f(res, k)))
            .collect();
        assert_eq!(row, &want, "rules row");
        if plain(f(res, "id")) == "R3" {
            // The detail lines that name a difference; the others list changes in flight.
            r3 = a(res, "detail")
                .iter()
                .map(plain)
                .filter(|d| d.contains(": baseline ") && d.contains(", flown "))
                .collect();
        }
    }
    for res in results {
        let res = o(res, "result");
        let status = plain(f(res, "status"));
        if status != "FAIL" && status != "WARN" {
            continue;
        }
        l.expect(&format!("### {} {status}", ev(f(res, "id"))));
        l.expect("");
        assert_eq!(l.item("Expected"), ev(f(res, "expected")));
        for d in a(res, "detail") {
            l.expect(&format!("- {}", ev(d)));
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
                vec![esc(&n), esc(&b), esc(&fl)]
            })
            .collect();
        assert_eq!(rows, want, "parameter differences are R3's detail lines");
    }

    // Parameters changed in flight: exactly the PARAM_CHANGED_IN_FLIGHT events, in order.
    l.expect("## Parameters changed in flight");
    l.expect("");
    l.expect(
        "R3 compares the parameters in effect at each ARM with the baseline; a change in flight of a parameter it does not ignore makes R3 WARN.",
    );
    l.expect("");
    let changes: Vec<&Obj> = a(r, "events")
        .iter()
        .map(|e| o(e, "event"))
        .filter(|e| plain(f(e, "kind")) == "PARAM_CHANGED_IN_FLIGHT")
        .collect();
    if changes.is_empty() {
        l.expect("No parameter changed in flight.");
        l.expect("");
    } else {
        let rows = l.table(&["Seq", "Boot time (s)", "Parameter", "Old", "New"]);
        assert_eq!(rows.len(), changes.len(), "one row per parameter change");
        for (row, e) in rows.iter().zip(changes) {
            assert_eq!(row[0], ev(f(e, "seq")));
            assert_eq!(micros(&row[1]).to_string(), plain(f(e, "boot_us")));
            assert_eq!(
                row[2..],
                [ev(f(e, "name")), ev(f(e, "old")), ev(f(e, "new"))]
            );
        }
    }

    // Transition tuning, exactly when the record has a vtol_type.
    if let Value::Object(vt) = f(vehicle, "vtol_type") {
        l.expect("## Transition tuning");
        l.expect("");
        assert_eq!(
            l.item("VTOL type"),
            format!("{} (VT_TYPE {})", ev(f(vt, "name")), ev(f(vt, "value")))
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
                assert_eq!(row, &vec![esc(&name), esc(&b), esc(&fl), mark.to_string()]);
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
        l.expect("The record holds no sealed topic digests.");
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
            assert_eq!(row[0], ev(f(t, "topic")));
            assert_eq!(row[1], ev(f(t, "multi_id")));
            assert_eq!(row[2], ev(f(t, "message_count")));
            match f(t, "first_timestamp_us") {
                Value::Null => assert_eq!(row[3], "none"),
                first => {
                    let (x, y) = row[3].split_once(" to ").expect("time span");
                    assert_eq!(micros(x).to_string(), plain(first));
                    assert_eq!(micros(y).to_string(), plain(f(t, "last_timestamp_us")));
                }
            }
            let digest = row[4]
                .strip_prefix('`')
                .and_then(|d| d.strip_suffix('`'))
                .expect("digest in a code span");
            assert!(
                digest.len() >= 8
                    && digest.bytes().all(|b| b.is_ascii_hexdigit())
                    && plain(f(t, "data_sha256")).starts_with(digest),
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
            assert_eq!(row[0], ev(f(e, "seq")));
            assert_eq!(micros(&row[1]).to_string(), plain(f(e, "boot_us")));
            assert_eq!(row[2], ev(f(e, "kind")));
            assert_eq!(row[3], e.get("category").map(ev).unwrap_or_default());
            let own = [
                "seq", "kind", "boot_us", "category", "utc_us", "topic", "instance", "index",
            ];
            let want = e
                .iter()
                .filter(|(k, _)| !own.contains(&k.as_str()))
                .map(|(k, v)| format!("{} {}", esc(k), ev(v)))
                .collect::<Vec<_>>()
                .join("; ");
            assert_eq!(row[4], want.trim(), "event {} detail", row[0]);
        }
        // The legend for `initial`, exactly when an event carries it.
        if events.iter().any(|e| o(e, "event").contains_key("initial")) {
            l.expect(
                "`initial` (ARM, FAILSAFE_SET): true when the event comes from the log's first `vehicle_status` sample, because the log starts armed or in failsafe; false when it is a change between two samples.",
            );
            l.expect("");
        }
    }

    // Log identity and digests.
    l.expect("## Log");
    l.expect("");
    assert_eq!(l.item("File"), esc(&file));
    assert_eq!(l.item("Size (bytes)"), ev(f(log, "size")));
    assert_eq!(
        l.item("Firmware"),
        format!("{} (git {})", ev(f(fw, "version")), ev(f(fw, "git")))
    );
    assert_eq!(l.item("SHA-256"), hex_span(f(log, "sha256")));
    assert_eq!(
        l.item("BLAKE3 (checked by verify --ulog like SHA-256; adds no security beyond it)"),
        hex_span(f(log, "blake3"))
    );
    assert_eq!(l.item("VTOL"), ev(f(vehicle, "is_vtol")));
    assert_eq!(l.item("MAV_TYPE"), ev(f(vehicle, "system_type")));
    l.expect("");

    // Seal.
    l.expect("## Seal");
    l.expect("");
    assert_eq!(
        l.item("Seal time (claimed by the sealer, not proven)"),
        ev(f(seal, "time_utc"))
    );
    let fp = hex_span(f(seal, "key_fingerprint"));
    assert_eq!(l.item("Key fingerprint"), fp);
    assert_eq!(
        l.item("Key custody (declared by the sealer; this report cannot attest it)"),
        ev(f(seal, "key_custody"))
    );
    let crates: Vec<String> = a(seal, "crypto_crates")
        .iter()
        .map(|c| {
            let c = o(c, "crate");
            format!("{} {}", ev(f(c, "name")), ev(f(c, "version")))
        })
        .collect();
    assert_eq!(l.item("Crypto crates (crate versions)"), crates.join(", "));
    assert_eq!(
        l.item("Merkle root"),
        format!(
            "{} ({}, {} leaves)",
            hex_span(f(merkle, "root")),
            ev(f(merkle, "algorithm")),
            ev(f(merkle, "leaf_count"))
        )
    );
    assert_eq!(l.item("Schema version"), ev(f(r, "schema_version")));
    l.expect("");

    // The verify command: the record and log file names, and the record's key fingerprint.
    l.expect("## Verify");
    l.expect("");
    l.expect(&format!(
        "With the public key whose fingerprint is {fp} saved as `sfr.pub`, in the directory that holds the record and the log:"
    ));
    l.expect("");
    // A record that declares an evaluation key is accepted only when asked.
    let allow = if plain(f(seal, "key_custody")) == "file-evaluation" {
        " --allow-evaluation-key"
    } else {
        ""
    };
    let record_name = format!("{stem}.sfr");
    match (shell_arg(&record_name), shell_arg(&file)) {
        (Some(record), Some(log)) => {
            let fence = l.next();
            assert!(
                fence.len() >= 3 && fence.chars().all(|c| c == '`'),
                "code fence"
            );
            let command = l.next();
            assert_eq!(
                command,
                format!("sfr verify {record} --pubkey sfr.pub{allow} --ulog {log}")
            );
            assert!(
                !command.contains(fence),
                "the fence is longer than any backtick run in the command"
            );
            l.expect(fence);
        }
        _ => {
            l.expect(&format!(
                "The file names hold a character that cannot be written safely in one command for \
                 every shell (a control character, a character that hides text, or a single \
                 quote), so the command takes them from shell variables. The log's file name, \
                 with each such character shown as a marker: {}. Set the variables `record` and \
                 `log` to the file names in your shell, then run the command.",
                esc(&file)
            ));
            for (title, lines) in [
                ("POSIX sh, bash:", posix_lines(&record_name, &file)),
                ("PowerShell:", powershell_lines(&record_name, &file)),
                (
                    "Then:",
                    vec![format!(
                        "sfr verify \"$record\" --pubkey sfr.pub{allow} --ulog \"$log\""
                    )],
                ),
            ] {
                l.expect("");
                l.expect(title);
                l.expect("");
                l.expect("```");
                for line in &lines {
                    l.expect(line);
                }
                l.expect("```");
            }
        }
    }
    l.expect("");
    l.expect("Without `--ulog`, `sfr verify` checks the record alone.");
    assert_eq!(l.peek(), None, "nothing after the verify section");
}
