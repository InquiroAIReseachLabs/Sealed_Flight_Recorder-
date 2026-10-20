//! The report (SPEC B1.8) is required by `verify` and safe to read: a verify with no matching
//! report fails unless told `--no-report`; a forged report fails whatever it is called; the Merkle
//! root and key fingerprint stand at the top of the report; and a character that hides or
//! reorders text (U+202E and the other Unicode format characters) is shown, never acted on, in
//! the report, in the terminal output and in `--json`.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const RULES: &str = "examples/rules.default.toml";
const RLO: char = '\u{202e}';

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sfr(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sfr"))
        .current_dir(root())
        .args(args)
        .output()
        .expect("sfr binary runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn text(o: &Output) -> String {
    format!("{}{}", stdout(o), String::from_utf8_lossy(&o.stderr))
}

fn scratch() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sfr-report-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Seals `log` (a path under the repository, or an absolute one) into `dir/out` with a new
/// evaluation key. Returns (record, report, public key).
fn seal(log: &Path, baseline: &str, dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let keys = dir.join("k");
    let o = sfr(&[
        "keygen",
        "--evaluation-only",
        "--out",
        keys.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let out = dir.join("out");
    let o = sfr(&[
        "seal",
        log.to_str().unwrap(),
        "--rules",
        RULES,
        "--baseline",
        baseline,
        "--key",
        keys.join("sfr.key").to_str().unwrap(),
        "--evaluation-only",
        "--seal-time",
        "2026-10-18T15:00:00Z",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(o.status.code().unwrap() <= 2, "{}", text(&o));
    let stem = log.file_stem().unwrap().to_string_lossy().into_owned();
    (
        out.join(format!("{stem}.sfr")),
        out.join(format!("{stem}.sfr.md")),
        keys.join("sfr.pub"),
    )
}

const FLIGHT: &str = "testdata/sitl/v1.17.0/failsafe_gps_loss.ulg";
const BASELINE: &str = "testdata/baselines/v1.17.0_failsafe_gps_loss.params";

#[test]
fn a_record_without_its_report_does_not_verify_unless_told_not_to_look() {
    let dir = scratch();
    let (record, report, public) = seal(&root().join(FLIGHT), BASELINE, &dir);
    let (r, p) = (record.to_str().unwrap(), public.to_str().unwrap());
    // With its report beside it, it verifies and names the report.
    let v = sfr(&["verify", "--allow-evaluation-key", r, "--pubkey", p]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    assert!(stdout(&v).contains("matches the record\n"), "{}", text(&v));
    // Without it, it does not: exit 1, and the reason says what to do.
    std::fs::remove_file(&report).unwrap();
    let v = sfr(&["verify", "--allow-evaluation-key", r, "--pubkey", p]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    let out = stdout(&v);
    assert!(
        out.contains("Integrity: FAILED: report: no report found beside the record: expected")
            && out.contains("--report <file>")
            && out.contains("--no-report"),
        "{out}"
    );
    assert!(!out.contains("VERIFIED"), "{out}");
    let j = sfr(&[
        "verify",
        "--allow-evaluation-key",
        r,
        "--pubkey",
        p,
        "--json",
    ]);
    assert_eq!(j.status.code(), Some(1));
    assert!(stdout(&j).contains("\"verified\": false"), "{}", text(&j));
    // --no-report verifies the record alone and says, in the output and on stderr, that nothing
    // was compared.
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        r,
        "--pubkey",
        p,
        "--no-report",
    ]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    assert!(
        stdout(&v).contains("report    NOT CHECKED (--no-report):"),
        "{}",
        text(&v)
    );
    assert!(
        String::from_utf8_lossy(&v.stderr).contains("sfr: notice: --no-report:"),
        "{}",
        text(&v)
    );
    let j = sfr(&[
        "verify",
        "--allow-evaluation-key",
        r,
        "--pubkey",
        p,
        "--no-report",
        "--json",
    ]);
    assert!(
        stdout(&j).contains("\"report_checked\": false"),
        "{}",
        text(&j)
    );
    // It does not look at a report that is there either, and the two options contradict.
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        r,
        "--pubkey",
        p,
        "--no-report",
        "--report",
        "x.sfr.md",
    ]);
    assert_eq!(v.status.code(), Some(4), "{}", text(&v));
    assert!(text(&v).contains("contradict each other"), "{}", text(&v));
}

#[test]
fn a_forged_report_under_another_name_does_not_stand_in_for_the_real_one() {
    // The report verify looks at is <record>.md. A forged report under any other name
    // was never looked at, and the record still verified.
    let dir = scratch();
    let (record, report, public) = seal(&root().join(FLIGHT), BASELINE, &dir);
    let (r, p) = (record.to_str().unwrap(), public.to_str().unwrap());
    let real = std::fs::read_to_string(&report).unwrap();
    assert!(real.contains("**Status: FAIL**"), "the flight fails R4");
    // The forger removes the real report, and leaves one that says PASS under another name.
    let forged = real
        .replace("**Status: FAIL**", "**Status: PASS**")
        .replace("| R4 | FAIL |", "| R4 | PASS |");
    std::fs::remove_file(&report).unwrap();
    let elsewhere = record.with_file_name("flight_PASS.sfr.md");
    std::fs::write(&elsewhere, &forged).unwrap();
    let v = sfr(&["verify", "--allow-evaluation-key", r, "--pubkey", p]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    assert!(
        stdout(&v).contains("report: no report found beside the record"),
        "{}",
        text(&v)
    );
    assert!(!stdout(&v).contains("VERIFIED"), "{}", text(&v));
    // Pointing verify at it names the first line that differs from what the record renders.
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        r,
        "--pubkey",
        p,
        "--report",
        elsewhere.to_str().unwrap(),
    ]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    assert!(
        stdout(&v).contains("Integrity: FAILED: report ")
            && stdout(&v).contains("differs from the record"),
        "{}",
        text(&v)
    );
    // The same forgery under the right name fails the same way.
    std::fs::write(&report, forged).unwrap();
    let v = sfr(&["verify", "--allow-evaluation-key", r, "--pubkey", p]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    assert!(
        stdout(&v).contains("differs from the record"),
        "{}",
        text(&v)
    );
}

/// The record's and the report's first lines hold the Merkle root and the key fingerprint, and
/// they are what `sfr verify` prints.
#[test]
fn the_merkle_root_and_key_fingerprint_stand_under_the_title_and_match_verify() {
    let dir = scratch();
    let (record, report, public) = seal(&root().join(FLIGHT), BASELINE, &dir);
    let md = std::fs::read_to_string(&report).unwrap();
    let lines: Vec<&str> = md.lines().collect();
    // Line 1 is the EVALUATION KEY banner of this evaluation record, then a blank, the title,
    // a blank, then the root and the fingerprint.
    assert_eq!(lines[0], "EVALUATION KEY: not for operational use");
    assert!(
        lines[2].starts_with("# Sealed flight record: "),
        "{}",
        lines[2]
    );
    assert!(lines[4].starts_with("- Merkle root: `"), "{}", lines[4]);
    assert!(
        lines[5].starts_with("- Key fingerprint: `sha256:"),
        "{}",
        lines[5]
    );
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        record.to_str().unwrap(),
        "--pubkey",
        public.to_str().unwrap(),
    ]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let out = stdout(&v);
    let root_hex = lines[4].split('`').nth(1).unwrap();
    let fingerprint = lines[5].split('`').nth(1).unwrap();
    assert!(out.contains(&format!("key       {fingerprint}\n")), "{out}");
    assert!(out.contains(&format!("merkle    {root_hex} (")), "{out}");
}

#[test]
fn a_right_to_left_override_in_a_value_is_shown_in_the_report_the_terminal_and_json() {
    // A log named with U+202E reached the report heading, the record name and the
    // verify output unchanged ("Trojan Source", CVE-2021-42574).
    let dir = scratch();
    let named = dir.join(format!("flight{RLO}gnp.ulg"));
    std::fs::copy(root().join(FLIGHT), &named).unwrap();
    let (record, report, public) = seal(&named, BASELINE, &dir);
    // The record keeps the character: its canonical form writes every character but the
    // controls as itself, and that is what its signature covers.
    assert!(std::fs::read_to_string(&record).unwrap().contains(RLO));

    // The report shows it as text, escaped for Markdown like any other punctuation, and its verify
    // command takes the names from shell variables set with the character written out in octal.
    let md = std::fs::read_to_string(&report).unwrap();
    assert!(!md.contains(RLO), "a raw U+202E in the report");
    assert!(md.contains("flight\\<U\\+202E\\>gnp\\.ulg"), "{md}");
    assert!(
        md.contains("log=\"$(printf 'flight\\342\\200\\256gnp.ulgx')\"; log=\"${log%x}\""),
        "{md}"
    );

    // Neither seal's output nor verify's, in text or JSON, holds the raw character.
    let (r, p) = (record.to_str().unwrap(), public.to_str().unwrap());
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        r,
        "--pubkey",
        p,
        "--ulog",
        named.to_str().unwrap(),
    ]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let out = text(&v);
    assert!(
        !out.contains(RLO),
        "a raw U+202E in the terminal output: {out}"
    );
    assert!(out.contains("flight<U+202E>gnp"), "{out}");
    let j = sfr(&[
        "verify",
        "--allow-evaluation-key",
        r,
        "--pubkey",
        p,
        "--json",
    ]);
    let json = text(&j);
    assert!(!json.contains(RLO), "a raw U+202E in the JSON: {json}");
    assert!(json.contains("flight\\u202egnp"), "{json}");
    // A missing file named with it is an error that does not carry the character to stderr.
    let bad = dir.join(format!("missing{RLO}file.sfr"));
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        bad.to_str().unwrap(),
        "--pubkey",
        p,
    ]);
    assert_eq!(v.status.code(), Some(4), "{}", text(&v));
    assert!(!text(&v).contains(RLO), "{}", text(&v));
    assert!(text(&v).contains("missing<U+202E>file.sfr"), "{}", text(&v));
}

#[test]
fn every_unicode_format_character_is_shown_in_the_report_not_acted_on() {
    // One log name per class of character: zero width, the line separator, a language tag, and the
    // isolates. Each report must show the marker and hold none of the raw characters.
    for (c, marker) in [
        ('\u{200b}', "<U+200B>"),
        ('\u{2028}', "<U+2028>"),
        ('\u{e0041}', "<U+E0041>"),
        ('\u{2066}', "<U+2066>"),
        ('\u{feff}', "<U+FEFF>"),
    ] {
        let dir = scratch();
        let named = dir.join(format!("a{c}b.ulg"));
        std::fs::copy(root().join(FLIGHT), &named).unwrap();
        let (record, report, public) = seal(&named, BASELINE, &dir);
        let md = std::fs::read_to_string(&report).unwrap();
        assert!(!md.contains(c), "{marker} left raw in the report");
        let escaped: String = marker
            .chars()
            .flat_map(|m| {
                if m.is_ascii_punctuation() {
                    vec!['\\', m]
                } else {
                    vec![m]
                }
            })
            .collect();
        assert!(md.contains(&format!("a{escaped}b")), "{marker} in {md}");
        let v = sfr(&[
            "verify",
            "--allow-evaluation-key",
            record.to_str().unwrap(),
            "--pubkey",
            public.to_str().unwrap(),
        ]);
        assert_eq!(v.status.code(), Some(0), "{marker}: {}", text(&v));
        assert!(!text(&v).contains(c), "{marker} left raw in the output");
    }
}

#[test]
fn a_log_given_under_another_name_verifies_and_the_output_says_so() {
    // Deep verify binds the log's content, not its name, and a renamed log verified
    // "record and log" with nothing said. It still verifies; now the output notes it.
    let dir = scratch();
    let (record, _, public) = seal(&root().join(FLIGHT), BASELINE, &dir);
    let other = dir.join("some_other_vehicle.ulg");
    std::fs::copy(root().join(FLIGHT), &other).unwrap();
    let (r, p) = (record.to_str().unwrap(), public.to_str().unwrap());
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        r,
        "--pubkey",
        p,
        "--ulog",
        other.to_str().unwrap(),
    ]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    assert!(
        stdout(&v).contains("Integrity: VERIFIED (record and log)")
            && stdout(&v).contains(
                "note      the log given is named some_other_vehicle.ulg, the record was sealed from one named failsafe_gps_loss.ulg;"
            ),
        "{}",
        text(&v)
    );
    // Under its own name there is no note.
    let same = dir.join("failsafe_gps_loss.ulg");
    std::fs::copy(root().join(FLIGHT), &same).unwrap();
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        r,
        "--pubkey",
        p,
        "--ulog",
        same.to_str().unwrap(),
    ]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    assert!(!stdout(&v).contains("note      "), "{}", text(&v));
}
