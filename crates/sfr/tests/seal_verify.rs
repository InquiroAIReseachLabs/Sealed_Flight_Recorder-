//! Gate tests: keygen, sealed records, standalone and deep verify (SPEC B1.3, B1.7,
//! B1.10 Deterministic, Replay, Tamper property).
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use sfr_core::crypto::rustcrypto::RustCrypto;
use sfr_core::keys::parse_public_key_pem;
use sfr_core::verify::{VerifyError, verify};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

mod report_facts;

const RULES: &str = "examples/rules.default.toml";
const SEAL_TIME: &str = "2026-10-18T15:00:00Z";

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

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn scratch() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sfr-c3-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A fresh evaluation key pair in `dir`.
fn keygen(dir: &Path) -> (String, String) {
    let out = sfr(&[
        "keygen",
        "--evaluation-only",
        "--out",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    (
        dir.join("sfr.key").to_str().unwrap().to_string(),
        dir.join("sfr.pub").to_str().unwrap().to_string(),
    )
}

/// Seals `log` into `out` and returns the record path and the exit code.
fn seal(log: &str, baseline: &str, key: &str, out: &Path) -> (String, i32) {
    seal_with(log, RULES, baseline, key, out)
}

/// [`seal`] with a given rules file.
fn seal_with(log: &str, rules: &str, baseline: &str, key: &str, out: &Path) -> (String, i32) {
    let mut args = vec![
        "seal",
        log,
        "--rules",
        rules,
        "--baseline",
        baseline,
        "--key",
        key,
        "--evaluation-only",
        "--out",
        out.to_str().unwrap(),
        "--seal-time",
        SEAL_TIME,
    ];
    // The pyulog sample's PX4 version cannot be read; sfr seals it only when told to.
    if log == "testdata/pyulog/sample.ulg" {
        args.push("--allow-untested-version");
    }
    let o = sfr(&args);
    let stem = Path::new(log).file_stem().unwrap().to_str().unwrap();
    let path = out.join(format!("{stem}.sfr"));
    assert!(path.exists(), "record written: {}", text(&o));
    (path.to_str().unwrap().to_string(), o.status.code().unwrap())
}

fn pubkey(path: &str) -> [u8; 32] {
    parse_public_key_pem(&std::fs::read_to_string(path).unwrap()).unwrap()
}

const GOLDEN: &[(&str, &str, i32)] = &[
    ("pyulog_sample", "testdata/pyulog/sample.ulg", 2),
    (
        "v1.14.4_mc_flight",
        "testdata/sitl/v1.14.4/mc_flight.ulg",
        0,
    ),
    (
        "v1.17.0_failsafe_battery_empty",
        "testdata/sitl/v1.17.0/failsafe_battery_empty.ulg",
        1,
    ),
    (
        "v1.17.0_failsafe_gps_loss",
        "testdata/sitl/v1.17.0/failsafe_gps_loss.ulg",
        1,
    ),
    (
        "v1.17.0_gz_quadtailsitter_transition",
        "testdata/sitl/v1.17.0/gz_quadtailsitter_transition.ulg",
        0,
    ),
    (
        "v1.17.0_gz_x500_vision_hover",
        "testdata/sitl/v1.17.0/gz_x500_vision_hover.ulg",
        0,
    ),
    (
        "v1.17.0_mc_flight_1",
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        0,
    ),
    (
        "v1.17.0_mc_flight_2",
        "testdata/sitl/v1.17.0/mc_flight_2.ulg",
        0,
    ),
    (
        "v1.17.0_payload_two_sources",
        "testdata/sitl/v1.17.0/payload_two_sources.ulg",
        1,
    ),
    (
        "v1.17.0_vtol_transition",
        "testdata/sitl/v1.17.0/vtol_transition.ulg",
        0,
    ),
    (
        "v1.17.0_vtol_quadchute",
        "testdata/sitl/v1.17.0/vtol_quadchute.ulg",
        1,
    ),
    (
        "v1.17.0_vtol_transition_abort",
        "testdata/sitl/v1.17.0/vtol_transition_abort.ulg",
        1,
    ),
    (
        "synthetic_r4_quadchute_on_disarm",
        "testdata/synthetic/r4_quadchute_on_disarm.ulg",
        1,
    ),
    (
        "synthetic_custom_detection",
        "testdata/synthetic/custom_detection.ulg",
        0,
    ),
];

/// The rules file a golden log is sealed with: `testdata/rules/<name>.toml` when it exists (the
/// default rules plus sections that log needs, such as `[sealed_topics]`), else the default.
fn rules_for(name: &str) -> String {
    let own = format!("testdata/rules/{name}.toml");
    if root().join(&own).exists() {
        own
    } else {
        RULES.to_string()
    }
}

#[test]
fn keygen_writes_a_private_key_only_its_owner_can_read_and_never_overwrites() {
    let dir = scratch();
    let (key, _) = keygen(&dir);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let again = sfr(&[
        "keygen",
        "--evaluation-only",
        "--out",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(again.status.code(), Some(4));
    assert!(
        text(&again).contains("never overwrites"),
        "{}",
        text(&again)
    );
    let no_flag = sfr(&["keygen", "--out", scratch().to_str().unwrap()]);
    assert_eq!(no_flag.status.code(), Some(4));
    assert!(text(&no_flag).contains("pkcs11-token") && text(&no_flag).contains("--tpm-sealed"));
    let first = String::from_utf8_lossy(
        &sfr(&[
            "keygen",
            "--evaluation-only",
            "--out",
            scratch().to_str().unwrap(),
        ])
        .stdout,
    )
    .into_owned();
    assert!(
        first.starts_with("EVALUATION KEY") && first.contains("fingerprint  sha256:"),
        "{first}"
    );
}

#[test]
fn sealing_twice_is_byte_identical_and_failing_rules_still_write() {
    let dir = scratch();
    let (key, _) = keygen(&dir.join("k"));
    let log = "testdata/sitl/v1.17.0/failsafe_battery_empty.ulg";
    let bl = "testdata/baselines/v1.17.0_failsafe_battery_empty.params";
    let (a, code_a) = seal(log, bl, &key, &dir.join("a"));
    let (b, code_b) = seal(log, bl, &key, &dir.join("b"));
    assert_eq!(
        (code_a, code_b),
        (1, 1),
        "R4 fails, the record is still written, exit 1"
    );
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    // Never overwrite a record.
    let o = sfr(&[
        "seal",
        log,
        "--rules",
        RULES,
        "--baseline",
        bl,
        "--key",
        &key,
        "--evaluation-only",
        "--out",
        dir.join("a").to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("never overwrites"), "{}", text(&o));
}

#[test]
fn every_golden_log_seals_byte_identically_twice_and_replays() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    for (name, log, code) in GOLDEN {
        let baseline = format!("testdata/baselines/{name}.params");
        let rules = rules_for(name);
        let (record, sealed_code) =
            seal_with(log, &rules, &baseline, &key, &dir.join(name).join("a"));
        assert_eq!(sealed_code, *code, "{log}");
        let (again, again_code) =
            seal_with(log, &rules, &baseline, &key, &dir.join(name).join("b"));
        assert_eq!(again_code, *code, "{log}");
        assert_eq!(
            std::fs::read(&record).unwrap(),
            std::fs::read(&again).unwrap(),
            "{log}: two seals with the same key and --seal-time differ"
        );
        // The report beside each record (SPEC B1.8): written by seal, byte-identical across the
        // two seals, and exactly what the record renders to.
        let (report, report_again) = (format!("{record}.md"), format!("{again}.md"));
        let md = std::fs::read(&report).unwrap_or_else(|e| panic!("{report}: {e}"));
        assert_eq!(
            md,
            std::fs::read(&report_again).unwrap(),
            "{log}: two seals give different reports"
        );
        let parsed = sfr_core::json::parse(&std::fs::read(&record).unwrap()).unwrap();
        assert_eq!(
            String::from_utf8(md.clone()).unwrap(),
            sfr_core::report::render(&parsed).unwrap(),
            "{log}: the report is not the record's rendering"
        );
        report_facts::check(&parsed, &String::from_utf8(md).unwrap());
        let o = sfr(&[
            "verify",
            "--allow-evaluation-key",
            &record,
            "--pubkey",
            &public,
            "--ulog",
            log,
        ]);
        assert_eq!(o.status.code(), Some(0), "{log}: {}", text(&o));
        let t = text(&o);
        assert!(
            t.starts_with(
                "EVALUATION KEY: not for operational use\nIntegrity: VERIFIED (record and log)"
            ),
            "{t}"
        );
        let o = sfr(&[
            "verify",
            "--allow-evaluation-key",
            &record,
            "--pubkey",
            &public,
        ]);
        assert_eq!(o.status.code(), Some(0), "{log}: {}", text(&o));
    }
}

/// The committed examples (examples/reports/, made by scripts/make_example_reports.sh): each
/// report is what its record renders to, every fact in it comes from the record, and each record
/// verifies against its log with the committed public key.
#[test]
fn the_example_reports_render_from_their_records_and_verify() {
    for name in [
        "vtol_transition",
        "failsafe_gps_loss",
        "gz_quadtailsitter_transition",
        "gz_x500_vision_hover",
    ] {
        let record = format!("examples/reports/{name}.sfr");
        let parsed = sfr_core::json::parse(&std::fs::read(root().join(&record)).unwrap()).unwrap();
        let md = std::fs::read_to_string(root().join(format!("{record}.md"))).unwrap();
        assert_eq!(
            md,
            sfr_core::report::render(&parsed).unwrap(),
            "{record}: the committed report is not the record's rendering; run scripts/make_example_reports.sh"
        );
        report_facts::check(&parsed, &md);
        let log = format!("testdata/sitl/v1.17.0/{name}.ulg");
        let o = sfr(&[
            "verify",
            "--allow-evaluation-key",
            &record,
            "--pubkey",
            "examples/reports/sfr.pub",
            "--ulog",
            &log,
        ]);
        assert_eq!(o.status.code(), Some(0), "{record}: {}", text(&o));
    }
}

/// A baseline whose VT_B_TRANS_DUR differs from the flown value: R3 fails, and the report shows
/// the difference in the parameter differences table and marks it DIFF under transition tuning.
#[test]
fn a_report_shows_r3_differences_and_the_facts_check_catches_any_stray_line() {
    let dir = scratch();
    let (key, _) = keygen(&dir.join("k"));
    let log = "testdata/sitl/v1.17.0/vtol_transition.ulg";
    let original =
        std::fs::read_to_string(root().join("testdata/baselines/v1.17.0_vtol_transition.params"))
            .unwrap();
    let changed = original.replace("\tVT_B_TRANS_DUR\t10.0\t", "\tVT_B_TRANS_DUR\t12.0\t");
    assert_ne!(changed, original, "the baseline holds VT_B_TRANS_DUR 10.0");
    let baseline = dir.join("changed.params");
    std::fs::write(&baseline, changed).unwrap();
    let (record, code) = seal(log, baseline.to_str().unwrap(), &key, &dir.join("out"));
    assert_eq!(code, 1, "R3 fails, the record is still written, exit 1");
    let parsed = sfr_core::json::parse(&std::fs::read(&record).unwrap()).unwrap();
    let md = std::fs::read_to_string(format!("{record}.md")).unwrap();
    report_facts::check(&parsed, &md);
    for want in [
        "### R3 FAIL",
        "| Parameter | Baseline | Flown |",
        "| VT\\_B\\_TRANS\\_DUR | f32\\:12 | f32\\:10 |",
        "| VT\\_B\\_TRANS\\_DUR | f32\\:12 | f32\\:10 | DIFF |",
    ] {
        assert!(md.lines().any(|l| l == want), "line {want:?} in\n{md}");
    }
    // The check is not vacuous: one added line, one changed value, or one dropped line fails it.
    let lines: Vec<&str> = md.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.starts_with("- SHA-256: "))
        .unwrap();
    let mut added = lines.clone();
    added.insert(at + 1, "- Pilot: not in the record");
    let mut altered = lines.clone();
    let wrong = lines[at].replacen('`', "`0", 1);
    altered[at] = &wrong;
    let mut dropped = lines.clone();
    dropped.remove(at);
    for (what, bad) in [("added", added), ("altered", altered), ("dropped", dropped)] {
        let bad = format!("{}\n", bad.join("\n"));
        let caught = std::panic::catch_unwind(|| report_facts::check(&parsed, &bad)).is_err();
        assert!(caught, "the facts check misses a line {what}");
    }
}

/// Log text that Markdown, HTML, or a shell would read as something else, and file names
/// that a shell would split or read as an option: the report shows each value as its own text
/// (the facts check requires every ASCII punctuation character escaped) and its verify command,
/// run as written by bash in the directory that holds the files, verifies the record.
#[test]
fn hostile_log_text_and_file_names_give_a_literal_report_and_a_working_verify_command() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let mut log = std::fs::read(root().join("testdata/synthetic/custom_detection.ulg")).unwrap();
    let texts = [
        "abc|def &lt;b&gt;x&lt;/b&gt; &amp; ~~gone~~ $$x$$ :x: *em* _u_ [l](http://x) `t` \\ #1",
        "<script>alert(1)</script> - 1. + 2) > q\tafter tab",
    ];
    for (i, t) in texts.iter().enumerate() {
        // A ULog logging message ('L'): level '4' (warning), timestamp, text.
        let mut payload = vec![b'4'];
        payload.extend_from_slice(&(1_000_000u64 + i as u64).to_le_bytes());
        payload.extend_from_slice(t.as_bytes());
        log.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_le_bytes());
        log.push(b'L');
        log.extend_from_slice(&payload);
    }
    for name in ["-x.ulg", "--ulog", "tab\there 'q' $(x).ulg"] {
        let case = dir.join(format!("case{}", name.len()));
        std::fs::create_dir_all(&case).unwrap();
        let log_path = case.join(name);
        std::fs::write(&log_path, &log).unwrap();
        let (record, _) = seal_with(
            log_path.to_str().unwrap(),
            &rules_for("synthetic_custom_detection"),
            "testdata/baselines/synthetic_custom_detection.params",
            &key,
            &case,
        );
        let parsed = sfr_core::json::parse(&std::fs::read(&record).unwrap()).unwrap();
        let md = std::fs::read_to_string(format!("{record}.md")).unwrap();
        report_facts::check(&parsed, &md);
        for t in texts {
            assert!(
                md.contains(
                    &t.replace('\t', " ")
                        .chars()
                        .fold(String::new(), |mut e, c| {
                            if c.is_ascii_punctuation() {
                                e.push('\\');
                            }
                            e.push(c);
                            e
                        })
                ),
                "{name}: the log text, escaped, in\n{md}"
            );
        }
        std::fs::copy(&public, case.join("sfr.pub")).unwrap();
        let command = md
            .lines()
            .find(|l| l.starts_with("sfr verify "))
            .expect("verify command");
        let bin = report_facts::shell_arg(env!("CARGO_BIN_EXE_sfr"));
        let o = Command::new("bash")
            .arg("-c")
            .arg(format!("{bin} {}", &command["sfr ".len()..]))
            .current_dir(&case)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(0), "{name}: {command}: {}", text(&o));
        assert!(
            text(&o).contains("Integrity: VERIFIED (record and log)"),
            "{}",
            text(&o)
        );
    }
}

/// Seal writes a record and its report together or neither: an existing report, or a symbolic
/// link where the report would go (even a dangling one), stops it before it writes anything.
#[test]
fn seal_refuses_an_existing_report_or_a_link_in_its_place_and_writes_nothing() {
    let dir = scratch();
    let (key, _) = keygen(&dir.join("k"));
    let log = "testdata/synthetic/custom_detection.ulg";
    let seal_into = |out: &Path| {
        sfr(&[
            "seal",
            log,
            "--rules",
            &rules_for("synthetic_custom_detection"),
            "--baseline",
            "testdata/baselines/synthetic_custom_detection.params",
            "--key",
            &key,
            "--evaluation-only",
            "--out",
            out.to_str().unwrap(),
        ])
    };
    let only_report = dir.join("only_report");
    std::fs::create_dir_all(&only_report).unwrap();
    std::fs::write(only_report.join("custom_detection.sfr.md"), "kept\n").unwrap();
    let o = seal_into(&only_report);
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    assert!(text(&o).contains("never overwrites"), "{}", text(&o));
    assert!(!only_report.join("custom_detection.sfr").exists());
    assert_eq!(
        std::fs::read_to_string(only_report.join("custom_detection.sfr.md")).unwrap(),
        "kept\n"
    );
    #[cfg(unix)]
    {
        let link = dir.join("link");
        std::fs::create_dir_all(&link).unwrap();
        std::os::unix::fs::symlink(
            dir.join("no_such_dir/target"),
            link.join("custom_detection.sfr.md"),
        )
        .unwrap();
        let o = seal_into(&link);
        assert_eq!(o.status.code(), Some(4), "{}", text(&o));
        assert!(
            !link.join("custom_detection.sfr").exists(),
            "no record left"
        );
        // With the link gone, the same seal writes both files.
        std::fs::remove_file(link.join("custom_detection.sfr.md")).unwrap();
        let o = seal_into(&link);
        assert_eq!(o.status.code(), Some(0), "{}", text(&o));
        assert!(link.join("custom_detection.sfr").exists());
        assert!(link.join("custom_detection.sfr.md").exists());
    }
}

/// xorshift64*, so the flips are the same on every run.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// 1,000 single-byte flips: seeded offsets (an offset may repeat) and nonzero XOR values.
#[test]
fn a_thousand_seeded_byte_flips_in_a_record_all_fail_verification() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let (record, _) = seal(
        "testdata/sitl/v1.17.0/vtol_transition_abort.ulg",
        "testdata/baselines/v1.17.0_vtol_transition_abort.params",
        &key,
        &dir,
    );
    let bytes = std::fs::read(&record).unwrap();
    let pk = pubkey(&public);
    let crypto = RustCrypto;
    assert!(verify(&bytes, None, &crypto, &pk).is_ok());
    let mut rng = Rng(0x5eed_0001);
    for i in 0..1000 {
        let mut t = bytes.clone();
        let at = (rng.next() % t.len() as u64) as usize;
        let x = (rng.next() % 255 + 1) as u8;
        t[at] ^= x;
        match verify(&t, None, &crypto, &pk) {
            Err(VerifyError::Mismatch(_)) => {}
            other => panic!("flip {i} at byte {at} (xor {x:#04x}) was not detected: {other:?}"),
        }
    }
}

/// 1,000 single-byte flips: seeded offsets (an offset may repeat) and nonzero XOR values.
#[test]
fn a_thousand_seeded_byte_flips_in_a_log_all_fail_verification() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    // A complete log small enough to re-read 1,000 times (the shrunk fuzz seed).
    let log = "fuzz/seeds/ulog_ingest/sitl_v1.17.0_failsafe_gps_loss_shrunk.ulg";
    let (record, _) = seal(
        log,
        "testdata/baselines/v1.17.0_failsafe_gps_loss.params",
        &key,
        &dir,
    );
    let rec = std::fs::read(&record).unwrap();
    let ulg = std::fs::read(root().join(log)).unwrap();
    let pk = pubkey(&public);
    let crypto = RustCrypto;
    assert!(verify(&rec, Some(&mut &ulg[..]), &crypto, &pk).is_ok());
    let mut rng = Rng(0x5eed_0002);
    for i in 0..1000 {
        let mut t = ulg.clone();
        let at = (rng.next() % t.len() as u64) as usize;
        let x = (rng.next() % 255 + 1) as u8;
        t[at] ^= x;
        match verify(&rec, Some(&mut &t[..]), &crypto, &pk) {
            Err(VerifyError::Mismatch(_)) => {}
            other => panic!("flip {i} at byte {at} (xor {x:#04x}) was not detected: {other:?}"),
        }
    }
}

/// Sealed topics the flip tests cover, as (topic, golden flight, log): a PX4 topic in a SIH
/// flight and the external vision odometry of the Gazebo vision flight, each from the shrunk fuzz seed of that flight (fuzz/README.md), and the synthetic custom
/// topic in three instances, so a wrong instance number is caught. The small logs keep
/// a thousand deep verifies quick; each case is its own test, so the cases run in parallel.
type SealedCase = (&'static str, &'static str, &'static str);
const BATTERY_STATUS: SealedCase = (
    "battery_status",
    "v1.17.0_failsafe_gps_loss",
    "fuzz/seeds/ulog_ingest/sitl_v1.17.0_failsafe_gps_loss_shrunk.ulg",
);
const VISUAL_ODOMETRY: SealedCase = (
    "vehicle_visual_odometry",
    "v1.17.0_gz_x500_vision_hover",
    "fuzz/seeds/ulog_ingest/sitl_v1.17.0_gz_x500_vision_hover_shrunk.ulg",
);
const CUSTOM_DETECTION: SealedCase = (
    "custom_detection",
    "synthetic_custom_detection",
    "testdata/synthetic/custom_detection.ulg",
);

/// Seals `topic` from `log` against the baseline of golden flight `golden`.
fn sealed_topic_record((topic, golden, log): SealedCase) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let rules = dir.join("rules.toml");
    let rules_text = std::fs::read_to_string(root().join(RULES)).unwrap()
        + &format!("\n[sealed_topics]\ntopics = [\"{topic}\"]\n");
    std::fs::write(&rules, rules_text).unwrap();
    let baseline = format!("testdata/baselines/{golden}.params");
    let o = sfr(&[
        "seal",
        log,
        "--rules",
        rules.to_str().unwrap(),
        "--baseline",
        &baseline,
        "--key",
        &key,
        "--evaluation-only",
        "--out",
        dir.to_str().unwrap(),
        "--seal-time",
        SEAL_TIME,
    ]);
    let stem = std::path::Path::new(log)
        .file_stem()
        .unwrap()
        .to_string_lossy();
    let record = dir.join(format!("{stem}.sfr"));
    assert!(record.exists(), "{}", text(&o));
    let rec = std::fs::read(record).unwrap();
    assert!(
        String::from_utf8_lossy(&rec).contains(&format!("\"multi_id\":0,\"topic\":\"{topic}\"")),
        "the record seals {topic}"
    );
    (
        rec,
        std::fs::read(root().join(log)).unwrap(),
        pubkey(&public),
    )
}

/// 1,000 seeded single-byte flips inside sealed topic messages in the log.
/// Deep verify must name the topic and the instance whose message was flipped.
#[test]
fn a_thousand_flips_in_sealed_topic_messages_name_the_topic_and_instance() {
    flips_in_sealed_topic_messages(BATTERY_STATUS, 0x5eed_0003);
}

#[test]
fn a_thousand_flips_in_vision_odometry_messages_name_the_topic_and_instance() {
    flips_in_sealed_topic_messages(VISUAL_ODOMETRY, 0x5eed_0103);
}

#[test]
fn a_thousand_flips_in_custom_topic_messages_name_the_topic_and_instance() {
    flips_in_sealed_topic_messages(CUSTOM_DETECTION, 0x5eed_0203);
}

fn flips_in_sealed_topic_messages(case: SealedCase, rng_seed: u64) {
    let topic = case.0;
    let (rec, ulg, pk) = sealed_topic_record(case);
    let crypto = RustCrypto;
    assert!(verify(&rec, Some(&mut &ulg[..]), &crypto, &pk).is_ok());
    let spans: Vec<(usize, usize, u8)> = data_records(&ulg)
        .into_iter()
        .filter(|(_, _, t, _)| t == topic)
        .map(|(at, len, _, multi_id)| (at, len, multi_id))
        .collect();
    assert!(!spans.is_empty());
    let mut rng = Rng(rng_seed);
    for i in 0..1000 {
        let (start, len, multi_id) = spans[(rng.next() % spans.len() as u64) as usize];
        let at = start + (rng.next() % len as u64) as usize;
        let x = (rng.next() % 255 + 1) as u8;
        let mut t = ulg.clone();
        t[at] ^= x;
        let named = format!("sealed topic {topic} instance {multi_id} ");
        match verify(&rec, Some(&mut &t[..]), &crypto, &pk) {
            Err(VerifyError::Mismatch(m)) => {
                let all: Vec<&String> = std::iter::once(&m.first).chain(&m.also).collect();
                assert!(
                    all.iter().any(|l| l.starts_with(&named)),
                    "{topic} flip {i} at byte {at} (xor {x:#04x}) did not name {named:?}: {all:?}"
                );
            }
            other => {
                panic!("{topic} flip {i} at byte {at} (xor {x:#04x}) was not detected: {other:?}")
            }
        }
    }
}

/// 1,000 seeded single-byte flips inside the sealed topic digests in the record. Standalone
/// verify fails on every one; for each flip that leaves the record readable, deep verify names
/// the topic and the instance of the digest entry that was flipped.
#[test]
fn a_thousand_flips_in_a_sealed_topic_digest_fail_and_deep_verify_names_it() {
    flips_in_a_sealed_topic_digest(BATTERY_STATUS, 0x5eed_0004);
}

#[test]
fn a_thousand_flips_in_a_vision_odometry_digest_fail_and_deep_verify_names_it() {
    flips_in_a_sealed_topic_digest(VISUAL_ODOMETRY, 0x5eed_0104);
}

#[test]
fn a_thousand_flips_in_a_custom_topic_digest_fail_and_deep_verify_names_it() {
    flips_in_a_sealed_topic_digest(CUSTOM_DETECTION, 0x5eed_0204);
}

fn flips_in_a_sealed_topic_digest(case: SealedCase, rng_seed: u64) {
    let topic = case.0;
    let (rec, ulg, pk) = sealed_topic_record(case);
    let crypto = RustCrypto;
    let text = String::from_utf8_lossy(&rec).into_owned();
    let start = text.find("\"sealed_topics\":[").unwrap();
    let end = start + text[start..].find(']').unwrap();
    // Each digest entry is a flat object; deep verify names an entry by the instance the log
    // gives at that position, which is the instance the record holds there.
    let entries: Vec<(usize, String)> = text[start..end]
        .match_indices('{')
        .map(|(i, _)| {
            let obj = &text[start + i..end];
            let obj = &obj[..obj.find('}').unwrap()];
            let id = obj.split("\"multi_id\":").nth(1).unwrap();
            (start + i, id[..id.find(',').unwrap()].to_string())
        })
        .collect();
    let mut instances: Vec<&str> = entries.iter().map(|(_, id)| id.as_str()).collect();
    instances.dedup();
    assert!(!entries.is_empty());
    let mut rng = Rng(rng_seed);
    for i in 0..1000 {
        let at = start + (rng.next() % (end - start) as u64) as usize;
        let x = (rng.next() % 255 + 1) as u8;
        let mut t = rec.clone();
        t[at] ^= x;
        match verify(&t, None, &crypto, &pk) {
            Err(VerifyError::Mismatch(_)) => {}
            other => {
                panic!(
                    "{topic} flip {i} at byte {at} (xor {x:#04x}) passed standalone verify: {other:?}"
                )
            }
        }
        // A flip that leaves the record readable is named by deep verify.
        if let Err(VerifyError::Mismatch(m)) = verify(&t, Some(&mut &ulg[..]), &crypto, &pk) {
            let readable = sfr_core::json::parse(&t).is_ok() && !m.first.contains("canonical");
            if readable && !m.first.starts_with("field ") && !m.first.starts_with("unknown field") {
                let entry = entries.iter().rev().find(|(from, _)| *from <= at);
                let all: Vec<&String> = std::iter::once(&m.first).chain(&m.also).collect();
                let named = match entry {
                    Some((_, id)) => format!("sealed topic {topic} instance {id} "),
                    None => format!("sealed topic {topic} instance "),
                };
                assert!(
                    all.iter().any(|l| l.starts_with(&named)),
                    "{topic} flip {i} at byte {at} (xor {x:#04x}) did not name {named:?}: {all:?}"
                );
            }
        }
    }
    assert_eq!(instances.len(), entries.len(), "one entry per instance");
}

/// Offsets and lengths of the data payloads of every 'D' record, with their topic names and
/// instances (`multi_id`).
fn data_records(log: &[u8]) -> Vec<(usize, usize, String, u8)> {
    let mut topics = std::collections::BTreeMap::new();
    let mut out = Vec::new();
    let mut pos = 16;
    while pos + 3 <= log.len() {
        let size = u16::from_le_bytes([log[pos], log[pos + 1]]) as usize;
        let ty = log[pos + 2];
        let body = &log[pos + 3..pos + 3 + size];
        if ty == b'A' {
            topics.insert(
                u16::from_le_bytes([body[1], body[2]]),
                (String::from_utf8_lossy(&body[3..]).into_owned(), body[0]),
            );
        } else if ty == b'D' {
            let id = u16::from_le_bytes([body[0], body[1]]);
            let (topic, multi_id) = topics.get(&id).cloned().unwrap_or_default();
            out.push((pos + 5, size - 2, topic, multi_id));
        }
        pos += 3 + size;
    }
    out
}

/// The `sfr_verify` fuzz seeds must stay valid records listed in the fuzz target: when a record
/// format change leaves them stale, the target's "only the seeds verify" check becomes vacuous
/// and mutations no longer reach the Merkle and signature code (fuzz/README.md says how to
/// re-seal them).
#[test]
fn the_sfr_verify_fuzz_seeds_verify_and_are_listed_in_the_target() {
    let pk = pubkey(
        root()
            .join("fuzz/seeds/sfr_verify_key.pub")
            .to_str()
            .unwrap(),
    );
    let target = std::fs::read_to_string(root().join("fuzz/fuzz_targets/sfr_verify.rs")).unwrap();
    let mut seeds = 0;
    for e in std::fs::read_dir(root().join("fuzz/seeds/sfr_verify")).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let rec = std::fs::read(&p).unwrap();
        assert!(
            verify(&rec, None, &RustCrypto, &pk).is_ok(),
            "fuzz seed {name} no longer verifies; re-seal the seeds (fuzz/README.md)"
        );
        assert!(
            target.contains(&format!("../seeds/sfr_verify/{name}")),
            "fuzz seed {name} is not listed in fuzz/fuzz_targets/sfr_verify.rs"
        );
        seeds += 1;
    }
    assert_eq!(
        target
            .matches("include_bytes!(\"../seeds/sfr_verify/")
            .count(),
        seeds,
        "the target lists exactly the seed files"
    );
}

#[test]
fn mismatches_are_named_precisely() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let log = "testdata/sitl/v1.17.0/mc_flight_1.ulg";
    let (record, _) = seal(
        log,
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        &key,
        &dir,
    );
    let rec = std::fs::read_to_string(&record).unwrap();

    // 1. One byte of an event in the record: deep verify names the sequence number and field.
    let at = rec.find("\"result\":\"ACCEPTED\"").unwrap() + "\"result\":\"ACCEPTE".len();
    let mut flipped = rec.clone().into_bytes();
    flipped[at] = b'E';
    let bad = dir.join("event.sfr");
    std::fs::write(&bad, &flipped).unwrap();
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        bad.to_str().unwrap(),
        "--pubkey",
        &public,
        "--ulog",
        log,
    ]);
    assert_eq!(o.status.code(), Some(1));
    let t = text(&o);
    assert!(
        t.contains(
            "Integrity: FAILED: event seq 2 (COMMAND) field `result`: sealed \"ACCEPTEE\", found \"ACCEPTED\""
        ),
        "{t}"
    );
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        bad.to_str().unwrap(),
        "--pubkey",
        &public,
    ]);
    assert_eq!(o.status.code(), Some(1));
    // The record declares an evaluation key: the warning comes first even when it fails.
    assert!(
        String::from_utf8_lossy(&o.stdout).starts_with(
            "EVALUATION KEY: not for operational use\nIntegrity: FAILED: Merkle root mismatch"
        ),
        "{}",
        text(&o)
    );
    let j = sfr(&[
        "verify",
        "--allow-evaluation-key",
        bad.to_str().unwrap(),
        "--pubkey",
        &public,
        "--json",
    ]);
    assert!(
        String::from_utf8_lossy(&j.stdout).contains("\"key_custody\": \"file-evaluation\""),
        "{}",
        text(&j)
    );
    assert!(
        text(&o).contains("Integrity: FAILED: Merkle root mismatch"),
        "{}",
        text(&o)
    );

    // 2. One parameter value in the log: names the parameter with sealed and found values.
    let mut ulg = std::fs::read(root().join(log)).unwrap();
    let needle = b"float MPC_XY_VEL_MAX";
    let p = ulg.windows(needle.len()).position(|w| w == needle).unwrap() + needle.len();
    ulg[p..p + 4].copy_from_slice(&9.5f32.to_le_bytes());
    let edited = dir.join("param.ulg");
    std::fs::write(&edited, &ulg).unwrap();
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        &record,
        "--pubkey",
        &public,
        "--ulog",
        edited.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o)
            .contains("Integrity: FAILED: parameter MPC_XY_VEL_MAX: sealed f32:12, found f32:9.5"),
        "{}",
        text(&o)
    );

    // 3. One byte elsewhere (a data field of a topic sfr does not read): log digest mismatch.
    let mut ulg = std::fs::read(root().join(log)).unwrap();
    let (off, len, topic, _) = data_records(&ulg)
        .into_iter()
        .find(|(_, len, t, _)| t == "sensor_combined" && *len > 12)
        .unwrap();
    ulg[off + len - 1] ^= 0x01;
    let edited = dir.join("elsewhere.ulg");
    std::fs::write(&edited, &ulg).unwrap();
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        &record,
        "--pubkey",
        &public,
        "--ulog",
        edited.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(1), "{topic}");
    assert!(
        text(&o).contains("Integrity: FAILED: log digest mismatch: sha256 sealed"),
        "{}",
        text(&o)
    );
}

#[test]
fn unknown_schema_version_wrong_key_and_evaluation_custody_are_refused() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let (other_key, other_pub) = keygen(&dir.join("k2"));
    let _ = other_key;
    let (record, _) = seal(
        "testdata/sitl/v1.17.0/mc_flight_2.ulg",
        "testdata/baselines/v1.17.0_mc_flight_2.params",
        &key,
        &dir,
    );
    let rec = std::fs::read_to_string(&record).unwrap();
    // Only schema 4 verifies: a later number is unknown, and so are schemas 1 and 2, whose
    // leaves are not bound to their section, and schema 3, whose results come from rules that
    // read less of the log. The version is read before anything else, so a
    // relabelled record is refused for that, whatever else is wrong with it.
    for other in [5, 3, 2, 1] {
        let relabelled = rec.replacen(
            "\"schema_version\":4",
            &format!("\"schema_version\":{other}"),
            1,
        );
        let bad = dir.join(format!("v{other}.sfr"));
        std::fs::write(&bad, relabelled).unwrap();
        let o = sfr(&[
            "verify",
            "--allow-evaluation-key",
            bad.to_str().unwrap(),
            "--pubkey",
            &public,
            "--no-report",
        ]);
        assert_eq!(o.status.code(), Some(1), "schema {other}");
        assert!(
            text(&o).contains(&format!(
                "unknown schema_version {other}; this verifier knows schema 4 only"
            )),
            "{}",
            text(&o)
        );
    }

    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        &record,
        "--pubkey",
        &other_pub,
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o).contains("not by the given public key"),
        "{}",
        text(&o)
    );

    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        &record,
        "--pubkey",
        &public,
        "--require-hardware-key",
    ]);
    assert_eq!(o.status.code(), Some(1));
    assert!(
        text(&o).contains(
            "Integrity: REFUSED: --require-hardware-key does not accept a record that declares custody file-evaluation"
        ),
        "{}",
        text(&o)
    );

    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        &record,
        "--pubkey",
        &public,
        "--trust-anchor",
        "ca.pem",
    ]);
    assert_eq!(o.status.code(), Some(4));
}

#[test]
fn seal_key_sources_and_seal_time_are_checked() {
    let dir = scratch();
    let (key, _) = keygen(&dir.join("k"));
    let base = [
        "seal",
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        "--rules",
        RULES,
        "--baseline",
        "testdata/baselines/v1.17.0_mc_flight_1.params",
    ];
    let with = |extra: &[&str]| {
        let mut a: Vec<&str> = base.to_vec();
        a.extend_from_slice(extra);
        sfr(&a)
    };
    let o = with(&["--key", &key]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("evaluation only"), "{}", text(&o));
    let o = with(&["--key-uri", "pkcs11:token=x"]);
    assert_eq!(o.status.code(), Some(4));
    let out = dir.join("t");
    let o = with(&[
        "--key",
        &key,
        "--evaluation-only",
        "--out",
        out.to_str().unwrap(),
        "--seal-time",
        "2026-10-18 15:00",
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("RFC 3339"), "{}", text(&o));
    let o = with(&[
        "--key",
        &key,
        "--evaluation-only",
        "--out",
        out.to_str().unwrap(),
        "--seal-time",
        "2026-10-18T17:00:00+02:00",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let rec = std::fs::read_to_string(out.join("mc_flight_1.sfr")).unwrap();
    assert!(rec.contains("\"time_utc\":\"2026-10-18T15:00:00Z\""));
    assert!(rec.contains("\"key_custody\":\"file-evaluation\""));
}

/// `verify` reports integrity and the flight rules on separate lines: a record that verifies and
/// whose rules failed is `Integrity: VERIFIED` and `Flight rules: FAIL (<ids>)`, exit 0, in text
/// and in JSON.
#[test]
fn integrity_and_flight_rules_are_reported_apart() {
    let record = "examples/reports/gz_x500_vision_hover.sfr";
    let key = "examples/reports/sfr.pub";
    let o = sfr(&["verify", "--allow-evaluation-key", record, "--pubkey", key]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(
        out.starts_with(
            "EVALUATION KEY: not for operational use\nIntegrity: VERIFIED (record)\nFlight rules: FAIL (R7)\n"
        ),
        "{out}"
    );
    assert!(!out.contains("\nstatus "), "{out}");
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        record,
        "--pubkey",
        key,
        "--json",
    ]);
    let json = String::from_utf8_lossy(&o.stdout).to_string();
    for part in [
        "\"integrity\": \"VERIFIED\"",
        "\"flight_rules\": \"FAIL\"",
        "\"R7\"",
    ] {
        assert!(json.contains(part), "{part} in {json}");
    }
    // A record whose rules pass or warn: the warned rules are named.
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        "examples/reports/vtol_transition.sfr",
        "--pubkey",
        key,
    ]);
    assert!(
        String::from_utf8_lossy(&o.stdout).contains("\nFlight rules: WARN (R4)\n"),
        "{}",
        text(&o)
    );
    // A record that fails its integrity check says nothing about its rules but that they are
    // unknown.
    let dir = scratch();
    let sealed = std::fs::read_to_string(root().join(record)).unwrap();
    let bad = dir.join("changed.sfr");
    std::fs::write(&bad, sealed.replacen("\"command\":", "\"command\":1", 1)).unwrap();
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        bad.to_str().unwrap(),
        "--pubkey",
        key,
    ]);
    assert_eq!(o.status.code(), Some(1));
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(out.contains("\nIntegrity: FAILED: "), "{out}");
    assert!(
        out.contains("\nFlight rules: UNKNOWN (the record failed its integrity check, so its rule results cannot be trusted)\n"),
        "{out}"
    );
    // The key and custody it names are shown, marked as unproven claims.
    assert!(
        out.ends_with("custody   unattested (declared file-evaluation)\n"),
        "{out}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// Without `--pubkey` or `--trust-anchor` nothing is verified: `Integrity: NOT CHECKED` on
/// standard output, exit 4, the key and custody the record claims marked as unproven, and how to
/// check it.
#[test]
fn verify_without_a_trusted_key_says_the_signer_is_not_checked() {
    let record = "examples/reports/vtol_transition.sfr";
    let o = sfr(&["verify", record]);
    assert_eq!(o.status.code(), Some(4));
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    for part in [
        "Integrity: NOT CHECKED (no trusted key given)\n",
        "Flight rules: UNKNOWN (the record's integrity was not checked)\n",
        "key       sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45 (named by the record, not proven)\n",
        "custody   unattested (declared file-evaluation)\n",
        "through a channel you trust",
    ] {
        assert!(out.contains(part), "{part} in {out}");
    }
    assert!(!out.contains("VERIFIED"), "{out}");
}

/// The report is bound to its record (SPEC B1.8): verify re-renders it from the verified record
/// and requires the `.sfr.md` beside the record, or the one `--report` names, to be identical.
/// Any edit to the report is an integrity failure naming the line; a missing report is said to
/// be unchecked.
#[test]
fn an_edited_report_fails_verification_and_names_the_line() {
    let dir = scratch();
    let (key, public) = keygen(&dir);
    let out = dir.join("out");
    let (record, code) = seal(
        "testdata/sitl/v1.17.0/vtol_transition.ulg",
        "testdata/baselines/v1.17.0_vtol_transition.params",
        &key,
        &out,
    );
    assert_eq!(code, 0);
    let report = format!("{record}.md");
    let original = std::fs::read_to_string(&report).unwrap();
    // The sibling report matches.
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        &record,
        "--pubkey",
        &public,
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(
        String::from_utf8_lossy(&o.stdout)
            .contains(&format!("report    {report} matches the record\n")),
        "{}",
        text(&o)
    );
    // Edits to the report, each alone: a status, a rule result, a digest, a deleted line, an
    // added line, a trailing byte.
    let lines: Vec<&str> = original.split('\n').collect();
    let status_line = lines
        .iter()
        .position(|l| l.contains("**Status: WARN**"))
        .unwrap();
    let edits: Vec<(&str, String, usize)> = vec![
        (
            "status",
            original.replacen("**Status: WARN**", "**Status: PASS**", 1),
            status_line + 1,
        ),
        (
            "rule result",
            original.replacen("| R3 | PASS |", "| R3 | FAIL |", 1),
            0,
        ),
        ("digest", original.replacen("sha256", "sha265", 1), 0),
        (
            "deleted line",
            lines
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != status_line)
                .map(|(_, l)| *l)
                .collect::<Vec<_>>()
                .join("\n"),
            status_line + 1,
        ),
        (
            "added line",
            format!("{original}Approved by the operator.\n"),
            0,
        ),
        ("trailing byte", format!("{original} "), 0),
    ];
    for (what, edited, line) in edits {
        assert_ne!(edited, original, "{what}: the edit changed nothing");
        std::fs::write(&report, &edited).unwrap();
        let o = sfr(&[
            "verify",
            "--allow-evaluation-key",
            &record,
            "--pubkey",
            &public,
        ]);
        assert_eq!(o.status.code(), Some(1), "{what}: {}", text(&o));
        let shown = String::from_utf8_lossy(&o.stdout).to_string();
        assert!(
            shown.contains(&format!("Integrity: FAILED: report {report}: ")),
            "{what}: {shown}"
        );
        if line > 0 {
            assert!(shown.contains(&format!("line {line} ")), "{what}: {shown}");
        }
        assert!(!shown.contains("VERIFIED"), "{what}: {shown}");
    }
    std::fs::write(&report, &original).unwrap();
    // --report names another file; a report of another record fails too.
    let other = dir.join("other");
    let (other_record, code) = seal(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        &key,
        &other,
    );
    assert_eq!(code, 0);
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        &record,
        "--pubkey",
        &public,
        "--report",
        &format!("{other_record}.md"),
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(
        text(&o).contains("line 3 differs from the record"),
        "{}",
        text(&o)
    );
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        &record,
        "--pubkey",
        &public,
        "--report",
        "/nonexistent.sfr.md",
    ]);
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    // Without a report beside it the record does not verify: a report that was not checked
    // proves nothing about the report a reader has. --no-report opts out, and says so.
    std::fs::remove_file(&report).unwrap();
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        &record,
        "--pubkey",
        &public,
    ]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(
        text(&o).contains("Integrity: FAILED: report: no report found beside the record: expected"),
        "{}",
        text(&o)
    );
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        &record,
        "--pubkey",
        &public,
        "--no-report",
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(
        String::from_utf8_lossy(&o.stdout).contains(
            "report    NOT CHECKED (--no-report): the report was not compared with the record, so it proves nothing\n"
        ),
        "{}",
        text(&o)
    );
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("sfr: notice: --no-report:"),
        "{}",
        text(&o)
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// SPEC B1.5: `seal` refuses a log whose PX4 version is outside v1.14 to v1.17, or cannot be
/// read, unless given `--allow-untested-version`; then the signed record (schema 3,
/// `seal.allow_untested_version`) and its report say so. A tested version records false, flag
/// or no flag. Schema 1 records still verify.
#[test]
fn an_untested_px4_version_is_refused_unless_allowed_and_then_recorded() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let out = dir.join("out");
    let sample = "testdata/pyulog/sample.ulg";
    let base = [
        "seal",
        sample,
        "--rules",
        RULES,
        "--baseline",
        "testdata/baselines/pyulog_sample.params",
    ];
    for extra in [
        &["--dry-run"][..],
        &[
            "--key",
            &key,
            "--evaluation-only",
            "--out",
            out.to_str().unwrap(),
        ][..],
    ] {
        let o = sfr(&[&base[..], extra].concat());
        assert_eq!(o.status.code(), Some(4), "{}", text(&o));
        assert!(
            text(&o).contains("sfr is tested on PX4 v1.14 to v1.17 only; nothing written")
                && text(&o).contains("--allow-untested-version"),
            "{}",
            text(&o)
        );
        assert!(!out.exists(), "nothing written");
    }
    let o = sfr(&[
        &base[..],
        &[
            "--key",
            &key,
            "--evaluation-only",
            "--out",
            out.to_str().unwrap(),
        ],
        &["--allow-untested-version"],
    ]
    .concat());
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    assert!(text(&o).contains("sfr: warning: "), "{}", text(&o));
    let record = out.join("sample.sfr");
    let bytes = std::fs::read_to_string(&record).unwrap();
    assert!(
        bytes.contains("\"allow_untested_version\":true"),
        "flag in the record"
    );
    assert!(bytes.contains("\"schema_version\":4"), "schema 4");
    let report = std::fs::read_to_string(out.join("sample.sfr.md")).unwrap();
    assert!(
        report.contains(sfr_core::report::UNTESTED_VERSION_LINE),
        "{report}"
    );
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        record.to_str().unwrap(),
        "--pubkey",
        &public,
    ]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    // The flag is signed: turning it off breaks the record.
    let off = dir.join("off.sfr");
    std::fs::write(
        &off,
        bytes.replace(
            "\"allow_untested_version\":true",
            "\"allow_untested_version\":false",
        ),
    )
    .unwrap();
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        off.to_str().unwrap(),
        "--pubkey",
        &public,
    ]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    // A tested version: the flag changes nothing, and the record says false.
    let tested = dir.join("tested");
    let o = sfr(&[
        "seal",
        "testdata/sitl/v1.14.4/mc_flight.ulg",
        "--rules",
        RULES,
        "--baseline",
        "testdata/baselines/v1.14.4_mc_flight.params",
        "--key",
        &key,
        "--evaluation-only",
        "--out",
        tested.to_str().unwrap(),
        "--allow-untested-version",
    ]);
    assert!(o.status.code().unwrap() <= 2, "{}", text(&o));
    let bytes = std::fs::read_to_string(tested.join("mc_flight.sfr")).unwrap();
    assert!(bytes.contains("\"allow_untested_version\":false"));
    assert!(
        !std::fs::read_to_string(tested.join("mc_flight.sfr.md"))
            .unwrap()
            .contains("Untested PX4 version")
    );
    // The fuzz seeds are sealed records of the current schema.
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        "fuzz/seeds/sfr_verify/sitl_v1.17.0_failsafe_gps_loss_shrunk.sfr",
        "--pubkey",
        "fuzz/seeds/sfr_verify_key.pub",
        "--no-report",
    ]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    assert!(text(&v).contains("Integrity: VERIFIED"), "{}", text(&v));
    std::fs::remove_dir_all(dir).unwrap();
}
