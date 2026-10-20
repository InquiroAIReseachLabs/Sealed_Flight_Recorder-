//! The sandbox engine (`sfr-wasm`) and the CLI are one engine (SPEC B1.10 Sandbox,
//! Deterministic). For the same log, rules, baseline, key and seal time, `sfr_wasm::seal` gives
//! the CLI's record, report, exit code and output text, and `sfr_wasm::verify` the CLI's verify
//! output, on golden logs that cover sealed topics, watched parameters on a tailsitter, payload
//! commands with R7, and an unsupported firmware. The headless browser test
//! (`tests/browser/sandbox.test.mjs`) holds the built page to the CLI on every golden log.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use sfr_core::json::Value;
use sfr_wasm::{Input, Key, SealRequest, Stream, VerifyRequest};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const SEAL_TIME: &str = "2026-10-18T15:00:00Z";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A fresh directory; the CLI runs inside it with bare file names, so its messages and output
/// name files as the sandbox does (a browser gives no path).
fn scratch() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sfr-c6-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sfr(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sfr"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("sfr binary runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

/// Links `rel` (relative to the repository) into `dir` as `name`.
fn link(dir: &Path, rel: &str, name: &str) {
    let target = root().join(rel).canonicalize().unwrap();
    std::os::unix::fs::symlink(target, dir.join(name)).unwrap();
}

/// An evaluation key pair in `dir` (`sfr.key`, `sfr.pub`).
fn keygen(dir: &Path) {
    let o = sfr(dir, &["keygen", "--evaluation-only", "--out", "."]);
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// Seals `log` in `dir` with the sandbox engine, as the page does, with the key file `sfr.key`
/// (`None` for the baseline: the sandbox's no-baseline text).
fn sandbox_seal(
    dir: &Path,
    log: &str,
    rules: &str,
    baseline: Option<&str>,
    allow_untested_version: bool,
) -> Result<sfr_wasm::SealOutput, sfr_wasm::Failure> {
    let log_bytes = read(dir, log);
    let rules_bytes = read(dir, rules);
    let baseline_bytes = baseline.map(|b| read(dir, b));
    let key = read(dir, "sfr.key");
    sfr_wasm::seal(SealRequest {
        log: Stream {
            name: log,
            size: log_bytes.len() as u64,
            reader: &mut &log_bytes[..],
        },
        rules: Input {
            name: rules,
            bytes: &rules_bytes,
        },
        baseline: baseline
            .zip(baseline_bytes.as_deref())
            .map(|(name, bytes)| Input { name, bytes }),
        key: Key::File(Input {
            name: "sfr.key",
            bytes: &key,
        }),
        seal_time: SEAL_TIME,
        allow_untested_version,
    })
}

/// The CLI's seal in `dir`, writing into `dir/cli/`. Its stdout names `cli/<name>`; the sandbox
/// names `<name>`.
fn cli_seal(dir: &Path, log: &str, rules: &str, baseline: &str, allow_untested: bool) -> Output {
    let allow: &[&str] = if allow_untested {
        &["--allow-untested-version"]
    } else {
        &[]
    };
    sfr(
        dir,
        &[
            &[
                "seal",
                log,
                "--rules",
                rules,
                "--baseline",
                baseline,
                "--key",
                "sfr.key",
                "--evaluation-only",
                "--seal-time",
                SEAL_TIME,
                "--out",
                "cli",
            ],
            allow,
        ]
        .concat(),
    )
}

/// Golden logs, each with what it covers: (name, log, rules).
const CASES: &[(&str, &str, &str)] = &[
    // R1 fails (exit 2) and its PX4 version cannot be read: sealed with --allow-untested-version.
    (
        "pyulog_sample",
        "testdata/pyulog/sample.ulg",
        "examples/rules.default.toml",
    ),
    // [sealed_topics] with a custom topic, two instances.
    (
        "synthetic_custom_detection",
        "testdata/synthetic/custom_detection.ulg",
        "testdata/rules/synthetic_custom_detection.toml",
    ),
    // [sealed_topics] with a PX4 topic.
    (
        "v1.17.0_gz_x500_vision_hover",
        "testdata/sitl/v1.17.0/gz_x500_vision_hover.ulg",
        "testdata/rules/v1.17.0_gz_x500_vision_hover.toml",
    ),
    // [payload_commands] and R7 ([authorized_sources]) with commands from two sources.
    (
        "v1.17.0_payload_two_sources",
        "testdata/sitl/v1.17.0/payload_two_sources.ulg",
        "testdata/rules/v1.17.0_payload_two_sources.toml",
    ),
    // The quad tailsitter: VTOL type tailsitter and the watched transition parameters.
    (
        "v1.17.0_gz_quadtailsitter_transition",
        "testdata/sitl/v1.17.0/gz_quadtailsitter_transition.ulg",
        "examples/rules.default.toml",
    ),
];

#[test]
fn the_sandbox_seals_the_cli_record_report_exit_code_and_text() {
    for (name, log, rules) in CASES {
        let dir = scratch();
        keygen(&dir);
        let log_name = Path::new(log).file_name().unwrap().to_str().unwrap();
        link(&dir, log, log_name);
        link(&dir, rules, "rules.toml");
        link(
            &dir,
            &format!("testdata/baselines/{name}.params"),
            "baseline.params",
        );
        // The pyulog sample's PX4 version cannot be read: both need --allow-untested-version.
        let allow = *name == "pyulog_sample";
        let cli = cli_seal(&dir, log_name, "rules.toml", "baseline.params", allow);
        let code = cli.status.code().unwrap();
        assert!(code <= 2, "{name}: {}", stderr(&cli));
        let s = sandbox_seal(&dir, log_name, "rules.toml", Some("baseline.params"), allow).unwrap();
        assert_eq!(s.exit_code, code, "{name}");
        assert_eq!(
            s.record,
            read(&dir, &format!("cli/{}", s.record_name)),
            "{name}: the records differ"
        );
        assert_eq!(
            s.report.as_bytes(),
            read(&dir, &format!("cli/{}", s.report_name)),
            "{name}: the reports differ"
        );
        assert_eq!(
            s.text,
            stdout(&cli).replace("cli/", ""),
            "{name}: the output text differs"
        );
        assert_eq!(
            s.notes.iter().map(|n| format!("{n}\n")).collect::<String>(),
            stderr(&cli),
            "{name}: the notes differ"
        );
    }
}

#[test]
fn without_a_baseline_the_sandbox_seals_what_the_cli_seals_from_the_no_baseline_text() {
    let dir = scratch();
    keygen(&dir);
    link(&dir, "testdata/sitl/v1.17.0/mc_flight_1.ulg", "flight.ulg");
    link(&dir, "examples/rules.default.toml", "rules.toml");
    std::fs::write(dir.join(sfr_wasm::NO_BASELINE_NAME), sfr_wasm::NO_BASELINE).unwrap();
    let cli = cli_seal(
        &dir,
        "flight.ulg",
        "rules.toml",
        sfr_wasm::NO_BASELINE_NAME,
        false,
    );
    assert_eq!(cli.status.code(), Some(1), "{}", stderr(&cli));
    let s = sandbox_seal(&dir, "flight.ulg", "rules.toml", None, false).unwrap();
    assert_eq!(s.exit_code, 1);
    assert_eq!(s.record, read(&dir, "cli/flight.sfr"));
    assert_eq!(s.report.as_bytes(), read(&dir, "cli/flight.sfr.md"));
    // R2 and R3 fail and say why; nothing is assumed.
    assert!(
        s.text
            .contains("R2    FAIL    firmware matches baseline     1.17.0"),
        "{}",
        s.text
    );
    assert!(s.text.contains("baseline absent, flown"), "{}", s.text);
}

#[test]
fn the_in_browser_key_seals_an_evaluation_record_the_cli_verifies() {
    let dir = scratch();
    link(&dir, "testdata/sitl/v1.17.0/mc_flight_1.ulg", "flight.ulg");
    let rules = std::fs::read(root().join("examples/rules.default.toml")).unwrap();
    let baseline =
        std::fs::read(root().join("testdata/baselines/v1.17.0_mc_flight_1.params")).unwrap();
    let log = read(&dir, "flight.ulg");
    let seed = [42u8; 32];
    let key = sfr_wasm::evaluation_key(&seed).unwrap();
    let s = sfr_wasm::seal(SealRequest {
        log: Stream {
            name: "flight.ulg",
            size: log.len() as u64,
            reader: &mut &log[..],
        },
        rules: Input {
            name: "rules.default.toml",
            bytes: &rules,
        },
        baseline: Some(Input {
            name: "flight.params",
            bytes: &baseline,
        }),
        key: Key::Seed(&seed),
        seal_time: "2026-10-19T12:00:00+02:00",
        allow_untested_version: false,
    })
    .unwrap();
    assert_eq!(s.exit_code, 0, "{}", s.text);
    assert!(
        s.text
            .starts_with("EVALUATION KEY: not for operational use\n")
    );
    assert!(
        s.report
            .starts_with("EVALUATION KEY: not for operational use\n")
    );
    let record = sfr_core::json::parse(&s.record).unwrap();
    let seal = |k: &str| match &record {
        Value::Object(r) => match r.get("seal") {
            Some(Value::Object(seal)) => match seal.get(k) {
                Some(Value::Str(v)) => v.clone(),
                other => panic!("seal.{k}: {other:?}"),
            },
            other => panic!("seal: {other:?}"),
        },
        other => panic!("record: {other:?}"),
    };
    assert_eq!(seal("key_label"), sfr_wasm::SANDBOX_KEY_LABEL);
    assert_eq!(seal("key_custody"), "file-evaluation");
    assert_eq!(seal("key_fingerprint"), key.fingerprint);
    assert_eq!(seal("time_utc"), "2026-10-19T10:00:00Z");
    std::fs::write(dir.join("flight.sfr"), &s.record).unwrap();
    // The report the sandbox wrote goes beside the record, so the CLI checks it against the record.
    std::fs::write(dir.join("flight.sfr.md"), &s.report).unwrap();
    std::fs::write(dir.join("sfr.pub"), &key.public_key_pem).unwrap();
    let o = sfr(
        &dir,
        &[
            "verify",
            "--allow-evaluation-key",
            "flight.sfr",
            "--pubkey",
            "sfr.pub",
            "--ulog",
            "flight.ulg",
        ],
    );
    assert_eq!(o.status.code(), Some(0), "{}", stdout(&o));
    assert!(stdout(&o).contains("VERIFIED (record and log)"));
}

/// The CLI's verify output in `dir`, and the sandbox's for the same files.
fn both_verify(dir: &Path, record: &str, log: Option<&str>) -> (Output, sfr_wasm::VerifyOutput) {
    let mut args = vec![
        "verify",
        "--allow-evaluation-key",
        record,
        "--pubkey",
        "sfr.pub",
    ];
    if let Some(l) = log {
        args.extend(["--ulog", l]);
    }
    // A record with no report beside it is verified alone, as the sandbox does (it takes none).
    if !dir.join(format!("{record}.md")).is_file() {
        args.push("--no-report");
    }
    let cli = sfr(dir, &args);
    let record_bytes = read(dir, record);
    let pubkey = read(dir, "sfr.pub");
    let log_bytes = log.map(|l| read(dir, l));
    let mut reader = log_bytes.as_deref();
    // The CLI checks <record>.md beside the record when it exists; the sandbox is given it.
    let report_name = format!("{record}.md");
    let report_bytes = dir
        .join(&report_name)
        .is_file()
        .then(|| read(dir, &report_name));
    // The page gives the engine its clock; here, this machine's.
    let now = sfr_core::seal::format_utc(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
    );
    let out = sfr_wasm::verify(VerifyRequest {
        now: &now,
        record: Input {
            name: record,
            bytes: &record_bytes,
        },
        public_key: Input {
            name: "sfr.pub",
            bytes: &pubkey,
        },
        log: log.zip(reader.as_mut()).map(|(name, r)| Stream {
            name,
            size: log_bytes.as_ref().map_or(0, |b| b.len() as u64),
            reader: r,
        }),
        report: report_bytes.as_deref().map(|bytes| Input {
            name: &report_name,
            bytes,
        }),
    })
    .unwrap();
    (cli, out)
}

#[test]
fn the_sandbox_verify_prints_what_the_cli_prints_verified_or_not() {
    let dir = scratch();
    keygen(&dir);
    link(&dir, "testdata/sitl/v1.17.0/mc_flight_1.ulg", "flight.ulg");
    link(&dir, "examples/rules.default.toml", "rules.toml");
    link(
        &dir,
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        "baseline.params",
    );
    let cli = cli_seal(&dir, "flight.ulg", "rules.toml", "baseline.params", false);
    assert_eq!(cli.status.code(), Some(0), "{}", stderr(&cli));
    std::fs::copy(dir.join("cli/flight.sfr"), dir.join("flight.sfr")).unwrap();
    // A changed command id in a copy of the record, as scripts/run_demo.sh step d does.
    let mut tampered = read(&dir, "flight.sfr");
    let text = String::from_utf8(tampered.clone()).unwrap();
    let kind = text.find("\"kind\":\"COMMAND\"").unwrap();
    let at = text[..kind].rfind("\"command\":").unwrap() + "\"command\":".len();
    tampered[at] = if tampered[at] == b'9' {
        b'1'
    } else {
        tampered[at] + 1
    };
    std::fs::write(dir.join("tampered.sfr"), &tampered).unwrap();
    // One changed byte in a copy of the log.
    let mut log = read(&dir, "flight.ulg");
    let mid = log.len() / 2;
    log[mid] ^= 0x40;
    std::fs::write(dir.join("changed.ulg"), &log).unwrap();
    for (record, log, code, headline) in [
        ("flight.sfr", None, 0, "Integrity: VERIFIED (record)"),
        (
            "flight.sfr",
            Some("flight.ulg"),
            0,
            "Integrity: VERIFIED (record and log)",
        ),
        (
            "tampered.sfr",
            None,
            1,
            "Integrity: FAILED: Merkle root mismatch",
        ),
        ("tampered.sfr", Some("flight.ulg"), 1, "Integrity: FAILED: "),
        ("flight.sfr", Some("changed.ulg"), 1, "Integrity: FAILED: "),
    ] {
        let (cli, out) = both_verify(&dir, record, log);
        assert_eq!(cli.status.code(), Some(code), "{record} {log:?}");
        assert_eq!(out.exit_code, code, "{record} {log:?}");
        assert_eq!(out.text, stdout(&cli), "{record} {log:?}");
        assert!(out.headline.starts_with(headline), "{}", out.headline);
    }
    // The structured results: each mismatch split into its parts, from the text sfr-core wrote.
    let (_, out) = both_verify(&dir, "tampered.sfr", Some("flight.ulg"));
    let first = &out.mismatches[0];
    assert_eq!(first.kind, "event", "{first:?}");
    assert_eq!(first.event_kind.as_deref(), Some("COMMAND"), "{first:?}");
    assert_eq!(first.field.as_deref(), Some("command"), "{first:?}");
    let (sealed, found) = (first.sealed.clone().unwrap(), first.found.clone().unwrap());
    assert_ne!(sealed, found);
    assert!(
        out.text
            .contains(&format!("Integrity: FAILED: {}\n", first.text)),
        "{}",
        out.text
    );
    assert!(
        out.text.contains(&format!(
            "event seq {} (COMMAND) field `command`: sealed {sealed}, found {found}",
            first.seq.unwrap()
        )),
        "{}",
        out.text
    );
    assert!(out.mismatches.iter().any(|m| m.kind == "merkle_root"));
    let (_, out) = both_verify(&dir, "tampered.sfr", None);
    assert_eq!(out.mismatches[0].kind, "merkle_root");
    let (_, out) = both_verify(&dir, "flight.sfr", Some("changed.ulg"));
    assert!(
        out.mismatches.iter().all(|m| m.kind != "record"),
        "{:?}",
        out.mismatches
    );
    // A changed parameter at log start, as the demo changes it.
    let mut log = read(&dir, "flight.ulg");
    let key = b"float MPC_XY_VEL_MAX";
    let at = log
        .windows(key.len())
        .enumerate()
        .position(|(o, w)| w == key && o >= 2 && log[o - 2] == b'P')
        .unwrap()
        + key.len();
    log[at..at + 4].copy_from_slice(&7.0f32.to_le_bytes());
    std::fs::write(dir.join("param.ulg"), &log).unwrap();
    let (cli, out) = both_verify(&dir, "flight.sfr", Some("param.ulg"));
    assert_eq!(out.text, stdout(&cli));
    let m = &out.mismatches[0];
    assert_eq!(
        (
            m.kind,
            m.parameter.as_deref(),
            m.sealed.as_deref(),
            m.found.as_deref()
        ),
        (
            "parameter",
            Some("MPC_XY_VEL_MAX"),
            Some("f32:12"),
            Some("f32:7")
        ),
        "{m:?}"
    );
    // A record verified with another key names both fingerprints.
    let other = dir.join("other");
    std::fs::create_dir_all(&other).unwrap();
    keygen(&other);
    std::fs::copy(other.join("sfr.pub"), dir.join("sfr.pub")).unwrap();
    let (cli, out) = both_verify(&dir, "flight.sfr", None);
    assert_eq!(out.text, stdout(&cli));
    let m = out.mismatches.iter().find(|m| m.kind == "key").unwrap();
    assert!(m.sealed.as_deref().unwrap().starts_with("sha256:"), "{m:?}");
    assert_ne!(m.sealed, m.found);
    // The JSON the page receives parses and carries the same parts.
    let json = sfr_wasm::result::verify_json(&out);
    let v = sfr_core::json::parse(json.as_bytes()).unwrap();
    let Value::Object(v) = v else {
        panic!("{json}")
    };
    assert_eq!(v.get("verified"), Some(&Value::Bool(false)));
    assert_eq!(v.get("text"), Some(&Value::Str(out.text.clone())));
}

#[test]
fn the_sandbox_refuses_bad_input_with_the_cli_exit_code_and_message() {
    let dir = scratch();
    keygen(&dir);
    link(&dir, "testdata/synthetic/custom_detection.ulg", "c.ulg");
    link(
        &dir,
        "testdata/rules/synthetic_custom_detection.toml",
        "rules.toml",
    );
    link(
        &dir,
        "testdata/baselines/synthetic_custom_detection.params",
        "baseline.params",
    );
    let full = read(&dir, "c.ulg");
    std::fs::write(dir.join("truncated.ulg"), &full[..full.len() - 7]).unwrap();
    let topics: Vec<String> = (0..65).map(|i| format!("\"t{i}\"")).collect();
    // The default rules plus 65 sealed topics: a usage error (exit 4).
    let default = std::fs::read_to_string(root().join("examples/rules.default.toml")).unwrap();
    std::fs::write(
        dir.join("many.toml"),
        format!(
            "{default}\n[sealed_topics]\ntopics = [{}]\n",
            topics.join(", ")
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("bad.params"),
        "# Firmware: 1.17.0\n1\t1\tX\t2\t7\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("latin1.toml"),
        b"format = \"sfr-rules/1\" # \xe9\n",
    )
    .unwrap();
    for (log, rules, baseline, code) in [
        ("c.ulg", "many.toml", "baseline.params", 4),
        ("c.ulg", "rules.toml", "bad.params", 3),
        ("c.ulg", "latin1.toml", "baseline.params", 3),
        ("truncated.ulg", "rules.toml", "baseline.params", 3),
    ] {
        let cli = cli_seal(&dir, log, rules, baseline, false);
        assert_eq!(cli.status.code(), Some(code), "{rules} {baseline}");
        let f = sandbox_seal(&dir, log, rules, Some(baseline), false).unwrap_err();
        assert_eq!(f.code, code, "{}", f.message);
        assert_eq!(format!("sfr: {}\n", f.message), stderr(&cli));
    }
    // A key file that is no key: exit 4 from both, naming the file.
    std::fs::write(dir.join("sfr.key"), "not a key\n").unwrap();
    let cli = cli_seal(&dir, "c.ulg", "rules.toml", "baseline.params", false);
    assert_eq!(cli.status.code(), Some(4));
    let f = sandbox_seal(&dir, "c.ulg", "rules.toml", Some("baseline.params"), false).unwrap_err();
    assert_eq!(f.code, 4);
    assert_eq!(format!("sfr: {}\n", f.message), stderr(&cli));
}
