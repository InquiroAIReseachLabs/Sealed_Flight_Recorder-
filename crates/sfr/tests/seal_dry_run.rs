//! Chunk 2 gate tests for `sfr seal --dry-run` (SPEC B1.4, B1.5, B1.6).
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const RULES: &str = "examples/rules.default.toml";

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

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn dry_run(log: &str, rules: &str, baseline: &str, json: bool) -> Output {
    let mut args = vec![
        "seal",
        log,
        "--rules",
        rules,
        "--baseline",
        baseline,
        "--dry-run",
    ];
    if json {
        args.push("--json");
    }
    sfr(&args)
}

/// A fresh scratch directory under the system temp dir, removed by the caller.
fn scratch() -> PathBuf {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "sfr-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// (expected-file name, log path, exit code) for every log in testdata/.
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
        "v1.17.0_vtol_transition",
        "testdata/sitl/v1.17.0/vtol_transition.ulg",
        0,
    ),
    (
        "v1.17.0_vtol_transition_abort",
        "testdata/sitl/v1.17.0/vtol_transition_abort.ulg",
        1,
    ),
];

#[test]
fn golden_logs_match_reviewed_expected_files() {
    // Every .ulg under testdata/ must have a golden entry.
    let mut logs = Vec::new();
    for dir in [
        "testdata/pyulog",
        "testdata/sitl/v1.14.4",
        "testdata/sitl/v1.17.0",
    ] {
        for e in std::fs::read_dir(root().join(dir)).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "ulg") {
                logs.push(format!(
                    "{dir}/{}",
                    p.file_name().unwrap().to_string_lossy()
                ));
            }
        }
    }
    logs.sort();
    let mut listed: Vec<String> = GOLDEN.iter().map(|g| g.1.to_string()).collect();
    listed.sort();
    assert_eq!(
        logs, listed,
        "every log in testdata/ has a reviewed expected file"
    );

    for (name, log, code) in GOLDEN {
        let baseline = format!("testdata/baselines/{name}.params");
        let out = dry_run(log, RULES, &baseline, true);
        assert_eq!(
            out.status.code(),
            Some(*code),
            "{log}: exit code; stderr: {}",
            stderr(&out)
        );
        let expected =
            std::fs::read_to_string(root().join(format!("testdata/expected/{name}.json"))).unwrap();
        assert!(
            stdout(&out) == expected,
            "{log}: output differs from testdata/expected/{name}.json; run scripts/testdata/regenerate.sh expected and compare"
        );
    }
}

#[test]
fn output_is_deterministic() {
    let a = dry_run(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        RULES,
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        true,
    );
    let b = dry_run(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        RULES,
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        true,
    );
    assert_eq!(a.stdout, b.stdout);
}

#[test]
fn table_prints_results_and_event_count() {
    let out = dry_run(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        RULES,
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        false,
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let s = stdout(&out);
    for line in [
        "R1    PASS",
        "R2    PASS",
        "R3    PASS",
        "R4    PASS",
        "R5    PASS",
        "R6    N/A",
        "events    22",
        "status    PASS",
    ] {
        assert!(s.contains(line), "missing `{line}` in:\n{s}");
    }
    assert!(
        s.contains("sha256    6e7b6956c20422aa9f31a13e7f074e80cba85760928fd895eed941e9492823fc"),
        "{s}"
    );
    assert!(s.contains("nothing is signed or written"), "{s}");
}

#[test]
fn missing_topic_exits_2_and_names_it() {
    let dir = scratch();
    let rules = dir.join("rules.toml");
    std::fs::write(&rules, "format = \"sfr-rules/1\"\n[required_topics]\ntopics = [\"vehicle_status\", \"airspeed_validated\"]\n").unwrap();
    let out = dry_run(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        rules.to_str().unwrap(),
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        false,
    );
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stdout(&out)
            .contains("R1    FAIL    required topics present       missing: airspeed_validated"),
        "{}",
        stdout(&out)
    );

    // The old pyulog sample has no failsafe_flags topic and an older vehicle_status.
    let out = dry_run(
        "testdata/pyulog/sample.ulg",
        RULES,
        "testdata/baselines/pyulog_sample.params",
        false,
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stdout(&out).contains("missing: vehicle_status.vehicle_type, failsafe_flags"),
        "{}",
        stdout(&out)
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn truncated_log_exits_3_and_names_the_offset() {
    let dir = scratch();
    let bytes = std::fs::read(root().join("testdata/sitl/v1.17.0/mc_flight_1.ulg")).unwrap();
    // Header area, mid header, mid definitions, mid data, last byte removed.
    for cut in [
        0usize,
        10,
        17,
        3_000,
        200_001,
        bytes.len() / 2 + 7,
        bytes.len() - 1,
    ] {
        let path = dir.join(format!("cut_{cut}.ulg"));
        std::fs::write(&path, &bytes[..cut]).unwrap();
        let out = dry_run(
            path.to_str().unwrap(),
            RULES,
            "testdata/baselines/v1.17.0_mc_flight_1.params",
            false,
        );
        let err = stderr(&out);
        assert_eq!(out.status.code(), Some(3), "cut at {cut}: {err}");
        assert!(
            err.contains(&format!("cut_{cut}.ulg")),
            "names the file: {err}"
        );
        assert!(
            err.contains("truncated") && err.contains("offset"),
            "names the offset: {err}"
        );
        assert!(!err.contains("panicked"), "{err}");
    }
    // Not a ULog at all.
    let path = dir.join("not_a_log.ulg");
    std::fs::write(&path, b"This is not a ULog file, just text.").unwrap();
    let out = dry_run(
        path.to_str().unwrap(),
        RULES,
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        false,
    );
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn malformed_rules_or_baseline_exit_3_with_the_line() {
    let dir = scratch();
    let rules = dir.join("bad.toml");
    std::fs::write(&rules, "format = \"sfr-rules/1\"\n[required_topics]\ntopics = [\"vehicle_status\"]\nthreshold = 2\n").unwrap();
    let out = dry_run(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        rules.to_str().unwrap(),
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        false,
    );
    assert_eq!(out.status.code(), Some(3));
    assert!(
        stderr(&out).contains("bad.toml: line 4: unknown key `required_topics.threshold`"),
        "{}",
        stderr(&out)
    );

    let baseline = dir.join("bad.params");
    std::fs::write(
        &baseline,
        "# Firmware: 1.17.0\n1\t1\tMPC_XY_VEL_MAX\tfast\t9\n",
    )
    .unwrap();
    let out = dry_run(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        RULES,
        baseline.to_str().unwrap(),
        false,
    );
    assert_eq!(out.status.code(), Some(3));
    assert!(
        stderr(&out).contains("bad.params: line 2: MPC_XY_VEL_MAX: `fast` is not a number"),
        "{}",
        stderr(&out)
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn one_changed_baseline_parameter_fails_r3_with_both_values() {
    let dir = scratch();
    let text =
        std::fs::read_to_string(root().join("testdata/baselines/v1.17.0_mc_flight_1.params"))
            .unwrap();
    let line = text
        .lines()
        .find(|l| l.starts_with("1\t1\tMPC_XY_VEL_MAX\t"))
        .expect("parameter in baseline");
    let changed = text.replace(line, "1\t1\tMPC_XY_VEL_MAX\t9.5\t9");
    let baseline = dir.join("changed.params");
    std::fs::write(&baseline, changed).unwrap();
    let out = dry_run(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        RULES,
        baseline.to_str().unwrap(),
        false,
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let s = stdout(&out);
    assert!(
        s.contains("R3    FAIL    parameters match baseline     1 differ"),
        "{s}"
    );
    assert!(
        s.contains("- MPC_XY_VEL_MAX: baseline f32:9.5, flown f32:12"),
        "{s}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn second_flight_against_first_baseline_shows_only_unignored_differences() {
    let out = dry_run(
        "testdata/sitl/v1.17.0/mc_flight_2.ulg",
        RULES,
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        false,
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let s = stdout(&out);
    let r3: Vec<&str> = s
        .lines()
        .skip_while(|l| !l.starts_with("R3"))
        .take_while(|l| !l.starts_with("R4"))
        .collect();
    assert_eq!(
        r3,
        [
            "R3    FAIL    parameters match baseline     3 differ",
            "              - CAL_BARO1_ID: baseline i32:0, flown absent",
            "              - CAL_BARO2_ID: baseline i32:0, flown absent",
            "              - CAL_BARO3_ID: baseline i32:0, flown absent",
        ],
        "volatile parameters COM_FLIGHT_UUID, LND_FLIGHT_T_LO, EKF2_MAG_DECL and CAL_BARO0_OFF are ignored"
    );
}

#[test]
fn failsafe_log_fails_r4_with_flag_and_time() {
    let out = dry_run(
        "testdata/sitl/v1.17.0/failsafe_gps_loss.ulg",
        RULES,
        "testdata/baselines/v1.17.0_failsafe_gps_loss.params",
        false,
    );
    assert_eq!(out.status.code(), Some(1));
    let s = stdout(&out);
    assert!(s.contains("R4    FAIL"), "{s}");
    assert!(s.contains("- failsafe while armed at boot_us 37936000: global_position_invalid, global_position_invalid_relaxed, local_position_invalid, local_position_invalid_relaxed, local_velocity_invalid"), "{s}");
    let out = dry_run(
        "testdata/sitl/v1.17.0/failsafe_battery_empty.ulg",
        RULES,
        "testdata/baselines/v1.17.0_failsafe_battery_empty.params",
        false,
    );
    assert!(
        stdout(&out).contains("- failsafe while armed at boot_us 23120000: battery_warning"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn vtol_log_has_start_and_end_and_passes_r6() {
    let out = dry_run(
        "testdata/sitl/v1.17.0/vtol_transition.ulg",
        RULES,
        "testdata/baselines/v1.17.0_vtol_transition.params",
        true,
    );
    assert_eq!(out.status.code(), Some(0));
    let s = stdout(&out);
    assert_eq!(
        s.matches("\"kind\": \"VTOL_TRANSITION_START\"").count(),
        2,
        "{s}"
    );
    assert_eq!(s.matches("\"kind\": \"VTOL_TRANSITION_END\"").count(), 2);
    assert_eq!(s.matches("\"kind\": \"VTOL_TRANSITION_ABORT\"").count(), 0);
    let table = stdout(&dry_run(
        "testdata/sitl/v1.17.0/vtol_transition.ulg",
        RULES,
        "testdata/baselines/v1.17.0_vtol_transition.params",
        false,
    ));
    assert!(
        table.contains("R6    PASS    VTOL transitions completed    2 START, 2 END, 0 problem(s)"),
        "{table}"
    );

    let abort = stdout(&dry_run(
        "testdata/sitl/v1.17.0/vtol_transition_abort.ulg",
        RULES,
        "testdata/baselines/v1.17.0_vtol_transition_abort.params",
        false,
    ));
    assert!(abort.contains("R6    FAIL"), "{abort}");
    assert!(
        abort.contains("- VTOL_TRANSITION_ABORT to_fw seq"),
        "{abort}"
    );
}

#[test]
fn multicopter_log_gives_r6_not_applicable() {
    for (name, log) in [
        (
            "v1.17.0_mc_flight_1",
            "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        ),
        ("v1.14.4_mc_flight", "testdata/sitl/v1.14.4/mc_flight.ulg"),
    ] {
        let s = stdout(&dry_run(
            log,
            RULES,
            &format!("testdata/baselines/{name}.params"),
            false,
        ));
        assert!(s.contains("R6    N/A"), "{log}: {s}");
    }
}

#[test]
fn extended_rules_run_when_enabled() {
    let s = stdout(&dry_run(
        "testdata/sitl/v1.17.0/failsafe_battery_empty.ulg",
        "examples/rules.extended.toml",
        "testdata/baselines/v1.17.0_failsafe_battery_empty.params",
        false,
    ));
    for line in [
        "X1    FAIL",
        "X2    PASS",
        "X3    PASS",
        "X4    PASS",
        "X5    PASS",
    ] {
        assert!(s.contains(line), "missing `{line}` in:\n{s}");
    }
    assert!(s.contains("below 0.25"), "{s}");
    let s = stdout(&dry_run(
        "testdata/pyulog/sample.ulg",
        "examples/rules.extended.toml",
        "testdata/baselines/pyulog_sample.params",
        false,
    ));
    assert!(
        s.contains("X5    FAIL    total dropout time            4 dropout(s), 119 ms in total"),
        "{s}"
    );
}

#[test]
fn usage_and_io_errors_exit_4() {
    let base = [
        "seal",
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        "--rules",
        RULES,
        "--baseline",
        "testdata/baselines/v1.17.0_mc_flight_1.params",
    ];
    let out = sfr(&base);
    assert_eq!(
        out.status.code(),
        Some(4),
        "seal without --dry-run needs a key source"
    );
    assert!(
        stderr(&out).contains("seal needs a key source"),
        "{}",
        stderr(&out)
    );

    let mut unknown = base.to_vec();
    unknown.extend(["--dry-run", "--sign-anyway"]);
    assert_eq!(sfr(&unknown).status.code(), Some(4));

    let out = dry_run(
        "testdata/does_not_exist.ulg",
        RULES,
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        false,
    );
    assert_eq!(out.status.code(), Some(4));
    assert!(
        stderr(&out).contains("cannot open log testdata/does_not_exist.ulg"),
        "{}",
        stderr(&out)
    );

    let out = sfr(&["seal", "testdata/sitl/v1.17.0/mc_flight_1.ulg", "--dry-run"]);
    assert_eq!(out.status.code(), Some(4));
    assert!(
        stderr(&out).contains("--rules is required"),
        "{}",
        stderr(&out)
    );

    // A path that is not valid UTF-8 is a usage error, not a panic.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let bad = std::ffi::OsStr::from_bytes(b"bad\xff.ulg");
        let out = Command::new(env!("CARGO_BIN_EXE_sfr"))
            .current_dir(root())
            .args(["seal".as_ref(), bad, "--dry-run".as_ref()])
            .output()
            .expect("sfr binary runs");
        assert_eq!(out.status.code(), Some(4), "{}", stderr(&out));
        assert!(
            stderr(&out).contains("is not valid UTF-8"),
            "{}",
            stderr(&out)
        );
    }

    assert_eq!(sfr(&["verify"]).status.code(), Some(4));
    assert_eq!(sfr(&["--help"]).status.code(), Some(0));
}

/// Byte offsets where records start, after the 16-byte header.
fn record_starts(log: &[u8]) -> Vec<(usize, u8)> {
    let mut out = Vec::new();
    let mut pos = 16;
    while pos + 3 <= log.len() {
        let size = usize::from(u16::from_le_bytes([log[pos], log[pos + 1]]));
        out.push((pos, log[pos + 2]));
        pos += 3 + size;
    }
    out
}

#[test]
fn a_log_without_data_records_is_truncated_exit_3() {
    let dir = scratch();
    let bytes = std::fs::read(root().join("testdata/sitl/v1.17.0/mc_flight_1.ulg")).unwrap();
    let first_sub = record_starts(&bytes)
        .into_iter()
        .find(|(_, t)| *t == b'A')
        .unwrap()
        .0;
    for (name, cut) in [("header_only", 16), ("definitions_only", first_sub)] {
        let path = dir.join(format!("{name}.ulg"));
        std::fs::write(&path, &bytes[..cut]).unwrap();
        let out = dry_run(
            path.to_str().unwrap(),
            RULES,
            "testdata/baselines/v1.17.0_mc_flight_1.params",
            false,
        );
        assert_eq!(out.status.code(), Some(3), "{name}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("ends before any data record"),
            "{}",
            stderr(&out)
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn r2_fails_on_other_firmware_and_r5_when_the_log_ends_armed() {
    let dir = scratch();
    let text =
        std::fs::read_to_string(root().join("testdata/baselines/v1.17.0_mc_flight_1.params"))
            .unwrap();
    let other = text.replace("# Firmware: 1.17.0 ", "# Firmware: 1.16.2 ");
    let baseline = dir.join("other_fw.params");
    std::fs::write(&baseline, other).unwrap();
    let s = stdout(&dry_run(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        RULES,
        baseline.to_str().unwrap(),
        false,
    ));
    assert!(
        s.contains("R2    FAIL") && s.contains("- version: baseline 1.16.2, log 1.17.0"),
        "{s}"
    );

    // Cut on a record boundary in the middle of the flight: the log ends armed.
    let bytes = std::fs::read(root().join("testdata/sitl/v1.17.0/mc_flight_1.ulg")).unwrap();
    let cut = record_starts(&bytes)
        .into_iter()
        .map(|(p, _)| p)
        .find(|&p| p > bytes.len() * 6 / 10)
        .unwrap();
    let path = dir.join("ends_armed.ulg");
    std::fs::write(&path, &bytes[..cut]).unwrap();
    let out = dry_run(
        path.to_str().unwrap(),
        RULES,
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        false,
    );
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let s = stdout(&out);
    assert!(
        s.contains("R5    FAIL") && s.contains("has no DISARM: the log ends armed"),
        "{s}"
    );
    std::fs::remove_dir_all(dir).unwrap();
}
