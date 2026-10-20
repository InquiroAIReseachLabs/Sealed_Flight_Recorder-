//! Gate tests for `sfr seal --dry-run` (SPEC B1.4, B1.5, B1.6).
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
    if UNTESTED_VERSION_LOGS.contains(&log) {
        args.push("--allow-untested-version");
    }
    sfr(&args)
}

/// Test logs whose PX4 version sfr cannot read: `seal` needs `--allow-untested-version`.
const UNTESTED_VERSION_LOGS: [&str; 2] = [
    "testdata/pyulog/sample.ulg",
    "fuzz/seeds/ulog_ingest/subscription_amplification.ulg",
];

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
fn golden_logs_match_reviewed_expected_files() {
    // Every .ulg under testdata/ must have a golden entry.
    let mut logs = Vec::new();
    for dir in [
        "testdata/pyulog",
        "testdata/sitl/v1.14.4",
        "testdata/sitl/v1.17.0",
        "testdata/synthetic",
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
        let out = dry_run(log, &rules_for(name), &baseline, true);
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
fn per_log_rules_extend_the_default_rules() {
    let default = std::fs::read_to_string(root().join(RULES)).unwrap();
    let mut n = 0;
    for e in std::fs::read_dir(root().join("testdata/rules")).unwrap() {
        let p = e.unwrap().path();
        let name = p.file_stem().unwrap().to_string_lossy().into_owned();
        assert!(
            GOLDEN.iter().any(|g| g.0 == name),
            "{}: names no golden log",
            p.display()
        );
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(
            text.starts_with(&default),
            "{}: must start with the text of {RULES}",
            p.display()
        );
        n += 1;
    }
    assert!(n > 0);
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
        // SITL has no RC link and no ground station: those flags are true in flight, not
        // required by the mission mode, so R4 warns and names them.
        "R4    WARN    no failsafe in flight         never true in flight; warning: failsafe_flags auto_mission_missing, gcs_connection_lost, manual_control_signal_lost, offboard_control_signal_lost true in flight",
        "R5    PASS",
        "R6    N/A",
        "events    22",
        "status    WARN",
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
            "R3    FAIL    parameters match baseline     3 differ; ignore [COM_FLIGHT_UUID, LND_FLIGHT_T_HI, LND_FLIGHT_T_LO, EKF2_MAG_DECL, CAL_BARO*_OFF, ASPD_SCALE_*, COM_MODE*_HASH] suppressed 4 difference(s); baseline file sha256 2a9d3eadefab6e234295a2c43f8b8dbec92744812fc7edecec1ceada763c1b63 (operator-supplied)",
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
    assert!(s.contains("- failsafe in flight at boot_us 37936000: global_position_invalid, global_position_invalid_relaxed, local_position_invalid, local_position_invalid_relaxed, local_velocity_invalid"), "{s}");
    let out = dry_run(
        "testdata/sitl/v1.17.0/failsafe_battery_empty.ulg",
        RULES,
        "testdata/baselines/v1.17.0_failsafe_battery_empty.params",
        false,
    );
    assert!(
        stdout(&out).contains("- failsafe in flight at boot_us 23120000: battery_warning"),
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

/// Gate: the tailsitter golden log (Gazebo `gz_quadtailsitter`, `VT_TYPE` 0).
#[test]
fn tailsitter_log_has_start_and_end_passes_r6_and_shows_transition_tuning() {
    let log = "testdata/sitl/v1.17.0/gz_quadtailsitter_transition.ulg";
    let baseline = "testdata/baselines/v1.17.0_gz_quadtailsitter_transition.params";
    let out = dry_run(log, RULES, baseline, true);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let s = stdout(&out);
    assert!(
        s.contains(
            "\"vtol_type\": {\n        \"name\": \"tailsitter\",\n        \"value\": 0\n      }"
        ),
        "{s}"
    );
    for (kind, n) in [
        ("VTOL_TRANSITION_START", 2),
        ("VTOL_TRANSITION_END", 2),
        ("VTOL_TRANSITION_ABORT", 0),
        ("QUADCHUTE", 0),
    ] {
        assert_eq!(
            s.matches(&format!("\"kind\": \"{kind}\"")).count(),
            n,
            "{kind}"
        );
    }
    assert!(
        s.contains("\"VTOL type tailsitter (VT_TYPE 0)\""),
        "R6 detail: {s}"
    );
    let table = stdout(&dry_run(log, RULES, baseline, false));
    for line in [
        "R6    PASS    VTOL transitions completed    2 START, 2 END, 0 problem(s)",
        "transition tuning (VTOL type tailsitter)",
        "  VT_B_TRANS_DUR    f32:5           f32:5           MATCH",
        "  VT_F_TRANS_DUR    f32:1.5         f32:1.5         MATCH",
    ] {
        assert!(table.contains(line), "missing {line:?} in {table}");
    }
    assert!(!table.contains("DIFF"), "{table}");
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

#[test]
fn oversize_text_inputs_are_refused_and_name_the_limit() {
    let dir = scratch();
    let big = dir.join("big.toml");
    // 16 MiB and one byte.
    std::fs::write(&big, vec![b'#'; 16 * 1024 * 1024 + 1]).unwrap();
    let out = dry_run(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        big.to_str().unwrap(),
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        false,
    );
    assert_eq!(out.status.code(), Some(3), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("exceeds the input limit of 16777216 bytes (SPEC B1.4)"),
        "{}",
        stderr(&out)
    );
    // Exactly 16 MiB is accepted: the default rules padded with a comment.
    let mut at = std::fs::read(root().join(RULES)).unwrap();
    at.extend_from_slice(b"#");
    at.resize(16 * 1024 * 1024 - 1, b'x');
    at.push(b'\n');
    let at_path = dir.join("at_limit.toml");
    std::fs::write(&at_path, &at).unwrap();
    let out = dry_run(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        at_path.to_str().unwrap(),
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        false,
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    // Key files: the public key for verify, the private key for seal; both exit 4.
    let out = sfr(&[
        "verify",
        "--allow-evaluation-key",
        "--pubkey",
        big.to_str().unwrap(),
        big.to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("public key") && stderr(&out).contains("16777216 bytes"),
        "{}",
        stderr(&out)
    );
    let out = sfr(&[
        "seal",
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        "--rules",
        RULES,
        "--baseline",
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        "--key",
        big.to_str().unwrap(),
        "--evaluation-only",
        "--out",
        dir.join("out").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("key file") && stderr(&out).contains("16777216 bytes"),
        "{}",
        stderr(&out)
    );

    // A record 1 or 2 bytes over 512 MiB (a sparse file) fails verification and names the
    // limit, in text and in --json.
    let record = dir.join("big.sfr");
    let pubkey = root().join("fuzz/seeds/sfr_verify_key.pub");
    for (over, json) in [(1, false), (1, true), (2, false), (2, true)] {
        let f = std::fs::File::create(&record).unwrap();
        f.set_len(512 * 1024 * 1024 + over).unwrap();
        drop(f);
        let mut args = vec![
            "verify",
            "--allow-evaluation-key",
            record.to_str().unwrap(),
            "--pubkey",
            pubkey.to_str().unwrap(),
        ];
        if json {
            args.push("--json");
        }
        let out = sfr(&args);
        assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
        let all = format!("{}{}", stdout(&out), stderr(&out));
        assert!(
            all.contains("the record exceeds the input limit of 536870912 bytes (SPEC B1.4)"),
            "{all}"
        );
        if json {
            assert!(stdout(&out).trim_start().starts_with('{'), "{all}");
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn the_subscription_amplification_log_is_handled() {
    // 3,891 subscriptions of one format (scripts/testdata/make_amplification_seed.py). It once
    // made sfr hold about 1.6 GB; now the subscriptions share one layout. R1 fails because the
    // log has no vehicle_status and no failsafe_flags data record.
    let dir = scratch();
    let baseline = dir.join("fw.params");
    std::fs::write(&baseline, "# Firmware: 1.17.0\n").unwrap();
    let out = dry_run(
        "fuzz/seeds/ulog_ingest/subscription_amplification.ulg",
        RULES,
        baseline.to_str().unwrap(),
        true,
    );
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("missing: vehicle_status, failsafe_flags"),
        "{}",
        stdout(&out)
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// The default rules followed by `extra`, written to a scratch rules file.
fn rules_plus(extra: &str) -> PathBuf {
    let path = scratch().join("rules.toml");
    let text = std::fs::read_to_string(root().join(RULES)).unwrap() + "\n" + extra;
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn a_sealed_topic_missing_from_the_log_fails_r1_and_names_it() {
    for topic in ["custom_detection", "vehicle_visual_odometry"] {
        let rules = rules_plus(&format!("[sealed_topics]\ntopics = [\"{topic}\"]\n"));
        let out = dry_run(
            "testdata/sitl/v1.17.0/mc_flight_1.ulg",
            rules.to_str().unwrap(),
            "testdata/baselines/v1.17.0_mc_flight_1.params",
            false,
        );
        assert_eq!(out.status.code(), Some(2), "{topic}: {}", stderr(&out));
        assert!(
            stdout(&out).contains(&format!(
                "R1    FAIL    required topics present       missing: {topic}"
            )),
            "{}",
            stdout(&out)
        );
    }
}

/// Gate: removing a declared topic's data from a log that had it fails R1 with
/// exit 2 and names the topic. The vision flight's seed keeps its `vehicle_visual_odometry`
/// subscription ('A' record) but loses every data record of it.
#[test]
fn removing_a_sealed_topics_data_from_its_log_fails_r1_and_names_it() {
    let seed = "fuzz/seeds/ulog_ingest/sitl_v1.17.0_gz_x500_vision_hover_shrunk.ulg";
    let log = std::fs::read(root().join(seed)).unwrap();
    let mut out = log[..16].to_vec();
    let (mut ids, mut dropped) = (std::collections::BTreeSet::new(), 0);
    let mut pos = 16;
    while pos + 3 <= log.len() {
        let size = u16::from_le_bytes([log[pos], log[pos + 1]]) as usize;
        let body = &log[pos + 3..pos + 3 + size];
        match log[pos + 2] {
            b'A' if &body[3..] == b"vehicle_visual_odometry" => {
                ids.insert([body[1], body[2]]);
            }
            b'D' if ids.contains(&[body[0], body[1]]) => {
                dropped += 1;
                pos += 3 + size;
                continue;
            }
            _ => {}
        }
        out.extend_from_slice(&log[pos..pos + 3 + size]);
        pos += 3 + size;
    }
    assert!(dropped > 0, "the seed has vehicle_visual_odometry data");
    let edited = scratch().join("vision_without_odometry.ulg");
    std::fs::write(&edited, out).unwrap();
    let o = dry_run(
        edited.to_str().unwrap(),
        "testdata/rules/v1.17.0_gz_x500_vision_hover.toml",
        "testdata/baselines/v1.17.0_gz_x500_vision_hover.params",
        false,
    );
    assert_eq!(o.status.code(), Some(2), "{}", stderr(&o));
    assert!(
        stdout(&o).contains(
            "R1    FAIL    required topics present       missing: vehicle_visual_odometry"
        ),
        "{}",
        stdout(&o)
    );
}

/// Gate: the Gazebo vision flight seals `vehicle_visual_odometry`, a real PX4
/// topic, and the synthetic fixture seals `custom_detection`, a topic PX4 does not define.
#[test]
fn sealed_topics_give_one_digest_per_instance_on_real_and_custom_topics() {
    for (name, log, entries) in [
        (
            "v1.17.0_gz_x500_vision_hover",
            "testdata/sitl/v1.17.0/gz_x500_vision_hover.ulg",
            &[("vehicle_visual_odometry", 0, 1687)][..],
        ),
        (
            "synthetic_custom_detection",
            "testdata/synthetic/custom_detection.ulg",
            &[
                ("custom_detection", 0, 5),
                ("custom_detection", 1, 2),
                ("custom_detection", 2, 0),
            ][..],
        ),
    ] {
        let out = dry_run(
            log,
            &rules_for(name),
            &format!("testdata/baselines/{name}.params"),
            true,
        );
        assert_eq!(out.status.code(), Some(0), "{name}: {}", stderr(&out));
        // The pretty JSON lists each entry's fields in key order; collect (topic, multi_id,
        // message_count) from the sealed_topics array.
        let s = stdout(&out);
        let start = s.find("\n  \"sealed_topics\": [").expect("sealed_topics");
        let end = start + s[start..].find("\n  ]").expect("end of sealed_topics");
        let field = |line: &str, key: &str| {
            line.trim()
                .strip_prefix(&format!("\"{key}\": "))
                .map(|v| v.trim_end_matches(',').trim_matches('"').to_string())
        };
        let (mut got, mut count, mut multi) = (Vec::new(), String::new(), String::new());
        for line in s[start..end].lines() {
            if let Some(v) = field(line, "message_count") {
                count = v;
            } else if let Some(v) = field(line, "multi_id") {
                multi = v;
            } else if let Some(v) = field(line, "topic") {
                got.push(format!("{v} {multi} {count}"));
            }
        }
        let want: Vec<String> = entries
            .iter()
            .map(|(t, m, c)| format!("{t} {m} {c}"))
            .collect();
        assert_eq!(got, want, "{name}");
    }
}

#[test]
fn more_than_64_sealed_topics_is_a_usage_error() {
    let list: Vec<String> = (0..65).map(|i| format!("\"t{i}\"")).collect();
    let rules = rules_plus(&format!(
        "[sealed_topics]\ntopics = [{}]\n",
        list.join(", ")
    ));
    let out = dry_run(
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        rules.to_str().unwrap(),
        "testdata/baselines/v1.17.0_mc_flight_1.params",
        false,
    );
    assert_eq!(out.status.code(), Some(4), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("`sealed_topics` exceeds the input limit of 64 topics (SPEC B1.4)"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn r7_names_each_command_from_an_unlisted_source() {
    // In mc_flight_1, twelve commands come from system 1 component 1. payload_deliverer's
    // boot-time DO_GRIPPER (211, PAYLOAD) carries uninitialized source ids, here system 191
    // component 46144: arbitrary, but in range for v1.17's 16-bit component field.
    let run = |extra: &str| {
        let rules = rules_plus(extra);
        dry_run(
            "testdata/sitl/v1.17.0/mc_flight_1.ulg",
            rules.to_str().unwrap(),
            "testdata/baselines/v1.17.0_mc_flight_1.params",
            false,
        )
    };
    let out = run("[authorized_sources]\nsources = [{ system = 1, component = 1 }]\n");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let t = stdout(&out);
    assert!(
        t.contains("R7    FAIL    authorized command sources    1 of 13 command(s) from unauthorized sources"),
        "{t}"
    );
    assert!(
        t.contains(
            "- event seq 1: command 211 (PAYLOAD) from system 191 component 46144 at boot_us "
        ),
        "{t}"
    );
    let out = run(
        "[authorized_sources]\nsources = [{ system = 1, component = 1 }, { system = 191, component = 46144 }]\n",
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(
        stdout(&out).contains("R7    PASS    authorized command sources    13 command(s) checked"),
        "{}",
        stdout(&out)
    );
    let out = run(
        "[authorized_sources]\ncategory = \"GENERAL\"\nsources = [{ system = 1, component = 1 }]\n",
    );
    assert!(
        stdout(&out).contains("R7    PASS    authorized command sources    12 command(s) checked"),
        "{}",
        stdout(&out)
    );
}

/// Gate: a changed `VT_B_TRANS_DUR` in the baseline fails R3 with both values
/// and shows DIFF in the transition tuning section, on the standard VTOL and the tailsitter.
#[test]
fn a_changed_watched_parameter_fails_r3_and_shows_diff_in_transition_tuning() {
    // (golden name, flown value as the baseline writes it, VTOL type, an unchanged row)
    for (name, flown, vtol, unchanged) in [
        (
            "v1.17.0_vtol_transition",
            "10.0",
            "standard",
            "  VT_F_TRANS_DUR    f32:5           f32:5           MATCH",
        ),
        (
            "v1.17.0_gz_quadtailsitter_transition",
            "5.0",
            "tailsitter",
            "  VT_F_TRANS_DUR    f32:1.5         f32:1.5         MATCH",
        ),
    ] {
        let dir = scratch();
        let baseline = dir.join("vtol.params");
        let from = format!("\tVT_B_TRANS_DUR\t{flown}\t9");
        let text =
            std::fs::read_to_string(root().join(format!("testdata/baselines/{name}.params")))
                .unwrap()
                .replace(&from, "\tVT_B_TRANS_DUR\t8.0\t9");
        assert!(
            text.contains("\tVT_B_TRANS_DUR\t8.0\t9"),
            "{name}: the baseline line was edited"
        );
        std::fs::write(&baseline, text).unwrap();
        let out = dry_run(
            &format!(
                "testdata/sitl/v1.17.0/{}.ulg",
                name.trim_start_matches("v1.17.0_")
            ),
            RULES,
            baseline.to_str().unwrap(),
            false,
        );
        assert_eq!(out.status.code(), Some(1), "{name}: {}", stderr(&out));
        let t = stdout(&out);
        let flown = flown.trim_end_matches(".0");
        for line in [
            "R3    FAIL    parameters match baseline     1 differ".to_string(),
            format!("- VT_B_TRANS_DUR: baseline f32:8, flown f32:{flown}"),
            format!("transition tuning (VTOL type {vtol})"),
            format!(
                "  VT_B_TRANS_DUR    f32:8           {:<16}DIFF",
                format!("f32:{flown}")
            ),
            unchanged.to_string(),
        ] {
            assert!(t.contains(&line), "{name}: missing {line:?} in {t}");
        }
    }
}

/// Gate: the payload SITL flight (commands from a ground station, 255/190, and
/// a second source, 42/191, to the vehicle, system 6). Its golden rules list the ground station
/// and the vehicle but not the second source.
#[test]
fn payload_log_has_payload_events_and_r7_names_the_second_source() {
    let log = "testdata/sitl/v1.17.0/payload_two_sources.ulg";
    let baseline = "testdata/baselines/v1.17.0_payload_two_sources.params";
    let golden = "testdata/rules/v1.17.0_payload_two_sources.toml";

    // PAYLOAD events: actuator, gripper twice, image capture and winch from the flight, plus
    // PX4's own boot-time DO_GRIPPER (docs/RULES.md, R7).
    let json = stdout(&dry_run(log, golden, baseline, true));
    assert_eq!(
        json.matches("\"category\": \"PAYLOAD\"").count(),
        6,
        "{json}"
    );
    assert_eq!(
        json.matches("\"category\": \"GENERAL\"").count(),
        6,
        "{json}"
    );

    let out = dry_run(log, golden, baseline, false);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    let t = stdout(&out);
    for line in [
        "R7    FAIL    authorized command sources    5 of 12 command(s) from unauthorized sources",
        "- event seq 8: command 211 (PAYLOAD) from system 42 component 191 at boot_us 34728000",
        "- event seq 9: command 2000 (PAYLOAD) from system 42 component 191 at boot_us 37712000",
        "- event seq 11: command 42600 (PAYLOAD) from system 42 component 191 at boot_us 40712000",
        "- event seq 12: command 211 (PAYLOAD) from system 42 component 191 at boot_us 43732000",
    ] {
        assert!(t.contains(line), "missing {line:?} in {t}");
    }
    assert!(!t.contains("from system 255 component 190"), "{t}");
    assert!(!t.contains("from system 6 component 1 "), "{t}");

    // No [authorized_sources]: R7 is N/A.
    let t = stdout(&dry_run(log, RULES, baseline, false));
    assert!(
        t.contains("R7    N/A     authorized command sources"),
        "{t}"
    );

    // Listing the second source too leaves only the boot-time DO_GRIPPER; scoped to GENERAL,
    // the ground station and the vehicle cover every command.
    let run = |extra: &str| {
        let rules = rules_plus(extra);
        stdout(&dry_run(log, rules.to_str().unwrap(), baseline, false))
    };
    let t = run(
        "[authorized_sources]\nsources = [{ system = 255, component = 190 }, { system = 6, component = 1 }, { system = 42, component = 191 }]\n",
    );
    assert!(
        t.contains("R7    FAIL    authorized command sources    1 of 12 command(s) from unauthorized sources"),
        "{t}"
    );
    let t = run(
        "[authorized_sources]\ncategory = \"GENERAL\"\nsources = [{ system = 255, component = 190 }, { system = 6, component = 1 }]\n",
    );
    assert!(
        t.contains("R7    PASS    authorized command sources    6 command(s) checked, all from authorized sources"),
        "{t}"
    );
}
