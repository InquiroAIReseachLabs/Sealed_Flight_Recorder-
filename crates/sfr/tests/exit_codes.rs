//! Exit code integration tests (SPEC B1.4, B1.10 "Exit codes").
//! Code 4 (usage) is covered here; codes 0 to 3 are tested with the commands that produce them.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::Command;

#[test]
fn no_command_is_a_usage_error_exit_4() {
    let output = Command::new(env!("CARGO_BIN_EXE_sfr"))
        .output()
        .expect("sfr binary runs");
    assert_eq!(
        output.status.code(),
        Some(sfr_core::exit_code::USAGE),
        "SPEC B1.4: usage error exits 4"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no command given"),
        "error names the problem, got: {stderr}"
    );
}

/// A file name given on the command line can hold a newline or another control character. Every
/// message that shows one shows it as a marker (`<U+000A>`), so a name cannot start a line of its
/// own that reads like a message of `sfr`.
#[test]
fn a_file_name_with_a_newline_is_shown_as_a_marker_in_every_message() {
    const NAME: &str = "gone\nsfr: forged line\u{1b}[31m.x";
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let (log, rules, baseline) = (
        "testdata/sitl/v1.17.0/mc_flight_1.ulg",
        "examples/rules.default.toml",
        "testdata/baselines/v1.17.0_mc_flight_1.params",
    );
    let record = "fuzz/seeds/sfr_verify/synthetic_custom_detection.sfr";
    let key = "fuzz/seeds/sfr_verify_key.pub";
    let cases: Vec<(&str, Vec<&str>)> = vec![
        (
            "seal log",
            vec![
                "seal",
                NAME,
                "--rules",
                rules,
                "--baseline",
                baseline,
                "--dry-run",
            ],
        ),
        (
            "seal rules",
            vec![
                "seal",
                log,
                "--rules",
                NAME,
                "--baseline",
                baseline,
                "--dry-run",
            ],
        ),
        (
            "seal baseline",
            vec![
                "seal",
                log,
                "--rules",
                rules,
                "--baseline",
                NAME,
                "--dry-run",
            ],
        ),
        (
            "seal cert",
            vec![
                "seal",
                log,
                "--rules",
                rules,
                "--baseline",
                baseline,
                "--dry-run",
                "--cert",
                NAME,
            ],
        ),
        (
            "seal chain",
            vec![
                "seal",
                log,
                "--rules",
                rules,
                "--baseline",
                baseline,
                "--dry-run",
                "--cert",
                "testdata/pki/signer.pem",
                "--chain",
                NAME,
            ],
        ),
        (
            "seal key",
            vec![
                "seal",
                log,
                "--rules",
                rules,
                "--baseline",
                baseline,
                "--key",
                NAME,
                "--evaluation-only",
            ],
        ),
        (
            "verify record",
            vec!["verify", NAME, "--pubkey", key, "--no-report"],
        ),
        (
            "verify pubkey",
            vec!["verify", record, "--pubkey", NAME, "--no-report"],
        ),
        (
            "verify report",
            vec!["verify", record, "--pubkey", key, "--report", NAME],
        ),
        (
            "verify ulog",
            vec![
                "verify",
                record,
                "--pubkey",
                key,
                "--no-report",
                "--ulog",
                NAME,
            ],
        ),
        (
            "verify anchor",
            vec![
                "verify",
                record,
                "--trust-anchor",
                NAME,
                "--no-crl-check",
                "--no-report",
            ],
        ),
        (
            "verify crl",
            vec![
                "verify",
                record,
                "--trust-anchor",
                "testdata/pki/root.pem",
                "--crl",
                NAME,
                "--no-report",
            ],
        ),
    ];
    for (label, args) in cases {
        let out = Command::new(env!("CARGO_BIN_EXE_sfr"))
            .current_dir(&root)
            .args(&args)
            .output()
            .expect("sfr binary runs");
        let err = String::from_utf8_lossy(&out.stderr);
        let all = format!("{}{err}", String::from_utf8_lossy(&out.stdout));
        assert!(
            all.contains("<U+000A>"),
            "{label}: the name is not shown with a marker: {all}"
        );
        assert!(
            !all.contains('\u{1b}') && !all.contains("\nsfr: forged line"),
            "{label}: the name started a line or drove the terminal: {all:?}"
        );
    }
}
