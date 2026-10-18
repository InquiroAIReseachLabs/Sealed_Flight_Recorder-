//! Exit code integration tests (SPEC B1.4, B1.10 "Exit codes").
//! Chunk 0 covers code 4 (usage). Codes 0 to 3 are added with the commands that produce them.
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
