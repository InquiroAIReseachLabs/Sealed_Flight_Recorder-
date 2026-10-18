//! `sfr` command line (SPEC B1.2, `crates/sfr`). Thin wrapper over `sfr-core`.
//!
//! Commands `seal`, `verify`, and `keygen` arrive in Chunks 2 and 3. Until then the
//! binary only knows the usage error path: no command is a usage error, exit code 4
//! (SPEC B1.4).
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut stderr = std::io::stderr().lock();
    let written = writeln!(
        stderr,
        "{}: no command given. Commands seal, verify, and keygen arrive in later chunks.",
        sfr_core::TOOL_NAME
    );
    match written {
        // Both outcomes are exit 4 (SPEC B1.4): a usage error, and a failed write to stderr
        // is an I/O error. The exit code carries the result when stderr cannot.
        Ok(()) | Err(_) => exit_with(sfr_core::exit_code::USAGE),
    }
}

/// Converts a SPEC B1.4 exit code into the process exit status.
fn exit_with(code: i32) -> ExitCode {
    // Exit codes are 0 to 4, so the conversion cannot truncate.
    ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX))
}
