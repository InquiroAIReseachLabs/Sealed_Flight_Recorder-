//! `sfr-pkcs11-helper` (SPEC B1.2): one Ed25519 signature from a PKCS#11 v3.0 token, then exit.
//!
//! `sfr seal --key-uri pkcs11:...` spawns this process, writes the signed payload to its stdin,
//! and verifies the returned signature itself before writing anything. It runs
//! apart from `sfr` because a static musl binary cannot load a vendor PKCS#11 module. The
//! signing code arrives in Chunk 3; the tested prototype is in `docs/DIAGNOSTIC.md` item 11.
#![forbid(unsafe_code)]

use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut stderr = std::io::stderr().lock();
    let written = writeln!(stderr, "sfr-pkcs11-helper: signing arrives in Chunk 3.");
    match written {
        // Exit 4 either way (SPEC B1.4): nothing was signed, and stderr is best effort.
        Ok(()) | Err(_) => ExitCode::from(4),
    }
}
