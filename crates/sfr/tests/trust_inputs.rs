//! The programs `sfr` runs to reach a key are found by fixed paths, never through the
//! environment or `PATH`: the PKCS#11 helper only beside the `sfr` binary (a test build with
//! the `dev-helper` feature aside), and the tpm2-tools commands only in `SFR_TPM2_TOOLS_DIR`
//! (absolute) or /usr/bin. A program planted on `PATH` or named in the environment, which would
//! see the payload or the seed, is never run.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const LOG: &str = "testdata/synthetic/custom_detection.ulg";
const RULES: &str = "testdata/rules/synthetic_custom_detection.toml";
const BASELINE: &str = "testdata/baselines/synthetic_custom_detection.params";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn scratch(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sfr-trust-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// An executable shell script at `path` that records it ran in `marker`, then runs `body`.
fn planted(path: &Path, marker: &Path, body: &str) {
    std::fs::write(
        path,
        format!("#!/bin/sh\necho ran >> '{}'\n{body}\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// PATH with `dir` first.
fn path_with(dir: &Path) -> String {
    format!(
        "{}:{}",
        dir.display(),
        std::env::var("PATH").unwrap_or_default()
    )
}

#[test]
fn a_planted_pkcs11_helper_never_signs_a_record() {
    let dir = scratch("helper");
    let (marker, fake) = (dir.join("ran"), dir.join("bin"));
    std::fs::create_dir_all(&fake).unwrap();
    // A helper that would sign with a key file and claim it is a token: the public key of the
    // file key, and an Ed25519 signature by it (OpenSSL 3).
    let o = Command::new(env!("CARGO_BIN_EXE_sfr"))
        .args(["keygen", "--evaluation-only", "--out"])
        .arg(dir.join("k"))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let key = dir.join("k/sfr.key");
    let body = format!(
        "case \"$1\" in\n  public-key) openssl pkey -in '{k}' -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \\n'; echo ;;\n  sign) cat > '{d}/msg'; openssl pkeyutl -sign -rawin -inkey '{k}' -in '{d}/msg' | od -An -tx1 | tr -d ' \\n'; echo ;;\nesac",
        k = key.display(),
        d = dir.display()
    );
    planted(&fake.join("sfr-pkcs11-helper"), &marker, &body);
    let out = dir.join("out");
    let o = Command::new(env!("CARGO_BIN_EXE_sfr"))
        .current_dir(root())
        .env("SFR_PKCS11_HELPER", fake.join("sfr-pkcs11-helper"))
        .env("PATH", path_with(&fake))
        .args([
            "seal",
            LOG,
            "--rules",
            RULES,
            "--baseline",
            BASELINE,
            "--key-uri",
            "pkcs11:object=k?module-path=/nonexistent/module.so&pin-source=env:P",
            "--seal-time",
            "2026-10-18T15:00:00Z",
            "--out",
        ])
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    assert!(!marker.exists(), "the planted helper ran: {}", text(&o));
    assert!(!out.join("custom_detection.sfr").exists(), "no record");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn tpm2_tools_come_from_an_absolute_directory_never_from_path() {
    let dir = scratch("tpm");
    let (marker, fake) = (dir.join("ran"), dir.join("bin"));
    std::fs::create_dir_all(&fake).unwrap();
    for tool in [
        "tpm2_createpolicy",
        "tpm2_create",
        "tpm2_load",
        "tpm2_unseal",
    ] {
        planted(&fake.join(tool), &marker, "exit 1");
    }
    let keygen = |env: &[(&str, &str)]| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sfr"));
        c.args(["keygen", "--tpm-sealed", "--out"])
            .arg(dir.join(format!("key{}", env.len())))
            .env("PATH", path_with(&fake))
            .env_remove("SFR_TPM2_TOOLS_DIR");
        for (k, v) in env {
            c.env(k, v);
        }
        c.output().unwrap()
    };
    // The planted tools first on PATH are not run.
    let o = keygen(&[]);
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    assert!(!marker.exists(), "a planted tpm2 tool ran: {}", text(&o));
    // A relative directory is refused.
    let o = keygen(&[("SFR_TPM2_TOOLS_DIR", "bin")]);
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    assert!(
        text(&o).contains("not an absolute directory"),
        "{}",
        text(&o)
    );
    assert!(!marker.exists());
    // The configured absolute directory is the one used.
    let o = keygen(&[("SFR_TPM2_TOOLS_DIR", fake.to_str().unwrap())]);
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    assert!(marker.exists(), "the configured directory's tool ran");
    std::fs::remove_dir_all(dir).unwrap();
}
