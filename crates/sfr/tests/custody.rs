//! Key custody (SPEC B1.3 `verify`): the custody a record declares is the sealer's own word, so
//! `verify` prints it as unattested unless a certificate chain to a trust anchor the verifier
//! supplied attests it; a record signed with an evaluation key does not verify unless asked for;
//! and `--require-hardware-key` means attested by chain, not declared.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

mod forge;

const LOG: &str = "testdata/synthetic/custom_detection.ulg";
const RULES: &str = "testdata/rules/synthetic_custom_detection.toml";
const BASELINE: &str = "testdata/baselines/synthetic_custom_detection.params";
const BANNER: &str = "EVALUATION KEY: not for operational use";

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
        "sfr-custody-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An evaluation key pair in a new directory: (private key file, public key file).
fn keygen(dir: &Path) -> (PathBuf, PathBuf) {
    let o = sfr(&[
        "keygen",
        "--evaluation-only",
        "--out",
        dir.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    (dir.join("sfr.key"), dir.join("sfr.pub"))
}

/// Seals the synthetic log with the evaluation key file `key`; returns the record path.
fn seal(key: &Path, out: &Path) -> PathBuf {
    let o = sfr(&[
        "seal",
        LOG,
        "--rules",
        RULES,
        "--baseline",
        BASELINE,
        "--key",
        key.to_str().unwrap(),
        "--evaluation-only",
        "--seal-time",
        "2026-10-18T15:00:00Z",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    out.join("custom_detection.sfr")
}

#[test]
fn a_record_signed_with_an_evaluation_key_is_refused_unless_it_is_allowed() {
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let record = seal(&key, &dir.join("out"));
    let (r, p) = (record.to_str().unwrap(), public.to_str().unwrap());

    // By default the signature verifies and the record is still not accepted: REFUSED, not
    // VERIFIED, exit 1, with the banner first and the way to accept it named.
    let v = sfr(&["verify", r, "--pubkey", p]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    let out = stdout(&v);
    assert!(
        out.starts_with(&format!(
            "{BANNER}\nIntegrity: REFUSED: the record is signed with an evaluation key"
        )),
        "{out}"
    );
    assert!(out.contains("--allow-evaluation-key accepts it"), "{out}");
    assert!(!out.contains("VERIFIED"), "{out}");
    assert!(
        out.contains(
            "Rule checks: UNKNOWN (the record was refused, so its rule results are not accepted)\n"
        ),
        "{out}"
    );
    assert!(
        out.contains("custody   unattested (declared file-evaluation)\n"),
        "{out}"
    );
    let j = sfr(&["verify", r, "--pubkey", p, "--json"]);
    assert_eq!(j.status.code(), Some(1));
    let json = stdout(&j);
    assert!(
        json.contains("\"verified\": false") && json.contains("\"integrity\": \"REFUSED\""),
        "{json}"
    );

    // With the flag it verifies, the banner is still the first line, and the custody is still
    // unattested.
    let v = sfr(&["verify", r, "--pubkey", p, "--allow-evaluation-key"]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let out = stdout(&v);
    assert!(
        out.starts_with(&format!("{BANNER}\nIntegrity: VERIFIED (record)\n")),
        "{out}"
    );
    assert!(
        out.contains("custody   unattested (declared file-evaluation)\n"),
        "{out}"
    );
    // The flag does not hide a record that fails for another reason.
    let mut bytes = std::fs::read(&record).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x20;
    let changed = dir.join("changed.sfr");
    std::fs::write(&changed, bytes).unwrap();
    let v = sfr(&[
        "verify",
        changed.to_str().unwrap(),
        "--pubkey",
        p,
        "--allow-evaluation-key",
    ]);
    assert_eq!(v.status.code(), Some(1));
    assert!(stdout(&v).contains("Integrity: FAILED: "), "{}", text(&v));
}

#[test]
fn relabelling_an_evaluation_record_as_a_token_record_fails_under_require_hardware_key() {
    // The attack: whoever holds only an evaluation key file re-signs a record with it after
    // setting key_custody to pkcs11-token. The signature is genuine, because the same key
    // signs it; only the sealer's word about where the key lives has changed.
    let dir = scratch();
    let (key, public) = keygen(&dir.join("k"));
    let record = seal(&key, &dir.join("out"));
    let forged = forge::relabelled_as_pkcs11(
        &std::fs::read(&record).unwrap(),
        &forge::key_from_file(&key),
    );
    let forged_path = dir.join("forged.sfr");
    std::fs::write(&forged_path, forged).unwrap();
    let (f, p) = (forged_path.to_str().unwrap(), public.to_str().unwrap());

    // Plain verify accepts the signature and cannot call the custody anything but unattested:
    // the banner is gone, and so is any suggestion that a token was involved.
    let v = sfr(&["verify", f, "--pubkey", p, "--no-report"]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let out = stdout(&v);
    assert!(
        out.contains("custody   unattested (declared pkcs11-token)\n")
            && !out.contains("attested by"),
        "{out}"
    );

    // --require-hardware-key means attested by a certificate chain, not declared: refused.
    let v = sfr(&[
        "verify",
        f,
        "--pubkey",
        p,
        "--no-report",
        "--require-hardware-key",
    ]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    let out = stdout(&v);
    assert!(
        out.contains("Integrity: REFUSED: --require-hardware-key needs custody attested by a certificate chain"),
        "{out}"
    );
    assert!(!out.contains("VERIFIED"), "{out}");
    // Allowing evaluation keys does not help the forger: it is not an evaluation record any more
    // and nothing attests the token.
    let v = sfr(&[
        "verify",
        f,
        "--pubkey",
        p,
        "--no-report",
        "--require-hardware-key",
        "--allow-evaluation-key",
    ]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    // The untouched evaluation record fails the same flag too.
    let v = sfr(&[
        "verify",
        record.to_str().unwrap(),
        "--pubkey",
        p,
        "--require-hardware-key",
        "--allow-evaluation-key",
    ]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    assert!(
        stdout(&v).contains("does not accept a record that declares custody file-evaluation"),
        "{}",
        text(&v)
    );
}
