//! Hardware key custody (SPEC B1.3, B1.7, B1.10 Key custody): `pkcs11-token` against SoftHSM v2
//! (CKM_EDDSA) and `tpm-sealed` against swtpm.
//!
//! The tests marked `#[ignore]` need a token or a TPM. `scripts/hardware_keys.sh` creates both
//! (a SoftHSM v2 token with an Ed25519 key, and swtpm behind tpm2-abrmd with a persistent
//! storage key at 0x81000001), sets the variables below, and runs them with `--ignored`; the CI
//! job `hardware-keys` runs that script.
//!
//! - `SFR_TEST_PKCS11_URI`: a `pkcs11:` URI of an Ed25519 key, with `module-path` and a
//!   `pin-source`, without a query string's PIN.
//! - `SFR_TEST_TPM`: set when tpm2-tools reach a TPM (`TPM2TOOLS_TCTI`).
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const LOG: &str = "testdata/sitl/v1.17.0/vtol_transition.ulg";
const BASELINE: &str = "testdata/baselines/v1.17.0_vtol_transition.params";
const RULES: &str = "examples/rules.default.toml";
const EVALUATION_LINE: &str = "EVALUATION KEY: not for operational use";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sfr_env(args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sfr"));
    c.current_dir(root()).args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().expect("sfr binary runs")
}

fn sfr(args: &[&str]) -> Output {
    sfr_env(args, &[])
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
        "sfr-hw-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn seal_with(uri: &str, out: &Path, env: &[(&str, &str)]) -> Output {
    sfr_env(
        &[
            "seal",
            LOG,
            "--rules",
            RULES,
            "--baseline",
            BASELINE,
            "--key-uri",
            uri,
            "--out",
            s(out),
        ],
        env,
    )
}

fn entries(dir: &Path) -> usize {
    std::fs::read_dir(dir).map_or(0, Iterator::count)
}

/// A hardware record: sealed, no evaluation banner anywhere, custody named, and it verifies
/// against `public` with the log, with its custody unattested; `--require-hardware-key` refuses
/// it without a certificate chain.
fn check_hardware_record(out: &Path, public: &Path, custody: &str, seal_out: &Output) {
    assert_eq!(seal_out.status.code(), Some(0), "{}", text(seal_out));
    let printed = String::from_utf8_lossy(&seal_out.stdout);
    assert!(!printed.contains(EVALUATION_LINE), "{printed}");
    assert!(printed.contains(&format!("({custody})")), "{printed}");
    let record = out.join("vtol_transition.sfr");
    let report = std::fs::read_to_string(out.join("vtol_transition.sfr.md")).unwrap();
    assert!(!report.contains("EVALUATION KEY"), "{report}");
    let bytes = std::fs::read_to_string(&record).unwrap();
    assert!(
        bytes.contains(&format!("\"key_custody\":\"{custody}\"")),
        "custody not in the record"
    );
    // It verifies against its public key, with the log. Its custody is the sealer's word: a
    // token's signature does not carry proof of the token, so verify says unattested.
    let v = sfr(&["verify", s(&record), "--pubkey", s(public), "--ulog", LOG]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let shown = String::from_utf8_lossy(&v.stdout);
    assert!(shown.contains("Integrity: VERIFIED"), "{shown}");
    assert!(
        shown.contains(&format!("custody   unattested (declared {custody})\n")),
        "{shown}"
    );
    assert!(!shown.contains(EVALUATION_LINE), "{shown}");
    // --require-hardware-key means attested by a certificate chain, not declared: a bare public
    // key cannot attest even a real token's custody, so it is refused.
    let v = sfr(&[
        "verify",
        s(&record),
        "--pubkey",
        s(public),
        "--require-hardware-key",
    ]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    let shown = String::from_utf8_lossy(&v.stdout);
    assert!(
        shown.contains("Integrity: REFUSED: --require-hardware-key needs custody attested by a certificate chain"),
        "{shown}"
    );
    assert!(!shown.contains("VERIFIED"), "{shown}");
}

/// `sfr pubkey` writes the key's public half to `dir/sfr.pub` and returns its path.
fn export_public(uri: &str, dir: &Path) -> PathBuf {
    let o = sfr(&["pubkey", "--key-uri", uri]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let path = dir.join("sfr.pub");
    std::fs::write(&path, &o.stdout).unwrap();
    path
}

// ---------------------------------------------------------------------------------------------
// Checks that need no token: refused before any module or tool runs.

#[test]
fn bad_key_uris_and_a_missing_helper_are_key_errors_and_write_nothing() {
    let out = scratch();
    for (uri, why) in [
        (
            "pkcs11:object=k?module-path=/m.so&pin-value=1234",
            "pin-value",
        ),
        ("pkcs11:object=k?pin-source=env:P", "module-path"),
        ("hsm:object=k", "not a key URI"),
        ("tpm-sealed:", "key directory"),
        (
            "tpm-sealed:/nonexistent/sfr-key-dir",
            "/nonexistent/sfr-key-dir/sfr.tpm.conf",
        ),
    ] {
        let o = seal_with(uri, &out, &[]);
        assert_eq!(o.status.code(), Some(4), "{uri}: {}", text(&o));
        assert!(text(&o).contains(why), "{uri}: {}", text(&o));
    }
    let o = seal_with(
        "pkcs11:object=k?module-path=/m.so&pin-source=env:P",
        &out,
        &[("SFR_PKCS11_HELPER", "/nonexistent/sfr-pkcs11-helper")],
    );
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    assert!(
        text(&o).contains("cannot run /nonexistent/sfr-pkcs11-helper"),
        "{}",
        text(&o)
    );
    // A key URI with a key file, or with --evaluation-only, is a usage error.
    let o = sfr(&[
        "seal",
        LOG,
        "--rules",
        RULES,
        "--baseline",
        BASELINE,
        "--key-uri",
        "tpm-sealed:x",
        "--key",
        "sfr.key",
        "--out",
        s(&out),
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("give one key source"), "{}", text(&o));
    let o = sfr(&[
        "seal",
        LOG,
        "--rules",
        RULES,
        "--baseline",
        BASELINE,
        "--key-uri",
        "tpm-sealed:x",
        "--evaluation-only",
        "--out",
        s(&out),
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("only to a key file"), "{}", text(&o));
    // --token-cert is gone: sfr records nothing about a token's certification.
    let o = sfr(&[
        "seal",
        LOG,
        "--rules",
        RULES,
        "--baseline",
        BASELINE,
        "--key-uri",
        "tpm-sealed:x",
        "--token-cert",
        "1234",
        "--out",
        s(&out),
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("--token-cert"), "{}", text(&o));
    assert_eq!(entries(&out), 0, "nothing may be written");
    let o = sfr(&[
        "keygen",
        "--tpm-sealed",
        "--evaluation-only",
        "--out",
        s(&out),
    ]);
    assert_eq!(o.status.code(), Some(4));
    let o = sfr(&[
        "keygen",
        "--evaluation-only",
        "--tpm-pcrs",
        "sha256:0",
        "--out",
        s(&out),
    ]);
    assert_eq!(o.status.code(), Some(4));
    let o = sfr(&[
        "keygen",
        "--tpm-sealed",
        "--tpm-parent",
        "81000001",
        "--out",
        s(&out),
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("0x and eight hex digits"), "{}", text(&o));
    assert_eq!(entries(&out), 0, "nothing may be written");
    std::fs::remove_dir_all(out).unwrap();
}

// ---------------------------------------------------------------------------------------------
// pkcs11-token (SoftHSM v2)

fn pkcs11_uri() -> String {
    std::env::var("SFR_TEST_PKCS11_URI")
        .expect("SFR_TEST_PKCS11_URI is set; run scripts/hardware_keys.sh")
}

#[test]
#[ignore = "needs a PKCS#11 token: scripts/hardware_keys.sh"]
fn a_pkcs11_token_seals_a_record_that_verifies_with_its_public_key() {
    let uri = pkcs11_uri();
    let dir = scratch();
    let public = export_public(&uri, &dir);
    let out = dir.join("out");
    let o = seal_with(&uri, &out, &[]);
    check_hardware_record(&out, &public, "pkcs11-token", &o);
    // The same seal time twice gives the same record: Ed25519 is deterministic in the token too.
    let again = dir.join("again");
    let fixed = |o: &Path| {
        sfr(&[
            "seal",
            LOG,
            "--rules",
            RULES,
            "--baseline",
            BASELINE,
            "--key-uri",
            &uri,
            "--out",
            s(o),
            "--seal-time",
            "2026-10-18T15:00:00Z",
        ])
    };
    let first = dir.join("first");
    assert_eq!(fixed(&first).status.code(), Some(0));
    assert_eq!(fixed(&again).status.code(), Some(0));
    assert_eq!(
        std::fs::read(first.join("vtol_transition.sfr")).unwrap(),
        std::fs::read(again.join("vtol_transition.sfr")).unwrap()
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "needs a PKCS#11 token: scripts/hardware_keys.sh"]
fn a_wrong_pin_or_an_unknown_key_writes_nothing() {
    let uri = pkcs11_uri();
    let (path, query) = uri.split_once('?').unwrap();
    let module = query
        .split('&')
        .find(|q| q.starts_with("module-path="))
        .unwrap();
    let out = scratch();
    let wrong_pin = format!("{path}?{module}&pin-source=env:SFR_TEST_WRONG_PIN");
    let o = seal_with(&wrong_pin, &out, &[("SFR_TEST_WRONG_PIN", "000000")]);
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    assert!(text(&o).contains("C_Login"), "{}", text(&o));
    let no_key = uri.replacen("object=", "object=no-such-key-", 1);
    let o = seal_with(&no_key, &out, &[]);
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    assert!(text(&o).contains("no Edwards-curve"), "{}", text(&o));
    assert_eq!(entries(&out), 0, "nothing may be written");
    std::fs::remove_dir_all(out).unwrap();
}

// ---------------------------------------------------------------------------------------------
// tpm-sealed (swtpm)

fn require_tpm() {
    assert!(
        std::env::var_os("SFR_TEST_TPM").is_some(),
        "SFR_TEST_TPM is set; run scripts/hardware_keys.sh"
    );
}

#[test]
#[ignore = "needs a TPM 2.0: scripts/hardware_keys.sh"]
fn a_tpm_sealed_key_seals_a_record_that_verifies_and_keygen_never_overwrites() {
    require_tpm();
    let dir = scratch();
    let key = dir.join("key");
    let o = sfr(&["keygen", "--tpm-sealed", "--out", s(&key)]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let mut files: Vec<String> = std::fs::read_dir(&key)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    files.sort();
    // The seed itself is never written: only the sealed blobs, the settings and the public key.
    assert_eq!(
        files,
        ["sfr.pub", "sfr.tpm.conf", "sfr.tpm.priv", "sfr.tpm.pub"]
    );
    let o = sfr(&["keygen", "--tpm-sealed", "--out", s(&key)]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("never overwrites"), "{}", text(&o));
    let uri = format!("tpm-sealed:{}", s(&key));
    let out = dir.join("out");
    let o = seal_with(&uri, &out, &[]);
    check_hardware_record(&out, &key.join("sfr.pub"), "tpm-sealed", &o);
    // `pubkey` gives the same public key the directory holds.
    let p = sfr(&["pubkey", "--key-uri", &uri]);
    assert_eq!(p.status.code(), Some(0), "{}", text(&p));
    let pem = std::fs::read_to_string(key.join("sfr.pub")).unwrap();
    assert!(String::from_utf8_lossy(&p.stdout).ends_with(&pem));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "needs a TPM 2.0: scripts/hardware_keys.sh"]
fn a_tpm_key_refuses_a_swapped_public_key_and_a_changed_pcr() {
    require_tpm();
    let dir = scratch();
    let key = dir.join("key");
    // PCR 23 is the debug PCR any process may extend; no other test uses it.
    let o = sfr(&[
        "keygen",
        "--tpm-sealed",
        "--tpm-pcrs",
        "sha256:23",
        "--out",
        s(&key),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    assert!(text(&o).contains("PCR policy sha256:23"), "{}", text(&o));
    let uri = format!("tpm-sealed:{}", s(&key));
    let out = dir.join("out");
    assert_eq!(seal_with(&uri, &out, &[]).status.code(), Some(0));
    // A public key in the directory that is not the sealed seed's: refused.
    let other = dir.join("other");
    let o = sfr(&["keygen", "--evaluation-only", "--out", s(&other)]);
    assert_eq!(o.status.code(), Some(0));
    let original = std::fs::read(key.join("sfr.pub")).unwrap();
    std::fs::copy(other.join("sfr.pub"), key.join("sfr.pub")).unwrap();
    let out2 = dir.join("out2");
    let o = seal_with(&uri, &out2, &[]);
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    assert!(text(&o).contains("is not the key in"), "{}", text(&o));
    std::fs::write(key.join("sfr.pub"), original).unwrap();
    // The PCR changes: the TPM refuses to unseal, and nothing is written.
    let extend = Command::new("tpm2_pcrextend")
        .arg(format!("23:sha256={}", "11".repeat(32)))
        .output()
        .expect("tpm2_pcrextend runs");
    assert!(extend.status.success(), "{}", text(&extend));
    let o = seal_with(&uri, &out2, &[]);
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    assert!(text(&o).contains("tpm2_unseal failed"), "{}", text(&o));
    assert_eq!(entries(&out2), 0, "nothing may be written");
    std::fs::remove_dir_all(dir).unwrap();
}
