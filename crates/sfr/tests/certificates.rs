//! Signer certificates and trust anchors (SPEC B1.3, B1.10 Certificates): `seal --cert --chain`
//! and `verify --trust-anchor --crl`, against the test PKI in `testdata/pki/`
//! (`scripts/testdata/make_test_pki.sh`). Every rejection the spec lists has a case here, and
//! `verify` given no trust source checks nothing.
// A panicking test is a failing test, so tests may use expect and unwrap.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use sfr_core::keys::{ed25519_pkcs8_v1_der, pem_encode};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const LOG: &str = "testdata/synthetic/custom_detection.ulg";
const RULES: &str = "testdata/rules/synthetic_custom_detection.toml";
const BASELINE: &str = "testdata/baselines/synthetic_custom_detection.params";
const SEAL_TIME: &str = "2026-10-18T15:00:00Z";
const PKI: &str = "testdata/pki";

/// The seed byte of each test key, as `scripts/testdata/make_test_pki.sh` makes them.
const SIGNER: u8 = 0x30;
const SIGNER_EXPIRED: u8 = 0x31;
const SIGNER_SERVER: u8 = 0x32;
const SIGNER_REVOKED: u8 = 0x33;

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
        "sfr-certs-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pki(name: &str) -> String {
    format!("{PKI}/{name}")
}

/// The test key with this seed byte, written as `sfr.key` in a new directory.
fn key_file(seed: u8) -> PathBuf {
    let dir = scratch();
    let path = dir.join("sfr.key");
    std::fs::write(
        &path,
        pem_encode("PRIVATE KEY", &ed25519_pkcs8_v1_der(&[seed; 32])),
    )
    .unwrap();
    path
}

/// Seals the test log with key `seed`, `cert` and `chain` (names in `testdata/pki/`), at
/// `time`; returns the output and the record path.
fn seal(seed: u8, cert: Option<&str>, chain: Option<&str>, time: &str) -> (Output, PathBuf) {
    let key = key_file(seed);
    let out = key.parent().unwrap().join("out");
    let cert = cert.map(pki);
    let chain = chain.map(pki);
    let mut args = vec![
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
        time,
        "--out",
        out.to_str().unwrap(),
    ];
    if let Some(c) = &cert {
        args.extend(["--cert", c.as_str()]);
    }
    if let Some(c) = &chain {
        args.extend(["--chain", c.as_str()]);
    }
    let o = sfr(&args);
    (o, out.join("custom_detection.sfr"))
}

fn verify_anchor(record: &Path, anchor: &str, crls: &[&str]) -> Output {
    let anchor = pki(anchor);
    let crls: Vec<String> = crls.iter().map(|c| pki(c)).collect();
    let mut args = vec![
        "verify",
        record.to_str().unwrap(),
        "--trust-anchor",
        &anchor,
    ];
    for c in &crls {
        args.extend(["--crl", c.as_str()]);
    }
    sfr(&args)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sfr_core::crypto::CryptoBackend;
    sfr_core::hex(&sfr_core::crypto::rustcrypto::RustCrypto.sha256(bytes))
}

/// The DER of a PEM certificate in `testdata/pki/`.
fn der(name: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(root().join(pki(name))).unwrap();
    sfr_core::keys::pem_decode(&text, "CERTIFICATE").unwrap()
}

#[test]
fn a_chain_to_the_trust_anchor_verifies_and_names_the_anchor() {
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let anchor = format!("sha256:{}", sha256_hex(&der("root.pem")));
    for crls in [&[][..], &["inter.crl"][..]] {
        let v = verify_anchor(&record, "root.pem", crls);
        assert_eq!(v.status.code(), Some(0), "{}", text(&v));
        let out = String::from_utf8_lossy(&v.stdout);
        assert!(out.contains("Integrity: VERIFIED (record)"), "{out}");
        assert!(
            out.contains(&format!(
                "trust     certificate chain to the trust anchor {anchor} at the seal time; {} CRL(s) checked",
                crls.len()
            )),
            "{out}"
        );
        // Custody stays declared: a chain proves who the key belongs to, not where it lives.
        assert!(
            out.contains(&format!(
                "custody   file-evaluation (declared; the key's certificate chains to the trust anchor {anchor})"
            )),
            "{out}"
        );
    }
    // With the log as well.
    let v = sfr(&[
        "verify",
        record.to_str().unwrap(),
        "--trust-anchor",
        &pki("root.pem"),
        "--ulog",
        LOG,
        "--json",
    ]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let json = String::from_utf8_lossy(&v.stdout);
    assert!(json.contains("\"trust\": \"trust-anchor\""), "{json}");
    assert!(json.contains("\"key_custody_proven\": false"), "{json}");
    // The certificate travels in the signed seal leaf: changing it breaks the signature.
    let bytes = std::fs::read_to_string(&record).unwrap();
    let start = bytes.find("\"signer_certificate\":\"").unwrap() + 30;
    let mut changed = bytes.clone().into_bytes();
    changed[start] = if changed[start] == b'A' { b'B' } else { b'A' };
    let tampered = record.with_file_name("tampered.sfr");
    std::fs::write(&tampered, changed).unwrap();
    let v = verify_anchor(&tampered, "root.pem", &[]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    assert!(text(&v).contains("Integrity: FAILED"), "{}", text(&v));
}

#[test]
fn every_rejection_the_spec_lists_fails_with_its_reason() {
    for (case, seed, cert, chain, time, anchor, crls, why) in [
        (
            "revoked by a supplied CRL",
            SIGNER_REVOKED,
            "signer_revoked.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &["inter.crl"][..],
            "revoked by a supplied CRL",
        ),
        (
            "expired at the seal time",
            SIGNER_EXPIRED,
            "signer_expired.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &[][..],
            "had expired at the seal time",
        ),
        (
            "not yet valid at the seal time",
            SIGNER,
            "signer.pem",
            Some("inter.pem"),
            "2025-06-01T00:00:00Z",
            "root.pem",
            &[][..],
            "not yet valid at the seal time",
        ),
        (
            "no code signing usage",
            SIGNER_SERVER,
            "signer_server.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &[][..],
            "lacks extended key usage code signing",
        ),
        (
            "another trust anchor",
            SIGNER,
            "signer.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "other_root.pem",
            &[][..],
            "does not reach a supplied trust anchor",
        ),
        (
            "intermediate missing from the record",
            SIGNER,
            "signer.pem",
            None,
            SEAL_TIME,
            "root.pem",
            &[][..],
            "does not reach a supplied trust anchor",
        ),
    ] {
        let (o, record) = seal(seed, Some(cert), chain, time);
        assert_eq!(o.status.code(), Some(0), "{case}: {}", text(&o));
        let v = verify_anchor(&record, anchor, crls);
        assert_eq!(v.status.code(), Some(1), "{case}: {}", text(&v));
        let out = text(&v);
        assert!(
            out.contains("Integrity: FAILED: certificate chain:") && out.contains(why),
            "{case}: {out}"
        );
        assert!(out.contains("Flight rules: UNKNOWN"), "{case}: {out}");
        assert!(!out.contains("VERIFIED"), "{case}: {out}");
    }
    // The revoked signer passes when no CRL is given: the CRL is what revokes it.
    let (_, record) = seal(
        SIGNER_REVOKED,
        Some("signer_revoked.pem"),
        Some("inter.pem"),
        SEAL_TIME,
    );
    assert_eq!(
        verify_anchor(&record, "root.pem", &[]).status.code(),
        Some(0)
    );
}

#[test]
fn seal_refuses_a_certificate_for_another_key_and_verify_refuses_two_trust_sources() {
    // The certificate certifies the 0x30 key; the record is signed by 0x31.
    let (o, record) = seal(
        SIGNER_EXPIRED,
        Some("signer.pem"),
        Some("inter.pem"),
        SEAL_TIME,
    );
    assert_eq!(o.status.code(), Some(4), "{}", text(&o));
    assert!(text(&o).contains("not the signing key"), "{}", text(&o));
    assert!(!record.exists() && !record.parent().unwrap().exists());
    let key = key_file(SIGNER);
    let k = key.to_str().unwrap();
    let o = sfr(&[
        "seal",
        LOG,
        "--rules",
        RULES,
        "--baseline",
        BASELINE,
        "--key",
        k,
        "--evaluation-only",
        "--chain",
        &pki("inter.pem"),
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(
        text(&o).contains("--chain applies only with --cert"),
        "{}",
        text(&o)
    );
    let (_, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    let r = record.to_str().unwrap();
    let pubkey = key.parent().unwrap().join("sfr.pub");
    std::fs::write(
        &pubkey,
        sfr_core::keys::public_key_pem(&sfr_core::crypto::Signer::public_key(
            &sfr_core::crypto::rustcrypto::FileKey::from_seed(&[SIGNER; 32], "k"),
        )),
    )
    .unwrap();
    let o = sfr(&[
        "verify",
        r,
        "--pubkey",
        pubkey.to_str().unwrap(),
        "--trust-anchor",
        &pki("root.pem"),
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(text(&o).contains("give one trust source"), "{}", text(&o));
    let o = sfr(&[
        "verify",
        r,
        "--pubkey",
        pubkey.to_str().unwrap(),
        "--crl",
        &pki("inter.crl"),
    ]);
    assert_eq!(o.status.code(), Some(4));
    assert!(
        text(&o).contains("--crl applies only to --trust-anchor"),
        "{}",
        text(&o)
    );
    // With --pubkey the same record verifies, and says what the signature was checked against.
    let o = sfr(&["verify", r, "--pubkey", pubkey.to_str().unwrap()]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("trust     the public key given with --pubkey"),
        "{out}"
    );
    assert!(
        out.contains("custody   file-evaluation (declared)\n"),
        "{out}"
    );
}

#[test]
fn a_record_without_a_certificate_cannot_chain_to_an_anchor() {
    let (o, record) = seal(SIGNER, None, None, SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let v = verify_anchor(&record, "root.pem", &[]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    assert!(
        text(&v).contains("Integrity: FAILED: the record carries no signer certificate"),
        "{}",
        text(&v)
    );
    // The key and custody the record names are still shown, marked as its claims.
    assert!(
        text(&v).contains("(named by the record, not proven)"),
        "{}",
        text(&v)
    );
}

#[test]
fn verify_with_no_trust_source_checks_nothing_and_exits_non_zero() {
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let v = sfr(&["verify", record.to_str().unwrap()]);
    assert_eq!(v.status.code(), Some(4), "{}", text(&v));
    let out = String::from_utf8_lossy(&v.stdout);
    assert!(
        out.contains("Integrity: NOT CHECKED (no trusted key given)\n"),
        "{out}"
    );
    assert!(!out.contains("VERIFIED"), "{out}");
    assert!(
        out.contains("custody   file-evaluation (declared by the record, not proven)"),
        "{out}"
    );
    assert!(out.contains("key       sha256:"), "{out}");
    assert!(
        out.contains("--pubkey <sfr.pub>") && out.contains("--trust-anchor <ca.pem>"),
        "{out}"
    );
    let v = sfr(&["verify", record.to_str().unwrap(), "--json"]);
    assert_eq!(v.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&v.stdout).contains("\"integrity\": \"NOT CHECKED\""));
}
