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

mod forge;

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
const SIGNER_LAPSED: u8 = 0x34;

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
    verify_anchor_at(record, anchor, crls, None)
}

/// `sfr verify --trust-anchor`, with `--at` when `at` is given.
fn verify_anchor_at(record: &Path, anchor: &str, crls: &[&str], at: Option<&str>) -> Output {
    let anchor = pki(anchor);
    let crls: Vec<String> = crls.iter().map(|c| pki(c)).collect();
    let mut args = vec![
        "verify",
        "--allow-evaluation-key",
        record.to_str().unwrap(),
        "--trust-anchor",
        &anchor,
    ];
    for c in &crls {
        args.extend(["--crl", c.as_str()]);
    }
    if let Some(at) = at {
        args.extend(["--at", at]);
    }
    sfr(&args)
}

/// This machine's clock as an RFC 3339 time `offset` seconds from now.
fn now_plus(offset: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sfr_core::seal::format_utc(now + offset)
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
                "trust     certificate chain to the trust anchor {anchor} at the verification time; {} CRL(s) checked",
                crls.len()
            )),
            "{out}"
        );
        // The time the chain was judged at is printed, and the seal time is labelled a claim.
        assert!(
            out.contains("time      20") && out.contains("(verifier clock); certificate validity was checked at this time, not at the claimed seal time\n"),
            "{out}"
        );
        assert!(
            out.contains("seal time 2026-10-18T15:00:00Z (claimed by the sealer, not proven)\n"),
            "{out}"
        );
        // Custody is attested by the chain to the anchor, and still says what the sealer declared.
        assert!(
            out.contains(&format!(
                "custody   attested by certificate chain to the trust anchor {anchor} (declared file-evaluation)"
            )),
            "{out}"
        );
    }
    // With the log as well.
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
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
    assert!(json.contains("\"custody_attested\": true"), "{json}");
    assert!(
        json.contains("\"key_custody\": \"file-evaluation\""),
        "{json}"
    );
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
    for (case, seed, cert, chain, time, anchor, crls, at, why) in [
        (
            "revoked by a supplied CRL",
            SIGNER_REVOKED,
            "signer_revoked.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &["inter.crl"][..],
            None,
            "revoked by a supplied CRL",
        ),
        (
            "expired at the verification time",
            SIGNER_EXPIRED,
            "signer_expired.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &[][..],
            None,
            "had expired at the verification time",
        ),
        (
            "not yet valid at the time given with --at",
            SIGNER,
            "signer.pem",
            Some("inter.pem"),
            "2025-06-01T00:00:00Z",
            "root.pem",
            &[][..],
            Some("2025-06-01T00:00:00Z"),
            "not yet valid at the verification time",
        ),
        (
            "no code signing usage",
            SIGNER_SERVER,
            "signer_server.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &[][..],
            None,
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
            None,
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
            None,
            "does not reach a supplied trust anchor",
        ),
    ] {
        let (o, record) = seal(seed, Some(cert), chain, time);
        assert_eq!(o.status.code(), Some(0), "{case}: {}", text(&o));
        let v = verify_anchor_at(&record, anchor, crls, at);
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
        "--allow-evaluation-key",
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
        "--allow-evaluation-key",
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
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        r,
        "--pubkey",
        pubkey.to_str().unwrap(),
    ]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("trust     the public key given with --pubkey"),
        "{out}"
    );
    assert!(
        out.contains("custody   unattested (declared file-evaluation)\n"),
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
        out.contains("custody   unattested (declared file-evaluation)"),
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

#[test]
fn custody_is_attested_by_the_chain_and_only_by_the_chain() {
    // A record that declares pkcs11-token, signed by the key the test CA certified.
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let declared = record.with_file_name("declared.sfr");
    std::fs::write(
        &declared,
        forge::relabelled_as_pkcs11(
            &std::fs::read(&record).unwrap(),
            &forge::key_from_seed(&[SIGNER; 32]),
        ),
    )
    .unwrap();
    let anchor = format!("sha256:{}", sha256_hex(&der("root.pem")));

    // With the chain, --require-hardware-key is met: the line says attested, by which anchor.
    let v = sfr(&[
        "verify",
        declared.to_str().unwrap(),
        "--trust-anchor",
        &pki("root.pem"),
        "--require-hardware-key",
    ]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let out = stdout(&v);
    assert!(
        out.contains(&format!(
            "custody   attested by certificate chain to the trust anchor {anchor} (declared pkcs11-token)\n"
        )),
        "{out}"
    );
    assert!(!out.contains("EVALUATION KEY"), "{out}");
    let j = sfr(&[
        "verify",
        declared.to_str().unwrap(),
        "--trust-anchor",
        &pki("root.pem"),
        "--json",
    ]);
    let json = stdout(&j);
    assert!(
        json.contains("\"custody_attested\": true")
            && json.contains("\"key_custody\": \"pkcs11-token\""),
        "{json}"
    );

    // The same record checked against the bare public key is unattested, and the flag refuses it.
    let pubkey = declared.with_file_name("sfr.pub");
    std::fs::write(
        &pubkey,
        sfr_core::keys::public_key_pem(&sfr_core::crypto::Signer::public_key(
            &forge::key_from_seed(&[SIGNER; 32]),
        )),
    )
    .unwrap();
    let v = sfr(&[
        "verify",
        declared.to_str().unwrap(),
        "--pubkey",
        pubkey.to_str().unwrap(),
    ]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    assert!(
        stdout(&v).contains("custody   unattested (declared pkcs11-token)\n"),
        "{}",
        text(&v)
    );
    let v = sfr(&[
        "verify",
        declared.to_str().unwrap(),
        "--pubkey",
        pubkey.to_str().unwrap(),
        "--require-hardware-key",
    ]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    assert!(
        stdout(&v).contains("Integrity: REFUSED: --require-hardware-key needs custody attested by a certificate chain"),
        "{}",
        text(&v)
    );

    // A chain does not turn a declared evaluation key into hardware: still refused.
    let v = sfr(&[
        "verify",
        record.to_str().unwrap(),
        "--trust-anchor",
        &pki("root.pem"),
        "--allow-evaluation-key",
        "--require-hardware-key",
    ]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    assert!(
        stdout(&v).contains("does not accept a record that declares custody file-evaluation"),
        "{}",
        text(&v)
    );
}

#[test]
fn a_backdated_seal_time_cannot_put_an_expired_certificate_back_in_its_window() {
    // signer_lapsed.pem was valid 2025-02-01 to 2025-12-31 and is expired now, but its window lies
    // inside inter's and root's, so a seal time of 2025-06-01 puts the whole chain "in window". The
    // seal time is the sealer's claim: the key holder wrote it, so it must decide nothing.
    let backdated = "2025-06-01T00:00:00Z";
    let (o, record) = seal(
        SIGNER_LAPSED,
        Some("signer_lapsed.pem"),
        Some("inter.pem"),
        backdated,
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let v = verify_anchor(&record, "root.pem", &[]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    let out = text(&v);
    assert!(
        out.contains("Integrity: FAILED: certificate chain:")
            && out.contains("had expired at the verification time"),
        "{out}"
    );
    assert!(!out.contains("VERIFIED"), "{out}");
    // Asking, explicitly and on the record, for the verification to be made as of mid-2025
    // judges the same record at that time, and says so.
    let v = verify_anchor_at(&record, "root.pem", &[], Some(backdated));
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let out = String::from_utf8_lossy(&v.stdout);
    assert!(
        out.contains(
            "time      2025-06-01T00:00:00Z (--at); certificate validity was checked at this time, not at the claimed seal time\n"
        ),
        "{out}"
    );
    assert!(
        out.contains("seal time 2025-06-01T00:00:00Z (claimed by the sealer, not proven)"),
        "{out}"
    );
    let json = sfr(&[
        "verify",
        "--allow-evaluation-key",
        record.to_str().unwrap(),
        "--trust-anchor",
        &pki("root.pem"),
        "--at",
        backdated,
        "--json",
    ]);
    let json = String::from_utf8_lossy(&json.stdout);
    assert!(
        json.contains("\"seal_time_claimed_utc\": \"2025-06-01T00:00:00Z\"")
            && json.contains("\"verification_time_utc\": \"2025-06-01T00:00:00Z\"")
            && json.contains("\"verification_time_source\": \"--at\""),
        "{json}"
    );
}

#[test]
fn a_seal_time_in_the_verifiers_future_is_refused_with_or_without_a_certificate() {
    // One day ahead of this machine's clock, with a certificate that is valid then (until 2036).
    let tomorrow = now_plus(86_400);
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), &tomorrow);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    for args in [
        vec!["--trust-anchor".to_string(), pki("root.pem")],
        vec!["--pubkey".to_string(), {
            let pubkey = record.with_file_name("sfr.pub");
            std::fs::write(
                &pubkey,
                sfr_core::keys::public_key_pem(&sfr_core::crypto::Signer::public_key(
                    &sfr_core::crypto::rustcrypto::FileKey::from_seed(&[SIGNER; 32], "k"),
                )),
            )
            .unwrap();
            pubkey.to_str().unwrap().to_string()
        }],
    ] {
        let mut a = vec![
            "verify".to_string(),
            "--allow-evaluation-key".to_string(),
            record.to_str().unwrap().to_string(),
        ];
        a.extend(args.clone());
        let refs: Vec<&str> = a.iter().map(String::as_str).collect();
        let v = sfr(&refs);
        assert_eq!(v.status.code(), Some(1), "{args:?}: {}", text(&v));
        let out = text(&v);
        assert!(
            out.contains("Integrity: FAILED: the seal time claimed by the sealer")
                && out.contains("is later than the verification time")
                && out.contains("300 s of clock skew"),
            "{args:?}: {out}"
        );
        assert!(!out.contains("VERIFIED"), "{args:?}: {out}");
        // A verification time the verifier chooses, after the claimed time, accepts it.
        let mut with_at = refs.clone();
        let later = now_plus(2 * 86_400);
        with_at.extend(["--at", &later]);
        let v = sfr(&with_at);
        assert_eq!(v.status.code(), Some(0), "{args:?}: {}", text(&v));
    }
    // The skew allowance is stated and small: a few minutes ahead still verifies.
    let (_, ahead) = seal(
        SIGNER,
        Some("signer.pem"),
        Some("inter.pem"),
        &now_plus(120),
    );
    assert_eq!(
        verify_anchor(&ahead, "root.pem", &[]).status.code(),
        Some(0)
    );
}
