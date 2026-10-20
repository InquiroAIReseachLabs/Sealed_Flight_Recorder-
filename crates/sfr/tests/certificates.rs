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

/// The current CRLs of the two issuers in the test chain: root (issued inter) and inter (issued
/// the signers). `verify --trust-anchor` needs one for each, unless it is given `--no-crl-check`.
const BOTH_CRLS: [&str; 2] = ["root.crl", "inter.crl"];

fn verify_anchor(record: &Path, anchor: &str, crls: &[&str]) -> Output {
    verify_anchor_with(record, anchor, crls, &[])
}

/// `sfr verify --trust-anchor`, with `--at` when `at` is given.
fn verify_anchor_at(record: &Path, anchor: &str, crls: &[&str], at: Option<&str>) -> Output {
    match at {
        Some(at) => verify_anchor_with(record, anchor, crls, &["--at", at]),
        None => verify_anchor(record, anchor, crls),
    }
}

/// This machine's clock as an RFC 3339 time `offset` seconds from now.
fn now_plus(offset: i64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    sfr_core::seal::format_utc(now + offset)
}

/// [`verify_anchor`] with more command-line words, such as `--no-crl-check`.
fn verify_anchor_with(record: &Path, anchor: &str, crls: &[&str], more: &[&str]) -> Output {
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
    args.extend_from_slice(more);
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
    // The CRLs may be given in either order.
    for crls in [BOTH_CRLS, ["inter.crl", "root.crl"]] {
        let v = verify_anchor(&record, "root.pem", &crls);
        assert_eq!(v.status.code(), Some(0), "{}", text(&v));
        let out = String::from_utf8_lossy(&v.stdout);
        assert!(out.contains("Integrity: VERIFIED (record)"), "{out}");
        assert!(
            out.contains(&format!(
                "trust     certificate chain to the trust anchor {anchor} at the verification time; 2 CRL(s) checked\n"
            )),
            "{out}"
        );
        // The time the chain was judged at is printed, and the seal time is labelled a claim.
        assert!(
            out.contains("time      20")
                && out.contains("(verifier clock); certificate validity was checked at this time, not at the claimed seal time\n"),
            "{out}"
        );
        assert!(
            out.contains("seal time 2026-10-18T15:00:00Z (claimed by the sealer, not proven)\n"),
            "{out}"
        );
        // Each CRL used is printed: its issuer, number, thisUpdate and nextUpdate.
        for line in [
            "crl       CN=sfr test root: CRL number 1, thisUpdate 2026-06-01T00:00:00Z, nextUpdate 2046-01-01T00:00:00Z\n",
            "crl       CN=sfr test inter: CRL number 1, thisUpdate 2026-06-01T00:00:00Z, nextUpdate 2046-01-01T00:00:00Z\n",
        ] {
            assert!(out.contains(line), "{line} in {out}");
        }
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
        "--crl",
        &pki("root.crl"),
        "--crl",
        &pki("inter.crl"),
        "--ulog",
        LOG,
        "--json",
    ]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let json = String::from_utf8_lossy(&v.stdout);
    assert!(json.contains("\"trust\": \"trust-anchor\""), "{json}");
    assert!(
        json.contains("\"crl_check\": true") && json.contains("\"number\": \"1\""),
        "{json}"
    );
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
    let v = verify_anchor(&tampered, "root.pem", &BOTH_CRLS);
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
            &BOTH_CRLS[..],
            None,
            "revoked by a supplied CRL",
        ),
        (
            "expired at the seal time",
            SIGNER_EXPIRED,
            "signer_expired.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &BOTH_CRLS[..],
            None,
            "had expired at the verification time",
        ),
        (
            "not yet valid at the seal time",
            SIGNER,
            "signer.pem",
            Some("inter.pem"),
            "2025-06-01T00:00:00Z",
            "root.pem",
            // Judged as of that time, the 2026 CRLs would be from the future: give the ones current then.
            &["root_2025.crl", "inter_stale.crl"][..],
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
            &BOTH_CRLS[..],
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
            &BOTH_CRLS[..],
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
            &BOTH_CRLS[..],
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
    // The revoked signer passes only when revocation is not checked at all: the CRL is what
    // revokes it.
    let (_, record) = seal(
        SIGNER_REVOKED,
        Some("signer_revoked.pem"),
        Some("inter.pem"),
        SEAL_TIME,
    );
    assert_eq!(
        verify_anchor_with(&record, "root.pem", &[], &["--no-crl-check"])
            .status
            .code(),
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
        text(&o).contains("--crl and --no-crl-check apply only to --trust-anchor"),
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

/// A signer that its issuer has revoked, sealed and ready to verify against `root.pem`.
fn revoked_record() -> PathBuf {
    let (o, record) = seal(
        SIGNER_REVOKED,
        Some("signer_revoked.pem"),
        Some("inter.pem"),
        SEAL_TIME,
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    record
}

#[test]
fn the_order_of_crl_arguments_never_decides_whether_a_revoked_signer_verifies() {
    // Issue 24, F1: webpki used the first CRL of the right issuer, so an older CRL of the same
    // issuer, given first, hid the revocation. The highest CRL number now decides, in any order.
    let record = revoked_record();
    // inter_older.crl is number 0 and lists nothing; inter_stale.crl is number 0, lists nothing and
    // is past its nextUpdate. inter.crl is number 1 and lists the signer.
    let sets: [&[&str]; 8] = [
        &["root.crl", "inter.crl", "inter_older.crl"],
        &["root.crl", "inter_older.crl", "inter.crl"],
        &["inter_older.crl", "inter.crl", "root.crl"],
        &["inter_older.crl", "root.crl", "inter.crl"],
        &["root.crl", "inter.crl", "inter_stale.crl"],
        &["root.crl", "inter_stale.crl", "inter.crl"],
        &["inter_stale.crl", "inter.crl", "root.crl"],
        &[
            "inter_stale.crl",
            "inter_older.crl",
            "root.crl",
            "inter.crl",
        ],
    ];
    for crls in sets {
        let v = verify_anchor(&record, "root.pem", crls);
        assert_eq!(v.status.code(), Some(1), "{crls:?}: {}", text(&v));
        let out = text(&v);
        assert!(
            out.contains("Integrity: FAILED: certificate chain:")
                && out.contains("revoked by a supplied CRL"),
            "{crls:?}: {out}"
        );
        assert!(!out.contains("VERIFIED"), "{crls:?}: {out}");
    }
    // The same files verify a signer that is not revoked, in either order, and the CRLs printed
    // are the current ones (number 1), not the older ones.
    let (o, good) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    for crls in sets {
        let v = verify_anchor(&good, "root.pem", crls);
        assert_eq!(v.status.code(), Some(0), "{crls:?}: {}", text(&v));
        let out = stdout(&v);
        assert!(
            out.contains("2 CRL(s) checked\n")
                && out.contains(
                    "crl       CN=sfr test inter: CRL number 1, thisUpdate 2026-06-01T00:00:00Z"
                ),
            "{crls:?}: {out}"
        );
        assert!(!out.contains("CRL number 0"), "{crls:?}: {out}");
    }
}

#[test]
fn every_issuer_in_the_chain_needs_a_crl_unless_checking_is_switched_off() {
    // Issue 24, F2: with no CRL a revoked signer verified and the trust line said "0 CRL(s)".
    let record = revoked_record();
    let refused = |crls: &[&str], missing: &[&str], present_not: &[&str]| {
        let v = verify_anchor(&record, "root.pem", crls);
        assert_eq!(v.status.code(), Some(1), "{crls:?}: {}", text(&v));
        let out = text(&v);
        assert!(
            out.contains(
                "Integrity: FAILED: certificate chain: no CRL was given for the issuer(s)"
            ),
            "{crls:?}: {out}"
        );
        for m in missing {
            assert!(out.contains(m), "{crls:?}: {m} in {out}");
        }
        for m in present_not {
            let issuers = out
                .split("issuer(s) ")
                .nth(1)
                .unwrap()
                .split(" of the certificates")
                .next()
                .unwrap();
            assert!(
                !issuers.contains(m),
                "{crls:?}: {m} should not be missing in {out}"
            );
        }
        assert!(!out.contains("VERIFIED"), "{crls:?}: {out}");
    };
    // None: both issuers are missing.
    refused(
        &[],
        &["CN=sfr test root", "CN=sfr test inter", "none were given"],
        &[],
    );
    // Only the signer's issuer: the intermediate's issuer, root, is missing.
    refused(
        &["inter.crl"],
        &["CN=sfr test root"],
        &["CN=sfr test inter"],
    );
    // Only root's: inter, the signer's issuer, is missing.
    refused(&["root.crl"], &["CN=sfr test inter"], &["CN=sfr test root"]);
    // A CRL of an unrelated issuer, even with a high number, covers nothing.
    refused(
        &["inter.crl", "other_root.crl"],
        &[
            "CN=sfr test root",
            "the CRLs given are from CN=sfr test inter; CN=sfr test other_root",
        ],
        &["CN=sfr test inter"],
    );
    // Switched off, it verifies, says so in the output, in the warning and in the JSON.
    let v = verify_anchor_with(&record, "root.pem", &[], &["--no-crl-check"]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    let out = stdout(&v);
    assert!(
        out.contains(
            "revocation NOT CHECKED (--no-crl-check): a revoked certificate would still verify\n"
        ),
        "{out}"
    );
    assert!(
        String::from_utf8_lossy(&v.stderr)
            .contains("sfr: warning: --no-crl-check: revocation is NOT checked"),
        "{}",
        text(&v)
    );
    let j = verify_anchor_with(&record, "root.pem", &[], &["--no-crl-check", "--json"]);
    assert!(stdout(&j).contains("\"crl_check\": false"), "{}", text(&j));
    // The switch contradicts --crl, and means nothing without --trust-anchor.
    let v = verify_anchor_with(&record, "root.pem", &["inter.crl"], &["--no-crl-check"]);
    assert_eq!(v.status.code(), Some(4), "{}", text(&v));
    assert!(
        text(&v).contains("--no-crl-check and --crl contradict each other"),
        "{}",
        text(&v)
    );
}

#[test]
fn a_crl_past_its_next_update_fails_against_the_verification_time() {
    // Issue 24, F2: nextUpdate was ignored, so a stale CRL alone was accepted. The record is
    // sealed in mid-June 2025, when this CRL was current, and the claimed time must not help it.
    let (o, record) = seal(
        SIGNER_LAPSED,
        Some("signer_lapsed.pem"),
        Some("inter.pem"),
        "2025-06-15T00:00:00Z",
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let v = verify_anchor(&record, "root.pem", &["root.crl", "inter_stale.crl"]);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    let out = text(&v);
    assert!(
        out.contains("Integrity: FAILED: certificate chain: the current CRL of CN=sfr test inter (number 0) is out of date: its nextUpdate 2025-07-01T00:00:00Z is not after the verification time 20"),
        "{out}"
    );
    assert!(!out.contains("VERIFIED"), "{out}");
}

#[test]
fn two_different_crls_with_one_number_from_one_issuer_are_refused() {
    let record = revoked_record();
    for crls in [
        ["root.crl", "inter.crl", "inter_same.crl"],
        ["inter_same.crl", "root.crl", "inter.crl"],
    ] {
        let v = verify_anchor(&record, "root.pem", &crls);
        assert_eq!(v.status.code(), Some(1), "{crls:?}: {}", text(&v));
        assert!(
            text(&v)
                .contains("two different CRLs from CN=sfr test inter have the same CRL number 1"),
            "{crls:?}: {}",
            text(&v)
        );
    }
}

#[test]
fn a_crl_of_another_issuer_never_displaces_the_issuers_own() {
    // other_root.crl is number 99, far above inter.crl's 1, but it speaks for another issuer.
    let record = revoked_record();
    let v = verify_anchor(
        &record,
        "root.pem",
        &["other_root.crl", "root.crl", "inter.crl"],
    );
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    assert!(
        text(&v).contains("revoked by a supplied CRL"),
        "{}",
        text(&v)
    );
    // And it is not printed as used for a chain it is not part of.
    let (_, good) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    let v = verify_anchor(
        &good,
        "root.pem",
        &["other_root.crl", "root.crl", "inter.crl"],
    );
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    assert!(!stdout(&v).contains("other_root"), "{}", text(&v));
    assert!(stdout(&v).contains("2 CRL(s) checked\n"), "{}", text(&v));
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
        "--crl",
        &pki("root.crl"),
        "--crl",
        &pki("inter.crl"),
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
        "--crl",
        &pki("root.crl"),
        "--crl",
        &pki("inter.crl"),
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
        "--crl",
        &pki("root.crl"),
        "--crl",
        &pki("inter.crl"),
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
    let v = verify_anchor(&record, "root.pem", &BOTH_CRLS);
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    let out = text(&v);
    assert!(
        out.contains("Integrity: FAILED: certificate chain:")
            && out.contains("had expired at the verification time"),
        "{out}"
    );
    assert!(!out.contains("VERIFIED"), "{out}");
    // Asking, explicitly and on the record, for the verification to be made as of mid-2025
    // judges the same record at that time, and says so. The CRLs are judged at that time too:
    // the ones current in June 2025 pass, the 2026 ones would be from the future.
    let crls_then = ["root_2025.crl", "inter_stale.crl"];
    let v = verify_anchor_at(&record, "root.pem", &crls_then, Some(backdated));
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
    let v = verify_anchor_at(&record, "root.pem", &BOTH_CRLS, Some(backdated));
    assert_eq!(v.status.code(), Some(1), "{}", text(&v));
    assert!(
        text(&v).contains(
            "has thisUpdate 2026-06-01T00:00:00Z, after the verification time 2025-06-01T00:00:00Z"
        ),
        "{}",
        text(&v)
    );
    let json = verify_anchor_with(
        &record,
        "root.pem",
        &crls_then,
        &["--at", backdated, "--json"],
    );
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
    let pubkey = record.with_file_name("sfr.pub");
    std::fs::write(
        &pubkey,
        sfr_core::keys::public_key_pem(&sfr_core::crypto::Signer::public_key(
            &sfr_core::crypto::rustcrypto::FileKey::from_seed(&[SIGNER; 32], "k"),
        )),
    )
    .unwrap();
    let r = record.to_str().unwrap();
    let (root, root_crl, inter_crl) = (pki("root.pem"), pki("root.crl"), pki("inter.crl"));
    let trust_sets: [Vec<&str>; 2] = [
        vec![
            "--trust-anchor",
            &root,
            "--crl",
            &root_crl,
            "--crl",
            &inter_crl,
        ],
        vec!["--pubkey", pubkey.to_str().unwrap()],
    ];
    for args in trust_sets {
        let mut a = vec!["verify", "--allow-evaluation-key", r];
        a.extend(args.iter().copied());
        let v = sfr(&a);
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
        let later = now_plus(2 * 86_400);
        let mut with_at = a.clone();
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
        verify_anchor(&ahead, "root.pem", &BOTH_CRLS).status.code(),
        Some(0)
    );
}
