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
const SIGNER_CODESIGN: u8 = 0x35;
const SIGNER_BOTH: u8 = 0x36;
const SIGNER_NOSIG: u8 = 0x37;
const SIGNER_NOKEYUSAGE: u8 = 0x38;

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

/// The test CRLs were issued on 2026-06-01, long before the tests run: every verify here allows
/// them that age, except the tests of the age limit itself.
const TEST_CRL_AGE: &str = "7300d";

/// The current CRLs of the two issuers in the test chain: root (issued inter) and inter (issued
/// the signers). `verify --trust-anchor` needs one for each, unless it is given `--no-crl-check`.
const BOTH_CRLS: [&str; 2] = ["root.crl", "inter.crl"];

fn verify_anchor(record: &Path, anchor: &str, crls: &[&str]) -> Output {
    verify_anchor_with(record, anchor, crls, &[])
}

/// `sfr verify --trust-anchor`, with `--at` when `at` is given.
fn verify_anchor_at(record: &Path, anchor: &str, crls: &[&str], at: Option<&str>) -> Output {
    match at {
        Some(at) => verify_anchor_with(record, anchor, crls, &["--at", at, "--allow-past-at"]),
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
    // --max-crl-age applies to CRLs, and --no-crl-check checks none: the two are not given together.
    if !more.contains(&"--no-crl-check") {
        args.extend(["--max-crl-age", TEST_CRL_AGE]);
    }
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
                "trust     certificate chain to the trust anchor {anchor} at the verification time; 2 CRL(s) checked, each with thisUpdate at most 630720000 s before the verification time (--max-crl-age)\n"
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
        "--max-crl-age",
        TEST_CRL_AGE,
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
            "issued for TLS server authentication only",
            SIGNER_SERVER,
            "signer_server.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &BOTH_CRLS[..],
            None,
            "lists TLS server authentication but not the sfr record-signing usage",
        ),
        (
            "issued for code signing only",
            SIGNER_CODESIGN,
            "signer_codesign.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &BOTH_CRLS[..],
            None,
            "lists code signing but not the sfr record-signing usage",
        ),
        (
            "record signing and also code signing and server authentication",
            SIGNER_BOTH,
            "signer_both.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &BOTH_CRLS[..],
            None,
            "also lists code signing; a key that signs records must not be certified for other purposes",
        ),
        (
            "keyUsage without digitalSignature",
            SIGNER_NOSIG,
            "signer_nosig.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &BOTH_CRLS[..],
            None,
            "keyUsage lacks digitalSignature",
        ),
        (
            "no keyUsage extension",
            SIGNER_NOKEYUSAGE,
            "signer_nokeyusage.pem",
            Some("inter.pem"),
            SEAL_TIME,
            "root.pem",
            &BOTH_CRLS[..],
            None,
            "has no keyUsage extension",
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
        assert!(out.contains("Rule checks: UNKNOWN"), "{case}: {out}");
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
        "--max-crl-age",
        TEST_CRL_AGE,
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
        text(&o).contains("--crl, --no-crl-check, --max-crl-age and --allow-partial-chain apply only to --trust-anchor"),
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
    // webpki used the first CRL of the right issuer, so an older CRL of the same
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
            out.contains("2 CRL(s) checked, each with thisUpdate at most 630720000 s before the verification time (--max-crl-age)\n")
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
    // With no CRL a revoked signer verified and the trust line said "0 CRL(s)".
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
    // nextUpdate was ignored, so a stale CRL alone was accepted. The record is
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
    assert!(stdout(&v).contains("2 CRL(s) checked, each with thisUpdate at most 630720000 s before the verification time (--max-crl-age)\n"), "{}", text(&v));
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
        "--no-report",
        "--trust-anchor",
        &pki("root.pem"),
        "--max-crl-age",
        TEST_CRL_AGE,
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
        "--no-report",
        "--trust-anchor",
        &pki("root.pem"),
        "--max-crl-age",
        TEST_CRL_AGE,
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
        "--no-report",
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
        "--no-report",
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
        "--max-crl-age",
        TEST_CRL_AGE,
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
        &["--at", backdated, "--allow-past-at", "--json"],
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
            "--max-crl-age",
            TEST_CRL_AGE,
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

/// A time in the past needs --allow-past-at, and the output then says first, in plain words,
/// that it verified as of that time and whether the chain holds now.
#[test]
fn a_past_verification_time_needs_its_flag_and_says_so_first() {
    // signer_lapsed.pem was valid 2025-02-01 to 2025-12-31; root_2025.crl and inter_stale.crl
    // were current in June 2025.
    let (o, record) = seal(
        SIGNER_LAPSED,
        Some("signer_lapsed.pem"),
        Some("inter.pem"),
        "2025-06-15T00:00:00Z",
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let crls = ["root_2025.crl", "inter_stale.crl"];
    let at = "2025-06-15T12:00:00Z";
    let without = sfr(&[
        "verify",
        "--allow-evaluation-key",
        record.to_str().unwrap(),
        "--trust-anchor",
        &pki("root.pem"),
        "--crl",
        &pki(crls[0]),
        "--crl",
        &pki(crls[1]),
        "--max-crl-age",
        TEST_CRL_AGE,
        "--at",
        at,
    ]);
    assert_eq!(without.status.code(), Some(4), "{}", text(&without));
    assert!(
        text(&without).contains("Add --allow-past-at"),
        "{}",
        text(&without)
    );
    let with = verify_anchor_with(&record, "root.pem", &crls, &["--at", at, "--allow-past-at"]);
    assert_eq!(with.status.code(), Some(0), "{}", text(&with));
    assert_eq!(
        stdout(&with).lines().next(),
        Some(
            "VERIFIED as of 2025-06-15T12:00:00Z at the verifier's request (--at, --allow-past-at), not now: the certificate chain is NOT valid now"
        ),
        "{}",
        text(&with)
    );
}

/// Every certificate, chain, trust anchor and CRL file is read up to the same 16 MiB as the rules
/// file; a longer one is refused as over an input limit (exit 3), not cut and not read whole.
#[test]
fn a_certificate_chain_anchor_or_crl_file_over_the_limit_is_refused() {
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let dir = scratch();
    let big = dir.join("big.pem");
    let mut bytes = vec![b'#'; 16 * 1024 * 1024 + 1];
    bytes.push(b'\n');
    std::fs::write(&big, &bytes).unwrap();
    let big = big.to_str().unwrap();
    let limit = "the file exceeds the input limit of 16777216 bytes (SPEC B1.4)";
    let key = key_file(SIGNER);
    let out = key.parent().unwrap().join("out2");
    for (flag, label) in [
        ("--cert", "signer certificate"),
        ("--chain", "certificate chain"),
    ] {
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
            "--out",
            out.to_str().unwrap(),
        ];
        let signer = pki("signer.pem");
        if flag == "--chain" {
            args.extend(["--cert", signer.as_str()]);
        }
        args.extend([flag, big]);
        let o = sfr(&args);
        assert_eq!(o.status.code(), Some(3), "{flag}: {}", text(&o));
        assert!(
            text(&o).contains(label) && text(&o).contains(limit),
            "{flag}: {}",
            text(&o)
        );
    }
    let rec = record.to_str().unwrap();
    let (root_pem, root_crl, inter_crl) = (pki("root.pem"), pki("root.crl"), pki("inter.crl"));
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        rec,
        "--trust-anchor",
        big,
        "--crl",
        &root_crl,
        "--crl",
        &inter_crl,
    ]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(
        text(&o).contains("trust anchor") && text(&o).contains(limit),
        "{}",
        text(&o)
    );
    let o = sfr(&[
        "verify",
        "--allow-evaluation-key",
        rec,
        "--trust-anchor",
        &root_pem,
        "--crl",
        &root_crl,
        "--crl",
        big,
    ]);
    assert_eq!(o.status.code(), Some(3), "{}", text(&o));
    assert!(
        text(&o).contains("CRL") && text(&o).contains(limit),
        "{}",
        text(&o)
    );
}

/// A CA whose issuer and subject names are the same but that another key signed is an
/// intermediate, not a root: as an anchor it needs --allow-partial-chain.
#[test]
fn a_self_issued_intermediate_as_trust_anchor_needs_allow_partial_chain() {
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let refused = verify_anchor(&record, "inter_selfissued.pem", &BOTH_CRLS);
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused));
    assert!(
        text(&refused).contains("is an intermediate CA (issued by CN=sfr test root), not a root"),
        "{}",
        text(&refused)
    );
    let allowed = verify_anchor_with(
        &record,
        "inter_selfissued.pem",
        &BOTH_CRLS,
        &["--allow-partial-chain"],
    );
    assert!(
        !text(&allowed).contains("is an intermediate CA (issued by"),
        "{}",
        text(&allowed)
    );
    // The real root, self-signed, is not refused for this.
    let root = verify_anchor(&record, "root.pem", &BOTH_CRLS);
    assert_eq!(root.status.code(), Some(0), "{}", text(&root));
}

/// An intermediate CA given as the trust anchor stops the chain short of a root: refused
/// unless --allow-partial-chain is given, which the trust line then states.
#[test]
fn an_intermediate_as_trust_anchor_needs_allow_partial_chain() {
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let refused = verify_anchor(&record, "inter.pem", &BOTH_CRLS);
    assert_eq!(refused.status.code(), Some(1), "{}", text(&refused));
    assert!(
        text(&refused).contains("is an intermediate CA (issued by CN=sfr test root), not a root"),
        "{}",
        text(&refused)
    );
    let allowed = verify_anchor_with(&record, "inter.pem", &BOTH_CRLS, &["--allow-partial-chain"]);
    assert_eq!(allowed.status.code(), Some(0), "{}", text(&allowed));
    assert!(
        stdout(&allowed).contains(
            "the anchor is an intermediate CA, accepted with --allow-partial-chain: nothing above it was checked"
        ),
        "{}",
        text(&allowed)
    );
    // The root as anchor needs no flag.
    let root = verify_anchor(&record, "root.pem", &BOTH_CRLS);
    assert_eq!(root.status.code(), Some(0), "{}", text(&root));
}

/// A CRL older than --max-crl-age (7 days unless given) fails; a delta CRL, an indirect CRL and
/// a CRL with a critical extension sfr does not read are refused, not ignored. Every CRL used
/// is printed with its issuer, number, thisUpdate and nextUpdate.
#[test]
fn old_delta_indirect_and_unknown_critical_crls_are_refused() {
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let verify = |inter_crl: &str, age: Option<&str>| {
        let (anchor, root_crl, inter_crl) = (pki("root.pem"), pki("root.crl"), pki(inter_crl));
        let mut args = vec![
            "verify",
            "--allow-evaluation-key",
            record.to_str().unwrap(),
            "--trust-anchor",
            &anchor,
            "--crl",
            &root_crl,
            "--crl",
            &inter_crl,
        ];
        if let Some(a) = age {
            args.extend(["--max-crl-age", a]);
        }
        sfr(&args)
    };
    // The test CRLs date from 2026-06-01: older than the default.
    let old = verify("inter.crl", None);
    assert_eq!(old.status.code(), Some(1), "{}", text(&old));
    assert!(
        text(&old).contains("more than --max-crl-age 604800 s before the verification time"),
        "{}",
        text(&old)
    );
    let ok = verify("inter.crl", Some(TEST_CRL_AGE));
    assert_eq!(ok.status.code(), Some(0), "{}", text(&ok));
    for line in [
        "crl       CN=sfr test inter: CRL number 1, thisUpdate 2026-06-01T00:00:00Z, nextUpdate 2046-01-01T00:00:00Z",
        "crl       CN=sfr test root: CRL number 1, thisUpdate 2026-06-01T00:00:00Z, nextUpdate 2046-01-01T00:00:00Z",
    ] {
        assert!(stdout(&ok).contains(line), "{line} in {}", text(&ok));
    }
    for (crl, why) in [
        ("inter_delta.crl", "a delta CRL (deltaCRLIndicator)"),
        (
            "inter_indirect.crl",
            "an indirect CRL (issuingDistributionPoint indirectCRL)",
        ),
        (
            "inter_critical.crl",
            "the extension 1.3.6.1.4.1.32473.1 is marked critical and sfr does not read it",
        ),
    ] {
        let o = verify(crl, Some(TEST_CRL_AGE));
        assert_ne!(o.status.code(), Some(0), "{crl}: {}", text(&o));
        assert!(
            text(&o).contains(why),
            "{crl}: want `{why}` in {}",
            text(&o)
        );
    }
}

/// RFC 5280 section 5.2.5: an issuingDistributionPoint that names a distribution point, or
/// limits the CRL to end-entity or CA certificates, makes it a partial CRL, which may not list a
/// certificate revoked in another one. Each is refused, and the message names the CRL file.
#[test]
fn a_crl_scoped_by_its_issuing_distribution_point_is_refused_naming_the_file() {
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    for (crl, why) in [
        (
            "inter_dp.crl",
            "a CRL scoped to one distribution point (issuingDistributionPoint distributionPoint)",
        ),
        (
            "inter_usercerts.crl",
            "a CRL that covers only end-entity certificates (issuingDistributionPoint onlyContainsUserCerts)",
        ),
        (
            "inter_cacerts.crl",
            "a CRL that covers only CA certificates (issuingDistributionPoint onlyContainsCACerts)",
        ),
    ] {
        let o = verify_anchor(&record, "root.pem", &["root.crl", crl]);
        assert_eq!(o.status.code(), Some(4), "{crl}: {}", text(&o));
        assert!(
            text(&o).contains(why),
            "{crl}: want `{why}` in {}",
            text(&o)
        );
        assert!(
            text(&o).contains(&format!("CRL {}: ", pki(crl))),
            "{crl}: the message names the file: {}",
            text(&o)
        );
        assert!(!text(&o).contains("Integrity: VERIFIED"), "{crl}");
    }
}

/// A complete CRL is never superseded by a scoped one of a higher number: given inter.crl
/// (number 1, complete, revoking the signer) and a scoped CRL of number 2 that lists nothing,
/// verify refuses the scoped CRL rather than taking it as current and passing the revoked
/// signer.
#[test]
fn a_complete_crl_is_never_superseded_by_a_scoped_one() {
    let (o, record) = seal(
        SIGNER_REVOKED,
        Some("signer_revoked.pem"),
        Some("inter.pem"),
        SEAL_TIME,
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let revoked = verify_anchor(&record, "root.pem", &BOTH_CRLS);
    assert_eq!(revoked.status.code(), Some(1), "{}", text(&revoked));
    for scoped in ["inter_dp.crl", "inter_usercerts.crl", "inter_cacerts.crl"] {
        for order in [
            ["root.crl", "inter.crl", scoped],
            ["root.crl", scoped, "inter.crl"],
        ] {
            let o = verify_anchor(&record, "root.pem", &order);
            assert_ne!(o.status.code(), Some(0), "{order:?}: {}", text(&o));
            assert!(!text(&o).contains("Integrity: VERIFIED"), "{order:?}");
            assert!(text(&o).contains(scoped), "{order:?}: {}", text(&o));
        }
    }
}

/// A trust anchor is checked before it is used: valid at the verification time, a CA
/// (basicConstraints cA TRUE), allowed to sign certificates (keyUsage keyCertSign), and with a
/// pathLenConstraint, if any, that allows the chain given. Each defective anchor is the test
/// root issued again with the same key and subject, so the chain would otherwise verify.
#[test]
fn an_expired_non_ca_non_signing_or_too_short_trust_anchor_is_refused() {
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let good = verify_anchor(&record, "root.pem", &BOTH_CRLS);
    assert_eq!(good.status.code(), Some(0), "{}", text(&good));
    for (anchor, why) in [
        ("root_expired.pem", "is not valid at the verification time"),
        (
            "root_not_ca.pem",
            "has basicConstraints cA FALSE, so it is not a CA certificate",
        ),
        (
            "root_no_certsign.pem",
            "has a keyUsage without keyCertSign, so it may not sign certificates",
        ),
        (
            "root_pathlen0.pem",
            "has pathLenConstraint 0, which allows 0 intermediate CA certificate(s) below it; the chain gives 1",
        ),
    ] {
        let o = verify_anchor(&record, anchor, &BOTH_CRLS);
        assert_eq!(o.status.code(), Some(1), "{anchor}: {}", text(&o));
        assert!(
            text(&o).contains("the trust anchor CN=sfr test root (sha256:")
                && text(&o).contains(why),
            "{anchor}: want `{why}` in {}",
            text(&o)
        );
        assert!(!text(&o).contains("Integrity: VERIFIED"), "{anchor}");
    }
    // The expired root is valid at a verification time inside its window.
    let o = verify_anchor_at(
        &record,
        "root_expired.pem",
        &BOTH_CRLS,
        Some("2020-06-01T00:00:00Z"),
    );
    assert!(
        !text(&o).contains("is not valid at the verification time"),
        "{}",
        text(&o)
    );
}

/// `--max-crl-age` is printed on the trust line as the value in effect; one longer than a used
/// CRL's own window (thisUpdate to nextUpdate) is warned about; and it is refused together with
/// `--no-crl-check`, which checks no CRL.
#[test]
fn max_crl_age_is_printed_warned_about_and_refused_without_crl_checks() {
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    // The test CRLs run from 2026-06-01 to 2046-01-01: a window of 618,105,600 s. 7300 days is
    // longer, so both CRLs are warned about.
    let v = verify_anchor(&record, "root.pem", &BOTH_CRLS);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    assert!(
        stdout(&v).contains(
            "each with thisUpdate at most 630720000 s before the verification time (--max-crl-age)"
        ),
        "{}",
        text(&v)
    );
    let err = String::from_utf8_lossy(&v.stderr).into_owned();
    for issuer in ["CN=sfr test root", "CN=sfr test inter"] {
        assert!(
            err.contains(&format!(
                "sfr: warning: --max-crl-age 630720000 s is longer than the validity window of the CRL of {issuer} (618105600 s, thisUpdate to nextUpdate)"
            )),
            "{err}"
        );
    }
    // Within the window: no warning.
    let anchor = pki("root.pem");
    let (root_crl, inter_crl) = (pki("root.crl"), pki("inter.crl"));
    let mut args = vec![
        "verify",
        "--allow-evaluation-key",
        record.to_str().unwrap(),
        "--trust-anchor",
        &anchor,
        "--crl",
        &root_crl,
        "--crl",
        &inter_crl,
        "--max-crl-age",
        "7000d",
    ];
    let v = sfr(&args);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    assert!(
        !text(&v).contains("is longer than the validity window"),
        "{}",
        text(&v)
    );
    assert!(stdout(&v).contains("at most 604800000 s"), "{}", text(&v));
    // Together with --no-crl-check: refused, exit 4.
    args.truncate(5);
    args.extend(["--no-crl-check", "--max-crl-age", "7d"]);
    let v = sfr(&args);
    assert_eq!(v.status.code(), Some(4), "{}", text(&v));
    assert!(
        text(&v)
            .contains("--max-crl-age applies to the CRLs checked, and --no-crl-check checks none"),
        "{}",
        text(&v)
    );
}

/// A trust anchor or CRL file that webpki cannot read is refused when it is loaded, in a sentence
/// that names the file, never a library's error name.
#[test]
fn an_unreadable_anchor_or_crl_file_is_refused_in_words_naming_the_file() {
    let (o, record) = seal(SIGNER, Some("signer.pem"), Some("inter.pem"), SEAL_TIME);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o));
    let dir = scratch();
    // A PEM block whose DER is a SEQUENCE holding one INTEGER: not a certificate.
    let bad = dir.join("bad_anchor.pem");
    std::fs::write(
        &bad,
        "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    let (root_crl, inter_crl) = (pki("root.crl"), pki("inter.crl"));
    let v = sfr(&[
        "verify",
        "--allow-evaluation-key",
        record.to_str().unwrap(),
        "--trust-anchor",
        bad.to_str().unwrap(),
        "--crl",
        &root_crl,
        "--crl",
        &inter_crl,
    ]);
    assert_eq!(v.status.code(), Some(4), "{}", text(&v));
    assert!(
        text(&v).contains(&format!(
            "trust anchor {}: the DER encoding is malformed",
            bad.display()
        )),
        "{}",
        text(&v)
    );
    assert!(!text(&v).contains("BadDer"), "{}", text(&v));
    std::fs::remove_dir_all(dir).unwrap();
}
