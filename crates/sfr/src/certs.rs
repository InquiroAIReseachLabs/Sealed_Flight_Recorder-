//! Signer certificates (SPEC B1.3 `seal --cert --chain`, `verify --trust-anchor --crl`).
//!
//! X.509 path validation is `rustls-webpki`, built with no crypto backend: every certificate
//! and CRL signature is checked here with `ed25519-dalek` (`verify_strict`), the one crypto
//! stack of every build (SPEC B1.10 Crypto). Only Ed25519 certificates and CRLs are accepted.
//!
//! A chain is valid when the signer certificate, through the record's intermediates, reaches a
//! supplied trust anchor; every certificate is valid at the record's seal time; the signer
//! certificate carries extended key usage code signing; and no certificate in the path is listed
//! in a supplied CRL. A listed serial counts as revoked whatever its revocation date, because the
//! seal time is the sealer's own statement: a key holder who backdates a seal must not escape a
//! revocation. There is no online check (no OCSP, no CRL download), by design.

use rustls_pki_types::{
    AlgorithmIdentifier, CertificateDer, InvalidSignature, SignatureVerificationAlgorithm,
    UnixTime, alg_id,
};
use sfr_core::crypto::CryptoBackend;
use sfr_core::crypto::rustcrypto::RustCrypto;
use sfr_core::keys::{ed25519_from_spki_der, pem_decode_all};
use sfr_core::seal::{format_utc, parse_seal_time_seconds};
use std::collections::BTreeMap;
use std::time::Duration;
use webpki::{
    CertRevocationList, EndEntityCert, Error, ExpirationPolicy, KeyUsage, OwnedCertRevocationList,
    RevocationCheckDepth, RevocationOptionsBuilder, UnknownStatusPolicy, anchor_from_trusted_cert,
};

/// id-kp-codeSigning, 1.3.6.1.5.5.7.3.3 (RFC 5280 section 4.2.1.12), as DER contents.
const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

/// id-ce-extKeyUsage, 2.5.29.37, as DER contents.
const EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];

/// One DER element at the start of `der`: its tag, its contents, and the bytes after it.
fn element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (bytes, rest) = rest.split_at_checked(n)?;
        (
            bytes.iter().fold(0usize, |l, &b| (l << 8) | usize::from(b)),
            rest,
        )
    };
    let (contents, after) = rest.split_at_checked(len)?;
    Some((tag, contents, after))
}

/// Whether a certificate (already parsed by webpki) carries the extension with this OID.
fn has_extension(cert: &[u8], oid: &[u8]) -> bool {
    let found = || -> Option<bool> {
        let (_, certificate, _) = element(cert)?;
        let (_, mut tbs, _) = element(certificate)?;
        // TBSCertificate fields; the extensions are the one tagged [3].
        while let Some((tag, contents, rest)) = element(tbs) {
            if tag == 0xa3 {
                let (_, mut exts, _) = element(contents)?;
                while let Some((_, ext, rest)) = element(exts) {
                    let (_, id, _) = element(ext)?;
                    if id == oid {
                        return Some(true);
                    }
                    exts = rest;
                }
                return Some(false);
            }
            tbs = rest;
        }
        Some(false)
    };
    found().unwrap_or(false)
}

/// id-ce-cRLNumber, 2.5.29.20, as DER contents.
const CRL_NUMBER: &[u8] = &[0x55, 0x1d, 0x14];

/// The whole DER element (tag, length and contents) at the start of `der`, and the bytes after it.
fn whole_element(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (_, _, rest) = element(der)?;
    let used = der.len().checked_sub(rest.len())?;
    Some((der.get(..used)?, rest))
}

/// An ASN.1 Time (UTCTime or GeneralizedTime, RFC 5280 section 4.1.2.5) as Unix seconds. The
/// form must be the one RFC 5280 requires: UTC, with seconds, no fraction.
fn der_time(tag: u8, contents: &[u8]) -> Result<i64, String> {
    let text = std::str::from_utf8(contents).map_err(|_| "a time is not ASCII".to_string())?;
    let digits_then_z = |t: &str, n: usize| {
        t.len() == n + 1 && t.ends_with('Z') && t.as_bytes().iter().take(n).all(u8::is_ascii_digit)
    };
    let (year, rest) = match tag {
        0x17 if digits_then_z(text, 12) => {
            let yy: i64 = text[..2].parse().map_err(|_| "a time is not a date")?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, &text[2..])
        }
        0x18 if digits_then_z(text, 14) => (
            text[..4].parse().map_err(|_| "a time is not a date")?,
            &text[4..],
        ),
        _ => {
            return Err(format!(
                "`{text}` is not a time RFC 5280 allows (UTC, with seconds)"
            ));
        }
    };
    let rfc3339 = format!(
        "{year:04}-{}-{}T{}:{}:{}Z",
        &rest[0..2],
        &rest[2..4],
        &rest[4..6],
        &rest[6..8],
        &rest[8..10]
    );
    parse_seal_time_seconds(&rfc3339)
}

/// The dotted form of an object identifier's DER contents.
fn oid_text(contents: &[u8]) -> String {
    let mut arcs: Vec<u64> = Vec::new();
    let mut value: u64 = 0;
    for &b in contents {
        value = value.saturating_mul(128) | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    // The first subidentifier carries the first two arcs.
    let mut it = arcs.into_iter();
    let mut out: Vec<u64> = Vec::new();
    if let Some(first) = it.next() {
        let top = (first / 40).min(2);
        out.push(top);
        out.push(first - 40 * top);
    }
    out.extend(it);
    out.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

/// Text that is safe to print: printable ASCII, and every other character as `\u{...}`.
fn ascii_safe(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if c.is_ascii_graphic() || c == ' ' {
            out.push(c);
        } else {
            out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
        }
    }
    out
}

/// An X.501 Name as `CN=..., O=...`, in the order the certificate stores it, safe to print. A
/// value of a type this does not read is shown as hex.
fn name_text(name_tlv: &[u8]) -> String {
    let read = || -> Option<String> {
        let (_, mut rdns, _) = element(name_tlv)?;
        let mut out: Vec<String> = Vec::new();
        while let Some((_, mut set, rest)) = element(rdns) {
            while let Some((_, atv, more)) = element(set) {
                let (_, oid, after) = element(atv)?;
                let (tag, value, _) = element(after)?;
                let key = match oid {
                    [0x55, 0x04, 0x03] => "CN".to_string(),
                    [0x55, 0x04, 0x06] => "C".to_string(),
                    [0x55, 0x04, 0x07] => "L".to_string(),
                    [0x55, 0x04, 0x08] => "ST".to_string(),
                    [0x55, 0x04, 0x0a] => "O".to_string(),
                    [0x55, 0x04, 0x0b] => "OU".to_string(),
                    [0x55, 0x04, 0x05] => "serialNumber".to_string(),
                    other => oid_text(other),
                };
                let shown = match (tag, std::str::from_utf8(value)) {
                    (0x0c | 0x13 | 0x16, Ok(v)) => ascii_safe(v),
                    _ => format!("#{}", sfr_core::hex(value)),
                };
                out.push(format!("{key}={shown}"));
                set = more;
            }
            rdns = rest;
        }
        Some(out.join(", "))
    };
    read().unwrap_or_else(|| "(unreadable name)".to_string())
}

/// The issuer and subject Names of a certificate, each as its whole DER element.
fn certificate_names(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (_, certificate, _) = element(der)?;
    let (_, mut tbs, _) = element(certificate)?;
    // [0] version (optional), serialNumber, signature, issuer, validity, subject.
    if tbs.first() == Some(&0xa0) {
        tbs = element(tbs)?.2;
    }
    let tbs = element(tbs)?.2; // serialNumber
    let tbs = element(tbs)?.2; // signature
    let (issuer, tbs) = whole_element(tbs)?;
    let tbs = element(tbs)?.2; // validity
    let (subject, _) = whole_element(tbs)?;
    Some((issuer.to_vec(), subject.to_vec()))
}

/// What `verify` reads of a CRL besides its signature, which webpki checks (RFC 5280 section 5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlInfo {
    /// The CRL's DER.
    der: Vec<u8>,
    /// The issuer Name, as its whole DER element: what a CRL is matched to a certificate by.
    issuer: Vec<u8>,
    /// `cRLNumber` as big-endian bytes without leading zeros (zero is empty).
    number: Vec<u8>,
    /// `thisUpdate`, Unix seconds.
    this_update: i64,
    /// `nextUpdate`, Unix seconds.
    next_update: i64,
}

impl CrlInfo {
    /// The issuer, as text safe to print.
    pub fn issuer_text(&self) -> String {
        name_text(&self.issuer)
    }

    /// `cRLNumber` in decimal.
    pub fn number_text(&self) -> String {
        let mut digits: Vec<u8> = Vec::new();
        let mut n = self.number.clone();
        while !n.is_empty() {
            // Divide the big-endian number by 10, collecting the remainder.
            let mut rem: u32 = 0;
            for b in &mut n {
                let cur = (rem << 8) | u32::from(*b);
                *b = u8::try_from(cur / 10).unwrap_or(0);
                rem = cur % 10;
            }
            digits.push(b'0' + u8::try_from(rem).unwrap_or(0));
            while n.first() == Some(&0) {
                n.remove(0);
            }
        }
        if digits.is_empty() {
            return "0".to_string();
        }
        digits.reverse();
        String::from_utf8(digits).unwrap_or_default()
    }

    /// `thisUpdate` as `YYYY-MM-DDTHH:MM:SSZ`.
    pub fn this_update_text(&self) -> String {
        format_utc(self.this_update)
    }

    /// `nextUpdate` as `YYYY-MM-DDTHH:MM:SSZ`.
    pub fn next_update_text(&self) -> String {
        format_utc(self.next_update)
    }
}

/// Reads the issuer, `cRLNumber`, `thisUpdate` and `nextUpdate` of a DER CRL. A CRL without a
/// `cRLNumber` or a `nextUpdate` is refused: it cannot be ordered or judged for staleness.
pub fn parse_crl(der: &[u8]) -> Result<CrlInfo, String> {
    let bad = |what: &str| format!("not a CRL this verifier reads: {what}");
    let (tag, list, rest) = element(der).ok_or_else(|| bad("not DER"))?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(bad("not one SEQUENCE"));
    }
    let (tag, tbs, _) = element(list).ok_or_else(|| bad("no TBSCertList"))?;
    if tag != 0x30 {
        return Err(bad("TBSCertList is not a SEQUENCE"));
    }
    let mut r = tbs;
    if r.first() == Some(&0x02) {
        r = element(r).ok_or_else(|| bad("version"))?.2;
    }
    r = element(r).ok_or_else(|| bad("signature algorithm"))?.2;
    let (issuer, mut r) = whole_element(r).ok_or_else(|| bad("issuer"))?;
    let (t, contents, after) = element(r).ok_or_else(|| bad("thisUpdate"))?;
    let this_update = der_time(t, contents)?;
    r = after;
    let (t, contents, after) = element(r).ok_or_else(|| bad("no nextUpdate"))?;
    if !matches!(t, 0x17 | 0x18) {
        return Err(bad("no nextUpdate"));
    }
    let next_update = der_time(t, contents)?;
    r = after;
    if r.first() == Some(&0x30) {
        r = element(r).ok_or_else(|| bad("revokedCertificates"))?.2;
    }
    let mut number: Option<Vec<u8>> = None;
    if r.first() == Some(&0xa0) {
        let (_, wrapped, _) = element(r).ok_or_else(|| bad("extensions"))?;
        let (_, mut exts, _) = element(wrapped).ok_or_else(|| bad("extensions"))?;
        while let Some((_, ext, rest)) = element(exts) {
            let (_, id, after_id) = element(ext).ok_or_else(|| bad("extension"))?;
            let after_id = if after_id.first() == Some(&0x01) {
                element(after_id).ok_or_else(|| bad("extension"))?.2
            } else {
                after_id
            };
            if id == CRL_NUMBER {
                let (_, value, _) = element(after_id).ok_or_else(|| bad("cRLNumber"))?;
                let (t, n, _) = element(value).ok_or_else(|| bad("cRLNumber"))?;
                if t != 0x02
                    || n.is_empty()
                    || n.len() > 21
                    || n.first().is_some_and(|b| b & 0x80 != 0)
                {
                    return Err(bad(
                        "cRLNumber is not a non-negative INTEGER of at most 20 octets",
                    ));
                }
                if number
                    .replace(n.iter().copied().skip_while(|&b| b == 0).collect())
                    .is_some()
                {
                    return Err(bad("two cRLNumber extensions"));
                }
            }
            exts = rest;
        }
    }
    Ok(CrlInfo {
        der: der.to_vec(),
        issuer: issuer.to_vec(),
        number: number.ok_or_else(|| {
            bad("no cRLNumber extension (RFC 5280 section 5.2.3), so it cannot be ordered")
        })?,
        this_update,
        next_update,
    })
}

/// Reads every CRL given and keeps, for each issuer, the one with the highest `cRLNumber`
/// (RFC 5280 section 5.2.3: numbers increase with each CRL an issuer makes). The result does not
/// depend on the order of `crls`. Two different CRLs of one issuer with the same highest number
/// are refused: nothing says which is current.
pub fn current_crls(crls: &[Vec<u8>]) -> Result<Vec<CrlInfo>, String> {
    // Every CRL of every issuer is read first, so the outcome does not depend on the order.
    let mut by_issuer: BTreeMap<Vec<u8>, Vec<CrlInfo>> = BTreeMap::new();
    for der in crls {
        let info = parse_crl(der).map_err(|e| format!("CRL: {e}"))?;
        by_issuer.entry(info.issuer.clone()).or_default().push(info);
    }
    let mut current = Vec::new();
    for (_, mut all) in by_issuer {
        // Numbers compare as unsigned integers: by length (no leading zeros), then by bytes.
        all.sort_by(|a, b| (a.number.len(), &a.number).cmp(&(b.number.len(), &b.number)));
        let Some(top) = all.pop() else { continue };
        // A CRL of the highest number that is not byte for byte the same CRL is a conflict.
        if let Some(other) = all
            .iter()
            .find(|c| c.number == top.number && c.der != top.der)
        {
            return Err(format!(
                "CRL: two different CRLs from {} have the same CRL number {}, so nothing says which is current",
                other.issuer_text(),
                other.number_text()
            ));
        }
        current.push(top);
    }
    Ok(current)
}

/// Ed25519 (RFC 8410) through `ed25519-dalek`'s `verify_strict`.
#[derive(Debug)]
struct Ed25519;

impl SignatureVerificationAlgorithm for Ed25519 {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let (Ok(pk), Ok(sig)) = (
            <[u8; 32]>::try_from(public_key),
            <[u8; 64]>::try_from(signature),
        ) else {
            return Err(InvalidSignature);
        };
        if RustCrypto.ed25519_verify(&pk, message, &sig) {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

static ALGORITHMS: &[&dyn SignatureVerificationAlgorithm] = &[&Ed25519];

/// Certificates from a file: every PEM `CERTIFICATE` block, or one DER certificate.
pub fn read_certificates(path: &str, what: &str) -> Result<Vec<Vec<u8>>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {what} {path}: {e}"))?;
    if bytes.first() == Some(&0x30) {
        return Ok(vec![bytes]);
    }
    let text =
        String::from_utf8(bytes).map_err(|_| format!("{what} {path} is neither PEM nor DER"))?;
    pem_decode_all(&text, "CERTIFICATE").map_err(|e| format!("{what} {path}: {e}"))
}

/// A CRL from a file: a PEM `X509 CRL` block, or DER.
pub fn read_crl(path: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read CRL {path}: {e}"))?;
    if bytes.first() == Some(&0x30) {
        return Ok(bytes);
    }
    let text =
        String::from_utf8(bytes).map_err(|_| format!("CRL {path} is neither PEM nor DER"))?;
    let mut blocks = pem_decode_all(&text, "X509 CRL").map_err(|e| format!("CRL {path}: {e}"))?;
    if blocks.len() != 1 {
        return Err(format!(
            "CRL {path} holds {} CRLs; give one per --crl",
            blocks.len()
        ));
    }
    Ok(blocks.remove(0))
}

/// The Ed25519 public key a certificate certifies.
pub fn certificate_key(der: &[u8]) -> Result<[u8; 32], String> {
    let cert = CertificateDer::from(der);
    let ee = EndEntityCert::try_from(&cert)
        .map_err(|e| format!("not an X.509 certificate: {}", why(&e)))?;
    // The whole SubjectPublicKeyInfo DER, outer SEQUENCE included.
    let spki = ee.subject_public_key_info();
    ed25519_from_spki_der(spki.as_ref())
        .ok_or_else(|| "the certificate's key is not Ed25519 (RFC 8410)".into())
}

/// `sha256:` and the hex SHA-256 of a certificate's DER.
pub fn certificate_fingerprint(der: &[u8]) -> String {
    format!("sha256:{}", sfr_core::hex(&RustCrypto.sha256(der)))
}

/// A plain-language reason for a webpki error.
fn why(e: &Error) -> String {
    match e {
        Error::UnknownIssuer => "the chain does not reach a supplied trust anchor".into(),
        Error::CertExpired { .. } => "a certificate had expired at the seal time".into(),
        Error::CertNotValidYet { .. } => "a certificate was not yet valid at the seal time".into(),
        Error::CertRevoked => "a certificate in the chain is revoked by a supplied CRL".into(),
        Error::RequiredEkuNotFoundContext(_) => {
            "the signer certificate lacks extended key usage code signing".into()
        }
        Error::CaUsedAsEndEntity => "the signer certificate is a CA certificate".into(),
        Error::EndEntityUsedAsCa => {
            "an intermediate certificate is not a CA certificate (basicConstraints)".into()
        }
        Error::InvalidSignatureForPublicKey => "a certificate's signature does not verify".into(),
        Error::InvalidCrlSignatureForPublicKey => "a CRL's signature does not verify".into(),
        Error::UnsupportedSignatureAlgorithmContext(_)
        | Error::UnsupportedSignatureAlgorithmForPublicKeyContext(_)
        | Error::UnsupportedCrlSignatureAlgorithmContext(_)
        | Error::UnsupportedCrlSignatureAlgorithmForPublicKeyContext(_) => {
            "a certificate or CRL is not signed with Ed25519, the only algorithm sfr accepts".into()
        }
        other => format!("{other:?}"),
    }
}

/// How `check_chain` treats revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlCheck {
    /// Every issuer of a certificate in the chain must have a current CRL among those given.
    Required,
    /// No revocation check at all (`verify --no-crl-check`).
    Off,
}

/// One CRL that was used: the current CRL of an issuer in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlUsed {
    /// The issuer, as text safe to print.
    pub issuer: String,
    /// `cRLNumber`, decimal.
    pub number: String,
    /// `thisUpdate`, `YYYY-MM-DDTHH:MM:SSZ`.
    pub this_update: String,
    /// `nextUpdate`, `YYYY-MM-DDTHH:MM:SSZ`.
    pub next_update: String,
}

impl CrlUsed {
    fn of(c: &CrlInfo) -> CrlUsed {
        CrlUsed {
            issuer: c.issuer_text(),
            number: c.number_text(),
            this_update: c.this_update_text(),
            next_update: c.next_update_text(),
        }
    }

    /// The CRL on one line, as `verify` prints it.
    pub fn line(&self) -> String {
        format!(
            "{}: CRL number {}, thisUpdate {}, nextUpdate {}",
            self.issuer, self.number, self.this_update, self.next_update
        )
    }
}

/// A chain that reached a trust anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainOk {
    /// The SHA-256 fingerprint of the trust anchor certificate the chain reached.
    pub anchor: String,
    /// The CRLs that were used, one per issuer in the chain; empty when revocation was not checked.
    pub crls: Vec<CrlUsed>,
    /// Whether revocation was checked.
    pub crl_check: bool,
}

/// Checks the signer certificate and its intermediates against the trust anchors and CRLs.
/// Certificates are judged at `seal_time` (Unix seconds); the CRLs are judged at `now`, the
/// verifier's clock, because a CRL's `nextUpdate` says how long its issuer stands behind it and
/// the sealer's claimed time says nothing about that.
///
/// With [`CrlCheck::Required`], every issuer of the signer certificate and of the intermediates
/// needs a current CRL (the highest `cRLNumber` among the CRLs given for it), which must be
/// neither past its `nextUpdate` nor from the future of `now`; a CRL of any other issuer counts
/// for nothing.
pub fn check_chain(
    signer: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    crls: &[Vec<u8>],
    seal_time: i64,
    now: i64,
    mode: CrlCheck,
) -> Result<ChainOk, String> {
    let signer_der = CertificateDer::from(signer);
    let ee = EndEntityCert::try_from(&signer_der)
        .map_err(|e| format!("signer certificate: {}", why(&e)))?;
    if !has_extension(signer, EXTENDED_KEY_USAGE) {
        return Err("the signer certificate lacks extended key usage code signing".into());
    }
    let anchor_ders: Vec<CertificateDer<'_>> = anchors
        .iter()
        .map(|a| CertificateDer::from(a.as_slice()))
        .collect();
    let trust: Vec<_> = anchor_ders
        .iter()
        .map(|a| anchor_from_trusted_cert(a).map_err(|e| format!("trust anchor: {}", why(&e))))
        .collect::<Result<_, _>>()?;
    let inter: Vec<CertificateDer<'_>> = intermediates
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();

    // The issuers whose CRLs matter: those of the signer and of the intermediates given.
    let mut issuers: Vec<Vec<u8>> = Vec::new();
    for der in std::iter::once(signer).chain(intermediates.iter().map(Vec::as_slice)) {
        if let Some((issuer, _)) = certificate_names(der)
            && !issuers.contains(&issuer)
        {
            issuers.push(issuer);
        }
    }
    let current = if mode == CrlCheck::Required || !crls.is_empty() {
        current_crls(crls)?
    } else {
        Vec::new()
    };
    let relevant: Vec<&CrlInfo> = current
        .iter()
        .filter(|c| issuers.contains(&c.issuer))
        .collect();
    let used: Vec<CrlUsed> = relevant.iter().map(|c| CrlUsed::of(c)).collect();
    if mode == CrlCheck::Required {
        for c in &relevant {
            if c.next_update <= now {
                return Err(format!(
                    "the current CRL of {} (number {}) is out of date: its nextUpdate {} is not after the verifier's clock, {}",
                    c.issuer_text(),
                    c.number_text(),
                    c.next_update_text(),
                    format_utc(now)
                ));
            }
            if c.this_update > now.saturating_add(CRL_FUTURE_SKEW_SECONDS) {
                return Err(format!(
                    "the current CRL of {} (number {}) has thisUpdate {}, after the verifier's clock, {}",
                    c.issuer_text(),
                    c.number_text(),
                    c.this_update_text(),
                    format_utc(now)
                ));
            }
        }
    }
    let owned: Vec<CertRevocationList<'_>> = relevant
        .iter()
        .map(|c| {
            OwnedCertRevocationList::from_der(&c.der)
                .map(CertRevocationList::from)
                .map_err(|e| format!("CRL: {}", why(&e)))
        })
        .collect::<Result<_, _>>()?;
    let refs: Vec<&CertRevocationList<'_>> = owned.iter().collect();
    let revocation = match mode {
        CrlCheck::Off => None,
        CrlCheck::Required => Some(
            RevocationOptionsBuilder::new(&refs)
                .map_err(|_| no_crl_message(&issuers, &current))?
                .with_depth(RevocationCheckDepth::Chain)
                // A certificate whose issuer has no current CRL here is an error, not "not revoked".
                .with_status_policy(UnknownStatusPolicy::Deny)
                // nextUpdate is judged above, against the verifier's clock; webpki would use the
                // time the certificates are judged at.
                .with_expiration_policy(ExpirationPolicy::Ignore)
                .build(),
        ),
    };
    let secs = u64::try_from(seal_time).map_err(|_| "verification time before 1970".to_string())?;
    let time = UnixTime::since_unix_epoch(Duration::from_secs(secs));
    let path = ee
        .verify_for_usage(
            ALGORITHMS,
            &trust,
            &inter,
            time,
            // On every certificate of the path: if it lists usages, code signing is one. The
            // signer certificate must list them (checked above), so it must name code signing.
            KeyUsage::required_if_present(CODE_SIGNING),
            revocation,
            None,
        )
        .map_err(|e| match e {
            Error::UnknownRevocationStatus => no_crl_message(&issuers, &current),
            other => why(&other),
        })?;
    let reached = path.anchor();
    let index = trust
        .iter()
        .position(|t| {
            t.subject == reached.subject
                && t.subject_public_key_info == reached.subject_public_key_info
        })
        .unwrap_or(0);
    Ok(ChainOk {
        anchor: anchors
            .get(index)
            .map_or_else(String::new, |a| certificate_fingerprint(a)),
        crls: if mode == CrlCheck::Required {
            used
        } else {
            Vec::new()
        },
        crl_check: mode == CrlCheck::Required,
    })
}

/// How far after the verification time a CRL's `thisUpdate` may lie, in seconds: the clock skew
/// allowed for a seal time (`sfr_core::seal::SEAL_TIME_SKEW_SECONDS` is 300; a CRL made a moment
/// ago on another machine must not fail).
const CRL_FUTURE_SKEW_SECONDS: i64 = 300;

/// Why revocation status is unknown: which issuers in the chain have no current CRL among those
/// given.
fn no_crl_message(issuers: &[Vec<u8>], current: &[CrlInfo]) -> String {
    let missing: Vec<String> = issuers
        .iter()
        .filter(|i| !current.iter().any(|c| &c.issuer == *i))
        .map(|i| name_text(i))
        .collect();
    let given: Vec<String> = current.iter().map(CrlInfo::issuer_text).collect();
    let given = if given.is_empty() {
        "none were given".to_string()
    } else {
        format!("the CRLs given are from {}", given.join("; "))
    };
    if missing.is_empty() {
        format!(
            "revocation status is unknown for a certificate in the chain: no current CRL given covers it ({given}); \
             --no-crl-check skips the revocation check"
        )
    } else {
        format!(
            "no CRL was given for the issuer(s) {} of the certificates in the chain, so a revoked certificate would pass; {given}. \
             Give a CRL for each issuer with --crl, or skip the check with --no-crl-check",
            missing.join("; ")
        )
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// The DER of a CRL in `testdata/pki/`.
    fn crl(name: &str) -> Vec<u8> {
        read_crl(&format!(
            "{}/../../testdata/pki/{name}.crl",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    #[test]
    fn a_crl_is_read_for_its_issuer_number_and_dates() {
        let c = parse_crl(&crl("inter")).unwrap();
        assert_eq!(c.issuer_text(), "CN=sfr test inter");
        assert_eq!(c.number_text(), "1");
        assert_eq!(c.this_update_text(), "2026-06-01T00:00:00Z");
        assert_eq!(c.next_update_text(), "2046-01-01T00:00:00Z");
        assert_eq!(parse_crl(&crl("inter_older")).unwrap().number_text(), "0");
        assert_eq!(parse_crl(&crl("other_root")).unwrap().number_text(), "99");
        let stale = parse_crl(&crl("inter_stale")).unwrap();
        assert_eq!(stale.next_update_text(), "2025-07-01T00:00:00Z");
        // Not a CRL, and a CRL with a trailing byte, are refused rather than guessed at.
        assert!(parse_crl(b"junk").is_err());
        let mut padded = crl("inter");
        padded.push(0);
        assert!(parse_crl(&padded).is_err());
    }

    #[test]
    fn a_crl_number_is_an_unsigned_integer_of_up_to_twenty_octets() {
        let n = |bytes: &[u8]| {
            CrlInfo {
                der: Vec::new(),
                issuer: Vec::new(),
                number: bytes.to_vec(),
                this_update: 0,
                next_update: 0,
            }
            .number_text()
        };
        assert_eq!(n(&[]), "0");
        assert_eq!(n(&[1]), "1");
        assert_eq!(n(&[1, 0]), "256");
        assert_eq!(
            n(&[0xff; 20]),
            "1461501637330902918203684832716283019655932542975"
        );
    }

    #[test]
    fn asn1_times_are_read_in_the_forms_rfc_5280_allows() {
        assert_eq!(der_time(0x17, b"700101000000Z").unwrap(), 0);
        assert_eq!(
            der_time(0x17, b"260601000000Z").unwrap(),
            der_time(0x18, b"20260601000000Z").unwrap()
        );
        // Two-digit years from 50 are 19xx, so 49 is 2049 and 50 is before the epoch we accept.
        assert!(der_time(0x17, b"490101000000Z").is_ok());
        assert!(der_time(0x17, b"500101000000Z").is_err());
        // No seconds, an offset, a fraction, a wrong tag, and a day that does not exist.
        for (tag, bad) in [
            (0x17, &b"2606010000Z"[..]),
            (0x17, b"260601000000+0100"),
            (0x18, b"20260601000000.5Z"),
            (0x17, b"20260601000000Z"),
            (0x18, b"260601000000Z"),
            (0x17, b"260231000000Z"),
        ] {
            assert!(
                der_time(tag, bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn the_current_crl_of_each_issuer_does_not_depend_on_the_order_given() {
        let all = [
            crl("inter"),
            crl("inter_older"),
            crl("inter_stale"),
            crl("root"),
            crl("other_root"),
        ];
        // The current CRL of each issuer as "issuer number", sorted.
        let expect = |order: &[usize]| -> Vec<String> {
            let given: Vec<Vec<u8>> = order.iter().map(|&i| all[i].clone()).collect();
            let mut got: Vec<String> = current_crls(&given)
                .unwrap()
                .iter()
                .map(|c| format!("{} {}", c.issuer_text(), c.number_text()))
                .collect();
            got.sort();
            got
        };
        let want = expect(&[0, 1, 2, 3, 4]);
        // One current CRL per issuer: inter's number 1 beats its numbers 0, and other_root's 99
        // belongs to other_root alone.
        assert_eq!(
            want,
            [
                "CN=sfr test inter 1",
                "CN=sfr test other_root 99",
                "CN=sfr test root 1"
            ]
        );
        // Every one of the 120 orders gives the same result.
        let mut order = [0usize, 1, 2, 3, 4];
        let mut seen = 0;
        permute(&mut order, 0, &mut |o| {
            assert_eq!(expect(o), want, "{o:?}");
            seen += 1;
        });
        assert_eq!(seen, 120);
    }

    /// Calls `f` with every permutation of `items[k..]` after `items[..k]` (Heap's recursion).
    fn permute(items: &mut [usize], k: usize, f: &mut dyn FnMut(&[usize])) {
        if k == items.len() {
            f(items);
            return;
        }
        for i in k..items.len() {
            items.swap(k, i);
            permute(items, k + 1, f);
            items.swap(k, i);
        }
    }

    #[test]
    fn a_name_is_printed_safely() {
        // CN=<U+202E>x, built by hand: SEQUENCE { SET { SEQUENCE { OID 2.5.4.3, UTF8String } } }.
        let value = "\u{202e}x\u{1b}[2J";
        let mut atv = vec![0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, value.len() as u8];
        atv.extend_from_slice(value.as_bytes());
        let mut name = vec![
            0x30,
            (atv.len() + 4) as u8,
            0x31,
            (atv.len() + 2) as u8,
            0x30,
            atv.len() as u8,
        ];
        name.extend_from_slice(&atv);
        let shown = name_text(&name);
        assert_eq!(shown, "CN=\\u{202e}x\\u{1b}[2J");
        assert!(shown.chars().all(|c| c.is_ascii_graphic() || c == ' '));
        assert_eq!(
            oid_text(&[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
            "1.2.840.113549.1.1.11"
        );
        assert_eq!(oid_text(&[0x55, 0x1d, 0x14]), "2.5.29.20");
    }
}
