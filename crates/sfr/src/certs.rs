//! Signer certificates (SPEC B1.3 `seal --cert --chain`, `verify --trust-anchor --crl`).
//!
//! X.509 path validation is `rustls-webpki`, built with no crypto backend: every certificate
//! and CRL signature is checked here with `ed25519-dalek` (`verify_strict`), the one crypto
//! stack of every build (SPEC B1.10 Crypto). Only Ed25519 certificates and CRLs are accepted.
//!
//! A chain is valid when the signer certificate, through the record's intermediates, reaches a
//! supplied trust anchor; every certificate is valid at the verification time, which is the
//! verifier's clock or the time given with `--at` and never the record's seal time (the sealer's
//! own claim: a key holder could set it inside a certificate's window); the signer certificate
//! carries the sfr record-signing extended key usage ([`SFR_RECORD_SIGNING`]) and the
//! keyUsage digitalSignature; and no certificate in the path is listed in a supplied CRL. A listed serial counts as revoked whatever its revocation date, for the same
//! reason. There is no online check (no OCSP, no CRL download), by design.

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

/// The extended key usage of a certificate for sealing records: the object identifier
/// `2.25.182460915354635260549596502533646383540`, as DER contents. It is in the arc of
/// UUID-derived identifiers (ITU-T X.667: 2.25 and the UUID as an integer), made from the version 5
/// UUID `8944b1ad-aa71-53df-ab6c-2d62d890f9b4` of the name `urn:sfr:eku:record-signing:1` in the
/// URL namespace, so nobody has to register it and no public usage (code signing, TLS) shares it.
/// A certificate issued for another purpose is not a record signer, and one issued for records is
/// not accepted for those purposes by the programs that check the usage.
pub const SFR_RECORD_SIGNING: &[u8] = &[
    0x69, 0x82, 0x92, 0xc4, 0xd8, 0xeb, 0xb5, 0xa7, 0x8a, 0xcf, 0xbf, 0xab, 0xb6, 0x8b, 0xac, 0xad,
    0xc4, 0xc3, 0xf3, 0x34,
];

/// The text of [`SFR_RECORD_SIGNING`].
pub const SFR_RECORD_SIGNING_TEXT: &str = "2.25.182460915354635260549596502533646383540";

/// id-kp-codeSigning, 1.3.6.1.5.5.7.3.3 (RFC 5280 section 4.2.1.12), as DER contents.
const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];

/// id-kp-serverAuth, 1.3.6.1.5.5.7.3.1, as DER contents.
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

/// anyExtendedKeyUsage, 2.5.29.37.0, as DER contents.
const ANY_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

/// id-ce-keyUsage, 2.5.29.15, as DER contents.
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];

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

/// The value of the extension with this OID in a certificate (already parsed by webpki): the
/// contents of its extnValue OCTET STRING. `None` when the certificate has no such extension.
fn extension_value<'a>(cert: &'a [u8], oid: &[u8]) -> Option<&'a [u8]> {
    let (_, certificate, _) = element(cert)?;
    let (_, mut tbs, _) = element(certificate)?;
    // TBSCertificate fields; the extensions are the one tagged [3].
    while let Some((tag, contents, rest)) = element(tbs) {
        if tag == 0xa3 {
            let (_, mut exts, _) = element(contents)?;
            while let Some((_, ext, rest)) = element(exts) {
                let (_, id, after_id) = element(ext)?;
                if id == oid {
                    // [critical BOOLEAN DEFAULT FALSE] extnValue OCTET STRING.
                    let (tag, first, after) = element(after_id)?;
                    let (tag, value) = if tag == 0x01 {
                        let (tag, value, _) = element(after)?;
                        (tag, value)
                    } else {
                        (tag, first)
                    };
                    return (tag == 0x04).then_some(value);
                }
                exts = rest;
            }
            return None;
        }
        tbs = rest;
    }
    None
}

/// The object identifiers (DER contents) in a certificate's extended key usage extension, or
/// `None` when it has none or it is malformed.
fn extended_key_usages(cert: &[u8]) -> Option<Vec<&[u8]>> {
    let value = extension_value(cert, EXTENDED_KEY_USAGE)?;
    let (tag, mut oids, _) = element(value)?;
    if tag != 0x30 {
        return None;
    }
    let mut out = Vec::new();
    while !oids.is_empty() {
        let (tag, oid, rest) = element(oids)?;
        if tag != 0x06 {
            return None;
        }
        out.push(oid);
        oids = rest;
    }
    Some(out)
}

/// Whether a certificate's keyUsage extension is present and sets digitalSignature (bit 0).
/// `Err` says what is wrong when it is absent, malformed, or lacks the bit.
fn check_digital_signature(cert: &[u8]) -> Result<(), String> {
    let Some(value) = extension_value(cert, KEY_USAGE) else {
        return Err(
            "the signer certificate has no keyUsage extension; it must carry digitalSignature"
                .into(),
        );
    };
    // BIT STRING: the number of unused bits, then the bits, bit 0 first.
    let bits = element(value)
        .filter(|(tag, _, _)| *tag == 0x03)
        .and_then(|(_, bits, _)| bits.get(1).copied());
    match bits {
        Some(first) if first & 0x80 != 0 => Ok(()),
        Some(_) => Err("the signer certificate's keyUsage lacks digitalSignature".into()),
        None => Err("the signer certificate's keyUsage extension is malformed".into()),
    }
}

/// The purposes a signer certificate is issued for, in words, or an error saying why it is not
/// a record-signing certificate (SPEC B1.3 `verify --trust-anchor`):
///
/// - its extended key usage must list [`SFR_RECORD_SIGNING`], so a certificate issued for code
///   signing or TLS server authentication is not a record signer;
/// - it must not also list code signing, TLS server authentication or `anyExtendedKeyUsage`, so a
///   certificate issued for records is not one for those purposes either;
/// - its keyUsage must be present and set digitalSignature.
fn check_signer_purpose(cert: &[u8]) -> Result<(), String> {
    let Some(usages) = extended_key_usages(cert) else {
        return Err(format!(
            "the signer certificate has no extended key usage; it must list the sfr record-signing usage {SFR_RECORD_SIGNING_TEXT}"
        ));
    };
    if !usages.contains(&SFR_RECORD_SIGNING) {
        let listed: Vec<String> = usages
            .iter()
            .map(|u| match *u {
                CODE_SIGNING => "code signing".to_string(),
                SERVER_AUTH => "TLS server authentication".to_string(),
                ANY_EXTENDED_KEY_USAGE => "any usage".to_string(),
                other => oid_text(other),
            })
            .collect();
        return Err(format!(
            "the signer certificate is not issued for sealing records: its extended key usage lists {} but not the sfr record-signing usage {SFR_RECORD_SIGNING_TEXT}",
            listed.join(", ")
        ));
    }
    for (oid, what) in [
        (CODE_SIGNING, "code signing"),
        (SERVER_AUTH, "TLS server authentication"),
        (ANY_EXTENDED_KEY_USAGE, "any usage (anyExtendedKeyUsage)"),
    ] {
        if usages.contains(&oid) {
            return Err(format!(
                "the signer certificate also lists {what}; a key that signs records must not be certified for other purposes"
            ));
        }
    }
    check_digital_signature(cert)
}

/// id-ce-cRLNumber, 2.5.29.20, as DER contents.
const CRL_NUMBER: &[u8] = &[0x55, 0x1d, 0x14];
/// id-ce-deltaCRLIndicator, 2.5.29.27: a delta CRL lists only changes to a base CRL.
const DELTA_CRL_INDICATOR: &[u8] = &[0x55, 0x1d, 0x1b];
/// id-ce-issuingDistributionPoint, 2.5.29.28.
const ISSUING_DISTRIBUTION_POINT: &[u8] = &[0x55, 0x1d, 0x1c];
/// id-ce-certificateIssuer, 2.5.29.29: a CRL entry for a certificate of another issuer.
const CERTIFICATE_ISSUER: &[u8] = &[0x55, 0x1d, 0x1d];

/// One extension: OID contents, critical, extnValue contents.
type Extension<'a> = (&'a [u8], bool, &'a [u8]);

/// The extensions of a SEQUENCE OF Extension.
fn extensions(mut exts: &[u8]) -> Result<Vec<Extension<'_>>, String> {
    let bad = || "not a CRL this verifier reads: an extension".to_string();
    let mut out = Vec::new();
    while let Some((_, ext, rest)) = element(exts) {
        let (_, id, after_id) = element(ext).ok_or_else(bad)?;
        let (critical, after) = if after_id.first() == Some(&0x01) {
            let (_, flag, after) = element(after_id).ok_or_else(bad)?;
            (flag.first().is_some_and(|&b| b != 0), after)
        } else {
            (false, after_id)
        };
        let (_, value, _) = element(after).ok_or_else(bad)?;
        out.push((id, critical, value));
        exts = rest;
    }
    Ok(out)
}

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
                "`{}` is not a time RFC 5280 allows (UTC, with seconds)",
                ascii_safe(text)
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

/// id-ce-basicConstraints, 2.5.29.19, as DER contents.
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];

/// A certificate's notBefore and notAfter, Unix seconds.
fn certificate_validity(der: &[u8]) -> Result<(i64, i64), String> {
    let bad = || "the certificate's validity cannot be read".to_string();
    let (_, certificate, _) = element(der).ok_or_else(bad)?;
    let (_, mut tbs, _) = element(certificate).ok_or_else(bad)?;
    if tbs.first() == Some(&0xa0) {
        tbs = element(tbs).ok_or_else(bad)?.2;
    }
    for _ in 0..3 {
        // serialNumber, signature, issuer
        tbs = element(tbs).ok_or_else(bad)?.2;
    }
    let (_, validity, _) = element(tbs).ok_or_else(bad)?;
    let (t, nb, rest) = element(validity).ok_or_else(bad)?;
    let not_before = der_time(t, nb)?;
    let (t, na, _) = element(rest).ok_or_else(bad)?;
    Ok((not_before, der_time(t, na)?))
}

/// What a trust anchor must be (RFC 5280 sections 4.2.1.3 and 4.2.1.9), checked because webpki
/// takes from an anchor only its subject, key and name constraints: valid at the verification
/// time; a CA (basicConstraints cA TRUE); allowed to sign certificates (keyUsage keyCertSign);
/// and, when it has a pathLenConstraint, allowing at least the `intermediates` given.
fn check_anchor(der: &[u8], intermediates: usize, verification_time: i64) -> Result<(), String> {
    let name = || {
        format!(
            "the trust anchor {} ({})",
            certificate_names(der).map_or_else(|| "?".into(), |(_, s)| name_text(&s)),
            certificate_fingerprint(der)
        )
    };
    let (not_before, not_after) = certificate_validity(der)?;
    if verification_time < not_before || verification_time > not_after {
        return Err(format!(
            "{} is not valid at the verification time {}: valid from {} to {}",
            name(),
            format_utc(verification_time),
            format_utc(not_before),
            format_utc(not_after)
        ));
    }
    // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }
    let bc = extension_value(der, BASIC_CONSTRAINTS)
        .and_then(element)
        .filter(|(tag, _, _)| *tag == 0x30)
        .map(|(_, c, _)| c);
    let Some(mut fields) = bc else {
        return Err(format!(
            "{} has no basicConstraints extension, so it is not a CA certificate",
            name()
        ));
    };
    let mut ca = false;
    let mut path_len: Option<u64> = None;
    while let Some((tag, contents, rest)) = element(fields) {
        match tag {
            0x01 => ca = contents.first().is_some_and(|&b| b != 0),
            0x02 if contents.len() <= 8 => {
                path_len = Some(contents.iter().fold(0u64, |n, &b| (n << 8) | u64::from(b)));
            }
            _ => return Err(format!("{}: its basicConstraints is malformed", name())),
        }
        fields = rest;
    }
    if !ca {
        return Err(format!(
            "{} has basicConstraints cA FALSE, so it is not a CA certificate",
            name()
        ));
    }
    // keyUsage BIT STRING: keyCertSign is bit 5.
    let key_cert_sign = extension_value(der, KEY_USAGE)
        .and_then(element)
        .filter(|(tag, _, _)| *tag == 0x03)
        .and_then(|(_, bits, _)| bits.get(1).copied())
        .map(|first| first & 0x04 != 0);
    match key_cert_sign {
        Some(true) => {}
        Some(false) => {
            return Err(format!(
                "{} has a keyUsage without keyCertSign, so it may not sign certificates",
                name()
            ));
        }
        None => {
            return Err(format!(
                "{} has no keyUsage extension; a trust anchor must carry keyCertSign",
                name()
            ));
        }
    }
    if let Some(n) = path_len
        && (intermediates as u64) > n
    {
        return Err(format!(
            "{} has pathLenConstraint {n}, which allows {n} intermediate CA certificate(s) below it; the chain gives {intermediates}",
            name()
        ));
    }
    Ok(())
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

/// Whether the certificate's signature verifies under its own public key. The names do not say:
/// a CA can carry its issuer's name as its own subject and still be signed by another key.
fn is_self_signed(der: &[u8]) -> bool {
    let Some((_, certificate, _)) = element(der) else {
        return false;
    };
    let Some((tbs, rest)) = whole_element(certificate) else {
        return false;
    };
    let Some((_, _, rest)) = element(rest) else {
        return false;
    };
    // signatureValue: a BIT STRING with no unused bits.
    let Some((0x03, bits, _)) = element(rest) else {
        return false;
    };
    let Some((&0, signature)) = bits.split_first() else {
        return false;
    };
    let der = CertificateDer::from(der);
    EndEntityCert::try_from(&der)
        .is_ok_and(|cert| cert.verify_signature(&Ed25519, tbs, signature).is_ok())
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
    // RFC 5280 section 5.1.2.3: the issuer is a non-empty Name, a SEQUENCE of RDNs.
    if issuer.first() != Some(&0x30) || name_text(issuer).is_empty() {
        return Err(bad("the issuer is not a Name"));
    }
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
        let (_, mut entries, after) = element(r).ok_or_else(|| bad("revokedCertificates"))?;
        // An entry that names another certificate issuer makes the CRL indirect; an entry
        // extension marked critical that this verifier does not read would change what the
        // entry means. Both are refused, not ignored.
        while let Some((_, entry, rest)) = element(entries) {
            let after_serial = element(entry).ok_or_else(|| bad("a revoked entry"))?.2;
            let after_date = element(after_serial)
                .ok_or_else(|| bad("a revoked entry"))?
                .2;
            if after_date.first() == Some(&0x30) {
                let (_, exts, _) = element(after_date).ok_or_else(|| bad("entry extensions"))?;
                for (id, critical, _) in extensions(exts)? {
                    if id == CERTIFICATE_ISSUER {
                        return Err(bad(
                            "an indirect CRL (an entry names another certificate issuer); sfr reads only CRLs of the issuer that signs them",
                        ));
                    }
                    if critical {
                        return Err(bad(&format!(
                            "an entry extension {} is marked critical and sfr does not read it",
                            oid_text(id)
                        )));
                    }
                }
            }
            entries = rest;
        }
        r = after;
    }
    let mut number: Option<Vec<u8>> = None;
    if r.first() == Some(&0xa0) {
        let (_, wrapped, _) = element(r).ok_or_else(|| bad("extensions"))?;
        let (_, exts, _) = element(wrapped).ok_or_else(|| bad("extensions"))?;
        for (id, critical, value) in extensions(exts)? {
            if id == DELTA_CRL_INDICATOR {
                return Err(bad(
                    "a delta CRL (deltaCRLIndicator); sfr reads only complete CRLs",
                ));
            }
            if id == ISSUING_DISTRIBUTION_POINT {
                // IssuingDistributionPoint (RFC 5280 section 5.2.5). Any field that narrows what
                // the CRL covers makes it a partial CRL: a certificate it does not list may be
                // revoked in another CRL. sfr reads only complete CRLs, so each is refused:
                // [0] distributionPoint, [1] onlyContainsUserCerts, [2] onlyContainsCACerts,
                // [3] onlySomeReasons, [4] indirectCRL, [5] onlyContainsAttributeCerts. A
                // BOOLEAN field encoded FALSE narrows nothing.
                let (_, mut fields, _) =
                    element(value).ok_or_else(|| bad("issuingDistributionPoint"))?;
                let mut scope = Vec::new();
                while let Some((tag, contents, rest)) = element(fields) {
                    let set = contents.first().is_some_and(|&b| b != 0);
                    let refused = match tag {
                        0xa0 => Some(
                            "a CRL scoped to one distribution point (issuingDistributionPoint distributionPoint)",
                        ),
                        0x81 if set => Some(
                            "a CRL that covers only end-entity certificates (issuingDistributionPoint onlyContainsUserCerts)",
                        ),
                        0x82 if set => Some(
                            "a CRL that covers only CA certificates (issuingDistributionPoint onlyContainsCACerts)",
                        ),
                        0x83 | 0xa3 => Some(
                            "a CRL that covers only some revocation reasons (issuingDistributionPoint onlySomeReasons)",
                        ),
                        0x84 if set => Some(
                            "an indirect CRL (issuingDistributionPoint indirectCRL); sfr reads only CRLs of the issuer that signs them",
                        ),
                        0x85 if set => Some(
                            "a CRL that covers only attribute certificates (issuingDistributionPoint onlyContainsAttributeCerts)",
                        ),
                        _ => None,
                    };
                    scope.extend(refused);
                    fields = rest;
                }
                if !scope.is_empty() {
                    return Err(bad(&format!(
                        "{}; sfr reads only complete CRLs",
                        scope.join("; ")
                    )));
                }
                continue;
            }
            if id == CRL_NUMBER {
                let (t, n, _) = element(value).ok_or_else(|| bad("cRLNumber"))?;
                // At most 20 significant octets (RFC 5280 section 5.2.3); leading zero octets, the
                // sign octet among them, do not count.
                let significant = n.iter().skip_while(|b| **b == 0).count();
                if t != 0x02
                    || n.is_empty()
                    || significant > 20
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
                continue;
            }
            if critical {
                return Err(bad(&format!(
                    "the extension {} is marked critical and sfr does not read it",
                    oid_text(id)
                )));
            }
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
    let mut first_error: Option<String> = None;
    for der in crls {
        match parse_crl(der) {
            Ok(info) => by_issuer.entry(info.issuer.clone()).or_default().push(info),
            // The error shown is the least of them, not the first met: the same CRLs in any
            // order give the same answer.
            Err(e) => {
                let e = format!("CRL: {e}");
                if first_error.as_ref().is_none_or(|f| e < *f) {
                    first_error = Some(e);
                }
            }
        }
    }
    if let Some(e) = first_error {
        return Err(e);
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

/// Why a certificate or CRL file could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileError {
    /// The file is longer than the input limit (SPEC B1.4, exit 3).
    Limit(String),
    /// Anything else: unreadable, or not what it should be (exit 4).
    Other(String),
}

impl std::fmt::Display for FileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (Self::Limit(m) | Self::Other(m)) = self;
        f.write_str(m)
    }
}

/// The whole file, if it is at most `max` bytes; a longer one is refused, never cut.
fn read_limited(path: &str, what: &str, max: u64) -> Result<Vec<u8>, FileError> {
    use std::io::Read;
    let shown = sfr_core::display::visible(path);
    let other = |e: std::io::Error| FileError::Other(format!("cannot read {what} {shown}: {e}"));
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(other)?
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(other)?;
    if bytes.len() as u64 > max {
        return Err(FileError::Limit(format!(
            "{what} {shown}: {}",
            sfr_core::limit_exceeded("the file", max, "bytes")
        )));
    }
    Ok(bytes)
}

/// Certificates from a file of at most `max` bytes: every PEM `CERTIFICATE` block, or one DER
/// certificate.
pub fn read_certificates(path: &str, what: &str, max: u64) -> Result<Vec<Vec<u8>>, FileError> {
    let shown = sfr_core::display::visible(path);
    let bytes = read_limited(path, what, max)?;
    if bytes.first() == Some(&0x30) {
        return Ok(vec![bytes]);
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| FileError::Other(format!("{what} {shown} is neither PEM nor DER")))?;
    pem_decode_all(&text, "CERTIFICATE")
        .map_err(|e| FileError::Other(format!("{what} {shown}: {e}")))
}

/// A CRL from a file of at most `max` bytes: a PEM `X509 CRL` block, or DER.
pub fn read_crl(path: &str, max: u64) -> Result<Vec<u8>, FileError> {
    let shown = sfr_core::display::visible(path);
    let bytes = read_limited(path, "CRL", max)?;
    if bytes.first() == Some(&0x30) {
        return Ok(bytes);
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| FileError::Other(format!("CRL {shown} is neither PEM nor DER")))?;
    let mut blocks = pem_decode_all(&text, "X509 CRL")
        .map_err(|e| FileError::Other(format!("CRL {shown}: {e}")))?;
    if blocks.len() != 1 {
        return Err(FileError::Other(format!(
            "CRL {shown} holds {} CRLs; give one per --crl",
            blocks.len()
        )));
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
    let s: &str = match e {
        Error::UnknownIssuer => "the chain does not reach a supplied trust anchor",
        Error::CertExpired { .. } => {
            "a certificate had expired at the verification time (the verifier's clock, or --at)"
        }
        Error::CertNotValidYet { .. } => {
            "a certificate was not yet valid at the verification time (the verifier's clock, or --at)"
        }
        Error::CertRevoked => "a certificate in the chain is revoked by a supplied CRL",
        Error::RequiredEkuNotFoundContext(_) => {
            return format!(
                "a certificate in the chain restricts its extended key usage and does not list the sfr record-signing usage {SFR_RECORD_SIGNING_TEXT}"
            );
        }
        Error::EmptyEkuExtension => {
            "a certificate has an extended key usage extension that lists no usage"
        }
        Error::CaUsedAsEndEntity => "the signer certificate is a CA certificate",
        Error::EndEntityUsedAsCa => {
            "an intermediate certificate is not a CA certificate (basicConstraints)"
        }
        Error::PathLenConstraintViolated => {
            "a CA certificate's pathLenConstraint does not allow the intermediate certificates below it"
        }
        Error::InvalidSignatureForPublicKey => "a certificate's signature does not verify",
        Error::InvalidCrlSignatureForPublicKey => "a CRL's signature does not verify",
        Error::SignatureAlgorithmMismatch => {
            "a certificate names one signature algorithm outside its signed part and another inside"
        }
        Error::UnsupportedSignatureAlgorithmContext(_)
        | Error::UnsupportedSignatureAlgorithmForPublicKeyContext(_)
        | Error::UnsupportedCrlSignatureAlgorithmContext(_)
        | Error::UnsupportedCrlSignatureAlgorithmForPublicKeyContext(_) => {
            "a certificate or CRL is not signed with Ed25519, the only algorithm sfr accepts"
        }
        Error::BadDer | Error::TrailingData(_) => "the DER encoding is malformed",
        Error::BadDerTime => "a time in it is not a valid DER time",
        Error::InvalidCertValidity => "a certificate's notAfter is before its notBefore",
        Error::InvalidSerialNumber => {
            "a certificate's serial number is not a positive integer of at most 20 octets"
        }
        Error::InvalidCrlNumber => {
            "a CRL's number is not a non-negative integer of at most 20 octets"
        }
        Error::UnsupportedCertVersion => "a certificate is not X.509 version 3",
        Error::UnsupportedCrlVersion => "a CRL is not version 2",
        Error::MalformedExtensions | Error::ExtensionValueInvalid => {
            "a certificate or CRL has a malformed extension"
        }
        Error::UnsupportedCriticalExtension => {
            "a certificate has a critical extension sfr does not read"
        }
        Error::MalformedNameConstraint
        | Error::InvalidNetworkMaskConstraint
        | Error::UnsupportedNameType => "a CA certificate has a name constraint sfr cannot read",
        Error::NameConstraintViolation => {
            "a certificate's name is outside a name constraint of a CA above it"
        }
        Error::MalformedDnsIdentifier | Error::CertNotValidForName(_) => {
            "a certificate has a malformed or unexpected name"
        }
        Error::IssuerNotCrlSigner => {
            "a CRL's issuer certificate is not allowed to sign CRLs (keyUsage cRLSign)"
        }
        Error::UnknownRevocationStatus => {
            "a certificate in the chain has no current CRL among those given"
        }
        Error::CrlExpired { .. } => "a CRL is past its nextUpdate",
        Error::UnsupportedDeltaCrl => "a delta CRL; sfr reads only complete CRLs",
        Error::UnsupportedIndirectCrl => {
            "an indirect CRL; sfr reads only CRLs of the issuer that signs them"
        }
        Error::UnsupportedCrlIssuingDistributionPoint
        | Error::UnsupportedRevocationReasonsPartitioning => {
            "a CRL scoped by its issuingDistributionPoint; sfr reads only complete CRLs"
        }
        Error::UnsupportedRevocationReason => {
            "a CRL entry gives a revocation reason sfr does not read"
        }
        Error::MaximumNameConstraintComparisonsExceeded
        | Error::MaximumPathBuildCallsExceeded
        | Error::MaximumPathDepthExceeded
        | Error::MaximumSignatureChecksExceeded => {
            "the chain is too long or too branched to check within the verifier's limits"
        }
        _ => "the certificates or CRLs could not be checked",
    };
    s.to_string()
}

/// Whether `der` can be a trust anchor at all (webpki reads its subject, key and name
/// constraints); `verify` checks each anchor file as it is loaded so a failure names the file.
pub fn check_anchor_der(der: &[u8]) -> Result<(), String> {
    anchor_from_trusted_cert(&CertificateDer::from(der))
        .map(|_| ())
        .map_err(|e| why(&e))
}

/// Whether `der` is a CRL `sfr` reads ([`parse_crl`]) and webpki can load; `verify` checks each
/// CRL file as it is loaded so a failure names the file.
pub fn check_crl_der(der: &[u8]) -> Result<(), String> {
    parse_crl(der)?;
    OwnedCertRevocationList::from_der(der)
        .map(|_| ())
        .map_err(|e| why(&e))
}

/// How `check_chain` treats revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrlCheck {
    /// Every issuer of a certificate in the chain must have a current CRL among those given.
    Required,
    /// No revocation check at all (`verify --no-crl-check`).
    Off,
}

/// The longest a CRL may have been out by default (`verify --max-crl-age`): seven days between
/// its `thisUpdate` and the verification time.
pub const DEFAULT_MAX_CRL_AGE_SECONDS: i64 = 7 * 24 * 3600;

/// How `verify --trust-anchor` judges a chain besides the certificates themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainPolicy {
    /// Whether revocation is checked.
    pub crl_check: CrlCheck,
    /// The oldest a current CRL may be, in seconds from its `thisUpdate` to the verification
    /// time.
    pub max_crl_age: i64,
    /// Whether a trust anchor may be an intermediate CA (`--allow-partial-chain`).
    pub allow_partial_chain: bool,
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
    /// `nextUpdate` minus `thisUpdate`, seconds: how long the issuer stands behind the CRL.
    pub window: i64,
}

impl CrlUsed {
    fn of(c: &CrlInfo) -> CrlUsed {
        CrlUsed {
            issuer: c.issuer_text(),
            number: c.number_text(),
            this_update: c.this_update_text(),
            next_update: c.next_update_text(),
            window: c.next_update.saturating_sub(c.this_update),
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
    /// The `--max-crl-age` in effect, seconds.
    pub max_crl_age: i64,
    /// Whether the anchor the chain reached is an intermediate CA, accepted only because of
    /// `--allow-partial-chain`: nothing above it was checked.
    pub partial: bool,
}

/// Checks the signer certificate and its intermediates against the trust anchors and CRLs, at
/// `verification_time` (Unix seconds): the verifier's clock or `--at`, never the record's claimed
/// seal time. The CRLs are judged at the same time: a CRL's `nextUpdate` says how long its issuer
/// stands behind it, and the sealer's claimed time says nothing about that.
///
/// With [`CrlCheck::Required`], every issuer of the signer certificate and of the intermediates
/// needs a current CRL (the highest `cRLNumber` among the CRLs given for it), which must be
/// neither past its `nextUpdate` nor from the future of `verification_time`; a CRL of any other
/// issuer counts for nothing.
pub fn check_chain(
    signer: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    crls: &[Vec<u8>],
    verification_time: i64,
    policy: &ChainPolicy,
) -> Result<ChainOk, String> {
    let mode = policy.crl_check;
    // A trust anchor that its own key did not sign is an intermediate CA: a chain that stops there
    // leaves everything above it unchecked, so it needs --allow-partial-chain.
    // The names are not enough: it is a root only if its own key signed it.
    let intermediate_anchor = |der: &[u8]| !is_self_signed(der);
    if !policy.allow_partial_chain
        && let Some(a) = anchors.iter().find(|a| intermediate_anchor(a))
    {
        return Err(format!(
            "the trust anchor {} is an intermediate CA (issued by {}), not a root; give the root, or add --allow-partial-chain to stop the chain there",
            certificate_fingerprint(a),
            certificate_names(a).map_or_else(String::new, |(i, _)| name_text(&i))
        ));
    }
    // Every anchor given is checked, whichever one the chain reaches; the pathLenConstraint is
    // checked on the anchors that issued the top of the chain given.
    let top_issuer = intermediates.last().map_or(signer, Vec::as_slice);
    let top_issuer = certificate_names(top_issuer).map(|(i, _)| i);
    for a in anchors {
        let issues_top = certificate_names(a).map(|(_, s)| s) == top_issuer;
        check_anchor(
            a,
            if issues_top { intermediates.len() } else { 0 },
            verification_time,
        )?;
    }
    let signer_der = CertificateDer::from(signer);
    let ee = EndEntityCert::try_from(&signer_der)
        .map_err(|e| format!("signer certificate: {}", why(&e)))?;
    check_signer_purpose(signer)?;
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
            if c.next_update <= verification_time {
                return Err(format!(
                    "the current CRL of {} (number {}) is out of date: its nextUpdate {} is not after the verification time {}",
                    c.issuer_text(),
                    c.number_text(),
                    c.next_update_text(),
                    format_utc(verification_time)
                ));
            }
            if verification_time.saturating_sub(c.this_update) > policy.max_crl_age {
                return Err(format!(
                    "the current CRL of {} (number {}) has thisUpdate {}, more than --max-crl-age {} s before the verification time {}; give a newer CRL from the issuer",
                    c.issuer_text(),
                    c.number_text(),
                    c.this_update_text(),
                    policy.max_crl_age,
                    format_utc(verification_time)
                ));
            }
            if c.this_update > verification_time.saturating_add(CRL_FUTURE_SKEW_SECONDS) {
                return Err(format!(
                    "the current CRL of {} (number {}) has thisUpdate {}, after the verification time {}",
                    c.issuer_text(),
                    c.number_text(),
                    c.this_update_text(),
                    format_utc(verification_time)
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
                // nextUpdate is judged above, against the verification time.
                .with_expiration_policy(ExpirationPolicy::Ignore)
                .build(),
        ),
    };
    let secs = u64::try_from(verification_time)
        .map_err(|_| "verification time before 1970".to_string())?;
    let time = UnixTime::since_unix_epoch(Duration::from_secs(secs));
    let path = ee
        .verify_for_usage(
            ALGORITHMS,
            &trust,
            &inter,
            time,
            // On every certificate of the path: if it lists usages, the record-signing usage is
            // one, so a CA limited to TLS cannot issue record signers. The signer certificate
            // must list them (checked above).
            KeyUsage::required_if_present(SFR_RECORD_SIGNING),
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
        max_crl_age: policy.max_crl_age,
        partial: anchors.get(index).is_some_and(|a| intermediate_anchor(a)),
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

    #[test]
    fn every_webpki_error_reads_as_a_sentence_not_a_variant_name() {
        let errors = [
            Error::BadDer,
            Error::BadDerTime,
            Error::CaUsedAsEndEntity,
            Error::CertRevoked,
            Error::EmptyEkuExtension,
            Error::EndEntityUsedAsCa,
            Error::ExtensionValueInvalid,
            Error::InvalidCertValidity,
            Error::InvalidCrlNumber,
            Error::InvalidNetworkMaskConstraint,
            Error::InvalidSerialNumber,
            Error::InvalidCrlSignatureForPublicKey,
            Error::InvalidSignatureForPublicKey,
            Error::IssuerNotCrlSigner,
            Error::MalformedDnsIdentifier,
            Error::MalformedExtensions,
            Error::MalformedNameConstraint,
            Error::MaximumNameConstraintComparisonsExceeded,
            Error::MaximumPathBuildCallsExceeded,
            Error::MaximumPathDepthExceeded,
            Error::MaximumSignatureChecksExceeded,
            Error::NameConstraintViolation,
            Error::PathLenConstraintViolated,
            Error::SignatureAlgorithmMismatch,
            Error::UnknownIssuer,
            Error::UnknownRevocationStatus,
            Error::UnsupportedCertVersion,
            Error::UnsupportedCriticalExtension,
            Error::UnsupportedCrlIssuingDistributionPoint,
            Error::UnsupportedCrlVersion,
            Error::UnsupportedDeltaCrl,
            Error::UnsupportedIndirectCrl,
            Error::UnsupportedNameType,
            Error::UnsupportedRevocationReason,
            Error::UnsupportedRevocationReasonsPartitioning,
        ];
        for e in errors {
            let text = why(&e);
            let debug = format!("{e:?}");
            assert!(!text.contains(&debug), "{debug}: {text}");
            assert!(
                text.starts_with(|c: char| c.is_ascii_lowercase()),
                "{debug}: {text}"
            );
            assert!(
                !text.split(' ').any(|w| w.len() > 1
                    && w.starts_with(|c: char| c.is_ascii_uppercase())
                    && w.chars().skip(1).any(|c| c.is_ascii_uppercase())
                    && w.chars().any(|c| c.is_ascii_lowercase())
                    && !w.contains("CRL")),
                "{debug}: {text}"
            );
        }
    }

    /// The DER of a CRL in `testdata/pki/`.
    fn crl(name: &str) -> Vec<u8> {
        read_crl(
            &format!(
                "{}/../../testdata/pki/{name}.crl",
                env!("CARGO_MANIFEST_DIR")
            ),
            1 << 20,
        )
        .unwrap()
    }

    /// The DER of a certificate in `testdata/pki/`.
    fn cert(name: &str) -> Vec<u8> {
        let text = std::fs::read_to_string(format!(
            "{}/../../testdata/pki/{name}.pem",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        pem_decode_all(&text, "CERTIFICATE").unwrap().remove(0)
    }

    /// Whether `signer` (issued by `inter`, under `root`) is accepted by webpki for `usage`, at a
    /// time all of them are valid (2026-10-18): what a program that uses the certificate for a
    /// purpose other than sealing records would conclude.
    fn accepted_for(signer: &str, usage: &KeyUsage) -> Result<(), Error> {
        let (signer, inter, root) = (cert(signer), cert("inter"), cert("root"));
        let signer_der = CertificateDer::from(signer.as_slice());
        let ee = EndEntityCert::try_from(&signer_der).unwrap();
        let root_der = CertificateDer::from(root.as_slice());
        let trust = [anchor_from_trusted_cert(&root_der).unwrap()];
        let inter_der = [CertificateDer::from(inter.as_slice())];
        let time = UnixTime::since_unix_epoch(Duration::from_secs(
            u64::try_from(parse_seal_time_seconds("2026-10-18T15:00:00Z").unwrap()).unwrap(),
        ));
        ee.verify_for_usage(ALGORITHMS, &trust, &inter_der, time, usage, None, None)
            .map(|_| ())
    }

    #[test]
    fn a_record_signing_certificate_is_not_a_certificate_for_other_purposes() {
        // The signer certificate lists the sfr record-signing usage and nothing else...
        let signer = cert("signer");
        assert_eq!(
            extended_key_usages(&signer).unwrap(),
            [SFR_RECORD_SIGNING],
            "only the record-signing usage"
        );
        check_signer_purpose(&signer).unwrap();
        // ... so a program that checks the usage accepts it for records and for nothing else.
        accepted_for("signer", &KeyUsage::required_if_present(SFR_RECORD_SIGNING)).unwrap();
        for other in [CODE_SIGNING, SERVER_AUTH] {
            assert!(
                matches!(
                    accepted_for("signer", &KeyUsage::required_if_present(other)),
                    Err(Error::RequiredEkuNotFoundContext(_))
                ),
                "a record-signing certificate was accepted for {}",
                oid_text(other)
            );
        }
        assert!(matches!(
            accepted_for("signer", &KeyUsage::server_auth()),
            Err(Error::RequiredEkuNotFoundContext(_))
        ));
    }

    #[test]
    fn a_certificate_for_another_purpose_is_not_a_record_signer() {
        // The other direction: the certificates issued for code signing and for TLS server
        // authentication are good for those purposes (webpki accepts them) and are refused as
        // record signers, with the reason.
        accepted_for(
            "signer_codesign",
            &KeyUsage::required_if_present(CODE_SIGNING),
        )
        .unwrap();
        accepted_for("signer_server", &KeyUsage::server_auth()).unwrap();
        for (name, why) in [
            (
                "signer_codesign",
                "lists code signing but not the sfr record-signing usage",
            ),
            (
                "signer_server",
                "lists TLS server authentication but not the sfr record-signing usage",
            ),
            ("signer_both", "also lists code signing"),
            ("signer_nosig", "keyUsage lacks digitalSignature"),
            ("signer_nokeyusage", "has no keyUsage extension"),
        ] {
            let err = check_signer_purpose(&cert(name)).unwrap_err();
            assert!(err.contains(why), "{name}: {err}");
        }
        for ok in [
            "signer",
            "signer_expired",
            "signer_revoked",
            "signer_lapsed",
        ] {
            check_signer_purpose(&cert(ok)).unwrap();
        }
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
// Test code: a panic is a failed test, and every indexed position is checked against a length first.
mod properties {
    //! Property tests of the certificate and CRL readers: the DER helpers, `parse_crl`,
    //! `current_crls`, the checks `verify` runs on each file it loads, and the text the report
    //! prints from a certificate. Inputs mix well-formed objects (built here, or read from
    //! `testdata/pki/`) with local damage, so the code past the first check runs.
    use super::*;
    use proptest::prelude::*;
    use proptest::sample::Index;
    use proptest::test_runner::RngSeed;
    use std::sync::OnceLock;

    /// The seed of a default run: any constant makes the run repeat exactly.
    const SEED: u64 = 0x6365_7274_735f_6372;

    /// The configuration of every property: `ProptestConfig::default()` reads `PROPTEST_CASES`
    /// and `PROPTEST_RNG_SEED`; when they are unset the run uses a fixed seed and 64 cases. No
    /// failure file is written next to the sources: the fixed seed already repeats a failure.
    fn config() -> ProptestConfig {
        let mut config = ProptestConfig::default();
        if std::env::var_os("PROPTEST_RNG_SEED").is_none() {
            config.rng_seed = RngSeed::Fixed(SEED);
        }
        if std::env::var_os("PROPTEST_CASES").is_none() {
            config.cases = 64;
        }
        config.failure_persistence = None;
        config
    }

    // -------------------------------------------------------------------------------------
    // Building DER, and the real objects of testdata/pki/.
    // -------------------------------------------------------------------------------------

    /// A DER length: short form below 128, else long form in at least `min_bytes` bytes.
    fn encode_len(len: usize, min_bytes: usize) -> Vec<u8> {
        if len < 0x80 && min_bytes == 0 {
            return vec![u8::try_from(len).unwrap()];
        }
        let mut bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        while bytes.len() < min_bytes {
            bytes.insert(0, 0);
        }
        let mut out = vec![0x80 | u8::try_from(bytes.len()).unwrap()];
        out.extend(bytes);
        out
    }

    /// One DER element.
    fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(encode_len(contents.len(), 0));
        out.extend_from_slice(contents);
        out
    }

    /// Several parts joined.
    fn cat(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    /// One attribute of a Name: OID contents, value tag, value bytes.
    type Attribute = (Vec<u8>, u8, Vec<u8>);

    /// An X.501 Name: a SEQUENCE of RDNs, each a SET of (OID contents, value tag, value bytes).
    fn name(rdns: &[Vec<Attribute>]) -> Vec<u8> {
        let mut all = Vec::new();
        for rdn in rdns {
            let mut set = Vec::new();
            for (oid, tag, value) in rdn {
                set.extend(tlv(0x30, &cat(&[&tlv(0x06, oid), &tlv(*tag, value)])));
            }
            all.extend(tlv(0x31, &set));
        }
        tlv(0x30, &all)
    }

    /// A Name with one CommonName, UTF8String.
    fn cn_name(cn: &[u8]) -> Vec<u8> {
        name(&[vec![(vec![0x55, 0x04, 0x03], 0x0c, cn.to_vec())]])
    }

    /// An ASN.1 Time as RFC 5280 section 4.1.2.5 writes it: UTCTime to 2049, else GeneralizedTime.
    fn time_tlv(unix: i64) -> Vec<u8> {
        let text = format_utc(unix);
        let digits: String = text.chars().filter(char::is_ascii_digit).collect();
        if digits.as_str() < "20500000000000" {
            tlv(0x17, format!("{}Z", &digits[2..]).as_bytes())
        } else {
            tlv(0x18, format!("{digits}Z").as_bytes())
        }
    }

    /// An Extension: OID contents, critical flag, and the extnValue contents.
    fn ext(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
        let flag = if critical {
            tlv(0x01, &[0xff])
        } else {
            Vec::new()
        };
        tlv(0x30, &cat(&[&tlv(0x06, oid), &flag, &tlv(0x04, value)]))
    }

    /// The cRLNumber extension for INTEGER contents `n`.
    fn number_ext(n: &[u8]) -> Vec<u8> {
        ext(CRL_NUMBER, false, &tlv(0x02, n))
    }

    /// The parts of a CRL, each already DER.
    struct Parts {
        version: bool,
        issuer: Vec<u8>,
        this_update: Vec<u8>,
        next_update: Option<Vec<u8>>,
        revoked: Option<Vec<u8>>,
        exts: Vec<Vec<u8>>,
    }

    /// A CertificateList with an Ed25519 algorithm and a signature of zeros: `parse_crl` reads
    /// the structure and does not check the signature.
    fn crl_from(p: &Parts) -> Vec<u8> {
        let alg = tlv(0x30, &tlv(0x06, &[0x2b, 0x65, 0x70]));
        let version = if p.version {
            tlv(0x02, &[1])
        } else {
            Vec::new()
        };
        let exts = if p.exts.is_empty() {
            Vec::new()
        } else {
            tlv(0xa0, &tlv(0x30, &p.exts.concat()))
        };
        let tbs = tlv(
            0x30,
            &cat(&[
                &version,
                &alg,
                &p.issuer,
                &p.this_update,
                p.next_update.as_deref().unwrap_or(&[]),
                p.revoked.as_deref().unwrap_or(&[]),
                &exts,
            ]),
        );
        let mut sig = vec![0u8];
        sig.extend([0u8; 64]);
        tlv(0x30, &cat(&[&tbs, &alg, &tlv(0x03, &sig)]))
    }

    /// The INTEGER contents of an unsigned number: minimal, with a 0x00 when the top bit is set,
    /// and `pad` extra leading zero octets.
    fn integer_contents(value: u128, pad: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = value
            .to_be_bytes()
            .into_iter()
            .skip_while(|&b| b == 0)
            .collect();
        if bytes.first().is_none_or(|&b| b & 0x80 != 0) {
            bytes.insert(0, 0);
        }
        let mut out = vec![0u8; pad];
        out.extend(bytes);
        out
    }

    /// A well-formed CRL and the values it holds.
    #[derive(Debug, Clone)]
    struct Spec {
        cn: Vec<u8>,
        number: u128,
        pad: usize,
        this_update: i64,
        next_update: i64,
        revoked: Vec<(Vec<u8>, i64)>,
        version: bool,
    }

    impl Spec {
        fn der(&self) -> Vec<u8> {
            let entries: Vec<u8> = self
                .revoked
                .iter()
                .flat_map(|(serial, at)| tlv(0x30, &cat(&[&tlv(0x02, serial), &time_tlv(*at)])))
                .collect();
            crl_from(&Parts {
                version: self.version,
                issuer: cn_name(&self.cn),
                this_update: time_tlv(self.this_update),
                next_update: Some(time_tlv(self.next_update)),
                revoked: (!self.revoked.is_empty()).then(|| tlv(0x30, &entries)),
                exts: vec![number_ext(&integer_contents(self.number, self.pad))],
            })
        }
    }

    /// Unix seconds of years 1970 to 2099 (UTCTime and GeneralizedTime are both used).
    fn time_secs() -> impl Strategy<Value = i64> {
        0i64..4_102_444_800
    }

    /// A number from one octet to sixteen: shifts spread the magnitudes.
    fn number_value() -> impl Strategy<Value = u128> {
        (any::<u128>(), 0u32..128).prop_map(|(v, s)| v >> s)
    }

    fn spec() -> impl Strategy<Value = Spec> {
        (
            prop::collection::vec(0x21u8..0x7f, 1..12),
            number_value(),
            0usize..3,
            time_secs(),
            time_secs(),
            prop::collection::vec((prop::collection::vec(1u8..0x7f, 1..9), time_secs()), 0..3),
            any::<bool>(),
        )
            .prop_map(
                |(cn, number, pad, this_update, next_update, revoked, version)| Spec {
                    cn,
                    number,
                    pad,
                    this_update,
                    next_update,
                    revoked,
                    version,
                },
            )
    }

    /// The files of `testdata/pki/`: (name, DER), CRLs and certificates.
    struct Corpus {
        crls: Vec<(String, Vec<u8>)>,
        certs: Vec<(String, Vec<u8>)>,
    }

    fn corpus() -> &'static Corpus {
        static CORPUS: OnceLock<Corpus> = OnceLock::new();
        CORPUS.get_or_init(|| {
            let dir = format!("{}/../../testdata/pki", env!("CARGO_MANIFEST_DIR"));
            let mut names: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            let (mut crls, mut certs) = (Vec::new(), Vec::new());
            for n in names {
                let path = format!("{dir}/{n}");
                if n.ends_with(".crl") {
                    crls.push((n, read_crl(&path, 1 << 20).unwrap()));
                } else if n.ends_with(".pem") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    for der in pem_decode_all(&text, "CERTIFICATE").unwrap() {
                        certs.push((n.clone(), der));
                    }
                }
            }
            Corpus { crls, certs }
        })
    }

    /// The corpus CRLs `parse_crl` accepts.
    fn accepted_crls() -> Vec<&'static (String, Vec<u8>)> {
        corpus()
            .crls
            .iter()
            .filter(|(_, d)| parse_crl(d).is_ok())
            .collect()
    }

    // -------------------------------------------------------------------------------------
    // Damage to a real object.
    // -------------------------------------------------------------------------------------

    /// One local damage to a byte string.
    #[derive(Debug, Clone)]
    enum Damage {
        /// XOR one byte with a nonzero mask.
        Flip(Index, u8),
        /// Keep a strictly shorter prefix.
        Truncate(Index),
        /// Insert `count` copies of a byte.
        Insert(Index, u8, usize),
        /// Delete up to `count` bytes.
        Delete(Index, usize),
        /// Copy a range (start, length) and insert the copy elsewhere.
        Duplicate(Index, usize, Index),
    }

    fn damage() -> impl Strategy<Value = Damage> {
        prop_oneof![
            (any::<Index>(), 1u8..=255).prop_map(|(i, m)| Damage::Flip(i, m)),
            any::<Index>().prop_map(Damage::Truncate),
            (any::<Index>(), any::<u8>(), 1usize..4).prop_map(|(i, b, n)| Damage::Insert(i, b, n)),
            (any::<Index>(), 1usize..4).prop_map(|(i, n)| Damage::Delete(i, n)),
            (any::<Index>(), 1usize..40, any::<Index>())
                .prop_map(|(s, l, a)| Damage::Duplicate(s, l, a)),
        ]
    }

    /// The damaged bytes, and the first offset the damage acts at. `bytes` is not empty.
    fn apply(d: &Damage, bytes: &[u8]) -> (Vec<u8>, usize) {
        let mut out = bytes.to_vec();
        let pos = match d {
            Damage::Flip(i, mask) => {
                let p = i.index(bytes.len());
                out[p] ^= mask;
                p
            }
            Damage::Truncate(i) => {
                let keep = i.index(bytes.len());
                out.truncate(keep);
                keep
            }
            Damage::Insert(i, b, n) => {
                let p = i.index(bytes.len() + 1);
                out.splice(p..p, std::iter::repeat_n(*b, *n));
                p
            }
            Damage::Delete(i, n) => {
                let p = i.index(bytes.len());
                out.drain(p..(p + n).min(bytes.len()));
                p
            }
            Damage::Duplicate(s, l, a) => {
                let start = s.index(bytes.len());
                let end = (start + l).min(bytes.len());
                let at = a.index(bytes.len() + 1);
                out.splice(at..at, bytes[start..end].iter().copied());
                at
            }
        };
        (out, pos)
    }

    /// A damage of a corpus object chosen by `pick`.
    fn damaged(objects: &'static [(String, Vec<u8>)]) -> impl Strategy<Value = (usize, Damage)> {
        (0..objects.len(), damage())
    }

    // -------------------------------------------------------------------------------------
    // Arbitrary inputs.
    // -------------------------------------------------------------------------------------

    /// Bytes that look like DER: a tag, a length in short or long form (padded, and declared
    /// longer or shorter than the contents by a few bytes), the contents, trailing bytes.
    fn der_like() -> impl Strategy<Value = Vec<u8>> {
        (
            any::<u8>(),
            prop::collection::vec(any::<u8>(), 0..200),
            0usize..5,
            -3isize..4,
            prop::collection::vec(any::<u8>(), 0..8),
        )
            .prop_map(|(tag, contents, min_bytes, delta, trailing)| {
                let declared = contents.len().saturating_add_signed(delta);
                let mut out = vec![tag];
                out.extend(encode_len(declared, min_bytes));
                out.extend(contents);
                out.extend(trailing);
                out
            })
    }

    /// Raw bytes, DER-like bytes, DER-like bytes inside a SEQUENCE inside a SEQUENCE.
    fn any_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            prop::collection::vec(any::<u8>(), 0..64),
            der_like(),
            der_like().prop_map(|b| tlv(0x30, &tlv(0x30, &b))),
            der_like().prop_map(|b| tlv(0x30, &b)),
        ]
    }

    /// A character the terminal could act on, or one that looks like text but is not: ASCII
    /// controls, DEL, C1 controls, bidirectional controls, a backslash, and any character.
    fn any_char() -> impl Strategy<Value = char> {
        prop_oneof![
            4 => (0u8..0x80).prop_map(char::from),
            2 => prop::sample::select(vec![
                '\u{1b}', '\u{7f}', '\u{9b}', '\u{85}', '\u{202e}', '\u{2066}', '\u{200f}',
                '\u{feff}', '\\', '\n', '\r', '\u{0}', '\u{ff}', '\u{10ffff}',
            ]),
            1 => any::<char>(),
        ]
    }

    fn any_text() -> impl Strategy<Value = String> {
        prop::collection::vec(any_char(), 0..40).prop_map(|c| c.into_iter().collect())
    }

    /// Whether a string is printable ASCII only: what the report may print.
    fn printable(text: &str) -> bool {
        text.bytes().all(|b| (0x20..=0x7e).contains(&b))
    }

    // -------------------------------------------------------------------------------------
    // format_utc (sfr_core::seal), used for every time the report prints.
    // -------------------------------------------------------------------------------------

    /// Every i64 is formatted without a panic, in the form `YYYY-MM-DDTHH:MM:SSZ` (the year is
    /// longer, or has a minus sign, outside 0000 to 9999). The doc comment of `format_utc` gives
    /// the form; the seconds, minutes and hours fields are always two digits.
    #[test]
    fn format_utc_handles_the_extremes() {
        for v in [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX] {
            let text = format_utc(v);
            assert!(text.ends_with('Z'), "{v}: {text}");
            assert!(text.contains('T'), "{v}: {text}");
        }
        // Known instants: the epoch, a leap day, and the last second of year 9999.
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(253_402_300_799), "9999-12-31T23:59:59Z");
    }

    proptest! {
        #![proptest_config(config())]

        /// `format_utc` never panics, and its time of day is HH:MM:SS of the seconds into the
        /// day (`rem_euclid`), for any i64 (SPEC B1.7 prints these times).
        #[test]
        fn format_utc_total_and_time_of_day(v in prop_oneof![
            any::<i64>(), Just(i64::MIN), Just(i64::MAX), -100_000i64..100_000
        ]) {
            let text = format_utc(v);
            let secs = v.rem_euclid(86_400);
            let want = format!("T{:02}:{:02}:{:02}Z", secs / 3600, (secs / 60) % 60, secs % 60);
            prop_assert!(text.ends_with(&want), "{} gave {}", v, text);
        }

        /// From 1970 to 9999 the text is exactly 20 characters, and the parser the record's
        /// `seal.time_utc` goes through (`parse_seal_time_seconds`) reads it back to the same
        /// seconds; the order of the instants is the order of the text.
        #[test]
        fn format_utc_round_trips_and_orders(a in 0i64..=253_402_300_799, b in 0i64..=253_402_300_799) {
            let (ta, tb) = (format_utc(a), format_utc(b));
            prop_assert_eq!(ta.len(), 20);
            prop_assert_eq!(parse_seal_time_seconds(&ta).unwrap(), a);
            prop_assert_eq!(a.cmp(&b), ta.cmp(&tb));
        }
    }

    // -------------------------------------------------------------------------------------
    // The DER reader: element and whole_element.
    // -------------------------------------------------------------------------------------

    /// The reader written again with u64 arithmetic: (tag, header length, contents length), or
    /// `None` when `element` must refuse: fewer than two bytes, indefinite length (0x80), a
    /// length of more than four octets, or a length that runs past the end.
    fn oracle(b: &[u8]) -> Option<(u8, usize, usize)> {
        let tag = *b.first()?;
        let first = *b.get(1)?;
        let (hdr, len) = if first < 0x80 {
            (2usize, u64::from(first))
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 {
                return None;
            }
            let bytes = b.get(2..2 + n)?;
            (
                2 + n,
                bytes.iter().fold(0u64, |l, &x| (l << 8) | u64::from(x)),
            )
        };
        if u64::try_from(b.len() - hdr).unwrap() < len {
            return None;
        }
        Some((tag, hdr, usize::try_from(len).unwrap()))
    }

    /// The offset of `inner` in `outer`, when it lies inside it.
    fn offset_in(outer: &[u8], inner: &[u8]) -> Option<usize> {
        let o = outer.as_ptr_range();
        let i = inner.as_ptr_range();
        if inner.is_empty() {
            // An empty slice has no bytes to place; callers check its length only.
            return Some(0);
        }
        if i.start >= o.start && i.end <= o.end {
            Some(i.start as usize - o.start as usize)
        } else {
            None
        }
    }

    proptest! {
        #![proptest_config(config())]

        /// `element` returns `Some` exactly when the DER length rules in its doc comment allow
        /// it (the oracle above), and then: the tag is the first byte; the header, contents and
        /// rest are consecutive and account for every byte of the input; contents and rest are
        /// sub-slices of the input (the same memory); and so `contents.len() + rest.len()` is
        /// smaller than the input, which is what makes the loops that walk a sequence end.
        #[test]
        fn element_laws(b in any_bytes()) {
            let got = element(&b);
            let want = oracle(&b);
            prop_assert_eq!(got.is_some(), want.is_some());
            if let (Some((tag, contents, rest)), Some((wtag, hdr, len))) = (got, want) {
                prop_assert_eq!(tag, wtag);
                prop_assert_eq!(contents.len(), len);
                prop_assert_eq!(hdr + contents.len() + rest.len(), b.len());
                prop_assert!(contents.len() + rest.len() < b.len());
                prop_assert_eq!(contents, &b[hdr..hdr + len]);
                prop_assert_eq!(rest, &b[hdr + len..]);
                if !contents.is_empty() {
                    prop_assert_eq!(offset_in(&b, contents), Some(hdr));
                }
                if !rest.is_empty() {
                    prop_assert_eq!(offset_in(&b, rest), Some(hdr + len));
                }
            }
        }

        /// `whole_element` is `element` with the header kept: it is `Some` exactly when `element`
        /// is, the whole element is the input up to the rest, the rest is the same rest, and
        /// reading the whole element again gives the same tag and contents and nothing after.
        #[test]
        fn whole_element_is_consistent_with_element(b in any_bytes()) {
            match (element(&b), whole_element(&b)) {
                (None, None) => {}
                (Some((tag, contents, rest)), Some((whole, wrest))) => {
                    prop_assert_eq!(wrest, rest);
                    prop_assert_eq!(whole, &b[..b.len() - rest.len()]);
                    let (t2, c2, r2) = element(whole).unwrap();
                    prop_assert_eq!(t2, tag);
                    prop_assert_eq!(c2, contents);
                    prop_assert!(r2.is_empty());
                }
                (e, w) => prop_assert!(false, "element {:?} but whole_element {:?}", e, w),
            }
        }

        /// A well-formed element built by `tlv` is read back whole, with the bytes after it
        /// untouched, for contents up to 70000 bytes (a three-octet length) and any tag.
        #[test]
        fn element_reads_what_tlv_wrote(
            tag in any::<u8>(),
            len in prop_oneof![0usize..300, 65_530usize..70_000],
            fill in any::<u8>(),
            after in prop::collection::vec(any::<u8>(), 0..5),
        ) {
            let contents = vec![fill; len];
            let mut bytes = tlv(tag, &contents);
            bytes.extend_from_slice(&after);
            let (t, c, r) = element(&bytes).unwrap();
            prop_assert_eq!(t, tag);
            prop_assert_eq!(c, contents.as_slice());
            prop_assert_eq!(r, after.as_slice());
        }
    }

    // -------------------------------------------------------------------------------------
    // der_time, oid_text, ascii_safe, name_text.
    // -------------------------------------------------------------------------------------

    /// Days in a month of the Gregorian calendar.
    fn days_in(year: i64, month: i64) -> i64 {
        match month {
            2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        }
    }

    /// A valid calendar instant: (year, month, day, hour, minute, second).
    fn calendar(
        years: std::ops::RangeInclusive<i64>,
    ) -> impl Strategy<Value = (i64, i64, i64, i64, i64, i64)> {
        (years, 1i64..=12, 0i64..31, 0i64..24, 0i64..60, 0i64..60)
            .prop_map(|(y, mo, d, h, mi, s)| (y, mo, 1 + d % days_in(y, mo), h, mi, s))
    }

    proptest! {
        #![proptest_config(config())]

        /// `der_time` never panics, whatever the tag and the contents, and when it accepts, the
        /// tag was UTCTime or GeneralizedTime (RFC 5280 section 4.1.2.5, quoted in its doc
        /// comment: UTC, with seconds, no fraction) and the contents end with `Z`.
        #[test]
        fn der_time_total_and_only_the_two_time_types(tag in any::<u8>(), contents in any_bytes()) {
            if der_time(tag, &contents).is_ok() {
                prop_assert!(tag == 0x17 || tag == 0x18);
                prop_assert_eq!(contents.last(), Some(&b'Z'));
                prop_assert_eq!(contents.len(), if tag == 0x17 { 13 } else { 15 });
            }
        }

        /// A GeneralizedTime `YYYYMMDDHHMMSSZ` of a valid instant in 1970 to 9999 is read to
        /// the seconds `format_utc` spells the same way.
        #[test]
        fn der_time_generalized_agrees_with_format_utc(c in calendar(1970..=9999)) {
            let (y, mo, d, h, mi, s) = c;
            let text = format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z");
            let secs = der_time(0x18, text.as_bytes()).unwrap();
            prop_assert_eq!(
                format_utc(secs),
                format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
            );
        }

        /// A UTCTime `YYMMDDHHMMSSZ`: years 70 to 99 are 1970 to 1999 and 00 to 49 are 2000 to
        /// 2049 (the rule in `der_time`, RFC 5280 section 4.1.2.5.1); 50 to 69 would be 1950 to
        /// 1969, before the epoch the record's time can hold, and is refused.
        #[test]
        fn der_time_utc_two_digit_year_rule(c in calendar(1970..=2069)) {
            let (y, mo, d, h, mi, s) = c;
            let text = format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}Z", y % 100);
            let got = der_time(0x17, text.as_bytes());
            if y >= 2050 {
                prop_assert!(got.is_err());
            } else {
                prop_assert_eq!(
                    format_utc(got.unwrap()),
                    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
                );
            }
        }

        /// A time that is not in the one allowed form is refused: wrong tag for the length, a
        /// fraction, an offset, a lowercase z, no Z, no seconds, an impossible month, day, hour,
        /// minute or second.
        #[test]
        fn der_time_refuses_other_forms(c in calendar(1970..=2049), kind in 0usize..12) {
            let (y, mo, d, h, mi, s) = c;
            let utc = format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{s:02}", y % 100);
            let gen_ = format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{s:02}");
            let (tag, text) = match kind {
                0 => (0x18, format!("{utc}Z")),
                1 => (0x17, format!("{gen_}Z")),
                2 => (0x17, format!("{utc}.5Z")),
                3 => (0x17, format!("{utc}+0000")),
                4 => (0x17, format!("{utc}z")),
                5 => (0x17, utc.clone()),
                6 => (0x17, format!("{}Z", &utc[..10])),
                7 => (0x18, format!("{}13{}Z", &gen_[..4], &gen_[6..])),
                8 => (0x18, format!("{}32{}Z", &gen_[..6], &gen_[8..])),
                9 => (0x18, format!("{}24{}Z", &gen_[..8], &gen_[10..])),
                10 => (0x18, format!("{}60{}Z", &gen_[..10], &gen_[12..])),
                _ => (0x18, format!("{}60Z", &gen_[..12])),
            };
            prop_assert!(der_time(tag, text.as_bytes()).is_err(), "{}", text);
        }

        /// `oid_text` never panics (including subidentifiers longer than 64 bits and a last
        /// subidentifier cut short), and writes only digits and dots.
        #[test]
        fn oid_text_total(contents in prop::collection::vec(any::<u8>(), 0..40)) {
            let text = oid_text(&contents);
            prop_assert!(text.bytes().all(|b| b.is_ascii_digit() || b == b'.'));
        }

        /// An object identifier built from arcs is written in dotted form: the first octets
        /// carry `40 * first + second` (the `first subidentifier` comment in `oid_text`), each
        /// arc is base 128 with the high bit on all but its last octet.
        #[test]
        fn oid_text_dotted_form(
            first in 0u64..3,
            second in 0u64..40,
            big in any::<u32>(),
            rest in prop::collection::vec(any::<u32>(), 0..6),
        ) {
            let second = if first == 2 { second + u64::from(big % 1000) } else { second };
            let mut arcs = vec![40 * first + second];
            arcs.extend(rest.iter().map(|&a| u64::from(a)));
            let mut der = Vec::new();
            for a in &arcs {
                let mut groups = vec![u8::try_from(a & 0x7f).unwrap()];
                let mut v = a >> 7;
                while v > 0 {
                    groups.push(u8::try_from(v & 0x7f).unwrap() | 0x80);
                    v >>= 7;
                }
                groups.reverse();
                der.extend(groups);
            }
            let mut want = vec![first.to_string(), second.to_string()];
            want.extend(rest.iter().map(u32::to_string));
            prop_assert_eq!(oid_text(&der), want.join("."));
        }

        /// `ascii_safe` keeps printable ASCII (space to tilde) and writes every other character
        /// as `\u{hex}` of its scalar value (its doc comment), so the output has no control
        /// character, no byte above 0x7e (not DEL, not a C1 control, not a bidirectional
        /// control), and applying it again changes nothing.
        #[test]
        fn ascii_safe_is_printable_ascii(text in any_text()) {
            let safe = ascii_safe(&text);
            prop_assert!(printable(&safe), "{:?}", safe);
            let mut want = String::new();
            for c in text.chars() {
                if (' '..='~').contains(&c) {
                    want.push(c);
                } else {
                    want.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
                }
            }
            prop_assert_eq!(&safe, &want);
            prop_assert_eq!(ascii_safe(&safe), safe);
        }

        /// `name_text` never panics and prints only printable ASCII, for any bytes: a Name that
        /// cannot be read is the fixed text `(unreadable name)`.
        #[test]
        fn name_text_is_printable_for_any_bytes(b in any_bytes()) {
            prop_assert!(printable(&name_text(&b)));
        }

        /// The same for a Name that is well-formed in structure and has hostile values: any
        /// attribute type, any value tag, any value bytes (invalid UTF-8, escape sequences,
        /// bidirectional controls), then one local damage. A string-typed value is escaped by
        /// `ascii_safe`; any other type is hex (`#` and the bytes), so no byte of a value reaches
        /// the output unescaped.
        #[test]
        fn name_text_is_printable_for_hostile_values(
            rdns in prop::collection::vec(
                prop::collection::vec(
                    (
                        prop_oneof![
                            Just(vec![0x55u8, 0x04, 0x03]),
                            Just(vec![0x55u8, 0x04, 0x0a]),
                            prop::collection::vec(any::<u8>(), 0..12),
                        ],
                        prop_oneof![
                            Just(0x0cu8), Just(0x13u8), Just(0x16u8), Just(0x14u8), any::<u8>()
                        ],
                        prop_oneof![
                            any_text().prop_map(String::into_bytes),
                            prop::collection::vec(any::<u8>(), 0..20),
                        ],
                    ),
                    1..3,
                ),
                0..4,
            ),
            d in damage(),
        ) {
            let n = name(&rdns);
            prop_assert!(printable(&name_text(&n)));
            let (broken, _) = apply(&d, &n);
            prop_assert!(printable(&name_text(&broken)));
        }

        /// A Name of known attribute types and printable values is shown as `KEY=value` joined
        /// by `, ` in the stored order; the value of a type that is not a string is `#` and its
        /// hex (`name_text`'s doc comment).
        #[test]
        fn name_text_known_attributes(
            values in prop::collection::vec(prop::collection::vec(0x20u8..0x7f, 0..10), 1..4),
            hex_value in prop::collection::vec(any::<u8>(), 0..6),
        ) {
            let keys: [(&[u8], &str); 4] = [
                (&[0x55, 0x04, 0x03], "CN"),
                (&[0x55, 0x04, 0x0a], "O"),
                (&[0x55, 0x04, 0x0b], "OU"),
                (&[0x55, 0x04, 0x06], "C"),
            ];
            let mut rdns = Vec::new();
            let mut want = Vec::new();
            for (i, v) in values.iter().enumerate() {
                let (oid, key) = keys[i % keys.len()];
                rdns.push(vec![(oid.to_vec(), 0x0c, v.clone())]);
                want.push(format!("{key}={}", String::from_utf8(v.clone()).unwrap()));
            }
            rdns.push(vec![(vec![0x55, 0x04, 0x03], 0x04, hex_value.clone())]);
            want.push(format!("CN=#{}", sfr_core::hex(&hex_value)));
            prop_assert_eq!(name_text(&name(&rdns)), want.join(", "));
        }
    }

    // -------------------------------------------------------------------------------------
    // parse_crl on CRLs built here.
    // -------------------------------------------------------------------------------------

    /// The decimal text `n` (big-endian, no leading zero) spells, read back to bytes by
    /// multiplying by ten: the check of `number_text` that shares no code with it.
    fn decimal_to_bytes(text: &str) -> Vec<u8> {
        let mut n: Vec<u8> = Vec::new();
        for digit in text.bytes() {
            let mut carry = u32::from(digit - b'0');
            for byte in n.iter_mut().rev() {
                let cur = u32::from(*byte) * 10 + carry;
                *byte = u8::try_from(cur & 0xff).unwrap();
                carry = cur >> 8;
            }
            while carry > 0 {
                n.insert(0, u8::try_from(carry & 0xff).unwrap());
                carry >>= 8;
            }
        }
        n
    }

    proptest! {
        #![proptest_config(config())]

        /// A well-formed CRL is read to the values it holds: `issuer` is the whole issuer
        /// Name, `number` the cRLNumber without leading zeros (zero is empty), thisUpdate and
        /// nextUpdate in seconds, the `der` is the input; and the texts the report prints are
        /// printable ASCII, the number in decimal, the times in `format_utc` form.
        #[test]
        fn parse_crl_reads_what_was_written(s in spec()) {
            let der = s.der();
            let info = parse_crl(&der).unwrap();
            prop_assert_eq!(&info.der, &der);
            prop_assert_eq!(&info.issuer, &cn_name(&s.cn));
            prop_assert_eq!(info.this_update, s.this_update);
            prop_assert_eq!(info.next_update, s.next_update);
            let minimal: Vec<u8> = s.number.to_be_bytes().into_iter().skip_while(|&b| b == 0).collect();
            prop_assert_eq!(&info.number, &minimal);
            prop_assert_eq!(info.number_text(), s.number.to_string());
            prop_assert_eq!(decimal_to_bytes(&info.number_text()), minimal);
            prop_assert_eq!(info.this_update_text(), format_utc(s.this_update));
            prop_assert_eq!(info.next_update_text(), format_utc(s.next_update));
            prop_assert!(printable(&info.issuer_text()));
            prop_assert_eq!(info.issuer_text(), format!("CN={}", String::from_utf8(s.cn.clone()).unwrap()));
        }

        /// A CRL without cRLNumber or without nextUpdate is refused (the doc comment of
        /// `parse_crl`: it cannot be ordered or judged for staleness), also when it has another
        /// extension or a revoked list.
        #[test]
        fn parse_crl_refuses_a_missing_number_or_next_update(
            s in spec(),
            missing_number in any::<bool>(),
            other_ext in any::<bool>(),
        ) {
            let other = ext(&[0x55, 0x1d, 0x23], false, &tlv(0x30, &[]));
            let entries = tlv(0x30, &tlv(0x30, &cat(&[&tlv(0x02, &[7]), &time_tlv(s.this_update)])));
            let revoked = (!s.revoked.is_empty()).then_some(entries);
            let mut exts = Vec::new();
            if other_ext {
                exts.push(other);
            }
            let (next, text) = if missing_number {
                (Some(time_tlv(s.next_update)), "cRLNumber")
            } else {
                exts.push(number_ext(&integer_contents(s.number, s.pad)));
                (None, "nextUpdate")
            };
            let der = crl_from(&Parts {
                version: s.version,
                issuer: cn_name(&s.cn),
                this_update: time_tlv(s.this_update),
                next_update: next,
                revoked,
                exts,
            });
            let err = parse_crl(&der).unwrap_err();
            prop_assert!(err.contains(text), "{}", err);
            prop_assert!(err.starts_with("not a CRL this verifier reads"), "{}", err);
            prop_assert_eq!(check_crl_der(&der).unwrap_err(), err);
        }

        /// The refusals and acceptances `parse_crl` documents in its comments, one per case
        /// (see the table in `variant`): a delta CRL, an indirect CRL, a critical extension it
        /// does not read, a cRLNumber that is not a non-negative INTEGER of at most 20 octets,
        /// two cRLNumbers, and every issuingDistributionPoint field that narrows what the CRL
        /// covers (a BOOLEAN field encoded FALSE narrows nothing and is accepted).
        #[test]
        fn parse_crl_refusal_table(s in spec(), kind in 0usize..24, rot in 0usize..3) {
            let (exts, entry_exts, want) = variant(kind, &s);
            let mut exts = exts;
            let at = rot % (exts.len() + 1);
            exts.rotate_left(at);
            let entry = {
                let e = cat(&[&tlv(0x02, &[9]), &time_tlv(s.this_update)]);
                let e = if entry_exts.is_empty() { e } else { cat(&[&e, &tlv(0x30, &entry_exts.concat())]) };
                tlv(0x30, &tlv(0x30, &e))
            };
            let der = crl_from(&Parts {
                version: s.version,
                issuer: cn_name(&s.cn),
                this_update: time_tlv(s.this_update),
                next_update: Some(time_tlv(s.next_update)),
                revoked: Some(entry),
                exts,
            });
            match (parse_crl(&der), want) {
                (Ok(info), None) => {
                    prop_assert_eq!(info.this_update, s.this_update);
                    prop_assert_eq!(info.next_update, s.next_update);
                }
                (Err(e), Some(text)) => prop_assert!(e.contains(text), "kind {}: {}", kind, e),
                (got, want) => prop_assert!(false, "kind {}: got {:?}, want refusal {:?}", kind, got.map(|i| i.number), want),
            }
        }
    }

    /// Extensions of the CRL, extensions of its one revoked entry, and the text the refusal
    /// must hold (`None`: accepted). The cRLNumber extension is added except where the case is
    /// about the number.
    fn variant(kind: usize, s: &Spec) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Option<&'static str>) {
        let num = number_ext(&integer_contents(s.number, 0));
        let idp = |field: &[u8], critical: bool| {
            ext(ISSUING_DISTRIBUTION_POINT, critical, &tlv(0x30, field))
        };
        let unknown = |critical: bool| ext(&[0x55, 0x1d, 0x23], critical, &tlv(0x30, &[]));
        let bool_field = |tag: u8, v: u8| tlv(tag, &[v]);
        match kind {
            0 => (vec![num], vec![], None),
            1 => (vec![num, unknown(false)], vec![], None),
            2 => (vec![num, unknown(true)], vec![], Some("marked critical")),
            3 => (vec![num.clone(), num], vec![], Some("two cRLNumber")),
            4 => (
                vec![num, ext(DELTA_CRL_INDICATOR, false, &tlv(0x02, &[1]))],
                vec![],
                Some("delta CRL"),
            ),
            5 => (vec![num, idp(&[], true)], vec![], None),
            6 => (
                vec![num, idp(&tlv(0xa0, &[]), true)],
                vec![],
                Some("distribution point"),
            ),
            7 => (
                vec![num, idp(&bool_field(0x81, 0xff), true)],
                vec![],
                Some("onlyContainsUserCerts"),
            ),
            8 => (vec![num, idp(&bool_field(0x81, 0x00), true)], vec![], None),
            9 => (
                vec![num, idp(&bool_field(0x82, 0xff), true)],
                vec![],
                Some("onlyContainsCACerts"),
            ),
            10 => (vec![num, idp(&bool_field(0x82, 0x00), true)], vec![], None),
            11 => (
                vec![num, idp(&tlv(0x83, &[6, 0x40]), true)],
                vec![],
                Some("onlySomeReasons"),
            ),
            12 => (
                vec![num, idp(&tlv(0xa3, &[]), true)],
                vec![],
                Some("onlySomeReasons"),
            ),
            13 => (
                vec![num, idp(&bool_field(0x84, 0xff), true)],
                vec![],
                Some("indirectCRL"),
            ),
            14 => (vec![num, idp(&bool_field(0x84, 0x00), true)], vec![], None),
            15 => (
                vec![num, idp(&bool_field(0x85, 0xff), true)],
                vec![],
                Some("attribute certificates"),
            ),
            16 => (vec![num, idp(&bool_field(0x85, 0x00), true)], vec![], None),
            17 => (
                vec![num],
                vec![ext(CERTIFICATE_ISSUER, false, &tlv(0x30, &[]))],
                Some("indirect CRL"),
            ),
            18 => (vec![num], vec![unknown(true)], Some("marked critical")),
            19 => (
                vec![num],
                vec![ext(&[0x55, 0x1d, 0x15], false, &tlv(0x0a, &[1]))],
                None,
            ),
            20 => (
                vec![ext(CRL_NUMBER, false, &tlv(0x02, &[0x80]))],
                vec![],
                Some("cRLNumber is not"),
            ),
            21 => (
                vec![ext(CRL_NUMBER, false, &tlv(0x02, &[]))],
                vec![],
                Some("cRLNumber is not"),
            ),
            22 => (
                vec![ext(CRL_NUMBER, false, &tlv(0x04, &[1]))],
                vec![],
                Some("cRLNumber is not"),
            ),
            _ => (
                vec![ext(CRL_NUMBER, false, &tlv(0x02, &[1; 22]))],
                vec![],
                Some("cRLNumber is not"),
            ),
        }
    }

    proptest! {
        #![proptest_config(config())]

        /// The cRLNumber INTEGER of at most 20 octets (the message `parse_crl` gives, from
        /// RFC 5280 section 5.2.3): a number of 21 significant octets is outside that bound and
        /// must be refused. The code lets a 0x00 sign octet through in front of 20 octets, and
        /// its bound of 21 octets also admits 21 octets with a nonzero first octet.
        #[test]
        fn crl_number_is_at_most_twenty_significant_octets(
            first in 1u8..0x80,
            rest in prop::collection::vec(any::<u8>(), 20..=20),
        ) {
            let mut n = vec![first];
            n.extend(rest);
            let der = crl_from(&Parts {
                version: true,
                issuer: cn_name(b"CA"),
                this_update: time_tlv(0),
                next_update: Some(time_tlv(1)),
                revoked: None,
                exts: vec![number_ext(&n)],
            });
            prop_assert!(parse_crl(&der).is_err());
        }

        /// A number of 20 octets with the 0x00 sign octet in front (21 octets of INTEGER) is
        /// accepted and printed in decimal.
        #[test]
        fn crl_number_of_twenty_octets_is_accepted(
            rest in prop::collection::vec(any::<u8>(), 19..=19),
            first in 0x80u8..=255,
        ) {
            let mut n = vec![0u8, first];
            n.extend(rest);
            let der = crl_from(&Parts {
                version: true,
                issuer: cn_name(b"CA"),
                this_update: time_tlv(0),
                next_update: Some(time_tlv(1)),
                revoked: None,
                exts: vec![number_ext(&n)],
            });
            let info = parse_crl(&der).unwrap();
            prop_assert_eq!(info.number.as_slice(), &n[1..]);
            prop_assert_eq!(decimal_to_bytes(&info.number_text()), n[1..].to_vec());
        }

        /// An error message of `parse_crl` is printed by `verify`, and a CRL file is input: the
        /// message must hold only printable ASCII, whatever the CRL's time fields contain.
        #[test]
        fn parse_crl_errors_are_printable(
            s in spec(),
            tag in prop_oneof![Just(0x17u8), Just(0x18u8), any::<u8>()],
            text in any_text(),
            which in any::<bool>(),
        ) {
            let bad = tlv(tag, text.as_bytes());
            let (this_update, next_update) = if which {
                (bad, time_tlv(s.next_update))
            } else {
                (time_tlv(s.this_update), bad)
            };
            let der = crl_from(&Parts {
                version: true,
                issuer: cn_name(&s.cn),
                this_update,
                next_update: Some(next_update),
                revoked: None,
                exts: vec![number_ext(&integer_contents(s.number, 0))],
            });
            if let Err(e) = parse_crl(&der) {
                prop_assert!(printable(&e), "{:?}", e);
            }
            if let Err(e) = check_crl_der(&der) {
                prop_assert!(printable(&e), "{:?}", e);
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // current_crls.
    // -------------------------------------------------------------------------------------

    /// A CRL of issuer `CA<issuer>` with this number; `this_update` tells CRLs of one number apart.
    fn numbered(issuer: usize, number: u128, this_update: i64) -> Vec<u8> {
        Spec {
            cn: format!("CA{issuer}").into_bytes(),
            number,
            pad: 0,
            this_update,
            next_update: this_update + 1000,
            revoked: Vec::new(),
            version: true,
        }
        .der()
    }

    proptest! {
        #![proptest_config(config())]

        /// `current_crls` keeps, for each issuer, the CRL with the highest cRLNumber (its doc
        /// comment, RFC 5280 section 5.2.3), compares numbers as unsigned integers whatever their
        /// length, and does not depend on the order of its input: every shuffle gives the same
        /// list.
        #[test]
        fn current_crls_keeps_the_highest_number_in_any_order(
            numbers in prop::collection::vec(
                prop::collection::btree_set(number_value(), 1..4),
                1..4,
            ),
            base in 0i64..1_000_000_000,
            order in any::<u64>(),
        ) {
            let mut all: Vec<(usize, u128, Vec<u8>)> = Vec::new();
            for (issuer, set) in numbers.iter().enumerate() {
                for (i, &n) in set.iter().enumerate() {
                    all.push((issuer, n, numbered(issuer, n, base + i64::try_from(i).unwrap())));
                }
            }
            let sorted: Vec<Vec<u8>> = all.iter().map(|(_, _, d)| d.clone()).collect();
            let mut shuffled = sorted.clone();
            // A deterministic permutation from `order`: a Fisher-Yates shuffle on an LCG.
            let mut state = order | 1;
            for i in (1..shuffled.len()).rev() {
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
                let j = usize::try_from(state >> 33).unwrap() % (i + 1);
                shuffled.swap(i, j);
            }
            let want = current_crls(&sorted).unwrap();
            let got = current_crls(&shuffled).unwrap();
            prop_assert_eq!(&got, &want);
            prop_assert_eq!(got.len(), numbers.len());
            let mut kept: Vec<&Vec<u8>> = got.iter().map(|c| &c.der).collect();
            let mut expected: Vec<&Vec<u8>> = Vec::new();
            for (issuer, set) in numbers.iter().enumerate() {
                let top = *set.iter().max().unwrap();
                let (_, _, der) = all.iter().find(|(i, n, _)| *i == issuer && *n == top).unwrap();
                expected.push(der);
            }
            kept.sort();
            expected.sort();
            prop_assert_eq!(kept, expected);
        }

        /// Two different CRLs of one issuer with the same highest number are refused (the doc
        /// comment of `current_crls`), in any order and also when other CRLs and other issuers
        /// are present; the message names the issuer and the number. The same CRL twice is not
        /// a conflict, and a conflict between two lower numbers is not one either (only the
        /// highest is judged).
        #[test]
        fn current_crls_refuses_a_conflict_at_the_top_only(
            top in 1u128..u128::MAX,
            a in 0i64..1_000_000,
            gap in 1i64..1000,
            lower in 0u128..1000,
            swap in any::<bool>(),
        ) {
            let top = top.max(2) | 1;
            let lower = lower % top;
            let c1 = numbered(0, top, a);
            let c2 = numbered(0, top, a + gap);
            let other = numbered(1, lower, a);
            let (x, y) = if swap { (c2.clone(), c1.clone()) } else { (c1.clone(), c2.clone()) };
            let err = current_crls(&[x.clone(), other.clone(), y.clone()]).unwrap_err();
            prop_assert!(err.starts_with("CRL: two different CRLs from CN=CA0 have the same CRL number "), "{}", err);
            prop_assert!(err.contains(&format!("number {top},")), "{}", err);
            prop_assert_eq!(current_crls(&[y, other.clone(), x]).unwrap_err(), err);
            // The same CRL twice is one CRL.
            let once = current_crls(&[c1.clone(), other.clone()]).unwrap();
            prop_assert_eq!(current_crls(&[c1.clone(), c1.clone(), other.clone()]).unwrap(), once);
            // A conflict below the highest number is not judged.
            if lower > 0 {
                let l2 = numbered(1, lower, a + gap);
                let ok = current_crls(&[other.clone(), l2, numbered(1, lower + top, 5)]).unwrap();
                prop_assert_eq!(ok.len(), 1);
                prop_assert_eq!(ok[0].number_text(), (lower + top).to_string());
            }
            // The same number encoded with and without padding is a different CRL.
            let mut padded = Spec {
                cn: b"CA2".to_vec(), number: top, pad: 0, this_update: a, next_update: a + 5,
                revoked: Vec::new(), version: true,
            };
            let plain = padded.der();
            padded.pad = 1;
            prop_assert!(current_crls(&[plain, padded.der()]).is_err());
        }

        /// One CRL `parse_crl` refuses makes the whole call fail with the message prefixed
        /// `CRL: `, wherever it is in the list. No CRLs is an empty result.
        #[test]
        fn current_crls_fails_on_one_bad_crl(
            n in 0usize..4,
            at in any::<Index>(),
            d in damage(),
            keep_prefix in any::<bool>(),
        ) {
            prop_assert!(current_crls(&[]).unwrap().is_empty());
            let mut list: Vec<Vec<u8>> = (0..n).map(|i| numbered(i, 5, 1)).collect();
            let victim = numbered(9, 5, 1);
            let (mut broken, _) = apply(&d, &victim);
            if keep_prefix && broken.len() > 1 {
                // A refusal that is certain: trailing data after the SEQUENCE.
                broken = victim.clone();
                broken.push(0);
            }
            let pos = at.index(list.len() + 1);
            list.insert(pos, broken.clone());
            match (parse_crl(&broken), current_crls(&list)) {
                (Err(e), Err(got)) => prop_assert_eq!(got, format!("CRL: {e}")),
                (Ok(_), Ok(got)) => prop_assert!(got.len() <= list.len()),
                (p, c) => prop_assert!(false, "parse {:?} but current {:?}", p.map(|_| ()), c.map(|_| ())),
            }
        }

        /// On the real CRLs of `testdata/pki/`: any subset in any order gives the same answer
        /// as the sorted subset (an error or the same list), and when it is a list it holds one
        /// CRL per issuer, with the highest number among those given of that issuer.
        #[test]
        fn current_crls_on_real_crls_is_order_independent(
            picks in prop::collection::vec(any::<Index>(), 0..8),
            order in prop::collection::vec(any::<Index>(), 8),
        ) {
            let pool = accepted_crls();
            prop_assert!(!pool.is_empty());
            let mut chosen: Vec<&Vec<u8>> = picks.iter().map(|i| &pool[i.index(pool.len())].1).collect();
            let mut sorted = chosen.clone();
            sorted.sort();
            // Permute by swapping each position with a chosen one.
            for (i, o) in order.iter().enumerate().take(chosen.len()) {
                let j = o.index(chosen.len());
                chosen.swap(i, j);
            }
            let a: Vec<Vec<u8>> = chosen.into_iter().cloned().collect();
            let b: Vec<Vec<u8>> = sorted.into_iter().cloned().collect();
            let (ra, rb) = (current_crls(&a), current_crls(&b));
            prop_assert_eq!(&ra, &rb);
            if let Ok(list) = ra {
                let mut issuers: Vec<&Vec<u8>> = list.iter().map(|c| &c.issuer).collect();
                issuers.sort();
                issuers.dedup();
                prop_assert_eq!(issuers.len(), list.len());
                for kept in &list {
                    for der in &a {
                        let info = parse_crl(der).unwrap();
                        if info.issuer == kept.issuer {
                            prop_assert!(
                                (info.number.len(), &info.number) <= (kept.number.len(), &kept.number)
                            );
                        }
                    }
                }
            }
        }
    }

    // -------------------------------------------------------------------------------------
    // Damaged real objects, and arbitrary bytes, for the functions that read files.
    // -------------------------------------------------------------------------------------

    /// The fields `parse_crl` reads.
    fn fields(i: &CrlInfo) -> (&[u8], &[u8], i64, i64) {
        (&i.issuer, &i.number, i.this_update, i.next_update)
    }

    /// What every accepted CrlInfo holds, however the CRL was damaged: the DER is the input;
    /// the issuer is one whole element; the number has no leading zero; both times are
    /// instants `format_utc` writes as a year 1970 to 9999; the printed texts are printable.
    fn check_invariants(der: &[u8], i: &CrlInfo) -> Result<(), TestCaseError> {
        prop_assert_eq!(&i.der, der);
        let (whole, rest) = whole_element(&i.issuer).unwrap();
        prop_assert_eq!(whole, i.issuer.as_slice());
        prop_assert!(rest.is_empty());
        prop_assert!(i.number.first() != Some(&0));
        prop_assert!(i.number.len() <= 21);
        for t in [i.this_update, i.next_update] {
            prop_assert!((0..=253_402_300_799).contains(&t), "{}", t);
        }
        prop_assert_eq!(decimal_to_bytes(&i.number_text()), i.number.clone());
        prop_assert!(printable(&i.issuer_text()));
        prop_assert_eq!(i.this_update_text().len(), 20);
        prop_assert_eq!(i.next_update_text().len(), 20);
        Ok(())
    }

    /// The offsets in a CRL of the outer header's end and of the end of the TBSCertList.
    fn crl_layout(der: &[u8]) -> (usize, usize) {
        let (_, contents, _) = element(der).unwrap();
        let header = der.len() - contents.len();
        let (whole_tbs, _) = whole_element(contents).unwrap();
        (header, header + whole_tbs.len())
    }

    proptest! {
        #![proptest_config(config())]

        /// No damage to a real CRL makes `parse_crl` or `check_crl_der` panic; when `parse_crl`
        /// accepts the damaged bytes the invariants of `check_invariants` hold; `check_crl_der`
        /// accepts only what `parse_crl` accepts and gives `parse_crl`'s message when it
        /// refuses; and a refusal is a message that starts `not a CRL this verifier reads` or
        /// is a webpki reason.
        #[test]
        fn damaged_crl_is_never_a_panic_and_accepted_ones_are_sound(
            (k, d) in damaged(&corpus().crls),
        ) {
            let original = &corpus().crls[k].1;
            let (bytes, _) = apply(&d, original);
            let parsed = parse_crl(&bytes);
            let checked = check_crl_der(&bytes);
            match (&parsed, &checked) {
                (Ok(info), _) => check_invariants(&bytes, info)?,
                (Err(e), Err(c)) => prop_assert_eq!(e, c),
                (Err(_), Ok(())) => prop_assert!(false, "check_crl_der accepts what parse_crl refuses"),
            }
        }

        /// A change that alters the length of a CRL, outside the outer SEQUENCE header (a
        /// truncation anywhere, or an insertion, a deletion or a duplication after the header),
        /// leaves the outer length wrong, and `parse_crl` must refuse it: it requires exactly
        /// one SEQUENCE and nothing after it.
        #[test]
        fn a_crl_of_the_wrong_length_is_refused((k, d) in damaged(&corpus().crls)) {
            let original = &corpus().crls[k].1;
            let (header, _) = crl_layout(original);
            let (bytes, pos) = apply(&d, original);
            if matches!(d, Damage::Flip(..)) {
                return Ok(());
            }
            if matches!(d, Damage::Truncate(_)) || pos >= header {
                prop_assert!(parse_crl(&bytes).is_err());
                prop_assert!(check_crl_der(&bytes).is_err());
            }
        }

        /// A byte flipped after the TBSCertList (the outer signatureAlgorithm, the signature
        /// value) changes nothing `parse_crl` reads, and one flipped anywhere that still parses
        /// differs from the original only in the TBSCertList or the outer header: the fields
        /// are the same unless the flip is inside the part `parse_crl` reads.
        #[test]
        fn a_flip_changes_the_fields_only_inside_the_tbs(
            k in any::<Index>(),
            pos in any::<Index>(),
            mask in 1u8..=255,
        ) {
            let pool = accepted_crls();
            let original = &pool[k.index(pool.len())].1;
            let before = parse_crl(original).unwrap();
            let (header, tbs_end) = crl_layout(original);
            let p = pos.index(original.len());
            let mut bytes = original.clone();
            bytes[p] ^= mask;
            if let Ok(after) = parse_crl(&bytes) {
                check_invariants(&bytes, &after)?;
                if p >= tbs_end {
                    prop_assert_eq!(fields(&after), fields(&before));
                }
                if fields(&after) != fields(&before) {
                    prop_assert!(p >= header && p < tbs_end, "flip at {} changed the fields", p);
                }
            } else {
                // A flip after the TBSCertList cannot make `parse_crl` refuse.
                prop_assert!(p < tbs_end, "flip at {} after the TBS was refused", p);
            }
        }

        /// No damage to a real certificate makes `check_anchor_der`, `certificate_key` or
        /// `certificate_fingerprint` panic. The fingerprint is `sha256:` and 64 lowercase hex
        /// digits for any bytes, equal for equal bytes and different for different bytes; a key
        /// that is returned is the 32 bytes of an Ed25519 key (RFC 8410), and an error is a
        /// non-empty line of printable ASCII.
        #[test]
        fn damaged_certificate_is_never_a_panic((k, d) in damaged(&corpus().certs)) {
            let original = &corpus().certs[k].1;
            let (bytes, _) = apply(&d, original);
            let fp = certificate_fingerprint(&bytes);
            prop_assert!(fp.starts_with("sha256:"));
            prop_assert_eq!(fp.len(), 7 + 64);
            prop_assert!(fp[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
            prop_assert_eq!(&fp, &certificate_fingerprint(&bytes));
            prop_assert_eq!(bytes == *original, fp == certificate_fingerprint(original));
            if let Err(e) = check_anchor_der(&bytes) {
                prop_assert!(!e.is_empty() && printable(&e), "{:?}", e);
            }
            match certificate_key(&bytes) {
                Ok(key) => prop_assert_eq!(key.len(), 32),
                Err(e) => prop_assert!(!e.is_empty() && printable(&e), "{:?}", e),
            }
        }

        /// None of the functions that read a file panics on arbitrary bytes, nor on bytes that
        /// look like DER; a refusal is an `Err` with a message, never an `Ok` that holds a
        /// result for bytes that are not an object of that kind; `current_crls` fails on a list
        /// that holds such bytes; the helpers (`element`, `whole_element`, `der_time`,
        /// `oid_text`, `name_text`, `ascii_safe`) take the same bytes.
        #[test]
        fn arbitrary_bytes_are_refused_without_a_panic(b in any_bytes(), t in any::<u8>()) {
            let _ = element(&b);
            let _ = whole_element(&b);
            let _ = der_time(t, &b);
            prop_assert!(oid_text(&b).bytes().all(|c| c.is_ascii_digit() || c == b'.'));
            prop_assert!(printable(&name_text(&b)));
            prop_assert!(printable(&ascii_safe(&String::from_utf8_lossy(&b))));
            let fp = certificate_fingerprint(&b);
            prop_assert_eq!(fp.len(), 71);
            if let Ok(info) = parse_crl(&b) {
                check_invariants(&b, &info)?;
            } else {
                prop_assert!(check_crl_der(&b).is_err());
                prop_assert!(current_crls(std::slice::from_ref(&b)).is_err());
                prop_assert!(current_crls(&[numbered(0, 1, 0), b.clone(), numbered(1, 2, 0)]).is_err());
            }
            if check_anchor_der(&b).is_ok() || certificate_key(&b).is_ok() {
                // Only a certificate webpki reads gets here: at least a SEQUENCE.
                prop_assert_eq!(b[0], 0x30);
            }
        }
    }

    proptest! {
        #![proptest_config(config())]

        /// The issuer of a CRL is a Name, a SEQUENCE (`CrlInfo::issuer`: "The issuer Name, as its
        /// whole DER element"; RFC 5280 section 4.1.2.4), so a CRL whose issuer element has any
        /// other tag must be refused. `parse_crl` takes any element, and `check_crl_der`, which
        /// `verify` runs on each CRL file, accepts it too.
        #[test]
        fn a_crl_issuer_that_is_not_a_sequence_is_refused(
            k in any::<Index>(),
            tag in (0u8..255).prop_map(|t| if t >= 0x30 { t + 1 } else { t }),
        ) {
            let pool = accepted_crls();
            let der = &pool[k.index(pool.len())].1;
            let info = parse_crl(der).unwrap();
            let at = der
                .windows(info.issuer.len())
                .position(|w| w == info.issuer.as_slice())
                .unwrap();
            let mut bytes = der.clone();
            bytes[at] = tag;
            prop_assert!(parse_crl(&bytes).is_err());
            prop_assert!(check_crl_der(&bytes).is_err());
        }
    }

    /// The real files: what `parse_crl` makes of each, so a change in the reader or in the data
    /// is seen. The refusals are the ones the file names say (delta, indirect, partial CRL, a
    /// critical extension); the others are accepted and checked by webpki as well.
    #[test]
    fn the_real_crls_are_read_as_their_names_say() {
        for (name, der) in &corpus().crls {
            let parsed = parse_crl(der);
            let expect_refusal = match name.as_str() {
                "inter_delta.crl" => Some("delta CRL"),
                "inter_indirect.crl" => Some("indirect"),
                "inter_dp.crl" => Some("distribution point"),
                "inter_cacerts.crl" => Some("onlyContainsCACerts"),
                "inter_usercerts.crl" => Some("onlyContainsUserCerts"),
                "inter_critical.crl" => Some("marked critical"),
                _ => None,
            };
            match (parsed, expect_refusal) {
                (Ok(info), None) => {
                    check_invariants(der, &info).unwrap();
                    check_crl_der(der).unwrap();
                }
                (Err(e), Some(text)) => assert!(e.contains(text), "{name}: {e}"),
                (got, want) => assert_eq!(
                    got.is_ok(),
                    want.is_none(),
                    "{name}: {:?} against {want:?}",
                    got.map(|i| i.number)
                ),
            }
        }
        for (name, der) in &corpus().certs {
            let key = certificate_key(der);
            assert!(key.is_ok(), "{name}: {key:?}");
            assert!(
                check_anchor_der(der).is_ok() || name.starts_with("signer"),
                "{name}"
            );
        }
    }
}
