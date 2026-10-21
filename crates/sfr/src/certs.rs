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
    let other = |e: std::io::Error| FileError::Other(format!("cannot read {what} {path}: {e}"));
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(other)?
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(other)?;
    if bytes.len() as u64 > max {
        return Err(FileError::Limit(format!(
            "{what} {path}: {}",
            sfr_core::limit_exceeded("the file", max, "bytes")
        )));
    }
    Ok(bytes)
}

/// Certificates from a file of at most `max` bytes: every PEM `CERTIFICATE` block, or one DER
/// certificate.
pub fn read_certificates(path: &str, what: &str, max: u64) -> Result<Vec<Vec<u8>>, FileError> {
    let bytes = read_limited(path, what, max)?;
    if bytes.first() == Some(&0x30) {
        return Ok(vec![bytes]);
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| FileError::Other(format!("{what} {path} is neither PEM nor DER")))?;
    pem_decode_all(&text, "CERTIFICATE")
        .map_err(|e| FileError::Other(format!("{what} {path}: {e}")))
}

/// A CRL from a file of at most `max` bytes: a PEM `X509 CRL` block, or DER.
pub fn read_crl(path: &str, max: u64) -> Result<Vec<u8>, FileError> {
    let bytes = read_limited(path, "CRL", max)?;
    if bytes.first() == Some(&0x30) {
        return Ok(bytes);
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| FileError::Other(format!("CRL {path} is neither PEM nor DER")))?;
    let mut blocks = pem_decode_all(&text, "X509 CRL")
        .map_err(|e| FileError::Other(format!("CRL {path}: {e}")))?;
    if blocks.len() != 1 {
        return Err(FileError::Other(format!(
            "CRL {path} holds {} CRLs; give one per --crl",
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
