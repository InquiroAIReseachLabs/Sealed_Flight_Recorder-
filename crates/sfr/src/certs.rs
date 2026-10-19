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

/// A chain that reached a trust anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainOk {
    /// The SHA-256 fingerprint of the trust anchor certificate the chain reached.
    pub anchor: String,
    /// The number of supplied CRLs that were checked.
    pub crls: usize,
}

/// Checks the signer certificate and its intermediates against the trust anchors and CRLs, at
/// `seal_time` (Unix seconds).
pub fn check_chain(
    signer: &[u8],
    intermediates: &[Vec<u8>],
    anchors: &[Vec<u8>],
    crls: &[Vec<u8>],
    seal_time: i64,
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
    let owned: Vec<CertRevocationList<'_>> = crls
        .iter()
        .map(|c| {
            OwnedCertRevocationList::from_der(c)
                .map(CertRevocationList::from)
                .map_err(|e| format!("CRL: {}", why(&e)))
        })
        .collect::<Result<_, _>>()?;
    let refs: Vec<&CertRevocationList<'_>> = owned.iter().collect();
    let revocation = if refs.is_empty() {
        None
    } else {
        Some(
            RevocationOptionsBuilder::new(&refs)
                .map_err(|_| "no CRL to check".to_string())?
                .with_depth(RevocationCheckDepth::Chain)
                // A CRL speaks only for its issuer: a certificate whose issuer has no CRL here
                // is not revoked by anything supplied.
                .with_status_policy(UnknownStatusPolicy::Allow)
                // The CRLs are offline files; their nextUpdate is compared with nothing, since
                // the only time sfr has is the sealer's own.
                .with_expiration_policy(ExpirationPolicy::Ignore)
                .build(),
        )
    };
    let secs = u64::try_from(seal_time).map_err(|_| "seal time before 1970".to_string())?;
    let time = UnixTime::since_unix_epoch(Duration::from_secs(secs));
    let path = ee
        .verify_for_usage(
            ALGORITHMS,
            &trust,
            &inter,
            time,
            // On every certificate of the path: if it lists usages, code signing is one. The
            // signer certificate must list them (checked below), so it must name code signing.
            KeyUsage::required_if_present(CODE_SIGNING),
            revocation,
            None,
        )
        .map_err(|e| why(&e))?;
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
        crls: crls.len(),
    })
}
