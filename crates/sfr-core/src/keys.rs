//! Key encodings (SPEC B1.3 keygen, B1.7 key fingerprint).
//!
//! `sfr.pub` is a PEM `PUBLIC KEY` (RFC 8410 SubjectPublicKeyInfo for Ed25519) and `sfr.key` a
//! PEM `PRIVATE KEY` (PKCS#8), the forms `openssl pkey` reads, so a record can be checked
//! without `sfr`. The key fingerprint is `sha256:` and the hex SHA-256 of the
//! SubjectPublicKeyInfo DER (`openssl pkey -pubin -in sfr.pub -outform DER | sha256sum`).

use crate::crypto::CryptoBackend;
use crate::hex;
use zeroize::Zeroizing;

/// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410 section 4), before the 32 key bytes.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// DER prefix of an Ed25519 PKCS#8 v1 private key (RFC 8410 section 7), before the 32-byte seed.
const PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The same for PKCS#8 v2 (RFC 5958 OneAsymmetricKey) with the public key and no attributes.
const PKCS8_V2_PREFIX: [u8; 16] = [
    0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// v2, between the seed and the public key: `publicKey [1] IMPLICIT BIT STRING`, 0 unused bits.
const PKCS8_V2_PUBLIC_KEY: [u8; 3] = [0x81, 0x21, 0x00];

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (RFC 4648 section 4).
pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let idx = ((n >> (18 - 6 * i)) & 63) as usize;
                out.push(char::from(B64.get(idx).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Strict standard base64 decoding: no whitespace, correct padding, zero trailing bits.
pub fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let value = |c: u8| B64.iter().position(|&x| x == c).map(|p| p as u32);
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks = bytes.len() / 4;
    for (ci, chunk) in bytes.chunks(4).enumerate() {
        let last = ci + 1 == chunks;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if i >= 4 - pad { 0 } else { value(c)? };
            n = (n << 6) | v;
        }
        let [_, a, b, c] = n.to_be_bytes();
        match pad {
            0 => out.extend_from_slice(&[a, b, c]),
            1 if c == 0 => out.extend_from_slice(&[a, b]),
            2 if b == 0 && c == 0 => out.push(a),
            _ => return None,
        }
    }
    Some(out)
}

/// PEM text with 64-character lines.
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let b64 = base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The DER inside the single PEM block labelled `label`.
pub fn pem_decode(text: &str, label: &str) -> Result<Vec<u8>, String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text
        .find(&begin)
        .ok_or_else(|| format!("no `{begin}` line"))?;
    let after = text.get(start + begin.len()..).unwrap_or("");
    let stop = after.find(&end).ok_or_else(|| format!("no `{end}` line"))?;
    let body: String = after
        .get(..stop)
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    base64_decode(&body).ok_or_else(|| format!("the {label} block is not valid base64"))
}

/// The DER of every PEM block labelled `label`, in file order. Text outside the blocks is
/// ignored, as `openssl` ignores it.
pub fn pem_decode_all(text: &str, label: &str) -> Result<Vec<Vec<u8>>, String> {
    let begin = format!("-----BEGIN {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(&begin) {
        let block = rest.get(start..).unwrap_or("");
        out.push(pem_decode(block, label)?);
        let end = format!("-----END {label}-----");
        let stop = block.find(&end).map_or(block.len(), |i| i + end.len());
        rest = block.get(stop..).unwrap_or("");
    }
    if out.is_empty() {
        return Err(format!("no `{begin}` line"));
    }
    Ok(out)
}

/// The RFC 8410 SubjectPublicKeyInfo DER of an Ed25519 public key.
pub fn ed25519_spki_der(public_key: &[u8; 32]) -> Vec<u8> {
    let mut der = SPKI_PREFIX.to_vec();
    der.extend_from_slice(public_key);
    der
}

/// The raw public key from an Ed25519 SubjectPublicKeyInfo DER.
pub fn ed25519_from_spki_der(der: &[u8]) -> Option<[u8; 32]> {
    let rest = der.strip_prefix(&SPKI_PREFIX[..])?;
    rest.try_into().ok()
}

/// The PKCS#8 v1 DER of an Ed25519 private key (`sfr.key`, the form `openssl genpkey` writes).
pub fn ed25519_pkcs8_v1_der(seed: &[u8; 32]) -> Zeroizing<Vec<u8>> {
    let mut der = Zeroizing::new(Vec::with_capacity(PKCS8_V1_PREFIX.len() + 32));
    der.extend_from_slice(&PKCS8_V1_PREFIX);
    der.extend_from_slice(seed);
    der
}

/// An Ed25519 seed (zeroized on drop) and, from a PKCS#8 v2 key, the public key it carries.
pub type SeedAndPublicKey = (Zeroizing<[u8; 32]>, Option<[u8; 32]>);

/// The seed, and the public key if the key is v2, from an Ed25519 PKCS#8 DER. Accepts v1 and
/// v2 without attributes; anything else is `None`.
pub fn ed25519_seed_from_pkcs8_der(der: &[u8]) -> Option<SeedAndPublicKey> {
    if let Some(seed) = der.strip_prefix(&PKCS8_V1_PREFIX[..]) {
        return Some((Zeroizing::new(seed.try_into().ok()?), None));
    }
    let rest = der.strip_prefix(&PKCS8_V2_PREFIX[..])?;
    let (seed, rest) = rest.split_at_checked(32)?;
    let public = rest.strip_prefix(&PKCS8_V2_PUBLIC_KEY[..])?;
    Some((
        Zeroizing::new(seed.try_into().ok()?),
        Some(public.try_into().ok()?),
    ))
}

/// `sfr.pub` text.
pub fn public_key_pem(public_key: &[u8; 32]) -> String {
    pem_encode("PUBLIC KEY", &ed25519_spki_der(public_key))
}

/// Reads `sfr.pub` text.
pub fn parse_public_key_pem(text: &str) -> Result<[u8; 32], String> {
    let der = pem_decode(text, "PUBLIC KEY")?;
    ed25519_from_spki_der(&der).ok_or_else(|| "not an Ed25519 public key (RFC 8410)".to_string())
}

/// The record's key fingerprint: `sha256:` and the hex SHA-256 of the SubjectPublicKeyInfo DER.
pub fn fingerprint(crypto: &dyn CryptoBackend, public_key: &[u8; 32]) -> String {
    format!(
        "sha256:{}",
        hex(&crypto.sha256(&ed25519_spki_der(public_key)))
    )
}

/// Decodes lowercase hex of exactly `N` bytes.
pub fn hex_decode<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != 2 * N {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = nibble(*bytes.get(2 * i)?)?;
        let lo = nibble(*bytes.get(2 * i + 1)?)?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        let v: &[(&str, &str)] = &[
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, enc) in v {
            assert_eq!(base64_encode(plain.as_bytes()), *enc);
            assert_eq!(base64_decode(enc).as_deref(), Some(plain.as_bytes()));
        }
        for bad in ["Zg=", "Zh==", "Z===", "Zm9v=", "Zg==Zg==", "Zm9*"] {
            assert_eq!(base64_decode(bad), None, "{bad}");
        }
    }

    #[test]
    fn public_key_pem_round_trips_and_matches_rfc8410() {
        // RFC 8410 section 10.1 example public key.
        let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n-----END PUBLIC KEY-----\n";
        let key = parse_public_key_pem(pem).expect("valid");
        assert_eq!(
            hex(&key),
            "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
        );
        assert_eq!(public_key_pem(&key), pem);
        assert_eq!(hex_decode::<32>(&hex(&key)), Some(key));
        assert_eq!(
            hex_decode::<2>("0A00"),
            None,
            "uppercase is not the record's hex"
        );
    }

    #[test]
    fn pkcs8_private_keys_round_trip_and_match_rfc8410() {
        // RFC 8410 section 10.3 example private key (v1).
        let pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n-----END PRIVATE KEY-----\n";
        let der = pem_decode(pem, "PRIVATE KEY").expect("valid PEM");
        let (seed, public) = ed25519_seed_from_pkcs8_der(&der).expect("v1 parses");
        assert_eq!(
            hex(&seed[..]),
            "d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842"
        );
        assert_eq!(public, None);
        assert_eq!(&ed25519_pkcs8_v1_der(&seed)[..], &der[..]);
        assert_eq!(pem_encode("PRIVATE KEY", &der), pem);
        // v2 with the public key, as aws-lc-rs wrote it.
        let mut v2 = PKCS8_V2_PREFIX.to_vec();
        v2.extend_from_slice(&seed[..]);
        v2.extend_from_slice(&PKCS8_V2_PUBLIC_KEY);
        v2.extend_from_slice(&[7; 32]);
        let (seed2, public2) = ed25519_seed_from_pkcs8_der(&v2).expect("v2 parses");
        assert_eq!(seed2, seed);
        assert_eq!(public2, Some([7; 32]));
        // Truncated, extended, other algorithms, and v2 with attributes are refused.
        assert!(ed25519_seed_from_pkcs8_der(der.get(..47).expect("short")).is_none());
        assert!(ed25519_seed_from_pkcs8_der(&[&der[..], &[0][..]].concat()).is_none());
        assert!(ed25519_seed_from_pkcs8_der(v2.get(..82).expect("short")).is_none());
        let mut x448 = der.clone();
        if let Some(b) = x448.get_mut(11) {
            *b = 0x71;
        }
        assert!(ed25519_seed_from_pkcs8_der(&x448).is_none());
        // RFC 8410 section 10.3 v2 example, which carries an attribute.
        let with_attr = "MHICAQEwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhCoB8wHQYKKoZIhvcNAQkJFDEPDA1DdXJkbGUgQ2hhaXJzgSEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
        assert!(ed25519_seed_from_pkcs8_der(&base64_decode(with_attr).expect("b64")).is_none());
    }
}
