//! Key encodings (SPEC B1.3 keygen, B1.7 key fingerprint).
//!
//! `sfr.pub` is a PEM `PUBLIC KEY` (RFC 8410 SubjectPublicKeyInfo for Ed25519) and `sfr.key` a
//! PEM `PRIVATE KEY` (PKCS#8), the forms `openssl pkey` reads, so a record can be checked
//! without `sfr`. The key fingerprint is `sha256:` and the hex SHA-256 of the
//! SubjectPublicKeyInfo DER (`openssl pkey -pubin -in sfr.pub -outform DER | sha256sum`).

use crate::crypto::CryptoBackend;
use crate::hex;

/// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410 section 4), before the 32 key bytes.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

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
}
