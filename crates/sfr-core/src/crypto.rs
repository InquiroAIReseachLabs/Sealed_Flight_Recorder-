//! Cryptography (SPEC B1.2, B1.10 Crypto).
//!
//! Every build, on every target, computes SHA-256 with `sha2`, Ed25519 with `ed25519-dalek`, and
//! BLAKE3 with `blake3` ([`rustcrypto::RustCrypto`]), so a record is byte-identical wherever it
//! is sealed. Code selects the backend by type; the trait exists so tests and fuzz targets can
//! substitute their own.

use std::fmt;

/// An incremental SHA-256 computation.
pub trait Sha256Stream {
    /// Feeds more bytes.
    fn update(&mut self, data: &[u8]);
    /// Consumes the stream and returns the 32-byte digest.
    fn finish(self: Box<Self>) -> [u8; 32];
}

/// A crate that computes part of a record, named by its crate version (`seal.crypto_crates`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrateVersion {
    /// The crate's name on crates.io.
    pub name: &'static str,
    /// The crate version pinned in `Cargo.lock`.
    pub version: &'static str,
}

/// The crates behind [`rustcrypto::RustCrypto`], sorted by name. A unit test holds these to
/// `Cargo.lock`.
pub const RUSTCRYPTO_CRATES: [CrateVersion; 3] = [
    CrateVersion {
        name: "blake3",
        version: "1.8.7",
    },
    CrateVersion {
        name: "ed25519-dalek",
        version: "3.0.0",
    },
    CrateVersion {
        name: "sha2",
        version: "0.11.1",
    },
];

/// What the engine needs from its cryptography.
pub trait CryptoBackend {
    /// The crates that compute the record's digests and signature, sorted by name (the
    /// record's `seal.crypto_crates`).
    fn crates(&self) -> &'static [CrateVersion];
    /// Starts an incremental SHA-256 (FIPS 180-4 defines the function).
    fn sha256_stream(&self) -> Box<dyn Sha256Stream>;
    /// Verifies an Ed25519 signature (RFC 8032).
    fn ed25519_verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool;
    /// SHA-256 of one buffer.
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        self.sha256_concat(&[data])
    }
    /// SHA-256 of the concatenation of `parts` (Merkle leaves and nodes).
    fn sha256_concat(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut s = self.sha256_stream();
        for p in parts {
            s.update(p);
        }
        s.finish()
    }
}

/// How the signing key is held (SPEC B1.7 key custody). Declared by the sealer and signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    /// The private key never leaves a PKCS#11 token or HSM.
    Pkcs11Token,
    /// The seed is sealed to one TPM 2.0 and in memory for one signature.
    TpmSealed,
    /// A key file; evaluation only.
    FileEvaluation,
}

impl Custody {
    /// Record spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Custody::Pkcs11Token => "pkcs11-token",
            Custody::TpmSealed => "tpm-sealed",
            Custody::FileEvaluation => "file-evaluation",
        }
    }

    /// Parses the record spelling.
    pub fn parse(s: &str) -> Option<Custody> {
        match s {
            "pkcs11-token" => Some(Custody::Pkcs11Token),
            "tpm-sealed" => Some(Custody::TpmSealed),
            "file-evaluation" => Some(Custody::FileEvaluation),
            _ => None,
        }
    }
}

/// A signing failure (SPEC B1.4 exit 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignError(pub String);

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SignError {}

/// A source of Ed25519 signatures.
pub trait Signer {
    /// The raw 32-byte public key.
    fn public_key(&self) -> [u8; 32];
    /// How the key is held.
    fn custody(&self) -> Custody;
    /// A label for the record (the key file name, token object label, or sealed-key directory).
    fn label(&self) -> String;
    /// Signs `message`.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError>;
}

/// `sha2`, `ed25519-dalek`, and `blake3`: the one backend of every build.
pub mod rustcrypto {
    use super::{CrateVersion, CryptoBackend, Custody, RUSTCRYPTO_CRATES, Sha256Stream};
    use super::{SignError, Signer};
    use crate::keys::ed25519_seed_from_pkcs8_der;
    use sha2::Digest;

    /// The backend.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct RustCrypto;

    struct Stream(sha2::Sha256);

    impl Sha256Stream for Stream {
        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }
        fn finish(self: Box<Self>) -> [u8; 32] {
            self.0.finalize().into()
        }
    }

    impl CryptoBackend for RustCrypto {
        fn crates(&self) -> &'static [CrateVersion] {
            &RUSTCRYPTO_CRATES
        }
        fn sha256_stream(&self) -> Box<dyn Sha256Stream> {
            Box::new(Stream(sha2::Sha256::new()))
        }
        fn sha256_concat(&self, parts: &[&[u8]]) -> [u8; 32] {
            let mut h = sha2::Sha256::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().into()
        }
        fn ed25519_verify(
            &self,
            public_key: &[u8; 32],
            message: &[u8],
            signature: &[u8; 64],
        ) -> bool {
            let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
                return false;
            };
            key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
                .is_ok()
        }
    }

    /// A seed held in this process: an evaluation key file or the sandbox's in-memory key
    /// (custody `file-evaluation`), or a seed just unsealed from a TPM (custody `tpm-sealed`,
    /// [`FileKey::unsealed_from_tpm`]).
    pub struct FileKey {
        key: ed25519_dalek::SigningKey,
        label: String,
        custody: Custody,
    }

    impl std::fmt::Debug for FileKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FileKey")
                .field("label", &self.label)
                .finish_non_exhaustive()
        }
    }

    impl FileKey {
        /// A key from its 32-byte seed (RFC 8032 private key).
        pub fn from_seed(seed: &[u8; 32], label: &str) -> FileKey {
            FileKey {
                key: ed25519_dalek::SigningKey::from_bytes(seed),
                label: label.to_string(),
                custody: Custody::FileEvaluation,
            }
        }

        /// A seed that a TPM 2.0 has just unsealed (custody `tpm-sealed`): the seed rests sealed
        /// to that TPM and is in this process's memory for one signature. `ed25519-dalek`
        /// zeroizes it when the key is dropped.
        pub fn unsealed_from_tpm(seed: &[u8; 32], label: &str) -> FileKey {
            FileKey {
                custody: Custody::TpmSealed,
                ..FileKey::from_seed(seed, label)
            }
        }

        /// Loads an Ed25519 PKCS#8 private key (v1, or v2 with the public key; RFC 8410).
        pub fn from_pkcs8_der(der: &[u8], label: &str) -> Result<FileKey, SignError> {
            let (seed, public) = ed25519_seed_from_pkcs8_der(der).ok_or_else(|| {
                SignError("not an Ed25519 PKCS#8 private key (RFC 8410, v1 or v2)".into())
            })?;
            let key = FileKey::from_seed(&seed, label);
            if public.is_some_and(|p| p != key.public_key()) {
                return Err(SignError(
                    "the PKCS#8 key's public key does not match its private key".into(),
                ));
            }
            Ok(key)
        }
    }

    impl Signer for FileKey {
        fn public_key(&self) -> [u8; 32] {
            self.key.verifying_key().to_bytes()
        }
        fn custody(&self) -> Custody {
            self.custody
        }
        fn label(&self) -> String {
            self.label.clone()
        }
        fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
            use ed25519_dalek::Signer as _;
            Ok(self.key.sign(message).to_bytes())
        }
    }
}

/// Test-only backend so `cargo test -p sfr-core` needs no feature.
#[cfg(test)]
pub(crate) mod test_backend {
    use super::{CrateVersion, CryptoBackend, Custody, Sha256Stream, SignError, Signer};
    use sha2::Digest;

    pub(crate) struct TestBackend;
    struct Stream(sha2::Sha256);

    impl Sha256Stream for Stream {
        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }
        fn finish(self: Box<Self>) -> [u8; 32] {
            self.0.finalize().into()
        }
    }

    impl CryptoBackend for TestBackend {
        fn crates(&self) -> &'static [CrateVersion] {
            &[CrateVersion {
                name: "test",
                version: "0",
            }]
        }
        fn sha256_stream(&self) -> Box<dyn Sha256Stream> {
            Box::new(Stream(sha2::Sha256::new()))
        }
        fn ed25519_verify(
            &self,
            public_key: &[u8; 32],
            message: &[u8],
            signature: &[u8; 64],
        ) -> bool {
            let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
                return false;
            };
            key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
                .is_ok()
        }
    }

    /// A deterministic test key.
    pub(crate) struct TestKey(pub(crate) ed25519_dalek::SigningKey);

    impl TestKey {
        pub(crate) fn new(seed: u8) -> TestKey {
            TestKey(ed25519_dalek::SigningKey::from_bytes(&[seed; 32]))
        }
    }

    impl Signer for TestKey {
        fn public_key(&self) -> [u8; 32] {
            self.0.verifying_key().to_bytes()
        }
        fn custody(&self) -> Custody {
            Custody::FileEvaluation
        }
        fn label(&self) -> String {
            "test.key".into()
        }
        fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
            use ed25519_dalek::Signer as _;
            Ok(self.0.sign(message).to_bytes())
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::rustcrypto::{FileKey, RustCrypto};
    use super::*;
    use crate::hex;
    use crate::keys::hex_decode;

    #[test]
    fn sha256_matches_the_fips_180_4_example() {
        assert_eq!(
            hex(&RustCrypto.sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            RustCrypto.sha256_concat(&[b"a", b"", b"bc"]),
            RustCrypto.sha256(b"abc")
        );
        let mut s = RustCrypto.sha256_stream();
        s.update(b"ab");
        s.update(b"c");
        assert_eq!(s.finish(), RustCrypto.sha256(b"abc"));
    }

    #[test]
    fn ed25519_matches_rfc8032_section_7_1() {
        // TEST 1, TEST 2, TEST 3: secret key, public key, message, signature.
        let vectors: [(&str, &str, &str, &str); 3] = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (secret, public, message, signature) in vectors {
            let key = FileKey::from_seed(&hex_decode::<32>(secret).expect("hex"), "rfc8032");
            let message: Vec<u8> = (0..message.len() / 2)
                .map(|i| u8::from_str_radix(&message[2 * i..2 * i + 2], 16).expect("hex"))
                .collect();
            let signature = hex_decode::<64>(signature).expect("hex");
            assert_eq!(hex(&key.public_key()), public);
            assert_eq!(key.sign(&message).expect("signs"), signature);
            assert!(RustCrypto.ed25519_verify(&key.public_key(), &message, &signature));
            let mut bad = signature;
            bad[0] ^= 1;
            assert!(!RustCrypto.ed25519_verify(&key.public_key(), &message, &bad));
        }
    }

    #[test]
    fn a_pkcs8_key_file_loads_and_a_mismatched_public_key_is_refused() {
        // RFC 8410 section 10.3 example private key; its public key is the section 10.1 example.
        let seed =
            hex_decode::<32>("d4ee72dbf913584ad5b6d8f1f769f8ad3afe7c28cbf1d4fbe097a88f44755842")
                .expect("hex");
        let v1 = crate::keys::ed25519_pkcs8_v1_der(&seed);
        let key = FileKey::from_pkcs8_der(&v1, "sfr.key").expect("v1 loads");
        assert_eq!(
            hex(&key.public_key()),
            "19bf44096984cdfe8541bac167dc3b96c85086aa30b6b6cb0c5c38ad703166e1"
        );
        assert_eq!(key.label(), "sfr.key");
        assert_eq!(key.custody(), Custody::FileEvaluation);
        let mut v2 = vec![
            0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        v2.extend_from_slice(&seed);
        v2.extend_from_slice(&[0x81, 0x21, 0x00]);
        v2.extend_from_slice(&key.public_key());
        assert!(FileKey::from_pkcs8_der(&v2, "v2").is_ok());
        let last = v2.len() - 1;
        v2[last] ^= 1;
        let err = FileKey::from_pkcs8_der(&v2, "v2").expect_err("mismatch refused");
        assert!(err.0.contains("does not match"), "{err}");
        assert!(FileKey::from_pkcs8_der(b"junk", "x").is_err());
    }

    #[test]
    fn the_named_crate_versions_are_the_ones_in_cargo_lock() {
        let lock =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
                .expect("workspace Cargo.lock");
        for c in RUSTCRYPTO_CRATES {
            let entry = format!("name = \"{}\"\nversion = \"{}\"\n", c.name, c.version);
            assert!(lock.contains(&entry), "Cargo.lock has no {entry}");
        }
        let names: Vec<&str> = RUSTCRYPTO_CRATES.iter().map(|c| c.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "seal.crypto_crates is sorted by name");
        assert_eq!(RustCrypto.crates(), &RUSTCRYPTO_CRATES[..]);
    }
}
