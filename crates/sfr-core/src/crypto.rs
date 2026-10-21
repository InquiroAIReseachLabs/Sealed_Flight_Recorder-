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
    /// Called as soon as the one signature of a run is made: a signer that holds a secret in
    /// this process clears it, and signs no more.
    fn wipe(&self) {}
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

    /// A seed held in this process: an evaluation key file
    /// (custody `file-evaluation`), or a seed just unsealed from a TPM (custody `tpm-sealed`,
    /// [`FileKey::unsealed_from_tpm`]).
    pub struct FileKey {
        /// The seed; cleared by [`Signer::wipe`]. A signing key is made from it for each
        /// signature and dropped (zeroized) with it.
        seed: std::sync::Mutex<zeroize::Zeroizing<[u8; 32]>>,
        public: [u8; 32],
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
                seed: std::sync::Mutex::new(zeroize::Zeroizing::new(*seed)),
                public: ed25519_dalek::SigningKey::from_bytes(seed)
                    .verifying_key()
                    .to_bytes(),
                label: label.to_string(),
                custody: Custody::FileEvaluation,
            }
        }

        /// A seed that a TPM 2.0 has just unsealed (custody `tpm-sealed`): the seed rests sealed
        /// to that TPM and is in this process's memory until the one signature is made
        /// ([`Signer::wipe`]).
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
            self.public
        }
        fn custody(&self) -> Custody {
            self.custody
        }
        fn label(&self) -> String {
            self.label.clone()
        }
        fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
            use ed25519_dalek::Signer as _;
            let seed = self
                .seed
                .lock()
                .map_err(|_| SignError("the signing key is not available".into()))?;
            if seed.iter().all(|b| *b == 0) {
                return Err(SignError(
                    "the signing key was cleared after its signature".into(),
                ));
            }
            // Dropped, and so zeroized by ed25519-dalek, when this call returns.
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            Ok(key.sign(message).to_bytes())
        }
        fn wipe(&self) {
            use zeroize::Zeroize as _;
            if let Ok(mut seed) = self.seed.lock() {
                seed.zeroize();
            }
        }
    }

    #[cfg(test)]
    #[allow(clippy::expect_used)]
    impl FileKey {
        /// The seed bytes held now.
        pub(crate) fn seed_bytes(&self) -> [u8; 32] {
            **self.seed.lock().expect("seed lock")
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
    pub(crate) struct TestKey(
        pub(crate) ed25519_dalek::SigningKey,
        pub(crate) std::cell::Cell<bool>,
    );

    impl TestKey {
        pub(crate) fn new(seed: u8) -> TestKey {
            TestKey(
                ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
                std::cell::Cell::new(false),
            )
        }
        /// Whether [`Signer::wipe`] has been called.
        pub(crate) fn wiped(&self) -> bool {
            self.1.get()
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
        fn wipe(&self) {
            self.1.set(true);
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
        // TEST 1, TEST 2, TEST 3, TEST 1024 and TEST SHA(abc): secret key, public key, message, signature.
        let vectors: [(&str, &str, &str, &str); 5] = [
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
            // TEST 1024: a 1023-byte message.
            (
                "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
                "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
                concat!(
                    "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355",
                    "f6c50544e23fb1433ddf73be84d879de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc",
                    "6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b",
                    "199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e06203b33890cc9b8",
                    "32f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d",
                    "206be6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d9562",
                    "9e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40",
                    "cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c65adb7553",
                    "878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b0707e0",
                    "917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26",
                    "401d2e22f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3",
                    "dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb751fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301",
                    "651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb3d1f",
                    "92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401ade",
                    "bf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab4",
                    "7b57f7f7276cd419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3",
                    "2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb37",
                    "97aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba7",
                    "7c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315c",
                    "f4fde7cb68606937380db2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef",
                    "68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
                ),
                "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
            ),
            // TEST SHA(abc): the message is SHA-512("abc").
            (
                "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
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
    fn wipe_clears_the_seed_and_no_more_signatures_are_made() {
        let key = FileKey::from_seed(&[7u8; 32], "k");
        let public = key.public_key();
        assert_eq!(key.seed_bytes(), [7u8; 32]);
        let signature = key.sign(b"m").expect("signs before the wipe");
        assert!(RustCrypto.ed25519_verify(&public, b"m", &signature));
        key.wipe();
        assert_eq!(key.seed_bytes(), [0u8; 32], "the seed buffer is cleared");
        assert!(key.sign(b"m").is_err());
        assert_eq!(key.public_key(), public);
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
