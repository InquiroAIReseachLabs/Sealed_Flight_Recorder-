//! Cryptographic backends (SPEC B1.2, B1.10 Crypto).
//!
//! Code selects a backend by type, never by default. The `sfr` CLI uses [`fips::Fips`] (the
//! AWS-LC FIPS module through aws-lc-rs); the browser sandbox uses [`portable::Portable`] (not
//! validated). Both may be compiled together under workspace feature unification; nothing in
//! this crate picks one implicitly.

use std::fmt;

/// An incremental SHA-256 computation.
pub trait Sha256Stream {
    /// Feeds more bytes.
    fn update(&mut self, data: &[u8]);
    /// Consumes the stream and returns the 32-byte digest.
    fn finish(self: Box<Self>) -> [u8; 32];
}

/// What a record names as its cryptographic module (SPEC B1.10 Crypto: the build profile, the
/// module version string, and the CMVP certificate number or none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleInfo {
    /// `development`, `validated`, or `portable`.
    pub profile: &'static str,
    /// The module's own version string.
    pub module: String,
    /// CMVP certificate number; only a validated-profile build may name one.
    pub certificate: Option<&'static str>,
}

/// What the engine needs from a cryptographic module.
pub trait CryptoBackend {
    /// One line naming the module, for messages and `sfr --version`.
    fn module_id(&self) -> &'static str;
    /// The record's `seal.crypto_module`.
    fn module_info(&self) -> ModuleInfo;
    /// Starts an incremental SHA-256 (FIPS 180-4).
    fn sha256_stream(&self) -> Box<dyn Sha256Stream>;
    /// Verifies an Ed25519 signature (FIPS 186-5 EdDSA).
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

/// The AWS-LC FIPS module through aws-lc-rs (`crypto-fips` feature).
#[cfg(feature = "crypto-fips")]
pub mod fips {
    use super::{CryptoBackend, Custody, ModuleInfo, Sha256Stream, SignError, Signer};
    use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
    use zeroize::Zeroizing;

    /// Handle to the module after its FIPS-mode check. The module's power-on self-tests run
    /// in a constructor before `main` and abort the process on failure, so a running `sfr`
    /// has passed them. The FIPS-mode check reports that the module was built with FIPS mode on.
    #[derive(Debug)]
    pub struct Fips {
        _private: (),
    }

    /// The module reported that it is not in approved mode (SPEC B1.4: exit 4).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct NotApprovedMode(pub String);

    impl std::fmt::Display for NotApprovedMode {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "the AWS-LC FIPS module is not in approved mode: {}",
                self.0
            )
        }
    }

    impl Fips {
        /// Checks FIPS mode before any other work (SPEC B1.10 Crypto). A failed power-on
        /// self-test aborts the process inside the module, so this only returns on success or
        /// on a module that runs but is not in approved mode.
        pub fn new() -> Result<Self, NotApprovedMode> {
            aws_lc_rs::try_fips_mode().map_err(|e| NotApprovedMode(e.to_string()))?;
            Ok(Fips { _private: () })
        }

        /// Generates an Ed25519 key pair from the module's DRBG. Returns the PKCS#8 v1 DER
        /// private key (the form `openssl pkey` reads; zeroized on drop) and the raw public key.
        pub fn generate_ed25519(&self) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), SignError> {
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let doc = Ed25519KeyPair::generate_pkcs8v1(&rng)
                .map_err(|_| SignError("the FIPS module could not generate a key".into()))?;
            let der = Zeroizing::new(doc.as_ref().to_vec());
            let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(&der)
                .map_err(|e| SignError(format!("generated key rejected: {e}")))?;
            let public = raw_public(&pair)?;
            Ok((der, public))
        }
    }

    fn raw_public(pair: &Ed25519KeyPair) -> Result<[u8; 32], SignError> {
        pair.public_key()
            .as_ref()
            .try_into()
            .map_err(|_| SignError("Ed25519 public key is not 32 bytes".into()))
    }

    /// The module version string from the linked module's headers, without the trailing NUL.
    fn version_string() -> String {
        let raw: &[u8] = aws_lc_fips_sys::AWSLC_VERSION_STRING;
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(raw.get(..end).unwrap_or(raw)).into_owned()
    }

    struct Stream(aws_lc_rs::digest::Context);

    impl Sha256Stream for Stream {
        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }
        fn finish(self: Box<Self>) -> [u8; 32] {
            let digest = self.0.finish();
            let mut out = [0u8; 32];
            out.copy_from_slice(digest.as_ref());
            out
        }
    }

    impl CryptoBackend for Fips {
        fn module_id(&self) -> &'static str {
            "aws-lc-rs fips (AWS-LC FIPS module, development profile)"
        }
        fn module_info(&self) -> ModuleInfo {
            // The validated profile (SPEC B1.10) is selected by the release build in Chunk 5;
            // every other build is the development profile and names no certificate.
            ModuleInfo {
                profile: "development",
                module: version_string(),
                certificate: None,
            }
        }
        fn sha256_stream(&self) -> Box<dyn Sha256Stream> {
            Box::new(Stream(aws_lc_rs::digest::Context::new(
                &aws_lc_rs::digest::SHA256,
            )))
        }
        fn sha256_concat(&self, parts: &[&[u8]]) -> [u8; 32] {
            // One-shot digests are measurably faster than a context per small Merkle input.
            let digest = if let [one] = parts {
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, one)
            } else {
                let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
                for p in parts {
                    buf.extend_from_slice(p);
                }
                aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &buf)
            };
            let mut out = [0u8; 32];
            out.copy_from_slice(digest.as_ref());
            out
        }
        fn ed25519_verify(
            &self,
            public_key: &[u8; 32],
            message: &[u8],
            signature: &[u8; 64],
        ) -> bool {
            UnparsedPublicKey::new(&ED25519, public_key)
                .verify(message, signature)
                .is_ok()
        }
    }

    /// An evaluation key file (custody `file-evaluation`).
    #[derive(Debug)]
    pub struct FileKey {
        pair: Ed25519KeyPair,
        label: String,
    }

    impl FileKey {
        /// Loads a PKCS#8 (v1 or v2) Ed25519 private key.
        pub fn from_pkcs8_der(der: &[u8], label: &str) -> Result<FileKey, SignError> {
            let pair = Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
                .map_err(|e| SignError(format!("not an Ed25519 PKCS#8 private key: {e}")))?;
            Ok(FileKey {
                pair,
                label: label.to_string(),
            })
        }
    }

    impl Signer for FileKey {
        fn public_key(&self) -> [u8; 32] {
            raw_public(&self.pair).unwrap_or([0; 32])
        }
        fn custody(&self) -> Custody {
            Custody::FileEvaluation
        }
        fn label(&self) -> String {
            self.label.clone()
        }
        fn sign(&self, message: &[u8]) -> Result<[u8; 64], SignError> {
            self.pair
                .sign(message)
                .as_ref()
                .try_into()
                .map_err(|_| SignError("Ed25519 signature is not 64 bytes".into()))
        }
    }
}

/// Portable pure-Rust backend for the wasm32 sandbox (`crypto-portable` feature). Not validated.
#[cfg(feature = "crypto-portable")]
pub mod portable {
    use super::{CryptoBackend, Custody, ModuleInfo, Sha256Stream, SignError, Signer};
    use sha2::Digest;

    /// The not-validated portable backend.
    #[derive(Debug, Default)]
    pub struct Portable;

    struct Stream(sha2::Sha256);

    impl Sha256Stream for Stream {
        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }
        fn finish(self: Box<Self>) -> [u8; 32] {
            self.0.finalize().into()
        }
    }

    impl CryptoBackend for Portable {
        fn module_id(&self) -> &'static str {
            "portable (sha2, ed25519-dalek; not validated)"
        }
        fn module_info(&self) -> ModuleInfo {
            ModuleInfo {
                profile: "portable",
                module: "sha2 and ed25519-dalek (not validated)".into(),
                certificate: None,
            }
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

    /// An in-memory evaluation key (the sandbox's ephemeral key).
    pub struct SeedKey {
        key: ed25519_dalek::SigningKey,
        label: String,
    }

    impl SeedKey {
        /// A key from a 32-byte seed.
        pub fn from_seed(seed: &[u8; 32], label: &str) -> SeedKey {
            SeedKey {
                key: ed25519_dalek::SigningKey::from_bytes(seed),
                label: label.to_string(),
            }
        }
    }

    impl Signer for SeedKey {
        fn public_key(&self) -> [u8; 32] {
            self.key.verifying_key().to_bytes()
        }
        fn custody(&self) -> Custody {
            Custody::FileEvaluation
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
    use super::{CryptoBackend, Custody, ModuleInfo, Sha256Stream, SignError, Signer};
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
        fn module_id(&self) -> &'static str {
            "test"
        }
        fn module_info(&self) -> ModuleInfo {
            ModuleInfo {
                profile: "test",
                module: "test".into(),
                certificate: None,
            }
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
