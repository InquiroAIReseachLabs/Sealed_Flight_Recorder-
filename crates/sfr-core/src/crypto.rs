//! Cryptographic backends (SPEC B1.2, B1.10 Crypto).
//!
//! Code selects a backend by type, never by default. The `sfr` CLI uses [`fips::Fips`] (the
//! AWS-LC FIPS module through aws-lc-rs); the browser sandbox uses [`portable::Portable`] (not
//! validated). Both may be compiled together under workspace feature unification; nothing in
//! this crate picks one implicitly.

/// An incremental SHA-256 computation.
pub trait Sha256Stream {
    /// Feeds more bytes.
    fn update(&mut self, data: &[u8]);
    /// Consumes the stream and returns the 32-byte digest.
    fn finish(self: Box<Self>) -> [u8; 32];
}

/// What the engine needs from a cryptographic module.
pub trait CryptoBackend {
    /// Names the module for the record's `seal.crypto_module` field and for `sfr --version`.
    fn module_id(&self) -> &'static str;
    /// Starts an incremental SHA-256 (FIPS 180-4).
    fn sha256_stream(&self) -> Box<dyn Sha256Stream>;
}

/// The AWS-LC FIPS module through aws-lc-rs (`crypto-fips` feature).
#[cfg(feature = "crypto-fips")]
pub mod fips {
    use super::{CryptoBackend, Sha256Stream};

    /// Handle proving the module passed its power-on self-tests and runs in approved mode.
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
        fn sha256_stream(&self) -> Box<dyn Sha256Stream> {
            Box::new(Stream(aws_lc_rs::digest::Context::new(
                &aws_lc_rs::digest::SHA256,
            )))
        }
    }
}

/// Portable pure-Rust backend for the wasm32 sandbox (`crypto-portable` feature). Not validated.
#[cfg(feature = "crypto-portable")]
pub mod portable {
    use super::{CryptoBackend, Sha256Stream};
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
        fn sha256_stream(&self) -> Box<dyn Sha256Stream> {
            Box::new(Stream(sha2::Sha256::new()))
        }
    }
}

/// Test-only backend so `cargo test -p sfr-core` needs no feature.
#[cfg(test)]
pub(crate) mod test_backend {
    use super::{CryptoBackend, Sha256Stream};
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
        fn sha256_stream(&self) -> Box<dyn Sha256Stream> {
            Box::new(Stream(sha2::Sha256::new()))
        }
    }
}
