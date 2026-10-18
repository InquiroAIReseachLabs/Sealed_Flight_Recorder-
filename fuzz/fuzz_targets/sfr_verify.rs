//! Fuzz target: arbitrary bytes through the `.sfr` reader (`verify` standalone).
//!
//! Bytes go to `sfr_core::verify::verify` without a log: the canonical-form scan, the schema
//! checks, the Merkle tree over byte ranges, and Ed25519 verification. The seeds in
//! `fuzz/seeds/sfr_verify/` are real records signed by the evaluation key whose public half is
//! `fuzz/seeds/sfr_verify_key.pub` (its private half was discarded), so mutations of them reach
//! the signature path. A panic, hang, or out-of-memory is a finding; a valid result for a
//! mutated record would be one too, and the target asserts that only the seeds verify.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sfr_core::crypto::{CryptoBackend, ModuleInfo, Sha256Stream};
use sfr_core::verify::verify;
use sha2::Digest;
use std::sync::LazyLock;

/// The raw key inside `fuzz/seeds/sfr_verify_key.pub`.
static KEY: LazyLock<[u8; 32]> = LazyLock::new(|| {
    sfr_core::keys::parse_public_key_pem(include_str!("../seeds/sfr_verify_key.pub"))
        .expect("the fuzz public key parses")
});

/// SHA-256 of each seed: the only inputs allowed to verify.
static SEEDS: LazyLock<Vec<[u8; 32]>> = LazyLock::new(|| {
    [
        &include_bytes!("../seeds/sfr_verify/pyulog_sample_first_65516.sfr")[..],
        &include_bytes!("../seeds/sfr_verify/sitl_v1.17.0_failsafe_gps_loss_shrunk.sfr")[..],
        &include_bytes!("../seeds/sfr_verify/sitl_v1.17.0_vtol_transition_abort_shrunk.sfr")[..],
    ]
    .iter()
    .map(|s| sha2::Sha256::digest(s).into())
    .collect()
});

/// Fuzz-only backend (pure Rust, not the FIPS module).
struct FuzzBackend;

struct Stream(sha2::Sha256);

impl Sha256Stream for Stream {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finish(self: Box<Self>) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl CryptoBackend for FuzzBackend {
    fn module_id(&self) -> &'static str {
        "fuzz (sha2, ed25519-dalek; not validated)"
    }
    fn module_info(&self) -> ModuleInfo {
        ModuleInfo { profile: "fuzz", module: "sha2 and ed25519-dalek".into(), certificate: None }
    }
    fn sha256_stream(&self) -> Box<dyn Sha256Stream> {
        Box::new(Stream(sha2::Sha256::new()))
    }
    fn ed25519_verify(&self, public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature)).is_ok()
    }
}

fuzz_target!(|data: &[u8]| {
    if verify(data, None, &FuzzBackend, &KEY, false).is_ok() {
        let digest: [u8; 32] = sha2::Sha256::digest(data).into();
        assert!(SEEDS.contains(&digest), "a record other than a seed verified");
    }
});
