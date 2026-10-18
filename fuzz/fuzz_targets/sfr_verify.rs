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
use sfr_core::crypto::CryptoBackend;
use sfr_core::crypto::rustcrypto::RustCrypto;
use sfr_core::verify::verify;
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
        &include_bytes!("../seeds/sfr_verify/sitl_v1.17.0_gz_x500_vision_hover_shrunk.sfr")[..],
        &include_bytes!("../seeds/sfr_verify/synthetic_custom_detection.sfr")[..],
    ]
    .iter()
    .map(|s| RustCrypto.sha256(s))
    .collect()
});

fuzz_target!(|data: &[u8]| {
    if verify(data, None, &RustCrypto, &KEY, false).is_ok() {
        assert!(SEEDS.contains(&RustCrypto.sha256(data)), "a record other than a seed verified");
    }
});
