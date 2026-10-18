//! Fuzz target: arbitrary bytes through the whole `seal --dry-run` path.
//!
//! Bytes go to `Px4Ingestor::ingest` (ULog reader, hashing, decoding, event timeline). When the
//! log is readable, the result is evaluated against `examples/rules.extended.toml` (core rules
//! plus every optional rule), turned into the dry-run JSON document, and written as canonical
//! JSON. Any panic, hang, or out-of-memory on the way is a finding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sfr_core::crypto::{CryptoBackend, Sha256Stream};
use sfr_core::evaluate::evaluate;
use sfr_core::ingest::{FlightLogIngestor, Px4Ingestor};
use sfr_core::json::canonical;
use sfr_core::params::{Baseline, parse_baseline};
use sfr_core::record::dry_run_json;
use sfr_core::rules::{Rules, parse_rules};
use sha2::Digest;
use std::sync::LazyLock;

const RULES_TEXT: &str = include_str!("../../examples/rules.extended.toml");
const BASELINE_TEXT: &str = "# Firmware: 1.17.0\n";

/// Fuzz-only SHA-256 backend (pure Rust, not the FIPS module).
struct FuzzBackend;

struct FuzzSha256(sha2::Sha256);

impl Sha256Stream for FuzzSha256 {
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finish(self: Box<Self>) -> [u8; 32] {
        self.0.finalize().into()
    }
}

impl CryptoBackend for FuzzBackend {
    fn module_id(&self) -> &'static str {
        "fuzz (sha2; not validated)"
    }
    fn sha256_stream(&self) -> Box<dyn Sha256Stream> {
        Box::new(FuzzSha256(sha2::Sha256::new()))
    }
}

static RULES: LazyLock<Rules> =
    LazyLock::new(|| parse_rules(RULES_TEXT).expect("examples/rules.extended.toml must parse"));
static BASELINE: LazyLock<Baseline> =
    LazyLock::new(|| parse_baseline(BASELINE_TEXT).expect("the fuzz baseline must parse"));
static RULES_SHA256: LazyLock<[u8; 32]> = LazyLock::new(|| sha2::Sha256::digest(RULES_TEXT.as_bytes()).into());

fuzz_target!(|data: &[u8]| {
    let mut input: &[u8] = data;
    let Ok(ingested) = Px4Ingestor.ingest("fuzz.ulg", &mut input, &FuzzBackend) else {
        return;
    };

    // Properties the ingest path documents: every byte is counted, and on success the reader
    // consumed the whole stream; events are numbered from 0 in timeline order.
    assert_eq!(ingested.identity.size, data.len() as u64, "LogIdentity.size");
    assert_eq!(ingested.flight.summary.bytes, data.len() as u64, "Summary.bytes on success");
    for (i, e) in ingested.events.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "event seq");
    }

    let eval = evaluate(&ingested, &RULES, &BASELINE);
    let doc = dry_run_json(&ingested, &eval, &RULES, &BASELINE, &RULES_SHA256);
    let text = canonical(&doc);
    assert!(text.starts_with('{') && text.ends_with('}'), "canonical JSON object");
});
