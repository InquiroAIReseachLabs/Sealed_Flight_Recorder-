//! Fuzz target: arbitrary bytes through the whole `seal --dry-run` path.
//!
//! Bytes go to `Px4Ingestor::ingest_sealing` (ULog reader, hashing, decoding, sealed topic
//! digests, event timeline). When the log is readable, the result is evaluated against
//! `examples/rules.extended.toml` plus the sections it only shows commented out (R7's
//! `[authorized_sources]` and `[sealed_topics]`), so every rule and every rules file section
//! runs, then turned into the dry-run JSON document and written as canonical JSON. Any panic,
//! hang, or out-of-memory on the way is a finding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sfr_core::crypto::CryptoBackend;
use sfr_core::crypto::rustcrypto::RustCrypto;
use sfr_core::evaluate::evaluate;
use sfr_core::ingest::{FlightLogIngestor, Px4Ingestor};
use sfr_core::json::canonical;
use sfr_core::params::{Baseline, parse_baseline};
use sfr_core::record::dry_run_json;
use sfr_core::rules::{Rules, parse_rules};
use std::sync::LazyLock;

const RULES_TEXT: &str = concat!(
    include_str!("../../examples/rules.extended.toml"),
    "\n[authorized_sources]\ncategory = \"PAYLOAD\"\n",
    "sources = [{ system = 1, component = 1 }, { system = 255, component = 190 }]\n",
    "\n[sealed_topics]\n",
    "topics = [\"vehicle_status\", \"vehicle_command\", \"battery_status\", \"sensor_combined\", ",
    "\"vehicle_visual_odometry\", \"custom_detection\"]\n",
);
const BASELINE_TEXT: &str = "# Firmware: 1.17.0\n";

static RULES: LazyLock<Rules> =
    LazyLock::new(|| parse_rules(RULES_TEXT).expect("the fuzz rules must parse"));
static BASELINE: LazyLock<Baseline> =
    LazyLock::new(|| parse_baseline(BASELINE_TEXT).expect("the fuzz baseline must parse"));
static RULES_SHA256: LazyLock<[u8; 32]> = LazyLock::new(|| RustCrypto.sha256(RULES_TEXT.as_bytes()));

fuzz_target!(|data: &[u8]| {
    let mut input: &[u8] = data;
    let Ok(ingested) =
        Px4Ingestor.ingest_sealing("fuzz.ulg", &mut input, &RustCrypto, &RULES.sealed_topics)
    else {
        return;
    };

    // Properties the ingest path documents: every byte is counted, and on success the reader
    // consumed the whole stream; events are numbered from 0 in timeline order.
    assert_eq!(ingested.identity.size, data.len() as u64, "LogIdentity.size");
    assert_eq!(ingested.flight.summary.bytes, data.len() as u64, "Summary.bytes on success");
    for (i, e) in ingested.events.iter().enumerate() {
        assert_eq!(e.seq, i as u64, "event seq");
    }
    // Sealed topic digests: only listed topics, sorted, and no instance counted twice.
    let keys: Vec<(&str, u8)> = ingested
        .sealed_topics
        .iter()
        .map(|d| (d.topic.as_str(), d.multi_id))
        .collect();
    assert!(keys.windows(2).all(|w| w[0] < w[1]), "sealed topics sorted and unique");
    assert!(
        ingested
            .sealed_topics
            .iter()
            .all(|d| RULES.sealed_topics.contains(&d.topic)),
        "only listed topics are sealed"
    );

    let eval = evaluate(&ingested, &RULES, &BASELINE);
    let doc = dry_run_json(&ingested, &eval, &RULES, &BASELINE, &RULES_SHA256);
    let text = canonical(&doc);
    assert!(text.starts_with('{') && text.ends_with('}'), "canonical JSON object");
});
