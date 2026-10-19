//! Fuzz target: arbitrary text through the rules file parser, then through everything that
//! reads a rules file.
//!
//! UTF-8 input goes to `sfr_core::rules::parse_rules`, which reads every section a rules file
//! may hold, the optional sections `[watched_parameters]`, `[sealed_topics]`,
//! `[payload_commands]` and `[authorized_sources]` included. A file that parses is then used to
//! ingest a fixed log (the shrunk payload flight, which has commands from several sources),
//! evaluate it, and build the dry-run JSON document, so the fuzzed sections reach the code that
//! uses them. The seeds are the shipped example rules and the golden logs' rules files. Any
//! panic, hang, or out-of-memory is a finding.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sfr_core::crypto::CryptoBackend;
use sfr_core::crypto::rustcrypto::RustCrypto;
use sfr_core::evaluate::evaluate;
use sfr_core::ingest::{FlightLogIngestor, Px4Ingestor};
use sfr_core::json::canonical;
use sfr_core::params::{Baseline, parse_baseline};
use sfr_core::record::dry_run_json;
use sfr_core::rules::{MAX_SEALED_TOPICS, parse_rules};
use std::sync::LazyLock;

const LOG: &[u8] =
    include_bytes!("../seeds/ulog_ingest/sitl_v1.17.0_payload_two_sources_shrunk.ulg");
const BASELINE_TEXT: &str =
    include_str!("../../testdata/baselines/v1.17.0_payload_two_sources.params");

static BASELINE: LazyLock<Baseline> =
    LazyLock::new(|| parse_baseline(BASELINE_TEXT).expect("the golden baseline parses"));

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(rules) = parse_rules(text) else {
        return;
    };

    // Properties the parser documents: lists are sorted and have no duplicate, and the sealed
    // topic limit holds.
    assert!(
        rules.sealed_topics.len() <= MAX_SEALED_TOPICS,
        "sealed topic limit"
    );
    assert!(
        rules.sealed_topics.windows(2).all(|w| w[0] < w[1]),
        "sealed topics sorted"
    );
    assert!(
        rules.watched.windows(2).all(|w| w[0] < w[1]),
        "watched parameters sorted"
    );
    let r1 = rules.r1_topics();
    let unique: std::collections::BTreeSet<&String> = r1.iter().collect();
    assert_eq!(unique.len(), r1.len(), "R1 topics listed once");
    assert!(
        rules.sealed_topics.iter().all(|t| r1.contains(t)),
        "every sealed topic is required"
    );

    let mut input: &[u8] = LOG;
    let ingested = Px4Ingestor
        .ingest_sealing("fuzz.ulg", &mut input, &RustCrypto, &rules.sealed_topics)
        .expect("the seed log ingests with any sealed topic list");
    let eval = evaluate(&ingested, &rules, &BASELINE);
    let doc = dry_run_json(
        &ingested,
        &eval,
        &rules,
        &BASELINE,
        &RustCrypto.sha256(text.as_bytes()),
    );
    let out = canonical(&doc);
    assert!(
        out.starts_with('{') && out.ends_with('}'),
        "canonical JSON object"
    );
});
