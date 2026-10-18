//! Record sections as JSON values (SPEC B1.7): the sections `seal --dry-run` prints and that
//! `seal.rs` hashes as Merkle leaves and signs.

use crate::evaluate::Evaluation;
use crate::events::event_json;
use crate::hex;
use crate::ingest::{Config, Ingested, LogIdentity, SealedTopicDigest};
use crate::json::{Obj, Value};
use crate::params::Baseline;
use crate::rules::Rules;
use std::collections::BTreeMap;

/// `log`: file name, size, sha256, blake3, firmware, vehicle type.
pub fn log_json(id: &LogIdentity) -> Value {
    let fw = &id.firmware;
    let firmware = Obj::new()
        .field("version", Value::opt_str(fw.version.clone()))
        .field(
            "ver_sw_release",
            fw.release
                .map_or(Value::Null, |r| Value::str(format!("0x{r:08x}"))),
        )
        .field("git", Value::opt_str(fw.git.clone()))
        .build();
    let vehicle = Obj::new()
        .field(
            "system_type",
            id.vehicle
                .system_type
                .map_or(Value::Null, |t| Value::Int(i64::from(t))),
        )
        .field(
            "is_vtol",
            id.vehicle.is_vtol.map_or(Value::Null, Value::Bool),
        )
        .field(
            "vtol_type",
            id.vehicle.vtol_type.as_ref().map_or(Value::Null, |t| {
                Obj::new()
                    .field("name", Value::str(t.name.clone()))
                    .field(
                        "value",
                        t.value.map_or(Value::Null, |v| Value::Int(i64::from(v))),
                    )
                    .build()
            }),
        )
        .build();
    Obj::new()
        .field("file_name", Value::str(id.file_name.clone()))
        .field("size", Value::u64_str(id.size))
        .field("sha256", Value::str(hex(&id.sha256)))
        .field("blake3", Value::str(hex(&id.blake3)))
        .field("firmware", firmware)
        .field("vehicle", vehicle)
        .build()
}

fn param_map<'a>(params: impl Iterator<Item = (&'a String, &'a crate::ulog::ParamValue)>) -> Value {
    let map: BTreeMap<String, Value> = params
        .map(|(k, v)| (k.clone(), Value::str(v.to_string())))
        .collect();
    Value::Object(map)
}

/// `config`: firmware, the sorted parameter map at log start, and the names the rules file
/// watches (sorted).
pub fn config_json(c: &Config, rules: &Rules) -> Value {
    Obj::new()
        .field("firmware", Value::opt_str(c.firmware.clone()))
        .field("parameters", param_map(c.params.iter()))
        .field(
            "watched_parameters",
            Value::Array(
                rules
                    .watched
                    .iter()
                    .map(|n| Value::str(n.clone()))
                    .collect(),
            ),
        )
        .build()
}

/// One `sealed_topics` entry (SPEC B1.5, B1.7).
pub fn sealed_topic_json(d: &SealedTopicDigest) -> Value {
    Obj::new()
        .field("topic", Value::str(d.topic.clone()))
        .field("multi_id", Value::Int(i64::from(d.multi_id)))
        .field("format_sha256", Value::str(hex(&d.format_sha256)))
        .field("message_count", Value::count(d.message_count))
        .field(
            "first_timestamp_us",
            d.first_timestamp_us.map_or(Value::Null, Value::u64_str),
        )
        .field(
            "last_timestamp_us",
            d.last_timestamp_us.map_or(Value::Null, Value::u64_str),
        )
        .field("data_sha256", Value::str(hex(&d.data_sha256)))
        .build()
}

/// `sealed_topics`, sorted by topic, then instance.
pub fn sealed_topics_json(ing: &Ingested) -> Value {
    Value::Array(ing.sealed_topics.iter().map(sealed_topic_json).collect())
}

/// `events`, in sequence order.
pub fn events_json(ing: &Ingested, rules: &Rules) -> Value {
    let fw = &ing.identity.firmware;
    Value::Array(
        ing.events
            .iter()
            .map(|e| event_json(e, fw, rules))
            .collect(),
    )
}

/// `baseline`: firmware, parameter map, ignore list.
pub fn baseline_json(b: &Baseline, rules: &Rules) -> Value {
    Obj::new()
        .field("firmware", Value::str(b.firmware.to_string()))
        .field("parameters", param_map(b.params.iter()))
        .field(
            "ignore",
            Value::Array(
                rules
                    .ignore
                    .iter()
                    .map(|p| Value::str(p.as_str()))
                    .collect(),
            ),
        )
        .build()
}

/// The `seal --dry-run --json` document: everything the record will hold except the seal
/// context, Merkle tree and signature.
pub fn dry_run_json(
    ing: &Ingested,
    eval: &Evaluation,
    rules: &Rules,
    baseline: &Baseline,
    rules_sha256: &[u8; 32],
) -> Value {
    Obj::new()
        .field("log", log_json(&ing.identity))
        .field("config", config_json(&ing.config, rules))
        .field("baseline", baseline_json(baseline, rules))
        .field(
            "rules",
            Obj::new()
                .field("text", Value::str(rules.text.clone()))
                .field("sha256", Value::str(hex(rules_sha256)))
                .build(),
        )
        .field(
            "results",
            Value::Array(eval.results.iter().map(|r| r.to_json()).collect()),
        )
        .field("sealed_topics", sealed_topics_json(ing))
        .field("events", events_json(ing, rules))
        .field("event_count", Value::count(ing.events.len() as u64))
        .field("status", Value::str(eval.status.as_str()))
        .build()
}
