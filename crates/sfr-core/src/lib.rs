//! Sealed Flight Record engine (SPEC B1.2, `crates/sfr-core`).
//!
//! Ingest, events, and rules and the record, Merkle tree, signing, and verification live here. The engine performs no I/O beyond reading byte streams handed to it,
//! has no networking, and contains no `unsafe` code.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod display;
pub mod evaluate;
pub mod events;
pub mod ingest;
pub mod json;
pub mod keys;
pub mod merkle;
pub mod params;
pub mod pkcs11_uri;
pub mod px4;
// Written by scripts/px4/px4_tables.py, which checks it byte for byte: not formatted.
#[rustfmt::skip]
pub mod px4_tables;
pub mod record;
pub mod report;
pub mod rules;
pub mod seal;
pub mod ulog;
pub mod verify;

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The message for an input over one of the SPEC B1.4 input limits: it names the limit.
pub fn limit_exceeded(subject: &str, limit: impl std::fmt::Display, unit: &str) -> String {
    format!("{subject} exceeds the input limit of {limit} {unit} (SPEC B1.4)")
}

/// Name of the tool and of its binary (SPEC B1.1).
pub const TOOL_NAME: &str = "sfr";

/// Record file extension (SPEC B1.1).
pub const RECORD_EXTENSION: &str = "sfr";

/// Record schema version `seal` writes (SPEC B1.7). Schema 1 was the first; schema 2 added
/// `seal.allow_untested_version`; schema 3 signs the shape of the tree (its size and the number
/// of leaves in each section) and tags every leaf with its section, and drops
/// `seal.token_cmvp_certificate`. A verifier must reject any version it does not know and must
/// never guess; this one knows [`KNOWN_SCHEMA_VERSIONS`], which is schema 3 only: a schema 1 or
/// 2 record has leaves that are not bound to their section, so it is refused, not accepted
/// beside the new form. Schema 4 adds the WARN result status, the overall statuses WARN and
/// NO ARMED FLIGHT, `log.vehicle_status_instances`, `log.skipped`, `baseline.sha256` and
/// `seal.allow_ignore_all`; a schema 3 record is refused, as its results were computed under
/// rules that read less of the log. Schema 5 ([`SCHEMA_VERSION_5`]) is schema 4 plus
/// `log.truncated`, `log.ulog_version` and `seal.allow_untested_ulog_version`; `seal` writes it
/// only for a log that ends in the middle of a record or has a ULog file format version above 1,
/// and schema 4, byte for byte as before, for every other log.
pub const SCHEMA_VERSION: u32 = 4;

/// The schema `seal` writes for a log that ends in the middle of a record or whose ULog file
/// format version is above 1 (SPEC B1.7): what a schema 4 record cannot state.
pub const SCHEMA_VERSION_5: u32 = 5;

/// The schema versions `verify` accepts.
pub const KNOWN_SCHEMA_VERSIONS: [u32; 2] = [4, 5];

/// The PX4 versions `sfr` is tested on, as (major, minor) series, inclusive: v1.14 to v1.17.
/// `seal` refuses a log outside them, or one whose version it cannot read, unless given
/// `--allow-untested-version` (SPEC B1.5).
pub const TESTED_PX4_SERIES: ((u8, u8), (u8, u8)) = ((1, 14), (1, 17));

/// Domain-separation prefix of the signed payload (SPEC B1.7).
pub const SIGNED_PAYLOAD_PREFIX: &[u8] = b"SFR-RECORD-V1";

/// Domain-separation byte prepended to a Merkle leaf before hashing (SPEC B1.7).
pub const MERKLE_LEAF_PREFIX: u8 = 0x00;

/// Domain-separation byte prepended to a Merkle interior node before hashing (SPEC B1.7).
pub const MERKLE_NODE_PREFIX: u8 = 0x01;

/// Process exit codes (SPEC B1.4).
pub mod exit_code {
    /// Seal: all rules PASS or N/A. Verify: VERIFIED.
    pub const OK: i32 = 0;
    /// Seal: one or more rules FAIL (record still written). Verify: verification failed.
    pub const RULE_FAIL: i32 = 1;
    /// Required topic missing from the log (record written with status FAIL).
    pub const MISSING_TOPIC: i32 = 2;
    /// Malformed or truncated input file.
    pub const MALFORMED_INPUT: i32 = 3;
    /// Usage, key, or file I/O error.
    pub const USAGE: i32 = 4;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_versions_four_and_five_verify() {
        assert_eq!(SCHEMA_VERSION, 4, "SPEC B1.7: schema 4");
        assert_eq!(SCHEMA_VERSION_5, 5, "SPEC B1.7: schema 5");
        assert_eq!(KNOWN_SCHEMA_VERSIONS, [4, 5]);
    }

    #[test]
    fn domain_separation_bytes_are_distinct() {
        assert_ne!(
            MERKLE_LEAF_PREFIX, MERKLE_NODE_PREFIX,
            "SPEC B1.7: leaf and node prefixes must differ"
        );
        assert_eq!(SIGNED_PAYLOAD_PREFIX, b"SFR-RECORD-V1");
    }

    #[test]
    fn exit_codes_match_spec_table() {
        assert_eq!(exit_code::OK, 0);
        assert_eq!(exit_code::RULE_FAIL, 1);
        assert_eq!(exit_code::MISSING_TOPIC, 2);
        assert_eq!(exit_code::MALFORMED_INPUT, 3);
        assert_eq!(exit_code::USAGE, 4);
    }
}
