//! Sealed Flight Record engine (SPEC B1.2, `crates/sfr-core`).
//!
//! Ingest, events, and rules (Chunk 2) and the record, Merkle tree, signing, and verification
//! (Chunk 3) live here. The engine performs no I/O beyond reading byte streams handed to it,
//! has no networking, and contains no `unsafe` code.
#![forbid(unsafe_code)]

pub mod crypto;
pub mod evaluate;
pub mod events;
pub mod ingest;
pub mod json;
pub mod keys;
pub mod merkle;
pub mod params;
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

/// Record schema version. Starts at 1 (SPEC B1.7). A verifier must reject any
/// version it does not know and must never guess.
pub const SCHEMA_VERSION: u32 = 1;

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
    fn schema_version_starts_at_one() {
        assert_eq!(SCHEMA_VERSION, 1, "SPEC B1.7: schema_version starts at 1");
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
