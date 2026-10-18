//! Browser build of `sfr-core` for the sandbox (SPEC B1.2, `crates/sfr-wasm`).
//!
//! Thin wrapper. Exposes seal, verify, and verify-with-log in Chunk 6. The sandbox and
//! the CLI must produce byte-identical records from the same inputs, which proves
//! they are one engine.
#![forbid(unsafe_code)]

pub use sfr_core::SCHEMA_VERSION;

#[cfg(test)]
mod tests {
    #[test]
    fn re_exports_the_engine_schema_version() {
        assert_eq!(super::SCHEMA_VERSION, sfr_core::SCHEMA_VERSION);
    }
}
