# tools/reference_verifier/

A second verifier of Sealed Flight Record files (schema 4), for anyone who wants to check a record without trusting `sfr`'s code. It follows [docs/RECORD_FORMAT.md](../../docs/RECORD_FORMAT.md), shares no code with `sfr` (it imports nothing from it), and is maintained in this repository by the same people, so it checks the format as that document states it, not an independent reading of it. It needs only the Python 3.11+ standard library (`tools/reference_verifier/sfr_ref_verify.py` uses `tomllib`, new in 3.11); Ed25519 is implemented in the file from RFC 8032 and checked against that RFC's test vectors.

- `sfr_ref_verify.py <record.sfr> <sfr.pub>` prints `VERIFIED` (exit 0) or `FAILED: <reason>` (exit 1). Its header lists every check it makes and every one it does not (certificate chains and CRLs, the custody policy, the report, the log, and the rules file beyond its TOML syntax and ignore list).
- `sfr_ref_verify.py --self-test` runs the RFC 8032 vectors and the record vectors in `vectors/`.
- `make_vectors.py` writes `vectors/`: records derived from `examples/reports/vtol_transition.sfr` and signed again with a test key, many of them built to trip a lenient JSON reader (a boolean where an integer belongs, unpaired surrogates, integers at and over 2^53, the nesting limit, duplicate keys, floats). `expected.json` gives each one's verdict; where the two verifiers are known to differ, it gives each one's verdict and why.

`crates/sfr/tests/reference_verifier.rs` runs `sfr verify` and this verifier on every vector and every committed record, and fails on any verdict other than the listed one. The CI golden-oracle job also runs the self-test and checks the vectors against their generator.
