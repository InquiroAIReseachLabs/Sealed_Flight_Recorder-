# fuzz/

cargo-fuzz targets (SPEC B1.2, B1.10 "Fuzzing"). Chunk 2 makes this directory a separate cargo-fuzz package; the workspace `Cargo.toml` already excludes it. It holds no package yet.

- Chunk 2 adds the ULog ingest target.
- Chunk 3 adds the `.sfr` reader target.

Gate: 60 seconds per CI run and 10 minutes nightly with zero panics, hangs, or out-of-memory.
