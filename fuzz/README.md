# fuzz/

cargo-fuzz targets (SPEC B1.2, B1.10 "Fuzzing"). This directory is a separate cargo-fuzz package, excluded from the workspace.

- Chunk 2 adds the ULog ingest target.
- Chunk 3 adds the `.sfr` reader target.

Gate: 60 seconds per CI run and 10 minutes nightly with zero panics, hangs, or out-of-memory.
