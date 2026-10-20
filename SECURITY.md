# Security

## Reporting a vulnerability

Report it privately: on this repository, open the **Security** tab and choose **Report a vulnerability**. Please do not open a public issue or pull request for it.

Include the `sfr --version` output or the commit, and the smallest input that shows the problem (a log, rules file, baseline, record or public key), or the steps to reproduce it.

## In scope

- The `sfr` command line and the `sfr-core` engine: a changed record that still verifies, a log change that `--ulog` misses, a signature or key accepted when it should be refused, a crash, hang or memory exhaustion on any input.
- The record format and verification steps in `docs/RECORD_FORMAT.md`, where following them as written would accept a changed record.
- The engine bundle built from `crates/sfr-wasm`, and the scripts in `scripts/` that build and sign releases.

## Out of scope

- What `docs/THREAT_MODEL.md` says a seal does not prove: a false log, a log changed before sealing, a stolen signing key, spoofed MAVLink source ids, a false seal time.
- Evaluation keys being file keys. Records sealed with one say so.
- PX4, the flight controller, the companion computer, and how logs reach it.
- Findings that need write access to this repository or to the sealing machine.
