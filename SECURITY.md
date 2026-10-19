# Security

## Reporting a vulnerability

Report a vulnerability privately through GitHub's private vulnerability reporting: on this repository's page, open the **Security** tab and choose **Report a vulnerability**. Please do not open a public issue, pull request or discussion for it.

Include what you found, the `sfr --version` output or the commit, and the smallest input that shows it (a log, rules file, baseline, record or public key), or the steps to reproduce it. Leave out personal information the report does not need.

## In scope

- The `sfr` command line and the `sfr-core` engine in this repository: a record that verifies after it was changed, a log change that a deep verify (`--ulog`) does not report, a signature or key accepted when it should be refused, a crash, hang, or memory exhaustion on any input, and anything that makes `seal` write a record or report it should not.
- The record format and the verification steps in `docs/RECORD_FORMAT.md`, where following them as written would accept a changed record.
- The engine bundle built from `crates/sfr-wasm`.
- The release files and their signature, once a release is published, and the scripts in `scripts/` that build and sign them.

## Out of scope

- What `docs/THREAT_MODEL.md` says a seal does not prove: a false log, a log changed before it was sealed, a stolen signing key, spoofed MAVLink source ids, or a false seal time.
- Evaluation keys (`file-evaluation` custody) being file keys: they are for evaluation only, every record sealed with one holds custody `file-evaluation`, and its report says EVALUATION KEY.
- PX4, the flight controller, the companion computer, and the way logs reach it.
- The website and any hosted service that uses the engine bundle; they are not in this repository.
- Findings that need write access to this repository or to the machine that seals.
