# Sealed Flight Record

After a PX4 flight, produce a signed, self-verifying record of the configuration that flew, the readiness rule results, and the operator, failsafe, and transition events, so anyone can later prove none of it was changed.

v1.0 evaluation release, in development.

## Try it offline

The demo image (`sfr-<version>-demo-image.tar.gz`, x86_64) holds the static `sfr`, two golden SITL logs with their notices, the default rules, and `scripts/run_demo.sh`. With no network it generates an evaluation key; seals the golden VTOL flight and prints the results table and event count; verifies the record alone and against the log; changes one byte of a COMMAND event in a copy of the record and shows verify naming that event; changes VTOL transition parameter `VT_B_TRANS_DUR` in a copy of the quad tailsitter log and shows verify naming the parameter with its sealed and found values; and prints the command that seals your own logs.

```
docker load -i sfr-<version>-demo-image.tar.gz
docker run --rm --network=none sfr-demo:<version>
```

## Downloads

Each build holds, for the version in `Cargo.toml`:

| File | Contents |
|---|---|
| `sfr-<version>-<target>.tar.gz` | the static `sfr` for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`, or `armv7-unknown-linux-musleabihf`, this README, `examples/`, and `BUILDINFO` |
| `sfr-<version>-<target>.cdx.json` | the CycloneDX SBOM of that `sfr`: every crate it links, with version, license, and SHA-256 |
| `sfr-<version>-benchmark.tar.gz` | `scripts/benchmark.sh` and the golden logs it reads, for any architecture ([docs/BENCHMARK.md](docs/BENCHMARK.md)) |
| `sfr-<version>-demo-image.tar.gz` | the demo image above |
| `SHA256SUMS` | the SHA-256 of every file above |
| `SHA256SUMS.sig` | the Ed25519 signature over `SHA256SUMS`, made offline with the release key (a release only) |

CI builds every file but the signature on each commit and keeps them as the `sfr-release-unsigned` artifact of the run. It publishes nothing; [docs/RELEASE.md](docs/RELEASE.md) says how a release is signed and made.

Check a download with OpenSSL 3 and coreutils alone, in the directory that holds the files and `sfr-release.pub`:

```
openssl pkeyutl -verify -pubin -inkey sfr-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum -c --ignore-missing SHA256SUMS
```

The first prints `Signature Verified Successfully` only for a good signature by the release key.

Release public key: not generated yet. The founder generates the release key on an offline machine with `scripts/release_sign.sh keygen <offline path>`, which writes its public half to `release/sfr-release.pub`; that file is committed and shown here before the first release.

## The record and its report

`sfr seal` writes the signed record `<name>.sfr` and, beside it, the report `<name>.sfr.md`: Markdown that GitHub and GitLab render, generated only from the record, with the `sfr verify` command that checks it. `examples/reports/` holds the records and reports of four golden SITL flights (standard VTOL, GPS loss failsafe, quad tailsitter, and a multicopter with a sealed topic and an R7 failure), sealed with an evaluation key.

## Verify timing

SPEC B1.10 gates standalone verification in-process and reports the whole `sfr verify` command beside it without a gate. Both come from the same CI test and are labelled below.

<!-- BEGIN verify-timing: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
Measured by `crates/sfr/tests/verify_perf.rs` in a release build, CI run 39182458471 on commit `817a6c44c5d2283a79fa7051eb4b2ed59bfedf1f`. The record holds 10,000 events (1704147 bytes).

| Measurement | What it times | Median | Min | Max | Runs | Gate (SPEC B1.10) |
|---|---|---|---|---|---|---|
| In-process verify | `sfr_core::verify` on the record bytes already in memory | 6.61 ms | 6.56 ms | 7.19 ms | 101 | gated: median under 10 ms |
| End-to-end `sfr verify` | the whole command: process start, reading the record and the public key, and verify | 9.53 ms | 9.43 ms | 17.62 ms | 101 | not gated, reported only |
<!-- END verify-timing -->
