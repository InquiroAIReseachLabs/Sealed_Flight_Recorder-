# Making a release

The founder makes each release. CI never signs, tags, or publishes: every commit's CI run builds the release files unsigned (the `sfr-release-unsigned` artifact), and the release private key never leaves the founder's offline machine. A release is a v1.0 evaluation release.

## What CI builds on each commit

| Job | Script | What it checks |
|---|---|---|
| `release-build` (one per target) | `scripts/check_reproducible.sh`, which runs `scripts/build_release.sh` twice from clean | `rust-lld` links a static `sfr` (`readelf -lW`: no INTERP; `readelf -dW`: no NEEDED; `file`: static) for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and `armv7-unknown-linux-musleabihf`; the two binaries and the two tarballs are byte-identical |
| `release-kit-sbom` | `scripts/build_benchmark_kit.sh`, `scripts/release_sbom.sh` | the benchmark kit; one CycloneDX SBOM per target, naming its target and listing `sha2`, `ed25519-dalek` and `blake3` |
| `demo` | `scripts/build_demo_image.sh`, `scripts/run_demo.sh` | the demo image, saved, then loaded on a cleaned Docker and run with `--network=none` in under 60 s |
| `records` | `scripts/check_same_records.sh` | every golden log seals to the same record and report with the x86_64 release binary as with the aarch64 and the armv7 ones (both under QEMU) |
| `benchmark` | `scripts/benchmark.sh` | from the x86_64 tarball and the kit in `debian:12-slim`, no build tools: 100 MB seal under 2 s, peak memory of every golden log and the 100 MB log |
| `release-assemble` | `scripts/release_assemble.sh`, `scripts/release_sign.sh` | `SHA256SUMS` lists exactly the release files; the signing script signs it with a throwaway key and the `openssl` command below verifies it |

The release builds remap the build paths and embed the commit (`SFR_BUILD_COMMIT`), so the same commit and the pinned toolchain give the same bytes on another machine.

## Steps

1. **Release key, once.** On an offline machine with OpenSSL 3: `scripts/release_sign.sh keygen /path/off/the/repository/sfr-release.key`. It writes the private key (mode 0600) and `release/sfr-release.pub`. Commit `release/sfr-release.pub` and show it in the README's Downloads section. The private key never enters the repository (`.gitignore` ignores `*.key`; `scripts/check_no_private_keys.sh` fails CI on any private key block).
2. **Files.** Download the `sfr-release-unsigned` artifact of the CI run of the commit to release, after every job of that run is green.
3. **aarch64 on aarch64 hardware.** SPEC B1.10 Releases: the release artifacts for aarch64 are built on native aarch64 hardware. On an aarch64 machine with the pinned toolchain (`rustup toolchain install` in the checkout of that commit): `scripts/build_release.sh aarch64-unknown-linux-musl dist/`. Compare its SHA-256 with the CI tarball of the same name. If they are identical, the CI file is that native build byte for byte. If not, put the native tarball in place of the CI one and run `scripts/release_assemble.sh <dir>` again to rewrite `SHA256SUMS`.
4. **aarch64 benchmark.** Run `scripts/benchmark.sh` on that machine from the aarch64 tarball and the benchmark kit ([BENCHMARK.md](BENCHMARK.md)) and keep its output: the aarch64 gate (100 MB seal under 4 s) counts only on real hardware.
5. **Sign**, on the offline machine: `scripts/release_sign.sh sign <dir>/SHA256SUMS /path/off/the/repository/sfr-release.key`. It refuses a key that is not `release/sfr-release.pub`, writes `SHA256SUMS.sig` (a raw 64-byte Ed25519 signature), and checks it with the command below.
6. **Check** in a fresh directory, with OpenSSL 3 and coreutils alone:

   ```
   openssl pkeyutl -verify -pubin -inkey sfr-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
   sha256sum -c SHA256SUMS
   ```

7. **Publish.** The founder tags the commit and makes the release with every file in `<dir>` and `SHA256SUMS.sig`. Each release names its crypto crates and their crate versions (`sfr --version`, `BUILDINFO`, the SBOMs).

## Licenses

The tarballs hold no LICENSE file: the project license is counsel's decision. The SBOMs list the license of every crate linked into `sfr`; the golden logs carry their own notices (`testdata/README.md`, `testdata/pyulog/NOTICE.md` and `LICENSE.md`, and a `.provenance.md` per SITL and synthetic log).
