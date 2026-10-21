# Releases

No release has been published. This page describes how one is made and how to check it. The release key holder makes each release. CI builds, checks and attests the files and creates a draft. It never signs, never publishes, and never holds the release private key, which stays on the release key holder's offline machine.

## The pieces

| Piece | File | What it does |
|---|---|---|
| Release workflow | `.github/workflows/release.yml` | On a pushed `v*` tag: tests, builds the three static binaries twice from clean, seals every golden log with all three, makes one SBOM per target, scans every file for traces of the build machine, writes `SHA256SUMS`, attests the tarballs, and creates a draft pre-release. On a manual run it does the same checks and uploads the files as a workflow artifact. |
| Post-release check | `.github/workflows/post-release-check.yml` | After the release is published: runs the download steps below on clean machines (`x86_64`, `aarch64`, `armv7`) and checks the release's file list, key and attestations. |
| aarch64 benchmark | `.github/workflows/benchmark-aarch64.yml` | By hand. Runs `scripts/benchmark.sh` on GitHub's arm64 hosted runner ([BENCHMARK.md](BENCHMARK.md)). |
| Review measurements | `.github/workflows/review-measurements.yml` | By hand. Coverage, mutation testing in shards and the long fuzz runs of the code review ([review/PHASE0.md](review/PHASE0.md)); uploads counts and statistics only. |
| Signing script | `scripts/release_sign.sh` | Run offline by the release key holder: `keygen`, `sign`, `verify`, and a self-test. |
| Tests of the above | `scripts/check_release_flow.sh`, `scripts/check_release_hygiene.sh`, `scripts/check_workflows.sh` | The offline signing flow with attacks on it, the hygiene scan, and the rules every workflow keeps (actions pinned by commit, no secret, no signing in CI, only the draft job writes). |

`rust-toolchain.toml` lists no cross targets. The release workflow, the benchmark workflow, the armv7 CI job and `scripts/build_release.sh` each add the target they build with.

Every commit's CI run also builds the release files unsigned (the `sfr-release-unsigned` artifact) and checks them:

| Job | Script | Checks |
|---|---|---|
| `release-build` (one per target) | `scripts/check_reproducible.sh` (runs `scripts/build_release.sh` twice from clean) | `sfr` is static for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and `armv7-unknown-linux-musleabihf`; both builds give identical binaries and tarballs |
| `release-kit-sbom` | `scripts/build_benchmark_kit.sh`, `scripts/release_sbom.sh` | the benchmark kit; one CycloneDX SBOM per target, listing `sha2`, `ed25519-dalek` and `blake3` |
| `records` | `scripts/check_same_records.sh` | every golden log seals to the same record and report with the x86_64 binary as with the aarch64 and armv7 ones (both under QEMU) |
| `benchmark` | `scripts/benchmark.sh` | seal and verify time and peak memory from the x86_64 tarball in `debian:12-slim` |
| `release-assemble` | `scripts/release_assemble.sh`, `scripts/release_sign.sh` | `SHA256SUMS` lists exactly the release files; a throwaway key signs it and the `openssl` command below verifies it |

The builds remap build paths, embed the commit (`SFR_BUILD_COMMIT`) and pack with fixed names, modes, owners and times, so the same commit and toolchain give the same bytes on another machine. The release workflow builds the `x86_64` tarball a second time on a different runner image and reports whether the bytes are identical (the `reproduce` job summary). That comparison is reported, not gated.

## The release key

One Ed25519 key signs `SHA256SUMS`. Its public half is committed at `release/sfr-release.pub`, shown with its fingerprint here, and attached to each release as `sfr-release.pub`. The fingerprint is the SHA-256 of the key's DER encoding. CI fails when this page disagrees with the key file.

<!-- BEGIN release-key: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
Release public key: not generated yet. The release key holder generates the release key on an offline machine with `scripts/release_sign.sh keygen <offline path>`, which writes its public half to `release/sfr-release.pub`; `scripts/regen_readme_numbers.sh` then shows it here, and both are committed before the first release.
<!-- END release-key -->

## Steps for the release key holder

1. **Release key, once.** On an offline machine with OpenSSL 3, in a checkout: `scripts/release_sign.sh keygen /path/off/the/repository/sfr-release.key`. It writes the private key (refuses to overwrite one) and `release/sfr-release.pub`. Keep the private key offline and keep an offline copy; the repository never holds it (`.gitignore` ignores `*.key`, and `scripts/check_no_private_keys.sh` fails CI on any private key block). Run `scripts/regen_readme_numbers.sh` to write the fingerprint into this page, and commit `release/sfr-release.pub` and `docs/RELEASE.md` in one pull request to `main`. In the same pull request, take out the first sentence of this page.
2. **Dry run.** In GitHub: Actions, `release`, Run workflow, branch `main`. It builds and checks everything and uploads `sfr-release-files-<version>-dry-run`; it creates no tag, release or attestation.
3. **Tag.** Tag the commit on `main` with `v` plus the version in `Cargo.toml` and push the tag. The workflow refuses a tag that does not match `Cargo.toml` or a commit that is not on `main`. When it is green, the draft pre-release holds the three tarballs, the three SBOMs and `SHA256SUMS`.
4. **Check, then sign offline.** When the run waits at the `release` environment, check that its commit is the commit on `main` that you reviewed, then approve it. On an online machine, download every file of the draft, run `sha256sum --check --strict SHA256SUMS` and the `gh attestation verify` command below on each tarball, and compare `SHA256SUMS` with the one in the workflow run's summary (job `assemble`). If a tag run fails after it made the draft, delete the draft before running again. Only then carry `SHA256SUMS` to the offline machine and run `scripts/release_sign.sh sign SHA256SUMS /path/off/the/repository/sfr-release.key`. Signing makes the draft's contents the project's word, so a changed draft must not be signed. The script refuses a key that is not `release/sfr-release.pub` and a file that is not a list of bare file names with their SHA-256, writes `SHA256SUMS.sig`, and verifies it.
5. **Upload.** Attach `SHA256SUMS.sig` and `sfr-release.pub` to the draft. Nothing else.
6. **Check the draft.** It must list exactly the nine files of the table below, be marked pre-release, and still be a draft. Download them to a clean directory and run the steps below once yourself.
7. **Publish.** The post-release check starts by itself; read its result under Actions.

## Release files

The tarballs hold no LICENSE file; the source is published with all rights reserved (README, Rights), and [NOTICE.md](../NOTICE.md) lists third-party material.

| File | Contents |
|---|---|
| `sfr-<version>-<target>.tar.gz` | the static `sfr` for one of the three targets, `README.md`, `examples/` (rules files, example records and reports, a synthetic sample log with its baseline), and `BUILDINFO` (the commit, the toolchain, and the SHA-256 of `bin/sfr`) |
| `sfr-<version>-<target>.cdx.json` | the CycloneDX SBOM of that `sfr`: its resolved dependency graph for the target from `Cargo.lock` (a superset of the crates it links; build-time crates marked `excluded`), with version, license and SHA-256 |
| `SHA256SUMS` | the SHA-256 of every file above |
| `SHA256SUMS.sig` | the Ed25519 signature over `SHA256SUMS`, made offline with the release key |
| `sfr-release.pub` | the release public key |

Each tarball also has a GitHub build provenance attestation. No container image is published.

## Check a release

You need `curl`, `tar`, `sha256sum` and OpenSSL 3. Every command below is run, in this order and in an empty directory, by the post-release check on clean machines.

1. Download your target's tarball and the three files that check it. The first two lines choose the release and the target (`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` or `armv7-unknown-linux-musleabihf`); the post-release check sets `SFR_VERSION` and `SFR_TARGET`.

   ```sh doc-release
   VERSION="${SFR_VERSION:-0.1.0}"
   TARGET="${SFR_TARGET:-x86_64-unknown-linux-musl}"
   BASE="https://github.com/InquiroAIReseachLabs/Sealed_Flight_Recorder-/releases/download/v$VERSION"
   curl -fsSLO "$BASE/sfr-$VERSION-$TARGET.tar.gz"
   curl -fsSLO "$BASE/SHA256SUMS"
   curl -fsSLO "$BASE/SHA256SUMS.sig"
   curl -fsSLO "$BASE/sfr-release.pub"
   ```

2. Check the release key. The first command fails unless the key you downloaded is byte for byte the key committed in this repository at the tag, a second channel that someone who can only edit release files cannot change. Then compare every hex digit of the fingerprint with the one on this page and anywhere else you trust. The signature only shows that the holder of this key signed `SHA256SUMS`, so stop here if anything differs. The post-release check runs this step and compares its output with the committed key:

   ```sh doc-release
   curl -fsSL "https://raw.githubusercontent.com/InquiroAIReseachLabs/Sealed_Flight_Recorder-/v$VERSION/release/sfr-release.pub" | cmp - sfr-release.pub
   FINGERPRINT="$(openssl pkey -pubin -in sfr-release.pub -outform DER | sha256sum | cut -d' ' -f1)"
   echo "release key fingerprint sha256:$FINGERPRINT"
   ```

3. Verify the signature on `SHA256SUMS`, then your tarball against its line in it. The first command prints `Signature Verified Successfully`; the second prints the tarball's name and `OK`, and fails if `SHA256SUMS` has no line for it. The `&&` stops the second command when the signature fails. The post-release check runs both:

   ```sh doc-release
   openssl pkeyutl -verify -pubin -inkey sfr-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig &&
     awk -v f="sfr-$VERSION-$TARGET.tar.gz" '$2 == f' SHA256SUMS | sha256sum --check --strict -
   ```

4. Check the build provenance attestation, which says which workflow built this exact file from which tag. It is independent of the key above and needs the GitHub CLI (`gh`) logged in. Without the two extra flags, any workflow of this repository could have produced the attestation. The post-release check runs it:

   ```sh doc-release
   gh attestation verify "sfr-$VERSION-$TARGET.tar.gz" --repo InquiroAIReseachLabs/Sealed_Flight_Recorder- \
     --signer-workflow InquiroAIReseachLabs/Sealed_Flight_Recorder-/.github/workflows/release.yml --source-ref "refs/tags/v$VERSION"
   ```

5. Unpack it, make an evaluation key, and seal the sample log, a synthetic log and not a flight. The post-release check runs these commands:

   ```sh doc-release
   tar -xzf "sfr-$VERSION-$TARGET.tar.gz"
   cd "sfr-$VERSION-$TARGET"
   bin/sfr --version
   mkdir -p keys out
   bin/sfr keygen --evaluation-only --out keys > /dev/null
   bin/sfr seal examples/sample/sample.ulg --rules examples/rules.default.toml \
     --baseline examples/sample/sample.params --key keys/sfr.key --evaluation-only --out out | grep -E '^(status|record)'
   bin/sfr verify out/sample.sfr --pubkey keys/sfr.pub --allow-evaluation-key --ulog examples/sample/sample.ulg | grep -E '^(Integrity|Rule checks)'
   ```

6. Change one parameter value in a copy of the record, and one byte of a copy of the log. Each verify exits 1 and says what no longer matches. The post-release check runs these commands and requires both exits to be 1:

   ```sh doc-release
   sed 's/"SYS_AUTOSTART":"i32:10040"/"SYS_AUTOSTART":"i32:10041"/' out/sample.sfr > out/changed.sfr
   rc=0; bin/sfr verify out/changed.sfr --pubkey keys/sfr.pub --allow-evaluation-key || rc=$?; echo "record changed: exit $rc"; test "$rc" = 1
   cp examples/sample/sample.ulg out/changed.ulg
   printf '\377' | dd of=out/changed.ulg bs=1 seek=600 conv=notrunc 2> /dev/null
   rc=0; bin/sfr verify out/sample.sfr --pubkey keys/sfr.pub --allow-evaluation-key --ulog out/changed.ulg || rc=$?; echo "log changed: exit $rc"; test "$rc" = 1
   ```

`sha256sum --check --strict` is GNU coreutils behaviour; on other systems use the one-line form in step 3. `scripts/check_release_flow.sh` runs the signature and checksum commands against a throwaway key and ten attacks.

## What each check proves

| Check | Proves | Does not prove |
|---|---|---|
| The fingerprint matches the one you trust | The `sfr-release.pub` you hold is the key the project published. | That the key's holder is who they claim, or that the key was not stolen. A fingerprint shown only on the page that hosts the files adds no independent trust. |
| `SHA256SUMS.sig` verifies | The holder of the release private key signed exactly these checksums. `release_sign.sh sign` signs only a list of exactly the release files for the version. | That the files are safe or correct, or that the signer reviewed them. A signature from a stolen key verifies. |
| `sha256sum --check` passes | The files you downloaded are the files the signed `SHA256SUMS` lists. | Anything about files it does not list. |
| `gh attestation verify` passes | GitHub recorded that a file with this digest was produced by this repository's release workflow on a stated commit. | That the source at that commit, or the workflow, is free of defects. |
| The `BUILDINFO` commit and a rebuild | With the pinned toolchain, building that commit gives the same bytes. | That every machine reproduces them. |

The signature and the attestation are separate witnesses: the signature depends on a key that stays offline, the attestation on GitHub and the workflow file at the tagged commit. They are independent only while the repository settings below hold. Someone with write access and no protections could change the workflow, tag their own commit and make a draft whose attestation verifies; the release key holder's signature, made after checking the run's commit, is then the check that matters. The SBOMs are covered by the signature and `SHA256SUMS`, not by an attestation.

## Repository settings

These are GitHub settings made once by the release key holder. No file in the repository can enforce them, because a workflow run at a tag reads the workflow from the tagged commit.

1. **Tags.** Settings, Rules, Rulesets, New tag ruleset, target `v*`: restrict creations, updates and deletions to the release key holder, and block force pushes.
2. **Main.** A ruleset or branch protection for `main`: require a pull request and the CI checks, block force pushes and deletions. The release workflow refuses a commit that is not on `main`.
3. **The `release` environment.** Settings, Environments, name `release`, with the release key holder as required reviewer. The `draft-release` job waits there.
4. **Immutable releases.** Settings, General, Releases: turn on immutable releases, so published files and the tag cannot be changed. Without it, the fingerprint comparison is the only defence after publishing.
5. **Actions permissions.** Read-only repository contents by default (the workflows ask for what they need), and only the actions the workflows use.

## Hygiene

The release workflow runs `scripts/check_release_hygiene.sh` on every file and every file inside every tarball. It fails on a home directory path, a GitHub runner name, an email address, a session or tool path, an internal word, the build machine's user or host name, or a tarball member that is not relative or not owned by root. A tarball is scanned through its member names, its gzip header and every unpacked member, not through its compressed bytes: those hold no readable text, and a pattern that matched in them would match by chance (about one random 4 MB file in four holds something shaped like an email address). The SBOMs carry crate author names but not their email addresses, and name the source tree as `/build/sfr`, as the binary does.

## Rotate the key

Rotate when the key may be exposed, when its holder changes, or on a schedule you set.

1. On the offline machine, make the new key with `scripts/release_sign.sh keygen <new offline path>`, in a checkout where `release/sfr-release.pub` has been moved aside (`keygen` never overwrites it).
2. Run `scripts/regen_readme_numbers.sh`, add a line to the key history below with the old and new fingerprints and the date, and commit the new `release/sfr-release.pub` and this page in one pull request.
3. Releases made before the rotation stay signed by the old key. Verify one with the `sfr-release.pub` attached to that release and the old fingerprint from the history.
4. If the old key may have been stolen, say so in the key history and in [SECURITY.md](../SECURITY.md), and sign a new `SHA256SUMS` for each affected release with the new key.

Key history: the first release key has no predecessor.
