# Making and verifying a release

This is the evaluation release 0.1.0 process. The founder makes each release. CI builds, checks and attests the files and creates a draft; it never signs, never publishes, and never holds the release private key. The key stays on the founder's offline machine.

## The pieces

| Piece | File | What it does |
|---|---|---|
| Release workflow | `.github/workflows/release.yml` | On a pushed `v*` tag: tests, builds the three static binaries twice from clean, seals every golden log with all three, makes one SBOM per target, scans every file for traces of the build machine, writes `SHA256SUMS`, attests the three tarballs, and creates a **draft pre-release**. On a manual run it does the same checks and uploads the files as a workflow artifact, and creates nothing. |
| Post-release check | `.github/workflows/post-release-check.yml` | After the release is published: runs the README quickstart's download steps on clean machines (`x86_64`, `aarch64`, `armv7`) and checks the release's file list, key and attestations. |
| aarch64 benchmark | `.github/workflows/benchmark-aarch64.yml` | By hand. Runs `scripts/benchmark.sh` on GitHub's arm64 hosted runner ([BENCHMARK.md](BENCHMARK.md)). |
| Signing script | `scripts/release_sign.sh` | Run by the founder, offline: `keygen`, `sign`, `verify`, and a self-test. |
| Tests of the above | `scripts/check_release_flow.sh`, `scripts/check_release_hygiene.sh`, `scripts/check_workflows.sh` | The whole offline signing flow and eight attacks on it, the hygiene scan, and the rules every workflow must keep (actions pinned by commit, no secret, no signing in CI, only the draft job writes). |

Every commit's CI run (`.github/workflows/ci.yml`) also builds the release files unsigned, as the `sfr-release-unsigned` artifact, and runs these checks:

| Job | Script | What it checks |
|---|---|---|
| `release-build` (one per target) | `scripts/check_reproducible.sh`, which runs `scripts/build_release.sh` twice from clean | `rust-lld` links a static `sfr` (`readelf -lW`: no INTERP; `readelf -dW`: no NEEDED; `file`: static) for `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` and `armv7-unknown-linux-musleabihf`; the two binaries and the two tarballs are byte-identical |
| `release-kit-sbom` | `scripts/build_benchmark_kit.sh`, `scripts/release_sbom.sh` | the benchmark kit; one CycloneDX SBOM per target, naming its target and listing `sha2`, `ed25519-dalek` and `blake3` |
| `records` | `scripts/check_same_records.sh` | every golden log seals to the same record and report with the x86_64 release binary as with the aarch64 and the armv7 ones (both under QEMU) |
| `benchmark` | `scripts/benchmark.sh` | from the x86_64 tarball and the kit in `debian:12-slim`, no build tools: 100 MB seal under 2 s, peak memory of every golden log and the 100 MB log |
| `release-assemble` | `scripts/release_assemble.sh`, `scripts/release_sign.sh` | `SHA256SUMS` lists exactly the release files; the signing script signs it with a throwaway key and the `openssl` command below verifies it |

The release builds remap the build paths, embed the commit (`SFR_BUILD_COMMIT`), and pack with fixed names, modes, owners and times, so that the same commit and the pinned toolchain give the same bytes on another machine. The release workflow builds the `x86_64` tarball a second time on a different runner image and reports whether the bytes are identical (the job summary of the `reproduce` job). That comparison is reported, not gated: a difference would mean the toolchain or the runner changed something outside the source, and it is a reason to look before a release, not a proof of tampering.

## The release key

One Ed25519 key signs `SHA256SUMS`. Its public half is committed at `release/sfr-release.pub`, shown with its fingerprint here and in the README, and attached to each release as `sfr-release.pub`. The fingerprint is the SHA-256 of the public key's DER encoding. CI fails when `README.md` or this page disagrees with the key file.

<!-- BEGIN release-key: written by scripts/regen_readme_numbers.sh, do not edit by hand -->
Release public key: not generated yet. The founder generates the release key on an offline machine with `scripts/release_sign.sh keygen <offline path>`, which writes its public half to `release/sfr-release.pub`; `scripts/regen_readme_numbers.sh` then shows it here, and both are committed before the first release.
<!-- END release-key -->

## Steps for the founder

1. **Release key, once.** On an offline machine with OpenSSL 3, in a checkout of the repository: `scripts/release_sign.sh keygen /path/off/the/repository/sfr-release.key`. It writes the private key (mode 0600, refuses to overwrite one) and `release/sfr-release.pub`. Keep the private key on the offline machine and make an offline copy; the repository never holds it (`.gitignore` ignores `*.key`, and `scripts/check_no_private_keys.sh` fails CI on any private key block). Then run `scripts/regen_readme_numbers.sh`, which writes the fingerprint into the README and this page, and commit `release/sfr-release.pub`, `README.md` and `docs/RELEASE.md` in one pull request to `main`.
2. **Dry run.** In GitHub: Actions, `release`, Run workflow, branch `main`. It builds and checks everything and uploads `sfr-release-files-<version>-dry-run`; it creates no tag, release or attestation.
3. **Tag.** Tag the commit on `main` that you want, with the name `v` plus the version in `Cargo.toml`, and push the tag. The workflow refuses a tag that does not match `Cargo.toml` or a commit that is not on `main`. When it is green, the draft pre-release "Evaluation release 0.1.0" holds the three tarballs, the three SBOMs and `SHA256SUMS`.
4. **Check, then sign offline.** When the run waits at the `release` environment, open it and check that its commit is the commit on `main` that you reviewed, then approve it (the repository settings section above). On an online machine, download every file of the draft and run `sha256sum --check --strict SHA256SUMS` and the `gh attestation verify` command below on each tarball; compare `SHA256SUMS` with the one printed in the workflow run's summary (job `assemble`). If a tag run fails after it made the draft, delete the draft before running again. Only then carry `SHA256SUMS` to the offline machine and run `scripts/release_sign.sh sign SHA256SUMS /path/off/the/repository/sfr-release.key`. Signing is the step that makes the draft's contents the project's word, so a changed draft must not be signed. It refuses a key that is not `release/sfr-release.pub`, a file that is not a list of bare file names with their SHA-256, writes `SHA256SUMS.sig` (a raw Ed25519 signature of 64 bytes), and verifies it with the command below.
5. **Upload.** Edit the draft and attach `SHA256SUMS.sig` and the public key file `sfr-release.pub` (the same file as `release/sfr-release.pub`). Nothing else is added.
6. **Check the draft.** It must list exactly nine files, be marked pre-release, and still be a draft. Download the files to a clean directory and run the verification commands below once yourself.
7. **Publish.** Publish the draft. The post-release check starts by itself; read its result under Actions.

## Verify a release

You need OpenSSL 3 and `sha256sum` (coreutils; on macOS `shasum -a 256`). The checksums in `SHA256SUMS` are SHA-256. The `b3sum` tool is for verifying records ([RECORD_FORMAT.md](RECORD_FORMAT.md)), not release files. In a directory that holds the files you downloaded:

First compare the key. Not run in CI by the docs test: the post-release check runs the same commands from the README quickstart, and `scripts/check_release_flow.sh` runs them against a throwaway key and ten attacks.

```sh doc-syntax
curl -fsSL https://raw.githubusercontent.com/InquiroAIReseachLabs/Sealed_Flight_Recorder-/v0.1.0/release/sfr-release.pub | cmp - sfr-release.pub
openssl pkey -pubin -in sfr-release.pub -outform DER | sha256sum
openssl pkeyutl -verify -pubin -inkey sfr-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
sha256sum --check --strict SHA256SUMS
```

The first command fails unless your key file is byte for byte the copy in the repository at the tag. Compare every hex digit of the second command's output with the fingerprint on this page and in the README. The third prints `Signature Verified Successfully` only for a good signature by that key. The fourth checks every file listed and needs all six files in the directory. With only one tarball downloaded, check its own line instead (it fails when `SHA256SUMS` has no line for it, which `--ignore-missing` would not). Not run in CI by the docs test, which has no release; `scripts/check_release_flow.sh` runs it:

```sh doc-syntax
awk -v f="sfr-0.1.0-x86_64-unknown-linux-musl.tar.gz" '$2 == f' SHA256SUMS | sha256sum --check --strict -
```

These flags are GNU coreutils 9 behaviour; other `sha256sum` builds (busybox, `shasum -a 256`) may differ, and the one-line form works with any of them. Then the attestation, which needs the GitHub CLI logged in to GitHub. The two extra flags matter: without them any workflow of this repository could have produced the attestation; with them it must be the release workflow, run for the tag. Not run in CI by the docs test: the post-release check runs it.

```sh doc-syntax
gh attestation verify sfr-0.1.0-x86_64-unknown-linux-musl.tar.gz --repo InquiroAIReseachLabs/Sealed_Flight_Recorder- \
  --signer-workflow InquiroAIReseachLabs/Sealed_Flight_Recorder-/.github/workflows/release.yml --source-ref refs/tags/v0.1.0
```

Inside each tarball, `BUILDINFO` names the commit, the toolchain, and the SHA-256 of `bin/sfr`.

## What each check proves

| Check | Proves | Does not prove |
|---|---|---|
| The fingerprint matches the one you trust | The `sfr-release.pub` you hold is the key the project published. | That the key's holder is who they claim, or that the key was not stolen. A fingerprint shown only on the page that hosts the files adds no independent trust: compare it somewhere else too. |
| `SHA256SUMS.sig` verifies | The holder of the release private key signed exactly these checksums. `release_sign.sh sign` signs only a list of exactly the six release files for the version. | That the files are safe or correct, or that the signer reviewed them. A signature from a stolen key verifies. |
| `sha256sum --check` passes | The files you downloaded are the files the signed `SHA256SUMS` lists, byte for byte. | Anything about files it does not list. |
| `gh attestation verify` passes | GitHub recorded that the file with this digest was produced by a run of this repository's release workflow, on a stated commit. | That the source at that commit is free of defects or that the workflow is. It is evidence of where a file came from, signed by GitHub, independent of the project's own key. |
| The BUILDINFO commit and a rebuild | With the pinned toolchain, building that commit gives the same bytes (the reproducibility report). | That every machine reproduces them; the report names what was compared. |

The signature and the attestation are separate witnesses: the signature depends on a key that stays offline, the attestation on GitHub and on the workflow file at the tagged commit. They are independent only while the repository's protections hold (the next section). Someone with write access to the repository and no protections can change the workflow, tag a commit of their own and make a draft whose attestation verifies; the founder's signature is then the check that matters, and it is made only after the founder has checked the run's commit. The SBOMs are covered by the signature and by `SHA256SUMS`, not by an attestation.

## Repository settings the release depends on

These are settings in GitHub, made by the founder once; no file in the repository can enforce them, because a workflow run at a tag reads the workflow from the tagged commit.

1. **Tags.** Settings, Rules, Rulesets, New ruleset, New tag ruleset, target `v*`: restrict creations, updates and deletions to the founder, and block force pushes. A release tag then cannot be moved or recreated on another commit.
2. **Main.** Settings, Rules, Rulesets (or Branches, branch protection rule) for `main`: require a pull request, require the CI checks, block force pushes and deletions. The release workflow refuses a commit that is not on `main`.
3. **The `release` environment.** Settings, Environments, New environment, name `release`: add the founder as a required reviewer. The `draft-release` job waits there. Approve it only after you have opened the run and checked that its commit is the commit you reviewed on `main`.
4. **Immutable releases.** Settings, General, Releases: turn on immutable releases, so published files and the tag cannot be changed afterwards. If it is not available to you, the fingerprint comparison is the only defence after publishing.
5. **Actions permissions.** Settings, Actions, General: workflow permissions "Read repository contents" by default (the workflows ask for what they need), and allow only the actions the workflows use.

## Hygiene

The release workflow runs `scripts/check_release_hygiene.sh` on every file and every file inside every tarball, and fails if it finds a home directory path, a GitHub runner name, an email address, a session or tool path, an internal word, the build machine's user name or host name, or a tarball member that is not relative or not owned by 0/0. The SBOMs carry crate author names but not their email addresses, and name the source tree as `/build/sfr`, as the binary does.

## Rotate the key

Rotate when the key may be exposed, when the person who holds it changes, or on a schedule you set.

1. On the offline machine, make the new key with `scripts/release_sign.sh keygen <new offline path>`. Do this in a checkout where `release/sfr-release.pub` has been moved aside, because `keygen` never overwrites the release public key.
2. Run `scripts/regen_readme_numbers.sh`, add a line to the key history below with the old and new fingerprints and the date, and commit the new `release/sfr-release.pub`, `README.md` and this page in one pull request.
3. Releases made before the rotation stay signed by the old key. Anyone verifying one uses the `sfr-release.pub` attached to that release and the old fingerprint from the key history.
4. If the old key may have been stolen, say so in the key history and in [SECURITY.md](../SECURITY.md), and sign a new `SHA256SUMS` for each affected release with the new key. A rotation does not make a signature from a stolen key trustworthy for files you cannot otherwise check.

Key history: the first release key has no predecessor.

## Licenses

The tarballs hold no LICENSE file: the source is published for review and evaluation, with all rights reserved (`README.md`, Rights), and `NOTICE.md` lists the third-party material. The SBOMs list the license of every crate linked into `sfr`; the golden logs carry their own notices (`testdata/README.md`, `testdata/pyulog/NOTICE.md` and `LICENSE.md`, and a `.provenance.md` per SITL and synthetic log).
