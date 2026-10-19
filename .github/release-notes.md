Evaluation release @VERSION@ of `sfr`, a pre-release. It is provided without warranty. Its quickstart signs with evaluation keys; a TPM-sealed key (`sfr keygen --tpm-sealed`) needs tpm2-tools on the machine, and a PKCS#11 key needs `sfr-pkcs11-helper` built from source.

Files: a static `sfr` for Linux `x86_64`, `aarch64` and `armv7` (tarballs), one CycloneDX SBOM per target, `SHA256SUMS`, `SHA256SUMS.sig` (signed offline with the release key), and `sfr-release.pub` (the release public key).

Release key fingerprint: `sha256:@FINGERPRINT@`. Check it against `README.md` and `docs/RELEASE.md` at this tag, and against any other channel you trust, before you rely on the signature.

Verify and run it with the commands in the README quickstart at this tag: https://github.com/@REPOSITORY@/blob/@TAG@/README.md#quickstart. Each tarball also has a GitHub build provenance attestation (`gh attestation verify`); `docs/RELEASE.md` says what the signature and the attestation each prove and do not prove.

Built from commit `@COMMIT@` by `.github/workflows/release.yml`.
