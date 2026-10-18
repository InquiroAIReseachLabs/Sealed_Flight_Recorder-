# Threat model

The signature binds the sealed record to the holder of the signing key at the moment of sealing. It proves the record and, with `--ulog`, the log have not changed since then. It does not prove the flight stack wrote a truthful log, that nothing happened to the log between disarm and sealing, or that the sealing machine was uncompromised.

## Disarm to seal

Sealing on the companion computer immediately after disarm shrinks the window in which the log can be changed before it is sealed. `docs/INTEGRATION_NOTES.md` gives a post-disarm hook example.

## Keys

- **`pkcs11-token`:** the private key never leaves a PKCS#11 token or HSM; the token signs.
- **`tpm-sealed`:** the Ed25519 seed is sealed to one TPM 2.0 and no other TPM can load it. It is in `sfr`'s memory for one signature, then zeroized; the FIPS module signs.
- **`file-evaluation`:** a key file, for evaluation only. Every record and report sealed with one says EVALUATION KEY.

A stolen key invalidates trust in every record signed with that fingerprint after the compromise. Custody is signed into the record but declared by the sealer. Only the signer certificate chain to the operator's trust anchor proves it, and that CA must issue certificates only to keys it has seen held in hardware. Revocation is checked against CRL files given to `verify`; there is no online revocation check, by design.

## Hardware tokens

A token is in scope for v1 only if its own CMVP certificate lists EdDSA with Ed25519 (FIPS 186-5) as an approved service. The operator's flight-test lead checks this before first use and passes the certificate number to `seal --token-cert`, which records it in the signed seal leaf. Many current tokens do not list Ed25519 as approved, and such a token is out of scope for v1. No shipping TPM implements EdDSA, so in `tpm-sealed` the TPM only protects the seed at rest.

## Operational Environment Affirmation (read before any deployment)

A CMVP certificate covers one module version on the operating systems and processors it lists. The validated build profile of `sfr` links AWS-LC FIPS 3.1.0, the module of certificate #5314 (static). Its security policy lists Amazon Linux 2023 on AWS Graviton4 and Intel Xeon Platinum 8375C as tested environments, and lists no vendor-affirmed environments.

`sfr` ships as a static musl binary and is meant to run on Jetson-class ARM64 companion computers. Neither musl nor those processors appear on the certificate. The security policy states: "CMVP makes no statement as to the correct operation of the module or the security strengths of the generated keys when so ported if the specific operational environment is not listed on the validation certificate."

**Deploying `sfr` on musl or on Jetson-class hardware is therefore a port to an untested environment.** Before a system's documentation describes `sfr`'s cryptography as validated, that system's assessor must approve the port under the CMVP's vendor and user affirmation rules (FIPS 140-3 CMVP Management Manual, section 7.9). The operator gives the assessor:

1. The validated-profile build log, showing the source archive SHA-256 matching the security policy, `bssl isfips` printing 1, and the module version string.
2. `sfr --version` from the deployed binary.
3. The `seal.crypto_module` field of a record sealed on the target hardware.
4. Proof that the module's power-on self-tests pass on that hardware. A failed self-test aborts `sfr` before it writes anything.

A development-profile build makes no validated-cryptography statement on any environment.

## What `sfr` does not claim

IL4, IL5, and NIST SP 800-171 apply to whole systems and environments, and a binary cannot meet them on its own. For a validated-profile build, the only permitted statement is: `sfr` uses FIPS 140-3 validated cryptography to support integration into IL4/IL5 and NIST SP 800-171 environments.

## Sensitivity

The record contains the full parameter set and is as sensitive as the log; handle it the same way.
