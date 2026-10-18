# Threat model

The signature binds the sealed record to the holder of the signing key at the moment of sealing. It proves the record and, with `--ulog`, the log have not changed since then. It does not prove the flight stack wrote a truthful log, that nothing happened to the log between disarm and sealing, or that the sealing machine was uncompromised.

## Disarm to seal

Sealing on the companion computer immediately after disarm shrinks the window in which the log can be changed before it is sealed. `docs/INTEGRATION_NOTES.md` gives a post-disarm hook example.

## Keys

- **`pkcs11-token`:** the private key never leaves a PKCS#11 token or HSM; the token signs.
- **`tpm-sealed`:** the Ed25519 seed is sealed to one TPM 2.0 and no other TPM can load it. It is in `sfr`'s memory for one signature, then zeroized; `sfr` signs with `ed25519-dalek`.
- **`file-evaluation`:** a key file, for evaluation only. Every record and report sealed with one says EVALUATION KEY.

A stolen key invalidates trust in every record signed with that fingerprint after the compromise. Custody is signed into the record but declared by the sealer. Only the signer certificate chain to the operator's trust anchor proves it, and that CA must issue certificates only to keys it has seen held in hardware. Revocation is checked against CRL files given to `verify`; there is no online revocation check, by design.

## Hardware tokens

A token is in scope for v1 only if its own CMVP certificate lists EdDSA with Ed25519 (FIPS 186-5) as an approved service. The operator's flight-test lead checks this before first use and passes the certificate number to `seal --token-cert`, which records it in the signed seal leaf. Many current tokens do not list Ed25519 as approved, and such a token is out of scope for v1. No shipping TPM implements EdDSA, so in `tpm-sealed` the TPM only protects the seed at rest.

## Sealed topics

The raw log digest already covers every topic. Sealed topic digests (`[sealed_topics]` in the rules file) add a per-topic proof inside the record: standalone verify covers them without the log, and a future inclusion-proof export can disclose one topic's digest without revealing the rest of the record. They do not interpret, validate, or judge the topic's contents.

## Command sources

Command source ids are the values recorded in the log. MAVLink source ids are self-reported unless MAVLink message signing is enabled on the link. R7 proves which source the log recorded, not that the source was authentic.

## Cryptography

On every target, `sfr` computes SHA-256 with `sha2`, Ed25519 with `ed25519-dalek`, and the supplementary BLAKE3 digest of the raw log with `blake3`; `seal.crypto_crates` names each crate and its crate version. The same crates build every target, so a record is byte-identical wherever it is sealed. These crates have no CMVP certificate, and `sfr` makes no FIPS 140 claim of any kind. A system whose requirements call for a CMVP-validated module must treat `sfr`'s digests and signatures as made outside one.

## What `sfr` does not claim

`sfr` holds no compliance status. IL4, IL5, and NIST SP 800-171 apply to whole systems and environments, and a binary cannot meet them on its own.

## Sensitivity

The record contains the full parameter set and is as sensitive as the log; handle it the same way.
