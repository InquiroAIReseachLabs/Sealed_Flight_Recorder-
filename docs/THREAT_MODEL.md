# Threat model

The signature binds the sealed record to the holder of the signing key at the moment of sealing. It proves the record and, with `--ulog`, the log have not changed since then. It does not prove the flight stack wrote a truthful log, that nothing happened to the log between disarm and sealing, or that the sealing machine was uncompromised.

## What is signed

Only the record, `<name>.sfr`, is signed: the Ed25519 signature covers its Merkle root, and the root covers every field of the record (the format is in [RECORD_FORMAT.md](RECORD_FORMAT.md)). The report `<name>.sfr.md` is a readable view that `seal` renders from the record; it has no signature and no digest of its own, and `sfr verify` never reads it. A report proves nothing by itself: verify its record.

## What a seal proves

A record that `sfr verify` reports VERIFIED proves that this record, signed by the key with this fingerprint, holds these rule results, this configuration and these events; with `--ulog`, that they match these log bytes (SHA-256 and BLAKE3 of the whole file) and that the embedded rules and baseline give the same results from them. The format is in [RECORD_FORMAT.md](RECORD_FORMAT.md).

## What a seal does not prove

- **That the data was accurate before sealing.** The seal proves that nothing changed after sealing. It says nothing about the log before then.
- **That the log was honest.** `sfr` checks what the log says, not whether the flight stack, its sensors or its estimator told the truth.
- **That the vehicle did what the log says.** A log is the flight stack's account of the flight, not the flight.
- **That the key holder is who they claim.** The record names a key by fingerprint. Who holds that key, and how (`key_custody`), is the sealer's statement until a signer certificate chain proves it, and this build cannot attach one. Get the public key from its owner by a channel you trust: `sfr verify` checks the signature against the key given with `--pubkey`, and verifies nothing without one. A public key that came with the record proves nothing about who signed it.
- **When the log was made, or sealed.** `seal.time_utc` is self-asserted: the sealing machine's clock or the `--seal-time` given, signed but not proven. Only a trusted time supplied from outside the sealer would prove it; `sfr` takes none.
- **That nothing changed the log before sealing.** The window from disarm to seal is open; see below.

## Attacks and what detects them

| Attack | Detected by | Shown by |
|---|---|---|
| Change any byte of a record | standalone verify: canonical form, field set, Merkle root, signature | `a_thousand_seeded_byte_flips_in_a_record_all_fail_verification` (`crates/sfr/tests/seal_verify.rs`) |
| Change any byte of the log after sealing | deep verify (`--ulog`): the log digests, then the parameter, event, result, sealed topic, firmware or vehicle that differs | `a_thousand_seeded_byte_flips_in_a_log_all_fail_verification`, `mismatches_are_named_precisely` |
| Change a sealed topic's messages, or its digest in the record | deep verify names the topic and instance; standalone verify fails on the digest | `a_thousand_flips_in_sealed_topic_messages_name_the_topic_and_instance`, `a_thousand_flips_in_a_sealed_topic_digest_fail_and_deep_verify_names_it` |
| Re-sign a changed record with another key | it verifies only against that other key: checked against the public key the verifier trusts, the fingerprint and the signature fail | `unknown_schema_version_wrong_key_and_evaluation_custody_are_refused` (a record checked against a key that did not sign it) |
| Mark a failing record PASS, or edit the embedded rules | `status` must agree with the results, which are signed leaves; `rules.text` must match its digest, inside the signed `rules` leaf | code only, `standalone` in `crates/sfr-core/src/verify.rs`; no test changes only these |
| Reorder results or events, even by the key holder | standalone verify checks rule-id and sequence order | `leaves_must_be_in_rule_id_and_sequence_order` (`crates/sfr-core/src/verify.rs`) |
| A record with an unknown `schema_version` | refused, never guessed at | `unknown_schema_version_wrong_key_and_evaluation_custody_are_refused` |
| A malleable signature or a weak public key | `ed25519-dalek` `verify_strict` | code only, `crates/sfr-core/src/crypto.rs`; no test in this repository covers either |
| An evaluation key passed off as an operational one | a record sealed with a key file holds custody `file-evaluation`, and its report, `seal` and `verify` start with EVALUATION KEY; `verify --require-hardware-key` refuses declared `file-evaluation` custody | `the_in_browser_key_seals_an_evaluation_record_the_cli_verifies`, `every_golden_log_seals_byte_identically_twice_and_replays`, `unknown_schema_version_wrong_key_and_evaluation_custody_are_refused` |
| Edit a report (`.sfr.md`) | nothing in the report: it is not signed. Verifying its record shows what was sealed | not tested: the report is outside the signature by design |
| Log text or a file name built to forge report content or a shell command | the report escapes every punctuation character of every value and quotes each file name in its `sfr verify` command | `hostile_log_text_and_file_names_give_a_literal_report_and_a_working_verify_command` |
| A log built to exhaust memory or time | input limits, refused with exit 3, and fuzzing | [LIMITS.md](LIMITS.md) |
| Edit the log between disarm and sealing | **not detected** | narrowed by sealing at once, below |
| A false log from a compromised flight stack or sealing machine | **not detected** | out of scope |
| A stolen signing key | **not detected** in any record it signs | key custody, below |
| Spoofed MAVLink source ids | **not detected**: R7 checks the ids the log recorded | command sources, below |
| A false seal time | **not detected** | above |

## Disarm to seal

Sealing on the companion computer immediately after disarm shrinks the window in which the log can be changed before it is sealed. [INTEGRATION_NOTES.md](INTEGRATION_NOTES.md) gives a post-disarm example.

## Keys

- **`pkcs11-token`:** the private key never leaves a PKCS#11 token or HSM; the token signs.
- **`tpm-sealed`:** the Ed25519 seed is sealed to one TPM 2.0 and no other TPM can load it. It is in `sfr`'s memory for one signature, then zeroized.
- **`file-evaluation`:** a key file, for evaluation only. Every record sealed with one records that custody, and its report and `sfr verify` output start with EVALUATION KEY.

This build signs only with `file-evaluation` keys; the two hardware sources exit 4 with "not available in this build". A stolen key invalidates trust in every record signed with that fingerprint after the compromise. Custody is signed into the record but declared by the sealer. Only a signer certificate chain to the operator's trust anchor would prove it, and that CA must issue certificates only to keys it has seen held in hardware. Revocation will be checked against CRL files given to `verify`; there is no online revocation check, by design.

A token is in scope only if its own CMVP certificate lists EdDSA with Ed25519 as an approved service; the operator's flight-test lead checks this before first use. No shipping TPM implements EdDSA, so in `tpm-sealed` the TPM only protects the seed at rest.

## Sealed topics

The raw log digest already covers every topic. Sealed topic digests (`[sealed_topics]` in the rules file) add a per-topic proof inside the record: standalone verify covers them without the log, and a future inclusion-proof export can disclose one topic's digest without revealing the rest of the record. They do not interpret or judge the topic's contents.

## Command sources

Command source ids are the values recorded in the log. MAVLink source ids are self-reported unless MAVLink message signing is enabled on the link. R7 proves which source the log recorded, not that the source was authentic.

## Cryptography

On every target, `sfr` computes SHA-256 with `sha2`, Ed25519 with `ed25519-dalek`, and the supplementary BLAKE3 digest of the raw log with `blake3`; `seal.crypto_crates` names each crate and its crate version. The same crates build every target, so a record is byte-identical wherever it is sealed. These crates have no CMVP certificate, and `sfr` makes no claim under any cryptographic module standard: treat its digests and signatures as made by ordinary open source code. `sfr` makes no claim that it meets any security standard or regime; such requirements apply to whole systems and how they are run.

## Sensitivity

The record contains the full parameter set and is as sensitive as the log; handle it the same way.
