# Threat model

The signature binds the sealed record to the holder of the signing key at the moment of sealing. It proves the record and, with `--ulog`, the log have not changed since then. It does not prove the flight stack wrote a truthful log, that nothing happened to the log between disarm and sealing, or that the sealing machine was uncompromised.

## What is signed

Only the record, `<name>.sfr`, is signed: the Ed25519 signature covers its Merkle root, and the root covers every field of the record (the format is in [RECORD_FORMAT.md](RECORD_FORMAT.md)). The report `<name>.sfr.md` is a readable view that `seal` renders from the record; it has no signature and no digest of its own. `sfr verify` binds it to the record: once the record verifies, it renders the report again from the record and requires the `.sfr.md` beside the record, or the one `--report` names, to be identical, byte for byte (rendering is deterministic and the same on every target). A report read without verifying its record proves nothing.

## What a seal proves

`sfr verify` reports `Integrity: VERIFIED` only after checking the signature against a public key the verifier supplied (`--pubkey`) or a key whose certificate chains to a trust anchor the verifier supplied (`--trust-anchor`); given neither, it reports `Integrity: NOT CHECKED` and exits 4. A record so verified proves that it has not changed since it was sealed: that this record, signed by the key with this fingerprint, holds these rule results, this configuration and these events, and that its report, when one is beside it or named, is the one it renders; with `--ulog`, that they match these log bytes (SHA-256 and BLAKE3 of the whole file) and that the embedded rules and baseline give the same results from them. The format is in [RECORD_FORMAT.md](RECORD_FORMAT.md).

## What a seal does not prove

- **That the data was genuine or accurate before sealing.** The seal proves that nothing changed after sealing. It says nothing about the log before then.
- **That the log was honest.** `sfr` checks what the log says, not whether the flight stack, its sensors or its estimator told the truth.
- **That the vehicle did what the log says.** A log is the flight stack's account of the flight, not the flight.
- **That the key holder is who they claim.** The record names a key by fingerprint. How that key is held (`key_custody`) is the sealer's statement and stays one. A signer certificate (`seal --cert`, `--chain`) that chains to the operator's trust anchor (`verify --trust-anchor`) shows to whom the anchor issued a certificate for the key, not where the key is kept; `verify` prints custody as declared either way. Get the public key or the trust anchor from its owner by a channel you trust: `sfr verify` checks the signature against the key given with `--pubkey` or the key whose certificate chains to `--trust-anchor`, and given neither prints `Integrity: NOT CHECKED` and exits 4. A public key that came with the record proves nothing about who signed it.
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
| Edit a report (`.sfr.md`) | verify re-renders the report from the verified record and names the first line that differs; a report verify did not find (`report    not checked`) is not checked | `an_edited_report_fails_verification_and_names_the_line` (`crates/sfr/tests/seal_verify.rs`) |
| Verify with no trusted key, or with the key file that came with the record | no `--pubkey` and no `--trust-anchor`: `Integrity: NOT CHECKED`, exit 4. A key that came with the record is checked like any other, so it proves only that its holder signed | `verify_without_a_trusted_key_says_the_signer_is_not_checked`, `verify_with_no_trust_source_checks_nothing_and_exits_non_zero` |
| Sign with a certificate that is revoked, expired, for another usage, or from another CA | `verify --trust-anchor --crl`: chain to the anchor, validity at the seal time, code signing, a current CRL for each issuer in the chain | `every_rejection_the_spec_lists_fails_with_its_reason` (`crates/sfr/tests/certificates.rs`) |
| Seal a log from an untested PX4 version and hide it | `seal` refuses without `--allow-untested-version`; with it, `seal.allow_untested_version` is signed, so clearing it breaks the signature | `an_untested_px4_version_is_refused_unless_allowed_and_then_recorded` |
| Relabel a schema 2 record as schema 1 | the schema version is in the signed payload, and a schema 1 record may not hold schema 2 fields | `unknown_schema_version_wrong_key_and_evaluation_custody_are_refused` |
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

`seal` signs with all three: `--key-uri pkcs11:...` through `sfr-pkcs11-helper`, `--key-uri tpm-sealed:<dir>` through tpm2-tools, and `--key <sfr.key> --evaluation-only`. A stolen key invalidates trust in every record signed with that fingerprint after the compromise. Custody is signed into the record but declared by the sealer, and `verify` never reports it as proven. A certificate chain to the operator's trust anchor adds what that CA vouches for: if the CA certifies only keys it has seen held in hardware, its certificate is the operator's evidence of custody, but `sfr` cannot see that policy. `verify --trust-anchor` requires the chain to reach the anchor, every certificate to be valid at the seal time, the signer certificate to carry extended key usage code signing, and no certificate in the path to be listed in the current CRL of its issuer, given with `--crl`. A listed certificate counts as revoked whatever its revocation date, because the seal time is the sealer's own statement and a stolen key could backdate a seal. Every CRL given is read, in any order, and for each issuer the one with the highest CRL number is current (RFC 5280 section 5.2.3), so an older CRL given first cannot hide a revocation. Every issuer in the chain needs a current CRL; a missing one, one past its `nextUpdate` by the verifier's clock, or one from another issuer, does not count, and `--no-crl-check` is the explicit, warned way to skip the check. There is no online revocation check, by design: a CRL is only as current as the file given, and withholding the newest CRL is not detected until its predecessor's `nextUpdate` passes.

`sfr` checks nothing about a token itself: not whether its private key can be exported, how it was made, or who has vouched for it. It needs a token that signs with Ed25519 (`CKM_EDDSA`); choosing one whose key cannot leave it is the operator's job. No shipping TPM implements EdDSA, so in `tpm-sealed` the TPM only protects the seed at rest: the seed is unsealed into `sfr`'s memory for one signature. A PCR policy (`keygen --tpm-sealed --tpm-pcrs`) makes the TPM refuse to unseal when the measured boot state differs, so after a firmware or boot change the key must be made again.

## Sealed topics

The raw log digest already covers every topic. Sealed topic digests (`[sealed_topics]` in the rules file) add a per-topic proof inside the record: standalone verify covers them without the log, and a future inclusion-proof export can disclose one topic's digest without revealing the rest of the record. They do not interpret or judge the topic's contents.

## Command sources

Command source ids are the values recorded in the log. MAVLink source ids are self-reported unless MAVLink message signing is enabled on the link. R7 proves which source the log recorded, not that the source was authentic.

## Cryptography

On every target, `sfr` computes SHA-256 with `sha2`, Ed25519 with `ed25519-dalek`, and the supplementary BLAKE3 digest of the raw log with `blake3`; `seal.crypto_crates` names each crate and its crate version. The same crates build every target, so a record is byte-identical wherever it is sealed. These crates have no CMVP certificate, and `sfr` makes no claim under any cryptographic module standard: treat its digests and signatures as made by ordinary open source code. `sfr` makes no claim that it meets any security standard or regime; such requirements apply to whole systems and how they are run.

## Sensitivity

The record contains the full parameter set and is as sensitive as the log; handle it the same way.
