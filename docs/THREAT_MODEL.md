# Threat model

A verified record has not changed since sealing, and the holder of the signing key sealed it. With `--ulog`, the log has not changed either. That is all: the flight stack may have written a false log, the log may have changed before sealing, and the sealing machine may have been compromised.

## What is signed

Only the record, `<name>.sfr`, is signed. The Ed25519 signature covers its Merkle root, and the root covers every field ([RECORD_FORMAT.md](RECORD_FORMAT.md)). The report `<name>.sfr.md` has no signature. `sfr verify` renders it again from the verified record and requires the `.sfr.md` beside the record (or the one `--report` names) to match byte for byte. With no report, verification fails unless you pass `--no-report`. A report never checked against its record proves nothing.

## What a seal proves

`sfr verify` prints `Integrity: VERIFIED` only after it checks the signature against a key you gave it (`--pubkey`) or a key whose certificate chains to a trust anchor you gave it (`--trust-anchor`). Given neither, it prints `Integrity: NOT CHECKED` and exits 4. A record signed with an evaluation key is `Integrity: REFUSED` unless you pass `--allow-evaluation-key`.

A verified record, signed by the key with this fingerprint, holds these rule results, this configuration and these events, and its report is the one it renders. With `--ulog`, the log matches too (by the SHA-256 of the whole file; the BLAKE3 digest beside it is an index and adds no security), and the embedded rules and baseline give the same results from it.

## What a seal does not prove

- **That the data was accurate before sealing.** A log is the flight stack's account of the flight. It may be wrong, and the vehicle may not have done what it says.
- **Who the key holder is.** The record names its key by fingerprint. Get the public key or trust anchor from its owner over a channel you trust. A key that arrives with the record proves nothing about who signed it.
- **Where the key is kept.** `key_custody` is a string the sealer wrote; a key file can say `pkcs11-token` as easily as a token can. `verify` prints `custody   unattested (declared pkcs11-token)` unless the signer certificate (`seal --cert`, `--chain`) chains to a trust anchor you supplied; then it prints `attested by certificate chain to the trust anchor ...`. That is only as good as the CA: `sfr` cannot tell whether the CA issued the certificate because the key is in hardware, and a CA that also issues certificates to file keys makes them attested too.
- **When the log was made or sealed.** `seal.time_utc` is the sealing machine's clock or `--seal-time`. It is signed but unchecked, and `verify` labels it claimed. `verify` never uses it to judge a certificate, and refuses a claimed time later than the verification time (the verifier's clock, or `--at`) by more than `SEAL_TIME_SKEW_SECONDS` of clock skew. A claimed time in the past stays unproven: a key holder can claim any earlier time.
- **That nothing changed the log before sealing.** See "Disarm to seal".

[design/README.md](design/README.md) has designs for some of these gaps. None is built.

## Attacks and what detects them

Twelve of these attacks worked against an earlier build. `scripts/claims_audit/t12_attacks.sh` runs them against that build, where each must succeed, and against the current one, where each must fail ([CLAIMS_AUDIT.md](CLAIMS_AUDIT.md)).

| Attack | Detected by | Shown by |
|---|---|---|
| Change any byte of a record | standalone verify (canonical form, field set, Merkle root, signature) | `a_thousand_seeded_byte_flips_in_a_record_all_fail_verification` (`crates/sfr/tests/seal_verify.rs`) |
| Change any byte of the log after sealing | deep verify (`--ulog`): the log digests, then the item that differs | `a_thousand_seeded_byte_flips_in_a_log_all_fail_verification`, `mismatches_are_named_precisely` |
| Change a sealed topic's messages, or its digest in the record | deep verify names the topic and instance; standalone verify fails on the digest | `a_thousand_flips_in_sealed_topic_messages_name_the_topic_and_instance`, `a_thousand_flips_in_a_sealed_topic_digest_fail_and_deep_verify_names_it` |
| Re-sign a changed record with another key | verifies only against that other key | `unknown_schema_version_wrong_key_and_evaluation_custody_are_refused` |
| Mark a failing record PASS, or edit the embedded rules | `status` must agree with the signed results; `rules.text` must match its signed digest | code only, `standalone` in `crates/sfr-core/src/verify.rs`; no test changes only these |
| Reorder results or events, even with the key | standalone verify checks rule-id and sequence order | `leaves_must_be_in_rule_id_and_sequence_order` (`crates/sfr-core/src/verify.rs`) |
| Unknown `schema_version`, or relabelling the schema | the version is signed; only schemas 4 and 5 are verified, and a schema 4 record relabelled 5 lacks the members schema 5 requires | `unknown_schema_version_wrong_key_and_evaluation_custody_are_refused` |
| Malleable signature or weak public key | `ed25519-dalek` `verify_strict` | code only, `crates/sfr-core/src/crypto.rs`; no test covers either |
| Evaluation key passed off as an operational one | EVALUATION KEY banner; `Integrity: REFUSED` unless `--allow-evaluation-key` | `a_record_signed_with_an_evaluation_key_is_refused_unless_it_is_allowed` (`crates/sfr/tests/custody.rs`), `the_in_browser_key_seals_an_evaluation_record_the_cli_verifies` |
| Relabel an evaluation record as hardware: re-sign with the same key file after setting `key_custody` to `pkcs11-token` | custody prints as unattested; `--require-hardware-key` refuses it | `relabelling_an_evaluation_record_as_a_token_record_fails_under_require_hardware_key` (`crates/sfr/tests/custody.rs`), `custody_is_attested_by_the_chain_and_only_by_the_chain` (`crates/sfr/tests/certificates.rs`) |
| Edit a report | verify names the first differing line | `an_edited_report_fails_verification_and_names_the_line` (`crates/sfr/tests/seal_verify.rs`) |
| No report, or a forged report under another name | verify fails unless `--no-report`, which says the report was not checked | `a_record_without_its_report_does_not_verify_unless_told_not_to_look`, `a_forged_report_under_another_name_does_not_stand_in_for_the_real_one` (`crates/sfr/tests/report_required.rs`) |
| Bidirectional control (U+202E), zero-width or other Unicode format character, or terminal control sequence in a file name, log message or parameter name | written as `<U+202E>` in the report and all output; `--json` writes `\u202e` | `a_right_to_left_override_in_a_value_is_shown_in_the_report_the_terminal_and_json`, `every_unicode_format_character_is_shown_in_the_report_not_acted_on` (`crates/sfr/tests/report_required.rs`), `scripts/check_format_characters.py` |
| Verify a log under another name | the content binds, not the name; a `note` line names both | `a_log_given_under_another_name_verifies_and_the_output_says_so` (`crates/sfr/tests/report_required.rs`) |
| Verify with no trusted key, or with the key that came with the record | `Integrity: NOT CHECKED`, exit 4 | `verify_without_a_trusted_key_says_the_signer_is_not_checked`, `verify_with_no_trust_source_checks_nothing_and_exits_non_zero` |
| Sign with a certificate that is revoked, expired, for another usage, or from another CA | `verify --trust-anchor --crl`: chain, validity, key usage (code-signing and TLS certificates are refused), a current CRL per issuer | `every_rejection_the_spec_lists_fails_with_its_reason` (`crates/sfr/tests/certificates.rs`), `a_certificate_for_another_purpose_is_not_a_record_signer` and `a_record_signing_certificate_is_not_a_certificate_for_other_purposes` (`crates/sfr/src/certs.rs`) |
| Backdate a seal into an expired certificate's window, or claim a seal time after the verifier's clock | validity is judged at the verifier's clock or `--at`; a claimed time more than `SEAL_TIME_SKEW_SECONDS` ahead is refused | `a_backdated_seal_time_cannot_put_an_expired_certificate_back_in_its_window`, `a_seal_time_in_the_verifiers_future_is_refused_with_or_without_a_certificate` (`crates/sfr/tests/certificates.rs`), `a_claimed_seal_time_may_not_lie_in_the_verifiers_future` (`crates/sfr-core/src/seal.rs`) |
| Seal a log of a ULog file format version above 1 and hide it | `seal` refuses without `--allow-untested-version`; with it `seal.allow_untested_ulog_version` and `log.ulog_version` are signed in the record, and the report says `Untested ULog file version` | `a_ulog_file_version_above_1_is_refused_unless_allowed_and_then_recorded` (`crates/sfr/tests/seal_verify.rs`) |
| Cut a log short inside a record to hide what came after | the signed record and the report state `log ended mid-record at byte N; K trailing bytes not parsed`; the missing tail is never a DISARM or a transition end, so a log that ends armed fails R5 and one that ends in transition fails R6; the digests cover every byte, so the record verifies only against the cut file. A cut at a record boundary looks like a complete log and is **not detected**: R5 and R6 still fail if it ends armed or in transition | `a_log_cut_mid_record_seals_says_where_and_its_digests_cover_every_byte` (`crates/sfr/tests/seal_verify.rs`), `a_log_cut_in_transition_fails_r5_and_r6_naming_the_cut` (`crates/sfr/tests/seal_dry_run.rs`) |
| Seal a log from an untested PX4 version and hide it | `seal` refuses without `--allow-untested-version`; with it the flag is signed in the record | `an_untested_px4_version_is_refused_unless_allowed_and_then_recorded` |
| Move a leaf to another section without the key (a result into `sealed_topics`, an event into `results`) | leaves are hashed with a section tag, so the root changes | `a_leaf_moved_to_another_section_changes_the_root_and_fails_the_signature` (`crates/sfr/tests/signed_structure.rs`) |
| Change the tree size or a section's leaf count | the signed payload holds both, and `merkle.sections` must match the arrays | `the_signature_covers_the_shape_of_the_tree`, `a_wrong_sections_count_is_named` (`crates/sfr/tests/signed_structure.rs`) |
| Log text or file name built to forge report content or a shell command | punctuation is escaped, control characters are shown as markers, and file names are quoted for POSIX sh, bash and PowerShell (or set from their bytes when no quoting is safe in all three) | `hostile_log_text_and_file_names_give_a_literal_report_and_a_working_verify_command` |
| A log built to exhaust memory or time | input limits (exit 3) and fuzzing | [LIMITS.md](LIMITS.md) |
| Edit the log between disarm and sealing | **not detected** | narrowed by sealing at once, below |
| False log from a compromised flight stack or sealing machine | **not detected** | out of scope |
| Stolen signing key | **not detected** in any record it signs | key custody, below |
| Spoofed MAVLink source ids | **not detected**: R7 checks the ids the log recorded | command sources, below |
| False seal time in the past, or re-signing a record with another time | **not detected**: no trusted time source | above |

## Inputs that decide the verdict

Every input that can change a rule result or the verify verdict, who supplies it, what follows if it is wrong, and what `sfr` does about it. Rule results are computed from what the log declares about itself; [VALIDATION.md](VALIDATION.md) lists the false passes that remain.

| Input | Supplied by | If it is wrong | Mitigation |
|---|---|---|---|
| `vehicle_status` arming state, flight mode and failsafe | log | R4 and R5 judge the wrong flight | field types must be PX4's (else the rule FAILs and names the field); every instance is read; a log with no ARM and no DISARM is NO ARMED FLIGHT, not PASS. A consistent rewrite before sealing is not detected. |
| `failsafe_flags` | log | R4 misses a failsafe | required flags come from the flight mode's requirement masks, with PX4's types; missing data FAILs R4; other flags true in flight WARN |
| `is_vtol`, transition fields, `vehicle_type`, `system_type` | log | R6 skips a VTOL | a VTOL `system_type` with `is_vtol` false FAILs R6 |
| Parameter records | log | R3 compares the wrong values | compared at every ARM in file order; a change in flight WARNs |
| `ver_sw_release`, `ver_sw` | log | R2 matches a false version | the R2 line labels the version self-reported |
| `vehicle_command` source ids | log | R7 passes a forged sender | **not detected**; the R7 line says the ids are self-reported |
| Message formats and subscriptions | log | a field read with the wrong type or layout | types pinned to PX4's message definitions; a field declared twice is refused; records `sfr` cannot attribute are counted as skipped in the record |
| Rules file | operator | a narrow scope passes more logs | embedded in the signed record; R3 and R7 state their scope; ignoring every parameter needs `--allow-ignore-all`, which is recorded |
| Baseline | operator | R2 and R3 compare against the wrong reference | its SHA-256 is in the record and in the R2 and R3 lines, and R2 calls it operator-supplied. A baseline made from the same log passes by construction. |
| `--allow-untested-version`, `--seal-time` | operator | a version outside the tested range, or a false time | the flag is in the signed record and the report; the seal time is labeled claimed |
| Signing key and declared custody | sealer | a record signed by someone else, or a file key called hardware | the key is named by fingerprint; custody is unattested unless a certificate chain to the verifier's trust anchor attests it |
| Public key or trust anchor | verifier | a forged record verifies | the verifier must get it from its owner over a trusted channel |
| CRLs (`--crl`, `--no-crl-check`) | verifier | a revoked signer verifies | a CRL that names the signer fails verification; a CRL withheld from the verifier cannot be detected offline |
| `--at`, `--allow-evaluation-key`, `--require-hardware-key` | verifier | a looser check than intended | `--at` prints a `time` line; an accepted evaluation key prints `EVALUATION KEY` first; `--require-hardware-key` only refuses more |
| The log given to `verify --ulog` | verifier | none: a different log fails | the rules run again on it, and the results and status must equal the sealed ones |
| Results and status in the record | record | a forged verdict | without `--ulog`, R1 to R7 must each appear once and the status must follow from them; with `--ulog`, they are derived again from the log |
| The report `.sfr.md` | record | a forged report | rendered again from the verified record and compared byte for byte |

## Disarm to seal

Sealing on the companion computer right after disarm shrinks the window in which the log can be changed. [INTEGRATION_NOTES.md](INTEGRATION_NOTES.md) has a post-disarm example.

## Keys

- **`pkcs11-token`:** the private key stays in a PKCS#11 token or HSM, and the token signs.
- **`tpm-sealed`:** the Ed25519 seed is sealed to one TPM 2.0 and no other TPM can load it. It is in `sfr`'s memory for one signature, then zeroized (`crates/sfr/src/hardware.rs`).
- **`file-evaluation`:** a key file, for evaluation only. Reports and `sfr verify` output carry an EVALUATION KEY banner, and `sfr verify` refuses it unless given `--allow-evaluation-key`.

`seal` uses them through `--key-uri pkcs11:...` (`sfr-pkcs11-helper`), `--key-uri tpm-sealed:<dir>` (tpm2-tools) and `--key <sfr.key> --evaluation-only`. The programs that see the payload or the seed are found by fixed paths only: `sfr-pkcs11-helper` in the directory of the running `sfr` (its canonical path), and the tpm2-tools commands in `/usr/bin`, or in the absolute directory `SFR_TPM2_TOOLS_DIR` names (a relative one is refused); never on `PATH`. A release build never reads `SFR_PKCS11_HELPER`: only a test build with the `dev-helper` feature does, and a release build with that feature does not compile. A stolen key voids trust in every record signed with that fingerprint after the theft.

`--require-hardware-key` means custody attested by a certificate chain, not declared. With `--pubkey` it always refuses, and a declared `file-evaluation` is refused whatever the chain.

`verify --trust-anchor` requires:

- the chain reaches the anchor, and every certificate is valid at the verification time (the verifier's clock, or `--at`; a time in the past needs `--allow-past-at`, and the output's first line then says the record verified as of that time and whether the chain is valid now);
- the anchor is a root (its own issuer); an intermediate CA given as the anchor needs `--allow-partial-chain`, and the trust line then says nothing above it was checked;
- the signer certificate carries the sfr record-signing extended key usage (`2.25.182460915354635260549596502533646383540`) and keyUsage digitalSignature, and not also code signing, TLS server authentication or any usage;
- no certificate in the path is in the current CRL of its issuer (`--crl`). A listed certificate counts as revoked whatever its revocation date, because a stolen key could backdate a seal.

Every CRL given is read, in any order; for each issuer the one with the highest CRL number is current (RFC 5280 section 5.2.3). Every issuer in the chain needs a current CRL: a missing one, one past its `nextUpdate` by the verifier's clock, one whose `thisUpdate` is more than `--max-crl-age` before the verification time (default 7 days, `DEFAULT_MAX_CRL_AGE_SECONDS` in `crates/sfr/src/certs.rs`), or one from another issuer does not count. Indirect CRLs, delta CRLs, CRLs that cover only some revocation reasons, and CRLs with a critical extension `sfr` does not read are refused, not ignored. `verify` prints the issuer, CRL number, thisUpdate and nextUpdate of every CRL it used. `--no-crl-check` skips the check with a warning.

The CRLs must come from the verifier, fetched from the issuer, never from the operator whose record is being checked. There is no online revocation check: a verifier given an older CRL cannot tell that a newer one exists, so a withheld newer CRL (one that revokes the signer) cannot be detected offline. `--max-crl-age` bounds how old that CRL can be.

`sfr` checks nothing about a token: not whether its key can be exported, how it was made, or who vouched for it. The token must sign Ed25519 (`CKM_EDDSA`). No shipping TPM implements EdDSA, so in `tpm-sealed` the TPM only protects the seed at rest. With a PCR policy (`keygen --tpm-sealed --tpm-pcrs`) the TPM refuses to unseal when the measured boot state differs, so after a firmware or boot change the key must be made again.

## Sealed topics

The raw log digest already covers every topic. Sealed topic digests (`[sealed_topics]` in the rules file) add a per-topic digest inside the record, so standalone verify covers them without the log. They do not interpret the topic's contents.

## Command sources

MAVLink source ids are self-reported unless message signing is on for the link. R7 shows which source the log recorded, not that the source was authentic.

## Cryptography

On every target, `sfr` uses `sha2` (SHA-256), `ed25519-dalek` (Ed25519) and `blake3` (a second digest of the log: `verify --ulog` checks it and a mismatch fails, but it adds no security beyond SHA-256); `seal.crypto_crates` names each crate and version, and a record is byte-identical wherever it is sealed. These crates have no CMVP certificate, and `sfr` makes no claim under any cryptographic module standard or security regime.

## Sensitivity

The record contains the full parameter set and is as sensitive as the log.
