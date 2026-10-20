# B1: trusted time

Design only; not built. Today the seal time is the sealing machine's clock, or the time given with `--seal-time`. It is signed, so it cannot change after sealing, but nothing checks it, and `sfr verify` prints it as claimed ([THREAT_MODEL.md](../THREAT_MODEL.md)). This page designs the one thing that would let a verifier say "this record existed no later than T": a time that comes from outside the sealer.

## What it would add, and what it would not

It would add: a statement, checkable offline, that the record's bytes existed no later than a time T that a time stamping authority (TSA) vouches for, and an ordering statement from the sealing machine's TPM.

It would not add:

- *When the flight happened.* A stamp is an upper bound on when the record existed. A flight from last week sealed and stamped today is stamped today.
- *Anything about the data before it was sealed.* The stamp covers the record's bytes, not the truth of the log inside them.
- *A lower bound.* Nothing proves the record was not made later than the claimed seal time but earlier than the stamp. The seal time stays a claim.

## Design

Two independent sources, each optional, each stored beside the record and never inside it (so the signed record and its Merkle root do not change, and a record can be stamped long after it was sealed).

### 1. A countersignature from a time stamping authority (UTC)

- **What is stamped.** The SHA-256 of the record file's exact bytes (the canonical JSON, as the file is stored). Not the report, not the log.
- **How.** `sfr stamp <record.sfr> --tsa-url <url>` (a separate command, so `seal` and `verify` stay offline) sends an RFC 3161 `TimeStampReq`: `messageImprint` holding SHA-256 and that digest, a random `nonce`, and `certReq` true. The response is a `TimeStampToken`: a CMS `SignedData` (RFC 5652) whose content is a `TSTInfo` with `genTime`, `serialNumber`, `messageImprint` and the TSA's `policy`. It is written as `<name>.sfr.tst`, with the request's nonce checked against the response before it is accepted.
- **A second form.** An OpenTimestamps proof (`<name>.sfr.ots`) anchors the same digest in a public blockchain through calendar servers. It needs no trusted authority, at the cost of a delay of hours before the proof is complete and a verifier that has the block header (or a trusted list of them).
- **Verification.** `sfr verify <record.sfr> ... --timestamp <name>.sfr.tst --tsa-anchor <tsa-ca.pem> [--crl ...]`. The verifier checks, in this order:
  1. the token's `messageImprint` equals the SHA-256 of the record file it was given;
  2. the CMS signature, with the signer certificate chaining to the TSA anchor the verifier supplied (the same trust rules as `--trust-anchor`: offline, anchors supplied by the verifier, a CRL for every issuer unless `--no-crl-check`);
  3. the signer certificate carries the extended key usage `id-kp-timeStamping` as the only usage, marked critical (RFC 3161 section 2.3), and its validity period includes `genTime`;
  4. the signing certificate identifier (`ESSCertIDv2`, RFC 5816) matches the certificate used.
- **Where it ends.** A token is only checkable while its certificates and algorithms are trusted. Long-term archives renew the stamp (an evidence record, RFC 4998) before the TSA certificate expires or its algorithm weakens. A renewal is a new token over the old one; the design stores a list of tokens, oldest first, and the verifier takes the earliest one that verifies.

### 2. A clock attestation from the TPM (ordering, not UTC)

- **What it is.** `TPM 2.0` `TPM2_GetTime`, with `qualifyingData` set to the record's SHA-256, signed by an attestation key (a restricted signing key) of the sealing TPM. The signed structure (`TPMS_TIME_ATTEST`) holds the TPM's `clock` (milliseconds, kept across restarts while the TPM has power), `resetCount`, `restartCount` and `safe`, and the qualifying data.
- **What it proves.** That this TPM, with this attestation key, signed this digest when its clock read this value. Two attestations from one TPM therefore order two records by `clock`, within one reset count. A changed `resetCount`, or a `safe` of false, is visible. It is not UTC: the TPM clock starts at an arbitrary value and the owner can set it (`TPM2_ClockSet`).
- **What the verifier needs.** The attestation key's public part from a source it trusts. Normally that is the same trust question as key custody: a certificate for the attestation key issued by an operator CA the verifier supplies, or the TPM manufacturer's endorsement key certificate chain. `sfr` checks the signature and the chain; it cannot see how the CA decided.
- **How it joins UTC.** A TPM attestation made near a TSA token (same minutes, same record digest) lets a reader say "the attestation clock `c` was at about UTC `t`" for that one TPM. That is a convenience for ordering, not a proof, and the output labels it that way.

## What the verifier prints

Only a verified token or proof may produce the words "existed no later than". These are the lines, in the place of the current `seal time` line, and nothing else prints that claim:

```text
time      trusted: the record existed no later than 2026-10-19T12:00:04Z (RFC 3161 token from TSA "Example TSA", anchor sha256:3f...c1)
seal time 2026-10-18T15:00:00Z (claimed by the sealer, not proven)
```

With no token (the default, and today's behaviour):

```text
time      NOT PROVEN: no timestamp token given; the seal time is the sealer's claim
seal time 2026-10-18T15:00:00Z (claimed by the sealer, not proven)
```

A token that was given and does not verify is an integrity failure, exit code 1, with the reason (`timestamp: the token's digest is not this record's`, `timestamp: the TSA certificate is not valid at genTime`, ...), never a quiet downgrade to "not proven". `--require-timestamp` makes the absence of a token a failure too. With a TPM attestation as well, an extra line: `clock     TPM attestation: clock 4417200 ms, reset count 3, same reset count as the earlier record in the chain` (the last words only with the chain of B2).

JSON gets `time_trusted` (true only with a verified token), `time_not_after_utc` and `time_source`. The report, which is generated from the record alone, does not mention a stamp: it cannot know one.

## Standards relied on

RFC 3161 (time-stamp protocol), RFC 5652 (CMS), RFC 5816 (ESSCertIDv2 for SHA-2), RFC 4998 (evidence record syntax, for renewal), RFC 5280 (certificates and CRLs, already used), the TCG `TPM 2.0` library specification part 3 (`TPM2_GetTime`, `TPMS_TIME_ATTEST`), and for the blockchain form the OpenTimestamps proof format.

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| The TSA is unreachable when the record is sealed | No token | The record is still good; `stamp` can be run later. The stamp then bounds from the later time. |
| The TSA's key or certificate is compromised, or the TSA lies | A false "no later than T" | Revocation (CRL) at verification; the verifier chooses its anchors; two TSAs from different operators can both be required (`--timestamp` repeated, all must verify). |
| The TSA certificate expires, or its algorithm is broken, before anyone verifies | The old token stops verifying | Renewal tokens (RFC 4998); the earliest verifying token is shown. |
| The sealer stamps a different file than the one it ships | The verifier's digest check fails | The digest is of the record file the verifier holds. |
| The TPM is reset, replaced, or its clock set | Attestation clocks are not comparable | `resetCount` and `safe` are shown; comparisons across a reset are refused. |
| The attestation key is not tied to the sealing key | The attestation proves a TPM saw the digest, not that this key's holder did | Same rule as custody: an operator CA issues both, or the claim is labelled unattested. |
| Network use in the tools | Breaks the offline promise | Only `sfr stamp` touches the network, only when asked, and `verify` takes the token as a file. |
| OpenTimestamps proof incomplete | No proof yet | The proof is printed as incomplete, not as a time. |

## Size

Small to medium. A new command `stamp`, a CMS and `TSTInfo` reader (the DER code already in `crates/sfr/src/certs.rs` covers certificates and CRLs; CMS adds a few hundred lines and the existing Ed25519-only signature rule would have to widen to the TSA's algorithms, which are commonly RSA or ECDSA), a verify option, tests with a locally run TSA, and documentation. About three engineer-weeks, most of it in the algorithm and CMS edge cases. The TPM attestation is a separate week on top, plus the key provisioning work. OpenTimestamps is a further week and an extra dependency decision.
