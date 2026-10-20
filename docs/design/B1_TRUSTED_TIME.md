# B1: trusted time

Design only; not built. Today the seal time is the sealing machine's clock, or the time given with `--seal-time`. It is signed, so it cannot change after sealing, but nothing checks it, and `sfr verify` prints it as claimed ([THREAT_MODEL.md](../THREAT_MODEL.md)). To let a verifier say "this record existed no later than T", the time has to come from outside the sealer.

## What it adds, and what it does not

It adds a statement, checkable offline, that the record's bytes existed no later than a time T vouched for by a time stamping authority (TSA), and an ordering statement from the sealing machine's TPM.

It does not add:

- *When the flight happened.* A stamp is an upper bound on when the record existed. A flight from last week, stamped today, is stamped today.
- *Anything about the data before sealing.* The stamp covers the record's bytes, not the truth of the log inside them.
- *A lower bound.* The seal time stays a claim.

## Design

Two optional sources, each stored beside the record and never inside it. The signed record and its Merkle root do not change, and a record can be stamped long after sealing.

### 1. A countersignature from a TSA (UTC)

- **What is stamped.** The SHA-256 of the record file's exact bytes. Not the report, not the log.
- **How.** `sfr stamp <record.sfr> --tsa-url <url>` (a separate command, so `seal` and `verify` stay offline) sends an RFC 3161 request with that digest and a random nonce. The response, a CMS `SignedData` (RFC 5652) holding a `TSTInfo`, is written as `<name>.sfr.tst` after the nonce is checked.
- **Verification.** `sfr verify <record.sfr> ... --timestamp <name>.sfr.tst --tsa-anchor <tsa-ca.pem>` checks, in order: the token's digest equals the SHA-256 of the record file; the CMS signature chains to the TSA anchor the verifier supplied (same rules as `--trust-anchor`, including a CRL for every issuer unless `--no-crl-check`); the signer certificate has `id-kp-timeStamping` as its only extended key usage, marked critical (RFC 3161 section 2.3), and is valid at `genTime`; the `ESSCertIDv2` (RFC 5816) matches.
- **Renewal.** A token is checkable only while its certificates and algorithms are trusted. Archives renew the stamp (RFC 4998) before the TSA certificate expires. A renewal is a new token over the old one; the design stores a list, oldest first, and the verifier shows the earliest that verifies.
- **Alternative.** An OpenTimestamps proof (`<name>.sfr.ots`) anchors the same digest in a public blockchain. It needs no trusted authority, but takes hours to complete and the verifier needs the block header or a trusted list of them.

### 2. A clock attestation from the TPM (ordering, not UTC)

- **What it is.** `TPM2_GetTime` with the record's SHA-256 as `qualifyingData`, signed by an attestation key of the sealing TPM. The signed `TPMS_TIME_ATTEST` holds `clock` (milliseconds), `resetCount`, `restartCount` and `safe`.
- **What it shows.** This TPM signed this digest when its clock read this value. Two attestations from one TPM order two records, within one reset count. It is not UTC: the clock starts at an arbitrary value and the owner can set it (`TPM2_ClockSet`).
- **What the verifier needs.** The attestation key's public part from a source it trusts: a certificate from an operator CA it supplies, or the TPM maker's endorsement key chain. This is the same trust question as key custody. `sfr` checks the signature and chain, not how the CA decided.

## What the verifier prints

Only a verified token or proof may print "existed no later than":

```text
time      trusted: the record existed no later than 2026-10-19T12:00:04Z (RFC 3161 token from TSA "Example TSA", anchor sha256:3f...c1)
seal time 2026-10-18T15:00:00Z (claimed by the sealer, not proven)
```

With no token (the default, and today's behaviour):

```text
time      NOT PROVEN: no timestamp token given; the seal time is the sealer's claim
seal time 2026-10-18T15:00:00Z (claimed by the sealer, not proven)
```

A token that is given and does not verify is an integrity failure (exit 1) with the reason, never a quiet downgrade to "not proven". `--require-timestamp` makes a missing token a failure too. JSON gets `time_trusted`, `time_not_after_utc` and `time_source`. The report is generated from the record alone and does not mention a stamp.

## Standards

RFC 3161, RFC 5652 (CMS), RFC 5816, RFC 4998, RFC 5280 (already used), the TCG `TPM 2.0` library specification part 3 (`TPM2_GetTime`), and the OpenTimestamps proof format.

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| TSA unreachable when sealing | No token | Run `stamp` later; the stamp bounds from the later time. |
| TSA key compromised, or the TSA lies | A false "no later than T" | CRL at verification; the verifier chooses its anchors; two TSAs from different operators can both be required. |
| TSA certificate expires or its algorithm breaks | The old token stops verifying | Renewal tokens; the earliest verifying token is shown. |
| TPM reset, replaced, or clock set | Clocks not comparable | `resetCount` and `safe` are shown; comparison across a reset is refused. |
| Attestation key not tied to the sealing key | Shows a TPM saw the digest, not that this key's holder did | An operator CA issues both, or the claim is labelled unattested. |
| OpenTimestamps proof incomplete | No proof yet | Printed as incomplete, not as a time. |

Only `sfr stamp` uses the network, and only when asked.

## Size

Small to medium. A `stamp` command, a CMS and `TSTInfo` reader, a verify option, tests against a locally run TSA, and docs. The DER code in `crates/sfr/src/certs.rs` covers certificates and CRLs; CMS adds a few hundred lines, and the Ed25519-only signature rule must widen to the algorithms TSAs use, commonly RSA or ECDSA. About three engineer-weeks. The TPM attestation is another week plus key provisioning; OpenTimestamps a further week and a dependency decision.
