# Design notes: five things a record does not do yet

These are design documents. **None of them is built.** `sfr` does what [README.md](../../README.md) and [THREAT_MODEL.md](../THREAT_MODEL.md) say. Each page covers what the change would add, what it would still not do, the standards it relies on, how it can fail, and its size.

Each page answers one question that a signed record cannot answer today:

| Page | Question | Answer |
|---|---|---|
| [B1: trusted time](B1_TRUSTED_TIME.md) | When did this record exist? | Only a time from outside the sealer can say. Add a detached RFC 3161 countersignature, and a TPM clock attestation for ordering. |
| [B2: chain](B2_CHAIN.md) | Is a record missing from the middle? | Link each record to the one before and count with a TPM counter. A missing last record stays invisible without a witness. |
| [B3: seal at the source](B3_SEAL_AT_SOURCE.md) | What happened between flight and seal? | Seal on the companion computer at the disarm edge, and record the remaining gap. |
| [B4: verifier independence](B4_VERIFIER_INDEPENDENCE.md) | Must I trust the `sfr` binary to check a record? | No. Write a small second verifier from the format, with shared test vectors. |
| [B5: access](B5_ACCESS.md) | Can I show one event without the whole flight? | Yes, with Merkle inclusion proofs over salted leaves. Proving who looked needs an outside witness. |

All five share these rules:

- A record shows it has not changed since it was sealed, by the holder of one key. It does not show the data was accurate when sealed. No design here changes that.
- A format change is a new schema version, and a verifier refuses a schema it does not know ([RECORD_FORMAT.md](../RECORD_FORMAT.md)).
- Anything that needs the network is optional, off by default, and never part of `seal` or `verify` unless asked. `sfr` runs offline ([SPEC.md](../SPEC.md), B1.1).

If all five were built, the order would be B4 (it lets others check every later change), then B1, B3, B2, and B5 last, because salted leaves change how every leaf is hashed.

Until a page is built, the README is the whole truth: `sfr` shows no change since sealing by the key holder, the seal time is the sealer's claim, and nobody checks a chain of records. Do not describe `sfr` as doing what these pages describe.
