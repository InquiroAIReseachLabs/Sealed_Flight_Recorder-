# Design notes: five things a record does not do yet

These are design documents. **None of them is built.** `sfr` today does what [README.md](../../README.md) and [docs/THREAT_MODEL.md](../THREAT_MODEL.md) say, and these pages do not change that. Each one names what a change would add, what it would still not do, the standards it would rely on, how it can fail, and how large it is.

The five answer one question each, taken from what a signed record cannot show today:

| Page | The question | One-line answer |
|---|---|---|
| [B1: trusted time](B1_TRUSTED_TIME.md) | When did this record exist? | Only a time supplied from outside the sealer can say, so add a detached RFC 3161 countersignature, and a TPM clock attestation for ordering. |
| [B2: chain](B2_CHAIN.md) | Is a record missing from the middle? | Link each record to the one before it and count with a TPM counter. A missing last record stays invisible without a witness. |
| [B3: seal at the source](B3_SEAL_AT_SOURCE.md) | What happened between the flight and the seal? | Seal on the companion computer at the disarm edge, and record and label the gap that remains. |
| [B4: verifier independence](B4_VERIFIER_INDEPENDENCE.md) | Must I trust the `sfr` binary to check a record? | No: a small second verifier written from the format, with shared test vectors, and a signing plan for both. |
| [B5: access](B5_ACCESS.md) | Can I show one event without showing the flight? | Yes, by Merkle inclusion proofs with salted leaves. Proving who looked at what needs an outside witness. |

What every page shares:

- A record proves it has not changed since it was sealed, by the holder of one key. It never proves the data was accurate when it was sealed ([README.md](../../README.md), "What a record proves"). No design here changes that sentence, and none may be described as doing so.
- Changes to the record format are a new schema version, and a verifier refuses a schema it does not know ([RECORD_FORMAT.md](../RECORD_FORMAT.md)).
- Anything that needs a service on the network is optional, off by default, and never part of `seal` or `verify` unless the person asks: `sfr` runs offline ([SPEC.md](../SPEC.md), B1.1).

Order of work if all five were built: B4 first (it makes every later change checkable by someone else), then B1, B3, B2, and B5 last because salted leaves change how every leaf is hashed.

## Not built, and why that matters for what you say about `sfr`

Until a page above is built and merged, the README's "What a record proves" is the whole truth: `sfr` shows no change since sealing by the key holder, with a seal time that is the sealer's claim and a chain of records that nobody checks. Do not describe `sfr` as doing what these pages describe.
