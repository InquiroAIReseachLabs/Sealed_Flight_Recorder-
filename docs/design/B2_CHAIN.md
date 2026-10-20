# B2: a chain of records

Design only; not built. Today each record stands alone. Whoever holds the signing key can leave a record out, show an old one as the newest, or hand over only the good ones, and nothing shows it ([THREAT_MODEL.md](../THREAT_MODEL.md)). This page designs a link from each record to the one before it, and a counter only a TPM can advance.

## What it stops, and what it does not

It stops a record removed from the middle (the next record names the removed one's root), reordering and back-dating (the counter orders records, the link ties each to its predecessor), and replacing one record with another (the next link no longer matches).

It does not stop:

- *Removal of the last records.* A chain ending at record seven looks complete. Only a copy of the head held where the sealer cannot change it (a witness, B5) shows more exist.
- *A fork.* A key holder can seal two records that claim the same predecessor and show each to a different audience. Detecting that needs a place where all heads are published.
- *A new chain.* The holder can start again with a fresh key, or clear the counter with the TPM owner's authority.
- *Anything about a record's content.*

## Design

### New fields (a new schema version, which a verifier refuses until it knows it)

In the `seal` object:

| Member | Value |
|---|---|
| `chain_id` | a random sixteen-byte value in hex, made once per vehicle and key and stored with the key |
| `sequence` | the position in the chain, from one; with a TPM, the counter value it returned |
| `prev_record_root` | the Merkle root of the previous record, or sixty-four zeros for the first |

They sit in the seal context leaf, so the signature covers them. A verifier can check alone that the later of two records names the earlier one's root and has `sequence` one higher.

### The TPM counter

At setup an NV index of type counter is defined (`TPM2_NV_DefineSpace`, `TPMA_NV_COUNTER`). The TPM only increments it (`TPM2_NV_Increment`), and the value survives power loss. `seal` increments it, reads it, and signs; `sequence` is the value read. The attestation (`TPM2_NV_Certify`, qualifying data the record's root) is stored as `<name>.sfr.nv`, so a verifier can check that this TPM held that value when it signed that root.

If a seal fails after the increment, the next record skips a number. The verifier shows the gap and a person decides whether the record was lost or never completed. A gap is never accepted silently and never proven to be a deletion.

Without a TPM the counter is a file next to the key, labelled `unattested` because the holder can reset it.

### The verifier

`sfr chain <record.sfr>... --pubkey <sfr.pub>` verifies each record as `verify` does, then checks per `chain_id` that `sequence` strictly increases and each present predecessor is named by root:

```text
chain     7 records, sequence 1 to 7, every link matches
chain     GAP: sequence 4 is followed by 6; record 5 is not among the files given
chain     FORK: two records claim sequence 5 after the same predecessor (roots 41...b7 and 77...02)
chain     NOT CHECKED: the last record given is sequence 7; the chain's end is not known
```

The last line always prints: the verifier cannot know whether later records exist.

## Standards

`TPM 2.0` library specification part 3 (`TPM2_NV_*`); RFC 6962 and RFC 9162 for heads that a witness cosigns (B5); [RECORD_FORMAT.md](../RECORD_FORMAT.md).

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Two vehicles share one key | Interleaved chain, constant gaps | One key per vehicle ([INTEGRATION_NOTES.md](../INTEGRATION_NOTES.md)). |
| TPM cleared or replaced | Counter restarts | New `chain_id` required; a lower `sequence` under the same key is reported as a restart. |
| Newest records deleted | Invisible | Output says "end not known"; closed only by B5's witness. |

## Size

Medium. A schema bump, new seal fields, a `chain` command and tests, TPM calls through `tpm2-tools` as `tpm-sealed` already does, and the NV attestation reader. About three engineer-weeks, plus one for hardware tests against `swtpm`, which implements the NV commands.
