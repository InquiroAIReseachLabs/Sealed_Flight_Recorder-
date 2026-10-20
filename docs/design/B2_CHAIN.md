# B2: a chain of records

Design only; not built. Today each record stands alone. Anyone who holds the signing key's records can leave one out, show an old one as the newest, or hand over only the good ones, and no record shows it ([THREAT_MODEL.md](../THREAT_MODEL.md)). This page designs a link from each record to the one before it, and a counter that only a TPM can advance.

## What it would stop, and what it would not

It would stop:

- *A record removed from the middle.* The next record names the removed one's root, so a verifier that holds the later record sees a gap.
- *Reordering and back-dating inside a chain.* The counter orders the records and the link ties each one to its predecessor, so a new record cannot be given an old position.
- *Quietly replacing one record by another.* The replacement has a different root, so the next record's link no longer matches.

It would not stop:

- *Removal of the last records.* A chain that ends at record seven looks complete; nobody knows record eight exists. Only a copy of the head held somewhere the sealer does not control (a witness, B5) shows that.
- *A fork.* A key holder can seal two different records that both claim the same predecessor and show each to a different audience. Detecting that needs a place where all heads are published.
- *A new chain.* The holder can start again with a fresh key, or, with the TPM owner's authority, clear the counter.
- *Anything about the content of a record.*

## Design

### New fields (a new schema version, so a verifier refuses it until it knows it)

In the `seal` object:

| Member | Value |
|---|---|
| `chain_id` | a random 16-byte value in hex, made once per vehicle and key and stored with the key; every record of one chain carries the same value |
| `sequence` | the position in the chain, an integer from one; with a TPM, the counter value the TPM returned |
| `prev_record_root` | the Merkle root of the previous record in the chain, or sixty-four zeros for the first |

They sit in the seal context leaf, so they are covered by the signature like everything else. `sequence` and `prev_record_root` give the verifier the check it can do alone: given two records of one chain, the later one names the earlier one's root and its `sequence` is one higher.

### The TPM counter

- At setup, an NV index of type counter is defined (`TPM 2.0` `TPM2_NV_DefineSpace`, attribute `TPMA_NV_COUNTER`) with the authorisation policy of the operator. The TPM allows only increments (`TPM2_NV_Increment`), never a decrement, and the value survives power loss.
- `seal` increments the counter, reads it, and signs. The record's `sequence` is the value read. The attestation (`TPM2_NV_Certify`, qualifying data the record's root) is stored beside the record as `<name>.sfr.nv`, so a verifier can check that this TPM, with this attestation key, held that counter value when it signed that root.
- If the seal fails after the increment, the next record skips a number. That is a gap by design: the verifier shows it as "sequence jumps from 7 to 9" and a person decides, with the sealer's note, whether record eight was lost or never completed. A gap is never silently accepted and never proven to be a deletion.

Without a TPM the chain still exists (the `sequence` is then a software counter kept in a file next to the key), and the verifier labels it `unattested`: the holder can reset it.

### The verifier

`sfr chain <record.sfr>... --pubkey <sfr.pub>` (a new command) verifies each record as `verify` does and then, for records of one `chain_id`, checks that the `sequence` values are strictly increasing, and that each record whose predecessor is present names its root. It prints one line per link, and a summary:

```text
chain     7 records, sequence 1 to 7, every link matches
```

or, for example:

```text
chain     GAP: sequence 4 is followed by 6; record 5 is not among the files given
chain     BREAK: record 6 names previous root 9c...e1, but record 5 has root 41...b7
chain     FORK: two records claim sequence 5 after the same predecessor (roots 41...b7 and 77...02)
chain     NOT CHECKED: the last record given is sequence 7; the chain's end is not known
```

The last line is always printed: the verifier states that it does not know whether later records exist.

## Standards relied on

`TPM 2.0` library specification part 3 (`TPM2_NV_DefineSpace`, `TPM2_NV_Increment`, `TPM2_NV_Certify`, `TPMA_NV_COUNTER`), RFC 6962 and RFC 9162 for the idea that a head (a root and a size) is what a witness cosigns (B5), and the existing record format ([RECORD_FORMAT.md](../RECORD_FORMAT.md)).

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Two vehicles share one key | One chain interleaved, constant gaps | One key per vehicle is already the guidance ([INTEGRATION_NOTES.md](../INTEGRATION_NOTES.md)); `chain_id` is per key. |
| The TPM is cleared or replaced | The counter restarts | A new `chain_id` is required at setup; a verifier that sees the same key with a lower `sequence` reports it as a restart, not as a link. |
| Power fails between increment and signing | A gap | Shown as a gap, never hidden. |
| The sealer deletes the newest records | Invisible | Named in the output ("end not known") and in the threat model; closed only by B5's witness. |
| A fork | Two valid-looking chains | Reported when both are present; prevented only by a witness. |
| Counter authorisation leaks | Anyone can advance the counter, producing gaps, not forgeries | Authorisation policy tied to the seal process; the signature is still needed for a record. |
| A software counter | Resettable | Labelled unattested. |

## Size

Medium. A schema bump (with the migration rule of A5: refuse older), new seal fields, a `chain` command and its tests, TPM calls through `tpm2-tools` as `tpm-sealed` already does, and the NV attestation reader. About three engineer-weeks, plus one for the hardware tests against `swtpm`, which implements the NV commands.
