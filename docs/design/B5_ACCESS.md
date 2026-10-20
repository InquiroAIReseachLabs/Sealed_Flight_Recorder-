# B5: access to a record

Design only; not built. Two needs hide behind "access". One is *showing less*: giving someone one event or one rule result without the whole flight. The other is *knowing who looked*. The first can be done with the Merkle tree the record already has, plus one change. The second cannot be done by `sfr` alone, and this page says what it needs.

## What it adds, and what it does not

It adds:

- *Selective disclosure.* A holder shows one leaf (an event, a result, a sealed topic digest) with a proof that it belongs to a record whose signature the recipient can check. The recipient learns that leaf, the record's size and each section's leaf count, and nothing about the other leaves.
- *Encrypted storage of the original log, off by default*, so a log can be kept and sent without everyone who handles the file reading it. The original ULog stays byte for byte what the flight controller wrote.

It does not add:

- *A guarantee that what was hidden was harmless.* The recipient can ask for more.
- *Anything about who accessed what*, without the witness described below.
- *Secrecy of the record's existence, size or section counts.* The signature covers them.

## Design

### Selective disclosure by inclusion proof

A record's leaves are hashed into a Merkle tree (RFC 6962 shape). The signature covers the root, the tree size and, since schema 3, each section's leaf count ([RECORD_FORMAT.md](../RECORD_FORMAT.md)). An inclusion proof for one leaf is the list of sibling hashes from the leaf to the root, the audit path of RFC 9162 section 2.1.3.

A *disclosure* file holds the leaf's canonical JSON and section, its index and audit path, and what the recipient needs to check the signature: the seal context leaf (key fingerprint, schema, claimed seal time), the root, the tree size, the section counts and the signature. The recipient hashes the leaf, walks the path to a root, compares it with the signed root, and verifies the signature. `sfr disclose <record.sfr> --leaf <kind>[:<id>] --out <file>` makes it; `sfr verify-disclosure <file> --pubkey <sfr.pub>` checks it. Neither needs the log.

### The one format change: salted leaves

An unsalted leaf is the hash of a short, guessable value; an event is a few small integers and names. Someone holding the root and a disclosed audit path knows the *hash* of each sibling and can test guesses against it ("was the command `22`?" is one hash away). Omitting a leaf hides it only if its hash cannot be guessed.

So a new schema version hashes each leaf with a random salt: SHA-256 of `0x00`, the section tag, a sixteen-byte salt and the canonical bytes (`merkle.salted` in the record). The salts are not in the signed record, because that would defeat the purpose. `seal --salt-leaves` writes them to `<name>.sfr.salts`, which stays with the sealer, and the record says `merkle.salted`. Disclosing a leaf includes its salt. Verifying the complete record needs the whole salts file, which is as sensitive as the log. Unsalted sealing stays the default and keeps today's format.

### Optional encryption of the original log

`sfr seal --encrypt-log-to <age recipient>` (off by default) writes an `age` file (`age-encryption.org/v1`, X25519, ChaCha20-Poly1305) of a *copy* of the log beside the record. `sfr` never changes, moves or deletes the original. The record holds the SHA-256 of the plaintext, so a person who decrypts gets bytes that `verify --ulog` accepts. The record does not bind to the encrypted copy, so storing or mailing it proves nothing, and encryption is not access control after decryption.

## What needs a witness or transparency log

Three things cannot be done by the sealer and verifier alone, because the sealer controls everything either holds:

1. That no record was left out or replaced (the end of a chain, B2).
2. That the sealer did not show two histories to two audiences (equivocation).
3. Who accessed what. An access log kept only by the operator can lose entries.

The design for all three is the same: an append-only Merkle log of heads and access entries, signed by the operator, whose head is *cosigned by independent witnesses* who check that each new head extends the previous one with a consistency proof (RFC 9162 section 2.1.4). Existing designs should be adopted: the Certificate Transparency log format (RFC 6962, RFC 9162), the C2SP `tlog-cosignature` and witness specifications, and the Sigsum and Rekor logs. `sfr` would produce the entries and verify inclusion and consistency proofs offline. Running a log and witnesses is an operational service outside `sfr`.

An access entry holds the record's root, the recipient's key fingerprint, what was disclosed, the time (claimed, or B1's if present) and the operator's signature. Once the head is witnessed, it shows the operator *recorded* a disclosure. It cannot show that no other disclosure happened, because a file can be copied without a log entry.

## Standards

RFC 6962 and RFC 9162, RFC 8785 (canonical leaves, unchanged), the `age` format, C2SP `tlog-cosignature` and witness specifications, and the record format.

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Disclosure from unsalted leaves | Hidden leaves guessable | The verifier refuses a disclosure from a record with `merkle.salted` false, unless told the leaf set is public anyway. |
| Salts file lost | A salted record cannot be recomputed whole | Keep it as carefully as the key. |
| A disclosed leaf shows more than intended | A leaf is a whole event | `disclose` prints what it will reveal; section counts cannot be hidden. |
| No witness | The three guarantees above do not hold | Output says "not witnessed". |
| Witnesses collude | A false history is cosigned | Several witnesses from different operators; the verifier states how many cosigned. |

## Size

Large overall, small in pieces. Selective disclosure with salted leaves: a schema bump, two commands and a disclosure format, about three engineer-weeks. Optional `age` encryption: about one week, using the `age` crate (a dependency decision under the repository's supply chain rules). The log and witness part: about three weeks on the `sfr` side. Running a log and recruiting independent witnesses is an operational program, not a coding task, and nothing here should be described as available until it exists.
