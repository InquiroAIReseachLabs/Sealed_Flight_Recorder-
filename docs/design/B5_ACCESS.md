# B5: access to a record

Design only; not built. Two different needs hide behind "access". One is *showing less*: giving someone one event, or one rule result, without handing over the whole flight. The other is *knowing who looked*: a trustworthy account of who read or received what. The first can be done with the Merkle tree the record already has, with one change. The second cannot be done by `sfr` alone, and this page says exactly what it needs.

## What it would add, and what it would not

It would add:

- *Selective disclosure.* A holder shows one leaf (an event, a result, a sealed topic digest) together with a proof that the leaf is part of a record whose signature the recipient can check. The recipient learns that leaf, the size of the record, and how many leaves each section has, and nothing else about the others.
- *Encrypted storage of the original log, off by default*, so a log can be kept and sent without being readable by everyone who handles the file, while the original ULog stays byte for byte what the flight controller wrote.

It would not add:

- *A guarantee that what was hidden was harmless.* A disclosed leaf is true to the record; the hidden ones are simply not shown. The recipient can ask for more.
- *Anything about who accessed what*, without the witness described below.
- *Secrecy of the record's existence, size or section counts.* The signature covers them.

## Design

### Selective disclosure by inclusion proof

A record's leaves are hashed into a Merkle tree (RFC 6962 shape) and the signature covers the root, the tree size and, in schema 3, the number of leaves in each section ([RECORD_FORMAT.md](../RECORD_FORMAT.md)). An inclusion proof for one leaf is the list of sibling hashes from the leaf to the root, the audit path of RFC 9162 section 2.1.3.

A *disclosure* is a file with:

1. the leaf's canonical JSON, and its section (so the recipient can compute the tagged leaf hash);
2. the leaf's index and the audit path;
3. what the recipient needs to check the signature: the record's seal context leaf (it holds the key fingerprint, the schema and the claimed seal time), the root, the tree size, the section counts, and the signature.

The recipient computes the leaf hash, walks the path to a root, compares it with the signed root, and verifies the signature with the public key. `sfr disclose <record.sfr> --leaf <kind>[:<id>] --out <file>` makes it; `sfr verify-disclosure <file> --pubkey <sfr.pub>` checks it. Nothing needs the log.

### The one change the format needs: salted leaves

An unsalted leaf is a hash of a short, guessable value. An event is a few small integers and names. Someone holding the root and a disclosed audit path knows the *hash* of each sibling, and can test guesses against it: "was the command `22`?" is one hash away. Hiding a leaf by omitting it only works if its hash cannot be guessed.

So a new schema version hashes each leaf with a random salt: the leaf hash is SHA-256 of `0x00`, the section tag, a 16-byte salt, and the canonical bytes. The salts are not part of the signed record (they would defeat the purpose); `seal` writes them to a separate file `<name>.sfr.salts` that stays with the sealer. A holder who discloses a leaf includes its salt. Without the salts file nobody can recompute any leaf, so nobody can verify that a *complete* record is intact; so the salts must travel with the record for anyone who needs the whole thing, and for them the file is as sensitive as the log. The record itself stays verifiable as it is today only if the salts are stored in it (the default): the salted mode that supports disclosure is therefore a choice made when sealing (`--salt-leaves`), and the choice is visible in the record (`merkle.salted`).

### Optional encryption of the original log

- `sfr seal --encrypt-log-to <age recipient>` (off by default) writes an `age` file (`age-encryption.org/v1`, X25519 recipients, ChaCha20-Poly1305) of a *copy* of the log beside the record. The original ULog is never changed, moved or deleted by `sfr`. The record still holds the SHA-256 of the original plaintext; a person who decrypts gets bytes that `verify --ulog` accepts.
- The encrypted copy is not the thing the record binds to, so storing or mailing it proves nothing by itself; the recipient decrypts and verifies.
- Encryption is not access control after decryption: whoever decrypts has the log.

## What needs a witness or a transparency log

Three things cannot be done by the sealer and the verifier alone, because the sealer controls everything either of them holds:

1. **That no record was left out or replaced** (the end of a chain, B2): a copy of the newest head must be held by someone else.
2. **That the sealer did not show two different histories to two audiences** (equivocation).
3. **Who accessed what.** An access log kept only by the operator can have entries removed, or whole stretches left off the end. An operator that wants outsiders to believe its access log needs the same property as a record chain.

The design for all three is the same: an append-only Merkle log of heads and access entries, signed by the operator, whose current head is *cosigned by independent witnesses* who check that each new head extends the previous one with a consistency proof (RFC 9162 section 2.1.4). A verifier then asks: is this entry included in a head that enough witnesses cosigned, and is that head consistent with the earlier ones I saw? Existing designs to adopt rather than invent: the Certificate Transparency log format (RFC 6962, RFC 9162), the `tlog-cosignature` and witness protocol of the C2SP specifications, and the Sigsum and Rekor logs. `sfr` would produce the entries and verify inclusion and consistency proofs offline from files; running a log and a witness is an operational service, outside `sfr`, and not built here.

An access entry would hold: the record's root, the recipient's key fingerprint, what was disclosed (the leaf kinds or the whole log), the time (claimed, with B1 if present) and the operator's signature. It proves that the operator *recorded* a disclosure, once the head is witnessed. It cannot prove that no *other* disclosure happened, since a copy of a file can be made without a log entry.

## Standards relied on

RFC 6962 and RFC 9162 (the tree, inclusion and consistency proofs), RFC 8785 (canonical leaves, unchanged), the `age` file format and its recipients, C2SP `tlog-cosignature` and witness specifications, and the existing record format.

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Unsalted leaves with disclosure | Hidden leaves guessable from their hashes | Salting is required for the disclosure mode; the verifier refuses a disclosure of an unsalted record (`merkle.salted` false) unless told the leaf set is public anyway. |
| The salts file is lost | The full record can no longer be recomputed in salted mode | Default keeps the salts in the record for whole-record verification; disclosure mode is a deliberate choice, and the salts file is kept with the same care as the key. |
| A disclosed leaf shows more than intended | A leaf is the whole event with its fields | Choose the leaf; `disclose` prints what it will reveal and the section counts, which cannot be hidden. |
| Sizes leak | The recipient sees the tree size and counts | Stated; they are signed. |
| An encrypted copy is mistaken for the evidence | Someone stores only the age file | The record binds to the plaintext's digest; the encrypted copy is labelled as a convenience in its name and in the output. |
| `age` recipient key lost | The copy cannot be read | The original is untouched; the operator keeps the original as before. |
| No witness exists | The three guarantees above do not hold | `sfr` says so: the output of a chain or an access log without a witnessed head is labelled "not witnessed". |
| A witness collusion | A false history is cosigned | Several witnesses, run by different operators; the verifier states how many cosigned. |

## Size

Large for the whole page; small for its pieces. Selective disclosure with salted leaves: a schema bump, two commands and a disclosure format, about three engineer-weeks, and the one design decision (salts in the record or beside it) to settle first. Optional `age` encryption: about one week, using the `age` crate (a dependency decision under the repository's supply chain rules). The log and witness part: `sfr` side (entries, proofs, offline verification) about three weeks; running a log and recruiting independent witnesses is an operational program of work, not a coding task, and nothing here should be described as available until it exists.
