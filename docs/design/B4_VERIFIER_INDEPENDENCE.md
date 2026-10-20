# B4: a verifier that does not trust the `sfr` binary

Design only; not built. A record is only worth what a checker's answer is worth. Today the only complete checker is `sfr verify`, written by the same people as `sfr seal`, built from the same code. A flaw in the shared code could make both agree on something wrong. [RECORD_FORMAT.md](../RECORD_FORMAT.md) already lets a reader check a golden record with `openssl`, `b3sum` and a short Python script; this page designs the next step: a second, minimal verifier written from the format alone, test vectors every verifier must agree on, and a plan for signing what is released.

## What it would add, and what it would not

It would add: a way for a person to check a record with software they can read in an afternoon, written without the `sfr` source in front of them; and a shared set of records, good and bad, with the answer each must give, so that two verifiers that disagree are found in a test run, not in a dispute.

It would not add: protection against a flaw in the format itself (two verifiers that follow a flawed format agree), or against a verifier substituted at the user's end (that is what the signing plan below is for).

## Design

### The minimal verifier

- **Scope.** The standalone checks of [RECORD_FORMAT.md](../RECORD_FORMAT.md) ("What a verifier checks"): canonical form, the field set, leaf order, the section tags and counts of the signed structure, the rules digest, the status, the key fingerprint, the Merkle root, and the Ed25519 signature. Deep verification (replaying the rules over a log) and certificate chains are not in it: they are `sfr`'s job, and a person who needs them uses `sfr`.
- **Input and output.** Two files and one key: the record and the public key. One line out per check, `ok` or `FAILED: <reason>`, and exit code zero only when every check passes. It prints the key fingerprint and says that the record does not show who holds the key.
- **Written from the document.** Its author works from RECORD_FORMAT.md and the vectors, not from `crates/`. Where the document is unclear, the fix goes into the document first, then into both programs. That is the point: the document must be enough.
- **Language and size.** Python 3 with only the standard library for the first one (the structural checks are already a short script in the document), and a second one in a language with a different JSON and hash stack (Go, using only its standard library and `crypto/ed25519`, whose verification rules differ from `ed25519-dalek`'s `verify_strict` in how it treats small-order keys). The difference is useful: the vectors include the weak-key and non-canonical-signature cases on which implementations are known to disagree, and the document says which answer `sfr` requires.
- **Where it lives.** A separate directory with its own tests and no dependency on the workspace, so it can be copied out; later possibly its own repository.

### Test vectors

A directory `testdata/vectors/` of records, each with a file naming the key and the expected result:

| Group | Contents |
|---|---|
| good | the golden examples; records with zero sealed topics and with several; one with zero events if the format allows it |
| structure | a leaf moved between sections; a count changed; a leaf dropped; the tree size changed |
| encoding | not canonical (whitespace, key order, escapes, a trailing newline, a byte order mark), a duplicate key, a number outside the safe range, a float, an invalid UTF-8 byte |
| signature | a flipped bit; a wrong key; the signature of another record; a signature valid under a lax verifier and invalid under a strict one (non-canonical `S`, a small-order key) |
| schema | an unknown schema version; an older one |
| semantic | a result list out of rule order; events out of sequence; a status that disagrees with the results |

Every verifier's test run reads the vectors and compares answers. `sfr` runs them in CI too, so a change to `sfr` that changes an answer shows up as a vector failure and needs a conscious edit.

### Release signing

What exists today ([RELEASE.md](../RELEASE.md)): CI builds and attests the files and creates a draft; it never signs. The release key holder signs `SHA256SUMS` offline with an Ed25519 key, the public key and its fingerprint are in the README, and the builds are reproducible (built twice from clean and compared).

The plan adds, for the verifier especially:

1. **Both verifiers in every release**, listed in `SHA256SUMS`, so one signature covers them.
2. **A second signature by a second person**, made offline on the same `SHA256SUMS`, with a published rule that a release counts only with both. Two keys held by two people turn a single stolen key into a non-event.
3. **The public keys and their fingerprints in three places that do not share an owner**: the README, the repository's tagged release notes, and a printed or out-of-band copy given to evaluators.
4. **A way to check without trusting the downloaded verifier**: the document's `openssl` and Python steps, which need nothing from the release.
5. **Build provenance** (a signed statement of the builder, source commit and inputs, such as the SLSA provenance format) beside the checksum, so a rebuild by a third party can be compared.
6. **A key rotation and revocation note**: how a retired release key is announced and how a verifier of an old record finds the key that was current then.

## Standards relied on

RFC 8785 (canonical JSON, for the encoding vectors), RFC 8032 (Ed25519) and the written account of its implementation differences, RFC 6962 (the tree), the format document itself, and for provenance the in-toto attestation and SLSA provenance formats.

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| The document is ambiguous | Two verifiers disagree on a vector | Fix the document, add a vector, change whichever program was wrong. |
| Both verifiers copy the same mistake | Agreement on a wrong answer | The second author must not read the first's code; vectors include the known hard cases; a third reader (a reviewer) works from the document alone. |
| Library differences (Ed25519 strictness, JSON parsing) | A record one accepts and the other refuses | The document names the required behaviour; vectors pin it. |
| The release signing key is stolen | Forged releases | Two signatures, offline keys, published fingerprints, rotation note. |
| An evaluator never checks the signature | The signature protects no one | The README quickstart shows the check as a step; the post-release workflow runs it. |
| The minimal verifier drifts behind `sfr` | Newer records unreadable | A schema is verifiable by the minimal verifier before it ships in `sfr` (the vectors for a schema are part of the change that adds it). |

## Size

Medium. The Python verifier is mostly the existing script in the document plus the signature step, a few days. The second-language verifier, about a week and a half. The vector set and its runner in CI, a week. The signing plan is process more than code: the second key holder, the documents, the provenance step in the release workflow, about a week of work plus the human arrangements.
