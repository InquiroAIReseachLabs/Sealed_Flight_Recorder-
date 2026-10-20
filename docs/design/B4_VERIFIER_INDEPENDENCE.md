# B4: a verifier that does not trust the `sfr` binary

Design only; not built. A record is worth what the checker's answer is worth. Today the only complete checker is `sfr verify`, written by the same people as `sfr seal` and built from the same code, so a flaw in the shared code could make both agree on something wrong. [RECORD_FORMAT.md](../RECORD_FORMAT.md) already lets a reader check a golden record with `openssl`, `b3sum` and a short Python script. This page designs the next step: a second minimal verifier written from the format alone, test vectors every verifier must agree on, and a plan for signing what is released.

## What it adds, and what it does not

It adds software a person can read in an afternoon, written without the `sfr` source in front of its author, and a shared set of good and bad records with the answer each must give. Verifiers that disagree are found in a test run, not in a dispute.

It does not protect against a flaw in the format itself (two verifiers following a flawed format agree), or against a verifier substituted at the user's end (that is what the signing plan is for).

## Design

### The minimal verifier

- **Scope.** The standalone checks of [RECORD_FORMAT.md](../RECORD_FORMAT.md) ("What a verifier checks"): canonical form, field set, leaf order, section tags and counts, rules digest, status, key fingerprint, Merkle root, Ed25519 signature. Deep verification and certificate chains stay in `sfr`.
- **Interface.** A record and a public key in; one line per check out, `ok` or `FAILED: <reason>`; exit zero only if all pass. It prints the key fingerprint and says the record does not show who holds the key.
- **Written from the document.** The author works from RECORD_FORMAT.md and the vectors, not from `crates/`. Where the document is unclear, the fix goes into the document first, then both programs.
- **Languages.** Python 3 with only the standard library first (the structural checks are already a short script in the document). Then Go with the standard library and `crypto/ed25519`, whose treatment of small-order keys differs from `ed25519-dalek`'s `verify_strict`. That difference is useful: the vectors include the weak-key and non-canonical-signature cases on which implementations disagree, and the document says which answer `sfr` requires.
- **Placement.** A separate directory with its own tests and no dependency on the workspace, so it can be copied out.

### Test vectors

`testdata/vectors/` holds records, each with a file naming the key and the expected result:

| Group | Contents |
|---|---|
| good | the golden examples; records with zero sealed topics and with several |
| structure | a leaf moved between sections; a count changed; a leaf dropped; the tree size changed |
| encoding | not canonical (whitespace, key order, escapes, trailing newline, byte order mark), a duplicate key, a number outside the safe range, a float, invalid UTF-8 |
| signature | a flipped bit; a wrong key; another record's signature; one valid under a lax verifier and invalid under a strict one (non-canonical `S`, a small-order key) |
| schema | an unknown version; an older one |
| semantic | results out of rule order; events out of sequence; a status that disagrees with the results |

Every verifier's tests compare answers on the vectors. `sfr` runs them in CI, so a change that alters an answer shows up as a vector failure and needs a deliberate edit.

### Release signing

Today ([RELEASE.md](../RELEASE.md)): CI builds and attests the files and creates a draft; it never signs. The release key holder signs `SHA256SUMS` offline with an Ed25519 key, and builds are reproducible (built twice from clean and compared). The plan adds:

1. Both verifiers in every release, listed in `SHA256SUMS`, so one signature covers them.
2. A second signature by a second person on the same `SHA256SUMS`, with a published rule that a release counts only with both. One stolen key then no longer matters.
3. Public keys and fingerprints in three places with different owners: the repository, the tagged release notes, and an out-of-band copy.
4. A check that does not trust the downloaded verifier: the document's `openssl` and Python steps.
5. Build provenance (a signed statement of builder, source commit and inputs, such as SLSA provenance) beside the checksum, so a third party can compare a rebuild.
6. A rotation and revocation note: how a retired release key is announced and how a verifier of an old record finds the key that was current then.

## Standards

RFC 8785 (canonical JSON), RFC 8032 (Ed25519), RFC 6962 (the tree), the format document, and the in-toto attestation and SLSA provenance formats.

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| The document is ambiguous | Two verifiers disagree on a vector | Fix the document, add a vector, change whichever program was wrong. |
| Both verifiers copy one mistake | Agreement on a wrong answer | The second author does not read the first's code; the vectors include the known hard cases; a reviewer works from the document alone. |
| Library differences (Ed25519 strictness, JSON parsing) | One accepts a record the other refuses | The document names the required behaviour; vectors pin it. |
| The release signing key is stolen | Forged releases | Two signatures, offline keys, published fingerprints, rotation note. |
| The minimal verifier falls behind `sfr` | Newer records unreadable | A schema's vectors ship with the change that adds it. |

## Size

Medium. The Python verifier is mostly the script already in the document plus the signature step: a few days. The Go verifier: about a week and a half. The vector set and its CI runner: a week. The signing plan is mostly process (a second key holder, documents, a provenance step in the release workflow): about a week plus the human arrangements.
