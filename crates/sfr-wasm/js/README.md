# Sealed Flight Record engine bundle

The `sfr` engine for a web page: seal a PX4 log, verify a record, verify a record with its log, and the tamper demo, in the browser. For the same log, rules, baseline, key and seal time it writes the same record and report bytes as the `sfr` command line, and returns what `sfr verify` prints together with each mismatch split into its parts.

`docs/SANDBOX.md` in the Sealed Flight Record repository documents the JavaScript API (`sfr.js`), the results, and the files below. `BUILDINFO` names the source commit; `SHA256SUMS` lists the SHA-256 of every other file (`sha256sum -c SHA256SUMS`).

| File | What it is |
|---|---|
| `sfr.js` | the API module the page imports |
| `sfr-worker.js` | the engine's thread, started by `sfr.js` |
| `pkg/` | the engine (WebAssembly) and its glue |
| `rules/` | the example rules files |
| `samples/` | the tamper demo's sample log (gzip), its baseline, its provenance and license notices |

Serve the directory as it is, from the same origin as the page that imports `sfr.js`. Files a person chooses are read in the browser and never uploaded.
