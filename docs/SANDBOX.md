# Sandbox: the engine bundle for the browser

The engine bundle runs `sfr` in a web page: seal a PX4 log, verify a record, verify a record with its log, and the tamper demo of `scripts/run_demo.sh`. It is a v1.0 evaluation release. The page that invited evaluators use is built and hosted separately; this repository delivers the bundle, its JavaScript API, and the tests that hold it to the command line.

## What it promises

- **One engine.** The bundle runs `crates/sfr-wasm`, the `sfr-core` engine built for WebAssembly, with the command line's crypto crates (`sha2`, `ed25519-dalek`, `blake3`). For the same log, rules, baseline, key and seal time it writes a record and a report byte-identical to `sfr seal`, and returns the text `sfr seal` and `sfr verify` print (SPEC B1.10 Sandbox). CI checks this on every golden log in Chromium, Firefox and WebKit.
- **Files a person chooses are read in the browser and never uploaded.** The bundle sends no file and no request body anywhere. It fetches files of its own bundle only, with GET, from the origin that serves it: the engine and the two example rules files when `load()` runs, and the sample log, its baseline and its manifest only when `loadSample()` or `runTamperDemo()` runs. CI checks, in each browser, that sealing and verifying files from disk make no request at all, that the tamper demo makes only those same-origin GET requests, that no request carries a body, and that no request goes to another host.
- **Evaluation keys only.** `load()` makes an Ed25519 key in the browser (seed from the browser's CSPRNG), labeled `EVALUATION KEY (sandbox, in-browser)` in the record, custody `file-evaluation`. Its seed stays in the worker's memory and is gone when the page closes; only its public key leaves, as PEM. An evaluation key file from `sfr keygen --evaluation-only` may be given instead. Operational records are sealed with the command line and a hardware key.
- **Without a baseline**, the engine seals against an empty one (firmware `none`, no parameters; `NO_BASELINE` in `crates/sfr-wasm/src/lib.rs`), so R2 and R3 fail and say what they found. Nothing is assumed.
- **Limit.** One log or record of at most 100 MiB (104,857,600 bytes). A larger file is refused, unread, with exit 4 and a message naming the limit (`docs/LIMITS.md`). The engine streams the log through a worker, so its own memory stays small; CI reports the browser's peak memory for the largest allowed log.

## The bundle

`scripts/build_engine.sh <out-dir>` builds it; every CI run keeps it as the artifact `sfr-engine-<commit>`.

| File | What it is |
|---|---|
| `sfr.js` | the API module a page imports |
| `sfr-worker.js` | the engine's thread, started by `sfr.js` |
| `pkg/sfr_wasm.js`, `pkg/sfr_wasm_bg.wasm` | the engine and its glue (`wasm-bindgen` 0.2.129) |
| `rules/rules.default.toml`, `rules/rules.extended.toml` | the example rules |
| `samples/mc_flight_1.ulg.gz` | the tamper demo's sample log, gzip-compressed |
| `samples/v1.17.0_mc_flight_1.params` | its baseline |
| `samples/mc_flight_1.provenance.md`, `samples/NOTICE.md`, `samples/TESTDATA.md` | its provenance and license notices |
| `samples/samples.json` | its name, repository path, size, SHA-256, compressed size, and the parameter the demo changes |
| `README.md` | a short guide to these files |
| `BUILDINFO` | version, source commit, `rustc` and `wasm-bindgen` versions, the sample's SHA-256 |
| `SHA256SUMS` | the SHA-256 of every other file: `sha256sum -c SHA256SUMS` |

`scripts/check_engine_bundle.sh <dir> <commit>` checks that a bundle is whole: every file present, `SHA256SUMS` listing exactly the other files with matching digests, and `BUILDINFO` naming the commit. CI runs it on every bundle it keeps.

**Serving it.** Serve the directory as it is, from the same origin as the page that imports `sfr.js` (a browser starts a module worker only from its own origin). The page's Content-Security-Policy must allow `script-src 'self' 'wasm-unsafe-eval'`, `worker-src 'self'` and `connect-src 'self'`; nothing else is needed. The sample log is about 8.5 MB, and is stored and sent gzip-compressed (about 3.1 MB; `samples/samples.json`, written by `scripts/build_engine.sh`, gives both sizes exactly). The bundle unpacks it in the browser with `DecompressionStream`, so it travels compressed on any static host; a host that itself sets `Content-Encoding: gzip` on the file also works. `loadSample()` reports the transfer size.

**The sample.** `mc_flight_1.ulg` is the smallest golden log that shows both tamper changes: it has COMMAND events to change in the record and float parameters at log start to change in the log, and every rule passes on it. `failsafe_gps_loss.ulg` also shows them, at 10.2 MB (3.8 MB compressed), with R4 failing on its GPS failsafe; `scripts/build_engine.sh` names the sample in one place.

## JavaScript API

```js
import * as sfr from './sfr-engine/sfr.js';

const { version, limits, sessionKey } = await sfr.load();
const sealed = await sfr.seal({ log: fileInput.files[0], rules: 'default', baseline: paramsFile });
const checked = await sfr.verifyWithLog({
  record: { name: sealed.recordName, data: sealed.record },
  publicKey: { name: 'sfr.pub', data: sessionKey.publicKeyPem },
  log: fileInput.files[0],
});
if (!checked.verified) console.log(checked.mismatch.kind, checked.mismatch.sealed, checked.mismatch.found);
```

A **file** argument is a `File`, a `Blob` with a `name`, or `{ name, data }` with `data` a `Blob`, `ArrayBuffer`, typed array or string. The name appears in messages and output as the command line shows a file name. Every function returns a promise. A function rejects only when it is called wrongly, when the browser cannot read a file, or when the engine has stopped (a WebAssembly trap, which the engine is built never to hit; the error says so); an input the engine refuses resolves to a result with its exit code and message.

| Function | What it does |
|---|---|
| `load()` | Starts the engine, fetches the example rules, makes the session's in-browser key. Resolves to `{ version, limits: { fileBytes, textBytes }, sessionKey: { keyId, fingerprint, publicKeyPem } }`. Later calls return the same. Every other function calls it first. |
| `newEvaluationKey()` | A new in-browser key: `{ keyId, fingerprint, publicKeyPem }`. |
| `seal({ log, rules, baseline, key, sealTime })` | `sfr seal`. `rules`: `'default'` (the default), `'extended'`, or a file. `baseline`: a file, or none (R2 and R3 then fail). `key`: `{ keyId }` from `newEvaluationKey()` or `load()`, or an evaluation key file; default the session key. `sealTime`: RFC 3339; default now. Resolves to a seal result. |
| `verify({ record, publicKey })` | `sfr verify --pubkey`, with the browser's clock as the verification time (the engine reads no clock): a record whose claimed seal time is more than 300 seconds later is refused. Resolves to a verify result. |
| `verifyWithLog({ record, publicKey, log })` | `sfr verify --pubkey --ulog`, with the same clock. Resolves to a verify result. |
| `loadSample()` | Fetches the sample on first use (later calls make no request): `{ name, path, size, sha256, log: File, baseline: File, baselinePath, parameter, notices: { provenance, license }, transfer: { gzBytes, compressedBytes, transferBytes, unpackedHere } }`. `transferBytes` is the size on the wire as the browser reports it (Resource Timing), or `null` where it does not. |
| `changeCommand(recordBytes)` | A copy of a record with one digit of the first COMMAND event's command id changed: `{ bytes, offset, from, to, description }`. |
| `changeParameter(logBlob, name, value)` | A copy of a log with float parameter `name` at log start set to `value`: `{ blob, offset, before, after, description }`. |
| `runTamperDemo({ onStep })` | Runs the demo on the sample (steps below), calling `onStep(step)` as each step ends. Resolves to `{ passed, seconds, sample, steps, error }`. |
| `engineMemoryBytes()` | The engine's WebAssembly memory, in bytes, as of its last reply. |

**Seal result.** When the record was written (`sealed: true`; exit 0, 1 or 2):

| Field | Value |
|---|---|
| `sealed` | `true` |
| `exitCode` | SPEC B1.4: 0 all rules PASS or N/A; 1 a rule FAIL; 2 a required topic missing. The record is written in each case. |
| `status` | `PASS` or `FAIL` |
| `record` | the record's bytes (`Uint8Array`), to save as `recordName` |
| `report` | the Markdown report, to save as `reportName` |
| `recordName`, `reportName` | `<log stem>.sfr`, `<log stem>.sfr.md` |
| `text` | what `sfr seal` prints, with file names in place of paths |
| `notes` | what `sfr seal` prints on standard error besides a failure, one per entry |
| `results` | each rule: `{ id, name, status, expected, found, detail: [lines] }` |
| `merkleRoot`, `leafCount`, `keyFingerprint`, `keyCustody`, `keyLabel`, `sealTimeClaimedUtc`, `eventCount` | as the record holds them; the seal time is the sealer's claim |
| `log` | `{ fileName, size, sha256, blake3, firmware }` |

When nothing was written: `{ sealed: false, exitCode: 3 or 4, message, text }`, with `text` what `sfr` prints on standard error (`sfr: <message>`).

**Verify result.**

| Field | Value |
|---|---|
| `exitCode` | 0 VERIFIED, 1 verification failed, 4 the record, the public key or the log could not be used, or a file is over the limit (`message` says why) |
| `verified` | `true` for exit 0 |
| `checked` | `record`, or `record and log` |
| `headline` | `Integrity: VERIFIED (record)`, `Integrity: VERIFIED (record and log)`, or `Integrity: FAILED: <first mismatch>` |
| `text` | exactly what `sfr verify` prints, with the record's file name in place of its path; for exit 4, what it prints on standard error. The page takes no report, so its `report` line is the one `sfr verify --no-report` prints |
| `message` | for exit 4, the reason; otherwise `null` |
| `keyCustody` | the record's custody, or what a record that failed claims (`null` if unreadable) |
| `keyFingerprint`, `cryptoCrates`, `sealTimeClaimedUtc`, `status`, `eventCount` | what a verified record says; `null` otherwise |
| `failedRules` | for a verified record, the ids of the rules whose sealed result is FAIL (empty when `status` is `PASS`); `null` otherwise |
| `mismatch` | the first mismatch, or `null` |
| `mismatches` | every mismatch, the first first (the text lists at most 21) |

**A mismatch.** Every field is present; a field the kind does not have is `null`. `text` is always the whole line `sfr verify` prints after `Integrity: FAILED: ` or `also: `. `sealed` and `found` are the values exactly as that line prints them (a typed parameter such as `f32:12`, or the JSON of an event or result field).

| Field | Value |
|---|---|
| `kind` | what changed (table below) |
| `text` | the whole line |
| `seq` | `event`: the event's sequence number |
| `eventKind` | `event`: the event's kind, for example `COMMAND` |
| `rule` | `result`: the rule id |
| `parameter` | `parameter`: its name |
| `topic`, `instance` | `sealed_topic`: the topic and its `multi_id` |
| `field` | the field that differs (see the kinds) |
| `sealed` | the value in the record |
| `found` | the value found: re-derived from the log, recomputed, or the given public key's fingerprint for `key` |
| `note` | extra text, such as why the log no longer parses |

| Kind | Meaning | Parts set |
|---|---|---|
| `event` | an event differs from the one re-derived from the log | `seq`, `eventKind`, `field`, `sealed`, `found` |
| `parameter` | a parameter at log start differs | `parameter`, `sealed`, `found` |
| `result` | a rule result differs | `rule`, `field`, `sealed`, `found` |
| `sealed_topic` | a sealed topic digest differs | `topic`, `instance`, `field`, `sealed`, `found` |
| `count` | the number of events or results differs | `field` (`events` or `results`), `sealed`, `found` |
| `sealed_topic_instances` | the sealed topic instances differ | `sealed`, `found` |
| `config` | the configuration's firmware or watched parameters differ | `field`, `sealed`, `found` |
| `log` | the log's firmware or vehicle differs | `field`, `sealed`, `found` |
| `log_digest` | the log's SHA-256 or size differs, or its BLAKE3 index (which adds no security: SHA-256 is the seal) | `field`, `sealed`, `found`, `note` |
| `log_unparseable` | the log's digest matches but it no longer parses | `note` |
| `merkle_root` | a leaf changed after sealing | `sealed` (recorded root), `found` (computed root) |
| `merkle_leaf_count` | the leaf count differs | `sealed`, `found` |
| `key` | the record was signed by another key | `sealed` (the record's key fingerprint), `found` (the given key's) |
| `signature` | the signature does not verify | |
| `status` | the overall status contradicts the results | `sealed`, `found` |
| `rules_digest` | the embedded rules text does not match its digest | |
| `custody` | a record that verified but is refused for its custody (text starting `refused:`); the page accepts evaluation keys and has no certificate chain to check, so it never gives this kind | |
| `record` | the record's form (JSON, schema, fields, order), or any other text | |

The parts are read from the text `sfr-core` writes (`crates/sfr-wasm/src/result.rs`); `crates/sfr/tests/sandbox.rs` and the browser test hold each kind to the text of real changed records and logs, so a change of wording fails CI.

**Demo steps.** Each step is `{ id, title, runs: [{ command, result }], passed, expected, note }`, with `command` the `sfr` command it stands for and `result` a seal or verify result.

| Step | What it does | Expected |
|---|---|---|
| a | makes an evaluation key | an in-browser EVALUATION KEY |
| b | seals the sample with the default rules and its baseline | exit 0, status PASS |
| c | verifies the record alone, then with the log | VERIFIED twice |
| d | changes one byte of a COMMAND event in a copy of the record, verifies it alone and with the log | exit 1: kind `merkle_root`, then kind `event` naming the event, `COMMAND`, field `command`, sealed and found values |
| e | changes `MPC_XY_VEL_MAX` to 7.0 in a copy of the log, verifies the record with it | exit 1: kind `parameter`, `MPC_XY_VEL_MAX`, found `f32:7` |

These are the steps of `scripts/run_demo.sh`, on one smaller log. The browser test runs the same steps with `sfr` on the same log and requires the same exit codes and output, keys, digests and times aside.

## Test harness and tests

`site/` is a plain page over the bundle, for CI only; `scripts/build_site.sh <out-dir>` puts it next to a fresh bundle (`<out-dir>/engine/`). `tests/browser/sandbox.test.mjs` drives it in Chromium, Firefox and WebKit (`npm ci` in `tests/browser` first; `node tests/browser/sandbox.test.mjs --site <out-dir> --sfr <sfr built from the same commit> --out <dir>`) and writes `summary.md`, `summary.json` and screenshots. CI tests WebKit, Safari's engine on Linux, not Safari itself; the hosted page should also be opened in Safari before it is offered.
