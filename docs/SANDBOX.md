# Sandbox: the engine bundle for the browser

The engine bundle runs `sfr` in a web page: seal a PX4 log, verify a record, verify a record with its log, and the tamper demo of `scripts/run_demo.sh`. This repository holds the bundle, its JavaScript API and the tests that hold it to the command line. The page in `site/` is a test harness for CI.

## What it does

- **One engine.** The bundle runs `crates/sfr-wasm`, the `sfr-core` engine built for WebAssembly, with the command line's crypto crates (`sha2`, `ed25519-dalek`, `blake3`). For the same log, rules, baseline, key and seal time it writes a record and a report byte-identical to `sfr seal`, and returns the text `sfr seal` and `sfr verify` print (SPEC B1.10 Sandbox). CI checks this on every golden log in Chromium, Firefox and WebKit.
- **Files stay in the browser.** The bundle sends no file and no request body. It fetches only its own files, with GET, from its own origin: the engine and the two example rules files when `load()` runs, and the sample log, its baseline and its manifest when `loadSample()` or `runTamperDemo()` runs. CI checks in each browser that sealing and verifying files from disk make no request, and that no request carries a body or goes to another host.
- **Evaluation keys only.** `load()` makes an Ed25519 key in the browser (seed from the browser's CSPRNG), labeled `EVALUATION KEY (sandbox, in-browser)`, custody `file-evaluation`. The seed stays in the worker's memory; only the public key leaves, as PEM. A key file from `sfr keygen --evaluation-only` may be given instead.
- **No baseline** means an empty one (firmware `none`, no parameters; `NO_BASELINE` in `crates/sfr-wasm/src/lib.rs`), so R2 and R3 fail and say what they found.
- **Size limit.** One log or record of at most 100 MiB (104,857,600 bytes); a larger file is refused unread with exit 4 ([LIMITS.md](LIMITS.md)).

## The bundle

`scripts/build_engine.sh <out-dir>` builds it; every CI run keeps it as the artifact `sfr-engine-<commit>`. It holds `sfr.js` (the API module), `sfr-worker.js` (the engine's thread), `pkg/` (the WebAssembly engine, built with `wasm-bindgen` 0.2.129), `rules/` (the two example rules files), `samples/` (the demo's gzip-compressed sample log `mc_flight_1.ulg`, its baseline, notices, and `samples.json` with its sizes and SHA-256), `BUILDINFO` (version, source commit, `rustc` and `wasm-bindgen` versions) and `SHA256SUMS` for every other file. `scripts/check_engine_bundle.sh <dir> <commit>` checks that all of it is present and matches; CI runs it on every bundle.

Serve the directory as it is, from the same origin as the page that imports `sfr.js` (a module worker starts only from its own origin). The Content-Security-Policy must allow `script-src 'self' 'wasm-unsafe-eval'`, `worker-src 'self'` and `connect-src 'self'`. The sample is the smallest golden log that shows both tamper changes (COMMAND events to change in the record, float parameters at log start to change in the log); `scripts/build_engine.sh` names it in one place.

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

A file argument is a `File`, a `Blob` with a `name`, or `{ name, data }` with `data` a `Blob`, `ArrayBuffer`, typed array or string. Every function returns a promise that rejects only when called wrongly, when the browser cannot read a file, or when the engine has stopped; an input the engine refuses resolves to a result with its exit code and message.

| Function | What it does |
|---|---|
| `load()` | Starts the engine, fetches the example rules, makes the session key. Resolves to `{ version, limits: { fileBytes, textBytes }, sessionKey: { keyId, fingerprint, publicKeyPem } }`. Later calls return the same; every other function calls it first. |
| `newEvaluationKey()` | A new in-browser key: `{ keyId, fingerprint, publicKeyPem }`. |
| `seal({ log, rules, baseline, key, sealTime })` | `sfr seal`. `rules`: `'default'`, `'extended'` or a file. `baseline`: a file, or none. `key`: `{ keyId }` or an evaluation key file; default the session key. `sealTime`: RFC 3339; default now. Resolves to a seal result. |
| `verify({ record, publicKey })` | `sfr verify --pubkey`, with the browser's clock as the verification time (the engine reads no clock): a record whose claimed seal time is more than 300 seconds later is refused. Resolves to a verify result. |
| `verifyWithLog({ record, publicKey, log })` | `sfr verify --pubkey --ulog`, same clock. |
| `loadSample()` | Fetches the sample on first use: `{ name, path, size, sha256, log, baseline, baselinePath, parameter, notices, transfer: { gzBytes, compressedBytes, transferBytes, unpackedHere } }`. `transferBytes` is the size on the wire from Resource Timing, or `null`. |
| `changeCommand(recordBytes)` | A copy of a record with one digit of the first COMMAND event's command id changed: `{ bytes, offset, from, to, description }`. |
| `changeParameter(logBlob, name, value)` | A copy of a log with float parameter `name` at log start set to `value`: `{ blob, offset, before, after, description }`. |
| `runTamperDemo({ onStep })` | Runs the demo (steps below), calling `onStep(step)` as each ends. Resolves to `{ passed, seconds, sample, steps, error }`. |
| `engineMemoryBytes()` | The engine's WebAssembly memory in bytes. |

**Seal result.** `{ sealed: true }` when a record was written (exit 0, 1 or 2; SPEC B1.4: 0 status PASS or WARN, 1 status FAIL or NO ARMED FLIGHT, 2 a required topic missing). Fields: `exitCode`, `status`, `record` (`Uint8Array`) and `report` (Markdown) to save as `recordName` and `reportName` (`<log stem>.sfr`, `<log stem>.sfr.md`), `text` (what `sfr seal` prints), `notes` (what it prints on standard error besides a failure), `results` (per rule `{ id, name, status, expected, found, detail: [lines] }`), `merkleRoot`, `leafCount`, `keyFingerprint`, `keyCustody`, `keyLabel`, `sealTimeClaimedUtc`, `eventCount`, and `log` (`{ fileName, size, sha256, blake3, firmware }`). When nothing was written: `{ sealed: false, exitCode: 3 or 4, message, text }`.

**Verify result.** `exitCode` is 0 VERIFIED, 1 verification failed, or 4 when the record, key or log could not be used or a file is over the limit (`message` says why); `verified` is `true` for 0. `checked` is `record` or `record and log`. `headline` is `Integrity: VERIFIED (record)`, `Integrity: VERIFIED (record and log)` or `Integrity: FAILED: <first mismatch>`. `text` is what `sfr verify` prints, with the record's file name for its path (for exit 4, what it prints on standard error); the page takes no report, so the `report` line is the one `sfr verify --no-report` prints. `keyCustody`, and, `null` unless the record verified, `keyFingerprint`, `cryptoCrates`, `sealTimeClaimedUtc`, `status`, `eventCount` and `failedRules` (ids of rules whose sealed result is FAIL). `mismatch` is the first mismatch or `null`; `mismatches` lists all, first first (the text lists at most 21).

### Mismatch kinds

A mismatch has the fields `kind`, `text` (the whole line `sfr verify` prints after `Integrity: FAILED: ` or `also: `), `seq`, `eventKind`, `rule`, `parameter`, `topic`, `instance`, `field`, `sealed`, `found` and `note`; a field the kind does not use is `null`. `sealed` and `found` are the values as that line prints them (a typed parameter such as `f32:12`, or the JSON of an event or result field).

| Kind | Meaning | Fields set |
|---|---|---|
| `event` | an event differs from the one re-derived from the log | `seq`, `eventKind`, `field`, `sealed`, `found` |
| `parameter` | a parameter at log start differs | `parameter`, `sealed`, `found` |
| `result` | a rule result differs | `rule`, `field`, `sealed`, `found` |
| `sealed_topic` | a sealed topic digest differs | `topic`, `instance` (its `multi_id`), `field`, `sealed`, `found` |
| `count` | the number of events or results differs | `field` (`events` or `results`), `sealed`, `found` |
| `sealed_topic_instances` | the sealed topic instances differ | `sealed`, `found` |
| `config` | firmware or watched parameters differ | `field`, `sealed`, `found` |
| `log` | the log's firmware or vehicle differs | `field`, `sealed`, `found` |
| `log_digest` | the log's SHA-256 or size differs, or its BLAKE3 index (adds no security: SHA-256 is the seal) | `field`, `sealed`, `found`, `note` |
| `log_unparseable` | the digest matches but the log no longer parses | `note` |
| `merkle_root` | a leaf changed after sealing | `sealed` (recorded root), `found` (computed) |
| `merkle_leaf_count` | the leaf count differs | `sealed`, `found` |
| `key` | signed by another key | `sealed` (the record's key fingerprint), `found` (the given key's) |
| `signature` | the signature does not verify | |
| `status` | the overall status contradicts the results | `sealed`, `found` |
| `rules_digest` | the embedded rules text does not match its digest | |
| `custody` | verified but refused for custody (text starts `refused:`); the page accepts evaluation keys and checks no certificate chain, so it never gives this kind | |
| `record` | the record's form (JSON, schema, fields, order), or any other text | |

The parts are read from the text `sfr-core` writes (`crates/sfr-wasm/src/result.rs`); `crates/sfr/tests/sandbox.rs` and the browser test hold each kind to the text of real changed records and logs.

**Demo steps.** Each step is `{ id, title, runs: [{ command, result }], passed, expected, note }`, with `command` the `sfr` command it stands for.

| Step | What it does | Expected |
|---|---|---|
| a | makes an evaluation key | an in-browser EVALUATION KEY |
| b | seals the sample with the default rules and its baseline | exit 0, status PASS or WARN |
| c | verifies the record alone, then with the log | VERIFIED twice |
| d | changes one byte of a COMMAND event in a copy of the record, verifies it alone and with the log | exit 1: kind `merkle_root`, then kind `event` (`COMMAND`, field `command`, sealed and found values) |
| e | changes `MPC_XY_VEL_MAX` to 7.0 in a copy of the log, verifies the record with it | exit 1: kind `parameter`, `MPC_XY_VEL_MAX`, found `f32:7` |

These are the steps of `scripts/run_demo.sh` on a smaller log; the browser test runs them with `sfr` too and requires the same exit codes and output, keys, digests and times aside.

## Test harness

`scripts/build_site.sh <out-dir>` puts the `site/` page next to a fresh bundle (`<out-dir>/engine/`). `tests/browser/sandbox.test.mjs` drives it in Chromium, Firefox and WebKit (`npm ci` in `tests/browser` first; `node tests/browser/sandbox.test.mjs --site <out-dir> --sfr <sfr built from the same commit> --out <dir>`) and writes `summary.md`, `summary.json` and screenshots. WebKit here is Safari's engine on Linux, not Safari.
