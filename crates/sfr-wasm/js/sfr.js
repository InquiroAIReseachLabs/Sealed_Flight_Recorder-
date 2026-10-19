// sfr.js: the Sealed Flight Record engine in the browser. docs/SANDBOX.md documents this API.
//
// Serve the whole engine bundle as it is, from the same origin as the page that imports this
// module. The engine runs in a worker (sfr-worker.js) and is the sfr command line's engine:
// for the same log, rules, baseline, key and seal time it writes the same record and report
// bytes and prints the same text.
//
// Files a person chooses are read in the browser and never uploaded: this module and its
// worker send no file and no request body anywhere. They fetch files of this bundle only, with
// GET: the engine and the two rules files when load() runs, and the sample log, its baseline
// and its manifest only when loadSample() (or runTamperDemo()) runs.

const bundle = new URL('.', import.meta.url);

let worker = null;
let loading = null;
let info = null;
let sessionKey = null;
let sample = null;
let engineBytes = 0;
const rules = {};
const pending = new Map();
let nextId = 1;

function call(op, args = {}) {
  if (!worker) return Promise.reject(new Error('call load() first'));
  return new Promise((resolve, reject) => {
    const id = nextId;
    nextId += 1;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, op, ...args });
  });
}

function startWorker() {
  worker = new Worker(new URL('sfr-worker.js', bundle), { type: 'module' });
  worker.onmessage = (event) => {
    const { id, result, error } = event.data;
    if (event.data.engineBytes) engineBytes = event.data.engineBytes;
    const p = pending.get(id);
    if (!p) return;
    pending.delete(id);
    if (error) p.reject(new Error(error));
    else p.resolve(result);
  };
  worker.onerror = (event) => {
    const error = new Error(`the engine could not start: ${event.message || 'unknown error'}`);
    for (const p of pending.values()) p.reject(error);
    pending.clear();
  };
}

async function fetchBundleFile(path) {
  const response = await fetch(new URL(path, bundle));
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response;
}

// A file as the engine takes it: { name, blob }. Accepts a File, a Blob (with `name`), or
// { name, data } with data a Blob, ArrayBuffer, typed array or string.
function input(value, what, fallbackName) {
  if (!value) throw new Error(`${what} is required`);
  if (value instanceof Blob) return { name: value.name || fallbackName, blob: value };
  if (typeof value === 'object' && 'data' in value) {
    const blob = value.data instanceof Blob ? value.data : new Blob([value.data]);
    return { name: value.name || fallbackName, blob };
  }
  throw new Error(`${what}: expected a File, a Blob, or { name, data }`);
}

function nowRfc3339() {
  return new Date().toISOString().replace(/\.\d+Z$/, 'Z');
}

/**
 * Starts the engine and fetches the two example rules files. Call once before anything else;
 * later calls return the same result. Makes an in-browser evaluation key for the session.
 * @returns {Promise<{version: string, limits: {fileBytes: number, textBytes: number}, sessionKey: {keyId: string, fingerprint: string, publicKeyPem: string}}>}
 */
export function load() {
  if (!loading) {
    loading = (async () => {
      startWorker();
      const [engine, def, ext] = await Promise.all([
        call('init'),
        fetchBundleFile('rules/rules.default.toml').then((r) => r.blob()),
        fetchBundleFile('rules/rules.extended.toml').then((r) => r.blob()),
      ]);
      rules.default = { name: 'rules.default.toml', blob: def };
      rules.extended = { name: 'rules.extended.toml', blob: ext };
      sessionKey = await call('newKey');
      info = { ...engine, sessionKey };
      return info;
    })();
  }
  return loading;
}

/**
 * Makes a new in-browser evaluation key (Ed25519, seed from the browser's CSPRNG). Its seed
 * stays in the worker's memory; only its public key leaves.
 * @returns {Promise<{keyId: string, fingerprint: string, publicKeyPem: string}>}
 */
export async function newEvaluationKey() {
  await load();
  return call('newKey');
}

/**
 * Seals a log, as `sfr seal --key <key> --evaluation-only --seal-time <time>`.
 * @param {object} o
 * @param {File|Blob|{name: string, data: *}} o.log the PX4 ULog file (at most 100 MiB)
 * @param {'default'|'extended'|File|Blob|{name: string, data: *}} [o.rules] default 'default'
 * @param {File|Blob|{name: string, data: *}} [o.baseline] without one, R2 and R3 fail
 * @param {{keyId: string}|File|Blob|{name: string, data: *}} [o.key] an in-browser key from
 *   newEvaluationKey(), or an evaluation key file (sfr.key); default the session key
 * @param {string} [o.sealTime] RFC 3339; default the current time
 * @returns {Promise<object>} the seal result (docs/SANDBOX.md)
 */
export async function seal({ log, rules: rulesChoice = 'default', baseline, key, sealTime } = {}) {
  await load();
  const req = {
    log: input(log, 'log', 'flight.ulg'),
    rules: typeof rulesChoice === 'string' ? rules[rulesChoice] : input(rulesChoice, 'rules', 'rules.toml'),
    baseline: baseline ? input(baseline, 'baseline', 'baseline.params') : null,
    sealTime: sealTime || nowRfc3339(),
  };
  if (!req.rules) throw new Error(`rules: expected 'default', 'extended' or a file, not ${rulesChoice}`);
  if (!key || typeof key.keyId === 'string') req.keyId = key ? key.keyId : sessionKey.keyId;
  else req.keyFile = input(key, 'key', 'sfr.key');
  return call('seal', req);
}

/**
 * Verifies a record against a public key, as `sfr verify --pubkey`.
 * @param {object} o
 * @param {File|Blob|{name: string, data: *}} o.record the record (.sfr)
 * @param {File|Blob|{name: string, data: *}} o.publicKey the public key (sfr.pub)
 * @returns {Promise<object>} the verify result (docs/SANDBOX.md)
 */
export async function verify({ record, publicKey } = {}) {
  await load();
  return call('verify', { record: input(record, 'record', 'record.sfr'), publicKey: input(publicKey, 'publicKey', 'sfr.pub'), now: nowRfc3339() });
}

/**
 * Verifies a record and the log it was sealed from, as `sfr verify --pubkey --ulog`.
 * @param {object} o
 * @param {File|Blob|{name: string, data: *}} o.record the record (.sfr)
 * @param {File|Blob|{name: string, data: *}} o.publicKey the public key (sfr.pub)
 * @param {File|Blob|{name: string, data: *}} o.log the log (.ulg)
 * @returns {Promise<object>} the verify result (docs/SANDBOX.md)
 */
export async function verifyWithLog({ record, publicKey, log } = {}) {
  await load();
  return call('verify', {
    record: input(record, 'record', 'record.sfr'),
    publicKey: input(publicKey, 'publicKey', 'sfr.pub'),
    log: input(log, 'log', 'flight.ulg'),
    now: nowRfc3339(),
  });
}

/** Bytes of memory the engine (WebAssembly) holds, as of its last reply. */
export function engineMemoryBytes() {
  return engineBytes;
}

// A gzip body unpacked as it streams; gzip's own checksum catches a damaged file. A host may
// already have removed the gzip layer (Content-Encoding): a ULog file starts with "ULog".
async function gunzip(blob) {
  const head = new Uint8Array(await blob.slice(0, 2).arrayBuffer());
  if (head[0] !== 0x1f || head[1] !== 0x8b) return { blob, unpackedHere: false };
  const out = await new Response(blob.stream().pipeThrough(new DecompressionStream('gzip'))).blob();
  return { blob: out, unpackedHere: true };
}

function transferSize(url) {
  const entries = performance.getEntriesByName(url.href);
  const last = entries[entries.length - 1];
  return last && typeof last.transferSize === 'number' && last.transferSize > 0 ? last.transferSize : null;
}

/**
 * Fetches the bundled sample log (gzip-compressed), its baseline and its manifest, on demand,
 * once; later calls return the same sample with no request.
 * @returns {Promise<object>} { name, path, size, sha256, log: File, baseline: File,
 *   parameter, notices: {provenance, license}, transfer: {compressedBytes, transferBytes, unpackedHere} }
 */
export function loadSample() {
  if (!sample) {
    sample = (async () => {
      const manifest = await (await fetchBundleFile('samples/samples.json')).json();
      const s = manifest.sample;
      const gzUrl = new URL(`samples/${s.gz}`, bundle);
      const [gz, baseline] = await Promise.all([
        fetchBundleFile(`samples/${s.gz}`).then((r) => r.blob()),
        fetchBundleFile(`samples/${s.baseline}`).then((r) => r.blob()),
      ]);
      const { blob, unpackedHere } = await gunzip(gz);
      if (blob.size !== s.size) throw new Error(`sample ${s.log} is ${blob.size} bytes, not ${s.size}`);
      return {
        name: s.log,
        path: s.path,
        size: s.size,
        sha256: s.sha256,
        log: new File([blob], s.log),
        baseline: new File([baseline], s.baseline),
        baselinePath: s.baseline_path,
        parameter: s.parameter,
        notices: { provenance: new URL(`samples/${s.provenance}`, bundle).href, license: new URL('samples/NOTICE.md', bundle).href },
        transfer: { compressedBytes: unpackedHere ? gz.size : null, gzBytes: s.gz_size, transferBytes: transferSize(gzUrl), unpackedHere },
      };
    })();
    sample.catch(() => { sample = null; });
  }
  return sample;
}

/**
 * A copy of a record with one digit of the first COMMAND event's command id changed, as
 * scripts/run_demo.sh step d changes it. The record's bytes are not changed.
 * @param {Uint8Array} recordBytes
 * @returns {{bytes: Uint8Array, offset: number, from: string, to: string, description: string}}
 */
export function changeCommand(recordBytes) {
  const text = new TextDecoder().decode(recordBytes);
  const kind = text.indexOf('"kind":"COMMAND"');
  const key = '"command":';
  const at = kind < 0 ? -1 : text.lastIndexOf(key, kind - key.length);
  const offset = at < 0 ? -1 : at + key.length;
  const from = offset < 0 ? '' : String.fromCharCode(recordBytes[offset]);
  if (!/^[1-9]$/.test(from)) throw new Error('the record has no COMMAND event with a command id');
  const to = from === '9' ? '1' : String(Number(from) + 1);
  const bytes = new Uint8Array(recordBytes);
  bytes[offset] = to.charCodeAt(0);
  return { bytes, offset, from, to, description: `byte ${offset} of the record copy: command id digit ${from} changed to ${to}` };
}

/**
 * A copy of a log with the float32 value of one parameter at log start (its first 'P' record)
 * replaced, as scripts/run_demo.sh step e changes it. The original Blob is not changed.
 * @param {Blob} log
 * @param {string} name a float parameter, for example MPC_XY_VEL_MAX
 * @param {number} value the new value
 * @returns {Promise<{blob: Blob, offset: number, before: string, after: string, description: string}>}
 */
export async function changeParameter(log, name, value) {
  const bytes = new Uint8Array(await log.arrayBuffer());
  const key = new TextEncoder().encode(`float ${name}`);
  let offset = -1;
  for (let o = 2; offset < 0 && o + key.length + 4 <= bytes.length; o += 1) {
    let match = bytes[o - 2] === 0x50;
    for (let j = 0; match && j < key.length; j += 1) match = bytes[o + j] === key[j];
    if (match) offset = o + key.length;
  }
  if (offset < 0) throw new Error(`the log has no 'P' record for float parameter ${name}`);
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const after = new Uint8Array(4);
  new DataView(after.buffer).setFloat32(0, value, true);
  const before = hex(bytes.subarray(offset, offset + 4));
  if (before === hex(after)) throw new Error(`${name} is already ${value} in the log`);
  return {
    blob: new Blob([log.slice(0, offset), after, log.slice(offset + 4)]),
    offset,
    before,
    after: hex(after),
    description: `bytes ${offset} to ${offset + 3} of the log copy: ${name} float32 bytes ${before} changed to ${hex(after)} (${value})`,
  };
}

/**
 * The tamper demo: the steps of scripts/run_demo.sh on the bundled sample log. Fetches the
 * sample on first use. Each step is reported to onStep as it ends.
 * @param {{onStep?: function(object): void}} [o]
 * @returns {Promise<{passed: boolean, seconds: number, sample: object, steps: object[]}>}
 */
export async function runTamperDemo({ onStep } = {}) {
  const started = performance.now();
  const steps = [];
  const s = await loadSample();
  const record = (r) => ({ name: r.recordName, data: r.record });
  const step = (id, title, runs, passed, expected, note) => {
    const st = { id, title, runs, passed, expected, note: note || null };
    steps.push(st);
    if (onStep) onStep(st);
    if (!passed) throw Object.assign(new Error(`step ${id}: expected ${expected}`), { step: st });
    return st;
  };
  try {
    const key = await newEvaluationKey();
    const pub = { name: 'sfr.pub', data: key.publicKeyPem };
    step('a', 'make an evaluation key', [{ command: 'sfr keygen --evaluation-only --out key', result: { keyFingerprint: key.fingerprint } }], true,
      'an in-browser EVALUATION KEY', `EVALUATION KEY: not for operational use; fingerprint ${key.fingerprint}`);

    const sealed = await seal({ log: s.log, baseline: s.baseline, key });
    step('b', `seal the sample flight (${s.path})`, [{
      command: `sfr seal ${s.path} --rules examples/rules.default.toml --baseline ${s.baselinePath} --key key/sfr.key --evaluation-only --out sealed`,
      result: sealed,
    }], sealed.exitCode === 0 && sealed.status === 'PASS', 'exit 0, status PASS', sealed.sealed ? `events in the record: ${sealed.eventCount}` : null);

    const c1 = await verify({ record: record(sealed), publicKey: pub });
    const c2 = await verifyWithLog({ record: record(sealed), publicKey: pub, log: s.log });
    step('c', 'verify the record alone, then with the log', [
      { command: `sfr verify sealed/${sealed.recordName} --pubkey key/sfr.pub`, result: c1 },
      { command: `sfr verify sealed/${sealed.recordName} --pubkey key/sfr.pub --ulog ${s.path}`, result: c2 },
    ], c1.verified && c2.verified && c2.checked === 'record and log', 'VERIFIED twice');

    const changed = changeCommand(sealed.record);
    const tampered = { name: 'tampered.sfr', data: changed.bytes };
    const d1 = await verify({ record: tampered, publicKey: pub });
    const d2 = await verifyWithLog({ record: tampered, publicKey: pub, log: s.log });
    step('d', 'change one byte of a COMMAND event in a copy of the record', [
      { command: 'sfr verify tampered.sfr --pubkey key/sfr.pub', result: d1 },
      { command: `sfr verify tampered.sfr --pubkey key/sfr.pub --ulog ${s.path}`, result: d2 },
    ], d1.exitCode === 1 && d1.mismatch.kind === 'merkle_root' && d2.exitCode === 1 && d2.mismatch.kind === 'event'
      && d2.mismatch.eventKind === 'COMMAND' && d2.mismatch.field === 'command',
    'exit 1 twice: the Merkle root, then the event, its kind and field, with the sealed and found values', changed.description);

    const param = await changeParameter(s.log, s.parameter, 7.0);
    const e1 = await verifyWithLog({ record: record(sealed), publicKey: pub, log: { name: 'changed.ulg', data: param.blob } });
    step('e', `change ${s.parameter} in a copy of the log`, [
      { command: `sfr verify sealed/${sealed.recordName} --pubkey key/sfr.pub --ulog changed.ulg`, result: e1 },
    ], e1.exitCode === 1 && e1.mismatch.kind === 'parameter' && e1.mismatch.parameter === s.parameter && e1.mismatch.found === 'f32:7',
    `exit 1 naming ${s.parameter} with its sealed value and found f32:7`, param.description);
    return { passed: true, seconds: (performance.now() - started) / 1000, sample: s, steps };
  } catch (e) {
    if (!e.step) throw e;
    return { passed: false, seconds: (performance.now() - started) / 1000, sample: s, steps, error: e.message };
  }
}
