// The engine's thread. It loads sfr-wasm once, when the page loads, and runs seal and verify
// off the page's thread so the page stays responsive. Files arrive as Blob or File objects and
// are read here, synchronously, a piece at a time (FileReaderSync), so a large log is never held
// whole in memory. This worker makes no network request after it has loaded the engine.
import init, * as sfr from './pkg/sfr_wasm.js';

let exports = null;
let stopped = '';
const keys = new Map(); // name -> { seed, fingerprint, publicKeyPem }
let limits = { file: 0, text: 0 };

// A file read for the engine from start to end; read(buf) is called by the engine.
class BlobSource {
  constructor(blob, name) {
    this.blob = blob;
    this.name = name;
    this.pos = 0;
    this.reader = new FileReaderSync();
  }

  read(buf) {
    if (this.pos >= this.blob.size) return 0;
    const end = Math.min(this.pos + buf.length, this.blob.size);
    let bytes;
    try {
      bytes = new Uint8Array(this.reader.readAsArrayBuffer(this.blob.slice(this.pos, end)));
    } catch (e) {
      throw `the browser could not read ${this.name}: ${e && e.message ? e.message : e}`;
    }
    buf.set(bytes);
    this.pos += bytes.length;
    return bytes.length;
  }
}

// A small file read whole, at most `cap` + 1 bytes, as the command line reads it: the engine
// then refuses one over the limit and names the limit.
function readSmall(input, cap) {
  if (!input) return undefined;
  const part = input.blob.size > cap ? input.blob.slice(0, cap + 1) : input.blob;
  try {
    return new Uint8Array(new FileReaderSync().readAsArrayBuffer(part));
  } catch (e) {
    throw new Error(`cannot read ${input.name}: ${e && e.message ? e.message : e}`);
  }
}

function plain(outcome, extra = {}) {
  const out = {
    code: outcome.code,
    message: outcome.message,
    headline: outcome.headline,
    text: outcome.text,
    notes: outcome.notes,
    ...extra,
  };
  outcome.free();
  return out;
}

function newKey(name) {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const k = sfr.evaluationKey(seed);
  const key = { seed, fingerprint: k.headline, publicKeyPem: k.text };
  k.free();
  keys.set(name, key);
  return { fingerprint: key.fingerprint, publicKeyPem: key.publicKeyPem };
}

function seal(req) {
  const rules = readSmall(req.rules, limits.text);
  const baseline = readSmall(req.baseline, limits.text);
  const keyFile = readSmall(req.keyFile, limits.text);
  const key = keys.get(req.keyName || 'session');
  const out = sfr.seal(
    new BlobSource(req.log.blob, req.log.name),
    req.log.name,
    req.log.blob.size,
    req.rules.name,
    rules,
    req.baseline ? req.baseline.name : undefined,
    baseline,
    req.keyFile ? req.keyFile.name : undefined,
    keyFile,
    key ? key.seed : undefined,
    req.sealTime,
  );
  const record = out.record;
  return plain(out, {
    record,
    recordName: out.recordName,
    report: out.report,
    reportName: out.reportName,
  });
}

function verify(req) {
  const pubkey = readSmall(req.pubkey, limits.text);
  // A record over the sandbox's limit is refused by its size, before it is read.
  const record = req.record.blob.size > limits.file
    ? new Uint8Array(0)
    : readSmall(req.record, limits.file);
  const out = sfr.verify(
    req.record.name,
    record,
    req.record.blob.size,
    req.pubkey.name,
    pubkey,
    req.log ? new BlobSource(req.log.blob, req.log.name) : undefined,
    req.log ? req.log.name : undefined,
    req.log ? req.log.blob.size : 0,
  );
  return plain(out);
}

const ops = {
  async init() {
    exports = await init({ module_or_path: new URL('./pkg/sfr_wasm_bg.wasm', import.meta.url) });
    limits = { file: sfr.maxFileBytes(), text: sfr.maxTextBytes() };
    return { version: sfr.version(), limits };
  },
  newKey: (req) => newKey(req.name),
  seal,
  verify,
};

self.onmessage = async (event) => {
  const { id, op } = event.data;
  const reply = { id };
  if (stopped) {
    reply.error = stopped;
  } else {
    try {
      reply.result = await ops[op](event.data);
    } catch (e) {
      if (e instanceof WebAssembly.RuntimeError) {
        // A trap (a panic, or memory exhausted) leaves the engine unusable.
        const panic = sfr.lastPanic();
        stopped = `The engine stopped: ${panic || e.message}. Nothing was written. `
          + 'Reload the page to start it again; for a very large log, use the sfr command line.';
        reply.error = stopped;
      } else {
        reply.error = `${e && e.message ? e.message : e}`;
      }
    }
  }
  if (exports) reply.engineBytes = exports.memory.buffer.byteLength;
  const transfer = reply.result && reply.result.record ? [reply.result.record.buffer] : [];
  self.postMessage(reply, transfer);
};
