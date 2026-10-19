// sfr-worker.js: the engine's thread (docs/SANDBOX.md). sfr.js starts it; nothing else should.
//
// It loads the engine (pkg/sfr_wasm_bg.wasm) once and runs seal and verify off the page's
// thread. Files arrive as Blob or File objects and are read here, synchronously, a piece at a
// time (FileReaderSync), straight into the engine: a large log is never held whole in memory,
// and nothing read here is sent anywhere. The worker's only request is the engine itself.
import init, * as sfr from './pkg/sfr_wasm.js';

let exports = null;
let stopped = '';
const keys = new Map(); // keyId -> 32-byte seed of an in-browser evaluation key
let limits = { file: 0, text: 0 };

// A file read for the engine from start to end; the engine calls read(buf).
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

function newKey() {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  const key = JSON.parse(sfr.evaluationKey(seed));
  const keyId = `k${keys.size + 1}`;
  keys.set(keyId, seed);
  return { keyId, fingerprint: key.fingerprint, publicKeyPem: key.publicKeyPem };
}

function seal(req) {
  const seed = req.keyFile ? undefined : keys.get(req.keyId);
  if (!req.keyFile && !seed) throw new Error(`no in-browser key ${req.keyId}`);
  const out = sfr.seal(
    new BlobSource(req.log.blob, req.log.name),
    req.log.name,
    req.log.blob.size,
    req.rules.name,
    readSmall(req.rules, limits.text),
    req.baseline ? req.baseline.name : undefined,
    readSmall(req.baseline, limits.text),
    req.keyFile ? req.keyFile.name : undefined,
    readSmall(req.keyFile, limits.text),
    seed,
    req.sealTime,
  );
  const result = JSON.parse(out.json);
  if (result.sealed) {
    result.record = out.record;
    result.report = out.report;
  }
  out.free();
  return result;
}

function verify(req) {
  // A record over the sandbox's limit is refused by its size, before it is read.
  const record = req.record.blob.size > limits.file ? new Uint8Array(0) : readSmall(req.record, limits.file);
  return JSON.parse(sfr.verify(
    req.record.name,
    record,
    req.record.blob.size,
    req.publicKey.name,
    readSmall(req.publicKey, limits.text),
    req.log ? new BlobSource(req.log.blob, req.log.name) : undefined,
    req.log ? req.log.name : undefined,
    req.log ? req.log.blob.size : 0,
  ));
}

const ops = {
  async init() {
    exports = await init({ module_or_path: new URL('./pkg/sfr_wasm_bg.wasm', import.meta.url) });
    limits = { file: sfr.maxFileBytes(), text: sfr.maxTextBytes() };
    return { version: sfr.version(), limits: { fileBytes: limits.file, textBytes: limits.text } };
  },
  newKey,
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
          + 'Load the page again to start it again; for a very large log, use the sfr command line.';
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
