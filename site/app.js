// The sandbox page: three panels (seal, verify, tamper demo) over the engine in worker.js.
//
// Loading fetches the engine, the two example rules files and the two sample logs with their
// baselines, all from this site. When the status line says Ready, document.body carries
// data-ready="true", and from then on the page makes no network request: files are read in the
// worker, results are shown here, and downloads are made from memory (blob: URLs).
import { renderMarkdown } from './markdown.js';

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------------------------
// The engine

const worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
const pending = new Map();
let nextId = 1;

worker.onmessage = (event) => {
  const { id, result, error, engineBytes } = event.data;
  if (engineBytes) document.body.dataset.engineBytes = String(engineBytes);
  const p = pending.get(id);
  if (!p) return;
  pending.delete(id);
  if (error) p.reject(new Error(error));
  else p.resolve(result);
};

worker.onerror = (event) => {
  setStatus(`The engine could not start: ${event.message || 'unknown error'}. Reload the page.`, 'error');
  for (const p of pending.values()) p.reject(new Error('the engine stopped'));
  pending.clear();
};

function call(op, args = {}) {
  return new Promise((resolve, reject) => {
    const id = nextId;
    nextId += 1;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, op, ...args });
  });
}

// ---------------------------------------------------------------------------------------------
// Loading

const state = {
  rules: {},
  samples: {},
  sessionKey: null,
  urls: new Map(), // element id -> blob: URLs it shows, revoked when replaced
};

function setStatus(text, kind) {
  const s = $('engine-status');
  s.textContent = text;
  s.className = `engine ${kind || ''}`;
}

async function fetchBlob(path) {
  const response = await fetch(path, { cache: 'force-cache' });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.blob();
}

// A gzip file unpacked into a Blob as it streams; gzip's own checksum catches a damaged file. A
// server may already have removed the gzip layer: a ULog file starts with "ULog", not 1f 8b.
async function gunzip(blob) {
  const head = new Uint8Array(await blob.slice(0, 2).arrayBuffer());
  if (head[0] !== 0x1f || head[1] !== 0x8b) return blob;
  return new Response(blob.stream().pipeThrough(new DecompressionStream('gzip'))).blob();
}

async function loadSamples() {
  const manifest = JSON.parse(await (await fetchBlob('samples/samples.json')).text());
  let bytes = 0;
  await Promise.all(manifest.samples.map(async (s) => {
    const [gz, baseline] = await Promise.all([fetchBlob(`samples/${s.gz}`), fetchBlob(`samples/${s.baseline}`)]);
    const log = await gunzip(gz);
    if (log.size !== s.size) throw new Error(`sample ${s.log} is ${log.size} bytes, not ${s.size}`);
    bytes += gz.size;
    state.samples[s.id] = {
      name: s.log,
      path: s.path,
      log,
      baselineName: s.baseline,
      baselinePath: s.baseline_path,
      baseline,
    };
  }));
  return bytes;
}

async function start() {
  try {
    const [info, def, ext, sampleBytes] = await Promise.all([
      call('init'),
      fetchBlob('rules/rules.default.toml'),
      fetchBlob('rules/rules.extended.toml'),
      loadSamples(),
    ]);
    state.rules.default = { name: 'rules.default.toml', blob: def };
    state.rules.extended = { name: 'rules.extended.toml', blob: ext };
    state.limits = info.limits;
    $('engine-version').textContent = info.version.trim().replace('\n', '; ');
    state.sessionKey = await call('newKey', { name: 'session' });
    $('key-fingerprint').textContent = state.sessionKey.fingerprint;
    showDownloads('key-download', [{ name: 'sfr.pub', data: state.sessionKey.publicKeyPem, label: 'Download the public key (sfr.pub)' }]);
    for (const id of ['seal-run', 'verify-run', 'demo-run']) $(id).disabled = false;
    const mb = (sampleBytes / 1e6).toFixed(1);
    setStatus(`Ready. The engine and the sample logs (${mb} MB) are loaded; from here on the page makes no network request.`, 'ready');
    document.body.dataset.ready = 'true';
  } catch (e) {
    setStatus(`The sandbox could not load: ${e.message}. Reload the page.`, 'error');
  }
}

// ---------------------------------------------------------------------------------------------
// Page helpers

function showDownloads(id, files) {
  const box = $(id);
  for (const url of state.urls.get(id) || []) URL.revokeObjectURL(url);
  box.replaceChildren();
  const urls = [];
  for (const f of files) {
    const url = URL.createObjectURL(new Blob([f.data], { type: f.type || 'application/octet-stream' }));
    urls.push(url);
    const a = document.createElement('a');
    a.href = url;
    a.download = f.name;
    a.className = 'button secondary';
    a.textContent = f.label || `Download ${f.name}`;
    box.appendChild(a);
  }
  state.urls.set(id, urls);
}

function banner(id, kind, title, text) {
  const b = $(id);
  b.className = `banner ${kind}`;
  b.replaceChildren();
  const strong = document.createElement('strong');
  strong.textContent = title;
  b.appendChild(strong);
  if (text) b.appendChild(document.createTextNode(` ${text}`));
}

function fileInput(id) {
  const f = $(id).files[0];
  return f ? { name: f.name, blob: f } : null;
}

function nowRfc3339() {
  return new Date().toISOString().replace(/\.\d+Z$/, 'Z');
}

// Runs a panel's task with its button disabled. When it ends, document.body's data-<name>-count
// goes up by one (the browser test waits on it).
async function busy(name, task) {
  $(`${name}-busy`).hidden = false;
  $(`${name}-run`).disabled = true;
  try {
    await task();
  } finally {
    $(`${name}-busy`).hidden = true;
    $(`${name}-run`).disabled = false;
    const key = `${name}Count`;
    document.body.dataset[key] = String(Number(document.body.dataset[key] || 0) + 1);
  }
}

// Tabs
const tabs = ['seal', 'verify', 'demo'];
for (const name of tabs) {
  $(`tab-${name}`).addEventListener('click', () => {
    for (const other of tabs) {
      $(`tab-${other}`).setAttribute('aria-selected', String(other === name));
      $(`panel-${other}`).hidden = other !== name;
    }
  });
}

// Drop zones: a file dropped anywhere on a zone goes to its file input.
for (const zone of document.querySelectorAll('.drop')) {
  const input = $(zone.dataset.for);
  zone.addEventListener('dragover', (e) => {
    e.preventDefault();
    zone.classList.add('over');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', (e) => {
    e.preventDefault();
    zone.classList.remove('over');
    if (e.dataTransfer && e.dataTransfer.files.length) {
      input.files = e.dataTransfer.files;
      input.dispatchEvent(new Event('change'));
    }
  });
}

for (const radio of document.querySelectorAll('input[name="rules"]')) {
  radio.addEventListener('change', () => {
    $('seal-rules-drop').hidden = document.querySelector('input[name="rules"]:checked').value !== 'file';
  });
}

// ---------------------------------------------------------------------------------------------
// Seal

const SEAL_RESULT = {
  0: ['ok', 'PASS.', 'Every rule passed or does not apply. The record is sealed and signed.'],
  1: ['bad', 'FAIL.', 'One or more rules failed. The record is still sealed and signed: the failure is the evidence.'],
  2: ['bad', 'FAIL.', 'A required topic is missing from the log. The record is still sealed and signed, and names the missing topic.'],
};

$('seal-report-source').addEventListener('change', (e) => {
  $('seal-report').hidden = e.target.checked;
  $('seal-report-md').hidden = !e.target.checked;
});

$('seal-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy('seal', sealFromForm);
});

async function sealFromForm() {
  const log = fileInput('seal-log');
  const result = $('seal-result');
  result.hidden = false;
  for (const id of ['seal-downloads', 'seal-report', 'seal-output']) $(id).replaceChildren();
  $('seal-report-md').textContent = '';
  $('seal-notes').hidden = true;
  if (!log) {
    banner('seal-banner', 'warn', 'Not sealed.', 'Choose a flight log (.ulg) first.');
    return;
  }
  const choice = document.querySelector('input[name="rules"]:checked').value;
  const rules = choice === 'file' ? fileInput('seal-rules-file') : state.rules[choice];
  if (!rules) {
    banner('seal-banner', 'warn', 'Not sealed.', 'Choose a rules file, or the default or extended rules.');
    return;
  }
  const keyFile = fileInput('seal-key');
  const sealTime = $('seal-time').value.trim() || nowRfc3339();
  let r;
  try {
    r = await call('seal', {
      log,
      rules,
      baseline: fileInput('seal-baseline'),
      keyFile,
      keyName: 'session',
      sealTime,
    });
  } catch (e) {
    banner('seal-banner', 'bad', 'Not sealed.', e.message);
    return;
  }
  $('seal-output').textContent = r.text || `sfr: ${r.message}\n`;
  if (r.code > 2) {
    banner('seal-banner', 'bad', `Not sealed (exit ${r.code}).`, r.message);
    return;
  }
  const [kind, title, text] = SEAL_RESULT[r.code];
  const signer = keyFile
    ? `Signed with the evaluation key file ${keyFile.name}.`
    : 'Signed with the in-browser evaluation key (EVALUATION KEY: not for operational use).';
  banner('seal-banner', kind, title, `${text} ${signer} (exit ${r.code})`);
  if (r.notes) {
    $('seal-notes').textContent = r.notes;
    $('seal-notes').hidden = false;
  }
  const files = [
    { name: r.recordName, data: r.record, type: 'application/json' },
    { name: r.reportName, data: r.report, type: 'text/markdown' },
  ];
  if (!keyFile) files.push({ name: 'sfr.pub', data: state.sessionKey.publicKeyPem, label: 'Download sfr.pub (to verify it)' });
  showDownloads('seal-downloads', files);
  renderMarkdown(r.report, $('seal-report'));
  $('seal-report-md').textContent = r.report;
}

// ---------------------------------------------------------------------------------------------
// Verify

$('verify-form').addEventListener('submit', (event) => {
  event.preventDefault();
  busy('verify', verifyFromForm);
});

function verifyBanner(r) {
  if (r.code === 0) {
    const deep = r.headline.includes('record and log');
    banner('verify-banner', 'ok', r.headline, deep
      ? 'The signature, the Merkle root and every leaf check, and the log replays to the same results, configuration and events.'
      : 'The signature, the Merkle root and every leaf check. Add the log for the deep check.');
  } else if (r.code === 1) {
    banner('verify-banner', 'bad', 'FAILED.', r.headline.replace(/^FAILED: /, ''));
  } else {
    banner('verify-banner', 'warn', `Not verified (exit ${r.code}).`, r.message);
  }
}

async function verifyFromForm() {
  const record = fileInput('verify-record');
  const pubkey = fileInput('verify-pubkey');
  $('verify-result').hidden = false;
  $('verify-output').textContent = '';
  if (!record || !pubkey) {
    banner('verify-banner', 'warn', 'Not verified.', 'Choose a record (.sfr) and a public key (sfr.pub).');
    return;
  }
  let r;
  try {
    r = await call('verify', { record, pubkey, log: fileInput('verify-log') });
  } catch (e) {
    banner('verify-banner', 'bad', 'Not verified.', e.message);
    return;
  }
  $('verify-output').textContent = r.code > 1 ? `sfr: ${r.message}\n` : r.text;
  verifyBanner(r);
}

// ---------------------------------------------------------------------------------------------
// Tamper demo: the steps of scripts/run_demo.sh, on the same two golden logs, with the same
// changes and the same expected results.

const PARAM = 'VT_B_TRANS_DUR';

// run_demo.sh step d: the offset of the first digit of the first COMMAND event's command id.
function commandDigitOffset(text) {
  const kind = text.indexOf('"kind":"COMMAND"');
  if (kind < 0) return -1;
  const key = '"command":';
  const at = text.lastIndexOf(key, kind - key.length);
  return at < 0 ? -1 : at + key.length;
}

// run_demo.sh step e: the offset of the value of the 'P' record of `float NAME` (the parameter
// at log start), the first one in the file.
function paramValueOffset(bytes, name) {
  const key = new TextEncoder().encode(`float ${name}`);
  for (let o = 2; o + key.length + 4 <= bytes.length; o += 1) {
    let match = true;
    for (let j = 0; j < key.length; j += 1) {
      if (bytes[o + j] !== key[j]) { match = false; break; }
    }
    if (match && bytes[o - 2] === 0x50) return o + key.length;
  }
  return -1;
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

function addStep(letter, title) {
  const li = document.createElement('li');
  li.dataset.step = letter;
  const h = document.createElement('h3');
  h.textContent = `${letter}. ${title}`;
  li.appendChild(h);
  $('demo-steps').appendChild(li);
  return li;
}

function addRun(li, command, output, code) {
  const p = document.createElement('p');
  p.className = 'cmd';
  p.textContent = `$ ${command}`;
  const pre = document.createElement('pre');
  pre.className = 'output';
  pre.dataset.code = String(code);
  pre.textContent = `${output}${output.endsWith('\n') ? '' : '\n'}(exit ${code})`;
  li.append(p, pre);
}

function addNote(li, text) {
  const p = document.createElement('p');
  p.textContent = text;
  li.appendChild(p);
}

function finish(li, ok, expected) {
  li.classList.add(ok ? 'ok' : 'bad');
  li.dataset.ok = String(ok);
  const p = document.createElement('p');
  p.className = 'verdict';
  p.textContent = ok ? `As expected: ${expected}.` : `NOT as expected: ${expected}.`;
  li.appendChild(p);
  if (!ok) throw new Error(`step ${li.dataset.step}: expected ${expected}`);
}

// Runs one engine call and shows it; returns its result.
async function run(li, command, op, args) {
  const r = await call(op, args);
  const output = r.code > 2 ? `sfr: ${r.message}` : r.text;
  addRun(li, command, (r.notes ? `${r.notes}\n` : '') + output, r.code);
  return r;
}

const blobOf = (data) => new Blob([data]);

async function runDemo() {
  $('demo-steps').replaceChildren();
  $('demo-summary').hidden = true;
  const started = performance.now();
  const vtol = state.samples.vtol;
  const ts = state.samples.tailsitter;
  const rules = state.rules.default;
  try {
    let li = addStep('a', 'keygen an evaluation key');
    const key = await call('newKey', { name: 'demo' });
    const keygenOut = `EVALUATION KEY: not for operational use\nfingerprint  ${key.fingerprint}\n(the key stays in this tab's memory; nothing is written)`;
    addRun(li, 'sfr keygen --evaluation-only --out key', keygenOut, 0);
    finish(li, true, 'exit 0 and EVALUATION KEY');
    const pub = { name: 'sfr.pub', blob: blobOf(key.publicKeyPem) };

    li = addStep('b', `seal the golden VTOL flight (${vtol.path})`);
    const b = await run(li, `sfr seal ${vtol.path} --rules examples/rules.default.toml --baseline ${vtol.baselinePath} --key key/sfr.key --evaluation-only --out sealed`, 'seal', {
      log: { name: vtol.name, blob: vtol.log },
      rules,
      baseline: { name: vtol.baselineName, blob: vtol.baseline },
      keyName: 'demo',
      sealTime: nowRfc3339(),
    });
    const events = (/^events\s+(\d+)$/m.exec(b.text || '') || [])[1];
    if (events) addNote(li, `events in the record: ${events}`);
    finish(li, b.code === 0 && b.text.includes('status    PASS') && Boolean(events), 'exit 0 and status PASS');
    const record = { name: b.recordName, blob: blobOf(b.record) };

    li = addStep('c', 'verify the record standalone, then with the log');
    let r = await run(li, `sfr verify sealed/${b.recordName} --pubkey key/sfr.pub`, 'verify', { record, pubkey: pub });
    const c1 = r.code === 0 && r.text.includes('VERIFIED (record)');
    r = await run(li, `sfr verify sealed/${b.recordName} --pubkey key/sfr.pub --ulog ${vtol.path}`, 'verify', {
      record, pubkey: pub, log: { name: vtol.name, blob: vtol.log },
    });
    finish(li, c1 && r.code === 0 && r.text.includes('VERIFIED (record and log)'), 'exit 0 and VERIFIED, twice');

    li = addStep('d', 'change one byte of a COMMAND event in a copy of the record');
    const tampered = new Uint8Array(b.record);
    const offset = commandDigitOffset(new TextDecoder().decode(tampered));
    const digit = offset < 0 ? '' : String.fromCharCode(tampered[offset]);
    if (!/^[1-9]$/.test(digit)) finish(li, false, 'a COMMAND event with a command id in the record');
    const next = digit === '9' ? '1' : String(Number(digit) + 1);
    tampered[offset] = next.charCodeAt(0);
    addNote(li, `byte ${offset} of the record copy: command id digit ${digit} changed to ${next}`);
    const changed = { name: 'tampered.sfr', blob: blobOf(tampered) };
    r = await run(li, 'sfr verify tampered.sfr --pubkey key/sfr.pub', 'verify', { record: changed, pubkey: pub });
    const d1 = r.code === 1 && r.text.includes('Merkle root mismatch');
    r = await run(li, `sfr verify tampered.sfr --pubkey key/sfr.pub --ulog ${vtol.path}`, 'verify', {
      record: changed, pubkey: pub, log: { name: vtol.name, blob: vtol.log },
    });
    finish(li, d1 && r.code === 1 && r.text.includes('(COMMAND) field `command`: sealed '), 'exit 1 twice: Merkle root mismatch, then the event and field named');

    li = addStep('e', `change ${PARAM} in a copy of the golden quad tailsitter log`);
    const e = await run(li, `sfr seal ${ts.path} --rules examples/rules.default.toml --baseline ${ts.baselinePath} --key key/sfr.key --evaluation-only --out sealed`, 'seal', {
      log: { name: ts.name, blob: ts.log },
      rules,
      baseline: { name: ts.baselineName, blob: ts.baseline },
      keyName: 'demo',
      sealTime: nowRfc3339(),
    });
    if (!(e.code === 0 && e.text.includes(PARAM))) finish(li, false, `exit 0 and ${PARAM} in the transition tuning`);
    const tsBytes = new Uint8Array(await ts.log.arrayBuffer());
    const at = paramValueOffset(tsBytes, PARAM);
    if (at < 0) finish(li, false, `a 'P' record for ${PARAM} in the log`);
    const old = hex(tsBytes.subarray(at, at + 4));
    if (old === '0000e040') finish(li, false, `${PARAM} other than 7.0 in the log`);
    // The log copy: the same bytes with four replaced; Blob slices, so nothing is copied.
    const seven = new Uint8Array([0x00, 0x00, 0xe0, 0x40]);
    const changedLog = new Blob([ts.log.slice(0, at), seven, ts.log.slice(at + 4)]);
    addNote(li, `bytes ${at} to ${at + 3} of the log copy: ${PARAM} float32 bytes ${old} changed to 0000e040 (7.0)`);
    r = await run(li, `sfr verify sealed/${e.recordName} --pubkey key/sfr.pub --ulog tailsitter.ulg`, 'verify', {
      record: { name: e.recordName, blob: blobOf(e.record) }, pubkey: pub, log: { name: 'tailsitter.ulg', blob: changedLog },
    });
    finish(li, r.code === 1 && r.text.includes(`parameter ${PARAM}: sealed f32:`) && r.text.includes('found f32:7'), `exit 1 naming ${PARAM} with its sealed value and found f32:7`);

    li = addStep('f', 'seal your own logs');
    addNote(li, 'Use the Seal panel, or the command line. With your logs in ./logs and your vehicle\'s baseline (a QGroundControl .params export plus a \'# Firmware:\' line) in ./baseline.params:');
    const pre = document.createElement('pre');
    pre.className = 'output';
    pre.textContent = 'mkdir -p sealed && { [ -f sealed/key/sfr.key ] || sfr keygen --evaluation-only --out sealed/key; } && for f in logs/*.ulg; do sfr seal "$f" --rules examples/rules.default.toml --baseline baseline.params --key sealed/key/sfr.key --evaluation-only --out sealed; done';
    li.appendChild(pre);
    li.classList.add('ok');
    li.dataset.ok = 'true';

    const seconds = ((performance.now() - started) / 1000).toFixed(1);
    banner('demo-summary', 'ok', 'DEMO PASSED.', `Every step gave the expected result, in ${seconds} s.`);
  } catch (err) {
    banner('demo-summary', 'bad', 'DEMO FAILED.', err.message);
  }
  $('demo-summary').hidden = false;
}

$('demo-run').addEventListener('click', () => busy('demo', runDemo));

start();
