// The sandbox test harness: three plain panels (seal, verify, tamper demo) over the engine
// bundle's API (engine/sfr.js, docs/SANDBOX.md). CI's browser gate drives it; the production
// page is built elsewhere on the same bundle.
//
// When the status line says Ready, document.body carries data-ready="true". After a panel's
// task ends, its data-<panel>-count goes up by one.
import * as sfr from './engine/sfr.js';
import { renderMarkdown } from './markdown.js';

const $ = (id) => document.getElementById(id);
const state = { sessionKey: null, urls: new Map() };

function setStatus(text, kind) {
  const s = $('engine-status');
  s.textContent = text;
  s.className = `engine ${kind || ''}`;
}

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

const file = (id) => $(id).files[0] || null;

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

async function start() {
  try {
    const info = await sfr.load();
    state.sessionKey = info.sessionKey;
    $('engine-version').textContent = info.version.trim().replace('\n', '; ');
    $('key-fingerprint').textContent = info.sessionKey.fingerprint;
    showDownloads('key-download', [{ name: 'sfr.pub', data: info.sessionKey.publicKeyPem, label: 'Download the public key (sfr.pub)' }]);
    for (const id of ['seal-run', 'verify-run', 'demo-run']) $(id).disabled = false;
    setStatus('Ready.', 'ready');
    document.body.dataset.ready = 'true';
  } catch (e) {
    setStatus(`The engine could not load: ${e.message}. Load the page again.`, 'error');
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
  $('seal-result').hidden = false;
  for (const id of ['seal-downloads', 'seal-report', 'seal-output']) $(id).replaceChildren();
  $('seal-report-md').textContent = '';
  $('seal-notes').hidden = true;
  const log = file('seal-log');
  if (!log) {
    banner('seal-banner', 'warn', 'Not sealed.', 'Choose a flight log (.ulg) first.');
    return;
  }
  const choice = document.querySelector('input[name="rules"]:checked').value;
  const rules = choice === 'file' ? file('seal-rules-file') : choice;
  if (!rules) {
    banner('seal-banner', 'warn', 'Not sealed.', 'Choose a rules file, or the default or extended rules.');
    return;
  }
  const keyFile = file('seal-key');
  let r;
  try {
    r = await sfr.seal({
      log,
      rules,
      baseline: file('seal-baseline') || undefined,
      key: keyFile || undefined,
      sealTime: $('seal-time').value.trim() || undefined,
    });
  } catch (e) {
    banner('seal-banner', 'bad', 'Not sealed.', e.message);
    return;
  }
  $('seal-output').textContent = r.text;
  if (!r.sealed) {
    banner('seal-banner', 'bad', `Not sealed (exit ${r.exitCode}).`, r.message);
    return;
  }
  const [kind, title, text] = SEAL_RESULT[r.exitCode];
  const signer = keyFile
    ? `Signed with the evaluation key file ${keyFile.name}.`
    : 'Signed with the in-browser evaluation key (EVALUATION KEY: not for operational use).';
  banner('seal-banner', kind, title, `${text} ${signer} (exit ${r.exitCode})`);
  if (r.notes.length) {
    $('seal-notes').textContent = r.notes.join('\n');
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

// One mismatch's parts, as a line: kind, then each part the kind has.
function mismatchLine(m) {
  const parts = ['seq', 'eventKind', 'rule', 'parameter', 'topic', 'instance', 'field', 'sealed', 'found']
    .filter((k) => m[k] !== null)
    .map((k) => `${k} ${m[k]}`);
  return `${m.kind}${parts.length ? `: ${parts.join(', ')}` : ''}`;
}

async function verifyFromForm() {
  const record = file('verify-record');
  const publicKey = file('verify-pubkey');
  const log = file('verify-log');
  $('verify-result').hidden = false;
  $('verify-output').textContent = '';
  $('verify-json').textContent = '';
  if (!record || !publicKey) {
    banner('verify-banner', 'warn', 'Not verified.', 'Choose a record (.sfr) and a public key (sfr.pub).');
    return;
  }
  let r;
  try {
    r = log ? await sfr.verifyWithLog({ record, publicKey, log }) : await sfr.verify({ record, publicKey });
  } catch (e) {
    banner('verify-banner', 'bad', 'Not verified.', e.message);
    return;
  }
  $('verify-output').textContent = r.text;
  $('verify-json').textContent = JSON.stringify({ exitCode: r.exitCode, verified: r.verified, checked: r.checked, mismatch: r.mismatch }, null, 2);
  if (r.verified) banner('verify-banner', 'ok', r.headline, '');
  else if (r.exitCode === 1) banner('verify-banner', 'bad', 'FAILED.', mismatchLine(r.mismatch));
  else banner('verify-banner', 'warn', `Not verified (exit ${r.exitCode}).`, r.message);
}

// ---------------------------------------------------------------------------------------------
// Tamper demo

function renderStep(st) {
  const li = document.createElement('li');
  li.dataset.step = st.id;
  li.dataset.ok = String(st.passed);
  li.className = st.passed ? 'ok' : 'bad';
  const h = document.createElement('h3');
  h.textContent = `${st.id}. ${st.title}`;
  li.appendChild(h);
  if (st.note) {
    const p = document.createElement('p');
    p.className = 'note';
    p.textContent = st.note;
    li.appendChild(p);
  }
  for (const run of st.runs) {
    const p = document.createElement('p');
    p.className = 'cmd';
    p.textContent = `$ ${run.command}`;
    li.appendChild(p);
    if (run.result.text !== undefined) {
      const pre = document.createElement('pre');
      pre.className = 'output';
      pre.dataset.code = String(run.result.exitCode);
      pre.textContent = `${run.result.text}(exit ${run.result.exitCode})`;
      li.appendChild(pre);
    }
    if (run.result.mismatch) {
      const m = document.createElement('p');
      m.className = 'mismatch';
      m.dataset.mismatch = JSON.stringify(run.result.mismatch);
      m.textContent = `First mismatch: ${mismatchLine(run.result.mismatch)}`;
      li.appendChild(m);
    }
  }
  const v = document.createElement('p');
  v.className = 'verdict';
  v.textContent = `${st.passed ? 'As expected' : 'NOT as expected'}: ${st.expected}.`;
  li.appendChild(v);
  $('demo-steps').appendChild(li);
}

async function runDemo() {
  $('demo-steps').replaceChildren();
  $('demo-summary').hidden = true;
  try {
    const res = await sfr.runTamperDemo({ onStep: renderStep });
    const t = res.sample.transfer;
    const fetched = t.transferBytes ? `${t.transferBytes} bytes transferred` : `${t.gzBytes} bytes compressed`;
    banner('demo-summary', res.passed ? 'ok' : 'bad', res.passed ? 'DEMO PASSED.' : 'DEMO FAILED.',
      `${res.passed ? 'Every step gave the expected result' : res.error}, in ${res.seconds.toFixed(1)} s. Sample ${res.sample.name}: ${res.sample.size} bytes, fetched on demand (${fetched}).`);
  } catch (e) {
    banner('demo-summary', 'bad', 'DEMO FAILED.', e.message);
  }
  $('demo-summary').hidden = false;
}

$('demo-run').addEventListener('click', () => busy('demo', runDemo));

start();
