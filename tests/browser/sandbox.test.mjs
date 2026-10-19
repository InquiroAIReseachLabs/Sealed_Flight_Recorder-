// sandbox.test.mjs: the headless browser gate for the engine bundle and its test harness page
// (SPEC B1.10 Sandbox; docs/SANDBOX.md).
//
// Serves a built harness (scripts/build_site.sh: the page plus the engine bundle in engine/) on
// 127.0.0.1, opens it in each browser, and checks, through the page's own controls:
//
//   records   every golden log, sealed with its golden rules and baseline, the CLI's evaluation
//             key file and one seal time, downloads a record and a report byte-identical to
//             `sfr seal`'s, with the CLI's output text and exit code; the same without a baseline
//   key       a record sealed with the in-browser key verifies with `sfr verify` and the page's
//             sfr.pub
//   verify    the verify panel prints what `sfr verify` prints, verified and failed, and its
//             structured first mismatch names the kind, event sequence number, event kind,
//             field, sealed and found values of the text
//   demo      the tamper demo gives the exit codes and output of `sfr` running the same steps on
//             the same sample log (keys, digests and times aside: each side makes its own key),
//             and its structured mismatches; the sample's transfer size is reported
//   limit     a log over the 100 MiB limit is refused, unread, with its message
//   network   user-file seal and verify make no request at all; the tamper demo makes only
//             same-origin GET requests for the sample's files; no request has a body; no request
//             goes to another host (the server logs every request; the browser reports every
//             request of the page and its worker)
//   memory    Chromium only: peak memory sealing, then verifying with the log, the largest log
//             the browser engine allows (built like scripts/benchmark.sh's large logs)
//
// It saves screenshots of the harness's three panels, light and dark, per browser, and writes
// summary.md and summary.json to the output directory. Exits 1 on any failed check.
//
// Usage: node sandbox.test.mjs --site <dir> --sfr <sfr built from the same commit> --out <dir>
//          [--browsers chromium,firefox,webkit]
// CHROMIUM_EXECUTABLE runs a preinstalled Chromium instead of Playwright's own.
import { chromium, firefox, webkit } from 'playwright';
import { execFileSync, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const SEAL_TIME = '2026-10-18T15:00:00Z';
const LIMIT = 100 * 1024 * 1024;
// The policy the test server sends with every file: the browser may contact this server only.
const CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; worker-src 'self'; connect-src 'self'; "
  + "style-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'";

function args() {
  const a = { browsers: 'chromium,firefox,webkit' };
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i += 2) {
    const k = argv[i].replace(/^--/, '');
    if (!['site', 'sfr', 'out', 'browsers'].includes(k) || argv[i + 1] === undefined) {
      throw new Error(`usage: node sandbox.test.mjs --site <dir> --sfr <sfr> --out <dir> [--browsers ...]; got ${argv[i]}`);
    }
    a[k] = argv[i + 1];
  }
  for (const k of ['site', 'sfr', 'out']) if (!a[k]) throw new Error(`--${k} is required`);
  return { ...a, site: path.resolve(a.site), sfr: path.resolve(a.sfr), out: path.resolve(a.out) };
}

const opt = args();
fs.rmSync(opt.out, { recursive: true, force: true });
fs.mkdirSync(opt.out, { recursive: true });
const work = path.join(opt.out, 'work');
fs.mkdirSync(work);

// ---------------------------------------------------------------------------------------------
// The CLI side

function sfr(cwd, argv) {
  const r = spawnSync(opt.sfr, argv, { cwd, encoding: 'utf8', maxBuffer: 64 << 20 });
  if (r.error) throw r.error;
  return { code: r.status, stdout: r.stdout, stderr: r.stderr };
}

function link(dir, target, name) {
  fs.symlinkSync(path.resolve(root, target), path.join(dir, name));
}

const golden = execFileSync('bash', ['-c', '. scripts/testdata/golden_logs.sh; golden_logs'], { cwd: root, encoding: 'utf8' })
  .trim().split('\n').map((line) => {
    const [name, log] = line.split(' ');
    const own = `testdata/rules/${name}.toml`;
    return {
      name,
      log,
      rules: fs.existsSync(path.join(root, own)) ? own : 'examples/rules.default.toml',
      baseline: `testdata/baselines/${name}.params`,
    };
  });

const keyDir = path.join(work, 'key');
if (sfr(work, ['keygen', '--evaluation-only', '--out', 'key']).code !== 0) throw new Error('sfr keygen failed');

// Seals one case with the CLI in its own directory, with bare file names, as the page names files.
function cliSeal(id, log, rules, baselineName, baselineText) {
  const dir = path.join(work, 'cli', id);
  fs.mkdirSync(dir, { recursive: true });
  const logName = path.basename(log);
  link(dir, log, logName);
  link(dir, rules, path.basename(rules));
  if (baselineText !== undefined) fs.writeFileSync(path.join(dir, baselineName), baselineText);
  else link(dir, baselineName, path.basename(baselineName));
  const r = sfr(dir, ['seal', logName, '--rules', path.basename(rules), '--baseline', path.basename(baselineName),
    '--key', path.join(keyDir, 'sfr.key'), '--evaluation-only', '--seal-time', SEAL_TIME, '--out', 'out']);
  if (r.code > 2) throw new Error(`sfr seal ${id}: ${r.stderr}`);
  const stem = logName.replace(/\.[^.]*$/, '');
  return {
    ...r,
    dir,
    record: fs.readFileSync(path.join(dir, 'out', `${stem}.sfr`)),
    report: fs.readFileSync(path.join(dir, 'out', `${stem}.sfr.md`)),
    text: r.stdout.replaceAll('out/', ''),
  };
}

// The engine's no-baseline text, as crates/sfr-wasm states it.
const lib = fs.readFileSync(path.join(root, 'crates/sfr-wasm/src/lib.rs'), 'utf8');
const NO_BASELINE = JSON.parse(/pub const NO_BASELINE: &str = ("(?:[^"\\]|\\.)*");/.exec(lib)[1]);
const NO_BASELINE_NAME = /pub const NO_BASELINE_NAME: &str = "([^"]+)";/.exec(lib)[1];

const cli = {};
for (const g of golden) cli[g.name] = cliSeal(g.name, g.log, g.rules, g.baseline);
const noBaselineLog = 'testdata/sitl/v1.17.0/mc_flight_1.ulg';
cli['no baseline'] = cliSeal('no-baseline', noBaselineLog, 'examples/rules.default.toml', NO_BASELINE_NAME, NO_BASELINE);

// The demo's changes, as engine/sfr.js makes them (changeCommand, changeParameter).
function changeCommand(record) {
  const text = record.toString('latin1');
  const kind = text.indexOf('"kind":"COMMAND"');
  const at = text.lastIndexOf('"command":', kind - 10) + 10;
  const t = Buffer.from(record);
  t[at] = t[at] === 0x39 ? 0x31 : t[at] + 1;
  return t;
}
function changeParameter(log, name, value) {
  const key = Buffer.from(`float ${name}`);
  let at = -1;
  for (let o = log.indexOf(key); o >= 0 && at < 0; o = log.indexOf(key, o + 1)) if (log[o - 2] === 0x50) at = o + key.length;
  const out = Buffer.from(log);
  out.writeFloatLE(value, at);
  return out;
}

// Verify cases: the CLI's own record of the golden VTOL flight, a copy with a changed command
// id, and a copy of the log with one changed byte.
const vdir = path.join(work, 'verify');
fs.mkdirSync(vdir);
const vtol = cli['v1.17.0_vtol_transition'];
fs.writeFileSync(path.join(vdir, 'vtol_transition.sfr'), vtol.record);
fs.copyFileSync(path.join(keyDir, 'sfr.pub'), path.join(vdir, 'sfr.pub'));
link(vdir, 'testdata/sitl/v1.17.0/vtol_transition.ulg', 'vtol_transition.ulg');
fs.writeFileSync(path.join(vdir, 'tampered.sfr'), changeCommand(vtol.record));
{
  const log = fs.readFileSync(path.join(root, 'testdata/sitl/v1.17.0/vtol_transition.ulg'));
  log[log.length >> 1] ^= 0x40;
  fs.writeFileSync(path.join(vdir, 'changed.ulg'), log);
}
const verifyCases = [
  ['vtol_transition.sfr', null],
  ['vtol_transition.sfr', 'vtol_transition.ulg'],
  ['tampered.sfr', null],
  ['tampered.sfr', 'vtol_transition.ulg'],
  ['vtol_transition.sfr', 'changed.ulg'],
].map(([record, log]) => {
  const r = sfr(vdir, ['verify', record, '--pubkey', 'sfr.pub', ...(log ? ['--ulog', log] : [])]);
  return { record, log, code: r.code, stdout: r.stdout };
});

// The demo's steps with the CLI, on the bundle's sample log.
const sample = JSON.parse(fs.readFileSync(path.join(opt.site, 'engine/samples/samples.json'), 'utf8')).sample;
const demoCli = (() => {
  const dir = path.join(work, 'demo');
  fs.mkdirSync(dir);
  link(dir, sample.path, sample.log);
  link(dir, sample.baseline_path, sample.baseline);
  link(dir, 'examples/rules.default.toml', 'rules.default.toml');
  const steps = {};
  const s = sfr(dir, ['seal', sample.log, '--rules', 'rules.default.toml', '--baseline', sample.baseline,
    '--key', path.join(keyDir, 'sfr.key'), '--evaluation-only', '--out', 'sealed']);
  steps.b = [{ code: s.code, text: s.stdout }];
  const recordName = sample.log.replace(/\.ulg$/, '.sfr');
  const record = fs.readFileSync(path.join(dir, 'sealed', recordName));
  fs.writeFileSync(path.join(dir, recordName), record);
  fs.copyFileSync(path.join(keyDir, 'sfr.pub'), path.join(dir, 'sfr.pub'));
  const v = (...a) => { const r = sfr(dir, ['verify', ...a, '--pubkey', 'sfr.pub']); return { code: r.code, text: r.stdout }; };
  steps.c = [v(recordName), v(recordName, '--ulog', sample.log)];
  fs.writeFileSync(path.join(dir, 'tampered.sfr'), changeCommand(record));
  steps.d = [v('tampered.sfr'), v('tampered.sfr', '--ulog', sample.log)];
  fs.writeFileSync(path.join(dir, 'changed.ulg'), changeParameter(fs.readFileSync(path.join(root, sample.path)), sample.parameter, 7.0));
  steps.e = [v(recordName, '--ulog', 'changed.ulg')];
  return steps;
})();

// Output with what differs between two runs masked: directories, digests and keys, times.
function mask(text) {
  return text
    .replace(/(^|\s)(?:\/|sealed\/)(?:[^\s/]+\/)*([^\s/]+)/gm, '$1$2')
    .replace(/[0-9a-f]{64}/g, '<hex>')
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/g, '<time>')
    .trimEnd();
}

// The largest log the browser engine allows: the golden VTOL flight, then its whole-record
// segments (scripts/benchmark/vtol_transition.segments) in order, again and again, while the
// log stays within the limit.
function largestLog(dest) {
  const manifest = fs.readFileSync(path.join(root, 'scripts/benchmark/vtol_transition.segments'), 'utf8');
  const src = fs.readFileSync(path.join(root, 'testdata/sitl/v1.17.0/vtol_transition.ulg'));
  const segments = manifest.split('\n').filter((l) => l.startsWith('segment ')).map((l) => l.split(' ').slice(1).map(Number));
  const fd = fs.openSync(dest, 'w');
  let size = 0;
  const write = (buf) => { fs.writeSync(fd, buf); size += buf.length; };
  write(src);
  let added = true;
  while (added) {
    added = false;
    for (const [off, len] of segments) {
      if (size + len > LIMIT) continue;
      write(src.subarray(off, off + len));
      added = true;
    }
  }
  fs.closeSync(fd);
  return size;
}

// ---------------------------------------------------------------------------------------------
// The server: every request is logged with its method, path, body size and the bytes sent.

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.wasm': 'application/wasm', '.json': 'application/json', '.gz': 'application/gzip', '.toml': 'text/plain; charset=utf-8',
  '.params': 'text/plain; charset=utf-8', '.md': 'text/markdown; charset=utf-8',
};
const served = [];
const server = http.createServer((req, res) => {
  const entry = { at: Date.now(), method: req.method, url: req.url, bodyBytes: 0, sentBytes: 0 };
  served.push(entry);
  req.on('data', (chunk) => { entry.bodyBytes += chunk.length; });
  req.on('end', () => {
    const url = new URL(req.url, 'http://x');
    let file = path.join(opt.site, decodeURIComponent(url.pathname));
    if (file.endsWith('/')) file = path.join(file, 'index.html');
    if (req.method !== 'GET' || !file.startsWith(opt.site) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      res.writeHead(req.method === 'GET' ? 404 : 405);
      res.end();
      return;
    }
    entry.sentBytes = fs.statSync(file).size;
    res.writeHead(200, {
      'Content-Security-Policy': CSP,
      'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream',
      'Content-Length': entry.sentBytes,
      'Cache-Control': 'no-store',
    });
    fs.createReadStream(file).pipe(res);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}/`;
const origin = new URL(base).origin;

// ---------------------------------------------------------------------------------------------
// The checks

const results = [];
let failed = 0;
function check(browser, name, ok, detail, seconds) {
  results.push({ browser, name, ok, detail, seconds });
  if (!ok) failed += 1;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${browser} ${name}: ${detail}${seconds !== undefined ? ` (${seconds.toFixed(1)} s)` : ''}`);
}

const count = (page, name) => page.evaluate((n) => Number(document.body.dataset[`${n}Count`] || 0), name);

async function waitCount(page, name, before) {
  await page.waitForFunction(([n, b]) => Number(document.body.dataset[`${n}Count`] || 0) > b, [name, before], { timeout: 600000 });
}

async function download(page, selector, dest) {
  const [dl] = await Promise.all([page.waitForEvent('download'), page.click(selector)]);
  await dl.saveAs(dest);
  return fs.readFileSync(dest);
}

async function sealOnPage(page, { log, rulesFile, rulesChoice = 'default', baseline, key, sealTime = '' }) {
  await page.click('#tab-seal');
  const before = await count(page, 'seal');
  await page.setInputFiles('#seal-log', log);
  if (rulesFile) {
    await page.check('input[name="rules"][value="file"]');
    await page.setInputFiles('#seal-rules-file', rulesFile);
  } else {
    await page.check(`input[name="rules"][value="${rulesChoice}"]`);
  }
  await page.setInputFiles('#seal-baseline', baseline || []);
  await page.setInputFiles('#seal-key', key || []);
  await page.locator('details.advanced').evaluate((d) => { d.open = true; });
  await page.fill('#seal-time', sealTime);
  await page.click('#seal-run');
  await waitCount(page, 'seal', before);
  return {
    banner: await page.textContent('#seal-banner'),
    output: await page.textContent('#seal-output'),
    links: await page.locator('#seal-downloads a').count(),
  };
}

async function verifyOnPage(page, record, pubkey, log) {
  await page.click('#tab-verify');
  const before = await count(page, 'verify');
  await page.setInputFiles('#verify-record', record);
  await page.setInputFiles('#verify-pubkey', pubkey);
  await page.setInputFiles('#verify-log', log || []);
  await page.click('#verify-run');
  await waitCount(page, 'verify', before);
  const json = await page.textContent('#verify-json');
  return {
    banner: await page.textContent('#verify-banner'),
    output: await page.textContent('#verify-output'),
    structured: json ? JSON.parse(json) : null,
  };
}

// The FAILED line of a verify output, without the prefix.
const failedLine = (text) => (/^FAILED: (.*)$/m.exec(text) || [])[1];

// Peak resident memory of one Chromium, in MiB, by process type as Chromium reports it
// (SystemInfo.getProcessInfo): "browser" (which also holds the page's Blob data), "renderer"
// (the page, its worker and the engine), and the largest of the others. The sampler reads each
// process's resident size (VmRSS) every 100 ms and keeps the largest per type and phase; `hwm`
// gives the kernel's high-water mark (VmHWM) for the whole run, which Linux updates lazily.
function memorySampler(cdp) {
  let pids = [];
  const peaks = { browser: 0, renderer: 0, other: 0 };
  const read = () => {
    for (const { id, kind } of pids) {
      try {
        const status = fs.readFileSync(`/proc/${id}/status`, 'utf8');
        const m = /VmRSS:\s+(\d+) kB/.exec(status);
        if (m) peaks[kind] = Math.max(peaks[kind], Number(m[1]) / 1024);
      } catch { /* the process ended */ }
    }
  };
  const refresh = async () => {
    const { processInfo } = await cdp.send('SystemInfo.getProcessInfo');
    pids = processInfo.map((p) => ({ id: p.id, kind: p.type === 'browser' || p.type === 'renderer' ? p.type : 'other' }));
  };
  const timer = setInterval(read, 100);
  return {
    refresh,
    // The peaks so far, and a fresh start for the next phase.
    async phase() {
      await refresh();
      read();
      const out = { ...peaks };
      for (const k of Object.keys(peaks)) peaks[k] = 0;
      return out;
    },
    hwm() {
      const out = { browser: 0, renderer: 0, other: 0 };
      for (const { id, kind } of pids) {
        try {
          const m = /VmHWM:\s+(\d+) kB/.exec(fs.readFileSync(`/proc/${id}/status`, 'utf8'));
          if (m) out[kind] = Math.max(out[kind], Number(m[1]) / 1024);
        } catch { /* the process ended */ }
      }
      return out;
    },
    stop: () => clearInterval(timer),
  };
}

const mib = (p) => `browser ${p.browser.toFixed(0)}, renderer ${p.renderer.toFixed(0)}, other ${p.other.toFixed(0)} MiB`;

const engines = { chromium, firefox, webkit };
const memory = {};
const transfer = {};
for (const name of opt.browsers.split(',')) {
  const launchOpts = name === 'chromium' && process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {};
  const browser = await engines[name].launch(launchOpts);
  const version = browser.version();
  const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  // Every http(s) request the browser makes for the page and its worker, from the first one.
  const seen = [];
  context.on('request', (r) => {
    if (!/^https?:/.test(r.url())) return;
    const body = r.postDataBuffer();
    seen.push({ at: Date.now(), method: r.method(), url: r.url(), body: body ? body.length : 0 });
  });
  page.on('pageerror', (e) => console.log(`${name} page error: ${e.message}`));
  const dl = path.join(opt.out, name);
  fs.mkdirSync(dl);
  const servedFrom = served.length;
  const mark = () => ({ server: served.length, browser: seen.length });
  const since = (w) => ({ server: served.slice(w.server), browser: seen.slice(w.browser) });
  const userFile = []; // [phase, requests] during user-file seal and verify: each must be empty

  let t = Date.now();
  await page.goto(base);
  await page.waitForSelector('body[data-ready="true"]', { timeout: 180000 });
  const loadServed = served.slice(servedFrom);
  check(name, 'loads', true, `${version}, Ready after ${loadServed.length} requests to this site (${loadServed.map((s) => s.url).join(', ')})`, (Date.now() - t) / 1000);

  // records
  t = Date.now();
  let w = mark();
  let same = 0;
  const differ = [];
  const cases = [...golden.map((g) => ({ id: g.name, log: g.log, rulesFile: g.rules, baseline: g.baseline })),
    { id: 'no baseline', log: noBaselineLog, rulesChoice: 'default', baseline: null }];
  for (const c of cases) {
    const want = cli[c.id];
    const r = await sealOnPage(page, {
      log: path.join(root, c.log),
      rulesFile: c.rulesFile ? path.join(root, c.rulesFile) : null,
      rulesChoice: c.rulesChoice,
      baseline: c.baseline ? path.join(root, c.baseline) : null,
      key: path.join(keyDir, 'sfr.key'),
      sealTime: SEAL_TIME,
    });
    if (r.links < 2) { differ.push(`${c.id}: no record (${r.banner.trim()})`); continue; }
    const record = await download(page, '#seal-downloads a:nth-child(1)', path.join(dl, `${c.id}.sfr`));
    const report = await download(page, '#seal-downloads a:nth-child(2)', path.join(dl, `${c.id}.sfr.md`));
    const problems = [];
    if (!record.equals(want.record)) problems.push('record');
    if (!report.equals(want.report)) problems.push('report');
    if (r.output !== want.text) problems.push('output text');
    if (!r.banner.includes(`(exit ${want.code})`)) problems.push(`exit code (CLI ${want.code})`);
    if (problems.length) differ.push(`${c.id}: ${problems.join(', ')} differ`);
    else same += 1;
  }
  userFile.push(['seal of every golden log', since(w)]);
  check(name, 'records', differ.length === 0, `byte-identical records and reports, output and exit code: ${same} of ${cases.length} (${golden.length} golden logs and the no-baseline case)${differ.length ? `; ${differ.join('; ')}` : ''}`, (Date.now() - t) / 1000);

  // key: the in-browser key, as a person uses the page (no key file, no seal time)
  t = Date.now();
  w = mark();
  {
    const r = await sealOnPage(page, {
      log: path.join(root, 'testdata/sitl/v1.17.0/gz_quadtailsitter_transition.ulg'),
      baseline: path.join(root, 'testdata/baselines/v1.17.0_gz_quadtailsitter_transition.params'),
    });
    const kdir = path.join(dl, 'in-browser-key');
    fs.mkdirSync(kdir);
    await download(page, '#seal-downloads a:nth-child(1)', path.join(kdir, 'tailsitter.sfr'));
    await download(page, '#seal-downloads a:nth-child(3)', path.join(kdir, 'sfr.pub'));
    link(kdir, 'testdata/sitl/v1.17.0/gz_quadtailsitter_transition.ulg', 'tailsitter.ulg');
    const v = sfr(kdir, ['verify', 'tailsitter.sfr', '--pubkey', 'sfr.pub', '--ulog', 'tailsitter.ulg']);
    const label = /"key_label":"([^"]*)"/.exec(fs.readFileSync(path.join(kdir, 'tailsitter.sfr'), 'utf8'));
    check(name, 'in-browser key', r.banner.includes('PASS.') && v.code === 0 && v.stdout.includes('VERIFIED (record and log)') && label && label[1].startsWith('EVALUATION KEY'),
      `sealed with the in-browser key (label "${label ? label[1] : '?'}"); sfr verify --ulog with the page's sfr.pub: exit ${v.code}, ${v.stdout.split('\n')[1] || v.stdout.split('\n')[0]}`, (Date.now() - t) / 1000);
  }
  userFile.push(['seal with the in-browser key', since(w)]);
  for (const scheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.screenshot({ path: path.join(opt.out, `${name}-seal-${scheme}.png`), fullPage: true });
  }
  await page.emulateMedia({ colorScheme: 'light' });

  // verify
  t = Date.now();
  w = mark();
  const vbad = [];
  for (const c of verifyCases) {
    const r = await verifyOnPage(page, path.join(vdir, c.record), path.join(vdir, 'sfr.pub'), c.log ? path.join(vdir, c.log) : null);
    const where = `${c.record}${c.log ? ` with ${c.log}` : ''}`;
    if (r.output !== c.stdout) vbad.push(`${where}: page printed ${JSON.stringify(r.output.split('\n').slice(0, 2))}, CLI ${JSON.stringify(c.stdout.split('\n').slice(0, 2))}`);
    const m = r.structured && r.structured.mismatch;
    if (c.code === 0 && (m || !r.structured.verified)) vbad.push(`${where}: structured result says not verified`);
    if (c.code === 1 && (!m || m.text !== failedLine(c.stdout))) vbad.push(`${where}: structured mismatch text ${m && m.text} is not the FAILED line`);
  }
  const deep = await verifyOnPage(page, path.join(vdir, 'tampered.sfr'), path.join(vdir, 'sfr.pub'), path.join(vdir, 'vtol_transition.ulg'));
  const m = deep.structured.mismatch;
  const parts = m && `kind ${m.kind}, seq ${m.seq}, event kind ${m.eventKind}, field ${m.field}, sealed ${m.sealed}, found ${m.found}`;
  const shaped = m && m.kind === 'event' && Number.isInteger(m.seq) && m.eventKind === 'COMMAND' && m.field === 'command'
    && m.sealed !== m.found && m.text === `event seq ${m.seq} (COMMAND) field \`command\`: sealed ${m.sealed}, found ${m.found}`;
  if (!shaped) vbad.push(`the changed record with its log: structured mismatch ${JSON.stringify(m)}`);
  userFile.push(['verify', since(w)]);
  check(name, 'verify', vbad.length === 0, `the verify panel prints what sfr verify prints: ${verifyCases.length - vbad.length} of ${verifyCases.length} cases; structured first mismatch of the changed record with its log: ${parts}${vbad.length ? `; ${vbad.join('; ')}` : ''}`, (Date.now() - t) / 1000);
  for (const scheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.screenshot({ path: path.join(opt.out, `${name}-verify-${scheme}.png`), fullPage: true });
  }
  await page.emulateMedia({ colorScheme: 'light' });

  // limit: a file one byte over the limit, refused by its size (a sparse file; never read)
  t = Date.now();
  w = mark();
  {
    const big = path.join(work, `over-${name}.ulg`);
    fs.closeSync(fs.openSync(big, 'w'));
    fs.truncateSync(big, LIMIT + 1);
    const r = await sealOnPage(page, { log: big, baseline: null });
    const want = `log over-${name}.ulg: ${LIMIT + 1} bytes is over the sandbox's limit of ${LIMIT} bytes (100 MiB)`;
    check(name, 'limit', r.banner.includes('Not sealed (exit 4).') && r.banner.includes(want), r.banner.trim(), (Date.now() - t) / 1000);
    fs.rmSync(big);
  }
  userFile.push(['refused oversize log', since(w)]);

  // demo: fetches the sample on demand
  t = Date.now();
  w = mark();
  await page.click('#tab-demo');
  const before = await count(page, 'demo');
  await page.click('#demo-run');
  await waitCount(page, 'demo', before);
  const demoRequests = since(w);
  const steps = await page.$$eval('#demo-steps li', (lis) => lis.map((li) => ({
    step: li.dataset.step,
    ok: li.dataset.ok,
    runs: [...li.querySelectorAll('pre.output[data-code]')].map((p) => ({ code: Number(p.dataset.code), text: p.textContent.replace(/\(exit \d+\)$/, '') })),
    mismatches: [...li.querySelectorAll('p.mismatch')].map((p) => JSON.parse(p.dataset.mismatch)),
  })));
  const summary = await page.textContent('#demo-summary');
  const dbad = [];
  for (const letter of ['b', 'c', 'd', 'e']) {
    const mine = steps.find((s) => s.step === letter);
    const theirs = demoCli[letter];
    if (!mine || mine.ok !== 'true') { dbad.push(`step ${letter} not passed on the page`); continue; }
    if (mine.runs.length !== theirs.length) { dbad.push(`step ${letter}: ${mine.runs.length} commands, the CLI ${theirs.length}`); continue; }
    mine.runs.forEach((run, i) => {
      const other = theirs[i];
      if (run.code !== other.code) dbad.push(`step ${letter} command ${i + 1}: exit ${run.code}, the CLI ${other.code}`);
      if (mask(run.text) !== mask(other.text)) dbad.push(`step ${letter} command ${i + 1}: output differs:\n--- page\n${mask(run.text)}\n--- sfr\n${mask(other.text)}`);
    });
  }
  const stepOf = (id) => steps.find((s) => s.step === id) || { mismatches: [] };
  const d2 = stepOf('d').mismatches[1];
  const e1 = stepOf('e').mismatches[0];
  if (!d2 || d2.kind !== 'event' || d2.eventKind !== 'COMMAND' || d2.field !== 'command') dbad.push(`step d: structured mismatch ${JSON.stringify(d2)}`);
  if (!e1 || e1.kind !== 'parameter' || e1.parameter !== sample.parameter || e1.found !== 'f32:7') dbad.push(`step e: structured mismatch ${JSON.stringify(e1)}`);
  const sampleTransfer = await page.evaluate(async () => (await (await import('./engine/sfr.js')).loadSample()).transfer);
  const gzServed = demoRequests.server.find((s) => s.url.endsWith('.ulg.gz'));
  transfer[name] = { ...sampleTransfer, servedBytes: gzServed ? gzServed.sentBytes : null, logBytes: sample.size };
  check(name, 'demo', dbad.length === 0 && summary.includes('DEMO PASSED'),
    `${summary.trim()} Steps b to e give the exit codes and output of sfr running the same steps on ${sample.log}; step d's structured mismatch: ${d2 && `${d2.kind} seq ${d2.seq} ${d2.eventKind} field ${d2.field}, sealed ${d2.sealed}, found ${d2.found}`}; step e's: ${e1 && `${e1.kind} ${e1.parameter}, sealed ${e1.sealed}, found ${e1.found}`}. Sample: ${sample.size} bytes, served compressed as ${gzServed ? gzServed.sentBytes : '?'} bytes${sampleTransfer.transferBytes ? `, ${sampleTransfer.transferBytes} bytes on the wire as the browser reports it` : ''}${dbad.length ? `; ${dbad.join('; ')}` : ''}`, (Date.now() - t) / 1000);
  for (const scheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.screenshot({ path: path.join(opt.out, `${name}-demo-${scheme}.png`), fullPage: true });
  }
  await page.emulateMedia({ colorScheme: 'light' });

  // After the demo: user-file seal and verify again, with the sample in memory.
  w = mark();
  await sealOnPage(page, { log: path.join(root, noBaselineLog), baseline: path.join(root, 'testdata/baselines/v1.17.0_mc_flight_1.params') });
  await verifyOnPage(page, path.join(vdir, 'vtol_transition.sfr'), path.join(vdir, 'sfr.pub'), path.join(vdir, 'vtol_transition.ulg'));
  userFile.push(['seal and verify after the demo', since(w)]);

  // network
  const sampleFiles = new Set(['samples.json', sample.gz, sample.baseline].map((f) => `/engine/samples/${f}`));
  const nbad = [];
  for (const [phase, reqs] of userFile) {
    if (reqs.server.length || reqs.browser.length) nbad.push(`${phase}: ${reqs.server.length + reqs.browser.length} requests (${[...reqs.server.map((s) => s.url), ...reqs.browser.map((b) => b.url)].join(', ')})`);
  }
  for (const s of demoRequests.server) if (s.method !== 'GET' || !sampleFiles.has(s.url)) nbad.push(`demo: ${s.method} ${s.url} is not a GET of the sample's files`);
  for (const b of demoRequests.browser) if (b.method !== 'GET' || new URL(b.url).origin !== origin || !sampleFiles.has(new URL(b.url).pathname)) nbad.push(`demo: ${b.method} ${b.url}`);
  const all = { server: served.slice(servedFrom), browser: seen };
  for (const s of all.server) if (s.bodyBytes || s.method !== 'GET') nbad.push(`${s.method} ${s.url} with a ${s.bodyBytes}-byte body`);
  for (const b of all.browser) {
    if (b.body) nbad.push(`${b.method} ${b.url} with a body`);
    if (new URL(b.url).origin !== origin) nbad.push(`a request to another host: ${b.url}`);
  }
  check(name, 'network', nbad.length === 0,
    `user-file seal and verify (${userFile.map(([p]) => p).join('; ')}): no request; the demo: ${demoRequests.server.length} same-origin GET requests, all for the sample (${demoRequests.server.map((s) => s.url).join(', ')}); whole session: ${all.server.length} requests at the server and ${all.browser.length} seen by the browser, none with a body, none to another host${nbad.length ? `; ${nbad.join('; ')}` : ''}`);
  await context.close();
  await browser.close();

  // memory (Chromium): a fresh browser, so the peaks below are this one page's alone
  if (name === 'chromium') {
    const large = path.join(work, 'largest.ulg');
    const size = largestLog(large);
    const fresh = await chromium.launch(launchOpts);
    const cdp = await fresh.newBrowserCDPSession();
    const sampler = memorySampler(cdp);
    const ctx = await fresh.newContext({ acceptDownloads: true });
    const p = await ctx.newPage();
    await sampler.refresh();
    await p.goto(base);
    await p.waitForSelector('body[data-ready="true"]', { timeout: 180000 });
    const atLoad = await sampler.phase();
    t = Date.now();
    const r = await sealOnPage(p, {
      log: large,
      baseline: path.join(root, 'testdata/baselines/v1.17.0_vtol_transition.params'),
    });
    const sealSeconds = (Date.now() - t) / 1000;
    const inSeal = await sampler.phase();
    const engineMiB = () => p.evaluate(async () => (await import('./engine/sfr.js')).engineMemoryBytes() / 1048576);
    const engineSeal = await engineMiB();
    const record = path.join(work, 'largest.sfr');
    await download(p, '#seal-downloads a:nth-child(1)', record);
    await download(p, '#seal-downloads a:nth-child(3)', path.join(work, 'largest.pub'));
    await sampler.phase();
    t = Date.now();
    const v = await verifyOnPage(p, record, path.join(work, 'largest.pub'), large);
    const verifySeconds = (Date.now() - t) / 1000;
    const inVerify = await sampler.phase();
    const session = sampler.hwm();
    sampler.stop();
    const engineVerify = await engineMiB();
    memory.chromium = {
      log_bytes: size, high_water_mib_whole_run: session, peak_mib_loading: atLoad, peak_mib_sealing: inSeal, peak_mib_verifying_with_log: inVerify,
      engine_mib_after_seal: engineSeal, engine_mib_after_verify: engineVerify, seal_seconds: sealSeconds, verify_seconds: verifySeconds,
    };
    const sealed = /\(exit [012]\)/.test(r.banner);
    check(name, 'memory', sealed && v.banner.includes('VERIFIED (record and log)') && inSeal.renderer > 0,
      `largest allowed log, ${size} bytes: sealed in ${sealSeconds.toFixed(1)} s (${r.banner.trim().split('.')[0]}), then verified with the log in ${verifySeconds.toFixed(1)} s. Peak resident memory by Chromium process: loading the page ${mib(atLoad)}; sealing ${mib(inSeal)}; verifying with the log ${mib(inVerify)}; kernel high-water mark for the whole run ${mib(session)}. Engine (WebAssembly) memory: ${engineSeal.toFixed(0)} MiB after the seal, ${engineVerify.toFixed(0)} MiB after the deep verify`);
    await fresh.close();
    fs.rmSync(large);
  }
}
server.close();

// ---------------------------------------------------------------------------------------------
// Summary

const lines = ['# Sandbox browser test', '', '| Browser | Check | Result | Detail | Seconds |', '|---|---|---|---|---|'];
for (const r of results) {
  lines.push(`| ${r.browser} | ${r.name} | ${r.ok ? 'PASS' : 'FAIL'} | ${r.detail.replaceAll('|', '/').replaceAll('\n', ' ')} | ${r.seconds !== undefined ? r.seconds.toFixed(1) : ''} |`);
}
fs.writeFileSync(path.join(opt.out, 'summary.md'), `${lines.join('\n')}\n`);
fs.writeFileSync(path.join(opt.out, 'summary.json'), `${JSON.stringify({ results, memory, transfer }, null, 2)}\n`);
console.log(`sandbox browser test: ${results.length - failed} of ${results.length} checks passed`);
process.exit(failed ? 1 : 0);
