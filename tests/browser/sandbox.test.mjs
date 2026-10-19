// sandbox.test.mjs: the headless browser gate for the sandbox page (SPEC B1.10 Sandbox, Chunk 6).
//
// Serves a built site (scripts/build_site.sh) on 127.0.0.1 with the headers of its _headers
// file, opens it in each browser, and checks, through the page's own controls:
//
//   network   after the page says Ready, sealing, verifying and the tamper demo make no network
//             request: the server logs every request it gets, and the browser reports every
//             http(s) request of the page and its worker
//   records   every golden log, sealed on the page with its golden rules and baseline, the CLI's
//             evaluation key file and one seal time, downloads a record and a report
//             byte-identical to those of `sfr seal`, and the page shows what `sfr seal` prints;
//             the same for a log sealed without a baseline (the bundled default rules)
//   key       a record sealed with the in-browser key verifies with `sfr verify` and the page's
//             sfr.pub
//   verify    the verify panel prints what `sfr verify` prints, verified and failed
//   demo      the tamper demo gives the exit codes and output of scripts/run_demo.sh, step by
//             step (fingerprints, digests, times and directories aside: the demo makes its own
//             key)
//   limit     a log over the sandbox's 100 MiB limit is refused with its message, unread
//   memory    Chromium only: the page's peak memory sealing, then verifying with the log, the
//             largest log the sandbox allows (built like scripts/benchmark.sh's large logs)
//
// It saves screenshots of the three panels, light and dark, per browser, and writes summary.md
// and summary.json to the output directory. Exits 1 on any failed check.
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

// The sandbox's no-baseline text, as crates/sfr-wasm states it.
const lib = fs.readFileSync(path.join(root, 'crates/sfr-wasm/src/lib.rs'), 'utf8');
const NO_BASELINE = JSON.parse(/pub const NO_BASELINE: &str = ("(?:[^"\\]|\\.)*");/.exec(lib)[1]);
const NO_BASELINE_NAME = /pub const NO_BASELINE_NAME: &str = "([^"]+)";/.exec(lib)[1];

const cli = {};
for (const g of golden) cli[g.name] = cliSeal(g.name, g.log, g.rules, g.baseline);
const noBaselineLog = 'testdata/sitl/v1.17.0/mc_flight_1.ulg';
cli['no baseline'] = cliSeal('no-baseline', noBaselineLog, 'examples/rules.default.toml', NO_BASELINE_NAME, NO_BASELINE);

// Verify cases: the CLI's own record of the golden VTOL flight, a copy with a changed command
// id (scripts/run_demo.sh step d), and a copy of the log with one changed byte.
const vdir = path.join(work, 'verify');
fs.mkdirSync(vdir);
const vtol = cli['v1.17.0_vtol_transition'];
fs.writeFileSync(path.join(vdir, 'vtol_transition.sfr'), vtol.record);
fs.copyFileSync(path.join(keyDir, 'sfr.pub'), path.join(vdir, 'sfr.pub'));
link(vdir, 'testdata/sitl/v1.17.0/vtol_transition.ulg', 'vtol_transition.ulg');
{
  const text = vtol.record.toString('latin1');
  const kind = text.indexOf('"kind":"COMMAND"');
  const at = text.lastIndexOf('"command":', kind - 10) + 10;
  const t = Buffer.from(vtol.record);
  t[at] = t[at] === 0x39 ? 0x31 : t[at] + 1;
  fs.writeFileSync(path.join(vdir, 'tampered.sfr'), t);
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

// scripts/run_demo.sh with this sfr, split into steps.
const demo = spawnSync('sh', [path.join(root, 'scripts/run_demo.sh')], {
  cwd: root, encoding: 'utf8', env: { ...process.env, SFR: opt.sfr }, maxBuffer: 64 << 20,
});
if (demo.status !== 0) throw new Error(`run_demo.sh failed:\n${demo.stdout}\n${demo.stderr}`);
const demoSteps = parseDemo(demo.stdout);

function parseDemo(text) {
  const steps = {};
  let step = null;
  let cur = null;
  for (const line of text.split('\n')) {
    const h = /^=== ([a-f])\. .* ===$/.exec(line);
    if (h) {
      step = { runs: [], notes: [] };
      steps[h[1]] = step;
      cur = null;
    } else if (!step) {
      // before the first step
    } else if (line.startsWith('$ sfr')) {
      cur = { lines: [] };
    } else if (cur && /^\(exit \d+\)$/.test(line)) {
      step.runs.push({ code: Number(/\d+/.exec(line)[0]), text: cur.lines.join('\n') });
      cur = null;
    } else if (cur) {
      cur.lines.push(line);
    } else if (/^(events in the record|byte \d+|bytes \d+)/.test(line)) {
      step.notes.push(line);
    }
  }
  return steps;
}

// Output with what differs between two runs masked: directories, digests and keys, times.
function mask(text) {
  return text
    .replace(/(^|\s)\/(?:[^\s/]+\/)+([^\s/]+)/gm, '$1$2')
    .replace(/[0-9a-f]{64}/g, '<hex>')
    .replace(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z/g, '<time>')
    .trimEnd();
}

// The largest log the sandbox allows: the golden VTOL flight, then its whole-record segments
// (scripts/benchmark/vtol_transition.segments) in order, again and again, while the log stays
// within the limit.
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
// The site

const headers = {};
for (const line of fs.readFileSync(path.join(opt.site, '_headers'), 'utf8').split('\n')) {
  const m = /^\s+([A-Za-z-]+):\s*(.+)$/.exec(line);
  if (m) headers[m[1]] = m[2];
}
const TYPES = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.wasm': 'application/wasm', '.json': 'application/json', '.gz': 'application/gzip', '.toml': 'text/plain; charset=utf-8',
  '.params': 'text/plain; charset=utf-8', '.md': 'text/markdown; charset=utf-8',
};
const served = [];
const server = http.createServer((req, res) => {
  served.push({ at: Date.now(), url: req.url });
  const url = new URL(req.url, 'http://x');
  let file = path.join(opt.site, decodeURIComponent(url.pathname));
  if (file.endsWith('/')) file = path.join(file, 'index.html');
  if (!file.startsWith(opt.site) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
    res.writeHead(404);
    res.end();
    return;
  }
  res.writeHead(200, { ...headers, 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
  fs.createReadStream(file).pipe(res);
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}/`;

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
  return { banner: await page.textContent('#verify-banner'), output: await page.textContent('#verify-output') };
}

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
for (const name of opt.browsers.split(',')) {
  const launchOpts = name === 'chromium' && process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {};
  const browser = await engines[name].launch(launchOpts);
  const version = browser.version();
  const context = await browser.newContext({ acceptDownloads: true, viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  const late = [];
  let ready = false;
  context.on('request', (r) => { if (ready && /^https?:/.test(r.url())) late.push(r.url()); });
  page.on('pageerror', (e) => console.log(`${name} page error: ${e.message}`));
  const dl = path.join(opt.out, name);
  fs.mkdirSync(dl);

  let t = Date.now();
  const servedBefore = served.length;
  await page.goto(base);
  await page.waitForSelector('body[data-ready="true"]', { timeout: 180000 });
  check(name, 'loads', true, `${version}, Ready after ${served.length - servedBefore} requests to this site`, (Date.now() - t) / 1000);
  const servedAtReady = served.length;
  ready = true;

  // records
  t = Date.now();
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
  check(name, 'records', differ.length === 0, `byte-identical records and reports, output and exit code: ${same} of ${cases.length} (${golden.length} golden logs and the no-baseline case)${differ.length ? `; ${differ.join('; ')}` : ''}`, (Date.now() - t) / 1000);

  // key: the in-browser key, as a person uses the page (no key file, no seal time)
  t = Date.now();
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
  for (const scheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.screenshot({ path: path.join(opt.out, `${name}-seal-${scheme}.png`), fullPage: true });
  }
  await page.emulateMedia({ colorScheme: 'light' });

  // verify
  t = Date.now();
  const vbad = [];
  for (const c of verifyCases) {
    const r = await verifyOnPage(page, path.join(vdir, c.record), path.join(vdir, 'sfr.pub'), c.log ? path.join(vdir, c.log) : null);
    if (r.output !== c.stdout) vbad.push(`${c.record}${c.log ? ` with ${c.log}` : ''}: page printed ${JSON.stringify(r.output.split('\n').slice(0, 2))}, CLI ${JSON.stringify(c.stdout.split('\n').slice(0, 2))}`);
  }
  check(name, 'verify', vbad.length === 0, `the verify panel prints what sfr verify prints: ${verifyCases.length - vbad.length} of ${verifyCases.length} cases (VERIFIED standalone and deep, a changed record standalone and deep, a changed log)${vbad.length ? `; ${vbad.join('; ')}` : ''}`, (Date.now() - t) / 1000);
  await verifyOnPage(page, path.join(vdir, 'tampered.sfr'), path.join(vdir, 'sfr.pub'), path.join(vdir, 'vtol_transition.ulg'));
  for (const scheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.screenshot({ path: path.join(opt.out, `${name}-verify-${scheme}.png`), fullPage: true });
  }
  await page.emulateMedia({ colorScheme: 'light' });

  // demo
  t = Date.now();
  await page.click('#tab-demo');
  const before = await count(page, 'demo');
  await page.click('#demo-run');
  await waitCount(page, 'demo', before);
  const steps = await page.$$eval('#demo-steps li', (lis) => lis.map((li) => ({
    step: li.dataset.step,
    ok: li.dataset.ok,
    runs: [...li.querySelectorAll('pre.output[data-code]')].map((p) => ({ code: Number(p.dataset.code), text: p.textContent.replace(/\n?\(exit \d+\)$/, '') })),
    notes: [...li.querySelectorAll('p')].map((p) => p.textContent),
  })));
  const summary = await page.textContent('#demo-summary');
  const dbad = [];
  for (const letter of ['a', 'b', 'c', 'd', 'e']) {
    const mine = steps.find((s) => s.step === letter);
    const theirs = demoSteps[letter];
    if (!mine || mine.ok !== 'true') { dbad.push(`step ${letter} not passed on the page`); continue; }
    if (mine.runs.length !== theirs.runs.length) { dbad.push(`step ${letter}: ${mine.runs.length} commands, run_demo.sh ${theirs.runs.length}`); continue; }
    mine.runs.forEach((run, i) => {
      const other = theirs.runs[i];
      if (run.code !== other.code) dbad.push(`step ${letter} command ${i + 1}: exit ${run.code}, run_demo.sh ${other.code}`);
      // Step a: keygen writes files the page does not; its first line is compared.
      const a = letter === 'a' ? run.text.split('\n')[0] : mask(run.text);
      const b = letter === 'a' ? other.text.split('\n')[0] : mask(other.text);
      if (a !== b) dbad.push(`step ${letter} command ${i + 1}: output differs:\n--- page\n${a}\n--- run_demo.sh\n${b}`);
    });
    for (const note of theirs.notes) if (!mine.notes.includes(note)) dbad.push(`step ${letter}: run_demo.sh says "${note}", the page does not`);
  }
  check(name, 'demo', dbad.length === 0 && summary.includes('DEMO PASSED'), `${summary.trim()} Steps a to e: the same exit codes and output as run_demo.sh${dbad.length ? `; ${dbad.join('; ')}` : ''}`, (Date.now() - t) / 1000);
  for (const scheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme: scheme });
    await page.screenshot({ path: path.join(opt.out, `${name}-demo-${scheme}.png`), fullPage: true });
  }
  await page.emulateMedia({ colorScheme: 'light' });

  // limit: a file one byte over the limit, refused by its size (a sparse file; never read)
  t = Date.now();
  {
    const big = path.join(work, `over-${name}.ulg`);
    fs.closeSync(fs.openSync(big, 'w'));
    fs.truncateSync(big, LIMIT + 1);
    const r = await sealOnPage(page, { log: big, baseline: null });
    const want = `log over-${name}.ulg: ${LIMIT + 1} bytes is over the sandbox's limit of ${LIMIT} bytes (100 MiB)`;
    check(name, 'limit', r.banner.includes('Not sealed (exit 4).') && r.banner.includes(want), r.banner.trim(), (Date.now() - t) / 1000);
    fs.rmSync(big);
  }

  // network: nothing after Ready, at the server or in the browser
  const after = served.slice(servedAtReady);
  check(name, 'network', after.length === 0 && late.length === 0,
    `requests after Ready: ${after.length} at the server, ${late.length} seen by the browser${after.length + late.length ? `: ${[...after.map((s) => s.url), ...late].join(', ')}` : ''}`);
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
    const engineSeal = Number(await p.evaluate(() => document.body.dataset.engineBytes)) / 1048576;
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
    const engineVerify = Number(await p.evaluate(() => document.body.dataset.engineBytes)) / 1048576;
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
fs.writeFileSync(path.join(opt.out, 'summary.json'), `${JSON.stringify({ results, memory }, null, 2)}\n`);
console.log(`sandbox browser test: ${results.length - failed} of ${results.length} checks passed`);
process.exit(failed ? 1 : 0);
