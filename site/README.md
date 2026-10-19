# site/

The sandbox page (SPEC B1.2, B1.10 Sandbox; `docs/SANDBOX.md`): HTML, CSS and JavaScript that load `crates/sfr-wasm`, the `sfr` engine built for WebAssembly.

| File | What it does |
|---|---|
| `index.html`, `style.css` | the page: Seal, Verify and Tamper demo panels, light and dark |
| `app.js` | loading, the three panels, the tamper demo (the steps of `scripts/run_demo.sh`) |
| `worker.js` | the engine's thread: loads `sfr-wasm`, reads the chosen files a piece at a time, runs seal and verify |
| `markdown.js` | shows the `.sfr.md` report as a page, setting text only, never HTML |
| `_headers` | the security headers Cloudflare Pages sends: the browser may contact this site only |

`scripts/build_site.sh <out-dir>` assembles a site ready to serve from these files, the built engine, the example rules and the two sample logs. `tests/browser/sandbox.test.mjs` is its gate.

Rules: no third-party scripts, fonts, analytics or CDN; zero network requests after the page says Ready. Files chosen on the page never leave the browser.
