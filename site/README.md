# site/

The test harness page for the engine bundle (`docs/SANDBOX.md`): a plain page that CI's browser gate (`tests/browser/sandbox.test.mjs`) drives in Chromium, Firefox and WebKit. The page that invited evaluators use is built elsewhere on the same bundle; this page has no design work and is not deployed.

| File | What it does |
|---|---|
| `index.html`, `style.css` | the page: Seal, Verify and Tamper demo panels |
| `app.js` | the three panels, over `engine/sfr.js` (the bundle's API) |
| `markdown.js` | shows the `.sfr.md` report as a page, setting text only, never HTML |

`scripts/build_site.sh <out-dir>` puts these files next to a fresh engine bundle in `<out-dir>/engine/`. Files chosen on the page are read in the browser and never uploaded.
