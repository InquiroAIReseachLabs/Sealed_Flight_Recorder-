# site/

A plain test page for the engine bundle (`docs/SANDBOX.md`), driven in Chromium, Firefox and WebKit by CI's browser gate (`tests/browser/sandbox.test.mjs`). It is not deployed.

| File | What it does |
|---|---|
| `index.html`, `style.css` | the Seal, Verify and Tamper demo panels |
| `app.js` | the panels, over `engine/sfr.js` |
| `markdown.js` | shows the `.sfr.md` report as text, never HTML |

`scripts/build_site.sh <out-dir>` puts these files next to a fresh engine bundle in `<out-dir>/engine/`. Files chosen on the page are read in the browser and never uploaded.
