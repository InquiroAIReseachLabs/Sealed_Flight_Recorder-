# Sandbox

The sandbox is a static web page that runs `sfr` in the browser: it seals a PX4 log, verifies a record, and runs the tamper demo of `scripts/run_demo.sh` on two bundled golden logs. It is a v1.0 evaluation release, for people evaluating Sealed Flight Record who do not want to install anything.

## What it is and what it promises

- **One engine.** The page runs `crates/sfr-wasm`, the `sfr-core` engine built for WebAssembly, with the same crypto crates as the command line (`sha2`, `ed25519-dalek`, `blake3`). Given the same log, rules, baseline, key and seal time, it writes a record and a report byte-identical to `sfr seal`, and prints what `sfr seal` and `sfr verify` print (SPEC B1.10 Sandbox). The CI job `sandbox` checks this on every golden log in Chromium, Firefox and WebKit.
- **Your files never leave the browser.** The page loads its engine, the two example rules files and the two sample logs once. After the status line says Ready it makes no network request: files are read in the tab, and downloads are made from memory. The CI job checks that the server receives no request, and the browser reports none, after Ready. The page's security headers (`site/_headers`) let the browser contact only the site itself, and the page loads no third-party script, font, analytics or content delivery network.
- **Evaluation keys only.** The page makes an Ed25519 key in the tab when it loads (the browser's random number generator), labeled `EVALUATION KEY (sandbox, in-browser)` in the record, custody `file-evaluation`. It is never written anywhere and is gone when the tab closes; the page offers its public key (`sfr.pub`) for download so records sealed with it can be verified later. Under "Same bytes as the command line", an evaluation key file from `sfr keygen --evaluation-only` and a seal time can be given instead. Operational records are sealed with the command line and a hardware key.
- **Without a baseline**, the page seals with an empty baseline (firmware `none`, no parameters; `NO_BASELINE` in `crates/sfr-wasm/src/lib.rs`), so R2 and R3 fail and say what they found. Nothing is assumed.
- **Limit.** One log or record of at most 100 MiB (104,857,600 bytes). A larger file is refused, unread, with a message naming the limit (`docs/LIMITS.md`). The engine streams the log, so its own memory stays small; the CI job reports the browser's peak memory for the largest allowed log.

## Build

`scripts/build_site.sh <out-dir>` builds the engine (release profile, the checkout's commit as the build commit), generates its JavaScript glue with `wasm-bindgen-cli` of the version `Cargo.lock` pins (`WASM_BINDGEN` names the binary), and writes the page, the engine, the example rules and the gzip-compressed sample logs to `<out-dir>`. The largest file is about 10 MB, under the 25 MiB per-file limit of Cloudflare Pages. Every CI run uploads this directory as the artifact `sfr-sandbox-site`; that is what the founder deploys.

`node tests/browser/sandbox.test.mjs --site <out-dir> --sfr <sfr built from the same commit> --out <dir>` is the browser gate (`npm ci` in `tests/browser` first). It writes `summary.md` and screenshots of the three panels, light and dark.

## Deploy on Cloudflare Pages behind Cloudflare Access (founder checklist)

The founder performs these steps. Cloudflare renames dashboard buttons from time to time; if a label differs, look for the nearest match. You need a Cloudflare account. Your domain's DNS must be on Cloudflare for the custom subdomain; without that, use only the `pages.dev` address (step 13 still protects it).

**Get the files**

1. Choose the subdomain, for example `sandbox.<your domain>`. Write it down; steps 9 and 12 use it.
2. On GitHub, open the repository, then **Actions**, then the CI run of the commit to deploy (the one with every job green).
3. At the bottom of the run page, under **Artifacts**, download **sfr-sandbox-site**. It is a zip file. Keep it as it is.

**Create the site**

4. Sign in to the Cloudflare dashboard and open **Workers & Pages**.
5. Select **Create application**, then the **Pages** tab, then **Upload assets** (also called "drag and drop your files").
6. Enter a project name, for example `sfr-sandbox`. It becomes `<project name>.pages.dev`.
7. Drag the zip file from step 3 onto the upload area and select **Deploy site**. Wait for "Success".
8. Do not turn on **Web Analytics** for this project, and do not enable Rocket Loader or Zaraz for the domain: each adds a script to the page, which the page's rules then block.

**Add the subdomain**

9. In the project, open **Custom domains**, select **Set up a custom domain**, enter the subdomain from step 1, and confirm. Cloudflare adds the DNS record. Wait until the domain shows **Active**.

**Restrict it to your email list (Cloudflare Access)**

10. Open **Zero Trust** from the dashboard's left menu. The first time, choose a team name and the Free plan (up to 50 users).
11. Go to **Access**, then **Applications**, then **Add an application**, and choose **Self-hosted**.
12. Name it `SFR sandbox`. Under the application domain, enter the subdomain from step 1.
13. Add a second application domain: `<project name>.pages.dev`. Add a third: `*.<project name>.pages.dev` (the preview addresses). Otherwise the page stays reachable at those addresses without a login.
14. Leave the session duration at 24 hours or shorter. Select **Next**.
15. Add a policy: name `Allowed evaluators`, action **Allow**. Under **Include**, choose **Emails** and enter each email address allowed in, one per entry. Select **Next**.
16. Under login methods, keep **One-time PIN** (Cloudflare emails a code; no other account is needed). Save the application.

**Check it**

17. Open the subdomain in a private browser window. Cloudflare asks for an email address: enter one from step 15, then the code it emails. The sandbox page opens and, after a few seconds, says **Ready**.
18. In the same window, open `<project name>.pages.dev`: it must also ask for the email first. Then try an address that is not on the list: it must not get in.
19. Open the browser's developer tools (F12), **Network** tab, and clear it after the page says Ready. Run the **Tamper demo**, then seal one log in the **Seal** panel. The Network list must stay empty except for downloads you click (`blob:` addresses).
20. Open the subdomain in **Safari** on a Mac (and, if you can, on an iPhone or iPad). Repeat step 17 and run the **Tamper demo**: it must end with **DEMO PASSED**. CI tests WebKit, Safari's engine, on Linux, not Safari itself, so this is the Safari check.

**Update it later**

21. Download the new **sfr-sandbox-site** artifact (steps 2 and 3). In the Pages project, open **Deployments**, select **Create deployment** (or **Upload**), drag in the zip, and deploy. The Access rules stay in place.
22. To add or remove a person, edit the policy from step 15.
