#!/usr/bin/env python3
"""ledger.py: the chunk ledger of the chunked code review (docs/review/PLAN.txt, Phase 0).

The ledger lists every production source file (the generated PX4 tables excepted) as chunks: line
ranges that start and end at function boundaries and hold at most 400 code lines (lines that are
neither blank nor comment), aiming at 200. A function over the limit is split at statement
boundaries and the split points are recorded. Inline test modules are not part of any chunk.

docs/review/ledger.json is the data; docs/review/LEDGER.md and docs/review/LONG_FUNCTIONS.md are
rendered from it. Status, passes and fix pull requests are edited with `set`; the measurements
(lint, coverage, mutants) are written by lint_baseline.py, coverage.py and mutants.py.

Usage:
  scripts/review/ledger.py build [--keep]    derive chunks from the work tree; --keep carries over
                                             status, passes and fix pull requests of chunks whose
                                             file and first and last item are unchanged
  scripts/review/ledger.py render            write LEDGER.md and LONG_FUNCTIONS.md from ledger.json
  scripts/review/ledger.py check             ledger.json agrees with the work tree and with the
                                             rendered files (exit 1 on any difference)
  scripts/review/ledger.py set ID key=value...   keys: status (todo, contract, review, fix, closed),
                                             passes (comma list), fix_prs (comma list)
  scripts/review/ledger.py --self-test

Needs tools/review_metrics (built on first use with `cargo build --release --locked`).
"""

import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LEDGER_JSON = os.path.join(ROOT, "docs/review/ledger.json")
LEDGER_MD = os.path.join(ROOT, "docs/review/LEDGER.md")
LONG_MD = os.path.join(ROOT, "docs/review/LONG_FUNCTIONS.md")
METRICS_DIR = os.path.join(ROOT, "tools/review_metrics")
METRICS_BIN = os.path.join(METRICS_DIR, "target/release/review-metrics")

TARGET = 200  # a chunk is closed at the next top-level boundary once it holds this many code lines
SOFT = 300  # ... and at the next boundary of any depth once it holds this many
MAX = 400  # no chunk holds more
SPLIT_TARGET = 300  # a function over MAX is cut into pieces of about this many code lines
LONG_FUNCTION = 100  # code lines
STATUSES = ("todo", "contract", "review", "fix", "closed")

EXCLUDED = [
    ("crates/sfr-core/src/px4_tables.rs",
     "generated data, checked against the PX4 sources by scripts/px4/px4_tables.py (docs/VALIDATION.md)"),
]

# Group, name, files in review order, contract sources (docs/review/PLAN.txt section 4).
GROUPS = [
    ("G1", "Log parser and ingest",
     ["crates/sfr-core/src/ulog.rs", "crates/sfr-core/src/ingest.rs", "crates/sfr-core/src/px4.rs"],
     "ULog file-format specification; PX4 message definitions at each supported tag; docs/SPEC.md ingest sections; docs/LIMITS.md"),
    ("G2", "Rule engine and events",
     ["crates/sfr-core/src/evaluate.rs", "crates/sfr-core/src/events.rs"],
     "docs/RULES.md; PX4 sources named in docs/VALIDATION.md"),
    ("G3", "Certificates and signatures",
     ["crates/sfr/src/certs.rs", "crates/sfr-core/src/crypto.rs"],
     "RFC 5280; docs/THREAT_MODEL.md; library documentation for the pinned versions"),
    ("G4", "Verification",
     ["crates/sfr-core/src/verify.rs", "crates/sfr/src/main.rs"],
     "docs/SPEC.md verify sections; docs/RECORD_FORMAT.md"),
    ("G5", "Sealed form",
     ["crates/sfr-core/src/json.rs", "crates/sfr-core/src/record.rs", "crates/sfr-core/src/merkle.rs",
      "crates/sfr-core/src/seal.rs"],
     "RFC 8785 subset as written in docs/SPEC.md; RFC 6962 and its replacement RFC 9162 for the tree"),
    ("G6", "Configuration",
     ["crates/sfr-core/src/rules.rs", "crates/sfr-core/src/params.rs", "crates/sfr-core/src/pkcs11_uri.rs"],
     "docs/RULES.md; RFC 7512 for PKCS#11 URIs"),
    ("G7", "Output",
     ["crates/sfr-core/src/report.rs", "crates/sfr-core/src/display.rs"],
     "docs/SPEC.md report sections"),
    ("G8", "Keys, hardware, CLI",
     ["crates/sfr-core/src/keys.rs", "crates/sfr/src/hardware.rs", "crates/sfr-pkcs11-helper/src/main.rs",
      "crates/sfr/src/main.rs"],
     "docs/INTEGRATION_NOTES.md; docs/THREAT_MODEL.md"),
    ("GX", "Cross-cutting",
     ["crates/sfr-core/src/lib.rs"],
     "docs/"),
]

# crates/sfr/src/main.rs is split by item: the verify command and what only it uses are G4, the
# rest (argument parsing, keygen, pubkey, seal, output paths, version, main) is G8.
MAIN_RS = "crates/sfr/src/main.rs"
MAIN_G4_ITEMS = {
    "parse_duration_seconds", "Trust", "PAST_AT_SKEW_SECONDS", "PARTIAL_CHAIN_NOTE", "chain_trust_line",
    "attestation_of", "verify_cmd", "not_checked",
}


def sh(*cmd, cwd=ROOT):
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout


def production_files():
    out = sh("git", "ls-files", "crates/*/src/*.rs").split()
    skip = {p for p, _ in EXCLUDED}
    return sorted(f for f in out if f not in skip)


def metrics(files):
    if not os.path.exists(METRICS_BIN):
        sh("cargo", "build", "--release", "--locked", "--manifest-path", os.path.join(METRICS_DIR, "Cargo.toml"))
    return {m["file"]: m for m in json.loads(sh(METRICS_BIN, ROOT, *files))}


def sha256(path, upto=None):
    """Digest of a file, or of its first `upto` lines: the production part, since tests are written
    after the last chunk and a new test must not make the ranges look stale."""
    with open(os.path.join(ROOT, path), "rb") as f:
        data = f.read()
    if upto is not None:
        data = b"".join(data.splitlines(keepends=True)[:upto])
    return hashlib.sha256(data).hexdigest()


class Code:
    """Counts code lines and tells comment lines from blank ones, for one file."""

    def __init__(self, runs, lines):
        self.runs = runs
        self.lines = lines
        self.is_code = set()
        for a, b in runs:
            self.is_code.update(range(a, b + 1))

    def count(self, a, b):
        return sum(1 for ln in range(a, b + 1) if ln in self.is_code)

    def is_comment(self, ln):
        return 1 <= ln <= len(self.lines) and ln not in self.is_code and self.lines[ln - 1].strip() != ""


def fn_label(it, parent):
    return f"{parent}::{it['name']}" if parent else it["name"]


def walk_fns(items, parent=None):
    for it in items:
        if it["kind"] == "fn":
            yield it, parent
        elif it["kind"] in ("impl", "trait", "mod"):
            yield from walk_fns(it["children"], it["name"])


def group_of_top_item(path, it):
    if path != MAIN_RS:
        return None
    return "G4" if it["name"] in MAIN_G4_ITEMS else "G8"


def atoms_of(path, fm, code):
    """Production atoms of one file, in order: dicts with start, end, label, depth, container, fn,
    top (index of the top-level item), brk (a test item sits between this atom and the one before)."""
    atoms = []
    prev_test_end = 0

    def add(it, depth, container, top, last_in_container_end=None, brk=False, cstart=None):
        a = {
            "start": it["attr_start"], "end": last_in_container_end or it["end"], "depth": depth,
            "container": container, "cstart": cstart, "kind": it["kind"], "top": top, "brk": brk,
            "label": fn_label(it, container) if it["kind"] == "fn" else f"{it['kind']} {it['name']}".strip(),
            "fn": None,
        }
        if it["kind"] == "fn":
            a["fn"] = {"name": fn_label(it, container), "start": it["start"], "end": it["end"],
                       "branches": it.get("branches", 0), "stmts": it.get("stmts", [])}
        atoms.append(a)

    for ti, it in enumerate(fm["items"]):
        if it["test"]:
            prev_test_end = it["end"]
            continue
        brk = prev_test_end and (not atoms or atoms[-1]["end"] < prev_test_end)
        if it["kind"] in ("impl", "trait", "mod"):
            kids = [c for c in it["children"] if not c["test"]]
            if kids:
                for ki, c in enumerate(kids):
                    last = ki == len(kids) - 1
                    add(c, 1, it["name"], ti, it["end"] if last else None, brk and ki == 0, it["attr_start"])
                continue
        add(it, 0, None, ti, None, brk)
    return atoms


def split_function(a, code):
    """Pieces of an oversize function atom: a list of (start, end, cut_line_text or None)."""
    fn = a["fn"]
    stmts = fn["stmts"] if fn else []
    total = code.count(a["start"], a["end"])
    k = -(-total // SPLIT_TARGET)
    if not stmts or k < 2:
        return [(a["start"], a["end"], None)]
    # A cut goes before a top-level statement, and before the comment lines just above it.
    cands = []
    for s, _ in stmts:
        ln = s
        while code.is_comment(ln - 1):
            ln -= 1
        if ln > a["start"]:
            cands.append((ln, s != ln))
    cuts = []
    for j in range(1, k):
        want = j * total / k
        best = None
        for ln, has_comment in cands:
            if cuts and ln <= cuts[-1]:
                continue
            dist = abs(code.count(a["start"], ln - 1) - want) - (25 if has_comment else 0)
            if best is None or dist < best[0]:
                best = (dist, ln)
        if best:
            cuts.append(best[1])
    bounds = [a["start"]] + cuts + [a["end"] + 1]
    out = []
    for i in range(len(bounds) - 1):
        text = None
        if i > 0:
            text = first_code_text(code, bounds[i], bounds[i + 1] - 1)
        out.append((bounds[i], bounds[i + 1] - 1, text))
    return out


def first_code_text(code, a, b):
    for ln in range(a, b + 1):
        if ln in code.is_code:
            return code.lines[ln - 1].strip()[:70]
    return None


def chunk_file(path, fm, src_lines, groups_for_item):
    """Chunks of one file. groups_for_item maps a top-level item index to its group id."""
    code = Code([tuple(r) for r in fm["code_lines"]], src_lines)
    atoms = atoms_of(path, fm, code)
    # segments: runs of atoms whose group is the same
    segments = []
    for a in atoms:
        g = groups_for_item(a["top"])
        if segments and segments[-1][0] == g and not a["brk"]:
            segments[-1][1].append(a)
        else:
            segments.append((g, [a]))
    chunks = []
    prev_end = 0
    for g, seg in segments:
        # contiguous ranges: each atom starts after the previous atom of the file ends
        cur, cur_loc = [], 0
        def flush():
            nonlocal cur, cur_loc
            if cur:
                chunks.append((g, cur))
            cur, cur_loc = [], 0
        units = []
        for a in seg:
            start = prev_end + 1 if not a["brk"] else a["start"]
            loc = code.count(start, a["end"])
            if loc > MAX and a["fn"]:
                pieces = split_function(a, code)
                if len(pieces) > 1:
                    for i, (s, e, text) in enumerate(pieces):
                        s0 = start if i == 0 else s
                        units.append({"atom": a, "start": s0, "end": e, "loc": code.count(s0, e), "alone": True,
                                      "piece": (i + 1, len(pieces), s, text)})
                    prev_end = a["end"]
                    continue
            units.append({"atom": a, "start": start, "end": a["end"], "loc": loc, "alone": loc > MAX,
                          "piece": None})
            prev_end = a["end"]
        for idx, u in enumerate(units):
            if u["alone"]:
                flush()
                chunks.append((g, [u]))
                continue
            if cur and cur_loc + u["loc"] > MAX:
                flush()
            elif cur and cur_loc >= TARGET and (u["atom"]["depth"] == 0 or cur_loc >= SOFT):
                flush()
            cur.append(u)
            cur_loc += u["loc"]
        flush()
    # a small tail chunk is joined to the one before it when the two fit
    merged = []
    for g, us in chunks:
        if merged and merged[-1][0] == g and not us[0]["piece"] and not merged[-1][1][-1]["piece"] \
                and sum(u["loc"] for u in us) < 60 \
                and sum(u["loc"] for u in merged[-1][1]) + sum(u["loc"] for u in us) <= MAX \
                and us[0]["start"] == merged[-1][1][-1]["end"] + 1:
            merged[-1][1].extend(us)
        else:
            merged.append((g, list(us)))
    out = []
    for g, us in merged:
        start, end = us[0]["start"], us[-1]["end"]
        fns = []
        for u in us:
            f = u["atom"]["fn"]
            if f and (u["piece"] is None or u["piece"][0] == 1):
                fns.append({"name": f["name"], "start": f["start"], "end": f["end"],
                            "code_lines": code.count(f["start"], f["end"]), "branches": f["branches"]})
        # containers (impl, trait, mod) the chunk is inside of without holding their header line
        opens = []
        for u in us:
            a = u["atom"]
            if a["container"] and a["cstart"] < start and a["container"] not in opens:
                opens.append(a["container"])
        split = None
        if us[0]["piece"]:
            i, n, s, text = us[0]["piece"]
            f = us[0]["atom"]["fn"]
            split = {"function": f["name"], "part": i, "of": n,
                     "cut_line": s if i > 1 else None, "cut_text": text}
        out.append({
            "group": g, "file": path, "start": start, "end": end,
            "code_lines": sum(u["loc"] for u in us),
            "first": us[0]["atom"]["label"] if not us[0]["piece"] else f"{us[0]['atom']['label']} (part {us[0]['piece'][0]})",
            "last": us[-1]["atom"]["label"] if not us[-1]["piece"] else f"{us[-1]['atom']['label']} (part {us[-1]['piece'][0]})",
            "inside": opens, "fns": fns, "split": split,
            "fns_over_100": sum(1 for f in fns if f["code_lines"] > LONG_FUNCTION),
            "branches": sum(f["branches"] for f in fns),
        })
    return out


def build(keep):
    files = production_files()
    m = metrics(files)
    chunks = []
    shas = {}
    by_file = {}
    for path in files:
        with open(os.path.join(ROOT, path)) as f:
            src_lines = f.read().split("\n")
        fm = m[path]
        if path == MAIN_RS:
            gf = lambda ti, fm=fm: group_of_top_item(MAIN_RS, fm["items"][ti])
        else:
            g = next(g for g, _, fs, _ in GROUPS if path in fs)
            gf = lambda ti, g=g: g
        by_file[path] = chunk_file(path, fm, src_lines, gf)
    for path, cs in by_file.items():
        shas[path] = sha256(path, max(c["end"] for c in cs))
    for g, _, fs, _ in GROUPS:
        n = 0
        for path in fs:
            for c in by_file[path]:
                if c["group"] != g:
                    continue
                n += 1
                c["id"] = f"C{g[1:]}.{n}"
                chunks.append(c)
    old = {}
    if keep and os.path.exists(LEDGER_JSON):
        with open(LEDGER_JSON) as f:
            for c in json.load(f)["chunks"]:
                old[(c["file"], c["first"], c["last"])] = c
    kept, orphan = 0, 0
    for c in chunks:
        o = old.pop((c["file"], c["first"], c["last"]), None)
        c["status"], c["passes"], c["fix_prs"] = "todo", [], []
        if o:
            c["status"], c["passes"], c["fix_prs"] = o["status"], o["passes"], o["fix_prs"]
            if "metrics" in o:
                c["metrics"] = o["metrics"]
            kept += 1
    if keep:
        for o in old.values():
            if o["status"] != "todo" or o["passes"] or o["fix_prs"]:
                orphan += 1
                print(f"warning: {o['id']} ({o['file']} {o['first']} .. {o['last']}) has status or pull requests "
                      "and matches no new chunk; re-enter them by hand", file=sys.stderr)
    data = {
        "commit": sh("git", "rev-parse", "HEAD").strip(),
        "limits": {"target": TARGET, "soft": SOFT, "max": MAX, "long_function": LONG_FUNCTION},
        "excluded": [{"file": p, "reason": r} for p, r in EXCLUDED],
        "groups": [{"id": g, "name": n, "files": fs, "contract_sources": cs} for g, n, fs, cs in GROUPS],
        "production_sha256": shas,
        "chunks": chunks,
    }
    write_json(data)
    print(f"{len(chunks)} chunks, {sum(c['code_lines'] for c in chunks)} code lines; kept {kept}, orphaned {orphan}")


def write_json(data):
    os.makedirs(os.path.dirname(LEDGER_JSON), exist_ok=True)
    with open(LEDGER_JSON, "w") as f:
        json.dump(data, f, indent=1, sort_keys=False)
        f.write("\n")


def load():
    with open(LEDGER_JSON) as f:
        return json.load(f)


def save(data):
    write_json(data)


def chunk_for(data, path, line):
    for c in data["chunks"]:
        if c["file"] == path and c["start"] <= line <= c["end"]:
            return c
    return None


# ---------------------------------------------------------------------------------------------
# Rendering

def md_cell(s):
    return str(s).replace("|", "\\|")


def render_ledger(data):
    chunks = data["chunks"]
    lim = data["limits"]
    out = []
    w = out.append
    w("# Chunk ledger\n")
    w("Every shipped source file is listed here as chunks: ranges of whole functions that hold few enough code "
      "lines to read in one sitting. `docs/review/PLAN.txt` says how a chunk is reviewed and closed. A code line is a "
      "line that is neither blank nor a comment; inline test modules belong to no chunk.\n")
    w("`docs/review/ledger.json` is the data and this page is rendered from it: do not edit the tables here. "
      "`scripts/review/ledger.py set` records a status, the passes done and the fix pull requests; "
      "`scripts/review/ledger.py check` fails when the ranges no longer match the source files or this page "
      "no longer matches the data. The measurements come from `scripts/review/lint_baseline.py`, "
      "`scripts/review/coverage.py` and `scripts/review/mutants.py`; their commands are in "
      "`docs/review/PHASE0.md`.\n")
    w("Status is one of `todo`, `contract`, `review`, `fix`, `closed`. A function over the chunk limit is cut at "
      "statement boundaries into parts, each its own chunk, and the cut is named in the notes column. "
      "`crates/sfr/src/main.rs` is split by function between G4 (the `verify` command) and G8 (everything else).\n")
    w(f"<!-- BEGIN ledger-summary: scripts/review/ledger.py render -->")
    w(f"Ledger of commit `{data['commit'][:7]}`: chunks of at most {lim['max']} code lines, closed at about "
      f"{lim['target']}; a long function has more than {lim['long_function']}.\n")
    w("| Group | Name | Files | Chunks | Code lines | Functions over the long-function limit |")
    w("|---|---|---|---|---|---|")
    tot = [0, 0, 0]
    for g in data["groups"]:
        cs = [c for c in chunks if c["group"] == g["id"]]
        if not cs:
            continue
        files = sorted({c["file"] for c in cs})
        n, loc, lf = len(cs), sum(c["code_lines"] for c in cs), sum(c["fns_over_100"] for c in cs)
        tot = [tot[0] + n, tot[1] + loc, tot[2] + lf]
        w(f"| {g['id']} | {g['name']} | {', '.join('`' + f.split('/', 1)[1] + '`' for f in files)} | {n} | {loc} | {lf} |")
    w(f"| | Total | | {tot[0]} | {tot[1]} | {tot[2]} |")
    w("")
    w("Not in the ledger:")
    for e in data["excluded"]:
        w(f"- `{e['file']}`: {e['reason']}.")
    w("- Test code (`crates/*/tests/`, inline test modules), `fuzz/`, `scripts/`, `tools/`: not production source.")
    w("- `sfr-wasm`: named in the plan, but not a crate of this workspace at this commit.")
    w("<!-- END ledger-summary -->\n")
    w("## Contract sources by group\n")
    w("<!-- BEGIN ledger-groups: scripts/review/ledger.py render -->")
    w("| Group | Contract sources |")
    w("|---|---|")
    for g in data["groups"]:
        w(f"| {g['id']} {g['name']} | {md_cell(g['contract_sources'])} |")
    w("<!-- END ledger-groups -->\n")
    w("## Chunks\n")
    w("<!-- BEGIN ledger-chunks: scripts/review/ledger.py render -->")
    w("| ID | File | Lines | Code | Long fns | Status | Passes | Fix PRs | Notes |")
    w("|---|---|---|---|---|---|---|---|---|")
    for c in chunks:
        notes = []
        if c["inside"]:
            notes.append("inside " + ", ".join(f"`{x}`" for x in c["inside"]))
        if c["split"]:
            s = c["split"]
            n = f"`{s['function']}` part {s['part']} of {s['of']}"
            if s["cut_line"]:
                n += f"; starts at line {s['cut_line']}: `{md_cell(s['cut_text'] or '')}`"
            notes.append(n)
        notes.append(f"{c['first']} .. {c['last']}".replace("`", ""))
        w(f"| {c['id']} | `{c['file'].split('/', 1)[1]}` | {c['start']}-{c['end']} | {c['code_lines']} | "
          f"{c['fns_over_100']} | {c['status']} | {', '.join(c['passes']) or '-'} | "
          f"{', '.join(c['fix_prs']) or '-'} | {md_cell('; '.join(notes))} |")
    w("<!-- END ledger-chunks -->\n")
    out_metrics = render_metrics(data)
    if out_metrics:
        w("## Measurements before any review\n")
        w(out_metrics)
    return "\n".join(out) + "\n"


def pct(a, b):
    return "-" if not b else f"{100 * a / b:.0f}%"


def render_metrics(data):
    chunks = data["chunks"]
    if not any("metrics" in c for c in chunks):
        return ""
    lines = []
    lines.append("Lint warnings are those of the set in `docs/review/lint-baseline.txt` that fall on shipped "
                 "lines of the chunk. Coverage is line and branch coverage of the whole workspace test run "
                 "(`scripts/review/coverage.py`). Mutants are those of `cargo mutants` on the chunk's lines "
                 "(`scripts/review/mutants.py`): caught, missed, unviable, timed out; the score is "
                 "caught / (caught + missed + timed out).\n")
    lines.append("<!-- BEGIN ledger-metrics: scripts/review/ledger.py render -->")
    lines.append("| ID | Lint | Line cov | Branch cov | Caught | Missed | Unviable | Timeout | Mutation score |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for c in chunks:
        m = c.get("metrics", {})
        lint = m.get("lint")
        cov = m.get("coverage")
        mu = m.get("mutants")
        lc = pct(cov["lines_hit"], cov["lines_total"]) if cov else "-"
        bc = pct(cov["branches_hit"], cov["branches_total"]) if cov else "-"
        if mu:
            denom = mu["caught"] + mu["missed"] + mu["timeout"]
            score = pct(mu["caught"], denom)
            cells = f"{mu['caught']} | {mu['missed']} | {mu['unviable']} | {mu['timeout']} | {score}"
        else:
            cells = "- | - | - | - | -"
        lines.append(f"| {c['id']} | {lint if lint is not None else '-'} | {lc} | {bc} | {cells} |")
    lines.append("<!-- END ledger-metrics -->\n")
    return "\n".join(lines)


def render_long(data):
    out = []
    w = out.append
    w("# Long functions\n")
    w("Functions of shipped code over the long-function limit, and the functions with the most branches. "
      "They are candidates for simplification, which the plan allows only after the chunk that holds them is "
      "pinned by tests (`docs/review/PLAN.txt`, refactoring rule). Rendered by `scripts/review/ledger.py render` "
      "from `docs/review/ledger.json`; the branch count is the one `tools/review_metrics` defines (each `if`, "
      "match arm, match guard, `while`, `for`, `&&`, `||`, `?` and `let ... else`).\n")
    fns = []
    for c in data["chunks"]:
        for f in c["fns"]:
            fns.append((f, c))
    long = sorted((x for x in fns if x[0]["code_lines"] > data["limits"]["long_function"]),
                  key=lambda x: -x[0]["code_lines"])
    w("<!-- BEGIN long-functions: scripts/review/ledger.py render -->")
    w(f"Functions over {data['limits']['long_function']} code lines: {len(long)}.\n")
    w("| Function | File | Lines | Code lines | Branches | Chunk |")
    w("|---|---|---|---|---|---|")
    for f, c in long:
        w(f"| `{f['name']}` | `{c['file'].split('/', 1)[1]}` | {f['start']}-{f['end']} | {f['code_lines']} | "
          f"{f['branches']} | {c['id']} |")
    w("<!-- END long-functions -->\n")
    w("## Most branches\n")
    w("<!-- BEGIN most-branches: scripts/review/ledger.py render -->")
    w("| Function | File | Lines | Code lines | Branches | Chunk |")
    w("|---|---|---|---|---|---|")
    for f, c in sorted(fns, key=lambda x: (-x[0]["branches"], x[0]["name"]))[:20]:
        w(f"| `{f['name']}` | `{c['file'].split('/', 1)[1]}` | {f['start']}-{f['end']} | {f['code_lines']} | "
          f"{f['branches']} | {c['id']} |")
    w("<!-- END most-branches -->\n")
    return "\n".join(out) + "\n"


PHASE0_MD = os.path.join(ROOT, "docs/review/PHASE0.md")


def score(m):
    """Mutation score of one chunk's counts: caught / (caught + missed + timed out), or None."""
    n = m["caught"] + m["missed"] + m["timeout"]
    return None if n == 0 else m["caught"] / n


def phase0_blocks(data):
    """Generated blocks of docs/review/PHASE0.md, by name."""
    chunks = data["chunks"]
    rated = [(score(c["metrics"]["mutants"]), c) for c in chunks
             if "mutants" in c.get("metrics", {}) and score(c["metrics"]["mutants"]) is not None
             and c["metrics"]["mutants"]["caught"] + c["metrics"]["mutants"]["missed"]
             + c["metrics"]["mutants"]["timeout"] >= 5]
    rated.sort(key=lambda x: (x[0], -x[1]["metrics"]["mutants"]["missed"], x[1]["id"]))
    low = ["| Rank | Chunk | File | Lines | Caught | Missed | Timeout | Score | Line coverage |",
           "|---|---|---|---|---|---|---|---|---|"]
    for i, (sc, c) in enumerate(rated[:10], 1):
        m = c["metrics"]["mutants"]
        cov = c["metrics"].get("coverage")
        lc = pct(cov["lines_hit"], cov["lines_total"]) if cov else "-"
        low.append(f"| {i} | {c['id']} | `{c['file'].split('/', 1)[1]}` | {c['start']}-{c['end']} | {m['caught']} | "
                   f"{m['missed']} | {m['timeout']} | {100 * sc:.0f}% | {lc} |")
    if not rated:
        low = ["No chunk has five or more rated mutants yet."]
    groups = ["| Group | Chunks | Code lines | Caught | Missed | Timeout | Unviable | Score | Line coverage | Branch coverage | Lint |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
    tot = {"c": 0, "m": 0, "t": 0, "u": 0, "n": 0, "loc": 0, "lh": 0, "lt": 0, "bh": 0, "bt": 0, "lint": 0}
    for g in data["groups"]:
        cs = [c for c in chunks if c["group"] == g["id"]]
        if not cs:
            continue
        a = {"c": 0, "m": 0, "t": 0, "u": 0, "loc": 0, "lh": 0, "lt": 0, "bh": 0, "bt": 0, "lint": 0}
        for c in cs:
            mt = c.get("metrics", {})
            mu, cv = mt.get("mutants"), mt.get("coverage")
            a["loc"] += c["code_lines"]
            a["lint"] += mt.get("lint") or 0
            if mu:
                a["c"] += mu["caught"]; a["m"] += mu["missed"]; a["t"] += mu["timeout"]; a["u"] += mu["unviable"]
            if cv:
                a["lh"] += cv["lines_hit"]; a["lt"] += cv["lines_total"]; a["bh"] += cv["branches_hit"]; a["bt"] += cv["branches_total"]
        for k in a:
            tot[k] += a[k]
        tot["n"] += len(cs)
        den = a["c"] + a["m"] + a["t"]
        groups.append(f"| {g['id']} {g['name']} | {len(cs)} | {a['loc']} | {a['c']} | {a['m']} | {a['t']} | {a['u']} | "
                      f"{pct(a['c'], den)} | {pct(a['lh'], a['lt'])} | {pct(a['bh'], a['bt'])} | {a['lint']} |")
    den = tot["c"] + tot["m"] + tot["t"]
    groups.append(f"| Total | {tot['n']} | {tot['loc']} | {tot['c']} | {tot['m']} | {tot['t']} | {tot['u']} | "
                  f"{pct(tot['c'], den)} | {pct(tot['lh'], tot['lt'])} | {pct(tot['bh'], tot['bt'])} | {tot['lint']} |")
    return {"phase0-lowest": "\n".join(low), "phase0-groups": "\n".join(groups)}


def replace_blocks(text, blocks):
    """Replaces the content between `<!-- BEGIN name: ... -->` and `<!-- END name -->` for each block."""
    for name, body in blocks.items():
        pat = re.compile(rf"(<!-- BEGIN {re.escape(name)}:[^\n]*-->\n)(.*?)(\n<!-- END {re.escape(name)} -->)", re.S)
        if not pat.search(text):
            continue
        text = pat.sub(lambda m: m.group(1) + body + m.group(3), text, count=1)
    return text


def render():
    data = load()
    with open(LEDGER_MD, "w") as f:
        f.write(render_ledger(data))
    with open(LONG_MD, "w") as f:
        f.write(render_long(data))
    if os.path.exists(PHASE0_MD):
        with open(PHASE0_MD) as f:
            text = f.read()
        with open(PHASE0_MD, "w") as f:
            f.write(replace_blocks(text, phase0_blocks(data)))


# ---------------------------------------------------------------------------------------------
# Check

def check():
    data = load()
    bad = []
    files = production_files()
    listed = {c["file"] for c in data["chunks"]}
    for p in files:
        if p not in listed:
            bad.append(f"{p}: not in the ledger")
        elif sha256(p, max(c["end"] for c in data["chunks"] if c["file"] == p)) != data["production_sha256"].get(p):
            bad.append(f"{p}: production code changed since the ledger was built (run build --keep)")
    for p in listed - set(files):
        bad.append(f"{p}: in the ledger but not a production source file")
    # ranges: ordered, disjoint, within the limit
    by_file = {}
    for c in data["chunks"]:
        by_file.setdefault(c["file"], []).append(c)
        if c["code_lines"] > data["limits"]["max"]:
            bad.append(f"{c['id']}: {c['code_lines']} code lines, over the limit")
        if c["status"] not in STATUSES:
            bad.append(f"{c['id']}: status {c['status']!r} is not one of {STATUSES}")
    for p, cs in by_file.items():
        cs.sort(key=lambda c: c["start"])
        for a, b in zip(cs, cs[1:]):
            if a["end"] >= b["start"]:
                bad.append(f"{a['id']} and {b['id']}: ranges overlap")
    ids = [c["id"] for c in data["chunks"]]
    if len(ids) != len(set(ids)):
        bad.append("chunk ids are not unique")
    # every production code line is in exactly one chunk
    if not bad:
        m = metrics(files)
        for p in files:
            fm = m[p]
            test_lines = set()
            for it in fm["items"]:
                if it["test"]:
                    test_lines.update(range(it["attr_start"], it["end"] + 1))
            code = set()
            for a, b in fm["code_lines"]:
                code.update(range(a, b + 1))
            code -= test_lines
            covered = set()
            for c in by_file[p]:
                covered.update(range(c["start"], c["end"] + 1))
            missing = sorted(code - covered)
            if missing:
                bad.append(f"{p}: code lines outside every chunk, first at line {missing[0]}")
            inside_tests = sorted(covered & test_lines)
            if inside_tests:
                bad.append(f"{p}: a chunk holds test code, first at line {inside_tests[0]}")
    if os.path.exists(PHASE0_MD):
        with open(PHASE0_MD) as f:
            cur = f.read()
        if replace_blocks(cur, phase0_blocks(data)) != cur:
            bad.append("docs/review/PHASE0.md: a generated block differs from ledger.json (run render)")
    for path, text in ((LEDGER_MD, render_ledger(data)), (LONG_MD, render_long(data))):
        try:
            with open(path) as f:
                if f.read() != text:
                    bad.append(f"{os.path.relpath(path, ROOT)}: differs from the rendering of ledger.json (run render)")
        except FileNotFoundError:
            bad.append(f"{os.path.relpath(path, ROOT)}: missing (run render)")
    for line in bad:
        print("FAIL:", line)
    print(f"ledger check: {len(bad)} problem(s), {len(data['chunks'])} chunks")
    return 1 if bad else 0


def set_fields(cid, pairs):
    data = load()
    for c in data["chunks"]:
        if c["id"] == cid:
            break
    else:
        print(f"no chunk {cid}", file=sys.stderr)
        return 2
    for p in pairs:
        k, _, v = p.partition("=")
        if k == "status":
            if v not in STATUSES:
                print(f"status must be one of {STATUSES}", file=sys.stderr)
                return 2
            c["status"] = v
        elif k in ("passes", "fix_prs"):
            c[k] = [x.strip() for x in v.split(",") if x.strip()]
        else:
            print(f"unknown key {k}", file=sys.stderr)
            return 2
    save(data)
    render()
    return 0


def self_test():
    # code lines, comments and splitting on a small synthetic file
    src = ["//! doc", "", "use a;", "", "// section", "fn big() {"]
    body = [f"    let x{i} = {i};" for i in range(40)]
    src += body + ["}", "", "fn small() {}", ""]
    runs = [(3, 3), (6, 6 + 40 + 1), (9 + 40, 9 + 40)]
    code = Code(runs, src)
    assert code.count(1, len(src)) == 1 + 1 + 40 + 1 + 1
    assert code.is_comment(5) and not code.is_comment(2) and not code.is_comment(3)
    a = {"start": 5, "end": 47, "fn": {"name": "big", "stmts": [(7 + i, 7 + i) for i in range(40)]}}
    pieces = split_function(a, code)
    assert pieces == [(5, 47, None)], pieces  # 41 code lines: below the split target, never cut
    global SPLIT_TARGET
    old, SPLIT_TARGET = SPLIT_TARGET, 15
    try:
        pieces = split_function(a, code)
        assert len(pieces) == 3 and pieces[0][0] == 5 and pieces[-1][1] == 47, pieces
        assert all(p[1] + 1 == q[0] for p, q in zip(pieces, pieces[1:]))
    finally:
        SPLIT_TARGET = old
    print("ledger self-test: ok")
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) >= 2 and argv[1] == "build":
        build("--keep" in argv[2:])
        render()
        return 0
    if len(argv) >= 2 and argv[1] == "render":
        render()
        return 0
    if len(argv) >= 2 and argv[1] == "check":
        return check()
    if len(argv) >= 4 and argv[1] == "set":
        return set_fields(argv[2], argv[3:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
