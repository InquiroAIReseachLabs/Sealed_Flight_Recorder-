#!/usr/bin/env python3
"""lint_baseline.py: the lint baseline of the chunked code review (docs/review/PLAN.txt, 0.2).

Runs clippy over the whole workspace with the review's warning set, without failing, and writes
docs/review/lint-baseline.txt: warning counts per file and per lint, with production code counted
apart from inline test modules and from separate test files. The production count of each chunk
goes into docs/review/ledger.json (metrics.lint).

Usage:
  scripts/review/lint_baseline.py [--tree DIR] [--raw FILE]
      --tree DIR   run clippy in this checkout (default: the repository); it must be the commit
                   the ledger was built from
      --raw FILE   read the saved `cargo clippy --message-format=json` output instead of running it
                   (the output of a run is saved next to the report when --save-raw FILE is given)
  scripts/review/lint_baseline.py --self-test
"""

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # noqa: E402

ROOT = ledger.ROOT
OUT = os.path.join(ROOT, "docs/review/lint-baseline.txt")

LINTS = [
    "clippy::indexing_slicing", "clippy::arithmetic_side_effects", "clippy::as_conversions",
    "clippy::cast_possible_truncation", "clippy::unwrap_used", "clippy::expect_used", "clippy::panic",
    "clippy::pedantic",
]
GENERATED = {p for p, _ in ledger.EXCLUDED}
CMD = ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--message-format=json", "--"]
for _l in LINTS:
    CMD += ["-W", _l]


def run_clippy(tree):
    p = subprocess.run(CMD, cwd=tree, capture_output=True, text=True)
    # clippy exits 0 with warnings; any other status means the build itself failed
    if p.returncode != 0:
        sys.stderr.write(p.stderr[-3000:])
        raise SystemExit(f"cargo clippy failed with status {p.returncode}")
    return p.stdout


def parse(raw, root):
    """Distinct warnings: (file, line, column, code, text) with the file relative to the checkout."""
    seen = {}
    for line in raw.splitlines():
        if not line.startswith("{"):
            continue
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("reason") != "compiler-message":
            continue
        msg = m["message"]
        if msg.get("level") not in ("warning", "error"):
            continue
        code = (msg.get("code") or {}).get("code")
        if not code:
            continue  # the "N warnings emitted" summary lines carry no code
        spans = [s for s in msg.get("spans", []) if s.get("is_primary")]
        if not spans:
            continue
        s = spans[0]
        # a span inside a macro expansion points at the use of the macro
        while s.get("expansion") and s["expansion"].get("span"):
            s = s["expansion"]["span"]
        f = s["file_name"]
        if os.path.isabs(f):
            if not f.startswith(root + os.sep):
                continue
            f = os.path.relpath(f, root)
        if not f.startswith(("crates/", "fuzz/", "tools/")):
            continue
        key = (f, s["line_start"], s["column_start"], code, msg["message"])
        seen[key] = True
    return sorted(seen)


def classify(path, line, test_ranges):
    if path in GENERATED:
        return "generated"
    if "/tests/" in path or path.startswith("fuzz/"):
        return "test_file"
    for a, b in test_ranges.get(path, ()):
        if a <= line <= b:
            return "inline_test"
    return "production"


def allow_attributes(files, test_ranges):
    """Allow and expect attributes in production code (not in test modules): each one hides warnings."""
    out = []
    pat = re.compile(r"#!?\[(allow|expect)\(([^\]]*)\)\]")
    for f in files:
        with open(os.path.join(ROOT, f)) as fh:
            lines = fh.read().split("\n")
        for i, text in enumerate(lines, 1):
            m = pat.search(text)
            if m and not any(a <= i <= b for a, b in test_ranges.get(f, ())):
                out.append((f, i, m.group(1), m.group(2), "reason" in m.group(2)))
    return out


def report(warnings, test_ranges, chunks_data, tool, commit, allows, prod_files):
    rows = [(f, ln, col, code, text, classify(f, ln, test_ranges)) for f, ln, col, code, text in warnings]
    by = {"production": [], "inline_test": [], "test_file": [], "generated": []}
    for r in rows:
        by[r[5]].append(r)
    out = []
    w = out.append
    w("Lint baseline (docs/review/PLAN.txt, 0.2)")
    w(f"Commit: {commit}")
    w(f"Tool:   {tool}")
    w("Command: cargo clippy --workspace --all-targets --locked -- " + " ".join(f"-W {x}" for x in LINTS))
    w("")
    w("A warning is counted once, after the allow attributes already in the source. Production code is")
    w("counted apart from inline test modules (#[cfg(test)]), separate test files (crates/*/tests/, fuzz/) and")
    w("generated code (px4_tables.rs). A warning in a chunk is fixed, or annotated with a one-line reason, when")
    w("the chunk is reviewed. Locations come from rerunning the command above.")
    w("")
    w("== Totals")
    for k, label in (("production", "production code"), ("inline_test", "inline test modules"),
                     ("test_file", "separate test files"), ("generated", "generated (not in ledger)")):
        w(f"{label:26s} {len(by[k]):6d}")
    w("")
    for k, title in (("production", "Production code, by file"), ("inline_test", "Inline test modules, by file"),
                     ("test_file", "Separate test files, by file"), ("generated", "Generated code, by file")):
        w(f"== {title}")
        files = {}
        for f, ln, col, code, text, _ in by[k]:
            files.setdefault(f, {}).setdefault(code, 0)
            files[f][code] += 1
        for f in sorted(files, key=lambda x: (-sum(files[x].values()), x)):
            lints = ", ".join(f"{c.replace('clippy::', '')}={n}" for c, n in sorted(files[f].items(), key=lambda x: (-x[1], x[0])))
            w(f"{f:50s} {sum(files[f].values()):5d}  {lints}")
        if not files:
            w("(none)")
        w("")
    w("== Production code, by lint")
    lints = {}
    for r in by["production"]:
        lints[r[3]] = lints.get(r[3], 0) + 1
    for c, n in sorted(lints.items(), key=lambda x: (-x[1], x[0])):
        w(f"{c:50s} {n:5d}")
    w("")
    w("== Production code, by chunk")
    for c in chunks_data["chunks"]:
        n = c.get("metrics", {}).get("lint")
        w(f"{c['id']:6s} {c['file']:46s} {c['start']:5d}-{c['end']:<5d} {n if n is not None else '-':>5}")
    w("")
    w("== Allow and expect attributes in production code (each hides warnings)")
    with_reason = sum(1 for a in allows if a[4])
    w(f"{len(allows)} attributes, {with_reason} with a reason = \"...\"")
    for f, ln, kind, what, has in sorted(allows):
        w(f"{f}:{ln}: #[{kind}({what})]{'' if has else '  (no reason attribute)'}")
    return "\n".join(out) + "\n"


def main(argv):
    if "--self-test" in argv:
        return self_test()
    tree = ROOT
    raw_file = None
    save_raw = None
    args = argv[1:]
    while args:
        a = args.pop(0)
        if a == "--tree":
            tree = os.path.abspath(args.pop(0))
        elif a == "--raw":
            raw_file = args.pop(0)
        elif a == "--save-raw":
            save_raw = args.pop(0)
        else:
            print(__doc__)
            return 2
    if raw_file:
        raw = open(raw_file).read()
    else:
        raw = run_clippy(tree)
        if save_raw:
            open(save_raw, "w").write(raw)
    warnings = parse(raw, tree)
    data = ledger.load()
    all_src = sh_lines("git", "ls-files", "crates/*/src/*.rs")
    m = ledger.metrics(all_src)
    test_ranges = {f: [(it["attr_start"], it["end"]) for it in m[f]["items"] if it["test"]] for f in all_src}
    prod_files = ledger.production_files()
    counts = {c["id"]: 0 for c in data["chunks"]}
    for f, ln, col, code, text in warnings:
        if classify(f, ln, test_ranges) == "production":
            c = ledger.chunk_for(data, f, ln)
            if c:
                counts[c["id"]] += 1
    for c in data["chunks"]:
        c.setdefault("metrics", {})["lint"] = counts[c["id"]]
    tool = subprocess.run(["cargo", "clippy", "--version"], cwd=tree, capture_output=True, text=True).stdout.strip()
    text = report(warnings, test_ranges, data, tool, data["commit"], allow_attributes(prod_files, test_ranges), prod_files)
    with open(OUT, "w") as f:
        f.write(text)
    ledger.save(data)
    ledger.render()
    print(f"{len(warnings)} warnings; wrote {os.path.relpath(OUT, ROOT)}")
    return 0


def sh_lines(*cmd):
    return subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True).stdout.split()


def self_test():
    raw = "\n".join([
        json.dumps({"reason": "compiler-message", "message": {
            "level": "warning", "code": {"code": "clippy::unwrap_used"}, "message": "used unwrap",
            "spans": [{"is_primary": True, "file_name": "crates/a/src/x.rs", "line_start": 5, "column_start": 3}]}}),
        json.dumps({"reason": "compiler-message", "message": {
            "level": "warning", "code": {"code": "clippy::unwrap_used"}, "message": "used unwrap",
            "spans": [{"is_primary": True, "file_name": "crates/a/src/x.rs", "line_start": 5, "column_start": 3}]}}),
        json.dumps({"reason": "compiler-message", "message": {
            "level": "warning", "code": None, "message": "1 warning emitted", "spans": []}}),
        json.dumps({"reason": "compiler-message", "message": {
            "level": "warning", "code": {"code": "dead_code"}, "message": "never used",
            "spans": [{"is_primary": True, "file_name": "/root/.cargo/registry/src/x/lib.rs", "line_start": 1,
                       "column_start": 1}]}}),
        "not json",
    ])
    got = parse(raw, "/repo")
    assert len(got) == 1 and got[0][:4] == ("crates/a/src/x.rs", 5, 3, "clippy::unwrap_used"), got
    assert classify("crates/a/src/x.rs", 5, {"crates/a/src/x.rs": [(4, 9)]}) == "inline_test"
    assert classify("crates/a/src/x.rs", 12, {"crates/a/src/x.rs": [(4, 9)]}) == "production"
    assert classify("crates/a/tests/t.rs", 1, {}) == "test_file"
    print("lint_baseline self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
