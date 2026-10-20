#!/usr/bin/env python3
"""coverage.py: line and branch coverage per chunk (docs/review/PLAN.txt, 0.3).

Runs the workspace tests under cargo-llvm-cov on the pinned nightly (branch coverage needs
nightly) and writes, for every chunk of docs/review/ledger.json, the production lines and branches
the test run reached (metrics.coverage). Inline test modules and separate test files are not
counted: a chunk's range holds production code only.

Usage:
  scripts/review/coverage.py [--tree DIR] [--lcov FILE] [--out-lcov FILE] [--lines FILE]
      --tree DIR       run in this checkout (default: the repository); it must be the commit the
                       ledger was built from
      --lcov FILE      read this lcov file instead of running the tests
      --out-lcov FILE  keep the lcov file of a run
      --lines FILE     write {file: {"covered": [...], "uncovered": [...]}} for the production
                       files, for scripts/review/mutants.py
  scripts/review/coverage.py --self-test

Needs cargo-llvm-cov and a nightly toolchain with llvm-tools-preview:
  rustup toolchain install nightly-2026-10-18 --profile minimal --component llvm-tools-preview
  cargo install cargo-llvm-cov --locked
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # noqa: E402

ROOT = ledger.ROOT
NIGHTLY = "nightly-2026-10-18"
IGNORE = r"(/tests/|/fuzz/|/tools/|px4_tables\.rs)"


def run(tree, out):
    cmd = ["cargo", f"+{NIGHTLY}", "llvm-cov", "--workspace", "--locked", "--branch", "--lcov",
           "--output-path", out, "--ignore-filename-regex", IGNORE]
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=tree, check=True)


def parse_lcov(text, tree):
    """{file: ({line: hits}, {(line, block, branch): taken})} for the files under crates/*/src/."""
    files = {}
    cur = None
    for raw in text.splitlines():
        if raw.startswith("SF:"):
            p = raw[3:]
            if os.path.isabs(p):
                p = os.path.relpath(p, tree)
            cur = files.setdefault(p, ({}, {})) if p.startswith("crates/") and "/src/" in p else None
        elif cur is None:
            continue
        elif raw.startswith("DA:"):
            ln, hits = raw[3:].split(",")[:2]
            cur[0][int(ln)] = max(cur[0].get(int(ln), 0), int(hits))
        elif raw.startswith("BRDA:"):
            ln, blk, br, taken = raw[5:].split(",")
            k = (int(ln), blk, br)
            t = 0 if taken == "-" else int(taken)
            cur[1][k] = max(cur[1].get(k, 0), t)
    return files


def chunk_numbers(c, lines, branches):
    a, b = c["start"], c["end"]
    lt = [h for ln, h in lines.items() if a <= ln <= b]
    bt = [t for (ln, _, _), t in branches.items() if a <= ln <= b]
    return {"lines_total": len(lt), "lines_hit": sum(1 for h in lt if h > 0),
            "branches_total": len(bt), "branches_hit": sum(1 for t in bt if t > 0)}


def main(argv):
    if "--self-test" in argv:
        return self_test()
    tree, lcov, out_lcov, lines_out = ROOT, None, None, None
    args = argv[1:]
    while args:
        a = args.pop(0)
        if a == "--tree":
            tree = os.path.abspath(args.pop(0))
        elif a == "--lcov":
            lcov = args.pop(0)
        elif a == "--out-lcov":
            out_lcov = os.path.abspath(args.pop(0))
        elif a == "--lines":
            lines_out = args.pop(0)
        else:
            print(__doc__)
            return 2
    if not lcov:
        lcov = out_lcov or os.path.join(tree, "target/review-lcov.info")
        run(tree, lcov)
    with open(lcov) as f:
        files = parse_lcov(f.read(), tree)
    data = ledger.load()
    tot = {"lines_total": 0, "lines_hit": 0, "branches_total": 0, "branches_hit": 0}
    for c in data["chunks"]:
        lines, branches = files.get(c["file"], ({}, {}))
        n = chunk_numbers(c, lines, branches)
        c.setdefault("metrics", {})["coverage"] = n
        for k in tot:
            tot[k] += n[k]
    ledger.save(data)
    ledger.render()
    if lines_out:
        prod = {c["file"] for c in data["chunks"]}
        dump = {}
        for f in sorted(prod):
            lines, _ = files.get(f, ({}, {}))
            dump[f] = {"covered": sorted(ln for ln, h in lines.items() if h > 0),
                       "uncovered": sorted(ln for ln, h in lines.items() if h == 0)}
        with open(lines_out, "w") as fh:
            json.dump(dump, fh)
    pc = lambda a, b: f"{100 * a / b:.1f}%" if b else "-"
    print(f"production lines {tot['lines_hit']}/{tot['lines_total']} ({pc(tot['lines_hit'], tot['lines_total'])}), "
          f"branches {tot['branches_hit']}/{tot['branches_total']} ({pc(tot['branches_hit'], tot['branches_total'])})")
    return 0


def self_test():
    text = "\n".join([
        "SF:/w/crates/a/src/x.rs", "DA:1,3", "DA:2,0", "DA:2,5", "DA:9,0",
        "BRDA:2,0,0,4", "BRDA:2,0,1,-", "BRDA:2,0,1,0", "end_of_record",
        "SF:/w/crates/a/tests/t.rs", "DA:1,1", "end_of_record",
    ])
    files = parse_lcov(text, "/w")
    assert list(files) == ["crates/a/src/x.rs"], files
    lines, branches = files["crates/a/src/x.rs"]
    assert lines == {1: 3, 2: 5, 9: 0}, lines  # one line seen twice keeps its larger count
    n = chunk_numbers({"start": 1, "end": 5}, lines, branches)
    assert n == {"lines_total": 2, "lines_hit": 2, "branches_total": 2, "branches_hit": 1}, n
    print("coverage self-test: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
