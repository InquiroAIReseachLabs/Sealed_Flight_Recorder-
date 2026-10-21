#!/usr/bin/env python3
"""mutants.py: mutation testing per file, attributed to chunks (docs/review/PLAN.txt, 0.4).

The test suite is too slow to run in full for every mutant (the whole workspace suite takes minutes
in a debug build, and there are thousands of mutants), so a mutant is tried against a cheap test
set first and only the survivors go on to the dearer ones. A mutant counts as caught when any tier
caught it. A survivor on a line that no test of the whole suite executes (coverage.py --lines) cannot
be caught by a later tier and is recorded as missed without being run again.

  tier 1  the unit tests of the crate that holds the file (sfr-core: --lib; sfr: --bins)
  tier 2  the end-to-end tests of the sfr command line on the golden logs (dev profile)
  tier 3  the record-forging and reference-verifier tests (optimized profile, they are slow)

Usage:
  scripts/review/mutants.py run --tier N|all --out DIR [--tree DIR] [--jobs 3] [--lines FILE]
                                [--shard K/M] [--quiet] [FILE...]
      Runs cargo-mutants for each file (default: every production source file, in review order)
      into DIR/tier<N>/<file>. Tiers 2 and 3 take only the survivors of the tiers before
      (found in DIR), on lines that tests reach (--lines). With `--tier all` each file goes
      through tiers 1, 2 and 3 in turn. With `--shard K/M` only every Mth file, from the Kth
      (counting from 0), is run, so M jobs together cover the list exactly once. With `--quiet` the
      output of cargo-mutants goes to DIR/log/ instead of the terminal, and only the counts of
      each run are printed: the names of missed mutants are findings, and the log of a CI run on a
      public repository is public.
  scripts/review/mutants.py merge-metrics LEDGER.json...
      Copies the mutation metrics of the chunks that each given ledger holds into docs/review/
      ledger.json (the ledgers of the shards of one run: no two hold the same chunk).
  scripts/review/mutants.py collect --out DIR [--lines FILE] [--missed-dir DIR]
      Merges the tiers, writes metrics.mutants of every chunk into docs/review/ledger.json and, with
      --missed-dir, one file per chunk listing its missed mutants.
  scripts/review/mutants.py --self-test

Needs cargo-mutants (cargo install cargo-mutants --locked).
"""

import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # noqa: E402

ROOT = ledger.ROOT

SFR_E2E = ["--test", "seal_dry_run", "--test", "falsepass", "--test", "report_required",
           "--test", "verify_results", "--test", "certificates", "--test", "trust_inputs",
           "--test", "signed_structure", "--test", "exit_codes", "--test", "custody",
           "--test", "key_file_and_index"]
FORGING = ["--test", "seal_verify", "--test", "reference_verifier"]
# Files whose behavior the forging tests hold (tier 3 runs for these only).
TIER3_FILES = {
    "crates/sfr-core/src/verify.rs", "crates/sfr-core/src/seal.rs", "crates/sfr-core/src/json.rs",
    "crates/sfr-core/src/merkle.rs", "crates/sfr-core/src/record.rs", "crates/sfr-core/src/keys.rs",
    "crates/sfr-core/src/crypto.rs", "crates/sfr/src/certs.rs", "crates/sfr/src/main.rs",
}


def review_order():
    """Production files, group by group (ledger order), without repeats."""
    seen, out = [], []
    for g in ledger.GROUPS:
        for f in g[2]:
            if f not in seen:
                seen.append(f)
                out.append(f)
    return out


def tier1_args(path):
    return ["--", "--lib"] if path.startswith("crates/sfr-core/") else ["--", "--bins"]


def slug(path):
    return path.replace("/", "__")


def mutant_id(m):
    s = m["span"]["start"]
    return f"{m['file']}:{s['line']}:{s['column']}: {m['name']}"


def outcomes_of(out_dir):
    """[(id, summary, mutant dict)] of the run in out_dir (mutants.out/outcomes.json), or []."""
    p = os.path.join(out_dir, "mutants.out", "outcomes.json")
    if not os.path.exists(p):
        return []
    with open(p) as f:
        d = json.load(f)
    res = []
    for o in d["outcomes"]:
        sc = o["scenario"]
        if not isinstance(sc, dict) or "Mutant" not in sc:
            continue
        m = sc["Mutant"]
        res.append((mutant_id(m), o["summary"], m))
    return res


def survivors(out, path, tiers_before, uncovered):
    """Mutants of `path` that no tier so far caught and that were viable, on lines tests reach."""
    state = {}
    for t in tiers_before:
        for mid, summary, m in outcomes_of(os.path.join(out, f"tier{t}", slug(path))):
            state[mid] = summary
    keep = []
    for mid, summary in state.items():
        if summary in ("MissedMutant", "Timeout"):
            line = int(mid.split(":")[1])
            if line not in uncovered.get(path, ()):
                keep.append(mid)
    return keep


def run(argv):
    tier, out, tree, jobs, lines_file, files, shard, quiet = None, None, ROOT, "3", None, [], None, False
    a = list(argv)
    while a:
        x = a.pop(0)
        if x == "--tier":
            t = a.pop(0)
            tier = t if t == "all" else int(t)
        elif x == "--quiet":
            quiet = True
        elif x == "--shard":
            k, m = a.pop(0).split("/")
            shard = (int(k), int(m))
        elif x == "--out":
            out = os.path.abspath(a.pop(0))
        elif x == "--tree":
            tree = os.path.abspath(a.pop(0))
        elif x == "--jobs":
            jobs = a.pop(0)
        elif x == "--lines":
            lines_file = a.pop(0)
        else:
            files.append(x)
    if tier not in (1, 2, 3, "all") or not out:
        print(__doc__)
        return 2
    if shard and not 0 <= shard[0] < shard[1]:
        print("--shard K/M needs 0 <= K < M", file=sys.stderr)
        return 2
    uncovered = {}
    if tier != 1:
        if not lines_file:
            print("tiers 2 and 3 need --lines (coverage.py --lines)", file=sys.stderr)
            return 2
        with open(lines_file) as f:
            uncovered = {k: set(v["uncovered"]) for k, v in json.load(f).items()}
    todo_files = files or review_order()
    if shard:
        todo_files = todo_files[shard[0]::shard[1]]
    for path in todo_files:
        for t in (1, 2, 3) if tier == "all" else (tier,):
            run_one(path, t, out, tree, jobs, uncovered, quiet)
    return 0


SUMMARY = re.compile(r"^\d+ mutants? tested in [^:]*: .*$", re.M)


def run_one(path, tier, out, tree, jobs, uncovered, quiet=False):
    """cargo-mutants on one file in one tier, into out/tier<N>/<file>."""
    if tier == 3 and path not in TIER3_FILES:
        return
    d = os.path.join(out, f"tier{tier}", slug(path))
    os.makedirs(d, exist_ok=True)
    cmd = ["cargo", "mutants", "-f", path, "-j", jobs, "--cargo-arg=--locked", "-o", d]
    if tier == 1:
        cmd += ["--timeout-multiplier", "5", "--minimum-test-timeout", "60"] + tier1_args(path)
    else:
        todo = survivors(out, path, range(1, tier), uncovered)
        if not todo:
            print(f"{path}: no survivors to try in tier {tier}", flush=True)
            return
        rx = "^(" + "|".join(re.escape(m) for m in todo) + ")$"
        cmd += ["--baseline", "skip", "--timeout", "300" if tier == 2 else "600", "--test-package", "sfr",
                "-F", rx]
        if tier == 3:
            cmd += ["--cargo-arg=--profile=qemu-test"]
        cmd += ["--"] + (SFR_E2E if tier == 2 else FORGING + (["--test", "canonical"] if path.endswith("json.rs") else []))
    print("+", path, "tier", tier, flush=True)
    if quiet:
        # No GITHUB_ACTIONS: cargo-mutants would print each missed mutant as a workflow annotation.
        env = {k: v for k, v in os.environ.items() if k != "GITHUB_ACTIONS"}
        os.makedirs(os.path.join(out, "log"), exist_ok=True)
        log = os.path.join(out, "log", f"tier{tier}-{slug(path)}.txt")
        with open(log, "w") as lf:
            r = subprocess.run(cmd, cwd=tree, env=env, stdout=lf, stderr=subprocess.STDOUT)
        with open(log) as lf:
            found = SUMMARY.findall(lf.read())
        # The summary line holds counts only.
        print(found[-1] if found else f"(no summary; cargo mutants exit status {r.returncode})", flush=True)
    else:
        r = subprocess.run(cmd, cwd=tree)
    if r.returncode not in (0, 2, 3):  # 0 all caught, 2 survivors, 3 timeouts; others are failures
        print(f"cargo mutants failed on {path} with status {r.returncode}", file=sys.stderr, flush=True)


def collect(argv):
    out, lines_file, missed_dir = None, None, None
    a = list(argv)
    while a:
        x = a.pop(0)
        if x == "--out":
            out = os.path.abspath(a.pop(0))
        elif x == "--lines":
            lines_file = a.pop(0)
        elif x == "--missed-dir":
            missed_dir = os.path.abspath(a.pop(0))
    if not out:
        print(__doc__)
        return 2
    uncovered = {}
    if lines_file:
        with open(lines_file) as f:
            uncovered = {k: set(v["uncovered"]) for k, v in json.load(f).items()}
    data = ledger.load()
    per = {c["id"]: {"caught": 0, "missed": 0, "unviable": 0, "timeout": 0, "not_run": 0, "tier": {"1": 0, "2": 0, "3": 0},
                     "missed_list": []} for c in data["chunks"]}
    ran_files = set()
    for path in sorted({c["file"] for c in data["chunks"]}):
        final = {}  # id -> (summary, tier_that_decided, mutant)
        for t in (1, 2, 3):
            for mid, summary, m in outcomes_of(os.path.join(out, f"tier{t}", slug(path))):
                ran_files.add(path)
                prev = final.get(mid)
                if prev and prev[0] in ("CaughtMutant", "Unviable"):
                    continue
                final[mid] = (summary, t, m)
        for mid, (summary, t, m) in final.items():
            line = m["span"]["start"]["line"]
            c = ledger.chunk_for(data, path, line)
            if not c:
                continue
            p = per[c["id"]]
            if summary == "CaughtMutant":
                p["caught"] += 1
                p["tier"][str(t)] += 1
            elif summary == "Unviable":
                p["unviable"] += 1
            elif summary == "Timeout":
                p["timeout"] += 1
                p["missed_list"].append(("timeout", mid))
            elif summary == "MissedMutant":
                p["missed"] += 1
                note = "not executed by any test" if line in uncovered.get(path, ()) else f"survived tier {t}"
                p["missed_list"].append((note, mid))
    for c in data["chunks"]:
        p = per[c["id"]]
        if c["file"] in ran_files:
            c.setdefault("metrics", {})["mutants"] = {k: p[k] for k in ("caught", "missed", "unviable", "timeout")}
            c["metrics"]["mutants"]["caught_by_tier"] = p["tier"]
        if missed_dir and p["missed_list"]:
            os.makedirs(missed_dir, exist_ok=True)
            with open(os.path.join(missed_dir, f"{c['id']}.txt"), "w") as f:
                f.write(f"{c['id']} {c['file']} lines {c['start']}-{c['end']}: mutants that no test caught\n")
                for note, mid in sorted(p["missed_list"], key=lambda x: int(x[1].split(":")[1])):
                    f.write(f"{mid}  [{note}]\n")
    ledger.save(data)
    ledger.render()
    tot = {k: sum(per[c["id"]][k] for c in data["chunks"]) for k in ("caught", "missed", "unviable", "timeout")}
    print(tot)
    return 0


def merge_metrics(argv):
    if not argv:
        print(__doc__)
        return 2
    data = ledger.load()
    seen = {}
    for p in argv:
        with open(p) as f:
            shard = json.load(f)
        for c in shard["chunks"]:
            m = c.get("metrics", {}).get("mutants")
            if m is None:
                continue
            if c["id"] in seen:
                print(f"chunk {c['id']} is in {seen[c['id']]} and {p}", file=sys.stderr)
                return 1
            seen[c["id"]] = p
            mine = next((x for x in data["chunks"] if x["id"] == c["id"]), None)
            if mine is None:
                print(f"{p}: chunk {c['id']} is not in the ledger", file=sys.stderr)
                return 1
            mine.setdefault("metrics", {})["mutants"] = m
    ledger.save(data)
    ledger.render()
    print(f"mutation metrics of {len(seen)} chunks merged from {len(argv)} ledgers")
    return 0


def self_test():
    m = {"file": "crates/a/src/x.rs", "name": "replace f -> u8 with 0", "span": {"start": {"line": 7, "column": 5}}}
    assert mutant_id(m) == "crates/a/src/x.rs:7:5: replace f -> u8 with 0"
    assert slug("crates/a/src/x.rs") == "crates__a__src__x.rs"
    assert tier1_args("crates/sfr-core/src/x.rs") == ["--", "--lib"]
    assert tier1_args("crates/sfr/src/main.rs") == ["--", "--bins"]
    rx = "^(" + "|".join(re.escape(x) for x in [mutant_id(m)]) + ")$"
    assert re.match(rx, mutant_id(m))
    assert SUMMARY.findall("x\n13 mutants tested in 86s: 1 missed, 3 caught, 9 unviable\n") == [
        "13 mutants tested in 86s: 1 missed, 3 caught, 9 unviable"]
    assert review_order()[0] == "crates/sfr-core/src/ulog.rs" and len(set(review_order())) == len(review_order())
    files = review_order()
    parts = [files[k::3] for k in range(3)]
    assert sorted(sum(parts, [])) == sorted(files) and all(parts)
    print("mutants self-test: ok")
    return 0


def main(argv):
    if len(argv) >= 2 and argv[1] == "--self-test":
        return self_test()
    if len(argv) >= 2 and argv[1] == "run":
        return run(argv[2:])
    if len(argv) >= 2 and argv[1] == "collect":
        return collect(argv[2:])
    if len(argv) >= 2 and argv[1] == "merge-metrics":
        return merge_metrics(argv[2:])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
