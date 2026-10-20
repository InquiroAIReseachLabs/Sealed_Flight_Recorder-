#!/usr/bin/env python3
"""Runs the false-pass corpus (testdata/falsepass/cases.json) through an sfr binary.

usage: run_falsepass.py <sfr> [--dir testdata/falsepass] [--table] [--no-check]

Seals each case with `seal --dry-run --json` and compares the exit code, overall status, the
named rule statuses and `found` texts, the vehicle_status instance count, the skipped-message
count and the event counts with the case's expected result. Prints one line per case, or with
--table a Markdown table of what the binary gave. Exit 1 when a case differs (unless
--no-check). Standard library only.
"""
import json
import os
import subprocess
import sys


def run(sfr, d, case):
    cmd = [sfr, "seal", os.path.join(d, case["log"]), "--rules", os.path.join(d, case["rules"]),
           "--baseline", os.path.join(d, case["baseline"]), "--dry-run", "--json"] + case["options"]
    p = subprocess.run(cmd, capture_output=True)
    doc = None
    if p.returncode in (0, 1, 2):
        try:
            doc = json.loads(p.stdout)
        except ValueError:
            doc = None
    return p.returncode, doc, p.stderr.decode("utf-8", "replace")


def summary(code, doc):
    if doc is None:
        return {"exit": code, "status": None, "results": {}}
    res = {r["id"]: r for r in doc["results"]}
    skipped = doc["log"].get("skipped")
    return {
        "exit": code,
        "status": doc["status"],
        "results": {k: v["status"] for k, v in res.items()},
        "found": {k: v["found"] for k, v in res.items()},
        "instances": doc["log"].get("vehicle_status_instances"),
        "skipped": (skipped["unknown_records"] + skipped["orphan_data_records"] + skipped["regions"])
        if skipped else None,
        "events": {k: sum(1 for e in doc["events"] if e["kind"] == k) for k in
                   {e["kind"] for e in doc["events"]}},
    }


def differences(expect, got):
    out = []
    if expect["exit"] != got["exit"]:
        out.append("exit %s, expected %s" % (got["exit"], expect["exit"]))
    if expect["status"] != got["status"]:
        out.append("status %s, expected %s" % (got["status"], expect["status"]))
    for rid, st in expect["results"].items():
        if got["results"].get(rid) != st:
            out.append("%s %s, expected %s" % (rid, got["results"].get(rid), st))
    for rid, text in expect.get("found", {}).items():
        if text not in got.get("found", {}).get(rid, ""):
            out.append("%s found %r lacks %r" % (rid, got.get("found", {}).get(rid), text))
    for key in ("instances", "skipped"):
        if key in expect and got.get(key) != expect[key]:
            out.append("%s %s, expected %s" % (key, got.get(key), expect[key]))
    for kind, n in expect.get("events", {}).items():
        if got.get("events", {}).get(kind, 0) != n:
            out.append("%s events %s, expected %s" % (kind, got.get("events", {}).get(kind, 0), n))
    return out


def short(got):
    if got["status"] is None:
        return "exit %d, nothing sealed" % got["exit"]
    rules = ", ".join("%s %s" % (k, v) for k, v in sorted(got["results"].items())
                      if k in ("R3", "R4", "R5", "R6", "R7"))
    return "exit %d, %s (%s)" % (got["exit"], got["status"], rules)


def main():
    args = sys.argv[1:]
    table = "--table" in args
    check = "--no-check" not in args
    args = [a for a in args if a not in ("--table", "--no-check")]
    d = "testdata/falsepass"
    if "--dir" in args:
        i = args.index("--dir")
        d = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1:
        print(__doc__)
        return 2
    sfr = args[0]
    with open(os.path.join(d, "cases.json"), encoding="utf-8") as f:
        cases = json.load(f)
    bad = 0
    if table:
        print("| Case | Item | Kind | Result |")
        print("|---|---|---|---|")
    for case in cases:
        code, doc, err = run(sfr, d, case)
        got = summary(code, doc)
        diff = differences(case["expect"], got)
        bad += bool(diff)
        if table:
            print("| %s | %s | %s | %s |" % (case["case"], case["item"], case["kind"], short(got)))
        else:
            print("%s %s: %s%s" % ("FAIL" if diff else "ok", case["case"], short(got),
                                   ("; " + "; ".join(diff)) if diff else ""))
    if not table:
        print("%d case(s), %d differ from the expected result" % (len(cases), bad))
    return 1 if (bad and check) else 0


if __name__ == "__main__":
    sys.exit(main())
