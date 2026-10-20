#!/usr/bin/env python3
"""Differential test: the pyulog oracle against sfr, both run now, on every golden log and every
false-pass case.

usage: python3 -I oracle_differential.py <sfr>
       (run with the Python that has scripts/testdata/requirements-dev.txt installed)

For each golden log (scripts/testdata/golden_logs.sh) it runs `sfr seal --dry-run --json` and
oracle.py, and compares them with compare_oracle.py: configuration, firmware, events, R1, R4, R5,
R6, R7, watched parameters and sealed topic digests. For each case in testdata/falsepass/cases.json
it compares the status of R1, R4, R5 and R6 (a case whose rules file sfr refuses for ignoring every parameter is sealed
again with --allow-ignore-all, which affects only R3). A log that pyulog cannot read at all must be one sfr
refuses too. Prints one line per log and exit 1 on any difference.

oracle.py is test-only: it is never built into sfr, and pyulog is never a dependency of the
product.
"""
import json
import os
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
HERE = os.path.join(ROOT, "scripts", "testdata")
FALSEPASS_RULES = ["R1", "R4", "R5", "R6"]


def golden():
    """(name, log, rules, flags) for each golden log, from golden_logs.sh."""
    script = (". scripts/testdata/golden_logs.sh; golden_logs | while read -r n l; do "
              "printf '%s\\t%s\\t%s\\t%s\\n' \"$n\" \"$l\" \"$(golden_rules_for \"$n\")\" "
              "\"$(golden_flags_for \"$n\")\"; done")
    out = subprocess.run(["bash", "-c", script], cwd=ROOT, check=True, capture_output=True,
                         text=True).stdout
    for line in out.splitlines():
        name, log, rules, flags = line.split("\t")
        yield name, log, rules, flags.split()


def sfr_json(sfr, log, rules, baseline, options):
    p = subprocess.run([sfr, "seal", log, "--rules", rules, "--baseline", baseline, "--dry-run",
                        "--json"] + options, cwd=ROOT, capture_output=True)
    if p.returncode not in (0, 1, 2):
        return None
    return json.loads(p.stdout)


def oracle_json(log, rules):
    p = subprocess.run([sys.executable, "-I", os.path.join(HERE, "oracle.py"), log, rules],
                       cwd=ROOT, capture_output=True)
    # pyulog prints its own warnings to standard output; the oracle's JSON is the last line.
    lines = p.stdout.decode("utf-8", "replace").strip().splitlines()
    if p.returncode != 0 or not lines or not lines[-1].startswith("{"):
        return None, p.stderr.decode("utf-8", "replace").strip().splitlines()[-1:]
    return json.loads(lines[-1]), None


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sfr = os.path.abspath(sys.argv[1])
    failures = 0
    tmp = os.path.join(ROOT, "target", "oracle-differential")
    os.makedirs(tmp, exist_ok=True)

    for name, log, rules, flags in golden():
        doc = sfr_json(sfr, log, rules, "testdata/baselines/%s.params" % name, flags)
        ora, err = oracle_json(log, rules)
        if doc is None or ora is None:
            print("FAIL golden %s: sfr %s, oracle %s" % (name, "ok" if doc else "refused",
                                                         err or "ok"))
            failures += 1
            continue
        a, b = os.path.join(tmp, name + ".json"), os.path.join(tmp, name + ".oracle.json")
        with open(a, "w") as f:
            json.dump(doc, f)
        with open(b, "w") as f:
            json.dump(ora, f)
        p = subprocess.run([sys.executable, "-I", os.path.join(HERE, "compare_oracle.py"), a, b],
                           capture_output=True, text=True)
        if p.returncode != 0:
            print("FAIL golden %s:\n%s" % (name, p.stdout + p.stderr))
            failures += 1
        else:
            print("ok   golden %s" % name)

    d = os.path.join("testdata", "falsepass")
    with open(os.path.join(ROOT, d, "cases.json")) as f:
        cases = json.load(f)
    for c in cases:
        log, rules = os.path.join(d, c["log"]), os.path.join(d, c["rules"])
        doc = sfr_json(sfr, log, rules, os.path.join(d, c["baseline"]), c["options"])
        if doc is None and c["expect"]["exit"] == 4:
            # Refused for its rules file, which ignores every parameter: --allow-ignore-all
            # accepts it, and changes nothing but R3.
            doc = sfr_json(sfr, log, rules, os.path.join(d, c["baseline"]),
                           c["options"] + ["--allow-ignore-all"])
        ora, err = oracle_json(log, rules)
        if ora is None:
            if doc is None:
                print("ok   falsepass %s: both refuse the log (pyulog: %s)" % (c["case"], err))
            else:
                print("FAIL falsepass %s: sfr reads the log, pyulog cannot (%s)" % (c["case"], err))
                failures += 1
            continue
        if doc is None:
            print("FAIL falsepass %s: sfr refuses the log, the oracle reads it" % c["case"])
            failures += 1
            continue
        got = {r["id"]: r["status"] for r in doc["results"]}
        diffs = ["%s sfr %s, oracle %s" % (r, got.get(r), ora["results"].get(r))
                 for r in FALSEPASS_RULES if got.get(r) != ora["results"].get(r)]
        if diffs:
            print("FAIL falsepass %s: %s" % (c["case"], "; ".join(diffs)))
            failures += 1
        else:
            print("ok   falsepass %s: %s" % (
                c["case"], " ".join("%s %s" % (r, got.get(r)) for r in FALSEPASS_RULES)))
    print("%d difference(s)" % failures)
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
