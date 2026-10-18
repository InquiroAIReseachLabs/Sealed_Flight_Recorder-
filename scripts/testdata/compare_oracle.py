#!/usr/bin/env python3
"""Compare `sfr seal --dry-run --json` output with the independent pyulog oracle.

Usage: python3 -I compare_oracle.py <sfr.json> <oracle.json>

The oracle (oracle.py, built on pyulog only from SPEC B1.5 and B1.6) and sfr were written
independently. This script maps sfr's event fields onto the oracle's schema and reports every
difference in configuration, firmware, events (kind, time, source, kind fields, order) and the
rules both evaluate (R1, R4, R5, R6). Exit 0 when they agree, 1 otherwise.
"""
import json
import sys

KIND_FIELDS = {
    "ARM": ["initial", "reason"],
    "DISARM": ["reason"],
    "NAV_STATE_CHANGE": ["old", "new"],
    "FAILSAFE_SET": ["flag"],
    "FAILSAFE_CLEAR": ["flag"],
    "COMMAND": ["command", "source_system", "source_component", "result"],
    "VTOL_TRANSITION_START": ["direction"],
    "VTOL_TRANSITION_END": ["direction"],
    "VTOL_TRANSITION_ABORT": ["direction"],
    "PARAM_CHANGED_IN_FLIGHT": ["name", "old", "new"],
    "LOG_MESSAGE": ["level", "text"],
    "LOG_DROPOUT": ["duration_ms"],
}
COMMON = ["kind", "boot_us", "topic", "instance", "index"]


def project(event):
    keys = COMMON + KIND_FIELDS.get(event["kind"], [])
    out = {}
    for k in keys:
        v = event.get(k)
        # The oracle leaves DISARM's `initial` out; sfr has none either.
        out[k] = v
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    with open(sys.argv[1], encoding="utf-8") as f:
        mine = json.load(f)
    with open(sys.argv[2], encoding="utf-8") as f:
        oracle = json.load(f)
    problems = []

    if mine["config"]["parameters"] != oracle["config"]:
        a, b = mine["config"]["parameters"], oracle["config"]
        for k in sorted(set(a) | set(b)):
            if a.get(k) != b.get(k):
                problems.append(f"config {k}: sfr {a.get(k)} oracle {b.get(k)}")
    fw = mine["log"]["firmware"]
    if fw["version"] != oracle["firmware"]["release"] or fw["git"] != oracle["firmware"]["git"]:
        problems.append(f"firmware: sfr {fw} oracle {oracle['firmware']}")
    if mine["log"]["vehicle"]["is_vtol"] != oracle.get("is_vtol"):
        problems.append(f"is_vtol: sfr {mine['log']['vehicle']['is_vtol']} oracle {oracle.get('is_vtol')}")

    a = [project(e) for e in mine["events"]]
    b = [project(e) for e in oracle["events"]]
    if len(a) != len(b):
        problems.append(f"event count: sfr {len(a)} oracle {len(b)}")
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            problems.append(f"event {i}: sfr {x} oracle {y}")
    seqs = [e["seq"] for e in mine["events"]]
    if seqs != list(range(len(seqs))):
        problems.append("sfr sequence numbers are not 0..n-1")

    results = {r["id"]: r["status"] for r in mine["results"]}
    for rid, status in oracle["results"].items():
        if results.get(rid) != status:
            problems.append(f"{rid}: sfr {results.get(rid)} oracle {status}")
    r1 = next(r for r in mine["results"] if r["id"] == "R1")
    found_missing = sorted(d.removeprefix("missing ") for d in r1["detail"])
    if found_missing != sorted(oracle["missing"]):
        problems.append(f"R1 missing: sfr {found_missing} oracle {sorted(oracle['missing'])}")

    for p in problems:
        print(p)
    print(f"{sys.argv[1]}: {len(a)} events, {len(problems)} difference(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
