#!/usr/bin/env python3
"""Compare `sfr seal --dry-run --json` output with the independent pyulog oracle.

Usage: python3 -I compare_oracle.py <sfr.json> <oracle.json>

The oracle (oracle.py: a test-only second implementation on pyulog, sharing no code with sfr;
its header says what it does and does not check). This script maps sfr's event fields onto the
oracle's schema and reports every
difference in configuration, firmware, `is_vtol` and `vtol_type`, events (kind, time, source, kind
fields including the COMMAND category, order), the rules both evaluate (R1, R4, R5, R6, R7),
`config.watched_parameters`, and every sealed topic digest entry field by field. Exit 0 when they
agree, 1 otherwise.
"""
import json
import sys

KIND_FIELDS = {
    "ARM": ["initial", "reason"],
    "DISARM": ["reason"],
    "NAV_STATE_CHANGE": ["old", "new"],
    "FAILSAFE_SET": ["flag"],
    "FAILSAFE_CLEAR": ["flag"],
    "COMMAND": ["command", "category", "source_system", "source_component", "result"],
    "VTOL_TRANSITION_START": ["direction"],
    "VTOL_TRANSITION_END": ["direction"],
    "VTOL_TRANSITION_ABORT": ["direction"],
    "QUADCHUTE": ["vtol_fixed_wing_system_failure"],
    "PARAM_CHANGED_IN_FLIGHT": ["name", "old", "new"],
    "LOG_MESSAGE": ["level", "text"],
    "LOG_DROPOUT": ["duration_ms"],
}
COMMON = ["kind", "boot_us", "topic", "instance", "index"]
SEALED_FIELDS = ["topic", "multi_id", "format_sha256", "message_count", "first_timestamp_us",
                 "last_timestamp_us", "data_sha256"]
ABSENT = object()


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
    # vtol_type: null, or {value, name}, compared exactly (absent on either side is a difference).
    vt_mine = mine["log"]["vehicle"].get("vtol_type", ABSENT)
    vt_oracle = oracle.get("vtol_type", ABSENT)
    if vt_mine is ABSENT or vt_oracle is ABSENT or vt_mine != vt_oracle:
        show = lambda v: "absent" if v is ABSENT else json.dumps(v, sort_keys=True)
        problems.append(f"vtol_type: sfr {show(vt_mine)} oracle {show(vt_oracle)}")

    w_mine = mine["config"].get("watched_parameters", ABSENT)
    w_oracle = oracle.get("watched_parameters", ABSENT)
    if w_mine is ABSENT or w_oracle is ABSENT or w_mine != w_oracle:
        show = lambda v: "absent" if v is ABSENT else v
        problems.append(f"watched_parameters: sfr {show(w_mine)} oracle {show(w_oracle)}")

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
            extra = ""
            if rid == "R7":
                extra = f" (oracle's unauthorized event sequence numbers: {oracle.get('r7_unauthorized')})"
            problems.append(f"{rid}: sfr {results.get(rid)} oracle {status}{extra}")
    if "R7" not in oracle["results"]:
        problems.append("R7: the oracle has no R7 status (regenerate the oracle)")
    r1 = next(r for r in mine["results"] if r["id"] == "R1")
    found_missing = sorted(d.removeprefix("missing ") for d in r1["detail"])
    if found_missing != sorted(oracle["missing"]):
        problems.append(f"R1 missing: sfr {found_missing} oracle {sorted(oracle['missing'])}")

    # Sealed topic digests: the same entries in the same order (topic, then multi_id), each field equal.
    s_mine = mine.get("sealed_topics", ABSENT)
    s_oracle = oracle.get("sealed_topics", ABSENT)
    if s_mine is ABSENT or s_oracle is ABSENT:
        problems.append(f"sealed_topics: absent in {'sfr' if s_mine is ABSENT else 'the oracle'}")
    else:
        key = lambda e: (e.get("topic"), e.get("multi_id"))
        if [key(e) for e in s_mine] != [key(e) for e in s_oracle]:
            problems.append(f"sealed_topics entries: sfr {[key(e) for e in s_mine]} "
                            f"oracle {[key(e) for e in s_oracle]}")
        by_oracle = {key(e): e for e in s_oracle}
        for e in s_mine:
            o = by_oracle.get(key(e))
            if o is None:
                continue
            for f in sorted(set(SEALED_FIELDS) | set(e) | set(o)):
                if e.get(f, ABSENT) != o.get(f, ABSENT):
                    problems.append(f"sealed_topics {key(e)} {f}: sfr {e.get(f, 'absent')} "
                                    f"oracle {o.get(f, 'absent')}")

    for p in problems:
        print(p)
    print(f"{sys.argv[1]}: {len(a)} events, {len(problems)} difference(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
