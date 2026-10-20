#!/usr/bin/env python3
"""Writes the PX4 tables sfr reads from the PX4-Autopilot source at each supported release tag.

usage: px4_tables.py <PX4-Autopilot git checkout> [--check]

For every release tag v1.14.0 to v1.17.x (no alpha, beta or rc), from that tag's tree and
nothing else:
  - the msg files of the topics the rules read: field names and types, and the constants
    (ARMING_STATE_*, NAVIGATION_STATE_*, VEHICLE_TYPE_*, VEHICLE_CMD_RESULT_* and the rest).
    A file is msg/versioned/<Name>.msg when that exists at the tag, else msg/<Name>.msg; the
    topic names come from its "# TOPICS" line, else from the file name;
  - which failsafe_flags flag makes which mode_req_* mask apply: the `!status_flags.<flag> ||
    ((status_flags.<mode_req> & mode_mask) == 0)` terms of FailsafeBase::modeCanRun
    (src/modules/commander/failsafe/framework.cpp), and, for the two masks that function
    leaves to the mode checks, the flags in the `if` that guards
    clearCanRunBits(<mode_req_manual_control or mode_req_wind_and_flight_time_compliance>)
    in src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp.

Writes crates/sfr-core/src/px4_tables.rs, the same tables as scripts/testdata/px4_tables.json
for the test scripts, and the per-tag source table in docs/VALIDATION.md
(between its px4-sources markers): tag, commit, and each file's path and git blob id. With
--check, writes nothing and exits 1 when either differs from what it would write. Standard
library and git only. The PX4-Autopilot checkout can be a blob-less clone
(git clone --filter=blob:none --no-checkout https://github.com/PX4/PX4-Autopilot.git).
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RUST_OUT = os.path.join(ROOT, "crates", "sfr-core", "src", "px4_tables.rs")
# The same tables for the test scripts (the pyulog oracle, the false-pass generator).
JSON_OUT = os.path.join(ROOT, "scripts", "testdata", "px4_tables.json")
ULOG = {"Bool": "bool", "Char": "char", "I8": "int8_t", "U8": "uint8_t", "I16": "int16_t",
        "U16": "uint16_t", "I32": "int32_t", "U32": "uint32_t", "I64": "int64_t",
        "U64": "uint64_t", "F32": "float", "F64": "double"}
DOC = os.path.join(ROOT, "docs", "VALIDATION.md")
DOC_START = "<!-- px4-sources:start (scripts/px4/px4_tables.py writes this table) -->"
DOC_END = "<!-- px4-sources:end -->"

# The msg files of the topics a rule reads.
MSGS = ["VehicleStatus", "FailsafeFlags", "VehicleCommand", "VehicleCommandAck",
        "BatteryStatus", "SensorGps", "EstimatorStatus", "EstimatorSelectorStatus",
        "VehicleImuStatus", "SensorSelection"]
FRAMEWORK = "src/modules/commander/failsafe/framework.cpp"
MODE_CHECK = "src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp"
SEPARATE = ["mode_req_manual_control", "mode_req_wind_and_flight_time_compliance"]
SCALARS = {"bool": "Bool", "char": "Char", "int8": "I8", "uint8": "U8", "byte": "U8",
           "int16": "I16", "uint16": "U16", "int32": "I32", "uint32": "U32", "int64": "I64",
           "uint64": "U64", "float32": "F32", "float64": "F64"}
TAG = re.compile(r"^v1\.(1[4-7])\.(\d+)$")


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True,
                          text=True).stdout


def release_tags(repo):
    tags = [t for t in git(repo, "tag", "--list", "v1.1*").split() if TAG.match(t)]
    return sorted(tags, key=lambda t: tuple(int(x) for x in t[1:].split(".")))


def snake(name):
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def parse_msg(text):
    """(topics, fields, constants) of a .msg file: fields as (name, scalar), arrays expanded."""
    topics, fields, constants = [], [], []
    for line in text.splitlines():
        if line.strip().startswith("# TOPICS"):
            topics += line.split()[2:]
        code = line.split("#", 1)[0].strip()
        if not code:
            continue
        m = re.match(r"^(\w+)(?:\[(\d+)\])?\s+(\w+)\s*(?:=\s*(\S+))?$", code)
        if not m:
            raise SystemExit("px4_tables.py: cannot read msg line %r" % line)
        typ, n, name, value = m.groups()
        if value is not None:
            constants.append((name, int(value, 0)))
            continue
        if typ not in SCALARS:
            continue  # a nested message: no rule reads one
        names = [name] if n is None else ["%s[%d]" % (name, i) for i in range(int(n))]
        fields += [(x, SCALARS[typ]) for x in names]
    return topics, fields, constants


def mode_requirements(framework, mode_check):
    """(flag, mode_req) pairs: modeCanRun's terms, then the two masks it leaves to modeCheck.cpp."""
    body = framework[framework.index("FailsafeBase::modeCanRun"):]
    body = body[:body.index("\n}")]
    pairs = re.findall(r"!status_flags\.(\w+)\s*\|\|\s*\(\(status_flags\.(mode_req_\w+)\s*&\s*mode_mask\)",
                       body)
    if not pairs:
        raise SystemExit("px4_tables.py: no requirement term in FailsafeBase::modeCanRun")
    for req in SEPARATE:
        clear = mode_check.index("clearCanRunBits((NavModes)reporter.failsafeFlags().%s)" % req)
        cond = mode_check[mode_check.rindex("if (", 0, clear):clear]
        cond = cond[:cond.index("{")]
        flags = [f for f in re.findall(r"failsafeFlags\(\)\.(\w+)", cond) if not f.startswith("mode_req_")]
        if not flags:
            raise SystemExit("px4_tables.py: no flag guards %s in modeCheck.cpp" % req)
        pairs += [(f, req) for f in flags]
    return pairs


def read_release(repo, tag):
    commit = git(repo, "rev-parse", tag + "^{commit}").strip()
    files = set(git(repo, "ls-tree", "-r", "--name-only", tag, "msg").split())
    sources, msgs = [], []
    for name in MSGS:
        path = "msg/versioned/%s.msg" % name
        if path not in files:
            path = "msg/%s.msg" % name
        if path not in files:
            raise SystemExit("px4_tables.py: %s has no %s.msg" % (tag, name))
        blob = git(repo, "rev-parse", "%s:%s" % (tag, path)).strip()
        sources.append((path, blob))
        topics, fields, constants = parse_msg(git(repo, "show", "%s:%s" % (tag, path)))
        msgs.append((name, topics or [snake(name)], fields, constants))
    texts = []
    for path in (FRAMEWORK, MODE_CHECK):
        sources.append((path, git(repo, "rev-parse", "%s:%s" % (tag, path)).strip()))
        texts.append(git(repo, "show", "%s:%s" % (tag, path)))
    return {"tag": tag, "commit": commit, "msgs": msgs, "sources": sources,
            "requirements": mode_requirements(*texts)}


def rust(releases):
    defs, index = [], {}
    for r in releases:
        r["topic_refs"] = []
        for name, topics, fields, constants in r["msgs"]:
            key = (name, tuple(fields), tuple(constants))
            if key not in index:
                index[key] = len(defs)
                defs.append(key)
            r["topic_refs"] += [(t, index[key]) for t in topics]
    def block(head, items):
        return ["        %s: &[]," % head] if not items else \
            ["        %s: &[" % head] + items + ["        ],"]

    out = ["//! PX4 message definitions and mode requirements at each supported release tag.",
           "//! Written by `scripts/px4/px4_tables.py` from the PX4-Autopilot source at each tag;",
           "//! do not edit. `docs/VALIDATION.md` lists every source file with its commit and blob.",
           "",
           "use crate::ulog::Scalar;",
           "",
           "/// One msg file as it is at one or more tags.",
           "pub struct MsgDef {",
           "    /// The file name without `.msg`.",
           "    pub name: &'static str,",
           "    /// Each field, arrays expanded as `name[i]`, with its type; nested messages left out.",
           "    pub fields: &'static [(&'static str, Scalar)],",
           "    /// Each constant and its value.",
           "    pub constants: &'static [(&'static str, i64)],",
           "}",
           "",
           "/// A PX4 release tag and what was read at it.",
           "pub struct Release {",
           "    /// The tag, such as `v1.17.0`.",
           "    pub tag: &'static str,",
           "    /// Major, minor and patch.",
           "    pub version: (u8, u8, u8),",
           "    /// The commit the tag names.",
           "    pub commit: &'static str,",
           "    /// Topic name and its message, an index into [`MSGS`].",
           "    pub topics: &'static [(&'static str, usize)],",
           "    /// `failsafe_flags` flag and the `mode_req_*` mask that says in which modes it stops",
           "    /// the mode from running.",
           "    pub mode_requirements: &'static [(&'static str, &'static str)],",
           "    /// Each source file read: path and git blob id.",
           "    pub sources: &'static [(&'static str, &'static str)],",
           "}",
           "",
           "/// Every distinct msg file definition.",
           "pub static MSGS: &[MsgDef] = &["]
    for name, fields, constants in defs:
        out.append("    MsgDef {")
        out.append("        name: %s," % q(name))
        out += block("fields", ["            (%s, Scalar::%s)," % (q(f), s) for f, s in fields])
        out += block("constants", ["            (%s, %d)," % (q(c), v) for c, v in constants])
        out.append("    },")
    out += ["];", "", "/// Every supported release tag, oldest first.", "pub static RELEASES: &[Release] = &["]
    for r in releases:
        v = tuple(int(x) for x in r["tag"][1:].split("."))
        out.append("    Release {")
        out.append("        tag: %s," % q(r["tag"]))
        out.append("        version: (%d, %d, %d)," % v)
        out.append("        commit: %s," % q(r["commit"]))
        out.append("        topics: &[")
        out += ["            (%s, %d)," % (q(t), i) for t, i in r["topic_refs"]]
        out.append("        ],")
        out.append("        mode_requirements: &[")
        out += ["            (%s, %s)," % (q(f), q(m)) for f, m in r["requirements"]]
        out.append("        ],")
        out.append("        sources: &[")
        out += ["            (%s, %s)," % (q(p), q(b)) for p, b in r["sources"]]
        out.append("        ],")
        out.append("    },")
    out.append("];")
    return "\n".join(out) + "\n"


def q(s):
    return '"%s"' % s


def as_json(releases):
    """{"msgs": [distinct msg definitions], "releases": [{..., "topics": {topic: msg index}}]}"""
    msgs, index, out = [], {}, []
    for r in releases:
        topics = {}
        for name, names, fields, constants in r["msgs"]:
            key = (name, tuple(fields), tuple(constants))
            if key not in index:
                index[key] = len(msgs)
                msgs.append({"msg": name, "fields": [[f, ULOG[s]] for f, s in fields],
                             "constants": dict(constants)})
            topics.update((t, index[key]) for t in names)
        out.append({"tag": r["tag"], "commit": r["commit"],
                    "version": [int(x) for x in r["tag"][1:].split(".")], "topics": topics,
                    "mode_requirements": [list(p) for p in r["requirements"]]})
    return json.dumps({"msgs": msgs, "releases": out}, indent=1, sort_keys=True) + "\n"


def doc_table(releases):
    lines = [DOC_START, "", "| Tag | Commit | File | Blob |", "|---|---|---|---|"]
    for r in releases:
        for i, (path, blob) in enumerate(r["sources"]):
            first = i == 0
            lines.append("| %s | %s | `%s` | `%s` |" % (
                "`%s`" % r["tag"] if first else "", "`%s`" % r["commit"] if first else "", path, blob))
    lines += ["", DOC_END]
    return "\n".join(lines)


def main():
    args = sys.argv[1:]
    check = "--check" in args
    args = [a for a in args if a != "--check"]
    if len(args) != 1:
        sys.exit(__doc__)
    releases = [read_release(args[0], t) for t in release_tags(args[0])]
    new_rust = rust(releases)
    doc = open(DOC, encoding="utf-8").read()
    a, b = doc.index(DOC_START), doc.index(DOC_END) + len(DOC_END)
    new_doc = doc[:a] + doc_table(releases) + doc[b:]
    new_json = as_json(releases)
    old = {p: open(p, encoding="utf-8").read() if os.path.exists(p) else "" for p in (RUST_OUT, JSON_OUT)}
    if check:
        bad = [p for p, o, n in [(RUST_OUT, old[RUST_OUT], new_rust), (JSON_OUT, old[JSON_OUT], new_json),
                                 (DOC, doc, new_doc)] if o != n]
        for p in bad:
            print("px4_tables.py --check: %s differs from the PX4 source" % os.path.relpath(p, ROOT))
        print("px4_tables.py --check: %d release tags, %s" % (len(releases), "differs" if bad else "up to date"))
        sys.exit(1 if bad else 0)
    open(RUST_OUT, "w", encoding="utf-8").write(new_rust)
    open(JSON_OUT, "w", encoding="utf-8").write(new_json)
    open(DOC, "w", encoding="utf-8").write(new_doc)
    print("px4_tables.py: %d release tags: %s" % (len(releases), " ".join(r["tag"] for r in releases)))


if __name__ == "__main__":
    main()
