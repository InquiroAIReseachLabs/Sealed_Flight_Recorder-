#!/usr/bin/env python3
"""Writes the test vectors in vectors/ (Python standard library only; no sfr code).

Every vector starts from examples/reports/vtol_transition.sfr, signed again with the vector key
(seed: SHA-256 of "sfr reference verifier test vectors"; vectors/vectors.pub is its public
half). A value-level vector edits the record and signs it again, so its signature is good and
only the other checks can refuse it; a byte-level vector edits the signed bytes. expected.json
gives each vector's verdict, accept or reject, or, where the two verifiers are known to differ,
each one's verdict and why; a test in crates/sfr/tests/reference_verifier.rs requires sfr verify
and sfr_ref_verify.py to give exactly those verdicts.

  make_vectors.py            write vectors/
  make_vectors.py --check    exit 1 if vectors/ differs from what would be written
"""
import base64
import copy
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import sfr_ref_verify as ref  # noqa: E402

SOURCE = os.path.join(HERE, "..", "..", "examples", "reports", "vtol_transition.sfr")
SEED = hashlib.sha256(b"sfr reference verifier test vectors").digest()
PUBLIC = ref.ed25519_public(SEED)
DER = ref.SPKI_PREFIX + PUBLIC
PEM = "-----BEGIN PUBLIC KEY-----\n" + base64.b64encode(DER).decode() + "\n-----END PUBLIC KEY-----\n"


def sign(r):
    """The record with its Merkle tree recomputed and signed by the vector key, as bytes."""
    r = copy.deepcopy(r)
    r["seal"]["key_fingerprint"] = "sha256:" + hashlib.sha256(DER).hexdigest()
    sections = ref.leaves(r)
    hashes = [ref.sha256(b"\x00" + bytes([tag]) + ref.jcs(x).encode("utf-8"))
              for _, tag, xs in sections for x in xs]
    root = ref.mth(hashes)
    r["merkle"] = {"algorithm": "sha256-rfc6962", "leaf_count": len(hashes), "root": root.hex(),
                   "sections": {name: len(xs) for name, _, xs in sections}}
    sig = ref.ed25519_sign(SEED, ref.signed_payload(r["schema_version"], sections, root))
    r["signature"] = {"algorithm": "ed25519", "value": sig.hex()}
    return ref.jcs(r).encode("utf-8")


def nested(n):
    v = []
    for _ in range(n):
        v = [v]
    return v


def vectors():
    base = json.loads(open(SOURCE, "rb").read())
    good = sign(base)
    out = {}

    def edit(name, verdict, f):
        r = copy.deepcopy(base)
        f(r)
        out[name] = (sign(r), verdict)

    def raw(name, verdict, f):
        out[name] = (f(good), verdict)

    out["valid.sfr"] = (good, "accept")
    # Types: a boolean where an integer belongs and the other way round.
    edit("bool_as_int.sfr", "reject", lambda r: r["seal"].__setitem__("allow_untested_version", 0))
    edit("int_as_bool_schema.sfr", "reject", lambda r: r.__setitem__("schema_version", True))
    edit("string_count.sfr", "reject", lambda r: r["events"][0].__setitem__("seq", "0"))
    # Integers at and over 2^53.
    edit("int_2_53_minus_1.sfr", "accept", lambda r: r["events"][0].__setitem__("index", 2 ** 53 - 1))
    edit("int_2_53.sfr", "reject", lambda r: r["events"][0].__setitem__("index", 2 ** 53))
    edit("int_2_53_plus_1.sfr", "reject", lambda r: r["events"][0].__setitem__("index", 2 ** 53 + 1))
    raw("negative_zero.sfr", "reject", lambda b: b.replace(b'"instance":0', b'"instance":-0', 1))
    raw("float.sfr", "reject", lambda b: b.replace(b'"instance":0', b'"instance":0.0', 1))
    raw("exponent.sfr", "reject", lambda b: b.replace(b'"instance":0', b'"instance":0e0', 1))
    raw("nan.sfr", "reject", lambda b: b.replace(b'"instance":0', b'"instance":NaN', 1))
    # Strings: surrogates, escapes, control characters, invalid UTF-8.
    raw("lone_high_surrogate.sfr", "reject",
        lambda b: b.replace(b'"name":"sfr"', b'"name":"\\ud800"', 1))
    raw("lone_low_surrogate.sfr", "reject",
        lambda b: b.replace(b'"name":"sfr"', b'"name":"\\udc00"', 1))
    raw("escaped_pair_not_canonical.sfr", "reject",
        lambda b: b.replace(b'"name":"sfr"', b'"name":"\\ud83d\\ude00"', 1))
    raw("escaped_slash.sfr", "reject", lambda b: b.replace(b'"name":"sfr"', b'"name":"s\\/fr"', 1))
    raw("raw_control_char.sfr", "reject", lambda b: b.replace(b'"name":"sfr"', b'"name":"s\x01fr"', 1))
    raw("invalid_utf8.sfr", "reject", lambda b: b.replace(b'"name":"sfr"', b'"name":"s\xc3fr"', 1))
    raw("byte_order_mark.sfr", "reject", lambda b: b"\xef\xbb\xbf" + b)
    # Structure: duplicate key, whitespace, trailing data, depth.
    raw("duplicate_key.sfr", "reject", lambda b: b.replace(b'"name":"sfr"', b'"name":"sfr","name":"sfr"', 1))
    raw("whitespace.sfr", "reject", lambda b: b.replace(b'"name":"sfr"', b'"name": "sfr"', 1))
    raw("trailing_newline.sfr", "reject", lambda b: b + b"\n")
    # The record object is at depth 0, so the innermost array of results[0].detail nested 59
    # times is at depth 63, the deepest allowed, and nested 60 times at depth 64.
    edit("depth_63.sfr", "accept", lambda r: r["results"][0].__setitem__("detail", [nested(59)]))
    edit("depth_64.sfr", "reject", lambda r: r["results"][0].__setitem__("detail", [nested(60)]))
    # Results as a set, and the overall status.
    edit("results_empty.sfr", "reject", lambda r: (r["results"].clear(), r.__setitem__("status", "PASS")))
    edit("result_status_failed.sfr", "reject",
         lambda r: (r["results"][3].__setitem__("status", "FAILED"), r.__setitem__("status", "PASS")))
    edit("result_status_object.sfr", "reject",
         lambda r: (r["results"][3].__setitem__("status", {}), r.__setitem__("status", "PASS")))
    edit("r4_removed.sfr", "reject", lambda r: (r["results"].pop(3), r.__setitem__("status", "PASS")))
    edit("r4_twice.sfr", "reject", lambda r: r["results"].insert(4, copy.deepcopy(r["results"][3])))
    edit("status_failed.sfr", "reject", lambda r: r.__setitem__("status", "FAILED"))
    edit("status_object.sfr", "reject", lambda r: r.__setitem__("status", {}))
    edit("status_disagrees.sfr", "reject", lambda r: r.__setitem__("status", "PASS"))
    edit("unknown_rule_id.sfr", "reject", lambda r: r["results"].append(
        dict(copy.deepcopy(r["results"][0]), id="Z1")))
    # Flags and the signature.
    edit("ignore_all_unflagged.sfr", "reject", lambda r: set_rules(r, IGNORE_ALL))
    edit("ignore_all_flagged.sfr", "accept",
         lambda r: (set_rules(r, IGNORE_ALL), r["seal"].__setitem__("allow_ignore_all", True)))
    edit("rules_unparsable.sfr", {"sfr": "reject", "reference": "accept",
                                  "why": "the reference verifier reads the rules file as TOML and its ignore list only, not every key"},
         lambda r: set_rules(r, "format = \"sfr-rules/1\"\n[nonsense]\n"))
    # Schema 5: a log that ends in the middle of a record, or of ULog file format version 2.
    edit("schema5_truncated.sfr", "accept", lambda r: schema5(r, cut=10))
    edit("schema5_ulog_version_2.sfr", "accept", lambda r: schema5(r, version=2))
    edit("schema5_neither.sfr", "reject", lambda r: schema5(r))
    edit("schema5_flag_disagrees.sfr", "reject",
         lambda r: (schema5(r, cut=10), r["seal"].__setitem__("allow_untested_ulog_version", True)))
    edit("schema5_cut_past_size.sfr", "reject",
         lambda r: (schema5(r, cut=10), r["log"]["truncated"].__setitem__("trailing_bytes", "11")))
    edit("schema5_cut_zero_bytes.sfr", "reject",
         lambda r: (schema5(r, cut=10), r["log"]["truncated"].update(
             offset=r["log"]["size"], trailing_bytes="0")))
    edit("schema5_member_missing.sfr", "reject", lambda r: (schema5(r, cut=10), r["log"].pop("ulog_version")))
    edit("schema4_with_truncated.sfr", "reject",
         lambda r: (schema5(r, cut=10), r.__setitem__("schema_version", 4)))
    raw("signature_flipped.sfr", "reject", lambda b: flip_signature(b))
    raw("merkle_root_changed.sfr", "reject", lambda b: b.replace(b'"command":211,', b'"command":311,', 1))
    return out


IGNORE_ALL = 'format = "sfr-rules/1"\n\n[required_topics]\ntopics = []\n\n[parameters]\nignore = ["*"]\n'


def schema5(r, cut=0, version=1):
    """The record as schema 5: the log ends `cut` bytes into an unfinished record (none if 0), and
    its ULog file format version is `version`, flagged when above 1."""
    r["schema_version"] = 5
    size = int(r["log"]["size"])
    r["log"]["truncated"] = None if cut == 0 else {"offset": str(size - cut), "trailing_bytes": str(cut)}
    r["log"]["ulog_version"] = version
    r["seal"]["allow_untested_ulog_version"] = version > 1


def set_rules(r, text):
    r["rules"] = {"text": text, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}


def flip_signature(b):
    r = json.loads(b)
    v = r["signature"]["value"]
    r["signature"]["value"] = v[:-1] + ("0" if v[-1] != "0" else "1")
    return ref.jcs(r).encode("utf-8")


def files():
    out = {"vectors.pub": PEM.encode()}
    expected = {}
    for name, (data, verdict) in vectors().items():
        out[name] = data
        expected[name] = verdict
    out["expected.json"] = (json.dumps(expected, indent=2, sort_keys=True) + "\n").encode()
    return out


def main():
    d = os.path.join(HERE, "vectors")
    want = files()
    if sys.argv[1:] == ["--check"]:
        bad = [n for n, data in sorted(want.items())
               if not os.path.exists(os.path.join(d, n)) or open(os.path.join(d, n), "rb").read() != data]
        bad += sorted(set(os.listdir(d)) - set(want))
        for n in bad:
            print("make_vectors.py --check: vectors/%s differs from the generator" % n)
        return 1 if bad else 0
    os.makedirs(d, exist_ok=True)
    for n, data in want.items():
        with open(os.path.join(d, n), "wb") as f:
            f.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
