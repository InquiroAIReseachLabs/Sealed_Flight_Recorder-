#!/usr/bin/env python3
"""sfr_ref_verify.py: a reference verifier for Sealed Flight Record files, schema 4.

Written from docs/RECORD_FORMAT.md alone; it imports nothing from sfr and needs only the Python
3.11+ standard library (Ed25519 is implemented here from RFC 8032).

  sfr_ref_verify.py <record.sfr> <sfr.pub>     prints VERIFIED (exit 0) or FAILED: <reason> (exit 1)
  sfr_ref_verify.py --self-test                runs the test vectors in vectors/ (exit 1 on a miss)

What it checks (the standalone checks of RECORD_FORMAT.md, "What a verifier checks"):
  - the size limit; strict JSON: UTF-8 without a byte order mark, no duplicate key, no
    floating-point number, NaN or infinity, integers within +-(2^53 - 1) and never -0, no
    unpaired surrogate, nesting at most 64 levels;
  - the bytes are exactly their RFC 8785 canonical form;
  - schema_version 4, exactly the thirteen top-level fields, the member types;
  - results: R1 to R7 exactly once each, other ids only X1 to X5, strictly increasing rule-id
    order, every status PASS, WARN, FAIL or N/A; the overall status equals the one the results
    give; sealed topics and events in order;
  - the rules digest; seal.allow_untested_version and seal.allow_ignore_all are booleans, and
    allow_ignore_all is true exactly when the embedded rules file ignores every parameter;
  - the custody value; certificates null or base64;
  - the Merkle root, leaf count and section counts recomputed from the leaves;
  - the key fingerprint against the given public key, and the Ed25519 signature over the signed
    payload, strictly: canonical point and scalar encodings, and no small-order key or R.

What it does NOT check, so a record it accepts may still be one sfr refuses:
  - certificate chains, extended key usage and CRLs (sfr verify --trust-anchor);
  - the custody policy: it reports custody and accepts an evaluation key, which sfr refuses
    without --allow-evaluation-key;
  - the report (.sfr.md) against the record;
  - the log: it never re-reads a log or runs the rules again (sfr verify --ulog does);
  - the rules file beyond its TOML syntax and its ignore list (sfr also refuses unknown keys
    and the other errors docs/RULES.md lists);
  - the contents of `log`, `config`, `baseline`, events and results beyond their digests and
    the checks above.
"""
import base64
import hashlib
import json
import os
import re
import sys
import tomllib

MAX_RECORD_BYTES = 512 * 1024 * 1024
MAX_DEPTH = 64
MAX_SAFE = 2 ** 53 - 1
FIELDS = {"schema_version", "tool", "seal", "log", "config", "baseline", "rules", "results",
          "sealed_topics", "events", "status", "merkle", "signature"}
CORE = ["R1", "R2", "R3", "R4", "R5", "R6", "R7"]
OPTIONAL = ["X1", "X2", "X3", "X4", "X5"]
STATUSES = {"PASS", "WARN", "FAIL", "N/A"}
OVERALL = {"PASS", "WARN", "FAIL", "NO ARMED FLIGHT"}
CUSTODY = {"pkcs11-token", "tpm-sealed", "file-evaluation"}
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class Bad(Exception):
    pass


# ----------------------------------------------------------------------------------------------
# Strict JSON parser for the record's value subset


class Parser:
    def __init__(self, b):
        self.b, self.i = b, 0

    def fail(self, why):
        raise Bad("not valid JSON at byte offset %d: %s" % (self.i, why))

    def ws(self):
        while self.i < len(self.b) and self.b[self.i] in b" \t\n\r":
            self.i += 1

    def value(self, depth):
        self.ws()
        c = self.b[self.i:self.i + 1]
        if c in (b"[", b"{") and depth >= MAX_DEPTH:
            self.fail("nesting deeper than %d levels" % MAX_DEPTH)
        if c == b"{":
            self.i += 1
            out = {}
            self.ws()
            if self.b[self.i:self.i + 1] == b"}":
                self.i += 1
                return out
            while True:
                self.ws()
                if self.b[self.i:self.i + 1] != b'"':
                    self.fail("expected a key")
                k = self.string()
                if k in out:
                    self.fail("duplicate key %r" % k)
                self.ws()
                if self.b[self.i:self.i + 1] != b":":
                    self.fail("expected ':'")
                self.i += 1
                out[k] = self.value(depth + 1)
                self.ws()
                c = self.b[self.i:self.i + 1]
                self.i += 1
                if c == b"}":
                    return out
                if c != b",":
                    self.fail("expected ',' or '}'")
        if c == b"[":
            self.i += 1
            out = []
            self.ws()
            if self.b[self.i:self.i + 1] == b"]":
                self.i += 1
                return out
            while True:
                out.append(self.value(depth + 1))
                self.ws()
                c = self.b[self.i:self.i + 1]
                self.i += 1
                if c == b"]":
                    return out
                if c != b",":
                    self.fail("expected ',' or ']'")
        if c == b'"':
            return self.string()
        for lit, v in ((b"true", True), (b"false", False), (b"null", None)):
            if self.b.startswith(lit, self.i):
                self.i += len(lit)
                return v
        m = re.compile(rb"-?(0|[1-9][0-9]*)").match(self.b, self.i)
        if not m:
            self.fail("unexpected character")
        if self.b[m.end():m.end() + 1] in (b".", b"e", b"E"):
            self.fail("floating-point number")
        text = m.group(0)
        n = int(text)
        if text == b"-0" or abs(n) > MAX_SAFE:
            self.fail("integer %s outside the safe range or -0" % text.decode())
        self.i = m.end()
        return n

    def string(self):
        self.i += 1
        out = []
        while True:
            if self.i >= len(self.b):
                self.fail("unterminated string")
            c = self.b[self.i]
            if c == 0x22:
                self.i += 1
                return "".join(out)
            if c < 0x20:
                self.fail("control character in a string")
            if c == 0x5C:
                e = self.b[self.i + 1:self.i + 2]
                self.i += 2
                simple = {b'"': '"', b"\\": "\\", b"/": "/", b"b": "\b", b"f": "\f", b"n": "\n",
                          b"r": "\r", b"t": "\t"}
                if e in simple:
                    out.append(simple[e])
                elif e == b"u":
                    hi = self.hex4()
                    if 0xD800 <= hi < 0xDC00:
                        if self.b[self.i:self.i + 2] != b"\\u":
                            self.fail("unpaired surrogate")
                        self.i += 2
                        lo = self.hex4()
                        if not 0xDC00 <= lo < 0xE000:
                            self.fail("unpaired surrogate")
                        out.append(chr(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)))
                    elif 0xDC00 <= hi < 0xE000:
                        self.fail("unpaired surrogate")
                    else:
                        out.append(chr(hi))
                else:
                    self.fail("bad escape")
                continue
            j = self.i
            while j < len(self.b) and self.b[j] not in (0x22, 0x5C) and self.b[j] >= 0x20:
                j += 1
            try:
                out.append(self.b[self.i:j].decode("utf-8"))
            except UnicodeDecodeError:
                self.fail("invalid UTF-8")
            self.i = j

    def hex4(self):
        h = self.b[self.i:self.i + 4]
        if not re.fullmatch(rb"[0-9a-fA-F]{4}", h):
            self.fail("bad \\u escape")
        self.i += 4
        return int(h, 16)


def parse(b):
    p = Parser(b)
    v = p.value(0)
    p.ws()
    if p.i != len(b):
        p.fail("data after the value")
    return v


# ----------------------------------------------------------------------------------------------
# RFC 8785 canonical form of the subset, and the RFC 6962 Merkle tree


def quote(s):
    esc = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    return '"' + "".join(esc.get(c) or ("\\u%04x" % ord(c) if ord(c) < 0x20 else c) for c in s) + '"'


def jcs(v):
    if v is None or isinstance(v, bool):
        return {None: "null", True: "true", False: "false"}[v]
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return quote(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
    return "{" + ",".join(quote(k) + ":" + jcs(v[k]) for k in keys) + "}"


def sha256(b):
    return hashlib.sha256(b).digest()


def mth(h):
    if len(h) == 1:
        return h[0]
    k = 1
    while k * 2 < len(h):
        k *= 2
    return sha256(b"\x01" + mth(h[:k]) + mth(h[k:]))


# ----------------------------------------------------------------------------------------------
# Ed25519 (RFC 8032 section 5.1), strict verification

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
G = (15112221349535400772501151409588531511454012693041857206046113283949847762202,
     46316835694926478169428394003475163141307993866256225615783033603165251855960, 1,
     15112221349535400772501151409588531511454012693041857206046113283949847762202
     * 46316835694926478169428394003475163141307993866256225615783033603165251855960 % P)
IDENTITY = (0, 1, 1, 0)


def add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def mul(s, p):
    q = IDENTITY
    while s > 0:
        if s & 1:
            q = add(q, p)
        p = add(p, p)
        s >>= 1
    return q


def equal(p, q):
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


def encode(p):
    zi = pow(p[2], P - 2, P)
    x, y = p[0] * zi % P, p[1] * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def decode(s):
    """A point from its 32-byte encoding, or None when the encoding is not canonical."""
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        if sign:
            return None
        x = 0
    else:
        x = pow(x2, (P + 3) // 8, P)
        if (x * x - x2) % P != 0:
            x = x * SQRT_M1 % P
        if (x * x - x2) % P != 0:
            return None
        if (x & 1) != sign:
            x = P - x
    return (x, y, 1, x * y % P)


def small_order(p):
    return equal(mul(8, p), IDENTITY)


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a, r = decode(public), decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= L or small_order(a) or small_order(r):
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % L
    return equal(mul(s, G), add(r, mul(k, a)))


def ed25519_public(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return encode(mul(a, G))


def ed25519_sign(seed, message):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    public = encode(mul(a, G))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % L
    big_r = encode(mul(r, G))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % L
    return big_r + int.to_bytes((r + k * a) % L, 32, "little")


# ----------------------------------------------------------------------------------------------
# The record


def public_key_from_pem(text):
    body = "".join(l for l in text.strip().splitlines() if not l.startswith("-----"))
    der = base64.b64decode(body, validate=True)
    if not (text.strip().startswith("-----BEGIN PUBLIC KEY-----") and len(der) == 44
            and der.startswith(SPKI_PREFIX)):
        raise Bad("the public key is not a PEM Ed25519 SubjectPublicKeyInfo")
    return der[12:], der


def rule_key(rid):
    m = re.fullmatch(r"([A-Z])([1-9][0-9]*)", rid) if isinstance(rid, str) else None
    return (m.group(1), int(m.group(2))) if m else None


def overall(results):
    st = [(r.get("id"), r.get("status")) for r in results]
    if any(s == "FAIL" for _, s in st):
        return "FAIL"
    if ("R5", "N/A") in st:
        return "NO ARMED FLIGHT"
    if any(s == "WARN" for _, s in st):
        return "WARN"
    return "PASS"


def leaves(r):
    context = {"schema_version": r["schema_version"], "tool": r["tool"], "seal": r["seal"]}
    return [("seal_context", 1, [context]), ("log", 2, [r["log"]]), ("config", 3, [r["config"]]),
            ("baseline", 4, [r["baseline"]]), ("rules", 5, [r["rules"]]),
            ("results", 6, r["results"]), ("sealed_topics", 7, r["sealed_topics"]),
            ("events", 8, r["events"])]


def signed_payload(schema, sections, root):
    counts = [len(xs) for _, _, xs in sections]
    out = b"SFR-RECORD-V1\x00" + schema.to_bytes(4, "big") + sum(counts).to_bytes(8, "big")
    for c in counts:
        out += c.to_bytes(8, "big")
    return out + root


def check(raw, pem):
    """None when the record verifies under the key, else the first problem."""
    if len(raw) > MAX_RECORD_BYTES:
        raise Bad("the record is larger than %d bytes" % MAX_RECORD_BYTES)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise Bad("the record starts with a byte order mark")
    r = parse(raw)
    if not isinstance(r, dict):
        raise Bad("the record is not an object")
    if r.get("schema_version") != 4 or isinstance(r.get("schema_version"), bool):
        raise Bad("unknown schema_version %s; this verifier knows schema 4 only"
                  % jcs(r.get("schema_version")) if "schema_version" in r else "no schema_version")
    if jcs(r).encode("utf-8") != raw:
        raise Bad("the record is not in canonical form (RFC 8785)")
    if set(r) != FIELDS:
        raise Bad("the fields differ from the schema: %s" % sorted(set(r) ^ FIELDS))
    obj = lambda v, *ks: isinstance(v, dict) and all(k in v for k in ks)
    string = lambda v: isinstance(v, str)
    if not (all(isinstance(r[k], dict) for k in ("tool", "seal", "log", "config", "baseline",
                                                    "rules", "merkle", "signature"))
            and all(isinstance(r[k], list) for k in ("results", "sealed_topics", "events"))
            and string(r["status"])):
        raise Bad("a top-level field has the wrong type")
    seal = r["seal"]
    if not (obj(seal, "key_custody", "key_fingerprint", "time_utc", "crypto_crates")
            and all(string(seal[k]) for k in ("key_custody", "key_fingerprint", "time_utc"))
            and isinstance(seal["crypto_crates"], list)
            and all(obj(c, "name", "version") and string(c["name"]) and string(c["version"])
                    for c in seal["crypto_crates"])):
        raise Bad("a seal member is missing or of the wrong type")
    # Results as a set, and their order.
    for i, x in enumerate(r["results"]):
        if not (obj(x, "id", "status") and string(x["id"])):
            raise Bad("result %d is not an object with a string id and a status" % i)
        if not string(x["status"]) or x["status"] not in STATUSES:
            raise Bad("result %s has status %s, not PASS, WARN, FAIL or N/A" % (x["id"], jcs(x["status"])))
        if x["id"] not in CORE and x["id"] not in OPTIONAL:
            raise Bad("result %s is not a rule sfr has" % x["id"])
    ids = [x["id"] for x in r["results"]]
    missing = [c for c in CORE if ids.count(c) != 1]
    if missing:
        raise Bad("results lack %s, or hold it more than once" % ", ".join(missing))
    keys = [rule_key(i) for i in ids]
    if any(b <= a for a, b in zip(keys, keys[1:])):
        raise Bad("results are not in strictly increasing rule-id order")
    if r["status"] not in OVERALL:  # a string: checked with the top-level types
        raise Bad("status %s is not PASS, WARN, FAIL or NO ARMED FLIGHT" % jcs(r["status"]))
    if r["status"] != overall(r["results"]):
        raise Bad("status is %s but the results say %s" % (r["status"], overall(r["results"])))
    topics = []
    for t in r["sealed_topics"]:
        if not (obj(t, "topic", "multi_id") and string(t["topic"]) and type(t["multi_id"]) is int):
            raise Bad("a sealed topic has no topic and multi_id")
        topics.append((t["topic"].encode("utf-8"), t["multi_id"]))
    if any(b <= a for a, b in zip(topics, topics[1:])):
        raise Bad("sealed topics are not in strictly increasing topic and multi_id order")
    if [e.get("seq") if isinstance(e, dict) else None for e in r["events"]] != list(range(len(r["events"]))):
        raise Bad("events are not in sequence order")
    # Rules digest and the ignore-everything flag.
    rules = r["rules"]
    if not (obj(rules, "text", "sha256") and string(rules["text"]) and string(rules["sha256"])
            and rules["sha256"] == sha256(rules["text"].encode("utf-8")).hex()):
        raise Bad("rules.sha256 does not match rules.text")
    for k in ("allow_untested_version", "allow_ignore_all"):
        if not isinstance(seal.get(k), bool):
            raise Bad("seal.%s must be a boolean" % k)
    try:
        ignore = tomllib.loads(rules["text"]).get("parameters", {}).get("ignore", [])
    except tomllib.TOMLDecodeError:
        raise Bad("the embedded rules file does not parse")
    if any(isinstance(p, str) and p and set(p) == {"*"} for p in ignore) != seal["allow_ignore_all"]:
        raise Bad("seal.allow_ignore_all disagrees with the embedded rules file")
    if seal["key_custody"] not in CUSTODY:
        raise Bad("unknown key custody %r" % seal["key_custody"])
    for k in ("signer_certificate",):
        v = seal.get(k)
        if v is not None and not (string(v) and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", v)):
            raise Bad("seal.%s must be null or base64" % k)
    chain = seal.get("certificate_chain")
    if chain is not None and not (isinstance(chain, list) and chain and seal.get("signer_certificate")
                                  and all(string(c) for c in chain)):
        raise Bad("seal.certificate_chain must be null or a non-empty array beside a signer certificate")
    # Merkle tree.
    sections = leaves(r)
    hashes = [sha256(b"\x00" + bytes([tag]) + jcs(x).encode("utf-8")) for _, tag, xs in sections for x in xs]
    root = mth(hashes)
    want = {"algorithm": "sha256-rfc6962", "leaf_count": len(hashes), "root": root.hex(),
            "sections": {name: len(xs) for name, _, xs in sections}}
    if r["merkle"] != want:
        raise Bad("merkle differs from the leaves: root %s over %d leaves" % (root.hex(), len(hashes)))
    # Key and signature.
    public, der = public_key_from_pem(pem)
    if seal["key_fingerprint"] != "sha256:" + sha256(der).hex():
        raise Bad("signed by key %s, not by the given public key" % seal["key_fingerprint"])
    sig = r["signature"]
    if set(sig) != {"algorithm", "value"} or sig["algorithm"] != "ed25519" \
            or not (string(sig["value"]) and re.fullmatch(r"[0-9a-f]{128}", sig["value"])):
        raise Bad("signature must hold exactly algorithm ed25519 and 128 lowercase hex digits")
    if not ed25519_verify(public, signed_payload(4, sections, root), bytes.fromhex(sig["value"])):
        raise Bad("signature does not verify")
    return None


def verify(raw, pem):
    try:
        check(raw, pem)
        return "VERIFIED"
    except Bad as e:
        return "FAILED: %s" % e
    except (ValueError, RecursionError) as e:
        return "FAILED: %s" % e


def self_test():
    here = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")
    with open(os.path.join(here, "expected.json"), encoding="utf-8") as f:
        expected = json.load(f)
    pem = open(os.path.join(here, "vectors.pub"), encoding="utf-8").read()
    bad = 0
    for name, want in sorted(expected.items()):
        if isinstance(want, dict):
            want = want["reference"]
        got = verify(open(os.path.join(here, name), "rb").read(), pem)
        ok = got.startswith("VERIFIED") == (want == "accept")
        bad += not ok
        print("%s %s: expected %s, %s" % ("ok" if ok else "MISS", name, want, got))
    # RFC 8032 section 7.1, test 1 and test 3.
    for seed, msg, sig in (
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a")):
        s = bytes.fromhex(seed)
        good = ed25519_sign(s, bytes.fromhex(msg)).hex() == sig and \
            ed25519_verify(ed25519_public(s), bytes.fromhex(msg), bytes.fromhex(sig))
        bad += not good
        print("%s RFC 8032 vector %s" % ("ok" if good else "MISS", seed[:8]))
    print("%d miss(es)" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a == ["--self-test"]:
        sys.exit(self_test())
    if len(a) != 2:
        sys.exit(__doc__)
    result = verify(open(a[0], "rb").read(), open(a[1], encoding="utf-8").read())
    print(result)
    sys.exit(0 if result == "VERIFIED" else 1)
