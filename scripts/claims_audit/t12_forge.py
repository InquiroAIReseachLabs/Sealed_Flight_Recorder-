#!/usr/bin/env python3
"""t12_forge.py: edit a record and sign it again, as the holder of its signing key could.

Independent of sfr: canonical JSON (RFC 8785 subset), the RFC 6962 Merkle tree and the signed
payload are written from docs/RECORD_FORMAT.md, and OpenSSL makes the Ed25519 signature. Reads
schemas 2 to 4 (schema 2: leaves untagged, payload of root only; schemas 3 and 4: tagged leaves,
tree shape in the payload and in merkle.sections).

  t12_forge.py resign <record.sfr> <key.pem> <out.sfr> [--set dotted.path=<json value>]...
  t12_forge.py move-leaf <record.sfr> <out.sfr>
      moves the last element of `results` to the front of `sealed_topics` and signs nothing
"""
import hashlib, json, struct, subprocess, sys, tempfile


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


def sign(key_pem, payload):
    with tempfile.TemporaryDirectory() as d:
        open(d + "/p", "wb").write(payload)
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key_pem, "-rawin", "-in", d + "/p",
                        "-out", d + "/s"], check=True, capture_output=True)
        return open(d + "/s", "rb").read()


SECTIONS = ["seal_context", "log", "config", "baseline", "rules", "results", "sealed_topics", "events"]


def tree(r):
    """(leaves as (tag, object), section counts) in the record's order."""
    context = {"schema_version": r["schema_version"], "tool": r["tool"], "seal": r["seal"]}
    groups = [[context], [r["log"]], [r["config"]], [r["baseline"]], [r["rules"]],
              r["results"], r["sealed_topics"], r["events"]]
    leaves = [(i + 1, x) for i, g in enumerate(groups) for x in g]
    return leaves, [len(g) for g in groups]


def resign(record_bytes, key_pem, sets):
    r = json.loads(record_bytes.decode("utf-8"))
    for path, value in sets:
        node = r
        *parents, last = path.split(".")
        for p in parents:
            node = node[p]
        node[last] = value
    schema = r["schema_version"]
    leaves, counts = tree(r)
    if schema == 2:
        hashes = [sha256(b"\x00" + jcs(x).encode("utf-8")) for _, x in leaves]
        root = mth(hashes)
        r["merkle"] = {"algorithm": "sha256-rfc6962", "leaf_count": len(leaves), "root": root.hex()}
        payload = b"SFR-RECORD-V1\x00" + struct.pack(">I", 2) + root
    elif schema in (3, 4):
        hashes = [sha256(b"\x00" + bytes([t]) + jcs(x).encode("utf-8")) for t, x in leaves]
        root = mth(hashes)
        r["merkle"] = {"algorithm": "sha256-rfc6962", "leaf_count": len(leaves), "root": root.hex(),
                       "sections": dict(zip(SECTIONS, counts))}
        payload = (b"SFR-RECORD-V1\x00" + struct.pack(">I", 3) + struct.pack(">Q", len(leaves))
                   + b"".join(struct.pack(">Q", c) for c in counts) + root)
    else:
        sys.exit("t12_forge.py: schema %r is not supported" % schema)
    r["signature"] = {"algorithm": "ed25519", "value": sign(key_pem, payload).hex()}
    return jcs(r).encode("utf-8")


def move_leaf(record_bytes):
    r = json.loads(record_bytes.decode("utf-8"))
    r["sealed_topics"].insert(0, r["results"].pop())
    return jcs(r).encode("utf-8")


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["resign"]:
        rec, key, out, rest = a[1], a[2], a[3], a[4:]
        sets = []
        while rest:
            if rest[0] != "--set":
                sys.exit("usage: t12_forge.py resign <record> <key.pem> <out> [--set path=json]...")
            path, _, value = rest[1].partition("=")
            sets.append((path, json.loads(value)))
            rest = rest[2:]
        open(out, "wb").write(resign(open(rec, "rb").read(), key, sets))
    elif a[:1] == ["move-leaf"]:
        open(a[2], "wb").write(move_leaf(open(a[1], "rb").read()))
    else:
        sys.exit(__doc__)
