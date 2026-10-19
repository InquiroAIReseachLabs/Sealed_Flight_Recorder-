#!/usr/bin/env python3
"""Write the segment manifest scripts/benchmark.sh uses to build its large logs (offline tooling,
standard library only; never shipped and never run by benchmark.sh).

usage: make_segments.py <flight.ulg> <repo-relative path of the flight>          print the manifest
       make_segments.py --check <manifest> <flight.ulg> <repo-relative path>     exit 1 if stale

A segment is a run of whole records from the flight's data section (from its first 'A' record to
the end) that holds no 'A', 'I' or 'M' record (subscriptions and info, which may appear once
only), cut at record boundaries into pieces of at most MAX_SEGMENT bytes. benchmark.sh writes one
full copy of the flight, then appends the segments in order, again and again, until the log
reaches the requested size. Every byte comes from the flight; nothing is rewritten, so the
timestamps restart with each repetition.
"""
import hashlib
import struct
import sys

MAX_SEGMENT = 1_000_000
ULOG_MAGIC = b"ULog\x01\x12\x35"


def manifest(path, rel):
    b = open(path, "rb").read()
    if b[:7] != ULOG_MAGIC:
        raise SystemExit(f"{path}: not a ULog file")
    pos, records = 16, []
    while pos + 3 <= len(b):
        size, ty = struct.unpack_from("<HB", b, pos)
        end = pos + 3 + size
        if end > len(b):
            raise SystemExit(f"{path}: truncated record at offset {pos}")
        records.append((pos, chr(ty), end))
        pos = end
    if pos != len(b):
        raise SystemExit(f"{path}: {len(b) - pos} trailing bytes")
    first_a = next(p for p, t, _ in records if t == "A")
    if b[16 + 2] == ord("B") and any(b[16 + 3 + 8:16 + 3 + 16]):
        raise SystemExit(f"{path}: logs with appended data are not supported")
    segments, start, end = [], None, None
    for p, t, e in records:
        if p < first_a:
            continue
        if t in "AIM":
            if start is not None:
                segments.append((start, end - start))
            start = None
            continue
        if t not in "DLCPOS":
            raise SystemExit(f"{path}: record type {t!r} at offset {p} in the data section")
        if start is not None and e - start > MAX_SEGMENT:
            segments.append((start, end - start))
            start = None
        if start is None:
            start = p
        end = e
    if start is not None:
        segments.append((start, end - start))
    lines = [
        "# Segments of the golden VTOL flight that scripts/benchmark.sh repeats to build its large",
        "# logs. Written by scripts/benchmark/make_segments.py; do not edit by hand.",
        "# segment <offset> <length>: whole records of the data section, no 'A', 'I' or 'M' record.",
        f"source {rel}",
        f"sha256 {hashlib.sha256(b).hexdigest()}",
        f"size {len(b)}",
    ]
    lines += [f"segment {o} {n}" for o, n in segments]
    return "\n".join(lines) + "\n"


def main():
    if sys.argv[1:2] == ["--check"]:
        _, _, committed, path, rel = sys.argv
        if open(committed).read() != manifest(path, rel):
            raise SystemExit(f"{committed} is stale: rerun scripts/benchmark/make_segments.py")
        print(f"{committed}: up to date")
    else:
        _, path, rel = sys.argv
        sys.stdout.write(manifest(path, rel))


if __name__ == "__main__":
    main()
