#!/usr/bin/env python3
"""Build a large ULog for benchmarks by repeating a real SITL flight (standard library only).

usage: make_large_log.py <flight.ulg> <out.ulg> <size in MB (10^6 bytes)>

The output is the flight's header and definitions section, then its data section repeated
until the file reaches the requested size. Each repetition after the first shifts every
timestamp forward by the flight's time span plus one second: the timestamp field of each data
record (at the offset its format gives it) and the timestamp of each logged string record.
Subscription and info records are written once, in the first repetition. Every other record
is copied unchanged. The result reads as one long log of back-to-back flights, so the reader,
event builder, and rules do the same work per byte as on the real flight.
"""
import struct
import sys

SIZES = {"int8_t": 1, "uint8_t": 1, "bool": 1, "char": 1, "int16_t": 2, "uint16_t": 2,
         "int32_t": 4, "uint32_t": 4, "float": 4, "int64_t": 8, "uint64_t": 8, "double": 8}


def records(b, pos):
    while pos + 3 <= len(b):
        size, ty = struct.unpack_from("<HB", b, pos)
        end = pos + 3 + size
        if end > len(b):
            return
        yield pos, chr(ty), b[pos + 3:end]
        pos = end


def type_size(t, formats):
    base, _, count = t.partition("[")
    n = int(count.rstrip("]")) if count else 1
    if base in SIZES:
        return SIZES[base] * n
    return sum(type_size(ft, formats) for ft, _ in formats[base]) * n


def timestamp_offset(name, formats):
    off = 0
    for ft, fname in formats[name]:
        if fname == "timestamp":
            return off
        off += type_size(ft, formats)
    raise SystemExit(f"format {name} has no timestamp field")


def main():
    src, out, mb = sys.argv[1], sys.argv[2], int(sys.argv[3])
    target = mb * 1_000_000
    b = open(src, "rb").read()
    if b[16 + 2] == ord("B") and any(b[16 + 3 + 8:16 + 3 + 16]):
        raise SystemExit("logs with appended data are not supported")
    formats, ts_off, first_a = {}, {}, None
    lo, hi = None, None
    for pos, ty, body in records(b, 16):
        if ty == "F":
            name, fields = body.decode().split(":", 1)
            formats[name] = [tuple(f.split(" ", 1)) for f in fields.split(";") if f]
        elif ty == "A":
            first_a = pos if first_a is None else first_a
            ts_off[struct.unpack_from("<H", body, 1)[0]] = timestamp_offset(body[3:].decode(), formats)
        elif ty == "D":
            msg_id = struct.unpack_from("<H", body, 0)[0]
            t = struct.unpack_from("<Q", body, 2 + ts_off[msg_id])[0]
            lo, hi = (t if lo is None else min(lo, t)), (t if hi is None else max(hi, t))
    span = hi - lo + 1_000_000
    head, data = b[:first_a], b[first_a:]
    with open(out, "wb") as f:
        f.write(head)
        written, rep = len(head), 0
        while written < target:
            shift = rep * span
            chunk = bytearray()
            for _, ty, body in records(data, 0):
                if rep and ty in "AIM":
                    continue
                body = bytearray(body)
                if ty == "D":
                    at = 2 + ts_off[struct.unpack_from("<H", body, 0)[0]]
                    struct.pack_into("<Q", body, at, struct.unpack_from("<Q", body, at)[0] + shift)
                elif ty == "L":
                    struct.pack_into("<Q", body, 1, struct.unpack_from("<Q", body, 1)[0] + shift)
                elif ty == "C":
                    struct.pack_into("<Q", body, 3, struct.unpack_from("<Q", body, 3)[0] + shift)
                chunk += struct.pack("<HB", len(body), ord(ty)) + body
                if written + len(chunk) >= target:
                    break
            f.write(chunk)
            written += len(chunk)
            rep += 1
    print(f"{out}: {written} bytes, {rep} repetition(s) of {src}")


if __name__ == "__main__":
    main()
