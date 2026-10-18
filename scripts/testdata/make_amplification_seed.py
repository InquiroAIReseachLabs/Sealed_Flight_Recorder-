#!/usr/bin/env python3
"""Writes the subscription-amplification regression log (standard library only).

One `failsafe_flags` format with 256 bool flags whose flattened names are 250 to 255 bytes,
subscribed 3,891 times (999,987 flattened fields, under the 1,000,000 limit), then one small
topic with one data record. Before each format was flattened once and shared, this 78 KB log
made `sfr` hold about 1.6 GB. It is a fuzz seed (fuzz/seeds/ulog_ingest/) and the input of
the regression tests in crates/sfr-core/src/ulog.rs and ingest.rs.

usage: make_amplification_seed.py <out.ulg>
"""
import struct
import sys

MAGIC = b"ULog\x01\x12\x35"


def rec(ty, body):
    return struct.pack("<HB", len(body), ord(ty)) + body


def main():
    out = MAGIC + bytes([1]) + struct.pack("<Q", 0)
    out += rec("B", bytes(16) + struct.pack("<QQQ", 0, 0, 0))
    out += rec("F", b"tiny:uint64_t timestamp;")
    out += rec("F", ("failsafe_flags:uint64_t timestamp;bool[256] " + "f" * 250 + ";").encode())
    for i in range(1_000_000 // 257):
        out += rec("A", struct.pack("<BH", i % 256, i) + b"failsafe_flags")
    out += rec("A", struct.pack("<BH", 0, 65535) + b"tiny")
    out += rec("D", struct.pack("<H", 65535) + struct.pack("<Q", 1000))
    with open(sys.argv[1], "wb") as f:
        f.write(out)


if __name__ == "__main__":
    main()
