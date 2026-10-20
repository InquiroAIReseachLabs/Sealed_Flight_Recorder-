#!/usr/bin/env python3
"""check_format_characters.py: the Unicode format characters `sfr` shows instead of acting on.

crates/sfr-core/src/display.rs lists the code points of Unicode general category Cf (Format) in
FORMAT_CHARACTERS: the bidirectional controls (U+202A to U+202E, U+2066 to U+2069), the
zero-width characters and the rest. The report and every line `sfr` prints show them as
<U+202E> instead of passing them on. This script holds that table to the Unicode database of the
Python that runs it (the `unicodedata` module of the standard library):

  - every code point Python files under Cf is in the table;
  - every code point in the table that Python knows is Cf (a code point a newer Unicode adds is
    unknown to an older Python, and is not an error here).

Usage: scripts/check_format_characters.py [--self-test]
"""

import os
import re
import sys
import unicodedata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(ROOT, "crates", "sfr-core", "src", "display.rs")


def table(source):
    """The (first, last) pairs of FORMAT_CHARACTERS in the Rust source."""
    m = re.search(r"pub const FORMAT_CHARACTERS: \[\(u32, u32\); (\d+)\] = \[(.*?)\n\];", source, re.S)
    if not m:
        raise ValueError("FORMAT_CHARACTERS not found")
    pairs = [(int(a, 16), int(b, 16)) for a, b in re.findall(r"\(0x([0-9A-Fa-f]+), 0x([0-9A-Fa-f]+)\)", m.group(2))]
    if len(pairs) != int(m.group(1)):
        raise ValueError("FORMAT_CHARACTERS declares %s ranges and lists %d" % (m.group(1), len(pairs)))
    return pairs


def problems(pairs, category=lambda cp: unicodedata.category(chr(cp))):
    listed = {cp for a, b in pairs for cp in range(a, b + 1)}
    out = []
    for cp in range(0x110000):
        is_cf = category(cp) == "Cf"
        if is_cf and cp not in listed:
            out.append("U+%04X is Cf in Unicode %s and is not in FORMAT_CHARACTERS" % (cp, unicodedata.unidata_version))
    for cp in sorted(listed):
        c = category(cp)
        if c not in ("Cf", "Cn"):
            out.append("U+%04X is in FORMAT_CHARACTERS and is %s in Unicode %s" % (cp, c, unicodedata.unidata_version))
    return out


def self_test():
    real = table(open(SOURCE, encoding="utf-8").read())
    assert not problems(real), problems(real)[:3]
    # A code point missing from the table is found, and so is one that is not Cf.
    missing = [p for p in real if p != (0x202A, 0x202E)] + [(0x202A, 0x202D)]
    assert any("U+202E" in p for p in problems(missing)), "a missing U+202E must be found"
    extra = real + [(0x0041, 0x0041)]
    assert any("U+0041" in p for p in problems(extra)), "a letter in the table must be found"
    # A synthetic category function: a code point Cf for it and absent from the table is found.
    fake = lambda cp: "Cf" if cp == 0x3000 else "Cn"
    assert any("U+3000" in p for p in problems([], fake))
    print("check_format_characters.py: self-test passed")


def main():
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    pairs = table(open(SOURCE, encoding="utf-8").read())
    found = problems(pairs)
    if found:
        print("check_format_characters.py: FORMAT_CHARACTERS and the Unicode database disagree:", file=sys.stderr)
        for p in found:
            print("  " + p, file=sys.stderr)
        sys.exit(1)
    n = sum(b - a + 1 for a, b in pairs)
    print("PASS: FORMAT_CHARACTERS holds the %d Cf code points of Unicode %s" % (n, unicodedata.unidata_version))


main()
