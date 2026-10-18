#!/usr/bin/env python3
"""Write a QGroundControl .params file of a ULog's initial parameters.

Usage: python3 -I make_baseline.py <log.ulg> <out.params>

Initial parameters are pyulog's `initial_parameters` (the definitions-section
'P' records). The type column comes from the 'P' record key type
("int32_t NAME" -> 6, "float NAME" -> 9), captured while pyulog parses.
"""

import os
import sys

from pyulog import ULog

P_TYPE = ord('P')
TYPE_CODE = {'int32_t': 6, 'float': 9}


class _TypedULog(ULog):
    """ULog that remembers the key type of each definitions-section 'P'."""

    def __init__(self, path):
        self._sfr_in_data = False
        self._sfr_types = {}
        self._MessageInfo = self._sfr_info
        super().__init__(path)

    def _read_file_data(self, message_name_filter_list, read_until=None):
        self._sfr_in_data = True
        return super()._read_file_data(message_name_filter_list, read_until)

    def _sfr_info(self, data, header, is_info_multiple=False):
        info = ULog._MessageInfo(data, header, is_info_multiple)
        if header.msg_type == P_TYPE and not self._sfr_in_data:
            self._sfr_types[info.key] = info.type
        return info


def decode_release(v):
    v = int(v)
    major, minor, patch, typ = (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff
    s = "%d.%d.%d" % (major, minor, patch)
    if typ == 255:
        return s
    if typ >= 192:
        return s + "-rc"
    if typ >= 128:
        return s + "-beta"
    if typ >= 64:
        return s + "-alpha"
    return s + "-dev"


def main():
    if len(sys.argv) != 3:
        sys.stderr.write("usage: make_baseline.py <log.ulg> <out.params>\n")
        return 2
    log_path, out_path = sys.argv[1], sys.argv[2]
    u = _TypedULog(log_path)
    info = u.msg_info_dict
    params = u.initial_parameters
    lines = []
    lines.append("# Onboard parameters for Vehicle 1")
    lines.append("#")
    lines.append("# Initial parameters of %s (definitions-section 'P' records)" % os.path.basename(log_path))
    # sfr requires exactly one Firmware line (SPEC B1.6). A log without ver_sw_release gets
    # the version "unknown", which R2 reports as a mismatch.
    fw = decode_release(info['ver_sw_release']) if 'ver_sw_release' in info else "unknown"
    if info.get('ver_sw'):
        fw += " " + info['ver_sw']
    lines.append("# Firmware: " + fw)
    lines.append("#")
    lines.append("# Vehicle-Id Component-Id Name Value Type")
    for name in sorted(params):
        key_type = u._sfr_types.get(name)
        if key_type not in TYPE_CODE:
            raise SystemExit("parameter %s has unsupported type %r" % (name, key_type))
        value = params[name]
        if key_type == 'int32_t':
            vs = str(int(value))
        else:
            vs = repr(float(value))
        lines.append("1\t1\t%s\t%s\t%d" % (name, vs, TYPE_CODE[key_type]))
    with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
        f.write("\n".join(lines) + "\n")
    return 0


if __name__ == '__main__':
    sys.exit(main())
