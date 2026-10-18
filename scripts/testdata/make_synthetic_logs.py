#!/usr/bin/env python3
"""Writes the synthetic golden logs under testdata/synthetic/ (standard library only).

r4_quadchute_on_disarm.ulg: a VTOL that arms, transitions to fixed wing, and on the
vehicle_status sample that disarms is already multicopter again (a quadchute on the
disarming sample, which R4 counts, SPEC B1.6). It then arms again, transitions to fixed
wing, disarms in fixed wing, and goes multicopter on the next, disarmed sample (a quadchute
after disarm, which R4 does not count). vehicle_status.failsafe is never set, so R4 fails on
the first quadchute alone.

custom_detection.ulg (Change Order 01): a multicopter flight that logs a topic PX4 does not
define, custom_detection, with a nested type (detection_box), in three instances: instance 0
with five messages, instance 1 with two, and instance 2 subscribed with none. A rules file that
lists it in [sealed_topics] seals it without knowing its structure.

usage: make_synthetic_logs.py <out dir>
"""
import os
import struct
import sys

MAGIC = b"ULog\x01\x12\x35"
VS = ("vehicle_status:uint64_t timestamp;uint8_t arming_state;uint8_t nav_state;bool failsafe;"
      "bool is_vtol;bool in_transition_mode;bool in_transition_to_fw;uint8_t vehicle_type;"
      "uint8_t system_type;uint8_t latest_arming_reason;uint8_t latest_disarming_reason;")
FS = "failsafe_flags:uint64_t timestamp;bool vtol_fixed_wing_system_failure;"


def rec(ty, body):
    return struct.pack("<HB", len(body), ord(ty)) + body


def info(key, value):
    k = key.encode()
    return rec("I", bytes([len(k)]) + k + value)


def param_i(name, v):
    k = ("int32_t " + name).encode()
    return rec("P", bytes([len(k)]) + k + struct.pack("<i", v))


def data(msg_id, payload):
    return rec("D", struct.pack("<H", msg_id) + payload)


def vs(ts, armed, in_tr, to_fw, fw):
    # arming_state 2 armed, 1 standby; nav_state 4 (AUTO_LOITER); vehicle_type 2 fixed wing,
    # 1 rotary wing; system_type 22 (standard VTOL); reasons 3 (internal) and 6 (land).
    return struct.pack("<QBBBBBBBBBB", ts, 2 if armed else 1, 4, 0, 1, in_tr, to_fw,
                       2 if fw else 1, 22, 3, 6)


def r4_quadchute_on_disarm():
    out = MAGIC + bytes([1]) + struct.pack("<Q", 0)
    out += rec("B", bytes(16) + struct.pack("<QQQ", 0, 0, 0))
    out += info("char[40] ver_sw", b"d6f12ad1c4f70ad3230afd7d86e971421e02fef4")
    out += info("uint32_t ver_sw_release", struct.pack("<I", 0x011100FF))
    out += rec("F", VS.encode()) + rec("F", FS.encode())
    out += param_i("SYS_AUTOSTART", 10043) + param_i("COM_DISARM_LAND", 2)
    out += rec("A", struct.pack("<BH", 0, 0) + b"vehicle_status")
    out += rec("A", struct.pack("<BH", 0, 1) + b"failsafe_flags")
    s = 1_000_000
    rows = [
        (1 * s, False, 0, 0, False),
        (2 * s, True, 0, 0, False),   # ARM
        (3 * s, True, 1, 1, False),   # START to fixed wing
        (4 * s, True, 0, 0, True),    # END: fixed wing
        (5 * s, False, 0, 0, False),  # DISARM and multicopter: quadchute on the disarming sample
        (6 * s, False, 0, 0, False),
        (7 * s, True, 0, 0, False),   # ARM
        (8 * s, True, 1, 1, False),   # START to fixed wing
        (9 * s, True, 0, 0, True),    # END: fixed wing
        (10 * s, False, 0, 0, True),  # DISARM, still fixed wing
        (11 * s, False, 0, 0, False), # multicopter while disarmed: quadchute after disarm
        (12 * s, False, 0, 0, False),
    ]
    for ts, armed, in_tr, to_fw, fw in rows:
        out += data(1, struct.pack("<QB", ts, 0))
        out += data(0, vs(ts, armed, in_tr, to_fw, fw))
    return out


BOX = "detection_box:float x;float y;float w;float h;"
DET = "custom_detection:uint64_t timestamp;uint32_t class_id;float confidence;detection_box box;"


def mc_vs(ts, armed):
    # A multicopter (vehicle_type 1, system_type 2 quadrotor), never VTOL, never in failsafe.
    return struct.pack("<QBBBBBBBBBB", ts, 2 if armed else 1, 4, 0, 0, 0, 0, 1, 2, 3, 6)


def detection(ts, class_id, confidence, x, y, w, h):
    return struct.pack("<QIf4f", ts, class_id, confidence, x, y, w, h)


def custom_detection():
    out = MAGIC + bytes([1]) + struct.pack("<Q", 0)
    out += rec("B", bytes(16) + struct.pack("<QQQ", 0, 0, 0))
    out += info("char[40] ver_sw", b"d6f12ad1c4f70ad3230afd7d86e971421e02fef4")
    out += info("uint32_t ver_sw_release", struct.pack("<I", 0x011100FF))
    out += rec("F", VS.encode()) + rec("F", FS.encode())
    out += rec("F", BOX.encode()) + rec("F", DET.encode())
    out += param_i("SYS_AUTOSTART", 10040) + param_i("COM_DISARM_LAND", 2)
    out += rec("A", struct.pack("<BH", 0, 0) + b"vehicle_status")
    out += rec("A", struct.pack("<BH", 0, 1) + b"failsafe_flags")
    out += rec("A", struct.pack("<BH", 0, 2) + b"custom_detection")
    out += rec("A", struct.pack("<BH", 1, 3) + b"custom_detection")
    out += rec("A", struct.pack("<BH", 2, 4) + b"custom_detection")
    s = 1_000_000
    for i in range(8):
        ts = (i + 1) * s
        out += data(1, struct.pack("<QB", ts, 0))
        out += data(0, mc_vs(ts, 2 <= i + 1 <= 6))  # armed from 2 s through 6 s
        if 2 <= i <= 6:
            out += data(2, detection(ts + 500, 7, 0.5 + i / 20, i, 2.0 * i, 1.5, 0.25))
        if i in (3, 5):
            out += data(3, detection(ts + 700, 9, 0.75, -1.0, i, 0.5, 0.5))
    return out


def main():
    d = sys.argv[1]
    with open(os.path.join(d, "r4_quadchute_on_disarm.ulg"), "wb") as f:
        f.write(r4_quadchute_on_disarm())
    with open(os.path.join(d, "custom_detection.ulg"), "wb") as f:
        f.write(custom_detection())


if __name__ == "__main__":
    main()
