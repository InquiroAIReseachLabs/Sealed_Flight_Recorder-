#!/usr/bin/env python3
"""Writes the synthetic golden logs under testdata/synthetic/ (standard library only).

r4_quadchute_on_disarm.ulg: a VTOL that arms, transitions to fixed wing, and on the
vehicle_status sample that disarms is already multicopter again (a quadchute on the
disarming sample, which R4 counts, SPEC B1.6). It then arms again, transitions to fixed
wing, disarms in fixed wing, and goes multicopter on the next, disarmed sample (a quadchute
after disarm, which R4 does not count). vehicle_status.failsafe is never set, so R4 fails on
the first quadchute alone.

custom_detection.ulg: a multicopter flight that logs a topic PX4 does not
define, custom_detection, with a nested type (detection_box), in three instances: instance 0
with five messages, instance 1 with two, and instance 2 subscribed with none. A rules file that
lists it in [sealed_topics] seals it without knowing its structure.

cut_control.ulg, cut_mid_message.ulg, cut_mid_header.ulg, cut_after_arm.ulg: a complete
multicopter flight and three copies of it that end in the middle of a record (cut_logs()).

ulog_version_2.ulg: the same complete flight with ULog file format version 2 in the header.

usage: make_synthetic_logs.py <out dir>
"""
import json
import os
import struct
import sys

MAGIC = b"ULog\x01\x12\x35"
VS = ("vehicle_status:uint64_t timestamp;uint8_t arming_state;uint8_t nav_state;bool failsafe;"
      "bool is_vtol;bool in_transition_mode;bool in_transition_to_fw;uint8_t vehicle_type;"
      "uint8_t system_type;uint8_t latest_arming_reason;uint8_t latest_disarming_reason;")


def px4_fields(tag, topic):
    """The fields of a topic's message at a PX4 release tag, as (type, name), from
    scripts/testdata/px4_tables.json, which scripts/px4/px4_tables.py writes from the
    PX4-Autopilot source at that tag."""
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "px4_tables.json")) as f:
        tables = json.load(f)
    rel = next(r for r in tables["releases"] if r["tag"] == tag)
    return [(t, n) for n, t in tables["msgs"][rel["topics"][topic]]["fields"]]


# Every log here states PX4 v1.17.0, and R1 requires the failsafe_flags fields R4 reads at the
# log's tag, so the format is that tag's message (msg/FailsafeFlags.msg) and a row sets every
# field to 0 but the timestamp.
FS_FIELDS = px4_fields("v1.17.0", "failsafe_flags")
FS = "failsafe_flags:" + "".join("%s %s;" % f for f in FS_FIELDS)
FS_PACK = {"uint64_t": "Q", "uint32_t": "I", "uint8_t": "B", "bool": "B"}


def fs_row(ts):
    return struct.pack("<" + "".join(FS_PACK[t] for t, _ in FS_FIELDS),
                       *[ts if n == "timestamp" else 0 for _, n in FS_FIELDS])


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
        out += data(1, fs_row(ts))
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
        out += data(1, fs_row(ts))
        out += data(0, mc_vs(ts, 2 <= i + 1 <= 6))  # armed from 2 s through 6 s
        if 2 <= i <= 6:
            out += data(2, detection(ts + 500, 7, 0.5 + i / 20, i, 2.0 * i, 1.5, 0.25))
        if i in (3, 5):
            out += data(3, detection(ts + 700, 9, 0.75, -1.0, i, 0.5, 0.5))
    return out


def mc_flight(version=1):
    """A complete multicopter flight: eight seconds, armed from 2 s through 6 s, disarmed at 7 s.

    Returns the bytes and the byte offset of every data record, in file order, as
    (offset, topic, boot_us) with topic "failsafe_flags" or "vehicle_status".
    """
    out = MAGIC + bytes([version]) + struct.pack("<Q", 0)
    out += rec("B", bytes(16) + struct.pack("<QQQ", 0, 0, 0))
    out += info("char[40] ver_sw", b"d6f12ad1c4f70ad3230afd7d86e971421e02fef4")
    out += info("uint32_t ver_sw_release", struct.pack("<I", 0x011100FF))
    out += rec("F", VS.encode()) + rec("F", FS.encode())
    out += param_i("SYS_AUTOSTART", 10040) + param_i("COM_DISARM_LAND", 2)
    out += rec("A", struct.pack("<BH", 0, 0) + b"vehicle_status")
    out += rec("A", struct.pack("<BH", 0, 1) + b"failsafe_flags")
    starts = []
    s = 1_000_000
    for i in range(1, 9):
        ts = i * s
        starts.append((len(out), "failsafe_flags", ts))
        out += data(1, fs_row(ts))
        starts.append((len(out), "vehicle_status", ts))
        out += data(0, mc_vs(ts, 2 <= i <= 6))  # ARM at 2 s, DISARM at 7 s
    return out, starts


def cut_logs():
    """The ULog specification, "Requirements for Parsers": "A parser must be able to correctly
    handle logs that end abruptly, in the middle of a message. The unfinished message should just
    be discarded." Three cuts of mc_flight(), and its control:

    cut_control.ulg      the complete flight.
    cut_mid_message.ulg  ends 7 bytes into the payload of the last vehicle_status record
                         (boot_us 8000000), after the DISARM.
    cut_mid_header.ulg   ends 2 bytes into the 3-byte header of that same record.
    cut_after_arm.ulg    ends 7 bytes into the payload of the record right after the ARM sample
                         (failsafe_flags at boot_us 3000000): the log ends armed.
    """
    whole, starts = mc_flight()
    last_vs = [o for o, t, ts in starts if t == "vehicle_status" and ts == 8_000_000][0]
    arm = [i for i, (o, t, ts) in enumerate(starts) if t == "vehicle_status" and ts == 2_000_000][0]
    after_arm = starts[arm + 1][0]
    return {
        "cut_control.ulg": whole,
        "cut_mid_message.ulg": whole[: last_vs + 3 + 7],
        "cut_mid_header.ulg": whole[: last_vs + 2],
        "cut_after_arm.ulg": whole[: after_arm + 3 + 7],
    }


def ulog_version_2():
    """mc_flight() with file format version 2 in the header: the specification describes version
    1, and asks a parser to "parse future/unknown file format versions as well (but it can print
    a warning)". sfr seals it only with --allow-untested-version."""
    return mc_flight(version=2)[0]


def main():
    d = sys.argv[1]
    with open(os.path.join(d, "r4_quadchute_on_disarm.ulg"), "wb") as f:
        f.write(r4_quadchute_on_disarm())
    with open(os.path.join(d, "custom_detection.ulg"), "wb") as f:
        f.write(custom_detection())
    for name, b in cut_logs().items():
        with open(os.path.join(d, name), "wb") as f:
            f.write(b)
    with open(os.path.join(d, "ulog_version_2.ulg"), "wb") as f:
        f.write(ulog_version_2())


if __name__ == "__main__":
    main()
