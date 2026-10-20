#!/usr/bin/env python3
"""Writes the false-pass corpus under testdata/falsepass/ (standard library only).

Each case is a log (and, where needed, a rules file) built to look like a passing flight to a
reader that trusts what the log declares about its own structure, together with the result
sfr must give. Most logs are written from scratch; the cases named `golden_*` are derived from
testdata/sitl/v1.17.0/mc_flight_1.ulg, keeping only the topics the core rules read. Beside each
attack sits a positive control: the same log without the trick, which must fail (or warn) for
the reason the attack tries to hide.

Writes <case>.ulg and <case>.params (the baseline: the log's parameters at the first ARM) for
every case, and cases.json, which tests read (crates/sfr/tests/falsepass.rs and the pyulog
differential, scripts/testdata/falsepass_oracle.py).

usage: make_falsepass.py <out dir>      (normally testdata/falsepass)
       make_falsepass.py --check <dir>  (exit 1 if <dir> differs from what would be written)
"""
import json
import os
import struct
import sys

MAGIC = b"ULog\x01\x12\x35"
GIT = b"d6f12ad1c4f70ad3230afd7d86e971421e02fef4"
RELEASE_1_17_0 = 0x011100FF
GOLDEN = "testdata/sitl/v1.17.0/mc_flight_1.ulg"

PACK = {"uint8_t": "B", "int8_t": "b", "uint16_t": "H", "int16_t": "h", "uint32_t": "I",
        "int32_t": "i", "uint64_t": "Q", "int64_t": "q", "float": "f", "double": "d",
        "bool": "B", "char": "B"}


def rec(ty, body):
    return struct.pack("<HB", len(body), ord(ty)) + body


class Log:
    """A ULog written record by record."""

    def __init__(self):
        self.out = bytearray(MAGIC + bytes([1]) + struct.pack("<Q", 0))
        self.out += rec("B", bytes(16) + struct.pack("<QQQ", 0, 0, 0))
        self.formats = {}
        self.subs = {}

    def info(self, key, value):
        k = key.encode()
        self.out += rec("I", bytes([len(k)]) + k + value)
        return self

    def firmware(self):
        self.info("char[40] ver_sw", GIT)
        return self.info("uint32_t ver_sw_release", struct.pack("<I", RELEASE_1_17_0))

    def format(self, name, fields):
        """fields: [(type, name)]"""
        self.formats[name] = fields
        text = name + ":" + "".join("%s %s;" % f for f in fields)
        self.out += rec("F", text.encode())
        return self

    def param_i(self, name, v):
        k = ("int32_t " + name).encode()
        self.out += rec("P", bytes([len(k)]) + k + struct.pack("<i", v))
        return self

    def param_f(self, name, v):
        k = ("float " + name).encode()
        self.out += rec("P", bytes([len(k)]) + k + struct.pack("<f", v))
        return self

    def sub(self, multi, msg_id, topic):
        self.subs[msg_id] = topic
        self.out += rec("A", struct.pack("<BH", multi, msg_id) + topic.encode())
        return self

    def data(self, msg_id, values, fields=None):
        fields = fields or self.formats[self.subs[msg_id]]
        payload = b"".join(struct.pack("<" + PACK[t], values.get(n, 0)) for t, n in fields)
        self.out += rec("D", struct.pack("<H", msg_id) + payload)
        return self

    def raw(self, ty, body):
        self.out += rec(ty, body)
        return self


def px4_fields(tag, topic):
    """The fields of a topic's message at a PX4 release tag, as (type, name), from
    scripts/testdata/px4_tables.json, which scripts/px4/px4_tables.py writes from the
    PX4-Autopilot source at that tag."""
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "px4_tables.json")) as f:
        tables = json.load(f)
    rel = next(r for r in tables["releases"] if r["tag"] == tag)
    return [(t, n) for n, t in tables["msgs"][rel["topics"][topic]]["fields"]]


# Every log here states PX4 v1.17.0 (RELEASE_1_17_0), so its formats are that tag's messages.
VS = px4_fields("v1.17.0", "vehicle_status")
# nav_state 4 is AUTO_LOITER: bit 4 of a mode_req_* field says that mode needs the flag clear.
FS = px4_fields("v1.17.0", "failsafe_flags")
S = 1_000_000


def retype(fields, name, new_type):
    return [(new_type if n == name else t, n) for t, n in fields]


def vs_row(ts, armed, **kw):
    row = {"timestamp": ts, "arming_state": 2 if armed else 1, "nav_state": 4,
           "vehicle_type": 1, "system_type": 2, "latest_arming_reason": 3,
           "latest_disarming_reason": 6}
    row.update(kw)
    return row


def flight(vs_fields=VS, fs_fields=FS, rows=8, armed=range(2, 7), vs_kw=None, fs_kw=None,
           extra=None, pre=None):
    """A multicopter that arms at 2 s and disarms at 7 s, one sample per second; vs_kw and
    fs_kw give per-second overrides, pre(log) adds definitions, extra(log, second) adds
    records."""
    log = Log().firmware()
    log.format("vehicle_status", vs_fields).format("failsafe_flags", fs_fields)
    log.param_i("SYS_AUTOSTART", 4001).param_f("MPC_XY_VEL_MAX", 12.0)
    if pre:
        pre(log)
    log.sub(0, 0, "vehicle_status").sub(0, 1, "failsafe_flags")
    for i in range(1, rows + 1):
        ts = i * S
        fk = {"timestamp": ts, "mode_req_global_position": 1 << 4}
        fk.update((fs_kw or (lambda i: {}))(i))
        log.data(1, fk)
        log.data(0, vs_row(ts, i in armed, **(vs_kw or (lambda i: {}))(i)))
        if extra:
            extra(log, i)
    return log


def in_flight(i):
    return 2 <= i <= 6


# --------------------------------------------------------------------------------------------
# Cases: rule inputs whose declared types differ from PX4's


def failsafe_uint8(control):
    t = "bool" if control else "uint8_t"
    return flight(vs_fields=retype(VS, "failsafe", t),
                  vs_kw=lambda i: {"failsafe": 1 if i == 4 else 0})


def arming_int8(control):
    t = "uint8_t" if control else "int8_t"
    return flight(vs_fields=retype(VS, "arming_state", t),
                  vs_kw=lambda i: {"failsafe": 1 if i == 4 else 0})


def VTOL_ROW(i):
    # A VTOL (is_vtol, system_type 22) that starts a transition to fixed wing at 3 s and
    # falls back to multicopter at 4 s: an aborted transition.
    return {"is_vtol": 1, "system_type": 22, "in_transition_mode": 1 if i == 3 else 0,
            "in_transition_to_fw": 1 if i == 3 else 0, "vehicle_type": 1}


def transition_uint8(control):
    t = "bool" if control else "uint8_t"
    return flight(vs_fields=retype(VS, "in_transition_mode", t), vs_kw=VTOL_ROW)


def resubscribe_retyped(control):
    """vehicle_status instance 0 subscribed with a bool failsafe, then the format is redefined
    with a uint8_t failsafe and instance 0 subscribed again; the second subscription carries
    the flight and the failsafe."""
    log = Log().firmware()
    log.format("vehicle_status", VS).format("failsafe_flags", FS)
    log.param_i("SYS_AUTOSTART", 4001).param_f("MPC_XY_VEL_MAX", 12.0)
    log.sub(0, 0, "vehicle_status").sub(0, 1, "failsafe_flags")
    log.data(1, {"timestamp": S, "mode_req_global_position": 1 << 4})
    log.data(0, vs_row(S, False))
    second = VS if control else retype(VS, "failsafe", "uint8_t")
    log.format("vehicle_status", second)
    log.sub(0, 2, "vehicle_status")
    for i in range(2, 9):
        ts = i * S
        log.data(1, {"timestamp": ts, "mode_req_global_position": 1 << 4})
        log.data(2, vs_row(ts, in_flight(i), failsafe=1 if i == 4 else 0), fields=second)
    return log


def _redefined_failsafe(control, fields):
    """failsafe_flags instance 0 subscribed, then, in the data section, its format redefined with
    `fields` and instance 0 subscribed again; the second subscription carries the flight, in
    which global_position_invalid is set at 4 s where the first layout has it. The control
    keeps one subscription and one format: the flag is true in flight at 4 s."""
    log = Log().firmware()
    log.format("vehicle_status", VS).format("failsafe_flags", FS)
    log.param_i("SYS_AUTOSTART", 4001).param_f("MPC_XY_VEL_MAX", 12.0)
    log.sub(0, 0, "vehicle_status").sub(0, 1, "failsafe_flags")
    log.data(1, {"timestamp": S, "mode_req_global_position": 1 << 4})
    log.data(0, vs_row(S, False))
    fs_id = 1
    if not control:
        log.format("failsafe_flags", fields)
        log.sub(0, 2, "failsafe_flags")
        fs_id = 2
    for i in range(2, 9):
        ts = i * S
        row = {"timestamp": ts, "mode_req_global_position": 1 << 4}
        if control:
            row["global_position_invalid"] = 1 if i == 4 else 0
        else:
            # Under the first layout these bytes would read global_position_invalid true at 4 s.
            row.update({n: (1 if i == 4 else 0) for _, n in fields if n.startswith("global_position_invalid")})
        log.data(fs_id, row, fields=FS if control else fields)
        log.data(0, vs_row(ts, in_flight(i)))
    return log


def format_redefined_drops_flag(control):
    """failsafe_flags redefined after its first subscription without global_position_invalid,
    a flag the flight mode requires clear."""
    return _redefined_failsafe(control, [f for f in FS if f[1] != "global_position_invalid"])


def format_redefined_renames_flag(control):
    """failsafe_flags redefined after its first subscription with global_position_invalid
    renamed, so a reader that looks the flag up by name finds nothing."""
    return _redefined_failsafe(control, [(t, n + "_x" if n == "global_position_invalid" else n) for t, n in FS])


def resubscribe_identical(control):
    """failsafe_flags instance 0 subscribed a second time with the same format and no new format
    record, as a logger may; the second subscription carries global_position_invalid true at
    4 s. Accepted and read like one subscription: R4 fails on the flag, as it does on the
    control, which has one subscription."""
    log = Log().firmware()
    log.format("vehicle_status", VS).format("failsafe_flags", FS)
    log.param_i("SYS_AUTOSTART", 4001).param_f("MPC_XY_VEL_MAX", 12.0)
    log.sub(0, 0, "vehicle_status").sub(0, 1, "failsafe_flags")
    fs_id = 1
    for i in range(1, 9):
        if i == 3 and not control:
            log.sub(0, 2, "failsafe_flags")
            fs_id = 2
        ts = i * S
        log.data(fs_id, {"timestamp": ts, "mode_req_global_position": 1 << 4,
                         "global_position_invalid": 1 if i == 4 else 0})
        log.data(0, vs_row(ts, in_flight(i)))
    return log


def clipping_decoy_field(control):
    """vehicle_imu_status declares a scalar field named `accel_clipping[0]` before the real
    array `uint32_t[3] accel_clipping`, so the two flatten to one name; the decoy stays 0 while
    the real first axis clips 500 times in flight. A reader that takes the first field of a name
    sees no clipping. The control declares the array alone: X4 fails on the clipping."""
    log = Log().firmware()
    log.format("vehicle_status", VS).format("failsafe_flags", FS)
    decoy = "" if control else "uint32_t accel_clipping[0];"
    imu = ("vehicle_imu_status:uint64_t timestamp;uint32_t accel_device_id;" + decoy
           + "uint32_t[3] accel_clipping;float accel_vibration_metric;")
    log.out += rec("F", imu.encode())
    log.format("sensor_selection", [("uint64_t", "timestamp"), ("uint32_t", "accel_device_id")])
    log.param_i("SYS_AUTOSTART", 4001).param_f("MPC_XY_VEL_MAX", 12.0)
    log.sub(0, 0, "vehicle_status").sub(0, 1, "failsafe_flags")
    log.sub(0, 2, "vehicle_imu_status").sub(0, 3, "sensor_selection")
    for i in range(1, 9):
        ts = i * S
        log.data(1, {"timestamp": ts, "mode_req_global_position": 1 << 4})
        log.data(0, vs_row(ts, in_flight(i)))
        clip = 100 * max(0, min(i, 6) - 1)  # rises while armed, from 2 s to 6 s
        payload = struct.pack("<QI", ts, 7) + (b"" if control else struct.pack("<I", 0))
        payload += struct.pack("<3If", clip, 0, 0, 0.5)
        log.raw("D", struct.pack("<H", 2) + payload)
        log.data(3, {"timestamp": ts, "accel_device_id": 7})
    return log


def failsafe_backdated(control):
    """vehicle_status samples one per second, armed from 2 s to 6 s; the sample written after
    the 4 s one, in failsafe, carries the timestamp 1.5 s, before the ARM, so a reader that
    places samples by timestamp sees the failsafe while disarmed. The control writes it at
    4.5 s: failsafe in flight."""
    log = Log().firmware()
    log.format("vehicle_status", VS).format("failsafe_flags", FS)
    log.param_i("SYS_AUTOSTART", 4001).param_f("MPC_XY_VEL_MAX", 12.0)
    log.sub(0, 0, "vehicle_status").sub(0, 1, "failsafe_flags")
    for i in range(1, 9):
        ts = i * S
        log.data(1, {"timestamp": ts, "mode_req_global_position": 1 << 4})
        log.data(0, vs_row(ts, in_flight(i)))
        if i == 4:
            back = ts + S // 2 if control else S + S // 2
            log.data(0, vs_row(back, True, failsafe=1))
            log.data(0, vs_row(ts + S // 2 + 1, True))
    return log


def mode_req_uint64(control):
    """mode_req_global_position declared uint64_t with only bit 36 set: as 32 bits it reads 0,
    so the required flag would look not required."""
    t = "uint32_t" if control else "uint64_t"
    bit = 4 if control else 36
    return flight(fs_fields=retype(FS, "mode_req_global_position", t),
                  fs_kw=lambda i: {"mode_req_global_position": 1 << bit,
                                   "global_position_invalid": 1 if i == 4 else 0})


def duplicate_failsafe(control):
    """A second `bool failsafe` field after the first: a reader that takes the first sees
    false where the second is true. The control has one failsafe field, true at 4 s."""
    fields = VS + ([] if control else [("bool", "failsafe")])
    log = Log().firmware()
    log.format("vehicle_status", fields).format("failsafe_flags", FS)
    log.param_i("SYS_AUTOSTART", 4001).param_f("MPC_XY_VEL_MAX", 12.0)
    log.sub(0, 0, "vehicle_status").sub(0, 1, "failsafe_flags")
    for i in range(1, 9):
        ts = i * S
        log.data(1, {"timestamp": ts, "mode_req_global_position": 1 << 4})
        row = vs_row(ts, in_flight(i), failsafe=1 if (control and i == 4) else 0)
        payload = b"".join(struct.pack("<" + PACK[t], row.get(n, 0)) for t, n in VS)
        if not control:
            payload += bytes([1 if i == 4 else 0])
        log.raw("D", struct.pack("<H", 0) + payload)
    return log


# --------------------------------------------------------------------------------------------
# Cases: instances, empty flights, flags, VTOL type


def instance_one_failsafe(control):
    """vehicle_status instance 0 is a clean flight; instance 1 is in failsafe in flight."""
    log = Log().firmware()
    log.format("vehicle_status", VS).format("failsafe_flags", FS)
    log.param_i("SYS_AUTOSTART", 4001).param_f("MPC_XY_VEL_MAX", 12.0)
    log.sub(0, 0, "vehicle_status").sub(0, 1, "failsafe_flags")
    if not control:
        log.sub(1, 2, "vehicle_status")
    for i in range(1, 9):
        ts = i * S
        log.data(1, {"timestamp": ts, "mode_req_global_position": 1 << 4})
        if control:
            log.data(0, vs_row(ts, in_flight(i), failsafe=1 if i == 4 else 0))
        else:
            log.data(0, vs_row(ts, in_flight(i)))
            log.data(2, vs_row(ts + 1000, in_flight(i), failsafe=1 if i == 4 else 0))
    return log


def never_armed_failsafe(control):
    """No sample is armed; failsafe is set. With nothing armed there is no flight to pass."""
    return flight(armed=range(2, 7) if control else range(0),
                  vs_kw=lambda i: {"failsafe": 1 if i == 4 else 0})


def flag_gcs_connection_lost(control):
    """failsafe_flags.gcs_connection_lost, which no mode_req_* mask covers in PX4 v1.17.0, true
    the whole armed interval, vehicle_status.failsafe never set: a reader that checks only
    vehicle_status.failsafe or only the required flags passes it. The control sets
    global_position_invalid instead, which AUTO_LOITER requires (mode_req_global_position)."""
    flag = "global_position_invalid" if control else "gcs_connection_lost"
    return flight(fs_kw=lambda i: {flag: int(in_flight(i))})


def vtol_mav_type_not_vtol(control):
    """system_type 22 (MAV_TYPE_VTOL_FIXEDROTOR) with is_vtol false on every sample, and an
    aborted transition. The control states is_vtol true."""
    def row(i):
        r = VTOL_ROW(i)
        r["is_vtol"] = 1 if control else 0
        return r
    return flight(vs_kw=row)


def mav_type_24_not_px4_vtol(control):
    """system_type 24 with is_vtol false on every sample, and the transition fields of an aborted
    transition. MAVLink counts 24 as a VTOL type; PX4's is_vtol (commander_helper.cpp, every
    supported tag) counts 19 to 23 only, so the log does not contradict itself and R6 is N/A,
    naming the type. The control is system_type 22, which PX4 counts: R6 cannot evaluate."""
    def row(i):
        r = VTOL_ROW(i)
        r["is_vtol"] = 0
        r["system_type"] = 22 if control else 24
        return r
    return flight(vs_kw=row)


def nav_state_beyond_max(control):
    """nav_state 31 in flight, NAVIGATION_STATE_MAX at v1.17.0, with global_position_invalid true
    at 4 s and mode_req_global_position naming AUTO_LOITER (4). No mode requirement names state
    31, so a reader that looks the flag up for it sees it as not required. The control flies in
    AUTO_LOITER: the flag is required and R4 fails."""
    return flight(vs_kw=lambda i: {"nav_state": 4 if control else 31},
                  fs_kw=lambda i: {"global_position_invalid": 1 if i == 4 else 0})


def hazard_whole_flight(control):
    """failsafe_flags.geofence_breached true on every sample from the ARM through the disarm,
    in AUTO_LOITER, whose mode requirements do not name it: a reader that fails only flags the
    mode requires sees a warning. The control sets it on one sample in flight only: a warning
    there too."""
    return flight(fs_kw=lambda i: {"geofence_breached": 1 if (in_flight(i) or i == 7) and (not control or i == 4) else 0})


def failsafe_flags_gap(control):
    """failsafe_flags samples at 3, 4 and 5 s, in flight, left out: the one at 4 s had
    global_position_invalid true, which AUTO_LOITER requires clear, so a reader sees no flag at
    all. The flags go unseen for 4 s in flight (PX4 publishes them at least every 600 ms). The
    control keeps every sample: R4 fails on the flag."""
    log = Log().firmware()
    log.format("vehicle_status", VS).format("failsafe_flags", FS)
    log.param_i("SYS_AUTOSTART", 4001).param_f("MPC_XY_VEL_MAX", 12.0)
    log.sub(0, 0, "vehicle_status").sub(0, 1, "failsafe_flags")
    for i in range(1, 9):
        ts = i * S
        if control or i not in (3, 4, 5):
            log.data(1, {"timestamp": ts, "mode_req_global_position": 1 << 4,
                         "global_position_invalid": 1 if i == 4 else 0})
        log.data(0, vs_row(ts, in_flight(i)))
    return log


def failsafe_flags_end_gap(control):
    """failsafe_flags samples stop at 4 s and none follows, 3 s before the disarm at 7 s: the
    sample at 5 s had global_position_invalid true, which AUTO_LOITER requires clear, so a
    reader that measures only the time between samples sees no flag and no gap. The flags go
    unseen for the last 3 s of the flight. The control keeps every sample: R4 fails on the flag."""
    log = Log().firmware()
    log.format("vehicle_status", VS).format("failsafe_flags", FS)
    log.param_i("SYS_AUTOSTART", 4001).param_f("MPC_XY_VEL_MAX", 12.0)
    log.sub(0, 0, "vehicle_status").sub(0, 1, "failsafe_flags")
    for i in range(1, 9):
        ts = i * S
        if control or i <= 4:
            log.data(1, {"timestamp": ts, "mode_req_global_position": 1 << 4,
                         "global_position_invalid": 1 if i == 5 else 0})
        log.data(0, vs_row(ts, in_flight(i)))
    return log


def failsafe_flags_start_gap(control):
    """failsafe_flags samples begin at 4 s and none precedes, 2 s after the arm at 2 s: the
    sample at 3 s had global_position_invalid true, which AUTO_LOITER requires clear. The flags
    go unseen for the first 2 s of the flight. The control keeps every sample: R4 fails on the
    flag."""
    log = Log().firmware()
    log.format("vehicle_status", VS).format("failsafe_flags", FS)
    log.param_i("SYS_AUTOSTART", 4001).param_f("MPC_XY_VEL_MAX", 12.0)
    log.sub(0, 0, "vehicle_status").sub(0, 1, "failsafe_flags")
    for i in range(1, 9):
        ts = i * S
        if control or i >= 4:
            log.data(1, {"timestamp": ts, "mode_req_global_position": 1 << 4,
                         "global_position_invalid": 1 if i == 3 else 0})
        log.data(0, vs_row(ts, in_flight(i)))
    return log


def unknown_messages(control):
    """A record of an unknown type and a data record for a message id never subscribed."""
    def extra(log, i):
        if not control and i == 3:
            log.raw("X", b"hidden")
            log.raw("D", struct.pack("<H", 77) + bytes(9))
    return flight(extra=extra)


def r7_scoped(control):
    """[authorized_sources] scoped to GENERAL: a PAYLOAD command from an unknown source is out
    of scope; the PASS line must say so. The control checks every category."""
    vc = [("uint64_t", "timestamp"), ("uint32_t", "command"), ("uint8_t", "source_system"),
          ("uint16_t", "source_component")]

    def pre(log):
        log.format("vehicle_command", vc)

    def extra(log, i):
        if i == 1:
            log.sub(0, 3, "vehicle_command")
        if i == 3:
            log.data(3, {"timestamp": 3 * S + 5, "command": 211, "source_system": 9,
                         "source_component": 99})
        if i == 4:
            log.data(3, {"timestamp": 4 * S + 5, "command": 176, "source_system": 1,
                         "source_component": 1})
    return flight(extra=extra, pre=pre)


# --------------------------------------------------------------------------------------------
# Cases derived from a golden flight


def read_records(data):
    """(type, body) for every record after the 16-byte header."""
    pos = 16
    out = []
    while pos + 3 <= len(data):
        size, ty = struct.unpack_from("<HB", data, pos)
        out.append((chr(ty), data[pos + 3:pos + 3 + size]))
        pos += 3 + size
    return data[:16], out


def flat_offsets(fmt_text, formats):
    """{field name: (offset, struct char)} of top-level scalar fields of a format."""
    _, fields = fmt_text.split(":", 1)
    out, pos = {}, 0
    for item in filter(None, fields.split(";")):
        ty, name = item.split(" ", 1)
        n = 1
        if "[" in ty:
            ty, cnt = ty.split("[")
            n = int(cnt.rstrip("]"))
        if ty in PACK:
            if n == 1:
                out[name] = (pos, PACK[ty])
            pos += struct.calcsize("<" + PACK[ty]) * n
        else:
            pos += size_of(formats[ty], formats) * n
    return out


def size_of(fmt_text, formats):
    _, fields = fmt_text.split(":", 1)
    total = 0
    for item in filter(None, fields.split(";")):
        ty, _ = item.split(" ", 1)
        n = 1
        if "[" in ty:
            ty, cnt = ty.split("[")
            n = int(cnt.rstrip("]"))
        total += (struct.calcsize("<" + PACK[ty]) if ty in PACK else size_of(formats[ty], formats)) * n
    return total


def golden(transform, root):
    """The golden flight with only the core topics kept, rewritten by transform(records)."""
    with open(os.path.join(root, GOLDEN), "rb") as f:
        data = f.read()
    header, records = read_records(data)
    if records and records[0][0] == "B" and records[0][1][8] & 1:
        raise SystemExit("make_falsepass.py: %s has appended data" % GOLDEN)
    keep = {"vehicle_status", "failsafe_flags"}
    formats, subs, out = {}, {}, []
    for ty, body in records:
        if ty == "F":
            text = body.decode()
            formats[text.split(":", 1)[0]] = text
        elif ty == "A":
            subs[struct.unpack_from("<H", body, 1)[0]] = body[3:].decode()
        elif ty == "M":
            continue
        elif ty == "D" and subs.get(struct.unpack_from("<H", body, 0)[0]) not in keep:
            continue
        out.append((ty, body))
    vs_id = next(k for k, v in subs.items() if v == "vehicle_status")
    arming = flat_offsets(formats["vehicle_status"], formats)["arming_state"]
    out = transform(out, vs_id, arming)
    return header + b"".join(rec(ty, body) for ty, body in out)


def is_armed_row(body, vs_id, arming):
    msg = struct.unpack_from("<H", body, 0)[0]
    return msg == vs_id and body[2 + arming[0]] == 2


def armed_rows_deleted(root, control):
    def t(records, vs_id, arming):
        if control:
            return records
        return [(ty, b) for ty, b in records if not (ty == "D" and is_armed_row(b, vs_id, arming))]
    return golden(t, root)


def param_at_arm(root, control):
    """A parameter record placed right after the arming vehicle_status row, so its time equals
    the ARM time. The control places it one data record later."""
    k = b"float MPC_XY_VEL_MAX"
    p = (bytes([len(k)]) + k + struct.pack("<f", 3.0))

    def t(records, vs_id, arming):
        out, armed_at = [], None
        for i, (ty, b) in enumerate(records):
            out.append((ty, b))
            if armed_at is None and ty == "D" and is_armed_row(b, vs_id, arming):
                armed_at = len(out)
        pos = armed_at
        if control:
            # After the next data record of another topic with a later timestamp.
            ts0 = struct.unpack_from("<Q", out[armed_at - 1][1], 2)[0]
            while not (out[pos][0] == "D" and struct.unpack_from("<Q", out[pos][1], 2)[0] > ts0):
                pos += 1
            pos += 1
        out.insert(pos, ("P", p))
        return out
    return golden(t, root)


# --------------------------------------------------------------------------------------------
# The corpus

RULES = "rules.toml"
RULES_R7 = "rules_r7_general.toml"
RULES_R7_ALL = "rules_r7_all.toml"
RULES_IGNORE_ALL = "rules_ignore_all.toml"
RULES_X4 = "rules_x4.toml"
RULES_IGNORE_UNION = "rules_ignore_union.toml"
# One pattern per character a parameter name can start with: no pattern matches every name
# alone, together they do.
NAME_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"

RULE_FILES = {
    RULES: '''format = "sfr-rules/1"

[required_topics]
topics = ["vehicle_status", "failsafe_flags"]
''',
    RULES_R7: '''format = "sfr-rules/1"

[required_topics]
topics = ["vehicle_status", "failsafe_flags"]

[payload_commands]
ids = [211]

[authorized_sources]
category = "GENERAL"
sources = [{ system = 1, component = 1 }]
''',
    RULES_R7_ALL: '''format = "sfr-rules/1"

[required_topics]
topics = ["vehicle_status", "failsafe_flags"]

[payload_commands]
ids = [211]

[authorized_sources]
sources = [{ system = 1, component = 1 }]
''',
    RULES_IGNORE_UNION: '''format = "sfr-rules/1"

[required_topics]
topics = ["vehicle_status", "failsafe_flags"]

[parameters]
ignore = [''' + ", ".join('"%s*"' % c for c in NAME_CHARS) + ''']
''',
    RULES_X4: '''format = "sfr-rules/1"

[required_topics]
topics = ["vehicle_status", "failsafe_flags"]

[extended.vibration]
max_accel_vibration_metric = 3.0
max_accel_clipping = 10
''',
    RULES_IGNORE_ALL: '''format = "sfr-rules/1"

[required_topics]
topics = ["vehicle_status", "failsafe_flags"]

[parameters]
ignore = ["*"]
''',
}

# name, item, what it tries, builder, rules, extra seal options, expected, control's expected.
# Expected: exit code, overall status, the results that matter, and text the result's
# `found` must contain. `None` exit: seal refuses the log (no record).
CASES = [
    ("failsafe_uint8", "1.1", "vehicle_status.failsafe declared uint8_t, true in flight",
     failsafe_uint8, RULES, [],
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "vehicle_status.failsafe is uint8_t in the log; PX4 defines bool"}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"}, "found": {"R4": "true in flight 1 time(s)"}}),
    ("arming_int8", "1.1", "vehicle_status.arming_state declared int8_t, failsafe in flight",
     arming_int8, RULES, [],
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL", "R5": "FAIL"},
      "found": {"R5": "vehicle_status.arming_state is int8_t in the log; PX4 defines uint8_t"}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL", "R5": "PASS"}}),
    ("transition_uint8", "1.1", "vehicle_status.in_transition_mode declared uint8_t, aborted transition",
     transition_uint8, RULES, [],
     {"exit": 1, "status": "FAIL", "results": {"R6": "FAIL"},
      "found": {"R6": "vehicle_status.in_transition_mode is uint8_t in the log; PX4 defines bool"}},
     {"exit": 1, "status": "FAIL", "results": {"R6": "FAIL"}, "found": {"R6": "1 problem(s)"}}),
    # Both logs of this case redefine vehicle_status with a format record in the data section,
    # which the ULog specification does not allow there: both are refused. The case
    # resubscribe_identical below is the accepted second subscription.
    ("resubscribe_retyped", "1.1", "a second subscription of vehicle_status retypes failsafe to uint8_t",
     resubscribe_retyped, RULES, [],
     {"exit": 3, "status": None, "results": {}},
     {"exit": 3, "status": None, "results": {}}),
    ("instance_one_failsafe", "1.2", "a clean vehicle_status instance 0, failsafe in flight on instance 1",
     instance_one_failsafe, RULES, [],
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "true in flight 1 time(s)"}, "instances": 2},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"}, "instances": 1}),
    ("never_armed_failsafe", "1.3", "never armed, failsafe set",
     never_armed_failsafe, RULES, [],
     {"exit": 1, "status": "NO ARMED FLIGHT", "results": {"R4": "N/A", "R5": "N/A"}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL", "R5": "PASS"}}),
    ("golden_armed_rows_deleted", "1.3", "a real flight with every armed vehicle_status row deleted",
     armed_rows_deleted, RULES, [],
     {"exit": 1, "status": "NO ARMED FLIGHT", "results": {"R5": "N/A"}},
     {"exit": 0, "status": "WARN", "results": {"R5": "PASS"}}),
    ("flag_gcs_connection_lost", "1.4",
     "failsafe_flags.gcs_connection_lost true for the whole armed interval",
     flag_gcs_connection_lost, RULES, [],
     {"exit": 0, "status": "WARN", "results": {"R4": "WARN"},
      "found": {"R4": "warning: failsafe_flags gcs_connection_lost true in flight"}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "required failsafe_flags global_position_invalid true in flight"}}),
    ("duplicate_failsafe", "1.5", "a second `bool failsafe` field in the vehicle_status format",
     duplicate_failsafe, RULES, [],
     {"exit": 3, "status": None, "results": {}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"}}),
    ("golden_param_at_arm", "1.6", "a parameter change at the ARM time, after the ARM row",
     param_at_arm, RULES, [],
     # The golden flight changes CAL_BARO0_OFF in flight itself; the inserted change is the second.
     {"exit": 0, "status": "WARN", "results": {"R3": "WARN"},
      "found": {"R3": "2 parameter(s) changed in flight"}, "events": {"PARAM_CHANGED_IN_FLIGHT": 2}},
     {"exit": 0, "status": "WARN", "results": {"R3": "WARN"}, "events": {"PARAM_CHANGED_IN_FLIGHT": 2}}),
    ("ignore_all", "1.7", "ignore = [\"*\"] in the rules file hides a parameter difference",
     None, RULES_IGNORE_ALL, [],
     {"exit": 4, "status": None, "results": {}},
     {"exit": 1, "status": "FAIL", "results": {"R3": "FAIL"}}),
    ("vtol_mav_type_not_vtol", "1.8", "system_type 22 (a VTOL) with is_vtol false, aborted transition",
     vtol_mav_type_not_vtol, RULES, [],
     {"exit": 1, "status": "FAIL", "results": {"R6": "FAIL"},
      "found": {"R6": "a VTOL MAV_TYPE, but is_vtol is false on every sample"}},
     {"exit": 1, "status": "FAIL", "results": {"R6": "FAIL"}, "found": {"R6": "1 problem(s)"}}),
    ("r7_scoped_general", "1.9", "R7 scoped to GENERAL hides a PAYLOAD command from an unknown source",
     r7_scoped, RULES_R7, [],
     {"exit": 0, "status": "PASS", "results": {"R7": "PASS"},
      "found": {"R7": "scope GENERAL only, 1 excluded by scope; source ids are self-reported by the sender"}},
     {"exit": 1, "status": "FAIL", "results": {"R7": "FAIL"}}),
    ("unknown_messages", "1.10", "a record of an unknown type and a data record without a subscription",
     unknown_messages, RULES, [],
     {"exit": 0, "status": "PASS", "results": {}, "skipped": 2},
     {"exit": 0, "status": "PASS", "results": {}, "skipped": 0}),
    ("format_redefined_drops_flag", "1.12",
     "failsafe_flags redefined after its first subscription without a required flag",
     format_redefined_drops_flag, RULES, [],
     {"exit": 3, "status": None, "results": {}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "required failsafe_flags global_position_invalid true in flight"}}),
    ("format_redefined_renames_flag", "1.12",
     "failsafe_flags redefined after its first subscription with a required flag renamed",
     format_redefined_renames_flag, RULES, [],
     {"exit": 3, "status": None, "results": {}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "required failsafe_flags global_position_invalid true in flight"}}),
    ("resubscribe_identical", "1.12",
     "failsafe_flags instance 0 subscribed twice with the same format (accepted)",
     resubscribe_identical, RULES, [],
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "required failsafe_flags global_position_invalid true in flight"}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "required failsafe_flags global_position_invalid true in flight"}}),
    ("failsafe_backdated", "2.4",
     "a vehicle_status sample in failsafe written in flight with a timestamp before the ARM",
     failsafe_backdated, RULES, [],
     {"exit": 3, "status": None, "results": {}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"}, "found": {"R4": "true in flight 1 time(s)"}}),
    ("mav_type_24_not_px4_vtol", "2.2",
     "system_type 24, a MAVLink VTOL type PX4 does not count, with is_vtol false (no R6 FAIL)",
     mav_type_24_not_px4_vtol, RULES, [],
     {"exit": 0, "status": "PASS", "results": {"R6": "N/A"},
      "found": {"R6": "system_type 24 is a MAVLink VTOL MAV_TYPE that PX4's is_vtol does not count"}},
     {"exit": 1, "status": "FAIL", "results": {"R6": "FAIL"},
      "found": {"R6": "a VTOL MAV_TYPE, but is_vtol is false on every sample"}}),
    ("nav_state_beyond_max", "2.5",
     "nav_state at NAVIGATION_STATE_MAX in flight, with a flag true that AUTO_LOITER requires",
     nav_state_beyond_max, RULES, [],
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "cannot evaluate: vehicle_status.nav_state is 31 in flight"}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "required failsafe_flags global_position_invalid true in flight"}}),
    ("hazard_whole_flight", "2.3",
     "a hazard flag (geofence_breached) true for the whole flight, not required by the mode",
     hazard_whole_flight, RULES, [],
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "hazard failsafe_flags geofence_breached true for the whole flight"}},
     {"exit": 0, "status": "WARN", "results": {"R4": "WARN"},
      "found": {"R4": "warning: failsafe_flags geofence_breached true in flight"}}),
    ("failsafe_flags_gap", "3.10",
     "failsafe_flags samples left out in flight where a required flag was true",
     failsafe_flags_gap, RULES, [],
     {"exit": 0, "status": "WARN", "results": {"R4": "WARN"},
      "found": {"R4": "warning: failsafe_flags 1 gap(s) over 1000 ms in flight, longest 4000 ms"}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "required failsafe_flags global_position_invalid true in flight"}}),
    ("failsafe_flags_end_gap", "3.10",
     "failsafe_flags samples stopped before the disarm, where a required flag was true",
     failsafe_flags_end_gap, RULES, [],
     {"exit": 0, "status": "WARN", "results": {"R4": "WARN"},
      "found": {"R4": "warning: failsafe_flags 1 gap(s) over 1000 ms in flight, longest 3000 ms"}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "required failsafe_flags global_position_invalid true in flight"}}),
    ("failsafe_flags_start_gap", "3.10",
     "failsafe_flags samples begun after the arm, where a required flag was true",
     failsafe_flags_start_gap, RULES, [],
     {"exit": 0, "status": "WARN", "results": {"R4": "WARN"},
      "found": {"R4": "warning: failsafe_flags 1 gap(s) over 1000 ms in flight, longest 2000 ms"}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "required failsafe_flags global_position_invalid true in flight"}}),
    ("ignore_union", "3.8", "63 ignore patterns, one per first character, that together hide a parameter difference",
     None, RULES_IGNORE_UNION, [],
     {"exit": 4, "status": None, "results": {}},
     {"exit": 1, "status": "FAIL", "results": {"R3": "FAIL"}}),
    ("clipping_decoy_field", "2.1",
     "a scalar field named accel_clipping[0] before the real accel_clipping array",
     clipping_decoy_field, RULES_X4, [],
     {"exit": 3, "status": None, "results": {}},
     {"exit": 1, "status": "FAIL", "results": {"X4": "FAIL"}}),
    ("mode_req_uint64", "1.11", "mode_req_global_position declared uint64_t, bit 36 set",
     mode_req_uint64, RULES, [],
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "failsafe_flags.mode_req_global_position is uint64_t in the log; PX4 defines uint32_t"}},
     {"exit": 1, "status": "FAIL", "results": {"R4": "FAIL"},
      "found": {"R4": "required failsafe_flags global_position_invalid true in flight"}}),
]


def baseline(params, firmware="1.17.0 " + GIT.decode()):
    lines = ["# Onboard parameters for Vehicle 1", "#", "# Firmware: " + firmware, "#",
             "# Vehicle-Id Component-Id Name Value Type"]
    for name in sorted(params):
        ty, v = params[name]
        lines.append("1\t1\t%s\t%s\t%d" % (name, v, 6 if ty == "i" else 9))
    return "\n".join(lines) + "\n"


def params_at_first_arm(data):
    """The parameters of a log at its first armed vehicle_status row, as baseline entries."""
    _, records = read_records(data)
    params, formats, subs, arming = {}, {}, {}, None
    for ty, body in records:
        if ty == "F":
            text = body.decode()
            formats[text.split(":", 1)[0]] = text
        elif ty == "A":
            subs[struct.unpack_from("<H", body, 1)[0]] = body[3:].decode()
        elif ty == "P":
            k = body[1:1 + body[0]].decode()
            t, name = k.split(" ", 1)
            raw = body[1 + body[0]:5 + body[0]]
            if t == "int32_t":
                params[name] = ("i", str(struct.unpack("<i", raw)[0]))
            else:
                params[name] = ("f", repr(struct.unpack("<f", raw)[0]))
        elif ty == "D":
            msg = struct.unpack_from("<H", body, 0)[0]
            if subs.get(msg) == "vehicle_status":
                fields = flat_offsets(formats["vehicle_status"], formats)
                off = fields.get("arming_state")
                if off and len(body) > 2 + off[0] and body[2 + off[0]] == 2:
                    break
    return params


def build(root):
    """{relative path: bytes} of the whole corpus."""
    files = {name: text.encode() for name, text in RULE_FILES.items()}
    manifest = []
    for name, item, what, builder, rules, opts, expect, control_expect in CASES:
        for control in (False, True):
            case = name + ("_control" if control else "")
            if builder is None:
                # ignore_all and ignore_union: a plain flight with one parameter off baseline, sealed with the
                # ignore-everything rules (the attack) or the plain rules (the control).
                data = bytes(flight().out)
                params = params_at_first_arm(data)
                params["MPC_XY_VEL_MAX"] = ("f", "9.5")
                case_rules = RULES if control else rules
            elif name.startswith("golden_"):
                data = builder(root, control)
                params = params_at_first_arm(data)
                case_rules = rules
            else:
                data = bytes(builder(control).out)
                params = params_at_first_arm(data)
                case_rules = RULES_R7_ALL if (control and rules == RULES_R7) else rules
            files[case + ".ulg"] = data
            files[case + ".params"] = baseline(params).encode()
            manifest.append({
                "case": case, "item": item, "kind": "control" if control else "attack",
                "what": what if not control else "control for " + name,
                "log": case + ".ulg", "rules": case_rules, "baseline": case + ".params",
                "options": opts, "expect": control_expect if control else expect,
            })
    files["cases.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    return files


def main():
    root = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    args = sys.argv[1:]
    check = args[:1] == ["--check"]
    if check:
        args = args[1:]
    if len(args) != 1:
        print(__doc__)
        return 2
    out = args[0]
    files = build(root)
    if check:
        bad = []
        for rel, data in sorted(files.items()):
            p = os.path.join(out, rel)
            if not os.path.exists(p) or open(p, "rb").read() != data:
                bad.append(rel)
        extra = sorted(set(f for f in os.listdir(out) if f not in files and f != "README.md")) \
            if os.path.isdir(out) else []
        for rel in bad:
            print("make_falsepass.py --check: %s differs from the generator" % rel)
        for rel in extra:
            print("make_falsepass.py --check: %s is not written by the generator" % rel)
        return 1 if bad or extra else 0
    os.makedirs(out, exist_ok=True)
    for rel, data in files.items():
        with open(os.path.join(out, rel), "wb") as f:
            f.write(data)
    return 0


if __name__ == "__main__":
    sys.exit(main())
