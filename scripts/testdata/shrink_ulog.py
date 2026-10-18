#!/usr/bin/env python3
"""Write a small but complete ULog from a large one, for fuzz seeds.

Usage: python3 -I shrink_ulog.py <in.ulg> <out.ulg> [--every N] [--no-multi-info] [--keep TOPIC]...

Copies the 16-byte header and every record unchanged, except data ('D') records: all rows of
the topics the events read (vehicle_status, failsafe_flags, vehicle_command,
vehicle_command_ack) are kept, every Nth row (default 20) of the topics the optional rules
read and of each topic named with --keep, and no rows of any other topic. With
--no-multi-info, 'M' records (perf counters and other blobs) are dropped too. The output
parses to the end, so a fuzzer starting from it
reaches the event and rule code instead of stopping at a truncated record. Logs with
appended data (flag bits) are refused, because dropping records would move the offsets.
Standard library only.
"""
import struct
import sys

KEEP_ALL = {"vehicle_status", "failsafe_flags", "vehicle_command", "vehicle_command_ack"}
KEEP_SOME = {"vehicle_gps_position", "sensor_gps", "battery_status", "estimator_status",
             "estimator_selector_status", "vehicle_imu_status", "sensor_selection"}


def main():
    args = sys.argv[1:]
    every = 20
    no_multi = "--no-multi-info" in args
    args = [a for a in args if a != "--no-multi-info"]
    keep_some = set(KEEP_SOME)
    while "--keep" in args:
        i = args.index("--keep")
        keep_some.add(args[i + 1])
        del args[i:i + 2]
    if "--every" in args:
        i = args.index("--every")
        every = int(args[i + 1])
        del args[i:i + 2]
    if len(args) != 2:
        print(__doc__)
        return 2
    data = open(args[0], "rb").read()
    out = bytearray(data[:16])
    if data[:7] != b"ULog\x01\x12\x35":
        raise SystemExit("not a ULog file")
    pos = 16
    topics = {}
    counts = {}
    while pos + 3 <= len(data):
        size, ty = struct.unpack_from("<HB", data, pos)
        end = pos + 3 + size
        if end > len(data):
            break
        body = data[pos + 3:end]
        keep = True
        if ty == ord("B") and body[8] & 1:
            raise SystemExit("log has appended data; not supported")
        if ty == ord("A"):
            msg_id = struct.unpack_from("<H", body, 1)[0]
            topics[msg_id] = body[3:].decode("ascii", "replace")
        elif ty == ord("D"):
            msg_id = struct.unpack_from("<H", body, 0)[0]
            topic = topics.get(msg_id)
            n = counts.get(msg_id, 0)
            counts[msg_id] = n + 1
            keep = topic in KEEP_ALL or (topic in keep_some and n % every == 0)
        elif ty == ord("M") and no_multi:
            keep = False
        if keep:
            out += data[pos:end]
        pos = end
    open(args[1], "wb").write(out)
    print(f"{args[0]}: {len(data)} bytes -> {args[1]}: {len(out)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
