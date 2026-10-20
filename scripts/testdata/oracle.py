#!/usr/bin/env python3
"""Test-only oracle for Sealed Flight Record event extraction and core rules, on pyulog.

What it is: a second implementation of the event extraction and of R1, R4, R5, R6 and R7, in
Python, that reads logs with pyulog (the PX4 project's ULog parser) instead of sfr's own parser
and shares no code with sfr. It follows docs/SPEC.md B1.5/B1.6/B1.7, docs/RECORD_FORMAT.md (sealed
topic digests), docs/RULES.md and the PX4 message definitions. It is maintained in the same
repository by the same people as sfr, and it was changed together with sfr when the rules
changed, so it is a check on the parsing and on the arithmetic of the rules, not an independent
reading of what the rules should be. It is never part of sfr or a release
(scripts/testdata/requirements-dev.txt pins pyulog for tests only).
Usage: python3 -I oracle.py <log.ulg> <rules.toml> [--required vehicle_status,failsafe_flags]
       [--ptime literal|max] [--param-index all|data] [--debug]

The rules file gives the required topics (R1, together with every sealed topic), the payload
command ids (COMMAND category), [authorized_sources] (R7), the watched parameter names, and the
sealed topics. --required, when given, replaces the rules file's [required_topics] list.

Prints one JSON object (sorted keys, compact separators) to stdout.
Diagnostics (with --debug) go to stderr.
"""

import argparse
import bisect
import hashlib
import json
import struct
import sys
import tomllib

import numpy as np
from pyulog import ULog

P_TYPE = ord('P')

# --------------------------------------------------------------------------
# pyulog with a file-order trace of the records that have no topic
# --------------------------------------------------------------------------


class _TracingMessageData(ULog._MessageData):
    """Records the timestamp of every valid 'D' record, in file order."""

    def initialize(self, data, header, subscriptions, ulog_object):
        bad = super().initialize(data, header, subscriptions, ulog_object)
        if not bad:
            msg_id, = ULog._unpack_ushort(data[:2])
            if msg_id in subscriptions:
                ulog_object._sfr_lit_ts = self.timestamp
                ulog_object._sfr_data_count += 1
                sub = subscriptions[msg_id]
                if sub.message_name == 'vehicle_status':
                    ulog_object._sfr_vs_ordinals.setdefault(sub.multi_id, []).append(
                        ulog_object._sfr_data_count)
        return bad


class TracingULog(ULog):
    """ULog that also keeps, in file order: parameter key types, data-section
    'P' records with the literal last data timestamp before them, 'L'/'C'
    records with their combined ordinal, and 'O' records."""

    def __init__(self, path):
        self._sfr_in_data = False
        self._sfr_lit_ts = None          # timestamp of the last valid 'D' so far
        self._sfr_data_count = 0
        self._sfr_vs_ordinals = {}       # vehicle_status multi_id -> data-record ordinal of each row
        self._sfr_seen_add = False       # an 'A' record has been seen
        self._sfr_def_param_types = {}   # name -> key type, definitions-section 'P'
        self._sfr_def_param_count = 0    # number of definitions-section 'P'
        self._sfr_param_all_count = 0    # number of 'P' records so far, whole file
        self._sfr_params = []            # data-section 'P'
        self._sfr_logging = []           # 'L' and 'C', in file order
        self._sfr_dropouts = []          # 'O', in file order
        self._sfr_p_before_add = 0       # data-section 'P' before the first 'A'
        # Instance attributes shadow the nested classes pyulog instantiates via self.
        self._MessageInfo = self._sfr_info
        self.MessageLogging = self._sfr_msg_logging
        self.MessageLoggingTagged = self._sfr_msg_logging_tagged
        self.MessageDropout = self._sfr_msg_dropout
        self._MessageData = _TracingMessageData
        self._MessageAddLogged = self._sfr_add_logged
        super().__init__(path)

    def _read_file_data(self, message_name_filter_list, read_until=None):
        self._sfr_in_data = True
        return super()._read_file_data(message_name_filter_list, read_until)

    def _sfr_last_ts(self):
        return self._sfr_lit_ts if self._sfr_lit_ts is not None else self._start_timestamp

    def _sfr_info(self, data, header, is_info_multiple=False):
        info = ULog._MessageInfo(data, header, is_info_multiple)
        if header.msg_type == P_TYPE:
            ordinal_all = self._sfr_param_all_count
            self._sfr_param_all_count += 1
            if not self._sfr_in_data:
                self._sfr_def_param_types[info.key] = info.type
                self._sfr_def_param_count += 1
            else:
                if not self._sfr_seen_add:
                    self._sfr_p_before_add += 1
                self._sfr_params.append({
                    'ordinal_all': ordinal_all,
                    'ordinal_data': len(self._sfr_params),
                    'name': info.key,
                    'type': info.type,
                    'value': info.value,
                    'lit_ts': self._sfr_last_ts(),
                    'max_ts': self._last_timestamp,
                    'data_seen': self._sfr_data_count,
                })
        return info

    def _sfr_msg_logging(self, data, header):
        m = ULog.MessageLogging(data, header)
        self._sfr_logging.append({'ordinal': len(self._sfr_logging), 'kind': 'L',
                                  'level': m.log_level, 'tag': None,
                                  'ts': m.timestamp, 'text': m.message})
        return m

    def _sfr_msg_logging_tagged(self, data, header):
        m = ULog.MessageLoggingTagged(data, header)
        self._sfr_logging.append({'ordinal': len(self._sfr_logging), 'kind': 'C',
                                  'level': m.log_level, 'tag': m.tag,
                                  'ts': m.timestamp, 'text': m.message})
        return m

    def _sfr_msg_dropout(self, data, header, timestamp):
        m = ULog.MessageDropout(data, header, timestamp)
        self._sfr_dropouts.append({'ordinal': len(self._sfr_dropouts),
                                   'duration': m.duration,
                                   'lit_ts': self._sfr_last_ts(),
                                   'max_ts': timestamp})
        return m

    def _sfr_add_logged(self, data, header, message_formats):
        self._sfr_seen_add = True
        return ULog._MessageAddLogged(data, header, message_formats)


# --------------------------------------------------------------------------
# Value formatting
# --------------------------------------------------------------------------


def f32_str(v):
    x = np.float32(v)
    if np.isnan(x):
        return "NaN"
    if np.isinf(x):
        return "inf" if x > 0 else "-inf"
    return np.format_float_positional(x, unique=True, trim='-')


def typed_str(key_type, value):
    if key_type == 'int32_t':
        return "i32:%d" % int(value)
    if key_type == 'float':
        return "f32:" + f32_str(value)
    raise ValueError("unsupported parameter type %r" % key_type)


def decode_release(v):
    if v is None:
        return None
    v = int(v)
    major, minor, patch, typ = (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff
    s = "%d.%d.%d" % (major, minor, patch)
    if typ == 255:
        return s
    # 0, 64, 128, 192 per the task; values in between take the band below them
    # (same banding as pyulog get_version_info and PX4 version.c type ranges).
    if typ >= 192:
        return s + "-rc"
    if typ >= 128:
        return s + "-beta"
    if typ >= 64:
        return s + "-alpha"
    return s + "-dev"


RESULT_NAMES = {0: "ACCEPTED", 1: "TEMPORARILY_REJECTED", 2: "DENIED", 3: "UNSUPPORTED",
                4: "FAILED", 5: "IN_PROGRESS", 6: "CANCELLED"}

# failsafe_flags flag -> mode_req field
MODE_REQ = {
    'angular_velocity_invalid': 'mode_req_angular_velocity',
    'attitude_invalid': 'mode_req_attitude',
    'local_altitude_invalid': 'mode_req_local_alt',
    'local_position_invalid': 'mode_req_local_position',
    'local_position_invalid_relaxed': 'mode_req_local_position_relaxed',
    'global_position_invalid': 'mode_req_global_position',
    'global_position_invalid_relaxed': 'mode_req_global_position_relaxed',
    'auto_mission_missing': 'mode_req_mission',
    'offboard_control_signal_lost': 'mode_req_offboard_signal',
    'home_position_invalid': 'mode_req_home_position',
    'manual_control_signal_lost': 'mode_req_manual_control',
    'wind_limit_exceeded': 'mode_req_wind_and_flight_time_compliance',
    'flight_time_limit_exceeded': 'mode_req_wind_and_flight_time_compliance',
}

# The failsafe_flags booleans of PX4 v1.14 to v1.17 (msg/FailsafeFlags.msg).
PX4_FLAGS = {
    'angular_velocity_invalid', 'attitude_invalid', 'local_altitude_invalid',
    'local_position_invalid', 'local_position_invalid_relaxed', 'local_velocity_invalid',
    'global_position_invalid', 'global_position_invalid_relaxed', 'auto_mission_missing',
    'offboard_control_signal_lost', 'home_position_invalid', 'manual_control_signal_lost',
    'gcs_connection_lost', 'battery_low_remaining_time', 'battery_unhealthy',
    'primary_geofence_breached', 'geofence_breached', 'mission_failure',
    'vtol_fixed_wing_system_failure', 'wind_limit_exceeded', 'flight_time_limit_exceeded',
    'local_position_accuracy_low', 'position_accuracy_low', 'navigator_failure',
    'fd_critical_failure', 'fd_esc_arming_failure', 'fd_imbalanced_prop', 'fd_motor_failure',
}

VS_REQUIRED_FIELDS = ['timestamp', 'arming_state', 'nav_state', 'failsafe', 'is_vtol',
                      'in_transition_mode', 'in_transition_to_fw', 'vehicle_type']
FF_REQUIRED_FIELDS = ['timestamp']
# The vehicle_command fields R7 reads; R1 requires them when R7 is enabled (SPEC B1.6).
VC_R7_FIELDS = ['command', 'source_system', 'source_component']
# SPEC B1.6 R7: each of them must be an 8-, 16- or 32-bit unsigned integer to be read.
VC_R7_TYPES = ('uint8_t', 'uint16_t', 'uint32_t')


def vc_readable(d):
    """A vehicle_command instance whose three R7 fields exist with an allowed type."""
    types = {f.field_name: f.type_str for f in d.field_data}
    return all(types.get(f) in VC_R7_TYPES for f in VC_R7_FIELDS)


def warn(debug, *a):
    if debug:
        print(*a, file=sys.stderr)


# --------------------------------------------------------------------------
# Topic access
# --------------------------------------------------------------------------


def topic_instances(ulog, name, debug):
    insts = sorted([d for d in ulog.data_list if d.name == name], key=lambda d: d.multi_id)
    ids = [d.multi_id for d in insts]
    if len(ids) != len(set(ids)):
        warn(debug, "WARNING: topic %s has several subscriptions with one multi_id" % name)
    return insts


class Topic:
    """One topic instance as plain Python lists."""

    def __init__(self, d):
        self.name = d.name
        self.instance = d.multi_id
        self.types = {f.field_name: f.type_str for f in d.field_data}
        self.cols = {k: v.tolist() for k, v in d.data.items()}
        self.n = len(self.cols['timestamp']) if 'timestamp' in self.cols else len(next(iter(self.cols.values())))

    def has(self, f):
        return f in self.cols

    def __getitem__(self, f):
        return self.cols[f]


def is_monotonic(xs):
    return all(xs[i] <= xs[i + 1] for i in range(len(xs) - 1))


# --------------------------------------------------------------------------
# Rules file (SPEC B1.6), read with tomllib
# --------------------------------------------------------------------------


def load_rules(path):
    with open(path, 'rb') as f:
        doc = tomllib.load(f)
    # SPEC B1.6: an entry listed twice in one list is a rules file error.
    lists = [
        ('required_topics.topics', doc.get('required_topics', {}).get('topics', [])),
        ('parameters.ignore', doc.get('parameters', {}).get('ignore', [])),
        ('watched_parameters.names', doc.get('watched_parameters', {}).get('names', [])),
        ('sealed_topics.topics', doc.get('sealed_topics', {}).get('topics', [])),
        ('payload_commands.ids', doc.get('payload_commands', {}).get('ids', [])),
        ('authorized_sources.sources',
         [(s['system'], s['component'])
          for s in doc.get('authorized_sources', {}).get('sources', [])]),
    ]
    for name, items in lists:
        if len(set(items)) != len(items):
            raise SystemExit('oracle.py: %s lists an entry twice (SPEC B1.6)' % name)
    sources = None
    category = None
    if 'authorized_sources' in doc:
        sec = doc['authorized_sources']
        sources = {(int(s['system']), int(s['component'])) for s in sec.get('sources', [])}
        category = sec.get('category')
    return {
        'required_topics': list(doc.get('required_topics', {}).get('topics', [])),
        'watched': list(doc.get('watched_parameters', {}).get('names', [])),
        'sealed': list(doc.get('sealed_topics', {}).get('topics', [])),
        'payload_ids': {int(i) for i in doc.get('payload_commands', {}).get('ids', [])},
        'r7_enabled': 'authorized_sources' in doc,
        'r7_sources': sources,
        'r7_category': category,
    }


# --------------------------------------------------------------------------
# vtol_type (SPEC B1.5, log identity)
# --------------------------------------------------------------------------

VT_TYPE_NAMES = {0: 'tailsitter', 1: 'tiltrotor', 2: 'standard'}


def vtol_type_of(is_vtol, init_params, init_types):
    """Null when not VTOL; else VT_TYPE at log start as {value, name}."""
    if not is_vtol:
        return None
    if init_types.get('VT_TYPE') != 'int32_t' or 'VT_TYPE' not in init_params:
        return {'value': None, 'name': 'unknown'}
    n = int(init_params['VT_TYPE'])
    return {'value': n, 'name': VT_TYPE_NAMES.get(n, 'unknown(%d)' % n)}


# --------------------------------------------------------------------------
# Sealed topic digests (SPEC B1.5, docs/RECORD_FORMAT.md), from the raw ULog
# bytes with an own record reader. pyulog is not used here: it does not
# expose the raw payload bytes.
# --------------------------------------------------------------------------

ULOG_MAGIC = b'ULog\x01\x12\x35'
ULOG_HEADER_LEN = 16
BASIC_SIZES = {'int8_t': 1, 'uint8_t': 1, 'bool': 1, 'char': 1,
               'int16_t': 2, 'uint16_t': 2,
               'int32_t': 4, 'uint32_t': 4, 'float': 4,
               'int64_t': 8, 'uint64_t': 8, 'double': 8}
MAX_NESTING = 8   # SPEC B1.4: 8 levels of nested types below a subscribed format


def parse_format(text):
    """'<name>:<type> <field>;...' -> (name, [(base type, array length or None, field name)])."""
    name, _, body = text.partition(':')
    fields = []
    for part in body.split(';'):
        part = part.strip()
        if not part:
            continue
        ftype, fname = part.split()
        count = None
        if ftype.endswith(']') and '[' in ftype:
            ftype, _, n = ftype[:-1].partition('[')
            count = int(n)
        fields.append((ftype, count, fname))
    return name, fields


def type_size(tname, formats, depth=0):
    """Byte size of a basic type or of a nested format (formats: name -> parsed fields)."""
    if tname in BASIC_SIZES:
        return BASIC_SIZES[tname]
    if tname not in formats or depth > MAX_NESTING:
        raise ValueError('unknown or too deeply nested type %r' % tname)
    return sum(type_size(t, formats, depth + 1) * (c if c is not None else 1)
               for t, c, _ in formats[tname])


def timestamp_offset(topic, formats):
    """Offset of the topic's own top-level uint64 'timestamp' field in its flattened layout."""
    if topic not in formats:
        return None
    off = 0
    for t, c, fname in formats[topic]:
        if fname == 'timestamp':
            return off if (t == 'uint64_t' and c is None) else None
        off += type_size(t, formats) * (c if c is not None else 1)
    return None


def data_section_formats(path):
    """The number of 'F' records after the first 'A', read as sealed_topic_digests reads records."""
    with open(path, 'rb') as f:
        buf = f.read()
    n = len(buf)
    pos = ULOG_HEADER_LEN
    count = 0
    appended = []
    first = True
    in_data = False
    while pos + 3 <= n:
        size, typ = struct.unpack_from('<HB', buf, pos)
        end = pos + 3 + size
        if end > n:
            break
        if in_data and appended and end > appended[0]:
            pos = appended.pop(0)
            continue
        if first and typ == ord('B') and size >= 40 and buf[pos + 3 + 8] & 1:
            appended = [o for o in struct.unpack_from('<3Q', buf, pos + 3 + 16) if o != 0]
        first = False
        if typ == ord('A'):
            in_data = True
        elif typ == ord('F') and in_data:
            count += 1
        pos = end
    return count


def sealed_topic_digests(path, topics, debug):
    """docs/RECORD_FORMAT.md 'Sealed topic digests', procedure steps 1 to 4."""
    topics = set(topics)
    if not topics:
        return []
    with open(path, 'rb') as f:
        buf = f.read()
    if buf[:7] != ULOG_MAGIC or len(buf) < ULOG_HEADER_LEN:
        raise ValueError('%s: not a ULog file' % path)
    n = len(buf)
    mv = memoryview(buf)
    pos = ULOG_HEADER_LEN
    formats = {}          # name -> parsed fields, latest 'F' (for layouts, nested types included)
    fmt_sha = {}          # sealed name -> SHA-256 of its latest 'F' payload
    entries = {}          # (name, multi_id) -> entry state
    by_msg_id = {}        # msg_id -> entry state (or absent)
    appended = []         # ULog appended-data offsets still ahead
    first = True
    in_data = False       # past the first 'A' (the data section)
    while pos + 3 <= n:
        size, typ = struct.unpack_from('<HB', buf, pos)
        end = pos + 3 + size
        if end > n:
            warn(debug, 'sealed topics: truncated record at offset %d' % pos)
            break
        if in_data and appended and end > appended[0]:
            # ULog appended data: a record that crosses the offset is dropped; reading resumes there.
            pos = appended.pop(0)
            continue
        payload = mv[pos + 3:end]
        if first and typ == ord('B') and size >= 40:
            incompat0 = payload[8]
            offs = struct.unpack_from('<3Q', payload, 16)
            if incompat0 & 1:
                appended = [o for o in offs if o != 0]
        first = False
        if typ == ord('F'):
            raw = bytes(payload)
            name, fields = parse_format(raw.decode('utf-8'))
            formats[name] = fields
            if name in topics:
                fmt_sha[name] = hashlib.sha256(raw).hexdigest()
        elif typ == ord('A'):
            in_data = True
            multi_id = payload[0]
            msg_id, = struct.unpack_from('<H', payload, 1)
            mname = bytes(payload[3:]).decode('utf-8')
            if mname in topics:
                key = (mname, multi_id)
                e = entries.get(key)
                if e is None:
                    try:
                        ts_off = timestamp_offset(mname, formats)
                    except ValueError:
                        ts_off = None
                    e = {'topic': mname, 'multi_id': multi_id, 'format_sha256': fmt_sha.get(mname),
                         'count': 0, 'first': None, 'last': None, 'h': hashlib.sha256(),
                         'ts_off': ts_off}
                    entries[key] = e
                by_msg_id[msg_id] = e
            else:
                by_msg_id.pop(msg_id, None)
        elif typ == ord('D'):
            msg_id, = struct.unpack_from('<H', payload, 0)
            e = by_msg_id.get(msg_id)
            if e is not None:
                p = payload[2:]
                if e['ts_off'] is None:
                    e['ts_off'] = timestamp_offset(e['topic'], formats)
                t = None
                if e['ts_off'] is not None and e['ts_off'] + 8 <= len(p):
                    t, = struct.unpack_from('<Q', p, e['ts_off'])
                else:
                    warn(debug, 'sealed topics: no timestamp in %s record at offset %d' % (e['topic'], pos))
                e['count'] += 1
                if e['count'] == 1:
                    e['first'] = t
                e['last'] = t
                e['h'].update(struct.pack('<Q', len(p)))
                e['h'].update(p)
        pos = end
    out = []
    for e in entries.values():
        out.append({
            'topic': e['topic'],
            'multi_id': e['multi_id'],
            'format_sha256': e['format_sha256'],
            'message_count': e['count'],
            'first_timestamp_us': None if e['first'] is None else str(e['first']),
            'last_timestamp_us': None if e['last'] is None else str(e['last']),
            'data_sha256': e['h'].hexdigest(),
        })
    out.sort(key=lambda x: (x['topic'].encode('utf-8'), x['multi_id']))
    return out


# --------------------------------------------------------------------------
# Main extraction
# --------------------------------------------------------------------------


def run(path, rules, required, ptime, param_index, debug):
    # R1 (SPEC B1.6): the rules file lists the required topics, every sealed topic is required
    # too, and with [authorized_sources] so is vehicle_command. --required, when given,
    # replaces the rules file's list.
    if required is None:
        required = list(rules['required_topics'])
    extra = list(rules['sealed']) + (['vehicle_command'] if rules['r7_enabled'] else [])
    required = list(required) + [t for t in extra if t not in required]
    u = TracingULog(path)
    info = u.msg_info_dict
    warn(debug, "file_corruption", u.file_corruption, "data records", u._sfr_data_count)
    # pyulog ignores a format record in the data section and reads later subscriptions with the
    # earlier format, where sfr uses the new one; it drops the data after a record it cannot
    # parse. Such a log is outside this oracle's scope; no golden log has either.
    if u.file_corruption:
        print("oracle.py: pyulog reports file corruption in %s; this output is not a reference"
              % path, file=sys.stderr)
    redefined = data_section_formats(path)
    if redefined:
        print("oracle.py: %s has %d format record(s) in the data section, which pyulog ignores;"
              " this output is not a reference" % (path, redefined), file=sys.stderr)
    warn(debug, "data-section P before first A:", u._sfr_p_before_add)

    # ---- config and firmware
    init = u.initial_parameters
    types = u._sfr_def_param_types
    if set(init) != set(types):
        warn(debug, "WARNING: initial parameter names differ from traced types")
    config = {name: typed_str(types[name], init[name]) for name in init}
    firmware = {"release": decode_release(info.get('ver_sw_release')),
                "git": info.get('ver_sw')}

    # ---- topics
    vs_insts = topic_instances(u, 'vehicle_status', debug)
    ff_insts = topic_instances(u, 'failsafe_flags', debug)
    vc_insts = topic_instances(u, 'vehicle_command', debug)
    ack_insts = topic_instances(u, 'vehicle_command_ack', debug)
    vs = Topic(vs_insts[0]) if vs_insts else None
    vs_ordinals = u._sfr_vs_ordinals
    ff = Topic(ff_insts[0]) if ff_insts else None
    if len(vs_insts) > 1 or len(ff_insts) > 1:
        warn(debug, "WARNING: several vehicle_status / failsafe_flags instances; using the lowest")

    # ---- R1
    missing = set()
    present_topics = {d.name for d in u.data_list}
    for t in required:
        if t not in present_topics:
            missing.add(t)
    # vehicle_status and failsafe_flags are read by the core rules regardless of the list
    if vs is None:
        missing.add('vehicle_status')
    else:
        for f in VS_REQUIRED_FIELDS:
            if not vs.has(f):
                missing.add('vehicle_status.' + f)
    if ff is None:
        missing.add('failsafe_flags')
    else:
        for f in FF_REQUIRED_FIELDS:
            if not ff.has(f):
                missing.add('failsafe_flags.' + f)
    # With [authorized_sources], the vehicle_command fields R7 reads (SPEC B1.6 R1), in every
    # instance with data (pyulog lists only those).
    if rules['r7_enabled']:
        for d in vc_insts:
            for f in VC_R7_FIELDS:
                if f not in d.data:
                    missing.add('vehicle_command.' + f)

    events = []   # (sort key tuple, generation counter, event dict)
    gen = [0]

    def emit(ev):
        key = (int(ev['boot_us']), ev['topic'], ev['instance'], ev['index'])
        events.append((key, gen[0], ev))
        gen[0] += 1

    # ---- failsafe_flags helpers, per failsafe_flags instance
    def ff_helpers(ff):
        ff_ts = ff['timestamp'] if (ff is not None and ff.has('timestamp')) else []
        if ff_ts and not is_monotonic(ff_ts):
            warn(debug, "WARNING: failsafe_flags timestamps are not monotonic")
        bools = sorted(f for f, t in ff.types.items() if t == 'bool') if ff is not None else []

        def row_at(t):
            """Index of the latest failsafe_flags row with timestamp <= t, or None."""
            if not ff_ts:
                return None
            k = bisect.bisect_right(ff_ts, t) - 1
            return k if k >= 0 else None

        def flag_true(row, f):
            if f == 'battery_warning':
                return ff[f][row] > 0
            return ff[f][row] != 0

        def names():
            n = list(bools)
            if ff is not None and ff.has('battery_warning') and ff.types['battery_warning'] == 'uint8_t':
                n.append('battery_warning')
            return sorted(n)
        return row_at, flag_true, names

    ff_by_inst = {d.multi_id: Topic(d) for d in ff_insts}

    def ff_for(instance):
        """The failsafe_flags instance that attributes vehicle_status instance `instance`."""
        return ff_by_inst.get(instance, ff)

    # ---- vehicle_status driven events, one instance at a time
    is_vtol = any(Topic(d).has('is_vtol') and any(x != 0 for x in Topic(d)['is_vtol'])
                  for d in vs_insts)

    def instance_events(vs):
        st = {'armed_rows': [], 'intervals': [], 'vtol_open': None, 'vtol_abort': False,
              'quadchute_rows': [], 'arms': 0, 'disarms': 0, 'arm_ordinals': []}
        armed_rows = st['armed_rows']
        arm_events = []
        intervals = st['intervals']
        quadchute_rows = st['quadchute_rows']
        ff = ff_for(vs.instance)
        ff_row_at, flag_true, ff_flag_names = ff_helpers(ff)
        if not vs.has('timestamp'):
            return st
        ts = vs['timestamp']
        if not is_monotonic(ts):
            warn(debug, "WARNING: vehicle_status timestamps are not monotonic")
        has_arm = vs.has('arming_state')
        has_nav = vs.has('nav_state')
        has_fs = vs.has('failsafe')
        has_vtol = all(vs.has(f) for f in ('in_transition_mode', 'in_transition_to_fw', 'vehicle_type'))
        armed_prev = None
        nav_prev = None
        fs_prev = None
        vstate_prev = None
        last_set_flags = None
        last_arm_t = None

        def vstate(i):
            if vs['in_transition_mode'][i]:
                return 'TFW' if vs['in_transition_to_fw'][i] else 'TMC'
            return 'FW' if vs['vehicle_type'][i] == 2 else 'MC'

        for i in range(vs.n):
            t = ts[i]
            base = {'boot_us': str(t), 'topic': 'vehicle_status', 'instance': vs.instance, 'index': i}
            # ARM / DISARM
            if has_arm:
                armed = vs['arming_state'][i] == 2
                armed_rows.append(armed)
                kind = None
                initial = False
                if i == 0:
                    if armed:
                        kind, initial = 'ARM', True
                elif armed != armed_prev:
                    kind = 'ARM' if armed else 'DISARM'
                if kind == 'ARM':
                    reason = vs['latest_arming_reason'][i] if vs.has('latest_arming_reason') else None
                    emit(dict(base, kind='ARM', initial=initial, reason=reason))
                    last_arm_t = t
                    arm_events.append(t)
                    intervals.append([t, None])
                    st['arms'] += 1
                    st['arm_ordinals'].append(vs_ordinals.get(vs.instance, [None] * (i + 1))[i])
                elif kind == 'DISARM':
                    reason = vs['latest_disarming_reason'][i] if vs.has('latest_disarming_reason') else None
                    emit(dict(base, kind='DISARM', initial=False, reason=reason))
                    if intervals and intervals[-1][1] is None:
                        intervals[-1][1] = t
                    st['disarms'] += 1
                armed_prev = armed
            else:
                armed_rows.append(None)
            # NAV_STATE_CHANGE
            if has_nav:
                nav = vs['nav_state'][i]
                if i == 0:
                    emit(dict(base, kind='NAV_STATE_CHANGE', old=None, new=nav))
                elif nav != nav_prev:
                    emit(dict(base, kind='NAV_STATE_CHANGE', old=nav_prev, new=nav))
                nav_prev = nav
            # FAILSAFE_SET / FAILSAFE_CLEAR
            if has_fs:
                fs = vs['failsafe'][i] != 0
                edge = (i == 0 and fs) or (i > 0 and fs != fs_prev)
                if edge and fs:
                    flags = []
                    row = ff_row_at(t)
                    if row is not None:
                        if last_arm_t is not None:
                            ref = ff_row_at(last_arm_t)
                            if ref is None:
                                ref = 0
                        else:
                            ref = 0
                        nav_now = vs['nav_state'][i] if has_nav else None
                        for f in ff_flag_names():
                            if not flag_true(row, f):
                                continue
                            required_now = False
                            mr = MODE_REQ.get(f)
                            if mr is not None and ff.has(mr) and nav_now is not None and 0 <= nav_now < 32:
                                required_now = ((ff[mr][row] >> nav_now) & 1) == 1
                            new_since_arm = not flag_true(ref, f)
                            if required_now or new_since_arm:
                                flags.append(f)
                    if not flags:
                        flags = ['unattributed']
                    last_set_flags = flags
                    for f in flags:
                        emit(dict(base, kind='FAILSAFE_SET', flag=f))
                elif edge and not fs:
                    for f in (last_set_flags or ['unattributed']):
                        emit(dict(base, kind='FAILSAFE_CLEAR', flag=f))
                fs_prev = fs
            # VTOL transitions
            if has_vtol:
                cur = vstate(i)
                direction = {'TFW': 'to_fw', 'TMC': 'to_mc'}
                if i == 0:
                    if cur in direction:
                        emit(dict(base, kind='VTOL_TRANSITION_START', direction=direction[cur]))
                        st['vtol_open'] = direction[cur]
                elif cur != vstate_prev:
                    # SPEC B1.5: fixed wing straight to multicopter is a QUADCHUTE, not a transition.
                    if (vstate_prev, cur) == ('FW', 'MC'):
                        row = ff_row_at(t)
                        qc = None
                        if row is not None and ff.has('vtol_fixed_wing_system_failure'):
                            qc = bool(flag_true(row, 'vtol_fixed_wing_system_failure'))
                        emit(dict(base, kind='QUADCHUTE', vtol_fixed_wing_system_failure=qc))
                        quadchute_rows.append(i)
                    if vstate_prev in direction:
                        if (vstate_prev, cur) in (('TFW', 'FW'), ('TMC', 'MC')):
                            emit(dict(base, kind='VTOL_TRANSITION_END', direction=direction[vstate_prev]))
                        else:
                            emit(dict(base, kind='VTOL_TRANSITION_ABORT', direction=direction[vstate_prev]))
                            st['vtol_abort'] = True
                        st['vtol_open'] = None
                    if cur in direction:
                        emit(dict(base, kind='VTOL_TRANSITION_START', direction=direction[cur]))
                        st['vtol_open'] = direction[cur]
                vstate_prev = cur
        st['arm_pairs'] = list(zip([iv[0] for iv in intervals], st['arm_ordinals']))
        return st

    vs_topics = [Topic(d) for d in vs_insts]
    states = [instance_events(t) for t in vs_topics]

    # ---- COMMAND
    cmds = []
    for d in vc_insts:
        if not vc_readable(d):
            continue    # no COMMAND event without a readable command and source (SPEC B1.6 R7)
        tp = Topic(d)
        for i in range(tp.n):
            cmds.append({'ts': tp['timestamp'][i], 'inst': tp.instance, 'idx': i,
                         'command': tp['command'][i], 'ss': tp['source_system'][i],
                         'sc': tp['source_component'][i]})
    cmds.sort(key=lambda c: (c['ts'], c['inst'], c['idx']))
    acks = []
    for d in ack_insts:
        tp = Topic(d)
        if not is_monotonic(tp['timestamp']):
            warn(debug, "WARNING: vehicle_command_ack timestamps are not monotonic")
        for i in range(tp.n):
            acks.append({'ts': tp['timestamp'][i], 'inst': tp.instance, 'idx': i,
                         'command': tp['command'][i], 'result': tp['result'][i],
                         'ts_': tp['target_system'][i], 'tc': tp['target_component'][i]})
    acks.sort(key=lambda a: (a['ts'], a['inst'], a['idx']))
    used = set()
    for ci, c in enumerate(cmds):
        nxt = None
        for c2 in cmds[ci + 1:]:
            if (c2['command'], c2['ss'], c2['sc']) == (c['command'], c['ss'], c['sc']):
                nxt = c2
                break
        cands = []
        for ai, a in enumerate(acks):
            if ai in used:
                continue
            if a['command'] != c['command'] or a['ts'] < c['ts']:
                continue
            if nxt is not None and a['ts'] >= nxt['ts']:
                continue
            if a['ts_'] != c['ss'] or a['tc'] != c['sc']:
                continue
            cands.append(ai)
        finals = [ai for ai in cands if acks[ai]['result'] != 5]
        chosen = finals[0] if finals else (cands[0] if cands else None)
        if chosen is None:
            result = "NO_ACK"
        else:
            used.add(chosen)
            r = acks[chosen]['result']
            result = RESULT_NAMES.get(r, "RESULT_%d" % r)
        # SPEC B1.5: PAYLOAD when the command id is in [payload_commands], otherwise GENERAL.
        category = 'PAYLOAD' if c['command'] in rules['payload_ids'] else 'GENERAL'
        emit({'kind': 'COMMAND', 'boot_us': str(c['ts']), 'topic': 'vehicle_command',
              'instance': c['inst'], 'index': c['idx'], 'command': c['command'],
              'category': category,
              'source_system': c['ss'], 'source_component': c['sc'], 'result': result})

    # ---- PARAM_CHANGED_IN_FLIGHT
    # Every instance's armed intervals with the data-record ordinal of the arming row.
    all_intervals = []
    for st in states:
        for (a, d), (_, ordinal) in zip(st['intervals'], st['arm_pairs']):
            all_intervals.append((a, d, ordinal))

    def in_flight(t, data_seen=None):
        # Window: after the arming row (a later time, or the same time with the 'P' record
        # after that row in the file), at or before the DISARM time.
        for a, d, ordinal in all_intervals:
            after = a < t or (a == t and data_seen is not None and ordinal is not None
                              and data_seen >= ordinal)
            if after and (d is None or t <= d):
                return True
        return False

    last_known = dict(config)
    for p in u._sfr_params:
        new = typed_str(p['type'], p['value'])
        old = last_known.get(p['name'])
        t = p['lit_ts'] if ptime == 'literal' else p['max_ts']
        if p['lit_ts'] != p['max_ts']:
            warn(debug, "P %s lit_ts %d max_ts %d" % (p['name'], p['lit_ts'], p['max_ts']))
        if old != new:
            warn(debug, "P change %s %s -> %s at lit %d max %d in_flight(lit)=%s in_flight(max)=%s"
                 % (p['name'], old, new, p['lit_ts'], p['max_ts'],
                    in_flight(p['lit_ts']), in_flight(p['max_ts'])))
            if in_flight(t, p['data_seen']):
                idx = p['ordinal_all'] if param_index == 'all' else p['ordinal_data']
                emit({'kind': 'PARAM_CHANGED_IN_FLIGHT', 'boot_us': str(t), 'topic': 'ulog.parameter',
                      'instance': 0, 'index': idx, 'name': p['name'], 'old': old, 'new': new})
        last_known[p['name']] = new

    # ---- LOG_MESSAGE
    for m in u._sfr_logging:
        lvl = m['level'] - ord('0')
        if 0 <= lvl <= 4:
            emit({'kind': 'LOG_MESSAGE', 'boot_us': str(m['ts']), 'topic': 'ulog.logging',
                  'instance': 0, 'index': m['ordinal'], 'level': lvl, 'text': m['text']})

    # ---- LOG_DROPOUT
    for o in u._sfr_dropouts:
        t = o['lit_ts'] if ptime == 'literal' else o['max_ts']
        if o['lit_ts'] != o['max_ts']:
            warn(debug, "O lit_ts %d max_ts %d" % (o['lit_ts'], o['max_ts']))
        emit({'kind': 'LOG_DROPOUT', 'boot_us': str(t), 'topic': 'ulog.dropout',
              'instance': 0, 'index': o['ordinal'], 'duration_ms': o['duration']})

    events.sort(key=lambda e: (e[0], e[1]))
    ev_list = [e[2] for e in events]

    # ---- Rules
    # The types PX4 v1.14 to v1.17 give the vehicle_status fields the rules read
    # (msg/VehicleStatus.msg at the release tags, msg/versioned/ from v1.16).
    vs_types = {'arming_state': 'uint8_t', 'nav_state': 'uint8_t', 'failsafe': 'bool',
                'is_vtol': 'bool', 'in_transition_mode': 'bool', 'in_transition_to_fw': 'bool',
                'vehicle_type': 'uint8_t', 'system_type': 'uint8_t'}

    def vs_ok(fields):
        """Every instance has each field with PX4's type."""
        return bool(vs_topics) and all(t.has(f) and t.types.get(f) == vs_types.get(f, t.types.get(f))
                                       for t in vs_topics for f in fields)

    def ff_ok():
        """failsafe_flags flags as PX4 types them: the mode_req_* fields uint32, battery_warning
        uint8, each PX4 flag name bool."""
        for t in ff_by_inst.values():
            for f, ty in t.types.items():
                if f.startswith('mode_req_') and ty != 'uint32_t':
                    return False
                if f == 'battery_warning' and ty != 'uint8_t':
                    return False
                if f in PX4_FLAGS and ty != 'bool':
                    return False
        return bool(ff_by_inst)

    results = {}
    results['R1'] = 'FAIL' if missing else 'PASS'
    any_arm = any(st['arms'] or st['disarms'] for st in states)
    if vs is None:
        results['R4'] = results['R5'] = results['R6'] = 'FAIL'
    else:
        # R4 (SPEC B1.6): vehicle_status.failsafe never true from ARM through the sample that
        # disarms, no QUADCHUTE in that window, and no failsafe_flags flag the nav_state in
        # effect requires true in that window (its mode_req_* bit), on every instance. Missing
        # or mistyped input is FAIL; a log with no ARM and no DISARM is N/A (no armed flight).
        r4_fields = ['arming_state', 'nav_state', 'failsafe']
        if is_vtol:
            r4_fields += ['in_transition_mode', 'in_transition_to_fw', 'vehicle_type']
        if not vs_ok(r4_fields) or not ff_ok() or ff is None or ff.n == 0:
            results['R4'] = 'FAIL'
        elif not any_arm:
            results['R4'] = 'N/A'
        else:
            bad = False
            warned = False
            windows = []
            for t, st in zip(vs_topics, states):
                rows = st['armed_rows']
                win = [bool(rows[i]) or (i > 0 and bool(rows[i - 1])) for i in range(t.n)]
                qc = set(st['quadchute_rows']) if is_vtol else set()
                if any(win[i] and (t['failsafe'][i] != 0 or i in qc) for i in range(t.n)):
                    bad = True
                ts = t['timestamp']
                for i in range(t.n):
                    if win[i] and (i == 0 or not win[i - 1]):
                        windows.append([ts[i], ts[i]])
                    elif win[i]:
                        windows[-1][1] = ts[i]
            # Flags: every failsafe_flags instance, in any instance's window; nav_state from the
            # vehicle_status instance of the same number, else the lowest.
            by_num = {t.instance: t for t in vs_topics}
            for fft in ff_by_inst.values():
                nav_t = by_num.get(fft.instance, vs_topics[0])
                nav_ts, nav = nav_t['timestamp'], nav_t['nav_state']
                for k, tk in enumerate(fft['timestamp']):
                    if not any(a <= tk <= b for a, b in windows):
                        continue
                    j = bisect.bisect_right(nav_ts, tk) - 1
                    if j < 0:
                        continue
                    n = nav[j]
                    # Every bool field is a flag, and battery_warning above 0.
                    flags = [f for f, ty in fft.types.items() if ty == 'bool']
                    if fft.types.get('battery_warning') == 'uint8_t':
                        flags.append('battery_warning')
                    for flag in flags:
                        if fft[flag][k] == 0:
                            continue
                        req = MODE_REQ.get(flag)
                        if req and fft.has(req) and 0 <= n < 32 and (fft[req][k] >> n) & 1:
                            bad = True
                        else:
                            warned = True
            results['R4'] = 'FAIL' if bad else ('WARN' if warned else 'PASS')
        # R5: every ARM followed by a DISARM, per instance; no ARM and no DISARM is N/A.
        if not vs_ok(['arming_state']):
            results['R5'] = 'FAIL'
        elif not any_arm:
            results['R5'] = 'N/A'
        else:
            results['R5'] = 'FAIL' if any(st['armed_rows'] and st['armed_rows'][-1]
                                          or st['arms'] != st['disarms'] for st in states) else 'PASS'
        # R6
        vtol_types = range(19, 26)
        sys_typed = all(t.types.get('system_type', 'uint8_t') == 'uint8_t' for t in vs_topics)
        if not vs_ok(['is_vtol']) or not sys_typed:
            results['R6'] = 'FAIL'
        elif not is_vtol:
            sys_vtol = any(x in vtol_types for t in vs_topics if t.has('system_type')
                           for x in t['system_type'])
            results['R6'] = 'FAIL' if sys_vtol else 'N/A'
        elif not vs_ok(['in_transition_mode', 'in_transition_to_fw', 'vehicle_type']):
            results['R6'] = 'FAIL'
        else:
            results['R6'] = 'FAIL' if any(st['vtol_abort'] or st['vtol_open'] is not None
                                          for st in states) else 'PASS'

    # R7 (SPEC B1.6), authorized command sources, over the whole log (every COMMAND event).
    # N/A without [authorized_sources]. With `category`, only COMMAND events of that category
    # are checked. FAIL names each event whose (source system, source component) is not listed.
    # A rule whose input data is missing is FAIL (B1.6): no vehicle_command data record, or
    # vehicle_command without command, source_system or source_component, or with one of them
    # not an 8-, 16- or 32-bit unsigned integer.
    r7_unauthorized = []
    if not rules['r7_enabled']:
        results['R7'] = 'N/A'
    else:
        vc_fields_ok = bool(vc_insts) and all(
            'timestamp' in d.data and vc_readable(d) for d in vc_insts)
        for seq, e in enumerate(ev_list):
            if e['kind'] != 'COMMAND':
                continue
            if rules['r7_category'] is not None and e['category'] != rules['r7_category']:
                continue
            if (int(e['source_system']), int(e['source_component'])) not in rules['r7_sources']:
                r7_unauthorized.append(seq)
        results['R7'] = 'FAIL' if (r7_unauthorized or not vc_fields_ok) else 'PASS'
        warn(debug, "R7 vehicle_command input present:", vc_fields_ok,
             "unauthorized seqs:", r7_unauthorized)

    # Sealed topic digests (SPEC B1.5, docs/RECORD_FORMAT.md), from the raw file bytes.
    sealed = sealed_topic_digests(path, rules['sealed'], debug)
    if debug:
        # Cross-check the own record reader against pyulog: count and first and last timestamp.
        by_key = {(d.name, d.multi_id): d for d in u.data_list}
        for s in sealed:
            d = by_key.get((s['topic'], s['multi_id']))
            pts = d.data['timestamp'].tolist() if d is not None else []
            mine = (s['message_count'], s['first_timestamp_us'], s['last_timestamp_us'])
            theirs = (len(pts), str(pts[0]) if pts else None, str(pts[-1]) if pts else None)
            if mine != theirs:
                warn(debug, "sealed %s/%d: reader %s pyulog %s" % (s['topic'], s['multi_id'], mine, theirs))

    return {
        'config': config,
        'firmware': firmware,
        'is_vtol': bool(is_vtol),
        'vtol_type': vtol_type_of(is_vtol, init, types),
        'events': ev_list,
        'results': results,
        'missing': sorted(missing),
        'r7_unauthorized': r7_unauthorized,
        # SPEC B1.6: the record lists the [watched_parameters] names in config.watched_parameters
        # (sorted by name, byte order).
        'watched_parameters': sorted(rules['watched'], key=lambda x: x.encode('utf-8')),
        'sealed_topics': sealed,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log')
    ap.add_argument('rules', help="the rules file the log is sealed with (TOML, SPEC B1.6)")
    ap.add_argument('--required', default=None,
                    help="comma-separated required topics; replaces the rules file's "
                         "[required_topics] (sealed topics stay required)")
    ap.add_argument('--ptime', choices=['literal', 'max'], default='max',
                    help="time of 'P'/'O': timestamp of the last 'D' before it (literal) "
                         "or pyulog's running maximum (max)")
    ap.add_argument('--param-index', choices=['all', 'data'], default='all',
                    help="ulog.parameter index: ordinal among all 'P' in the file, or among "
                         "data-section 'P' only")
    ap.add_argument('--debug', action='store_true')
    a = ap.parse_args()
    required = None if a.required is None else [t for t in a.required.split(',') if t]
    obj = run(a.log, load_rules(a.rules), required, a.ptime, a.param_index, a.debug)
    sys.stdout.write(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    sys.stdout.write("\n")


if __name__ == '__main__':
    main()
