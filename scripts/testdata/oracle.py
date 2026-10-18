#!/usr/bin/env python3
"""Independent oracle for Sealed Flight Record event extraction and core rules.

Written only from docs/SPEC.md B1.5/B1.6 and docs/DIAGNOSTIC.md items 4, 5, 6.
Usage: python3 -I oracle.py <log.ulg> [--required vehicle_status,failsafe_flags]
       [--ptime literal|max] [--param-index all|data] [--debug]

Prints one JSON object (sorted keys, compact separators) to stdout.
Diagnostics (with --debug) go to stderr.
"""

import argparse
import bisect
import json
import sys

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
        return bad


class TracingULog(ULog):
    """ULog that also keeps, in file order: parameter key types, data-section
    'P' records with the literal last data timestamp before them, 'L'/'C'
    records with their combined ordinal, and 'O' records."""

    def __init__(self, path):
        self._sfr_in_data = False
        self._sfr_lit_ts = None          # timestamp of the last valid 'D' so far
        self._sfr_data_count = 0
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

# failsafe_flags flag -> mode_req field (DIAGNOSTIC 4.5)
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

VS_REQUIRED_FIELDS = ['timestamp', 'arming_state', 'nav_state', 'failsafe', 'is_vtol',
                      'in_transition_mode', 'in_transition_to_fw', 'vehicle_type']
FF_REQUIRED_FIELDS = ['timestamp']


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
# Main extraction
# --------------------------------------------------------------------------


def run(path, required, ptime, param_index, debug):
    u = TracingULog(path)
    info = u.msg_info_dict
    warn(debug, "file_corruption", u.file_corruption, "data records", u._sfr_data_count)
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

    events = []   # (sort key tuple, generation counter, event dict)
    gen = [0]

    def emit(ev):
        key = (int(ev['boot_us']), ev['topic'], ev['instance'], ev['index'])
        events.append((key, gen[0], ev))
        gen[0] += 1

    # ---- failsafe_flags helpers
    ff_ts = ff['timestamp'] if (ff is not None and ff.has('timestamp')) else []
    if ff_ts and not is_monotonic(ff_ts):
        warn(debug, "WARNING: failsafe_flags timestamps are not monotonic")
    ff_bool_flags = []
    if ff is not None:
        ff_bool_flags = sorted(f for f, t in ff.types.items() if t == 'bool')

    def ff_row_at(t):
        """Index of the latest failsafe_flags row with timestamp <= t, or None."""
        if not ff_ts:
            return None
        k = bisect.bisect_right(ff_ts, t) - 1
        return k if k >= 0 else None

    def flag_true(row, f):
        if f == 'battery_warning':
            return ff[f][row] > 0
        return ff[f][row] != 0

    def ff_flag_names():
        names = list(ff_bool_flags)
        if ff is not None and ff.has('battery_warning'):
            names.append('battery_warning')
        return sorted(names)

    # ---- vehicle_status driven events
    armed_rows = []          # per row: armed bool (None if unknown)
    arm_events = []          # ARM times, in order
    intervals = []           # [t_arm, t_disarm or None]
    vtol_open = None         # direction of the open transition
    vtol_abort = False
    is_vtol = False
    if vs is not None and vs.has('timestamp'):
        ts = vs['timestamp']
        if not is_monotonic(ts):
            warn(debug, "WARNING: vehicle_status timestamps are not monotonic")
        has_arm = vs.has('arming_state')
        has_nav = vs.has('nav_state')
        has_fs = vs.has('failsafe')
        has_vtol = all(vs.has(f) for f in ('in_transition_mode', 'in_transition_to_fw', 'vehicle_type'))
        if vs.has('is_vtol'):
            is_vtol = any(x != 0 for x in vs['is_vtol'])
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
                elif kind == 'DISARM':
                    reason = vs['latest_disarming_reason'][i] if vs.has('latest_disarming_reason') else None
                    emit(dict(base, kind='DISARM', initial=False, reason=reason))
                    if intervals and intervals[-1][1] is None:
                        intervals[-1][1] = t
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
                        vtol_open = direction[cur]
                elif cur != vstate_prev:
                    # SPEC B1.5: fixed wing straight to multicopter is a QUADCHUTE, not a transition.
                    if (vstate_prev, cur) == ('FW', 'MC'):
                        row = ff_row_at(t)
                        qc = None
                        if row is not None and ff.has('vtol_fixed_wing_system_failure'):
                            qc = bool(flag_true(row, 'vtol_fixed_wing_system_failure'))
                        emit(dict(base, kind='QUADCHUTE', vtol_fixed_wing_system_failure=qc))
                    if vstate_prev in direction:
                        if (vstate_prev, cur) in (('TFW', 'FW'), ('TMC', 'MC')):
                            emit(dict(base, kind='VTOL_TRANSITION_END', direction=direction[vstate_prev]))
                        else:
                            emit(dict(base, kind='VTOL_TRANSITION_ABORT', direction=direction[vstate_prev]))
                            vtol_abort = True
                        vtol_open = None
                    if cur in direction:
                        emit(dict(base, kind='VTOL_TRANSITION_START', direction=direction[cur]))
                        vtol_open = direction[cur]
                vstate_prev = cur

    # ---- COMMAND
    cmds = []
    for d in vc_insts:
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
        emit({'kind': 'COMMAND', 'boot_us': str(c['ts']), 'topic': 'vehicle_command',
              'instance': c['inst'], 'index': c['idx'], 'command': c['command'],
              'source_system': c['ss'], 'source_component': c['sc'], 'result': result})

    # ---- PARAM_CHANGED_IN_FLIGHT
    def in_flight(t):
        # Window: strictly after the ARM time, at or before the DISARM time.
        for a, d in intervals:
            if a < t and (d is None or t <= d):
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
            if in_flight(t):
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
    results = {}
    results['R1'] = 'FAIL' if missing else 'PASS'
    if vs is None:
        results['R4'] = results['R5'] = results['R6'] = 'FAIL'
    else:
        # R4: a failsafe row inside an armed interval [ARM row, DISARM row)
        if vs.has('arming_state') and vs.has('failsafe'):
            r4 = 'PASS'
            for i in range(vs.n):
                if armed_rows[i] and vs['failsafe'][i] != 0:
                    r4 = 'FAIL'
                    break
            results['R4'] = r4
        else:
            results['R4'] = 'FAIL'
        # R5: log must not end armed
        if vs.has('arming_state') and vs.n > 0:
            results['R5'] = 'FAIL' if armed_rows[-1] else 'PASS'
        else:
            results['R5'] = 'FAIL'
        # R6
        if not vs.has('is_vtol'):
            results['R6'] = 'FAIL'
        elif not is_vtol:
            results['R6'] = 'N/A'
        elif not all(vs.has(f) for f in ('in_transition_mode', 'in_transition_to_fw', 'vehicle_type')):
            results['R6'] = 'FAIL'
        else:
            results['R6'] = 'FAIL' if (vtol_abort or vtol_open is not None) else 'PASS'

    return {
        'config': config,
        'firmware': firmware,
        'is_vtol': bool(is_vtol),
        'events': ev_list,
        'results': results,
        'missing': sorted(missing),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('log')
    ap.add_argument('--required', default='vehicle_status,failsafe_flags')
    ap.add_argument('--ptime', choices=['literal', 'max'], default='max',
                    help="time of 'P'/'O': timestamp of the last 'D' before it (literal) "
                         "or pyulog's running maximum (max)")
    ap.add_argument('--param-index', choices=['all', 'data'], default='all',
                    help="ulog.parameter index: ordinal among all 'P' in the file, or among "
                         "data-section 'P' only")
    ap.add_argument('--debug', action='store_true')
    a = ap.parse_args()
    required = [t for t in a.required.split(',') if t]
    obj = run(a.log, required, a.ptime, a.param_index, a.debug)
    sys.stdout.write(json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    sys.stdout.write("\n")


if __name__ == '__main__':
    main()
