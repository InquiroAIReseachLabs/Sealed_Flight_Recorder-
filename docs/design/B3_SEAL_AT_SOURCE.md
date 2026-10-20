# B3: seal at the source

Design only; not built. The weakest interval is the one before the seal: from disarm to the moment a key signs the log. In that interval anyone with access to the file can change it, and the seal then covers the changed file ([THREAT_MODEL.md](../THREAT_MODEL.md)). Today's guidance is to seal soon and keep the key off the vehicle where possible ([INTEGRATION_NOTES.md](../INTEGRATION_NOTES.md)). This page designs sealing on the companion computer, triggered by the disarm, and a record of how long the unsealed interval was.

## What it adds, and what it does not

It adds a hook that seals at the disarm edge with the key in the companion computer's TPM, so the interval shrinks to seconds, and a time in the record for each step, so the interval is measured and `verify` and the report print it.

It does not add:

- *Protection from a compromised companion computer.* It sees the log, can use the key, and sets the times.
- *Protection from the flight controller.* If PX4 writes a wrong log, the log is wrong.
- *A proven clock.* The times are the companion computer's clock (see B1).

## Design

### The trigger

The hook is a small separate program on the companion computer, not part of `sfr`; it calls `sfr seal`. It reads the vehicle's MAVLink 2 stream:

1. It watches `HEARTBEAT` from the flight controller. `base_mode` carries `MAV_MODE_FLAG_SAFETY_ARMED` (bit value 128). Set to clear is the disarm edge; the hook records its own clock as `t_edge_seen`.
2. It waits for the logger to close the file. PX4's logger keeps writing briefly after disarm (`SDLOG_MODE` and related parameters decide).
3. It gets the log from a mounted card, over MAVLink (`LOG_ENTRY`, `LOG_REQUEST_DATA`) or MAVLink FTP, and records `t_transfer_done`.
4. It runs `sfr seal` with the vehicle's TPM-sealed key (`--key-uri tpm-sealed:<dir>`, already supported) and the rules and baseline for that airframe.

### ULog appended data

A logger can continue an existing ULog after a restart. The flag bits message marks it: the incompatibility flag `DATA_APPENDED` says data was appended, and `appended_offsets` gives where. `sfr` already reads both ([RECORD_FORMAT.md](../RECORD_FORMAT.md)). If either shows appended data, the hook records it and the report says "this log contains appended data from a later session". A file that grows after sealing is caught by the next `verify --ulog`, which fails on the digest; the hook also refuses to seal a file shorter than one it already sealed under the same name.

### What goes into the record

New members of the seal context (a new schema version):

| Member | Meaning |
|---|---|
| `airframe_id` | MAVLink system id, the board's unique id (`AUTOPILOT_VERSION.uid`) and the airframe name, declared by the hook; not proven |
| `t_disarm` | the disarm time in log time (the `vehicle_status` sample where `arming_state` leaves armed) |
| `t_edge_seen`, `t_transfer_done`, `t_seal` | companion clock at each step |
| `hook` | the hook's name and version, so a record shows it did not come from `sfr seal` by hand |

`verify` prints the gaps it can compute and the clock each comes from:

```text
gap       edge seen 3 s after the disarm sample, log complete 41 s later, sealed 2 s after that (companion clock; the log's own clock for the disarm)
gap       not measured: sealed by hand, not by the disarm hook
```

The gap is a label, not a gate. A policy such as "reject a gap over a minute" is the verifier's; `verify --max-gap <seconds>` offers it and says what it checked.

## Standards and formats

MAVLink 2 (`HEARTBEAT`, `LOG_ENTRY`, `LOG_REQUEST_DATA`, `AUTOPILOT_VERSION`, FTP), the ULog format (`FLAG_BITS`, `appended_offsets`), PX4's documented logger behaviour at disarm, and the TPM sealing already in `sfr` (`keygen --tpm-sealed`).

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Heartbeat edge missed | No `t_edge_seen`, late seal | The hook also polls `vehicle_status` in the log; `gap` says the edge was not seen. |
| Several arm and disarm cycles in one log | The first disarm does not end the flight | The hook seals only when the logger closes the file. |
| Log not closed (power cut) | No seal at the edge | The hook seals the partial file at next start and says so in `gap`. |
| Companion clock wrong | Wrong times | Labelled as the companion clock; B1 adds an outside time. |
| Shell access edits the log between transfer and seal | Sealed as edited | The window is seconds and stated; this is the compromised-companion case. |

## Size

Medium to large, mostly outside `sfr`. The hook is a few hundred lines in a language with a MAVLink library. The `sfr` side is a schema bump, the new members with their report and verify lines, and `--max-gap`. Testing needs PX4 SITL with a companion process, which the repository already uses for its logs. About four engineer-weeks, plus two for field trials on real hardware, which the author of this page does not have.
