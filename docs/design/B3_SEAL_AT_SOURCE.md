# B3: seal at the source

Design only; not built. The weakest interval in the system is the one before the seal: from the vehicle's disarm to the moment a key signs the log. In that interval anyone with access to the log file can change it, and the seal then covers the changed file ([THREAT_MODEL.md](../THREAT_MODEL.md), "What a record does not prove"). The guidance today is to seal soon and to keep the key off the vehicle where possible ([INTEGRATION_NOTES.md](../INTEGRATION_NOTES.md)). This page designs sealing on the vehicle's companion computer, triggered by the disarm itself, and a record of how long the unsealed interval was.

## What it would add, and what it would not

It would add:

- A hook that seals the log at the disarm edge, with the key in the companion computer's TPM, so the interval shrinks from "whenever someone gets to a ground station" to seconds.
- Times in the record for each step, so the interval is measured, not assumed, and printed by `verify` and in the report.

It would not add:

- *Protection from a compromised companion computer.* That computer sees the log, holds the key's use, and sets the times. A compromised vehicle produces a signed record of what the compromised vehicle says.
- *Protection from the flight controller.* PX4 writes the log; if the flight controller is wrong or hostile, the log is.
- *A proven clock.* The times in the record are the companion computer's clock (see B1).

## Design

### The trigger

The hook is a small separate program on the companion computer (not part of `sfr`; it calls `sfr seal`). It reads the vehicle's MAVLink 2 stream:

1. It watches `HEARTBEAT` (message id zero) from the flight controller. The `base_mode` field carries `MAV_MODE_FLAG_SAFETY_ARMED` (bit value 128). A change from set to clear is the disarm edge. The hook records `t_edge_seen`, its own clock when it saw the edge.
2. It waits for the flight controller's logger to close the file. PX4's logger keeps writing for a short time after disarm (the `SDLOG_MODE` and related parameters decide), and appends when the log is later continued (below).
3. It obtains the log: from a mounted card, or over MAVLink (`LOG_ENTRY` and `LOG_REQUEST_DATA`) or MAVLink FTP. It records `t_transfer_done`.
4. It runs `sfr seal` with the vehicle's TPM-sealed key (`--key-uri tpm-sealed:<dir>`, already supported), the rules and the baseline for that airframe.

### ULog appended data

The ULog format lets a logger continue an existing file after a restart. The flag bits message near the start of the file marks it: the incompatibility flag `DATA_APPENDED` (the lowest bit of the first incompatibility byte) says data was appended, and `appended_offsets` gives the byte positions where the appended sections begin. `sfr` already reads both ([RECORD_FORMAT.md](../RECORD_FORMAT.md)). A log that was appended to was written in more than one session, and the hook must treat it as worth a note rather than as ordinary:

- If `DATA_APPENDED` is set, or any `appended_offsets` entry is non-zero, when the hook obtains the log, the hook records that, and the report says "this log contains appended data from a later session".
- A file that grows after it was sealed is not detected by the seal; it is detected the next time someone runs `verify --ulog`, which fails on the digest. The hook keeps the length it sealed and refuses to seal a file under the same name that is shorter than one it has already sealed.

### What goes into the record

New members of the seal context (a new schema version; the record stays one signed object):

| Member | Meaning |
|---|---|
| `airframe_id` | the vehicle identifier: the MAVLink system id, the board's unique id from the autopilot (`AUTOPILOT_VERSION.uid`), and the airframe name; so a record names which vehicle sealed it. Declared by the hook, from the flight controller; not proven. |
| `t_disarm` | the disarm time as the log gives it (the `vehicle_status` sample where `arming_state` leaves armed), in log time |
| `t_edge_seen` | the companion clock when the hook saw the heartbeat edge |
| `t_transfer_done` | the companion clock when the log was fully received |
| `t_seal` | the existing seal time, the companion clock |
| `hook` | the hook's name and version, so a record shows it came through the hook and not from `sfr seal` by hand |

`verify` prints the gaps it can compute and labels each one's source:

```text
gap       edge seen 3 s after the disarm sample, log complete 41 s later, sealed 2 s after that (companion clock; the log's own clock for the disarm)
```

The report states the same sentence under the seal section. If any time is missing (a record sealed by hand), it prints `gap       not measured: sealed by hand, not by the disarm hook`.

### The measured gap is a label, not a gate

The record cannot prove the log is unchanged in the measured gap; it states how long the window was. A policy (for example, "reject a record whose gap is over a minute") is the verifier's own and is not enforced by `sfr`; `verify` offers `--max-gap <seconds>` for those who want it, and says what it checked.

## Standards and formats relied on

MAVLink 2 (`HEARTBEAT`, `LOG_ENTRY`, `LOG_REQUEST_DATA`, `AUTOPILOT_VERSION`, and the FTP microservice), the ULog file format (the `FLAG_BITS` message and `appended_offsets`), the PX4 logger's documented behaviour at disarm, and, for the key, the TPM sealing already in `sfr` (`keygen --tpm-sealed`).

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| The heartbeat edge is missed (link loss, the hook restarted) | No `t_edge_seen`, a late seal | The hook also polls `vehicle_status` in the log; `gap` says the edge was not seen. |
| Several arm and disarm cycles in one log | The first disarm does not end the flight | The hook seals only when the logger closes the file; the report lists every arm and disarm event as it does today. |
| The log is not closed (power cut) | No seal at the edge | The hook seals the partial file at the next start and says so in `gap`. |
| The companion clock is wrong | Wrong times | They are labelled as the companion clock; B1 adds an outside time. |
| The hook is stopped or replaced | Records without the `hook` member, or with a different version | Visible in the record; a verifier may require the hook. |
| An attacker with shell access edits the log between transfer and seal | Sealed as edited | The window is seconds and is stated; this is the compromised-companion case above. |
| The key is on the vehicle and the vehicle is lost | The key goes with it | One key per vehicle, as already advised; a TPM-sealed key does not leave the TPM. |

## Size

Medium to large, mostly outside `sfr`. The hook is a few hundred lines in a language with a MAVLink library; the `sfr` side is a schema bump with the new members, their report and verify lines, and `--max-gap`. Testing needs PX4 SITL with a companion process, which the repository already uses for its logs. About four engineer-weeks, with a further two for field trials on real hardware (not available to the author of this page).
