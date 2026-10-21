# cut_mid_message.ulg

Synthetic. Written by `scripts/testdata/make_synthetic_logs.py` (Python standard library only); not a flight and not a third-party log. Regenerate with:

```
python3 -I scripts/testdata/make_synthetic_logs.py testdata/synthetic
```

`vehicle_status` and `failsafe_flags` use PX4 field names and types for a multicopter with one sample of each per second of boot time, from 1 s to 8 s: armed from 2 s, disarmed at 7 s, never in failsafe; firmware is reported as v1.17.0. Its data records start at byte 1758 and alternate `failsafe_flags` (96 bytes) and `vehicle_status` (23 bytes); the last `vehicle_status` record, at boot_us 8000000, starts at byte 2687.

This log is `cut_control.ulg` cut 7 bytes into the payload of that last record: the 3-byte header and 7 of its 20 payload bytes remain. The ULog file format specification (`docs/en/dev_log/ulog_file_format.md` in PX4-Autopilot at commit `d28a64240f7b7570d65776b9b6397eddec0dd9ba`, lines 477 and 478): a parser must be able to handle a log that ends abruptly, in the middle of a message, and the unfinished message should be discarded. `sfr` reads every record before byte 2687, after the DISARM, and the record and report state `log ended mid-record at byte 2687; 10 trailing bytes not parsed`.

Expected: PASS, exit 0; R5 1 ARM, 1 DISARM; schema 5, `log.truncated` offset 2687, 10 trailing bytes.

| Field | Value |
|---|---|
| SHA-256 | `b243536a24f7b284ec0a25aa7fe1e9845a4111117bf458e3bc84e6efb910aa14` |
| Size | 859 bytes |
