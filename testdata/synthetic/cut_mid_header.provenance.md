# cut_mid_header.ulg

Synthetic. Written by `scripts/testdata/make_synthetic_logs.py` (Python standard library only); not a flight and not a third-party log. Regenerate with:

```
python3 -I scripts/testdata/make_synthetic_logs.py testdata/synthetic
```

`vehicle_status` and `failsafe_flags` use PX4 field names and types for a multicopter with one sample of each per second of boot time, from 1 s to 8 s: armed from 2 s, disarmed at 7 s, never in failsafe; firmware is reported as v1.17.0. Its data records start at byte 576 and alternate `failsafe_flags` (14 bytes) and `vehicle_status` (23 bytes); the last `vehicle_status` record, at boot_us 8000000, starts at byte 849.

This log is `cut_control.ulg` cut 2 bytes into the 3-byte header of that last record. The ULog file format specification (`docs/en/dev_log/ulog_file_format.md` in PX4-Autopilot at commit `d28a64240f7b7570d65776b9b6397eddec0dd9ba`, lines 477 and 478): a parser must be able to handle a log that ends abruptly, in the middle of a message, and the unfinished message should be discarded. `sfr` reads every record before byte 849, and the record and report state `log ended mid-record at byte 849; 2 trailing bytes not parsed`.

Expected: PASS, exit 0; R5 1 ARM, 1 DISARM; schema 5, `log.truncated` offset 849, 2 trailing bytes.

| Field | Value |
|---|---|
| SHA-256 | `9bec748e3aae4b4ef24c34e049a973928f330770a00d3e925c1822b9ad40abe7` |
| Size | 851 bytes |
