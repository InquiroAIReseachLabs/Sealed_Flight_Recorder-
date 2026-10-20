# ulog_version_2.ulg

Synthetic. Written by `scripts/testdata/make_synthetic_logs.py` (Python standard library only); not a flight and not a third-party log. Regenerate with:

```
python3 -I scripts/testdata/make_synthetic_logs.py testdata/synthetic
```

The same complete flight as `cut_control.ulg`, with file format version 2 in byte 7 of the file header. The ULog file format specification (`docs/en/dev_log/ulog_file_format.md` in PX4-Autopilot at commit `d28a64240f7b7570d65776b9b6397eddec0dd9ba`) gives the current version as 1 (line 65) and asks a parser to parse future or unknown file format versions as well, with a warning if it likes (line 475). `sfr` reads it as version 1, but `seal` refuses it (exit 4, nothing written) unless given `--allow-untested-version`; then the record (schema 5, `seal.allow_untested_ulog_version` true, `log.ulog_version` 2) and its report say `Untested ULog file version`.

`vehicle_status` and `failsafe_flags` use PX4 field names and types for a multicopter with one sample of each per second of boot time, from 1 s to 8 s: armed from 2 s, disarmed at 7 s, never in failsafe; firmware is reported as v1.17.0. Its data records start at byte 576 and alternate `failsafe_flags` (14 bytes) and `vehicle_status` (23 bytes); the last `vehicle_status` record, at boot_us 8000000, starts at byte 849.

Expected: PASS, exit 0, sealed with `--allow-untested-version`; refused, exit 4, without it; schema 5.

| Field | Value |
|---|---|
| SHA-256 | `e7a793032fd799003fd5dda796a1b1bc1910e07cabf25f7b4f74aae835c48ef8` |
| Size | 872 bytes |
