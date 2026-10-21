# cut_control.ulg

Synthetic. Written by `scripts/testdata/make_synthetic_logs.py` (Python standard library only); not a flight and not a third-party log. Regenerate with:

```
python3 -I scripts/testdata/make_synthetic_logs.py testdata/synthetic
```

The complete flight the three `cut_*` logs are cut from, and their control: it ends at a record boundary, so it is a complete log, sealed as schema 4.

`vehicle_status` and `failsafe_flags` use PX4 field names and types for a multicopter with one sample of each per second of boot time, from 1 s to 8 s: armed from 2 s, disarmed at 7 s, never in failsafe; firmware is reported as v1.17.0. Its data records start at byte 1758 and alternate `failsafe_flags` (96 bytes) and `vehicle_status` (23 bytes); the last `vehicle_status` record, at boot_us 8000000, starts at byte 2687.

Expected: PASS, exit 0; R5 1 ARM, 1 DISARM.

| Field | Value |
|---|---|
| SHA-256 | `70fabfd41bb9602e2616407e96672801aa6016f06d9d46459c80184ece7871a3` |
| Size | 872 bytes |
