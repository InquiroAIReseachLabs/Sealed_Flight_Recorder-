# r4_quadchute_on_disarm.ulg

Synthetic. Written by `scripts/testdata/make_synthetic_logs.py` (Python standard library only); not a flight and not a third-party log. Regenerate with:

```
python3 -I scripts/testdata/make_synthetic_logs.py testdata/synthetic
```

It exercises the R4 window (SPEC B1.6: from the ARM sample through the sample that disarms). `vehicle_status` and `failsafe_flags` use PX4 field names and types; firmware is reported as v1.17.0. Twelve `vehicle_status` samples, one per second of boot time:

| boot_us | armed | VTOL state | Expected |
|---|---|---|---|
| 1000000 | no | multicopter | |
| 2000000 | yes | multicopter | ARM |
| 3000000 | yes | transition to fixed wing | VTOL_TRANSITION_START |
| 4000000 | yes | fixed wing | VTOL_TRANSITION_END |
| 5000000 | no | multicopter | DISARM and QUADCHUTE; R4 counts it (the disarming sample) |
| 6000000 | no | multicopter | |
| 7000000 | yes | multicopter | ARM |
| 8000000 | yes | transition to fixed wing | VTOL_TRANSITION_START |
| 9000000 | yes | fixed wing | VTOL_TRANSITION_END |
| 10000000 | no | fixed wing | DISARM |
| 11000000 | no | multicopter | QUADCHUTE; R4 does not count it (after disarm) |
| 12000000 | no | multicopter | |

`vehicle_status.failsafe` and `failsafe_flags.vtol_fixed_wing_system_failure` are false throughout, so R4 fails on the first quadchute alone.
