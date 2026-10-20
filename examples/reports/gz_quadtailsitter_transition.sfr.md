EVALUATION KEY: not for operational use

# Sealed flight record: gz\_quadtailsitter\_transition\.ulg

- Merkle root: `729542277b0295798a9207f159900a99cf44d7331c29d992ab1b2627d355ef49` (sha256\-rfc6962, 35 leaves)
- Key fingerprint: `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45`

**Status: WARN**. Sealed (time claimed by the sealer) 2026\-10\-18T15\:00\:00Z by sfr 0\.1\.0. This report is generated from the record gz\_quadtailsitter\_transition\.sfr alone.

## Rule checks

Results are computed from data the log declares about itself; see VALIDATION.md.

| Rule | Status | Name | Found |
|---|---|---|---|
| R1 | PASS | required topics present | all present |
| R2 | PASS | firmware matches baseline | log states PX4 1\.17\.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4 \(self\-reported\)\; baseline file sha256 5b9bed041d2643d13fc3ab3877210db8d43c33848588053e228837abfa83a578 \(operator\-supplied\) |
| R3 | PASS | parameters match baseline | no differences\; ignore \[COM\_FLIGHT\_UUID\, LND\_FLIGHT\_T\_HI\, LND\_FLIGHT\_T\_LO\, EKF2\_MAG\_DECL\, CAL\_BARO\*\_OFF\, ASPD\_SCALE\_\*\, COM\_MODE\*\_HASH\] suppressed 0 difference\(s\)\; baseline file sha256 5b9bed041d2643d13fc3ab3877210db8d43c33848588053e228837abfa83a578 \(operator\-supplied\) |
| R4 | WARN | no failsafe in flight | never true in flight\; warning\: failsafe\_flags auto\_mission\_missing\, fd\_esc\_arming\_failure\, gcs\_connection\_lost\, manual\_control\_signal\_lost\, offboard\_control\_signal\_lost true in flight |
| R5 | PASS | arm and disarm consistent | 1 ARM\, 1 DISARM |
| R6 | PASS | VTOL transitions completed | 2 START\, 2 END\, 0 problem\(s\) |
| R7 | N\/A | authorized command sources | no \[authorized\_sources\] in the rules file |

### R4 WARN

- Expected: vehicle\_status\.failsafe false in flight \(from ARM through the sample that disarms\)\, no quadchute \(fixed wing straight to multicopter\) in flight\, and no failsafe\_flags flag that the current nav\_state requires true in flight\; other failsafe\_flags flags true in flight are warnings
- warning\: failsafe\_flags\.auto\_mission\_missing true in flight from boot\_us 9064000 \(181 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.fd\_esc\_arming\_failure true in flight from boot\_us 37376000 \(127 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.gcs\_connection\_lost true in flight from boot\_us 9064000 \(181 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.manual\_control\_signal\_lost true in flight from boot\_us 9064000 \(181 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.offboard\_control\_signal\_lost true in flight from boot\_us 9064000 \(181 sample\(s\)\)\, not required by the nav\_state in effect

## Parameter differences

R3 found no difference between the baseline and the flown parameters.

## Parameters changed in flight

R3 compares the parameters in effect at each ARM with the baseline; a change in flight of a parameter it does not ignore makes R3 WARN.

No parameter changed in flight.

## Transition tuning

- VTOL type: tailsitter (VT_TYPE 0)

| Parameter | Baseline | Flown | R3 |
|---|---|---|---|
| VT\_ARSP\_TRANS | f32\:15 | f32\:15 | MATCH |
| VT\_B\_TRANS\_DUR | f32\:5 | f32\:5 | MATCH |
| VT\_FW\_DIFTHR\_EN | i32\:7 | i32\:7 | MATCH |
| VT\_FW\_DIFTHR\_S\_P | f32\:1 | f32\:1 | MATCH |
| VT\_FW\_DIFTHR\_S\_R | f32\:1 | f32\:1 | MATCH |
| VT\_FW\_DIFTHR\_S\_Y | f32\:1 | f32\:1 | MATCH |
| VT\_F\_TRANS\_DUR | f32\:1\.5 | f32\:1\.5 | MATCH |
| VT\_PITCH\_MIN | f32\:\-5 | f32\:\-5 | MATCH |
| VT\_TRANS\_MIN\_TM | f32\:2 | f32\:2 | MATCH |
| VT\_TRANS\_TIMEOUT | f32\:15 | f32\:15 | MATCH |

## Sealed topics

The record holds no sealed topic digests.

## Events

| Seq | Boot time (s) | Kind | Category | Detail |
|---|---|---|---|---|
| 0 | 4.968000 | COMMAND | PAYLOAD | command 211; result NO\_ACK; source\_component 17676; source\_system 194 |
| 1 | 5.104000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old none; old\_name none |
| 2 | 8.908000 | COMMAND | GENERAL | command 400; result ACCEPTED; source\_component 1; source\_system 1 |
| 3 | 8.920000 | ARM |  | initial false; reason 3; reason\_name command\_internal |
| 4 | 12.032000 | COMMAND | GENERAL | command 22; result ACCEPTED; source\_component 1; source\_system 1 |
| 5 | 12.044000 | COMMAND | GENERAL | command 400; result ACCEPTED; source\_component 1; source\_system 1 |
| 6 | 12.052000 | NAV\_STATE\_CHANGE |  | new 17; new\_name AUTO\_TAKEOFF; old 4; old\_name AUTO\_LOITER |
| 7 | 28.244000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old 17; old\_name AUTO\_TAKEOFF |
| 8 | 33.580000 | COMMAND | GENERAL | command 3000; result NO\_ACK; source\_component 1; source\_system 1 |
| 9 | 33.596000 | VTOL\_TRANSITION\_START |  | direction to\_fw |
| 10 | 36.056000 | VTOL\_TRANSITION\_END |  | direction to\_fw |
| 11 | 37.376000 | LOG\_MESSAGE |  | level 4; text \[health\_and\_arming\_checks\] Preflight Fail\: ESC failure detected |
| 12 | 45.832000 | LOG\_MESSAGE |  | level 3; text \[sensors\] Accel \#0 fail\:  TIMEOUT\!  |
| 13 | 57.136000 | COMMAND | GENERAL | command 3000; result NO\_ACK; source\_component 1; source\_system 1 |
| 14 | 57.148000 | VTOL\_TRANSITION\_START |  | direction to\_mc |
| 15 | 61.540000 | VTOL\_TRANSITION\_END |  | direction to\_mc |
| 16 | 67.660000 | COMMAND | GENERAL | command 21; result ACCEPTED; source\_component 1; source\_system 1 |
| 17 | 67.684000 | NAV\_STATE\_CHANGE |  | new 18; new\_name AUTO\_LAND; old 4; old\_name AUTO\_LOITER |
| 18 | 67.936000 | COMMAND | GENERAL | command 1001; result NO\_ACK; source\_component 1; source\_system 1 |
| 19 | 67.936000 | COMMAND | GENERAL | command 1000; result NO\_ACK; source\_component 1; source\_system 1 |
| 20 | 67.936000 | COMMAND | GENERAL | command 1001; result NO\_ACK; source\_component 1; source\_system 1 |
| 21 | 105.868000 | DISARM |  | reason 6; reason\_name auto\_disarm\_land |
| 22 | 105.868000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old 18; old\_name AUTO\_LAND |

`initial` (ARM, FAILSAFE_SET): true when the event comes from the log's first `vehicle_status` sample, because the log starts armed or in failsafe; false when it is a change between two samples.

## Log

- File: gz\_quadtailsitter\_transition\.ulg
- Size (bytes): 34095400
- Firmware: 1\.17\.0 (git d6f12ad1c4f70ad3230afd7d86e971421e02fef4)
- SHA-256: `6a3f297f4ae8a827625f22ee6e69640b12f0c48d4436b839f54c9d8a716ea26b`
- BLAKE3 (index only, adds no security): `b95166069a098547e424856dc87be7e9ead9e2477dd763a964d256cd470b4d94`
- VTOL: true
- MAV_TYPE: 20

## Seal

- Seal time (claimed by the sealer, not proven): 2026\-10\-18T15\:00\:00Z
- Key fingerprint: `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45`
- Key custody (declared by the sealer; this report cannot attest it): file\-evaluation
- Crypto crates (crate versions): blake3 1\.8\.7, ed25519\-dalek 3\.0\.0, sha2 0\.11\.1
- Merkle root: `729542277b0295798a9207f159900a99cf44d7331c29d992ab1b2627d355ef49` (sha256\-rfc6962, 35 leaves)
- Schema version: 4

## Verify

With the public key whose fingerprint is `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45` saved as `sfr.pub`, in the directory that holds the record and the log:

```
sfr verify gz_quadtailsitter_transition.sfr --pubkey sfr.pub --allow-evaluation-key --ulog gz_quadtailsitter_transition.ulg
```

Without `--ulog`, `sfr verify` checks the record alone.
