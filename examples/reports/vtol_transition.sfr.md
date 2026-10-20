EVALUATION KEY: not for operational use

# Sealed flight record: vtol\_transition\.ulg

- Merkle root: `cb0183bc5b2bb55bd02c2d2a2f592cb10f60c36520d2ab22f8701c3e66ff9375` (sha256\-rfc6962, 34 leaves)
- Key fingerprint: `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45`

**Status: WARN**. Sealed (time claimed by the sealer) 2026\-10\-18T15\:00\:00Z by sfr 0\.1\.0. This report is generated from the record vtol\_transition\.sfr alone.

## Rules

| Rule | Status | Name | Found |
|---|---|---|---|
| R1 | PASS | required topics present | all present |
| R2 | PASS | firmware matches baseline | log states PX4 1\.17\.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4 \(self\-reported\)\; baseline file sha256 d4da23c173b4031487e802b4971921f834d255f1eb47c4906228cb93edf18885 \(operator\-supplied\) |
| R3 | PASS | parameters match baseline | no differences\; ignore \[COM\_FLIGHT\_UUID\, LND\_FLIGHT\_T\_HI\, LND\_FLIGHT\_T\_LO\, EKF2\_MAG\_DECL\, CAL\_BARO\*\_OFF\, ASPD\_SCALE\_\*\, COM\_MODE\*\_HASH\] suppressed 1 difference\(s\)\; baseline file sha256 d4da23c173b4031487e802b4971921f834d255f1eb47c4906228cb93edf18885 \(operator\-supplied\) |
| R4 | WARN | no failsafe in flight | never true in flight\; warning\: failsafe\_flags auto\_mission\_missing\, gcs\_connection\_lost\, manual\_control\_signal\_lost\, offboard\_control\_signal\_lost true in flight |
| R5 | PASS | arm and disarm consistent | 1 ARM\, 1 DISARM |
| R6 | PASS | VTOL transitions completed | 2 START\, 2 END\, 0 problem\(s\) |
| R7 | N\/A | authorized command sources | no \[authorized\_sources\] in the rules file |

### R4 WARN

- Expected: vehicle\_status\.failsafe false in flight \(from ARM through the sample that disarms\)\, no quadchute \(fixed wing straight to multicopter\) in flight\, and no failsafe\_flags flag that the current nav\_state requires true in flight\; other failsafe\_flags flags true in flight are warnings
- warning\: failsafe\_flags\.auto\_mission\_missing true in flight from boot\_us 4892000 \(155 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.gcs\_connection\_lost true in flight from boot\_us 4892000 \(155 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.manual\_control\_signal\_lost true in flight from boot\_us 4892000 \(155 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.offboard\_control\_signal\_lost true in flight from boot\_us 4892000 \(155 sample\(s\)\)\, not required by the nav\_state in effect

## Parameter differences

R3 found no difference between the baseline and the flown parameters.

## Parameters changed in flight

R3 compares the parameters in effect at each ARM with the baseline; a change in flight of a parameter it does not ignore makes R3 WARN.

| Seq | Boot time (s) | Parameter | Old | New |
|---|---|---|---|---|
| 4 | 5.308000 | CAL\_BARO0\_OFF | f32\:0 | f32\:2\.4414062 |

## Transition tuning

- VTOL type: standard (VT_TYPE 2)

| Parameter | Baseline | Flown | R3 |
|---|---|---|---|
| VT\_ARSP\_TRANS | f32\:10 | f32\:10 | MATCH |
| VT\_B\_TRANS\_DUR | f32\:10 | f32\:10 | MATCH |
| VT\_FW\_DIFTHR\_EN | i32\:0 | i32\:0 | MATCH |
| VT\_FW\_DIFTHR\_S\_P | f32\:1 | f32\:1 | MATCH |
| VT\_FW\_DIFTHR\_S\_R | f32\:1 | f32\:1 | MATCH |
| VT\_FW\_DIFTHR\_S\_Y | f32\:0\.1 | f32\:0\.1 | MATCH |
| VT\_F\_TRANS\_DUR | f32\:5 | f32\:5 | MATCH |
| VT\_PITCH\_MIN | f32\:\-5 | f32\:\-5 | MATCH |
| VT\_TRANS\_MIN\_TM | f32\:2 | f32\:2 | MATCH |
| VT\_TRANS\_TIMEOUT | f32\:15 | f32\:15 | MATCH |

## Sealed topics

The record holds no sealed topic digests.

## Events

| Seq | Boot time (s) | Kind | Category | Detail |
|---|---|---|---|---|
| 0 | 0.116000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old none; old\_name none |
| 1 | 0.160000 | COMMAND | PAYLOAD | command 211; result NO\_ACK; source\_component 37952; source\_system 51 |
| 2 | 4.672000 | COMMAND | GENERAL | command 400; result ACCEPTED; source\_component 1; source\_system 1 |
| 3 | 4.676000 | ARM |  | initial false; reason 3; reason\_name command\_internal |
| 4 | 5.308000 | PARAM\_CHANGED\_IN\_FLIGHT |  | name CAL\_BARO0\_OFF; new f32\:2\.4414062; old f32\:0 |
| 5 | 7.652000 | COMMAND | GENERAL | command 22; result ACCEPTED; source\_component 1; source\_system 1 |
| 6 | 7.664000 | COMMAND | GENERAL | command 400; result ACCEPTED; source\_component 1; source\_system 1 |
| 7 | 7.676000 | NAV\_STATE\_CHANGE |  | new 17; new\_name AUTO\_TAKEOFF; old 4; old\_name AUTO\_LOITER |
| 8 | 22.244000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old 17; old\_name AUTO\_TAKEOFF |
| 9 | 27.484000 | COMMAND | GENERAL | command 3000; result NO\_ACK; source\_component 1; source\_system 1 |
| 10 | 27.500000 | VTOL\_TRANSITION\_START |  | direction to\_fw |
| 11 | 30.512000 | VTOL\_TRANSITION\_END |  | direction to\_fw |
| 12 | 56.156000 | COMMAND | GENERAL | command 3000; result NO\_ACK; source\_component 1; source\_system 1 |
| 13 | 56.172000 | VTOL\_TRANSITION\_START |  | direction to\_mc |
| 14 | 56.772000 | VTOL\_TRANSITION\_END |  | direction to\_mc |
| 15 | 62.144000 | COMMAND | GENERAL | command 21; result ACCEPTED; source\_component 1; source\_system 1 |
| 16 | 62.160000 | NAV\_STATE\_CHANGE |  | new 18; new\_name AUTO\_LAND; old 4; old\_name AUTO\_LOITER |
| 17 | 62.412000 | COMMAND | GENERAL | command 1001; result NO\_ACK; source\_component 1; source\_system 1 |
| 18 | 62.412000 | COMMAND | GENERAL | command 1000; result NO\_ACK; source\_component 1; source\_system 1 |
| 19 | 62.412000 | COMMAND | GENERAL | command 1001; result NO\_ACK; source\_component 1; source\_system 1 |
| 20 | 88.272000 | DISARM |  | reason 6; reason\_name auto\_disarm\_land |
| 21 | 88.272000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old 18; old\_name AUTO\_LAND |

`initial` (ARM, FAILSAFE_SET): true when the event comes from the log's first `vehicle_status` sample, because the log starts armed or in failsafe; false when it is a change between two samples.

## Log

- File: vtol\_transition\.ulg
- Size (bytes): 24295307
- Firmware: 1\.17\.0 (git d6f12ad1c4f70ad3230afd7d86e971421e02fef4)
- SHA-256: `86d64e54d1261991f4035355550f64e017f8a486c5c665848d6e68ae67fc9bf3`
- BLAKE3 (index only, adds no security): `0af5378155f2d8dc440697a01096d4af50217c6eb33f93b3bef3d976a54adbfd`
- VTOL: true
- MAV_TYPE: 22

## Seal

- Seal time (claimed by the sealer, not proven): 2026\-10\-18T15\:00\:00Z
- Key fingerprint: `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45`
- Key custody (declared by the sealer; this report cannot attest it): file\-evaluation
- Crypto crates (crate versions): blake3 1\.8\.7, ed25519\-dalek 3\.0\.0, sha2 0\.11\.1
- Merkle root: `cb0183bc5b2bb55bd02c2d2a2f592cb10f60c36520d2ab22f8701c3e66ff9375` (sha256\-rfc6962, 34 leaves)
- Schema version: 4

## Verify

With the public key whose fingerprint is `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45` saved as `sfr.pub`, in the directory that holds the record and the log:

```
sfr verify vtol_transition.sfr --pubkey sfr.pub --allow-evaluation-key --ulog vtol_transition.ulg
```

Without `--ulog`, `sfr verify` checks the record alone.
