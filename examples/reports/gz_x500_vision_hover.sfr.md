EVALUATION KEY: not for operational use

# Sealed flight record: gz\_x500\_vision\_hover\.ulg

- Merkle root: `993657f8f9b03922f45f25c9ce6089c049c6195d354501c36fe95efe29fc143d` (sha256\-rfc6962, 29 leaves)
- Key fingerprint: `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45`

**Status: FAIL**. Sealed (time claimed by the sealer) 2026\-10\-18T15\:00\:00Z by sfr 0\.1\.0. This report is generated from the record gz\_x500\_vision\_hover\.sfr alone.

## Rules

| Rule | Status | Name | Found |
|---|---|---|---|
| R1 | PASS | required topics present | all present |
| R2 | PASS | firmware matches baseline | log states PX4 1\.17\.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4 \(self\-reported\)\; baseline file sha256 6cabf8246fc1d120d93b0c35c160bde7517af6ad7cd48cecc7f8dd8909892894 \(operator\-supplied\) |
| R3 | PASS | parameters match baseline | no differences\; ignore \[COM\_FLIGHT\_UUID\, LND\_FLIGHT\_T\_HI\, LND\_FLIGHT\_T\_LO\, EKF2\_MAG\_DECL\, CAL\_BARO\*\_OFF\, ASPD\_SCALE\_\*\, COM\_MODE\*\_HASH\] suppressed 1 difference\(s\)\; baseline file sha256 6cabf8246fc1d120d93b0c35c160bde7517af6ad7cd48cecc7f8dd8909892894 \(operator\-supplied\) |
| R4 | WARN | no failsafe in flight | never true in flight\; warning\: failsafe\_flags auto\_mission\_missing\, manual\_control\_signal\_lost\, offboard\_control\_signal\_lost true in flight |
| R5 | PASS | arm and disarm consistent | 1 ARM\, 1 DISARM |
| R6 | N\/A | VTOL transitions completed | vehicle\_status\.is\_vtol false on every sample |
| R7 | FAIL | authorized command sources | 1 of 8 command\(s\) from unauthorized sources\; scope every category\, 0 excluded by scope\; source ids are self\-reported by the sender |

### R4 WARN

- Expected: vehicle\_status\.failsafe false in flight \(from ARM through the sample that disarms\)\, no quadchute \(fixed wing straight to multicopter\) in flight\, and no failsafe\_flags flag that the current nav\_state requires true in flight\; other failsafe\_flags flags true in flight are warnings
- warning\: failsafe\_flags\.auto\_mission\_missing true in flight from boot\_us 8984000 \(86 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.manual\_control\_signal\_lost true in flight from boot\_us 8984000 \(86 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.offboard\_control\_signal\_lost true in flight from boot\_us 8984000 \(86 sample\(s\)\)\, not required by the nav\_state in effect

### R7 FAIL

- Expected: every COMMAND event from an authorized source \(system\/component 1\/1\)
- event seq 0\: command 211 \(PAYLOAD\) from system 132 component 34432 at boot\_us 4920000

## Parameter differences

R3 found no difference between the baseline and the flown parameters.

## Parameters changed in flight

R3 compares the parameters in effect at each ARM with the baseline; a change in flight of a parameter it does not ignore makes R3 WARN.

| Seq | Boot time (s) | Parameter | Old | New |
|---|---|---|---|---|
| 4 | 9.556000 | CAL\_BARO0\_OFF | f32\:0 | f32\:2\.4414062 |

## Sealed topics

| Topic | Instance | Messages | Time span (s) | Data digest |
|---|---|---|---|---|
| vehicle\_visual\_odometry | 0 | 1687 | 5.436000 to 55.996000 | `c55188e1dd751d34` |

## Events

| Seq | Boot time (s) | Kind | Category | Detail |
|---|---|---|---|---|
| 0 | 4.920000 | COMMAND | PAYLOAD | command 211; result NO\_ACK; source\_component 34432; source\_system 132 |
| 1 | 5.192000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old none; old\_name none |
| 2 | 8.476000 | COMMAND | GENERAL | command 400; result ACCEPTED; source\_component 1; source\_system 1 |
| 3 | 8.480000 | ARM |  | initial false; reason 3; reason\_name command\_internal |
| 4 | 9.556000 | PARAM\_CHANGED\_IN\_FLIGHT |  | name CAL\_BARO0\_OFF; new f32\:2\.4414062; old f32\:0 |
| 5 | 11.556000 | COMMAND | GENERAL | command 22; result ACCEPTED; source\_component 1; source\_system 1 |
| 6 | 11.568000 | COMMAND | GENERAL | command 400; result ACCEPTED; source\_component 1; source\_system 1 |
| 7 | 11.576000 | NAV\_STATE\_CHANGE |  | new 17; new\_name AUTO\_TAKEOFF; old 4; old\_name AUTO\_LOITER |
| 8 | 17.684000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old 17; old\_name AUTO\_TAKEOFF |
| 9 | 47.668000 | COMMAND | GENERAL | command 21; result ACCEPTED; source\_component 1; source\_system 1 |
| 10 | 47.684000 | NAV\_STATE\_CHANGE |  | new 18; new\_name AUTO\_LAND; old 4; old\_name AUTO\_LOITER |
| 11 | 47.936000 | COMMAND | GENERAL | command 1001; result NO\_ACK; source\_component 1; source\_system 1 |
| 12 | 47.936000 | COMMAND | GENERAL | command 1000; result NO\_ACK; source\_component 1; source\_system 1 |
| 13 | 47.936000 | COMMAND | GENERAL | command 1001; result NO\_ACK; source\_component 1; source\_system 1 |
| 14 | 55.016000 | DISARM |  | reason 6; reason\_name auto\_disarm\_land |
| 15 | 55.016000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old 18; old\_name AUTO\_LAND |

`initial` (ARM, FAILSAFE_SET): true when the event comes from the log's first `vehicle_status` sample, because the log starts armed or in failsafe; false when it is a change between two samples.

## Log

- File: gz\_x500\_vision\_hover\.ulg
- Size (bytes): 15797162
- Firmware: 1\.17\.0 (git d6f12ad1c4f70ad3230afd7d86e971421e02fef4)
- SHA-256: `56524cc22d68b3125648386600b3dfa0811a08c65d3912613279be91c96f46a1`
- BLAKE3 (index only, adds no security): `a01cacdb446d5fcfb0901d9371983315fa91b7935a7739d7f6aa98e3122d227c`
- VTOL: false
- MAV_TYPE: 2

## Seal

- Seal time (claimed by the sealer, not proven): 2026\-10\-18T15\:00\:00Z
- Key fingerprint: `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45`
- Key custody (declared by the sealer; this report cannot attest it): file\-evaluation
- Crypto crates (crate versions): blake3 1\.8\.7, ed25519\-dalek 3\.0\.0, sha2 0\.11\.1
- Merkle root: `993657f8f9b03922f45f25c9ce6089c049c6195d354501c36fe95efe29fc143d` (sha256\-rfc6962, 29 leaves)
- Schema version: 4

## Verify

With the public key whose fingerprint is `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45` saved as `sfr.pub`, in the directory that holds the record and the log:

```
sfr verify gz_x500_vision_hover.sfr --pubkey sfr.pub --allow-evaluation-key --ulog gz_x500_vision_hover.ulg
```

Without `--ulog`, `sfr verify` checks the record alone.
