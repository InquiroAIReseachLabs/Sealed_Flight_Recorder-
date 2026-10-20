EVALUATION KEY: not for operational use

# Sealed flight record: failsafe\_gps\_loss\.ulg

- Merkle root: `89e340ec03d012e681d01d70ad4b19a3f78dd030bf79a91949e3a7222349b301` (sha256\-rfc6962, 39 leaves)
- Key fingerprint: `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45`

**Status: FAIL**. Sealed (time claimed by the sealer) 2026\-10\-18T15\:00\:00Z by sfr 0\.1\.0. This report is generated from the record failsafe\_gps\_loss\.sfr alone.

## Rule checks

Results are computed from data the log declares about itself; see VALIDATION.md.

| Rule | Status | Name | Found |
|---|---|---|---|
| R1 | PASS | required topics present | all present |
| R2 | PASS | firmware matches baseline | log states PX4 1\.17\.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4 \(self\-reported\)\; baseline file sha256 1319740d27e0a3cd0597fa504fe7253a996a7ba07de1df595565ec45dd3da6a2 \(operator\-supplied\) |
| R3 | PASS | parameters match baseline | no differences\; ignore \[COM\_FLIGHT\_UUID\, LND\_FLIGHT\_T\_HI\, LND\_FLIGHT\_T\_LO\, EKF2\_MAG\_DECL\, CAL\_BARO\*\_OFF\, ASPD\_SCALE\_\*\, COM\_MODE\*\_HASH\] suppressed 0 difference\(s\)\; baseline file sha256 1319740d27e0a3cd0597fa504fe7253a996a7ba07de1df595565ec45dd3da6a2 \(operator\-supplied\) |
| R4 | FAIL | no failsafe in flight | true in flight 1 time\(s\)\, required failsafe\_flags global\_position\_invalid\, local\_position\_invalid true in flight\; warning\: failsafe\_flags auto\_mission\_missing\, gcs\_connection\_lost\, global\_position\_invalid\, global\_position\_invalid\_relaxed\, local\_position\_invalid\, local\_position\_invalid\_relaxed\, local\_velocity\_invalid\, manual\_control\_signal\_lost\, offboard\_control\_signal\_lost true in flight |
| R5 | PASS | arm and disarm consistent | 1 ARM\, 1 DISARM |
| R6 | N\/A | VTOL transitions completed | vehicle\_status\.is\_vtol false on every sample |
| R7 | N\/A | authorized command sources | no \[authorized\_sources\] in the rules file |

### R4 FAIL

- Expected: vehicle\_status\.failsafe false in flight \(from ARM through the sample that disarms\)\, no quadchute \(fixed wing straight to multicopter\) in flight\, and no failsafe\_flags flag that the current nav\_state requires true in flight\; other failsafe\_flags flags true in flight are warnings
- failsafe in flight at boot\_us 37936000\: global\_position\_invalid\, global\_position\_invalid\_relaxed\, local\_position\_invalid\, local\_position\_invalid\_relaxed\, local\_velocity\_invalid
- warning\: failsafe\_flags\.auto\_mission\_missing true in flight from boot\_us 4132000 \(78 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.gcs\_connection\_lost true in flight from boot\_us 4132000 \(78 sample\(s\)\)\, not required by the nav\_state in effect
- failsafe\_flags\.global\_position\_invalid true in flight from boot\_us 37924000 \(2 sample\(s\)\)\, required by nav\_state 4
- warning\: failsafe\_flags\.global\_position\_invalid true in flight from boot\_us 38476000 \(13 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.global\_position\_invalid\_relaxed true in flight from boot\_us 37924000 \(15 sample\(s\)\)\, not required by the nav\_state in effect
- failsafe\_flags\.local\_position\_invalid true in flight from boot\_us 37924000 \(2 sample\(s\)\)\, required by nav\_state 4
- warning\: failsafe\_flags\.local\_position\_invalid true in flight from boot\_us 38476000 \(13 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.local\_position\_invalid\_relaxed true in flight from boot\_us 37924000 \(15 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.local\_velocity\_invalid true in flight from boot\_us 37924000 \(15 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.manual\_control\_signal\_lost true in flight from boot\_us 4132000 \(78 sample\(s\)\)\, not required by the nav\_state in effect
- warning\: failsafe\_flags\.offboard\_control\_signal\_lost true in flight from boot\_us 4132000 \(78 sample\(s\)\)\, not required by the nav\_state in effect

## Parameter differences

R3 found no difference between the baseline and the flown parameters.

## Parameters changed in flight

R3 compares the parameters in effect at each ARM with the baseline; a change in flight of a parameter it does not ignore makes R3 WARN.

No parameter changed in flight.

## Sealed topics

The record holds no sealed topic digests.

## Events

| Seq | Boot time (s) | Kind | Category | Detail |
|---|---|---|---|---|
| 0 | 0.096000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old none; old\_name none |
| 1 | 0.124000 | COMMAND | PAYLOAD | command 211; result NO\_ACK; source\_component 13376; source\_system 17 |
| 2 | 3.864000 | COMMAND | GENERAL | command 400; result ACCEPTED; source\_component 1; source\_system 1 |
| 3 | 3.868000 | ARM |  | initial false; reason 3; reason\_name command\_internal |
| 4 | 6.836000 | COMMAND | GENERAL | command 22; result ACCEPTED; source\_component 1; source\_system 1 |
| 5 | 6.848000 | COMMAND | GENERAL | command 400; result ACCEPTED; source\_component 1; source\_system 1 |
| 6 | 6.856000 | NAV\_STATE\_CHANGE |  | new 17; new\_name AUTO\_TAKEOFF; old 4; old\_name AUTO\_LOITER |
| 7 | 12.664000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old 17; old\_name AUTO\_TAKEOFF |
| 8 | 17.752000 | LOG\_MESSAGE |  | level 4; text \[failure\] inject failure unit\: gps \(4\)\, type\: off \(1\)\, instance\: 0 |
| 9 | 17.752000 | COMMAND | GENERAL | command 420; result NO\_ACK; source\_component 0; source\_system 0 |
| 10 | 18.760000 | LOG\_MESSAGE |  | level 3; text \[failure\] Timeout waiting for ack |
| 11 | 37.920000 | LOG\_MESSAGE |  | level 4; text \[mc\_pos\_control\] invalid setpoints |
| 12 | 37.920000 | LOG\_MESSAGE |  | level 4; text \[mc\_pos\_control\] Failsafe\: blind land |
| 13 | 37.936000 | LOG\_MESSAGE |  | level 4; text \[failsafe\] Failsafe activated  |
| 14 | 37.936000 | NAV\_STATE\_CHANGE |  | new 12; new\_name DESCEND; old 4; old\_name AUTO\_LOITER |
| 15 | 37.936000 | FAILSAFE\_SET |  | flag global\_position\_invalid; initial false |
| 16 | 37.936000 | FAILSAFE\_SET |  | flag global\_position\_invalid\_relaxed; initial false |
| 17 | 37.936000 | FAILSAFE\_SET |  | flag local\_position\_invalid; initial false |
| 18 | 37.936000 | FAILSAFE\_SET |  | flag local\_position\_invalid\_relaxed; initial false |
| 19 | 37.936000 | FAILSAFE\_SET |  | flag local\_velocity\_invalid; initial false |
| 20 | 45.172000 | DISARM |  | reason 6; reason\_name auto\_disarm\_land |
| 21 | 45.172000 | NAV\_STATE\_CHANGE |  | new 4; new\_name AUTO\_LOITER; old 12; old\_name DESCEND |
| 22 | 45.172000 | FAILSAFE\_CLEAR |  | flag global\_position\_invalid |
| 23 | 45.172000 | FAILSAFE\_CLEAR |  | flag global\_position\_invalid\_relaxed |
| 24 | 45.172000 | FAILSAFE\_CLEAR |  | flag local\_position\_invalid |
| 25 | 45.172000 | FAILSAFE\_CLEAR |  | flag local\_position\_invalid\_relaxed |
| 26 | 45.172000 | FAILSAFE\_CLEAR |  | flag local\_velocity\_invalid |

`initial` (ARM, FAILSAFE_SET): true when the event comes from the log's first `vehicle_status` sample, because the log starts armed or in failsafe; false when it is a change between two samples.

## Log

- File: failsafe\_gps\_loss\.ulg
- Size (bytes): 10217078
- Firmware: 1\.17\.0 (git d6f12ad1c4f70ad3230afd7d86e971421e02fef4)
- SHA-256: `5ce6ca4963b231d3641edcb25e7b3d07c7da6e8971857cbef074ce04e496cdfc`
- BLAKE3 (checked by verify --ulog like SHA-256; adds no security beyond it): `ee6a2f0b11ce02d41104006f81af206f0f6cfefb3eb33e690242e97b4587918d`
- VTOL: false
- MAV_TYPE: 2

## Seal

- Seal time (claimed by the sealer, not proven): 2026\-10\-18T15\:00\:00Z
- Key fingerprint: `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45`
- Key custody (declared by the sealer; this report cannot attest it): file\-evaluation
- Crypto crates (crate versions): blake3 1\.8\.7, ed25519\-dalek 3\.0\.0, sha2 0\.11\.1
- Merkle root: `89e340ec03d012e681d01d70ad4b19a3f78dd030bf79a91949e3a7222349b301` (sha256\-rfc6962, 39 leaves)
- Schema version: 4

## Verify

With the public key whose fingerprint is `sha256:1ab979d4bed49693df5e1482cfb3a5432a6dd632de3c95dc24f7c9896c7eec45` saved as `sfr.pub`, in the directory that holds the record and the log:

```
sfr verify failsafe_gps_loss.sfr --pubkey sfr.pub --allow-evaluation-key --ulog failsafe_gps_loss.ulg
```

Without `--ulog`, `sfr verify` checks the record alone.
