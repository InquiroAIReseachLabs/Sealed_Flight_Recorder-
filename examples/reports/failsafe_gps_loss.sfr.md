EVALUATION KEY: not for operational use

# Sealed flight record: failsafe\_gps\_loss\.ulg

- Merkle root: `c05aa62a80822c2c78406652a99a79c5f0e2b5509a9f7b5725a81e0bc32dc707` (sha256\-rfc6962, 39 leaves)
- Key fingerprint: `sha256:336b85ba4e9d3ef9be68f80c9bd84dd2ec2398eb498a8813308b0cbc41ffea51`

**Status: FAIL**. Sealed (time claimed by the sealer) 2026\-10\-18T15\:00\:00Z by sfr 0\.1\.0, v1.0 evaluation release. This report is generated from the record failsafe\_gps\_loss\.sfr alone.

## Rules

| Rule | Status | Name | Found |
|---|---|---|---|
| R1 | PASS | required topics present | all present |
| R2 | PASS | firmware matches baseline | 1\.17\.0 d6f12ad1c4f70ad3230afd7d86e971421e02fef4 |
| R3 | PASS | parameters match baseline | no differences |
| R4 | FAIL | no failsafe in flight | true in flight 1 time\(s\) |
| R5 | PASS | arm and disarm consistent | 1 ARM\, 1 DISARM |
| R6 | N\/A | VTOL transitions completed | vehicle\_status\.is\_vtol false on every sample |
| R7 | N\/A | authorized command sources | no \[authorized\_sources\] in the rules file |

### R4 FAIL

- Expected: vehicle\_status\.failsafe false in flight \(from ARM through the sample that disarms\)\, and no quadchute \(fixed wing straight to multicopter\) in flight
- failsafe in flight at boot\_us 37936000\: global\_position\_invalid\, global\_position\_invalid\_relaxed\, local\_position\_invalid\, local\_position\_invalid\_relaxed\, local\_velocity\_invalid

## Parameter differences

R3 found no difference between the baseline and the flown parameters.

## Parameters changed in flight

These are reported, not a rule failure: R3 compares the parameters at log start with the baseline.

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
- BLAKE3 (supplementary): `ee6a2f0b11ce02d41104006f81af206f0f6cfefb3eb33e690242e97b4587918d`
- VTOL: false
- MAV_TYPE: 2

## Seal

- Seal time (claimed by the sealer, not proven): 2026\-10\-18T15\:00\:00Z
- Key fingerprint: `sha256:336b85ba4e9d3ef9be68f80c9bd84dd2ec2398eb498a8813308b0cbc41ffea51`
- Key custody (declared by the sealer; this report cannot attest it): file\-evaluation
- Crypto crates (crate versions): blake3 1\.8\.7, ed25519\-dalek 3\.0\.0, sha2 0\.11\.1
- Merkle root: `c05aa62a80822c2c78406652a99a79c5f0e2b5509a9f7b5725a81e0bc32dc707` (sha256\-rfc6962, 39 leaves)
- Schema version: 2

## Verify

With the public key whose fingerprint is `sha256:336b85ba4e9d3ef9be68f80c9bd84dd2ec2398eb498a8813308b0cbc41ffea51` saved as `sfr.pub`, in the directory that holds the record and the log:

```
sfr verify failsafe_gps_loss.sfr --pubkey sfr.pub --allow-evaluation-key --ulog failsafe_gps_loss.ulg
```

Without `--ulog`, `sfr verify` checks the record alone.
