# Validation

What was tested, on what, how many crafted false-pass attempts there were and what became of them, and which kinds of false pass remain. Every result here is computed from data the log declares about itself; this page says how far that can be trusted.

## What was tested

- **Golden logs.** The logs `scripts/testdata/golden_logs.sh` lists: 19 logs, which are the pyulog sample, one PX4 v1.14.4 flight and ten PX4 v1.17.0 flights recorded in simulation (`testdata/sitl/`), and seven synthetic logs (`testdata/synthetic/`), of which three end in the middle of a record and one has ULog file format version 2. Each is sealed and its expected output is committed under `testdata/expected/`. No golden log comes from PX4 v1.15 or v1.16: those versions are covered only by the field-type tables in `crates/sfr-core/src/ingest.rs`.
- **False-pass corpus.** `testdata/falsepass/`, written by `scripts/testdata/make_falsepass.py`: 15 crafted logs, each built to look like a passing flight to a reader that trusts what a log declares about its own structure, and beside each a positive control without the trick (30 logs in all, listed in `testdata/falsepass/cases.json`). `crates/sfr/tests/falsepass.rs` checks every case.
- **Crafted records.** `tools/reference_verifier/vectors/`, written by `tools/reference_verifier/make_vectors.py`: 37 records, many built to trip a lenient JSON reader or to carry a result set that is not R1 to R7 exactly once. `crates/sfr/tests/reference_verifier.rs` runs `sfr verify` and the reference verifier on each.
- **Tampering and trust inputs.** The claims audit ([CLAIMS_AUDIT.md](CLAIMS_AUDIT.md)): 24 tamper cases in T3 (`scripts/claims_audit/t03_tamper.py`), 12 attacks on the seal time, custody, CRLs, the report and the signed structure in T12 (`scripts/claims_audit/t12_attacks.sh`); and the tests of planted key programs, intermediate anchors, CRL age and verification at a past time (`crates/sfr/tests/trust_inputs.rs`, `crates/sfr/tests/certificates.rs`).
- **Output.** Log text and file names built to forge report content or a shell command (`hostile_log_text_and_file_names_give_a_literal_report_and_a_working_verify_command` in `crates/sfr/tests/seal_verify.rs`).

## PX4 sources

The PX4 field names, field types, enum values and mode requirements `sfr` uses come from the PX4-Autopilot source at each release tag `sfr` supports (`v1.14.0` to `v1.17.0`, no pre-release), never from a log or a test fixture. `scripts/px4/px4_tables.py` reads them from each tag's tree and writes `crates/sfr-core/src/px4_tables.rs` and the table below; the `px4-sources` CI job runs it again with `--check` against a fresh clone of PX4-Autopilot. From `v1.16.0` some files are under `msg/versioned/`; the script takes that path when it exists at the tag. A log is checked against the tables of the tag its `ver_sw_release` names; for a version that is not a release tag, against every tag of its minor series; outside `v1.14` to `v1.17` (sealed only with `--allow-untested-version`), against every tag. The version is what the log says about itself.

<!-- px4-sources:start (scripts/px4/px4_tables.py writes this table) -->

| Tag | Commit | File | Blob |
|---|---|---|---|
| `v1.14.0` | `b8c541dd7277ed735139d7d1bfb829d61fbe29fb` | `msg/VehicleStatus.msg` | `878b4b04ed36a790bba27d98653fa3fdb6fc4de1` |
|  |  | `msg/FailsafeFlags.msg` | `b697b7085b3d1b4d056c45797ff476c0e3abab22` |
|  |  | `msg/VehicleCommand.msg` | `19e2761cdb36eec26dc9fa3dd5fcd96b432bef84` |
|  |  | `msg/VehicleCommandAck.msg` | `ef43256af5cb9b7b4264737c7f4c6004e2c221f8` |
|  |  | `msg/BatteryStatus.msg` | `65845b57aec2f7e4176cf58b01ff3cbe3e3df8db` |
|  |  | `msg/SensorGps.msg` | `4404dd524fbac5049574a2a168db1ae4f78b5fe4` |
|  |  | `msg/EstimatorStatus.msg` | `f3b76f18edbaf85cad4ebdcfca1c806c5ce9d4e6` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `88123548a76d4933fb936adf53981424fb13c98c` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `598531a0da9bdaace34a3959c741df6d55b598d8` |
| `v1.14.1` | `beb834af2b489941409f39599a98970339f8917c` | `msg/VehicleStatus.msg` | `878b4b04ed36a790bba27d98653fa3fdb6fc4de1` |
|  |  | `msg/FailsafeFlags.msg` | `b697b7085b3d1b4d056c45797ff476c0e3abab22` |
|  |  | `msg/VehicleCommand.msg` | `19e2761cdb36eec26dc9fa3dd5fcd96b432bef84` |
|  |  | `msg/VehicleCommandAck.msg` | `ef43256af5cb9b7b4264737c7f4c6004e2c221f8` |
|  |  | `msg/BatteryStatus.msg` | `65845b57aec2f7e4176cf58b01ff3cbe3e3df8db` |
|  |  | `msg/SensorGps.msg` | `4404dd524fbac5049574a2a168db1ae4f78b5fe4` |
|  |  | `msg/EstimatorStatus.msg` | `f3b76f18edbaf85cad4ebdcfca1c806c5ce9d4e6` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `88123548a76d4933fb936adf53981424fb13c98c` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `598531a0da9bdaace34a3959c741df6d55b598d8` |
| `v1.14.2` | `968732477803be8a73edd13a29c8ab71458eb354` | `msg/VehicleStatus.msg` | `878b4b04ed36a790bba27d98653fa3fdb6fc4de1` |
|  |  | `msg/FailsafeFlags.msg` | `b697b7085b3d1b4d056c45797ff476c0e3abab22` |
|  |  | `msg/VehicleCommand.msg` | `19e2761cdb36eec26dc9fa3dd5fcd96b432bef84` |
|  |  | `msg/VehicleCommandAck.msg` | `ef43256af5cb9b7b4264737c7f4c6004e2c221f8` |
|  |  | `msg/BatteryStatus.msg` | `65845b57aec2f7e4176cf58b01ff3cbe3e3df8db` |
|  |  | `msg/SensorGps.msg` | `4404dd524fbac5049574a2a168db1ae4f78b5fe4` |
|  |  | `msg/EstimatorStatus.msg` | `f3b76f18edbaf85cad4ebdcfca1c806c5ce9d4e6` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `88123548a76d4933fb936adf53981424fb13c98c` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `598531a0da9bdaace34a3959c741df6d55b598d8` |
| `v1.14.3` | `1dacb4cdef2d7145754fc788fa8dc482eed74b40` | `msg/VehicleStatus.msg` | `878b4b04ed36a790bba27d98653fa3fdb6fc4de1` |
|  |  | `msg/FailsafeFlags.msg` | `b697b7085b3d1b4d056c45797ff476c0e3abab22` |
|  |  | `msg/VehicleCommand.msg` | `19e2761cdb36eec26dc9fa3dd5fcd96b432bef84` |
|  |  | `msg/VehicleCommandAck.msg` | `ef43256af5cb9b7b4264737c7f4c6004e2c221f8` |
|  |  | `msg/BatteryStatus.msg` | `65845b57aec2f7e4176cf58b01ff3cbe3e3df8db` |
|  |  | `msg/SensorGps.msg` | `4404dd524fbac5049574a2a168db1ae4f78b5fe4` |
|  |  | `msg/EstimatorStatus.msg` | `f3b76f18edbaf85cad4ebdcfca1c806c5ce9d4e6` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `88123548a76d4933fb936adf53981424fb13c98c` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `598531a0da9bdaace34a3959c741df6d55b598d8` |
| `v1.14.4` | `1555f2bd2229544c43966ab5f94879c41d8e1e01` | `msg/VehicleStatus.msg` | `878b4b04ed36a790bba27d98653fa3fdb6fc4de1` |
|  |  | `msg/FailsafeFlags.msg` | `b697b7085b3d1b4d056c45797ff476c0e3abab22` |
|  |  | `msg/VehicleCommand.msg` | `19e2761cdb36eec26dc9fa3dd5fcd96b432bef84` |
|  |  | `msg/VehicleCommandAck.msg` | `ef43256af5cb9b7b4264737c7f4c6004e2c221f8` |
|  |  | `msg/BatteryStatus.msg` | `65845b57aec2f7e4176cf58b01ff3cbe3e3df8db` |
|  |  | `msg/SensorGps.msg` | `4404dd524fbac5049574a2a168db1ae4f78b5fe4` |
|  |  | `msg/EstimatorStatus.msg` | `f3b76f18edbaf85cad4ebdcfca1c806c5ce9d4e6` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `88123548a76d4933fb936adf53981424fb13c98c` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `598531a0da9bdaace34a3959c741df6d55b598d8` |
| `v1.15.0` | `30e763b6780061d70a14894e3e8b06e6a656f9b8` | `msg/VehicleStatus.msg` | `4c711b9763e1cfe209ebf2923970f0df99a7b58d` |
|  |  | `msg/FailsafeFlags.msg` | `44945afaead07bf812cfd6088f0c3f9e0ee9bd7d` |
|  |  | `msg/VehicleCommand.msg` | `b147bef092085f827092e761967456fc8cf9dacc` |
|  |  | `msg/VehicleCommandAck.msg` | `6f54fa46315b557c31550a1b88e281ed29447ea3` |
|  |  | `msg/BatteryStatus.msg` | `66fcffa0e68f0d3cddabcde05bf2784ca04dd42d` |
|  |  | `msg/SensorGps.msg` | `ce2bfad4fd8ea87aa2009e1a112e59d96dbd6577` |
|  |  | `msg/EstimatorStatus.msg` | `5491734b1d8e72fe9e167a005fe08c679849e2a1` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `9f88f85f3e8eaf68f7b617a00947bba9c5d77452` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `598531a0da9bdaace34a3959c741df6d55b598d8` |
| `v1.15.1` | `93eef0c78719a9ac972d46593262c76c978ed3c4` | `msg/VehicleStatus.msg` | `4c711b9763e1cfe209ebf2923970f0df99a7b58d` |
|  |  | `msg/FailsafeFlags.msg` | `44945afaead07bf812cfd6088f0c3f9e0ee9bd7d` |
|  |  | `msg/VehicleCommand.msg` | `5606883623fae4db305289f1a9d50e32f5dfcaf2` |
|  |  | `msg/VehicleCommandAck.msg` | `6f54fa46315b557c31550a1b88e281ed29447ea3` |
|  |  | `msg/BatteryStatus.msg` | `66fcffa0e68f0d3cddabcde05bf2784ca04dd42d` |
|  |  | `msg/SensorGps.msg` | `ce2bfad4fd8ea87aa2009e1a112e59d96dbd6577` |
|  |  | `msg/EstimatorStatus.msg` | `5491734b1d8e72fe9e167a005fe08c679849e2a1` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `9f88f85f3e8eaf68f7b617a00947bba9c5d77452` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `598531a0da9bdaace34a3959c741df6d55b598d8` |
| `v1.15.2` | `4817c0618a1286846116e90c6eb8919efaa013cf` | `msg/VehicleStatus.msg` | `4c711b9763e1cfe209ebf2923970f0df99a7b58d` |
|  |  | `msg/FailsafeFlags.msg` | `44945afaead07bf812cfd6088f0c3f9e0ee9bd7d` |
|  |  | `msg/VehicleCommand.msg` | `5606883623fae4db305289f1a9d50e32f5dfcaf2` |
|  |  | `msg/VehicleCommandAck.msg` | `6f54fa46315b557c31550a1b88e281ed29447ea3` |
|  |  | `msg/BatteryStatus.msg` | `66fcffa0e68f0d3cddabcde05bf2784ca04dd42d` |
|  |  | `msg/SensorGps.msg` | `ce2bfad4fd8ea87aa2009e1a112e59d96dbd6577` |
|  |  | `msg/EstimatorStatus.msg` | `5491734b1d8e72fe9e167a005fe08c679849e2a1` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `9f88f85f3e8eaf68f7b617a00947bba9c5d77452` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `598531a0da9bdaace34a3959c741df6d55b598d8` |
| `v1.15.3` | `80171359656faf881dc643022f61ebde734d7cb6` | `msg/VehicleStatus.msg` | `4c711b9763e1cfe209ebf2923970f0df99a7b58d` |
|  |  | `msg/FailsafeFlags.msg` | `44945afaead07bf812cfd6088f0c3f9e0ee9bd7d` |
|  |  | `msg/VehicleCommand.msg` | `5606883623fae4db305289f1a9d50e32f5dfcaf2` |
|  |  | `msg/VehicleCommandAck.msg` | `6f54fa46315b557c31550a1b88e281ed29447ea3` |
|  |  | `msg/BatteryStatus.msg` | `66fcffa0e68f0d3cddabcde05bf2784ca04dd42d` |
|  |  | `msg/SensorGps.msg` | `ce2bfad4fd8ea87aa2009e1a112e59d96dbd6577` |
|  |  | `msg/EstimatorStatus.msg` | `5491734b1d8e72fe9e167a005fe08c679849e2a1` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `9f88f85f3e8eaf68f7b617a00947bba9c5d77452` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `598531a0da9bdaace34a3959c741df6d55b598d8` |
| `v1.15.4` | `99c40407ffd7ac184e2d7b4b293f36f10fe561ef` | `msg/VehicleStatus.msg` | `4c711b9763e1cfe209ebf2923970f0df99a7b58d` |
|  |  | `msg/FailsafeFlags.msg` | `44945afaead07bf812cfd6088f0c3f9e0ee9bd7d` |
|  |  | `msg/VehicleCommand.msg` | `5606883623fae4db305289f1a9d50e32f5dfcaf2` |
|  |  | `msg/VehicleCommandAck.msg` | `6f54fa46315b557c31550a1b88e281ed29447ea3` |
|  |  | `msg/BatteryStatus.msg` | `66fcffa0e68f0d3cddabcde05bf2784ca04dd42d` |
|  |  | `msg/SensorGps.msg` | `ce2bfad4fd8ea87aa2009e1a112e59d96dbd6577` |
|  |  | `msg/EstimatorStatus.msg` | `5491734b1d8e72fe9e167a005fe08c679849e2a1` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `9f88f85f3e8eaf68f7b617a00947bba9c5d77452` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `598531a0da9bdaace34a3959c741df6d55b598d8` |
| `v1.16.0` | `6ea3539157ca358c70a515878b77077af7d4611d` | `msg/versioned/VehicleStatus.msg` | `0a94fde86c896b8ce55078105c4c4eb96a5d4820` |
|  |  | `msg/FailsafeFlags.msg` | `33240b075981d5a361c9b1cc8302e44389bce71f` |
|  |  | `msg/versioned/VehicleCommand.msg` | `96162e9f89f9e784db63f2a4a7a5f047fd997637` |
|  |  | `msg/versioned/VehicleCommandAck.msg` | `c11a5f8c5dfdc0dbcbe10e504a812eb31046a868` |
|  |  | `msg/versioned/BatteryStatus.msg` | `852db501dfd6bd50d827c580a7e81f54caee7d70` |
|  |  | `msg/SensorGps.msg` | `ce2bfad4fd8ea87aa2009e1a112e59d96dbd6577` |
|  |  | `msg/EstimatorStatus.msg` | `3de2bfd72293c9c616c91ff57a31e7aac70573ef` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `30375908a9a83fb9b294d6cb5d23aadb4f174eed` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `7352a6bbfe9e77866aca1741ecdc292a5386e0f6` |
| `v1.16.1` | `94cb2012792b2ae89f0b147cfee53ee31ae550be` | `msg/versioned/VehicleStatus.msg` | `0a94fde86c896b8ce55078105c4c4eb96a5d4820` |
|  |  | `msg/FailsafeFlags.msg` | `33240b075981d5a361c9b1cc8302e44389bce71f` |
|  |  | `msg/versioned/VehicleCommand.msg` | `96162e9f89f9e784db63f2a4a7a5f047fd997637` |
|  |  | `msg/versioned/VehicleCommandAck.msg` | `c11a5f8c5dfdc0dbcbe10e504a812eb31046a868` |
|  |  | `msg/versioned/BatteryStatus.msg` | `852db501dfd6bd50d827c580a7e81f54caee7d70` |
|  |  | `msg/SensorGps.msg` | `ce2bfad4fd8ea87aa2009e1a112e59d96dbd6577` |
|  |  | `msg/EstimatorStatus.msg` | `3de2bfd72293c9c616c91ff57a31e7aac70573ef` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `30375908a9a83fb9b294d6cb5d23aadb4f174eed` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `7352a6bbfe9e77866aca1741ecdc292a5386e0f6` |
| `v1.16.2` | `54f0455ffcd755534539a7cf33a09a20bf71d29d` | `msg/versioned/VehicleStatus.msg` | `0a94fde86c896b8ce55078105c4c4eb96a5d4820` |
|  |  | `msg/FailsafeFlags.msg` | `33240b075981d5a361c9b1cc8302e44389bce71f` |
|  |  | `msg/versioned/VehicleCommand.msg` | `96162e9f89f9e784db63f2a4a7a5f047fd997637` |
|  |  | `msg/versioned/VehicleCommandAck.msg` | `c11a5f8c5dfdc0dbcbe10e504a812eb31046a868` |
|  |  | `msg/versioned/BatteryStatus.msg` | `852db501dfd6bd50d827c580a7e81f54caee7d70` |
|  |  | `msg/SensorGps.msg` | `ce2bfad4fd8ea87aa2009e1a112e59d96dbd6577` |
|  |  | `msg/EstimatorStatus.msg` | `3de2bfd72293c9c616c91ff57a31e7aac70573ef` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `30375908a9a83fb9b294d6cb5d23aadb4f174eed` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `7352a6bbfe9e77866aca1741ecdc292a5386e0f6` |
| `v1.17.0` | `d6f12ad1c4f70ad3230afd7d86e971421e02fef4` | `msg/versioned/VehicleStatus.msg` | `0dffdc2c92de9063f085614796deacf7980f10ea` |
|  |  | `msg/FailsafeFlags.msg` | `243a4b5c9e20753aa8b73d89375e687d9f241145` |
|  |  | `msg/versioned/VehicleCommand.msg` | `8f20ec2d8570f965870abcac3048e6284d2c5733` |
|  |  | `msg/versioned/VehicleCommandAck.msg` | `c11a5f8c5dfdc0dbcbe10e504a812eb31046a868` |
|  |  | `msg/versioned/BatteryStatus.msg` | `7c390c4576d925a2b098603ad6aa31028ea4a53d` |
|  |  | `msg/SensorGps.msg` | `2e94d174f344386e8487a027d2cabc24679d12bc` |
|  |  | `msg/EstimatorStatus.msg` | `cf565e02d3ad2741eb8df3659080af3455edc297` |
|  |  | `msg/EstimatorSelectorStatus.msg` | `52f8085901096ee06f89aa2e0eb9b0ce2daf6e89` |
|  |  | `msg/VehicleImuStatus.msg` | `78fb44703ed90da66f234e6cc10248168718c36d` |
|  |  | `msg/SensorSelection.msg` | `799ccf18a3893dec54f315e3916863447e1b14ce` |
|  |  | `src/modules/commander/failsafe/framework.cpp` | `19528b59e988654766173361851d13e74110923d` |
|  |  | `src/modules/commander/HealthAndArmingChecks/checks/modeCheck.cpp` | `d13a4a19ae6cc2eb5579d82546ce521cb7b72f42` |

<!-- px4-sources:end -->

## The ULog specification

`docs/en/dev_log/ulog_file_format.md` in PX4-Autopilot, at commit `d28a64240f7b7570d65776b9b6397eddec0dd9ba`, sets requirements for parsers (section "Requirements for Parsers", lines 470 to 480 at that commit; the file is unchanged at `3fe7acc19dffcd694e2fed5a86f7a913701202fe`). The tests named `ulog_spec_*` in `crates/sfr-core/src/ingest.rs` check `sfr` against them:

- **Unknown incompatible flag bits.** Every one of the 63 bits other than DATA_APPENDED makes `sfr` refuse the log, as the specification requires. Unknown compatible flag bits are ignored, and a flag bits message longer than 40 bytes is read with its extra bytes ignored.
- **Unknown message types** are skipped, as required; the flight reads the same with them as without, and the record counts them (`log.skipped`).
- **Appended data** is read as ordinary data: a flight cut in the middle of a record, with the rest of it appended at the announced offset, gives the same rows and events as the uncut flight. The cut record is the one skipped region. Writing this test found that `sfr` counted the region without the cut record's 3-byte header; it now counts the whole record.
- **A log that ends in the middle of a record.** The specification, lines 477 and 478: "A parser must be able to correctly handle logs that end abruptly, in the middle of a message. The unfinished message should just be discarded." `sfr` reads every complete record, discards the unfinished one, and seals the log. The signed record (schema 5, `log.truncated`) and its report say `log ended mid-record at byte N; K trailing bytes not parsed`, where N is the offset of the unfinished record and K the bytes from there to the end of the file. `log.size`, `log.sha256` and `log.blake3` still cover every byte of the file, so `verify --ulog` passes on the cut file and fails on any longer or shorter one. The rules read the missing tail as input that never arrived: a log that ends armed fails R5, and the finding names the cut. Tests: `ulog_spec_a_log_that_ends_in_the_middle_of_a_message_is_read_up_to_it` (in `crates/sfr-core/src/ingest.rs`), `every_cut_is_read_up_to_the_unfinished_record_never_a_panic` (every cut of a sample log, in `crates/sfr-core/src/ulog.rs`), and `a_log_cut_mid_record_seals_says_where_and_its_digests_cover_every_byte` (in `crates/sfr/tests/seal_verify.rs`), on the fixtures `testdata/synthetic/cut_mid_message.ulg`, `cut_mid_header.ulg` and `cut_after_arm.ulg` and their control `cut_control.ulg`. A golden log cut in its data section is checked by `a_cut_log_is_read_up_to_the_cut_unless_it_has_no_data_record` (in `crates/sfr/tests/seal_dry_run.rs`).
- **Future file format versions.** The specification gives the current version as 1 (line 65) and asks a parser to "parse future/unknown file format versions as well (but it can print a warning)" (line 475). `sfr` reads any version as version 1. `seal` refuses a log whose version is above 1 (exit 4, nothing written) unless given `--allow-untested-version`, the flag that already covers an untested PX4 version; then it warns, and the signed record (schema 5, `seal.allow_untested_ulog_version` true, `log.ulog_version`) and its report say `Untested ULog file version`. Tests: `ulog_spec_a_future_file_format_version_is_read_and_reported` (in `crates/sfr-core/src/ingest.rs`) and `a_ulog_file_version_above_1_is_refused_unless_allowed_and_then_recorded` (in `crates/sfr/tests/seal_verify.rs`), on `testdata/synthetic/ulog_version_2.ulg`.

Where `sfr` does otherwise, on purpose (`ulog_spec_differences_sfr_keeps`, `a_cut_log_is_read_up_to_the_cut_unless_it_has_no_data_record`):

- A log that ends before its first data record, whether at a record boundary or inside a record, is refused (exit 3): it holds no flight for the rules to read. A file shorter than its 16-byte header is not a log.
- A log that ends in the middle of a record before an appended-data offset it announced is refused (exit 3): its appended data is missing. The specification's version history (lines 504 to 508) notes that data appended to a log cut in the middle of a message cannot be parsed by a version 1 parser.
- DATA_APPENDED set with every offset 0 is read as a log with nothing appended; the specification says at least one offset is non-zero then.
- An appended-data offset past the end of the file is refused as truncated; the specification does not say what to do.

## The oracles

An oracle here is a second implementation that `sfr`'s output is compared with. None of them was written by a separate team: each is maintained in this repository by the same people as `sfr`, and each was changed when the rules changed. They share no code with `sfr`, so they catch parsing and arithmetic mistakes, and a difference between two readings of the same text. They do not catch a rule that is wrong in the document both follow.

| Oracle | What it is | What it compares |
|---|---|---|
| `scripts/testdata/oracle.py` | Python on pyulog, the PX4 project's ULog parser, instead of `sfr`'s parser. It takes PX4's field types, flags and mode requirements from `scripts/testdata/px4_tables.json`, which `scripts/px4/px4_tables.py` writes from the same PX4 source as `sfr`'s tables: the data is shared, the code is not. Test-only: `scripts/testdata/requirements-dev.txt` pins pyulog and numpy by hash, and neither is a dependency of `sfr`. | Events, R1, R4, R5, R6 and R7, sealed topic digests and configuration on every golden log (`scripts/testdata/compare_oracle.py`); R1, R4, R5 and R6 on every false-pass log. `scripts/testdata/oracle_differential.py` runs both now; the `oracle-differential` CI job fails on any difference. |
| `tools/reference_verifier/sfr_ref_verify.py` | A record verifier in the Python standard library, from [RECORD_FORMAT.md](RECORD_FORMAT.md). | The verdict on every crafted record and every committed record (`crates/sfr/tests/reference_verifier.rs`). |
| `crates/sfr/tests/report_facts/mod.rs` | A test-side reading of the report, written from the record. | Every line of every report the tests make, including the quoting of the verify command. |
| `scripts/testdata/make_baseline.py` | The baselines, read with pyulog. | R3, through the committed baselines. |

## False-pass attempts and what became of them

The 15 crafted logs of `testdata/falsepass/cases.json`, each sealed by the build before these fixes (commit `27dedad`) and by this one. The earlier build gave PASS on 14 of them; the fifteenth, `golden_armed_rows_deleted`, failed R3 only because its baseline holds the parameters in effect at the first ARM, which that build did not compare; it did not see the trick (R5 PASS with no ARM and no DISARM). `scripts/testdata/run_falsepass.py` prints the table for any build.

| Outcome on this build | Cases |
|---|---|
| FAIL, naming the trick | 7: `failsafe_uint8`, `arming_int8`, `transition_uint8`, `resubscribe_retyped` (a field type that is not PX4's), `instance_one_failsafe` (a second `vehicle_status` instance), `vtol_mav_type_not_vtol` (a VTOL `system_type` with `is_vtol` false), `mode_req_uint64` (a mode requirement mask wider than PX4's) |
| NO ARMED FLIGHT, not a PASS | 2: `never_armed_failsafe`, `golden_armed_rows_deleted` |
| WARN | 2: `flag_gcs_connection_lost` (a failsafe flag true in flight that the flight mode does not require), `golden_param_at_arm` (a parameter changed at the arming time) |
| Refused, nothing sealed | 2: `duplicate_failsafe` (a field declared twice), `ignore_all` (a rules file that ignores every parameter, refused without `--allow-ignore-all`) |
| PASS, with the trick stated in the signed record and the report | 2: `r7_scoped_general` (R7 scoped to one command category; the R7 line states the scope and how many commands it excluded), `unknown_messages` (records `sfr` cannot attribute; the record and the report count them as skipped) |

So 13 of the 15 no longer give a plain PASS. The last 2 pass because the operator chose the scope, or because the skipped records hold nothing the rules read; the signed record says so in both cases. Every positive control gives its stated result, and `scripts/testdata/oracle_differential.py` gets the same R1, R4, R5 and R6 from pyulog on all 30 logs. Run on the build at `27dedad`, the same script differs from pyulog on 16 of the false-pass logs and 9 of the golden logs.

## False passes that remain

These cannot be caught from the log, because the log or the operator supplies the input that decides them. Each is also a row of the input table in [THREAT_MODEL.md](THREAT_MODEL.md#inputs-that-decide-the-verdict).

- **A log edited before sealing.** `sfr` seals the bytes it is given. A log rewritten consistently before `seal` (rows removed, values changed, types kept as PX4 defines them) is sealed as it is, and its rules are computed from the rewritten data. The seal proves the log has not changed since sealing, not that it is what the vehicle wrote. Sealing on the vehicle, or as close to it as possible, narrows this.
- **Forged command source ids.** R7 reads `source_system` and `source_component` from `vehicle_command`, which the sender of each command sets. A sender that claims an authorized id passes R7; the R7 line says the ids are self-reported.
- **A baseline taken from the same log.** R2 and R3 compare the log with the operator's baseline. A baseline made from the flight log itself (as `scripts/testdata/make_baseline.py` does for the golden logs) passes R2 and R3 by construction. The record carries the baseline's SHA-256, so a reviewer can ask where it came from; `sfr` cannot.
- **Operator-set scope.** The rules file decides which topics R1 requires, which parameters R3 ignores and which command categories R7 checks. A narrow rules file passes more logs. The rules file is embedded in the signed record and its scope is stated in the R3 and R7 lines, and a rules file that ignores every parameter needs `--allow-ignore-all`, which is recorded.

## Reproducing

Not run in CI as written here: the second command needs a Python with the test-only packages, which the `oracle-differential` CI job installs itself before running the same script.

```sh doc-syntax
python3 -I scripts/testdata/run_falsepass.py target/release/sfr --table
"$SFR_ORACLE_PYTHON" -I scripts/testdata/oracle_differential.py target/release/sfr
```

`SFR_ORACLE_PYTHON` is a Python with `scripts/testdata/requirements-dev.txt` installed. The claims audit (T12 and T13) runs both from a fresh clone.
