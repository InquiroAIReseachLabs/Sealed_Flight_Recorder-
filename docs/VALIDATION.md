# Validation

What was tested, on what, how many crafted false-pass attempts there were and what became of them, and which kinds of false pass remain. Every result here is computed from data the log declares about itself; this page says how far that can be trusted.

## What was tested

- **Golden logs.** The logs `scripts/testdata/golden_logs.sh` lists: 14 logs, which are the pyulog sample, one PX4 v1.14.4 flight and ten PX4 v1.17.0 flights recorded in simulation (`testdata/sitl/`), and two synthetic logs (`testdata/synthetic/`). Each is sealed and its expected output is committed under `testdata/expected/`. No golden log comes from PX4 v1.15 or v1.16: those versions are covered only by the field-type tables in `crates/sfr-core/src/ingest.rs`.
- **False-pass corpus.** `testdata/falsepass/`, written by `scripts/testdata/make_falsepass.py`: 15 crafted logs, each built to look like a passing flight to a reader that trusts what a log declares about its own structure, and beside each a positive control without the trick (30 logs in all, listed in `testdata/falsepass/cases.json`). `crates/sfr/tests/falsepass.rs` checks every case.
- **Crafted records.** `tools/reference_verifier/vectors/`, written by `tools/reference_verifier/make_vectors.py`: 37 records, many built to trip a lenient JSON reader or to carry a result set that is not R1 to R7 exactly once. `crates/sfr/tests/reference_verifier.rs` runs `sfr verify` and the reference verifier on each.
- **Tampering and trust inputs.** The claims audit ([CLAIMS_AUDIT.md](CLAIMS_AUDIT.md)): 24 tamper cases in T3 (`scripts/claims_audit/t03_tamper.py`), 12 attacks on the seal time, custody, CRLs, the report and the signed structure in T12 (`scripts/claims_audit/t12_attacks.sh`); and the tests of planted key programs, intermediate anchors, CRL age and verification at a past time (`crates/sfr/tests/trust_inputs.rs`, `crates/sfr/tests/certificates.rs`).
- **Output.** Log text and file names built to forge report content or a shell command (`hostile_log_text_and_file_names_give_a_literal_report_and_a_working_verify_command` in `crates/sfr/tests/seal_verify.rs`).

## The oracles

An oracle here is a second implementation that `sfr`'s output is compared with. None of them was written by a separate team: each is maintained in this repository by the same people as `sfr`, and each was changed when the rules changed. They share no code with `sfr`, so they catch parsing and arithmetic mistakes, and a difference between two readings of the same text. They do not catch a rule that is wrong in the document both follow.

| Oracle | What it is | What it compares |
|---|---|---|
| `scripts/testdata/oracle.py` | Python on pyulog, the PX4 project's ULog parser, instead of `sfr`'s parser. Test-only: `scripts/testdata/requirements-dev.txt` pins pyulog and numpy by hash, and neither is a dependency of `sfr`. | Events, R1, R4, R5, R6 and R7, sealed topic digests and configuration on every golden log (`scripts/testdata/compare_oracle.py`); R1, R4, R5 and R6 on every false-pass log. `scripts/testdata/oracle_differential.py` runs both now; the `oracle-differential` CI job fails on any difference. |
| `tools/reference_verifier/sfr_ref_verify.py` | A record verifier in the Python standard library, from [RECORD_FORMAT.md](RECORD_FORMAT.md). | The verdict on every crafted record and every committed record (`crates/sfr/tests/reference_verifier.rs`). |
| `crates/sfr/tests/report_facts/mod.rs` | A test-side reading of the report, written from the record. | Every line of every report the tests make, including the quoting of the verify command. |
| `scripts/testdata/make_baseline.py` | The baselines, read with pyulog. | R3, through the committed baselines. |

## False-pass attempts and what became of them

The 15 crafted logs of `testdata/falsepass/cases.json`, each sealed by the build before these fixes (commit `27dedad`) and by this one. The earlier build gave PASS on 14 of them; the fifteenth, `golden_armed_rows_deleted`, failed R3 only because its baseline holds the parameters in effect at the first ARM, which that build did not compare; it did not see the trick (R5 PASS with no ARM and no DISARM). `scripts/testdata/run_falsepass.py` prints the table for any build.

| Outcome on this build | Cases |
|---|---|
| FAIL, naming the trick | 7: `failsafe_uint8`, `arming_int8`, `transition_uint8`, `resubscribe_retyped` (a field type that is not PX4's), `instance_one_failsafe` (a second `vehicle_status` instance), `vtol_mav_type_not_vtol` (a VTOL `system_type` with `is_vtol` false), `mode_req_uint64` (a mode requirement mask wider than PX4's) |
| NO ARMED FLIGHT, not a PASS | 2: `never_armed_failsafe`, `golden_armed_rows_deleted` |
| WARN | 2: `flag_gps_invalid` (a failsafe flag true in flight that the flight mode does not require), `golden_param_at_arm` (a parameter changed at the arming time) |
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
