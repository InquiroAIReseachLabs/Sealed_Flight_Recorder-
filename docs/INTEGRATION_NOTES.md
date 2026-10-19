# Integration notes

How `sfr` fits into a flight operation: which parts of a PX4 log it reads, how to seal on a companion computer right after disarm, how to use it in CI, and where the signing key should live. The commands below need `sfr` built as in the [README](../README.md#quickstart) and run from the repository root; the ones CI runs write only into `try/`.

## What `sfr` reads from a log

`sfr` reads a PX4 ULog file (PX4 v1.14 to v1.17; tested on v1.14.4 and v1.17.0 logs; other versions are accepted with a warning but not tested, [RULES.md](RULES.md)) once, as a stream, and hashes every byte. The decoders are in `crates/sfr-core/src/ingest.rs`; [RULES.md](RULES.md) says which rule reads what.

| Topic | Fields | Why | Needed |
|---|---|---|---|
| `vehicle_status` | `arming_state`, `nav_state`, `failsafe`, `is_vtol`, `in_transition_mode`, `in_transition_to_fw`, `vehicle_type`; also `system_type`, `latest_arming_reason`, `latest_disarming_reason` when present | ARM, DISARM, NAV_STATE_CHANGE, FAILSAFE and VTOL events; the vehicle identity; R4, R5, R6 | always (R1) |
| `failsafe_flags` | every `bool` field, and `battery_warning` | which flags a failsafe event and R4 name | always (R1) |
| `vehicle_command` | `command`, `source_system`, `source_component` | COMMAND events; R7 | with `[authorized_sources]` (R1) |
| `vehicle_command_ack` | `command`, `result`, `target_system`, `target_component` | each command's result, else `NO_ACK` | no |
| `vehicle_gps_position`, else `sensor_gps` | `fix_type`, `time_utc_usec` (instance 0) | UTC time of events, from the first sample with a fix | no: without it `utc_us` is null |
| `vehicle_gps_position` | `fix_type`, `satellites_used` (instance 0) | X2 | with `[extended.gps_fix_at_arm]` |
| `battery_status` | `remaining`, `connected` | X1 | with `[extended.min_battery]` |
| `estimator_status`, `estimator_selector_status` | `filter_fault_flags`; `primary_instance` | X3 | with `[extended.estimator_faults]` |
| `vehicle_imu_status`, `sensor_selection` | `accel_device_id`, `accel_clipping`, `accel_vibration_metric`; `accel_device_id` | X4 | with `[extended.vibration]` |
| each topic in `[sealed_topics]` | none: each instance's format record and data records are digested as bytes | the sealed topic digests | yes (R1) |
| each topic in `[required_topics]` | none: data records are counted | R1 | yes (R1) |

Besides topics, `sfr` reads the info messages `ver_sw_release` and `ver_sw` (firmware identity, R2), the parameters ('P' records: those before the first subscription are the configuration that flew, later ones are PARAM_CHANGED_IN_FLIGHT events), logged messages at warning level or above ('L' and 'C', LOG_MESSAGE events), and dropouts ('O', LOG_DROPOUT events and X5). It does not decode the `event` topic, and it does not read `vtol_vehicle_status`. [LIMITS.md](LIMITS.md) gives the limits a log must stay within.

**PX4 logging.** The PX4 source puts `vehicle_status`, `failsafe_flags`, `vehicle_command` and `vehicle_command_ack` in PX4's default logging profile at every publication; every golden log in `testdata/` was recorded in SITL with a larger profile, so no hardware log with the default profile has been checked. With PX4's default logging modes the log file is closed at disarm, so a sealed log ends shortly after the DISARM event. A `logger_topics.txt` file on the flight controller replaces the profiles: if you use one, keep the topics above in it.

## Sealing on a companion computer after disarm

Sealing right after disarm shortens the time in which a log can be changed before it is sealed ([THREAT_MODEL.md](THREAT_MODEL.md)). This example is a script and two systemd units for a Linux companion computer. **It is an example: it has not been tested on any specific vehicle or companion computer.** Bringing the finished log from the flight controller to the companion computer is up to your system and is not part of `sfr`; the example only expects each finished log to be moved, complete, into one directory.

The script seals and verifies every log in `incoming/`, then moves it to `sealed/`, or to `failed/` when it cannot be sealed or the record does not verify, so a bad log is not retried forever. A rule FAIL is not a failure here: the record is written and holds the result.

```sh doc-test
mkdir -p try
cat > try/sfr-seal-incoming <<'EOF'
#!/usr/bin/env bash
# sfr-seal-incoming: seal and verify every finished PX4 log in $SFR_DATA/incoming.
# Example only; not tested on any specific vehicle.
set -euo pipefail
sfr="${SFR:-/usr/local/bin/sfr}"
conf="${SFR_CONF:-/etc/sfr}"
data="${SFR_DATA:-/var/lib/sfr}"
mkdir -p "$data/incoming" "$data/records" "$data/sealed" "$data/failed"
for log in "$data"/incoming/*.ulg; do
  [ -e "$log" ] || continue
  name="$(basename "$log" .ulg)"
  rc=0
  "$sfr" seal "$log" --rules "$conf/rules.toml" --baseline "$conf/baseline.params" \
    --key "$conf/sfr.key" --evaluation-only --out "$data/records" || rc=$?
  # 0: every rule passed; 1: a rule failed; 2: a required topic is missing. All three wrote the record.
  if [ "$rc" -gt 2 ]; then
    echo "sfr-seal-incoming: $name: seal exited $rc, nothing written; moved to failed/" >&2
    mv "$log" "$data/failed/"
    continue
  fi
  if ! "$sfr" verify "$data/records/$name.sfr" --pubkey "$conf/sfr.pub" --ulog "$log"; then
    echo "sfr-seal-incoming: $name: the new record does not verify; moved to failed/" >&2
    mv "$log" "$data/failed/"
    continue
  fi
  mv "$log" "$data/sealed/"
  echo "sfr-seal-incoming: $name: sealed (seal exit $rc) and verified"
done
EOF
chmod +x try/sfr-seal-incoming
```

CI runs it on two golden logs, one that passes every rule and one that fails R4, with a new evaluation key:

```sh doc-test
mkdir -p try/conf try/data/incoming
target/release/sfr keygen --evaluation-only --out try/conf > /dev/null
cp examples/rules.default.toml try/conf/rules.toml
cp testdata/baselines/v1.17.0_failsafe_gps_loss.params try/conf/baseline.params
cp testdata/sitl/v1.17.0/vtol_transition.ulg testdata/sitl/v1.17.0/failsafe_gps_loss.ulg try/data/incoming/
SFR=target/release/sfr SFR_CONF=try/conf SFR_DATA=try/data try/sfr-seal-incoming > try/run.log 2>&1
grep '^sfr-seal-incoming' try/run.log
ls try/data/records try/data/sealed
```

```text doc-output
sfr-seal-incoming: failsafe_gps_loss: sealed (seal exit 1) and verified
sfr-seal-incoming: vtol_transition: sealed (seal exit 1) and verified
try/data/records:
failsafe_gps_loss.sfr
failsafe_gps_loss.sfr.md
vtol_transition.sfr
vtol_transition.sfr.md

try/data/sealed:
failsafe_gps_loss.ulg
vtol_transition.ulg
```

`vtol_transition` exits 1 here because it is checked against the other flight's baseline (R3 fails): one baseline per vehicle configuration is what you would install.

The two units start the script whenever `incoming/` holds a file. Not run in CI: they need systemd on the companion computer. They are not shell, so they are not checked at all; check them with `systemd-analyze verify` on the target.

```ini
# /etc/systemd/system/sfr-seal.path (example, not tested on any vehicle)
[Unit]
Description=Seal PX4 logs as they arrive in /var/lib/sfr/incoming

[Path]
DirectoryNotEmpty=/var/lib/sfr/incoming

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/sfr-seal.service (example, not tested on any vehicle)
[Unit]
Description=Seal and verify the PX4 logs in /var/lib/sfr/incoming

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sfr-seal-incoming
```

Install it on the companion computer, with the `sfr` binary built for that computer, your rules file, the baseline of that vehicle's configuration, and its key. Not run in CI: it changes a machine's system directories.

```sh doc-syntax
sudo install -m 0755 sfr /usr/local/bin/sfr
sudo install -m 0755 sfr-seal-incoming /usr/local/bin/sfr-seal-incoming
sudo install -d -m 0700 /etc/sfr /var/lib/sfr
sudo install -m 0644 rules.toml /etc/sfr/rules.toml
sudo install -m 0644 baseline.params /etc/sfr/baseline.params
sudo install -m 0644 sfr.pub /etc/sfr/sfr.pub
sudo install -m 0600 sfr.key /etc/sfr/sfr.key
sudo install -m 0644 sfr-seal.path sfr-seal.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sfr-seal.path
journalctl -u sfr-seal.service
```

Copy the records from `/var/lib/sfr/records/` off the vehicle with the logs; anyone with the public key can then verify them anywhere.

## In CI or another pipeline

`sfr verify` reports two things apart. `Integrity:` is the seal: VERIFIED when the record (and, with `--ulog`, the log) has not changed since it was sealed. `Flight rules:` is the rule results sealed in the record: PASS, or FAIL with the failing rule ids. The exit code follows integrity only: 0 when the record verifies, even if its flight rules failed, and 1 when it does not. `--json` gives the same as `integrity`, `flight_rules` and `failed_rules`. This function fails a pipeline on a record that does not verify against its log, and on one that verifies but recorded a rule FAIL:

```sh doc-test
mkdir -p try
check_record() { # check_record <record.sfr> <sfr.pub> <log.ulg>
  if ! target/release/sfr verify "$1" --pubkey "$2" --ulog "$3" --json > try/verify.json; then
    echo "FAIL: $1 does not verify: $(grep '"first_mismatch"' try/verify.json)"
    return 1
  fi
  if ! grep -q '"flight_rules": "PASS"' try/verify.json; then
    echo "FAIL: $1 verifies, but a rule failed when it was sealed"
    return 1
  fi
  echo "ok: $1"
}
check_record examples/reports/vtol_transition.sfr examples/reports/sfr.pub testdata/sitl/v1.17.0/vtol_transition.ulg
check_record examples/reports/failsafe_gps_loss.sfr examples/reports/sfr.pub testdata/sitl/v1.17.0/failsafe_gps_loss.ulg || echo "the pipeline stops here"
cp testdata/sitl/v1.17.0/vtol_transition.ulg try/changed.ulg
printf 'x' | dd of=try/changed.ulg bs=1 seek=4096 conv=notrunc status=none
check_record examples/reports/vtol_transition.sfr examples/reports/sfr.pub try/changed.ulg || echo "the pipeline stops here"
```

```text doc-output
ok: examples/reports/vtol_transition.sfr
FAIL: examples/reports/failsafe_gps_loss.sfr verifies, but a rule failed when it was sealed
the pipeline stops here
FAIL: examples/reports/vtol_transition.sfr does not verify:   "first_mismatch": "log digest mismatch: sha256 sealed \"86d64e54d1261991f4035355550f64e017f8a486c5c665848d6e68ae67fc9bf3\", found \"4df365611ef8c5dfb0f783f6bbffd18b7214dbc29cdc3253cc512f28b0d9ddba\"",
the pipeline stops here
```

In a pipeline script run with `set -e`, the `return 1` stops the job; the `|| echo` above only lets this page show all three cases. The exit codes of every command are in the [README](../README.md#exit-codes).

## Keys

- **Keep the signing key off the vehicle where you can.** A key on a vehicle goes wherever the vehicle goes. If logs reach a ground station soon after landing, sealing there keeps the key off the vehicle at the cost of a longer disarm-to-seal window; sealing on the companion computer shortens the window but puts a key on board. Choose per operation, and use one key per vehicle, so that a lost vehicle costs the records of one key.
- **This build has file keys only** (`sfr keygen --evaluation-only`); every record they seal holds custody `file-evaluation`, and its report says EVALUATION KEY. A key file is protected only by file permissions (`keygen` writes `sfr.key` with mode 0600). The hardware key sources, a PKCS#11 token and a TPM-sealed seed, exit 4 with "not available in this build", so this page has no commands for them yet.
- **`sfr` does not manage keys beyond `keygen`.** It does not rotate, revoke, back up, escrow or distribute them. Keep a list of which fingerprint belongs to which vehicle and when it was in service; when a key is lost or stolen, stop trusting records with its fingerprint from that time ([THREAT_MODEL.md](THREAT_MODEL.md)).
- **Give verifiers the public key out of band.** `verify` checks a record against the `sfr.pub` it is given; a record re-signed by someone else verifies against their key. Publish each vehicle's public key and fingerprint where your verifiers can check it.
- **Use `--seal-time` only for reproducible examples.** Without it, the seal time is the sealing machine's clock, which is still the sealer's statement, not proof ([THREAT_MODEL.md](THREAT_MODEL.md)).
