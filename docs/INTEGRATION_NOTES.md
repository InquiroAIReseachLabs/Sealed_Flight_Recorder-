# Integration notes

Which parts of a PX4 log `sfr` reads, how to seal on a companion computer after disarm, how to use it in CI, and where the signing key should live. The commands need `sfr` built as in the [README](../README.md) and run from the repository root; the ones CI runs write only into `try/`.

## What `sfr` reads from a log

`sfr` reads a PX4 ULog file once, as a stream, and hashes every byte. It accepts PX4 v1.14 to v1.17 (tested on v1.14.4 and v1.17.0 logs); other versions are refused unless sealed with `--allow-untested-version`, which the record and report then state ([RULES.md](RULES.md)). The decoders are in `crates/sfr-core/src/ingest.rs`; [RULES.md](RULES.md) says which rule reads what.

| Topic | Fields | Used for | Needed |
|---|---|---|---|
| `vehicle_status` | `arming_state`, `nav_state`, `failsafe`, `is_vtol`, `in_transition_mode`, `in_transition_to_fw`, `vehicle_type`; `system_type`, `latest_arming_reason`, `latest_disarming_reason` when present | ARM, DISARM, NAV_STATE_CHANGE, FAILSAFE and VTOL events; vehicle identity; R4, R5, R6 | always (R1) |
| `failsafe_flags` | every `bool` field, and `battery_warning` | the flags a failsafe event and R4 name | always (R1) |
| `vehicle_command` | `command`, `source_system`, `source_component` | COMMAND events; R7 | with `[authorized_sources]` (R1) |
| `vehicle_command_ack` | `command`, `result`, `target_system`, `target_component` | each command's result, else `NO_ACK` | no |
| `vehicle_gps_position`, else `sensor_gps` | `fix_type`, `time_utc_usec` (instance 0) | UTC time of events, from the first sample with a fix | no (`utc_us` is null without it) |
| `vehicle_gps_position` | `fix_type`, `satellites_used` (instance 0) | X2 | with `[extended.gps_fix_at_arm]` |
| `battery_status` | `remaining`, `connected` | X1 | with `[extended.min_battery]` |
| `estimator_status`, `estimator_selector_status` | `filter_fault_flags`; `primary_instance` | X3 | with `[extended.estimator_faults]` |
| `vehicle_imu_status`, `sensor_selection` | `accel_device_id`, `accel_clipping`, `accel_vibration_metric`; `accel_device_id` | X4 | with `[extended.vibration]` |
| each topic in `[sealed_topics]` | none: format and data records are digested as bytes | the sealed topic digests | yes (R1) |
| each topic in `[required_topics]` | none: data records are counted | R1 | yes (R1) |

It also reads the info messages `ver_sw_release` and `ver_sw` (firmware identity, R2), the parameters ('P' records: those before the first subscription are the configuration that flew, later ones are PARAM_CHANGED_IN_FLIGHT events), logged messages at warning level or above ('L' and 'C', LOG_MESSAGE events), and dropouts ('O', LOG_DROPOUT events and X5). It does not decode the `event` topic or read `vtol_vehicle_status`. Input limits are in [LIMITS.md](LIMITS.md).

**PX4 logging.** PX4's default logging profile includes `vehicle_status`, `failsafe_flags`, `vehicle_command` and `vehicle_command_ack` at every publication. The golden logs in `testdata/` were recorded in SITL with a larger profile; no hardware log with the default profile has been checked. With the default logging modes the log closes at disarm. A `logger_topics.txt` on the flight controller replaces the profiles: keep the topics above in it.

## Sealing on a companion computer after disarm

Sealing right after disarm shortens the time in which a log can be changed before it is sealed ([THREAT_MODEL.md](THREAT_MODEL.md)). The example is a script and two systemd units for a Linux companion computer. It has not been tested on any specific vehicle. Getting the finished log from the flight controller is outside `sfr`; the script expects each finished log to be moved, complete, into one directory.

It seals and verifies every log in `incoming/`, then moves it to `sealed/`, or to `failed/` when it cannot be sealed or the record does not verify. A rule FAIL is not a failure here: the record is written and holds the result.

```sh doc-test
mkdir -p try
cat > try/sfr-seal-incoming <<'EOF'
#!/usr/bin/env bash
# sfr-seal-incoming: seal and verify every finished PX4 log in $SFR_DATA/incoming.
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
  if ! "$sfr" verify "$data/records/$name.sfr" --pubkey "$conf/sfr.pub" --allow-evaluation-key --ulog "$log"; then
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

CI runs it on two golden logs with a new evaluation key:

```sh doc-test
mkdir -p try/conf try/data/incoming
target/release/sfr keygen --evaluation-only --out try/conf > /dev/null
cp examples/rules.default.toml try/conf/rules.toml
cp testdata/baselines/v1.17.0_failsafe_gps_loss.params try/conf/baseline.params
cp testdata/sitl/v1.17.0/vtol_transition.ulg testdata/sitl/v1.17.0/failsafe_gps_loss.ulg try/data/incoming/
SFR=target/release/sfr SFR_CONF=try/conf SFR_DATA=try/data try/sfr-seal-incoming > try/run.log 2>&1
grep '^sfr-seal-incoming' try/run.log
ls try/data/sealed
```

```text doc-output
sfr-seal-incoming: failsafe_gps_loss: sealed (seal exit 1) and verified
sfr-seal-incoming: vtol_transition: sealed (seal exit 1) and verified
failsafe_gps_loss.ulg
vtol_transition.ulg
```

`vtol_transition` exits 1 here because it is checked against the other flight's baseline (R3 fails); install one baseline per vehicle configuration.

The two units start the script whenever `incoming/` holds a file. They are not run or checked in CI; check them with `systemd-analyze verify` on the target.

```ini
# /etc/systemd/system/sfr-seal.path
[Unit]
Description=Seal PX4 logs as they arrive

[Path]
DirectoryNotEmpty=/var/lib/sfr/incoming

[Install]
WantedBy=multi-user.target
```

```ini
# /etc/systemd/system/sfr-seal.service
[Unit]
Description=Seal and verify PX4 logs

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sfr-seal-incoming
```

Install the script as `/usr/local/bin/sfr-seal-incoming`, the units in `/etc/systemd/system/`, and put `sfr`, `rules.toml`, `baseline.params`, `sfr.pub` and `sfr.key` where the script's `SFR` and `SFR_CONF` defaults point (`/usr/local/bin/sfr`, `/etc/sfr/`; mode 0600 for the key), then run `systemctl enable --now sfr-seal.path`. Not run in CI.

Copy the records from `/var/lib/sfr/records/` off the vehicle with the logs; anyone with the public key can verify them.

## In CI or another pipeline

`sfr verify` reports two things apart. `Integrity:` is VERIFIED when the record (and, with `--ulog`, the log) has not changed since sealing. `Flight rules:` is the rule results sealed in the record: PASS, or FAIL with the failing rule ids. The exit code follows integrity only: 0 when the record verifies, even if its rules failed, 1 when it does not. `--json` gives `integrity`, `flight_rules` and `failed_rules`. This function fails a pipeline on a record that does not verify against its log, and on one that verifies but recorded a rule FAIL:

```sh doc-test
mkdir -p try
check_record() { # check_record <record.sfr> <sfr.pub> <log.ulg>
  if ! target/release/sfr verify "$1" --pubkey "$2" --allow-evaluation-key --ulog "$3" --json > try/verify.json; then
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

Under `set -e` the `return 1` stops the job; the `|| echo` only lets this page show all three cases. Exit codes are in the [README](../README.md#exit-codes).

## Keys

- **Keep the signing key off the vehicle where you can.** Sealing at a ground station keeps the key off the vehicle but lengthens the disarm-to-seal window; sealing on the companion computer shortens it but puts a key on board. Use one key per vehicle, so a lost vehicle costs the records of one key.
- **Seal operational records with a hardware key.** A key file (`sfr keygen --evaluation-only`) is for evaluation: its records hold custody `file-evaluation` and say EVALUATION KEY, `sfr verify` refuses them (`Integrity: REFUSED`) unless given `--allow-evaluation-key`, and the file is protected only by its mode (0600); `seal` warns when group or other users can access it. Custody is what the sealer declares, and `sfr verify` prints it as unattested unless the signer's certificate chains to your trust anchor ([THREAT_MODEL.md](THREAT_MODEL.md#keys)).
- **`sfr` manages no keys beyond `keygen`.** It does not rotate, revoke, back up or distribute them. Keep a list of which fingerprint belongs to which vehicle and when; when a key is lost or stolen, stop trusting records with its fingerprint from that time.
- **Give verifiers the public key, or a trust anchor, out of band.** A record re-signed by someone else verifies against their key. With a CA, seal with the vehicle's certificate (`seal --cert vehicle.pem --chain intermediates.pem`) and give verifiers the root and a CRL for every issuer in the chain, root included (`verify --trust-anchor root.pem --crl root.crl --crl ca.crl`). A CRL past its `nextUpdate` fails verification. A key whose certificate you revoke stops verifying, for records sealed before the revocation too.
- **Issue vehicle certificates for sealing records only.** `verify --trust-anchor` accepts a signer certificate only if its extended key usage lists the record-signing usage `2.25.182460915354635260549596502533646383540` (a UUID-derived identifier, so it needs no registration) and its keyUsage sets digitalSignature. It must not also list code signing, TLS server authentication or any usage. In OpenSSL: `keyUsage = critical, digitalSignature` and `extendedKeyUsage = 2.25.182460915354635260549596502533646383540`. An intermediate CA that limits its extended key usage must list it too.
- **Use `--seal-time` only for reproducible examples.** Otherwise the seal time is the sealing machine's clock, which `verify` prints as claimed; certificates are judged at the verifier's clock (or `--at`), and a seal time in the verifier's future is refused.

### A key in a PKCS#11 token or HSM (`pkcs11-token`)

The token makes the key and signs; the private key never leaves it. `sfr` reaches the token through `sfr-pkcs11-helper`, a separate program that loads the token's PKCS#11 module (the static `sfr` cannot). The token must sign with Ed25519 (`CKM_EDDSA`). Put the helper beside `sfr`, or name it with `SFR_PKCS11_HELPER`, and make the key with the token's own tools, here OpenSC's `pkcs11-tool`. Not run in CI by the docs test; the CI job `hardware-keys` runs the same steps against SoftHSM v2 (`scripts/hardware_keys.sh`):

```sh doc-syntax
cargo build --release --locked -p sfr-pkcs11-helper
cp target/release/sfr-pkcs11-helper "$(dirname "$(command -v sfr)")/"
pkcs11-tool --module "$MODULE" --token-label flight-keys --login \
  --keypairgen --key-type EC:edwards25519 --label sfr-seal --id 01
```

The key URI (RFC 7512) names the module, the PIN source, the token and the key. The PIN comes from a file (`pin-source=file:<path>`, its first line) or a variable (`pin-source=env:<name>`); a PIN in the URI (`pin-value`) is refused. `sfr pubkey` prints the public half for verifiers. Not run in CI: it needs a token:

```sh doc-syntax
KEY="pkcs11:token=flight-keys;object=sfr-seal?module-path=$MODULE&pin-source=file:/etc/sfr/pin"
sfr pubkey --key-uri "$KEY" > sfr.pub
sfr seal "$LOG" --rules rules.toml --baseline vehicle.params --key-uri "$KEY" --out records
```

### A seed sealed to a TPM (`tpm-sealed`)

`sfr keygen --tpm-sealed` takes a 32-byte seed from the operating system's random number generator and seals it to this machine's TPM through tpm2-tools; the seed goes through a pipe and never reaches disk. It writes `sfr.tpm.pub` and `sfr.tpm.priv` (blobs no other TPM can load), `sfr.tpm.conf` (parent handle and PCR selection) and `sfr.pub`. It needs tpm2-tools and a persistent storage key in the TPM, by default at handle `0x81000001` (`--tpm-parent` names another), reached through `/dev/tpmrm0` unless `TPM2TOOLS_TCTI` says otherwise. With `--tpm-pcrs sha256:0,7` the TPM unseals only while those PCRs hold their values from `keygen`, so a firmware or boot change makes the key unusable. `seal` unseals the seed for one signature and checks it against `sfr.pub`. Not run in CI by the docs test; the CI job `hardware-keys` runs it against swtpm:

```sh doc-syntax
sfr keygen --tpm-sealed --tpm-pcrs sha256:0,7 --out /etc/sfr/key
sfr seal "$LOG" --rules rules.toml --baseline vehicle.params --key-uri tpm-sealed:/etc/sfr/key --out records
```
