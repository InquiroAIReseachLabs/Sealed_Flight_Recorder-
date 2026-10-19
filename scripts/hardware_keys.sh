#!/usr/bin/env bash
# hardware_keys.sh: the hardware key custody tests (SPEC B1.10 Key custody) against a software
# token and a software TPM, as the CI job hardware-keys runs them.
#
#   1. pkcs11-token: a fresh SoftHSM v2 token with an Ed25519 key made inside it (pkcs11-tool
#      --keypairgen EC:edwards25519; the token signs with CKM_EDDSA).
#   2. tpm-sealed: swtpm, reached through tpm2-abrmd (the resource manager that /dev/tpmrm0 is on
#      a real machine), with a persistent storage key at 0x81000001.
#   3. sfr-pkcs11-helper is built, then crates/sfr/tests/hardware.rs runs with --ignored.
#
# Needs: softhsm2, opensc (pkcs11-tool), swtpm, tpm2-tools, tpm2-abrmd, libtss2-tcti-tabrmd0 and
# dbus (Debian and Ubuntu package names). Everything lives in a temporary directory, which is
# removed at the end with the processes started here. No network: swtpm listens on localhost.
#
# Usage: scripts/hardware_keys.sh
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { echo "hardware_keys.sh: $*" >&2; exit 1; }
for tool in softhsm2-util pkcs11-tool swtpm tpm2_createprimary tpm2_evictcontrol tpm2-abrmd dbus-run-session; do
  command -v "$tool" > /dev/null || die "$tool is required (see the header of this script)"
done

# tpm2-abrmd talks over D-Bus: run the rest inside a private session bus.
if [ -z "${SFR_HW_IN_BUS:-}" ]; then
  SFR_HW_IN_BUS=1 exec dbus-run-session -- "$0" "$@"
fi

work="$(mktemp -d)"
pids=()
cleanup() {
  for p in "${pids[@]+"${pids[@]}"}"; do kill "$p" 2> /dev/null || true; done
  rm -rf "$work"
}
trap cleanup EXIT

# --- SoftHSM v2 token and an Ed25519 key inside it.
module=""
for m in /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so /usr/local/lib/softhsm/libsofthsm2.so; do
  [ -f "$m" ] && { module="$m"; break; }
done
[ -n "$module" ] || die "libsofthsm2.so not found"
mkdir -p "$work/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$work/tokens" > "$work/softhsm2.conf"
export SOFTHSM2_CONF="$work/softhsm2.conf"
pin="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
printf '%s\n' "$pin" > "$work/pin"
chmod 600 "$work/pin"
softhsm2-util --init-token --free --label sfr-ci --so-pin "$pin-so" --pin "$pin" > /dev/null
pkcs11-tool --module "$module" --token-label sfr-ci --login --pin "$pin" \
  --keypairgen --key-type EC:edwards25519 --label sfr-seal --id 01 > /dev/null
export SFR_TEST_PKCS11_URI="pkcs11:token=sfr-ci;object=sfr-seal?module-path=$module&pin-source=file:$work/pin"
echo "PASS: SoftHSM v2 token sfr-ci with an Ed25519 key"

# --- swtpm behind tpm2-abrmd, with a persistent storage key.
mkdir -p "$work/tpm"
port=$((20000 + RANDOM % 20000))
swtpm socket --tpmstate dir="$work/tpm" --tpm2 --server type=tcp,port=$port \
  --ctrl type=tcp,port=$((port + 1)) --flags not-need-init,startup-clear &
pids+=("$!")
abrmd_user=()
[ "$(id -u)" = 0 ] && abrmd_user=(--allow-root)
tpm2-abrmd --session --tcti="swtpm:host=127.0.0.1,port=$port" "${abrmd_user[@]}" > "$work/abrmd.log" 2>&1 &
pids+=("$!")
export TPM2TOOLS_TCTI="tabrmd:bus_type=session"
ready=0
for _ in $(seq 1 100); do
  tpm2_getcap properties-fixed > /dev/null 2>&1 && { ready=1; break; }
  sleep 0.1
done
[ "$ready" = 1 ] || { cat "$work/abrmd.log" >&2; die "the TPM did not come up"; }
tpm2_createprimary -C o -G ecc -c "$work/srk.ctx" -Q
tpm2_evictcontrol -C o -c "$work/srk.ctx" 0x81000001 -Q
export SFR_TEST_TPM=1
echo "PASS: swtpm with a persistent storage key at 0x81000001"

# --- The tests.
cd "$root"
cargo build --locked -p sfr-pkcs11-helper --quiet
cargo test --locked -p sfr --test hardware -- --include-ignored
echo "PASS: hardware key custody (pkcs11-token on SoftHSM v2, tpm-sealed on swtpm)"
