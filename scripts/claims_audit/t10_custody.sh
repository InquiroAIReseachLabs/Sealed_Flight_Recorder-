#!/usr/bin/env bash
# T10 Key custody: pkcs11-token on SoftHSM v2 and tpm-sealed on swtpm, sealed and verified; the declared custody
# printed; a certificate chain to a supplied trust anchor; a revoked certificate in a supplied CRL.
# Needs softhsm2-util, pkcs11-tool (OpenSC), swtpm, tpm2-tools, tpm2-abrmd, dbus-run-session, openssl 3.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
R=$A_REPO; SFR=$A_SFR; W=$A_WORK/t10
if [ -z "${T10_IN_BUS:-}" ]; then rm -rf $W; mkdir -p $W; T10_IN_BUS=1 exec dbus-run-session -- "$0" "$@"; fi
cd $R; echo "commit $(git rev-parse HEAD)"
# the helper the pkcs11 key source needs, built from this commit (outside the clone)
mkdir -p $W/bin; cp $SFR $W/bin/sfr
CARGO_TARGET_DIR=$W/target cargo build --release --locked -p sfr-pkcs11-helper -q 2>&1 | tail -2
cp $W/target/release/sfr-pkcs11-helper $W/bin/; SFR=$W/bin/sfr
pids=(); trap 'for p in "${pids[@]}"; do kill $p 2>/dev/null; done' EXIT
# --- SoftHSM token with an Ed25519 key made inside it
module=/usr/lib/softhsm/libsofthsm2.so; [ -f $module ] || module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
mkdir -p $W/tokens; printf 'directories.tokendir = %s\nobjectstore.backend = file\n' $W/tokens > $W/softhsm2.conf; export SOFTHSM2_CONF=$W/softhsm2.conf
pin=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n'); printf '%s\n' $pin > $W/pin; chmod 600 $W/pin
softhsm2-util --init-token --free --label t10 --so-pin "$pin-so" --pin $pin > /dev/null
pkcs11-tool --module $module --token-label t10 --login --pin $pin --keypairgen --key-type EC:edwards25519 --label sfr-seal --id 01 > /dev/null
KEY="pkcs11:token=t10;object=sfr-seal?module-path=$module&pin-source=file:$W/pin"
echo "== SoftHSM v2 token 't10' with an Ed25519 key generated inside it (pkcs11-tool --keypairgen --key-type EC:edwards25519)"
# --- swtpm
mkdir -p $W/tpm; port=$((20000 + RANDOM % 20000))
swtpm socket --tpmstate dir=$W/tpm --tpm2 --server type=tcp,port=$port --ctrl type=tcp,port=$((port+1)) --flags not-need-init,startup-clear & pids+=($!)
tpm2-abrmd --session --tcti="swtpm:host=127.0.0.1,port=$port" --allow-root > $W/abrmd.log 2>&1 & pids+=($!)
export TPM2TOOLS_TCTI="tabrmd:bus_type=session"
for _ in $(seq 100); do tpm2_getcap properties-fixed > /dev/null 2>&1 && break; sleep 0.1; done
tpm2_createprimary -C o -G ecc -c $W/srk.ctx -Q && tpm2_evictcontrol -C o -c $W/srk.ctx 0x81000001 -Q
echo "== swtpm (software TPM 2.0) behind tpm2-abrmd, storage key at 0x81000001"
LOG=testdata/synthetic/custom_detection.ulg; RULES=testdata/rules/synthetic_custom_detection.toml; BASE=testdata/baselines/synthetic_custom_detection.params
SEAL="--rules $RULES --baseline $BASE --seal-time 2026-10-18T15:00:00Z"

echo; echo "################ 1. pkcs11-token"
set -x
$SFR pubkey --key-uri "$KEY" > $W/pkcs11.pub
$SFR seal $LOG $SEAL --key-uri "$KEY" --out $W/pk | grep -E '^(status|record|report)'
$SFR verify $W/pk/custom_detection.sfr --pubkey $W/pkcs11.pub | grep -E '^(Integrity|Flight|custody|key |seal time|EVALUATION)'
echo "exit ${PIPESTATUS[0]}"
set +x
echo "-- --require-hardware-key with only a public key (nothing attests the custody): must be refused"
$SFR verify $W/pk/custom_detection.sfr --pubkey $W/pkcs11.pub --require-hardware-key | grep -E '^(Integrity|custody)' | cut -c1-200; rc=${PIPESTATUS[0]}; echo "exit $rc"
check "pkcs11-token record verifies with its public key; custody printed as unattested (declared pkcs11-token)" "$($SFR verify $W/pk/custom_detection.sfr --pubkey $W/pkcs11.pub 2>&1 | grep -q '^custody   unattested (declared pkcs11-token)' ; echo $?)"
check "--require-hardware-key without a chain is refused (exit 1)" "$([ $rc -eq 1 ]; echo $?)"
echo "-- the private key cannot be exported from the token:"
pkcs11-tool --module $module --token-label t10 --login --pin $pin --list-objects --type privkey 2>&1 | grep -E 'Private Key|Usage|Access' | head -4

echo; echo "################ 2. tpm-sealed"
set -x
$SFR keygen --tpm-sealed --out $W/tpmkey | head -3
$SFR seal $LOG $SEAL --key-uri tpm-sealed:$W/tpmkey --out $W/tp | grep -E '^(status|record|report)'
$SFR verify $W/tp/custom_detection.sfr --pubkey $W/tpmkey/sfr.pub | grep -E '^(Integrity|Flight|custody|key |seal time|EVALUATION)'
echo "exit ${PIPESTATUS[0]}"
set +x
ls -l $W/tpmkey | awk '{print "   " $1, $NF}'
check "tpm-sealed record verifies with its public key; custody printed as unattested (declared tpm-sealed)" "$($SFR verify $W/tp/custom_detection.sfr --pubkey $W/tpmkey/sfr.pub 2>&1 | grep -q '^custody   unattested (declared tpm-sealed)'; echo $?)"

echo; echo "################ 3. a certificate chain to a supplied trust anchor, and a revoked certificate in a supplied CRL"
pki=$W/pki; mkdir -p $pki/new
EKU=2.25.182460915354635260549596502533646383540
cat > $pki/ca.cnf <<CNF
[ ca ]
default_ca = test
[ test ]
dir = $pki
database = \$dir/index.txt
serial = \$dir/serial
crlnumber = \$dir/crlnumber
new_certs_dir = \$dir/new
default_md = default
policy = any
unique_subject = no
copy_extensions = none
[ any ]
commonName = supplied
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = t10
[ v3_root ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ v3_inter ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_signer ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = $EKU
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ crl ]
authorityKeyIdentifier = keyid
CNF
: > $pki/index.txt; echo 1000 > $pki/serial; echo 01 > $pki/crlnumber
for n in root inter; do openssl genpkey -algorithm ed25519 -out $pki/$n.key 2>/dev/null; done
q() { "$@" > /dev/null 2>&1; }
openssl req -new -config $pki/ca.cnf -key $pki/root.key -subj /CN=t10-root -out $pki/root.csr 2>/dev/null
q openssl ca -batch -notext -config $pki/ca.cnf -selfsign -keyfile $pki/root.key -extensions v3_root -startdate 20250101000000Z -enddate 20460101000000Z -in $pki/root.csr -out $pki/root.pem
openssl req -new -config $pki/ca.cnf -key $pki/inter.key -subj /CN=t10-inter -out $pki/inter.csr 2>/dev/null
q openssl ca -batch -notext -config $pki/ca.cnf -cert $pki/root.pem -keyfile $pki/root.key -extensions v3_inter -startdate 20250101000000Z -enddate 20460101000000Z -in $pki/inter.csr -out $pki/inter.pem
# a certificate for the token's PUBLIC key (the private key stays in the token): openssl x509 -force_pubkey
cert_for() { # name pubkey.pem
  q openssl x509 -new -force_pubkey "$2" -subj "/CN=t10 $1" -CA $pki/inter.pem -CAkey $pki/inter.key -extfile <(printf '[x]\nbasicConstraints = critical, CA:false\nkeyUsage = critical, digitalSignature\nextendedKeyUsage = %s\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n' $EKU) -extensions x -days 3000 -out $pki/$1.pem
  # register the serial in the CA database so it can be revoked
  openssl x509 -in $pki/$1.pem -noout -serial | cut -d= -f2
}
openssl x509 -in $pki/inter.pem -noout -enddate | sed 's/^/inter /'
echo "-- certificates (issued by the test CA to the PUBLIC keys of the token key and of the TPM key):"
s1=$(cert_for tokencert $W/pkcs11.pub); s2=$(cert_for tpmcert $W/tpmkey/sfr.pub); echo "serials: $s1 $s2"
gencrl() { echo "$2" > $pki/crlnumber; cp "$3" $pki/index.txt; q openssl ca -batch -config $pki/ca.cnf -gencrl -cert $pki/$1.pem -keyfile $pki/$1.key -crlexts crl -crl_lastupdate 20260601000000Z -crl_nextupdate 20460101000000Z -out $pki/$4.pem; openssl crl -in $pki/$4.pem -outform DER -out $pki/$4.crl 2>/dev/null; }
: > $pki/index.empty
gencrl root 01 $pki/index.empty root_crl; gencrl inter 01 $pki/index.empty inter_clean
# revoke the token certificate: put it in the index as revoked (serial, as the CA database records it)
printf 'R\t460101000000Z\t260601000000Z,keyCompromise\t%s\tunknown\t/CN=t10 tokencert\n' $s1 > $pki/index.revoked
gencrl inter 02 $pki/index.revoked inter_revoked
echo; echo "-- 3a. token key sealed WITH its certificate and the intermediate; verified against the supplied root and CRLs (nothing revoked)"
set -x
$SFR seal $LOG $SEAL --key-uri "$KEY" --cert $pki/tokencert.pem --chain $pki/inter.pem --out $W/pkc | grep -E '^(status|record)'
$SFR verify $W/pkc/custom_detection.sfr --trust-anchor $pki/root.pem --crl $pki/root_crl.crl --crl $pki/inter_clean.crl --require-hardware-key | grep -E '^(Integrity|Flight|trust|custody|crl|time|seal time)' | cut -c1-230
rc=${PIPESTATUS[0]}; echo "exit $rc"
set +x
check "token key with its certificate: chain to the supplied root verifies, custody attested, --require-hardware-key accepted" "$([ $rc -eq 0 ]; echo $?)"
echo; echo "-- 3b. the same record, with a CRL that lists the token's certificate (a revoked certificate in a supplied CRL): must fail"
$SFR verify $W/pkc/custom_detection.sfr --trust-anchor $pki/root.pem --crl $pki/root_crl.crl --crl $pki/inter_revoked.crl | grep -E '^(Integrity|Flight)' | cut -c1-230; rc=${PIPESTATUS[0]}; echo "exit $rc"
check "a revoked certificate in a supplied CRL fails (exit 1)" "$([ $rc -eq 1 ]; echo $?)"
echo; echo "-- 3c. a chain to a trust anchor that was NOT supplied (an unrelated root): must fail"
openssl genpkey -algorithm ed25519 -out $pki/other.key 2>/dev/null; openssl req -new -x509 -config $pki/ca.cnf -key $pki/other.key -subj /CN=other-root -days 3000 -out $pki/other.pem 2>/dev/null
$SFR verify $W/pkc/custom_detection.sfr --trust-anchor $pki/other.pem --crl $pki/root_crl.crl --crl $pki/inter_clean.crl | grep -E '^(Integrity|Flight)' | cut -c1-230; rc=${PIPESTATUS[0]}; echo "exit $rc"
check "a chain to an anchor that was not supplied fails (exit 1)" "$([ $rc -eq 1 ]; echo $?)"
echo; echo "-- 3d. the TPM-sealed key with its certificate, same checks"
$SFR seal $LOG $SEAL --key-uri tpm-sealed:$W/tpmkey --cert $pki/tpmcert.pem --chain $pki/inter.pem --out $W/tpc | grep -E '^(status|record)'
$SFR verify $W/tpc/custom_detection.sfr --trust-anchor $pki/root.pem --crl $pki/root_crl.crl --crl $pki/inter_clean.crl --require-hardware-key | grep -E '^(Integrity|custody)' | cut -c1-230; rc=${PIPESTATUS[0]}; echo "exit $rc"
check "TPM-sealed key with its certificate: chain verifies, --require-hardware-key accepted" "$([ $rc -eq 0 ]; echo $?)"
echo; echo "-- 3e. what the record says about WHEN it was sealed:"
grep -o '"time_utc":"[^"]*"' $W/pkc/custom_detection.sfr
$SFR verify $W/pkc/custom_detection.sfr --trust-anchor $pki/root.pem --crl $pki/root_crl.crl --crl $pki/inter_clean.crl | grep -E '^(time|seal time)'

check "seal time is printed as claimed by the sealer, not proven" "$($SFR verify $W/pkc/custom_detection.sfr --trust-anchor $pki/root.pem --crl $pki/root_crl.crl --crl $pki/inter_clean.crl 2>&1 | grep -q '^seal time .* (claimed by the sealer, not proven)'; echo $?)"
finish
