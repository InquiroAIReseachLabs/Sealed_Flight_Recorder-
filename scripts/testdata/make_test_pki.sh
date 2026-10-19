#!/usr/bin/env bash
# make_test_pki.sh: the test certificates and CRL for `seal --cert --chain` and
# `verify --trust-anchor --crl` (crates/sfr/tests/certificates.rs), made with OpenSSL 3.
#
#   scripts/testdata/make_test_pki.sh <dir>     write the PKI into <dir> (created; must be empty)
#   scripts/testdata/make_test_pki.sh --check   make it in a temporary directory and compare it,
#                                               byte for byte, with testdata/pki/
#
# Every key comes from a fixed test seed (below, and the same constants in
# crates/sfr/tests/certificates.rs), every date is fixed, and Ed25519 signatures are
# deterministic, so the output is the same on every run. These are test keys: their seeds are
# public, so nothing they sign means anything outside the tests. No private key file is kept.
#
#   root.pem          test root CA (trust anchor)
#   other_root.pem    an unrelated root CA
#   inter.pem         intermediate CA, issued by root
#   signer.pem        signer, issued by inter, code signing, valid 2026-01-01 to 2036-01-01
#   signer_expired.pem   another signer, valid 2020-01-01 to 2021-01-01
#   signer_server.pem    another signer whose only extended key usage is server authentication
#   signer_revoked.pem   another signer, revoked in inter.crl
#   inter.crl         CRL issued by inter, listing signer_revoked.pem
set -euo pipefail
export LC_ALL=C TZ=UTC

# name|seed byte (the 32-byte seed repeats it)
SEEDS="root|10 other_root|40 inter|20 signer|30 signer_expired|31 signer_server|32 signer_revoked|33"

die() { echo "make_test_pki.sh: $*" >&2; exit 1; }
command -v openssl > /dev/null || die "openssl 3 is required"

# The PKCS#8 v1 DER of the Ed25519 key with seed byte $1 repeated, on stdout.
pkcs8() {
  printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'
  local i; for i in $(seq 32); do printf "\\x$1"; done
}

make() {
  local out="$1" work
  mkdir -p "$out"
  [ -z "$(ls -A "$out")" ] || die "$out is not empty"
  work="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$work'" RETURN
  local entry name seed
  for entry in $SEEDS; do
    name="${entry%|*}" seed="${entry#*|}"
    pkcs8 "$seed" | openssl pkey -inform DER -out "$work/$name.key"
  done
  cat > "$work/ca.cnf" <<EOF
[ ca ]
default_ca = test
[ test ]
dir = $work
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
CN = sfr test
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
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_server ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ crl ]
authorityKeyIdentifier = keyid
EOF
  : > "$work/index.txt"
  mkdir -p "$work/new"
  echo 1000 > "$work/serial"
  echo 01 > "$work/crlnumber"
  # issue <name> <issuer or self> <extensions> <notBefore> <notAfter>
  issue() {
    local name="$1" issuer="$2" ext="$3" from="$4" to="$5"
    openssl req -new -config "$work/ca.cnf" -key "$work/$name.key" -subj "/CN=sfr test $name" \
      -out "$work/$name.csr"
    if [ "$issuer" = self ]; then
      openssl ca -batch -notext -config "$work/ca.cnf" -selfsign -keyfile "$work/$name.key" \
        -extensions "$ext" -startdate "$from" -enddate "$to" -in "$work/$name.csr" \
        -out "$out/$name.pem" 2> /dev/null
    else
      openssl ca -batch -notext -config "$work/ca.cnf" -cert "$out/$issuer.pem" \
        -keyfile "$work/$issuer.key" -extensions "$ext" -startdate "$from" -enddate "$to" \
        -in "$work/$name.csr" -out "$out/$name.pem" 2> /dev/null
    fi
  }
  issue root self v3_root 20250101000000Z 20460101000000Z
  issue other_root self v3_root 20250101000000Z 20460101000000Z
  issue inter root v3_inter 20250101000000Z 20460101000000Z
  issue signer inter v3_signer 20260101000000Z 20360101000000Z
  issue signer_expired inter v3_signer 20200101000000Z 20210101000000Z
  issue signer_server inter v3_server 20260101000000Z 20360101000000Z
  issue signer_revoked inter v3_signer 20260101000000Z 20360101000000Z
  # Revoke signer_revoked as of 2026-06-01, then a CRL by inter with fixed dates. Only
  # inter's entries go into inter's CRL.
  openssl ca -batch -config "$work/ca.cnf" -cert "$out/inter.pem" -keyfile "$work/inter.key" \
    -revoke "$out/signer_revoked.pem" -crl_reason keyCompromise 2> /dev/null
  sed -i -E 's/^R\t([0-9]+Z)\t[0-9]+Z,/R\t\1\t260601000000Z,/' "$work/index.txt"
  grep -v -E "CN=sfr test (root|other_root|inter)$" "$work/index.txt" > "$work/index.inter"
  mv "$work/index.inter" "$work/index.txt"
  openssl ca -batch -config "$work/ca.cnf" -gencrl -cert "$out/inter.pem" \
    -keyfile "$work/inter.key" -crlexts crl -crl_lastupdate 20260601000000Z \
    -crl_nextupdate 20460101000000Z -out "$out/inter.crl" 2> /dev/null
}

case "${1:-}" in
  --check)
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    make "$tmp/pki"
    if diff -r "$tmp/pki" "$root/testdata/pki" > /dev/null; then
      echo "PASS: testdata/pki matches scripts/testdata/make_test_pki.sh"
    else
      diff -r "$tmp/pki" "$root/testdata/pki" || true
      die "testdata/pki differs from what this script makes"
    fi
    ;;
  "" | -*) die "usage: make_test_pki.sh <dir> | --check" ;;
  *) make "$1" ;;
esac
