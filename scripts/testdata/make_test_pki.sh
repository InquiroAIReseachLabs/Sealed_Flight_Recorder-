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
#   signer.pem        signer, issued by inter, for sealing records (the sfr record-signing extended
#                     key usage 2.25.182460915354635260549596502533646383540, keyUsage digitalSignature),
#                     valid 2026-01-01 to 2036-01-01
#   signer_expired.pem   another signer, valid 2020-01-01 to 2021-01-01
#   signer_lapsed.pem    another signer, valid 2025-02-01 to 2025-12-31: expired now, but inside
#                        the validity of inter and root, so a seal time backdated into 2025 would
#                        revive it if a verifier trusted the seal time
#   signer_server.pem    another signer whose only extended key usage is server authentication
#   signer_codesign.pem  another signer whose only extended key usage is code signing (what a record
#                        signer certificate was before the record-signing usage)
#   signer_both.pem      another signer with the record-signing usage and also code signing and
#                        server authentication
#   signer_nosig.pem     another signer with the record-signing usage and keyUsage nonRepudiation
#                        only, no digitalSignature
#   signer_nokeyusage.pem  another signer with the record-signing usage and no keyUsage extension
#   signer_revoked.pem   another signer, revoked in inter.crl
#   inter.crl         CRL issued by inter, number 1, listing signer_revoked.pem
#   root.crl          CRL issued by root, number 1, listing nothing (inter is not revoked)
#   inter_older.crl   CRL issued by inter, number 0, listing nothing: older than inter.crl
#   inter_stale.crl   CRL issued by inter, number 0, listing nothing, valid 2025-06-01 to
#                     2025-07-01: older than inter.crl and past its nextUpdate
#   root_2025.crl     CRL issued by root, number 0, listing nothing, valid 2025-06-01 to
#                     2025-07-01: with inter_stale.crl, the CRLs current in mid-June 2025
#   inter_same.crl    CRL issued by inter with the same number as inter.crl (1) and other content
#   other_root.crl    CRL issued by the unrelated other_root, number 99, listing nothing
#   inter_delta.crl   CRL issued by inter, number 2, a delta CRL (deltaCRLIndicator): refused
#   inter_indirect.crl  CRL issued by inter, number 2, indirect (issuingDistributionPoint
#                     indirectCRL): refused
#   inter_critical.crl  CRL issued by inter, number 2, with a critical extension sfr does not
#                     read (1.3.6.1.4.1.32473.1, an example OID, RFC 5612): refused
#   inter_dp.crl      CRL issued by inter, number 2, listing nothing, scoped to one distribution
#                     point (issuingDistributionPoint distributionPoint): refused
#   inter_usercerts.crl  CRL issued by inter, number 2, listing nothing, scoped to end-entity
#                     certificates (issuingDistributionPoint onlyContainsUserCerts): refused
#   inter_cacerts.crl CRL issued by inter, number 2, listing nothing, scoped to CA certificates
#                     (issuingDistributionPoint onlyContainsCACerts): refused
set -euo pipefail
export LC_ALL=C TZ=UTC

# name|seed byte (the 32-byte seed repeats it)
SEEDS="root|10 other_root|40 inter|20 signer|30 signer_expired|31 signer_server|32 signer_revoked|33 signer_lapsed|34 signer_codesign|35 signer_both|36 signer_nosig|37 signer_nokeyusage|38"

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
extendedKeyUsage = 2.25.182460915354635260549596502533646383540
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_codesign ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_both ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = 2.25.182460915354635260549596502533646383540, codeSigning, serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_nosig ]
basicConstraints = critical, CA:false
keyUsage = critical, nonRepudiation
extendedKeyUsage = 2.25.182460915354635260549596502533646383540
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_nokeyusage ]
basicConstraints = critical, CA:false
extendedKeyUsage = 2.25.182460915354635260549596502533646383540
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
[ crl_delta ]
authorityKeyIdentifier = keyid
2.5.29.27 = critical, ASN1:INTEGER:1
[ crl_indirect ]
authorityKeyIdentifier = keyid
issuingDistributionPoint = critical, @idp_indirect
[ idp_indirect ]
fullname = URI:http://example.com/inter.crl
indirectCRL = TRUE
[ crl_critical ]
authorityKeyIdentifier = keyid
1.3.6.1.4.1.32473.1 = critical, ASN1:NULL
[ crl_dp ]
authorityKeyIdentifier = keyid
issuingDistributionPoint = critical, @idp_dp
[ idp_dp ]
fullname = URI:http://example.com/inter-part1.crl
[ crl_usercerts ]
authorityKeyIdentifier = keyid
issuingDistributionPoint = critical, @idp_usercerts
[ idp_usercerts ]
onlyuser = TRUE
[ crl_cacerts ]
authorityKeyIdentifier = keyid
issuingDistributionPoint = critical, @idp_cacerts
[ idp_cacerts ]
onlyCA = TRUE
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
  issue signer_lapsed inter v3_signer 20250201000000Z 20251231000000Z
  issue signer_codesign inter v3_codesign 20260101000000Z 20360101000000Z
  issue signer_both inter v3_both 20260101000000Z 20360101000000Z
  issue signer_nosig inter v3_nosig 20260101000000Z 20360101000000Z
  issue signer_nokeyusage inter v3_nokeyusage 20260101000000Z 20360101000000Z
  # Revoke signer_revoked as of 2026-06-01, then a CRL by inter with fixed dates. Only
  # inter's entries go into inter's CRL.
  openssl ca -batch -config "$work/ca.cnf" -cert "$out/inter.pem" -keyfile "$work/inter.key" \
    -revoke "$out/signer_revoked.pem" -crl_reason keyCompromise 2> /dev/null
  sed -i -E 's/^R\t([0-9]+Z)\t[0-9]+Z,/R\t\1\t260601000000Z,/' "$work/index.txt"
  grep -v -E "CN=sfr test (root|other_root|inter)$" "$work/index.txt" > "$work/index.inter"
  mv "$work/index.inter" "$work/index.txt"
  cp "$work/index.txt" "$work/index.with_revoked"
  : > "$work/index.empty"
  # gencrl <issuer> <crl number, hex> <index file> <lastUpdate> <nextUpdate> <file> [<extensions>]
  gencrl() {
    echo "$2" > "$work/crlnumber"
    cp "$3" "$work/index.txt"
    openssl ca -batch -config "$work/ca.cnf" -gencrl -cert "$out/$1.pem" -keyfile "$work/$1.key" \
      -crlexts "${7:-crl}" -crl_lastupdate "$4" -crl_nextupdate "$5" -out "$out/$6" 2> /dev/null
  }
  gencrl inter 01 "$work/index.with_revoked" 20260601000000Z 20460101000000Z inter.crl
  gencrl root 01 "$work/index.empty" 20260601000000Z 20460101000000Z root.crl
  gencrl inter 00 "$work/index.empty" 20260101000000Z 20460101000000Z inter_older.crl
  gencrl inter 00 "$work/index.empty" 20250601000000Z 20250701000000Z inter_stale.crl
  gencrl inter 01 "$work/index.empty" 20260601000000Z 20460101000000Z inter_same.crl
  gencrl root 00 "$work/index.empty" 20250601000000Z 20250701000000Z root_2025.crl
  gencrl other_root 63 "$work/index.empty" 20260601000000Z 20460101000000Z other_root.crl
  gencrl inter 02 "$work/index.empty" 20260601000000Z 20460101000000Z inter_delta.crl crl_delta
  gencrl inter 02 "$work/index.empty" 20260601000000Z 20460101000000Z inter_indirect.crl crl_indirect
  gencrl inter 02 "$work/index.empty" 20260601000000Z 20460101000000Z inter_critical.crl crl_critical
  gencrl inter 02 "$work/index.empty" 20260601000000Z 20460101000000Z inter_dp.crl crl_dp
  gencrl inter 02 "$work/index.empty" 20260601000000Z 20460101000000Z inter_usercerts.crl crl_usercerts
  gencrl inter 02 "$work/index.empty" 20260601000000Z 20460101000000Z inter_cacerts.crl crl_cacerts
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
