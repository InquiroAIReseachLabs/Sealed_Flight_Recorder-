#!/usr/bin/env bash
# t12_attacks.sh: the T12 block of the claims audit: the six attacks of Issue #24 that the
# A-series fixed (A1 seal time, A2 custody, A3 CRL handling, A4 report, A5 signed structure,
# A7 signer certificate usage), each run against an earlier build (where it must SUCCEED) and the
# current build (where it must FAIL), with the result as a table.
#
#   scripts/t12_attacks.sh <earlier sfr> <current sfr>
#
# An attack "succeeds" when the verifier accepts what it must not (or, for A5 and the bidi
# character, when the check that stops it does not fire). Every attack is first preceded by a
# control: the same steps with nothing wrong, which must verify, so that an attack cannot "fail"
# only because the setup was refused for another reason.
#
# The earlier build is whatever you pass: the baseline of the task is main at 4031c96
# (`git worktree add ../sfr-4031c96 4031c96 && cargo build --release --locked -p sfr` there).
# The record forger is independent of sfr (scripts/t12_forge.py, OpenSSL for signatures) and the
# test PKI is made here with OpenSSL, so each build is given certificates it understands: the
# earlier build the code-signing form, the current build the record-signing form (A7).
# Needs: openssl 3, python3, the files under testdata/. Writes only to a temporary directory.
set -uo pipefail
[ $# -eq 2 ] || { echo "usage: $0 <earlier sfr> <current sfr>" >&2; exit 2; }
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
old="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
new="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
forge="$root/scripts/t12_forge.py"
W="${T12_KEEP:-$(mktemp -d)}"; mkdir -p "$W"; [ -n "${T12_KEEP:-}" ] || trap 'rm -rf "$W"' EXIT
LOG="$root/testdata/synthetic/custom_detection.ulg"
RULES="$root/testdata/rules/synthetic_custom_detection.toml"
BASE="$root/testdata/baselines/synthetic_custom_detection.params"
SEAL_TIME=2026-10-18T15:00:00Z
EKU_SFR=2.25.182460915354635260549596502533646383540

# ---- a test PKI, in both certificate forms -------------------------------------------------
pki="$W/pki"; mkdir -p "$pki/new"
cat > "$pki/ca.cnf" <<CNF
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
CN = t12
[ v3_root ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[ v3_inter ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_old ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ v3_new ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = $EKU_SFR
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[ crl ]
authorityKeyIdentifier = keyid
CNF
: > "$pki/index.txt"; echo 1000 > "$pki/serial"; echo 01 > "$pki/crlnumber"
quiet() { "$@" > /dev/null 2>&1; }
for n in root inter good_old good_new lapsed_old lapsed_new revoked_old revoked_new; do
  openssl genpkey -algorithm ed25519 -out "$pki/$n.key" 2> /dev/null
done
issue() { # name issuer|self ext from to
  openssl req -new -config "$pki/ca.cnf" -key "$pki/$1.key" -subj "/CN=t12 $1" -out "$pki/$1.csr" 2> /dev/null
  if [ "$2" = self ]; then
    quiet openssl ca -batch -notext -config "$pki/ca.cnf" -selfsign -keyfile "$pki/$1.key" -extensions "$3" \
      -startdate "$4" -enddate "$5" -in "$pki/$1.csr" -out "$pki/$1.pem"
  else
    quiet openssl ca -batch -notext -config "$pki/ca.cnf" -cert "$pki/$2.pem" -keyfile "$pki/$2.key" \
      -extensions "$3" -startdate "$4" -enddate "$5" -in "$pki/$1.csr" -out "$pki/$1.pem"
  fi
}
issue root self v3_root 20250101000000Z 20460101000000Z
issue inter root v3_inter 20250101000000Z 20460101000000Z
for f in old new; do
  issue "good_$f" inter "v3_$f" 20260101000000Z 20360101000000Z
  issue "lapsed_$f" inter "v3_$f" 20250201000000Z 20251231000000Z
  issue "revoked_$f" inter "v3_$f" 20260101000000Z 20360101000000Z
done
gencrl() { # issuer number index lastUpdate nextUpdate out
  echo "$2" > "$pki/crlnumber"; cp "$3" "$pki/index.txt"
  quiet openssl ca -batch -config "$pki/ca.cnf" -gencrl -cert "$pki/$1.pem" -keyfile "$pki/$1.key" \
    -crlexts crl -crl_lastupdate "$4" -crl_nextupdate "$5" -out "$pki/$6.pem"
  openssl crl -in "$pki/$6.pem" -outform DER -out "$pki/$6.crl" 2> /dev/null
}
: > "$pki/index.empty"
for f in old new; do # revoke both revoked_* certificates in inter's current CRL
  quiet openssl ca -batch -config "$pki/ca.cnf" -cert "$pki/inter.pem" -keyfile "$pki/inter.key" \
    -revoke "$pki/revoked_$f.pem" -crl_reason keyCompromise
done
sed -i -E 's/^R\t([0-9]+Z)\t[0-9]+Z,/R\t\1\t260601000000Z,/' "$pki/index.txt"
grep -v -E "CN=t12 (root|inter)$" "$pki/index.txt" > "$pki/index.revoked"
gencrl inter 02 "$pki/index.revoked" 20260601000000Z 20460101000000Z inter_current
gencrl inter 01 "$pki/index.empty" 20250601000000Z 20250701000000Z inter_stale
gencrl root 01 "$pki/index.empty" 20260601000000Z 20460101000000Z root_crl

# ---- helpers ---------------------------------------------------------------------------------
# supports <bin> <flag>: whether the usage text a build prints with no command names the flag.
supports() { local u; u="$("$1" 2>&1)"; grep -q -e "$2" <<< "$u"; }
keyfile() { openssl pkey -in "$pki/$1.key" -out "$W/$1.pem" 2> /dev/null; echo "$W/$1.pem"; }

# seal <bin> <dir> <key.pem> [more seal args...]: seals the synthetic log into <dir>, at $SEAL_AT if set.
seal() {
  local bin="$1" dir="$2" key="$3"; shift 3
  rm -rf "$dir"; mkdir -p "$dir"
  "$bin" seal "$LOG" --rules "$RULES" --baseline "$BASE" --key "$key" --evaluation-only \
    --seal-time "${SEAL_AT:-$SEAL_TIME}" --out "$dir" "$@" > "$dir.seal.txt" 2>&1
}
# vflags <bin>: the flags that make an evaluation-key record acceptable to this build, if any.
vflags() { supports "$1" "--allow-evaluation-key" && printf '%s' "--allow-evaluation-key"; }
# anchor_verify <bin> <record> <cert flavor-independent crl files...>
anchor_verify() {
  local bin="$1" rec="$2"; shift 2
  local crls=(); for c in "$@"; do crls+=(--crl "$c"); done
  # shellcheck disable=SC2046
  "$bin" verify "$rec" --trust-anchor "$pki/root.pem" "${crls[@]}" $(vflags "$bin") 2>&1
}
accepted() { grep -q '^Integrity: VERIFIED' <<< "$1"; }

declare -A RES   # RES[<id>.<build>] = succeeded | failed
declare -A WHY   # WHY[<id>.<build>] = the first line that says why
note() { RES["$1.$2"]="$3"; WHY["$1.$2"]="$4"; }
first_line() { grep -m1 -E '^(Integrity|chain|custody)' <<< "$1" | cut -c1-150; }

run_build() { # <label> <bin>
  local L="$1" bin="$2" F cdir="$W/$1"
  mkdir -p "$cdir"
  # Which certificate form this build understands: the one whose honest record verifies.
  F=""
  for f in new old; do
    seal "$bin" "$cdir/c0$f" "$(keyfile good_$f)" --cert "$pki/good_$f.pem" --chain "$pki/inter.pem"
    out="$(anchor_verify "$bin" "$cdir/c0$f/custom_detection.sfr" "$pki/root_crl.crl" "$pki/inter_current.crl")"
    if accepted "$out"; then F=$f; break; fi; [ -n "${T12_DEBUG:-}" ] && { echo "-- control $f:"; echo "$out"; }
  done
  if [ -z "$F" ]; then echo "t12: the control (an honest record, signed by a good certificate) does not verify with $bin" >&2; echo "$out" >&2; exit 1; fi
  note control "$L" "verifies" "certificate form: $F"
  local crls_ok=("$pki/root_crl.crl" "$pki/inter_current.crl")

  # A1a: a lapsed certificate with a backdated seal time.
  SEAL_AT=2025-06-01T00:00:00Z seal "$bin" "$cdir/a1a" "$(keyfile lapsed_$F)" --cert "$pki/lapsed_$F.pem" --chain "$pki/inter.pem"
  out="$(anchor_verify "$bin" "$cdir/a1a/custom_detection.sfr" "${crls_ok[@]}")"
  if accepted "$out"; then note A1a "$L" succeeded "VERIFIED"; else note A1a "$L" failed "$(first_line "$out")"; fi
  # A1b: a seal time in the verifier's future (certificate valid then).
  SEAL_AT=2035-12-31T00:00:00Z seal "$bin" "$cdir/a1b" "$(keyfile good_$F)" --cert "$pki/good_$F.pem" --chain "$pki/inter.pem"
  out="$(anchor_verify "$bin" "$cdir/a1b/custom_detection.sfr" "${crls_ok[@]}")"
  if accepted "$out"; then note A1b "$L" succeeded "VERIFIED"; else note A1b "$L" failed "$(first_line "$out")"; fi

  # A2a: an evaluation-key record, verified with no flag at all.
  "$bin" keygen --evaluation-only --out "$cdir/ek" > /dev/null 2>&1
  seal "$bin" "$cdir/a2" "$cdir/ek/sfr.key"
  out="$("$bin" verify "$cdir/a2/custom_detection.sfr" --pubkey "$cdir/ek/sfr.pub" 2>&1)"; rc=$?
  if accepted "$out" && [ $rc -eq 0 ]; then note A2a "$L" succeeded "VERIFIED, exit 0"; else note A2a "$L" failed "$(first_line "$out")"; fi
  # A2b: custody relabelled pkcs11-token, signed again with the evaluation key, --require-hardware-key.
  python3 -I "$forge" resign "$cdir/a2/custom_detection.sfr" "$cdir/ek/sfr.key" "$cdir/a2/forged.sfr" \
    --set 'seal.key_custody="pkcs11-token"' --set 'seal.key_label="pkcs11:token=prod;object=sfr-seal"'
  # shellcheck disable=SC2046
  out="$("$bin" verify "$cdir/a2/forged.sfr" --pubkey "$cdir/ek/sfr.pub" --require-hardware-key $(vflags "$bin") \
        $(supports "$bin" --no-report && printf '%s' --no-report) 2>&1)"; rc=$?
  if accepted "$out" && ! grep -q 'EVALUATION KEY' <<< "$out" && [ $rc -eq 0 ]; then
    note A2b "$L" succeeded "VERIFIED under --require-hardware-key, no banner"; else note A2b "$L" failed "$(first_line "$out")"; fi

  # A3a: a revoked signer; an older CRL of the same issuer comes first.
  seal "$bin" "$cdir/a3" "$(keyfile revoked_$F)" --cert "$pki/revoked_$F.pem" --chain "$pki/inter.pem"
  out="$(anchor_verify "$bin" "$cdir/a3/custom_detection.sfr" "$pki/root_crl.crl" "$pki/inter_stale.crl" "$pki/inter_current.crl")"
  if accepted "$out"; then note A3a "$L" succeeded "VERIFIED (revoked signer)"; else note A3a "$L" failed "$(first_line "$out")"; fi
  # A3b: the same signer, no CRL given at all.
  out="$(anchor_verify "$bin" "$cdir/a3/custom_detection.sfr")"
  if accepted "$out"; then note A3b "$L" succeeded "VERIFIED (revoked signer)"; else note A3b "$L" failed "$(first_line "$out")"; fi
  # A3c: the same signer, only a CRL past its nextUpdate.
  out="$(anchor_verify "$bin" "$cdir/a3/custom_detection.sfr" "$pki/root_crl.crl" "$pki/inter_stale.crl")"
  if accepted "$out"; then note A3c "$L" succeeded "VERIFIED (revoked signer)"; else note A3c "$L" failed "$(first_line "$out")"; fi

  # A4a: the report is missing. A4b: a forged report under another name. (Evaluation key record.)
  seal "$bin" "$cdir/a4" "$cdir/ek/sfr.key"
  mkdir -p "$cdir/a4a" "$cdir/a4b"
  cp "$cdir/a4/custom_detection.sfr" "$cdir/a4a/"; cp "$cdir/a4/custom_detection.sfr" "$cdir/a4b/"
  sed 's/Status: /Status: (forged) /' "$cdir/a4/custom_detection.sfr.md" > "$cdir/a4b/other.sfr.md"
  for k in a4a a4b; do
    # shellcheck disable=SC2046
    out="$("$bin" verify "$cdir/$k/custom_detection.sfr" --pubkey "$cdir/ek/sfr.pub" $(vflags "$bin") 2>&1)"
    id=A4a; [ $k = a4b ] && id=A4b
    if accepted "$out"; then note $id "$L" succeeded "VERIFIED, report not checked"; else note $id "$L" failed "$(first_line "$out")"; fi
  done
  # A4c: U+202E in the log's file name reaches the report and the output as a raw character.
  rlo="$cdir/gpl$(printf '\xe2\x80\xae')exe.ulg"; cp "$LOG" "$rlo"
  rm -rf "$cdir/a4c"; mkdir -p "$cdir/a4c"
  "$bin" seal "$rlo" --rules "$RULES" --baseline "$BASE" --key "$cdir/ek/sfr.key" --evaluation-only \
    --seal-time "$SEAL_TIME" --out "$cdir/a4c" > "$cdir/a4c.seal.txt" 2>&1
  raw=0; for f in "$cdir"/a4c/*.sfr.md "$cdir/a4c.seal.txt"; do grep -q $'\xe2\x80\xae' "$f" && raw=1; done
  if [ $raw -eq 1 ]; then note A4c "$L" succeeded "raw U+202E in the report or the output"; else note A4c "$L" failed "no raw U+202E; shown as <U+202E>"; fi

  # A5: the last result moved into sealed_topics, nothing signed again. It succeeds when the Merkle
  # root and the signature still match (no "Merkle root mismatch" is reported).
  python3 -I "$forge" move-leaf "$cdir/a4/custom_detection.sfr" "$cdir/a4/moved.sfr"
  # shellcheck disable=SC2046
  out="$("$bin" verify "$cdir/a4/moved.sfr" --pubkey "$cdir/ek/sfr.pub" $(vflags "$bin") \
        $(supports "$bin" --no-report && printf '%s' --no-report) 2>&1)"
  if grep -q 'Merkle root mismatch' <<< "$out"; then note A5 "$L" failed "$(grep -m1 -o 'Merkle root mismatch[^(]*' <<< "$out")"
  else note A5 "$L" succeeded "root and signature still valid; $(first_line "$out")"; fi

  # A7: a certificate issued for code signing only, used as the record signer.
  seal "$bin" "$cdir/a7" "$(keyfile good_old)" --cert "$pki/good_old.pem" --chain "$pki/inter.pem"
  out="$(anchor_verify "$bin" "$cdir/a7/custom_detection.sfr" "${crls_ok[@]}")"
  if accepted "$out"; then note A7 "$L" succeeded "VERIFIED"; else note A7 "$L" failed "$(first_line "$out" | cut -c1-110)"; fi
}

run_build earlier "$old"
run_build current "$new"

# ---- the table -------------------------------------------------------------------------------
printf '%s\n' "T12: the attacks of the A-series, earlier build against current build"
printf '%s\n' "  earlier: $("$old" --version 2>&1 | head -1)    current: $("$new" --version 2>&1 | head -1)"
printf '\n%-6s %-38s %-10s %-10s %s\n' ID ATTACK EARLIER CURRENT RESULT
bad=0
row() { # id name
  local e="${RES[$1.earlier]}" c="${RES[$1.current]}" v="as expected"
  if [ "$e" != succeeded ] || [ "$c" != failed ]; then v="NOT AS EXPECTED"; bad=1; fi
  printf '%-6s %-38s %-10s %-10s %s\n' "$1" "$2" "$e" "$c" "$v"
}
row A1a "backdated seal time, lapsed cert"
row A1b "seal time in the verifier's future"
row A2a "evaluation key, no flag"
row A2b "custody relabelled, --require-hw"
row A3a "revoked, older CRL given first"
row A3b "revoked, no CRL given"
row A3c "revoked, only a stale CRL"
row A4a "report missing"
row A4b "forged report, other name"
row A4c "U+202E in a file name"
row A5  "leaf moved to another section"
row A7  "code-signing cert as signer"
printf '\ncontrol (honest record, good certificate): earlier %s (%s); current %s (%s)\n' \
  "${RES[control.earlier]}" "${WHY[control.earlier]}" "${RES[control.current]}" "${WHY[control.current]}"
printf '\nwhy the current build refuses:\n'
for id in A1a A1b A2a A2b A3a A3b A3c A4a A4b A4c A5 A7; do printf '  %-4s %s\n' "$id" "${WHY[$id.current]}"; done
[ -n "${T12_DEBUG:-}" ] && { printf '\nwhy the earlier build stops it (debug):\n'; for id in A1a A1b; do printf '  %-4s %s\n' "$id" "${WHY[$id.earlier]}"; done; }
exit $bad
