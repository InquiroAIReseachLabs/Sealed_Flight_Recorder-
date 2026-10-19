#!/usr/bin/env bash
# release_sign.sh: the Ed25519 signature over a release's SHA256SUMS (SPEC B1.10 Releases), made
# and checked with OpenSSL 3 alone. The founder runs it on an offline machine; CI never holds the
# release private key, and no private key enters the repository (.gitignore: *.key).
#
#   scripts/release_sign.sh keygen <private-key-file>
#       Once, offline: a new Ed25519 release key. Writes the private key (PKCS#8 PEM, mode 0600)
#       to <private-key-file>, which must not exist and must stay off the repository, and its
#       public half to release/sfr-release.pub, which is committed and shown in the README
#       (scripts/regen_readme_numbers.sh writes it there with its fingerprint).
#   scripts/release_sign.sh sign <SHA256SUMS> <private-key-file> [--pubkey <public-key>]
#       Writes <SHA256SUMS>.sig (a raw 64-byte Ed25519 signature), refusing a private key whose
#       public half is not the release key (default release/sfr-release.pub), and a SHA256SUMS
#       that does not list exactly the release's six files (scripts/release_assemble.sh --names
#       github; set SFR_RELEASE_VERSION to re-sign an earlier release), then checks the
#       signature with the verify command below.
#   scripts/release_sign.sh verify <SHA256SUMS> [--pubkey <public-key>]
#       Runs the documented check:
#         openssl pkeyutl -verify -pubin -inkey sfr-release.pub -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig
#       which prints "Signature Verified Successfully" and exits 0 only for a good signature.
#   scripts/release_sign.sh --self-test
#       With a throwaway key in a temporary directory: keygen, sign, verify passes; a changed
#       SHA256SUMS, a changed signature, and a different key each fail; sign refuses a key that
#       is not the release key.
set -euo pipefail
caller="$PWD"
# A relative path argument is relative to the directory the script was started in.
abs() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$caller/$1" ;; esac; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
release_pub=release/sfr-release.pub
die() { echo "release_sign.sh: $*" >&2; exit 1; }
command -v openssl > /dev/null || die "openssl is required"
case "$(openssl version)" in OpenSSL\ [3-9].*) ;; *) die "OpenSSL 3 or later is required (pkeyutl -rawin), found: $(openssl version)" ;; esac

# public_of <private-key-file>: the PEM public key.
public_of() { openssl pkey -in "$1" -pubout; }

keygen() { # keygen <private-key-file> <public-key-file>
  [ ! -e "$1" ] || die "$1 exists; keygen never overwrites a key"
  [ ! -e "$2" ] || die "$2 exists; keygen never overwrites the release public key"
  mkdir -p "$(dirname "$2")"
  (umask 077 && openssl genpkey -algorithm ed25519 -out "$1")
  public_of "$1" > "$2"
  echo "private key $1 (mode 0600; keep it offline, never commit it)"
  echo "public key  $2"
  echo "next: scripts/regen_readme_numbers.sh shows the key in README.md; commit both files"
}

verify() { # verify <SHA256SUMS> <public-key-file>
  [ -f "$1.sig" ] || die "no signature $1.sig"
  openssl pkeyutl -verify -pubin -inkey "$2" -rawin -in "$1" -sigfile "$1.sig"
}

sign() { # sign <SHA256SUMS> <private-key-file> <public-key-file>
  local want
  [ -f "$1" ] || die "no $1"
  [ -f "$2" ] || die "no private key $2"
  [ -f "$3" ] || die "no release public key $3; run: scripts/release_sign.sh keygen <offline path>"
  [ "$(public_of "$2")" = "$(cat "$3")" ] || die "the private key $2 is not the release key $3"
  # Only the SHA256SUMS of this release is worth signing: sha256sum lines, each ending in a
  # newline, listing exactly the release's six file names for the version in Cargo.toml (or in
  # SFR_RELEASE_VERSION, to re-sign an earlier release): no path, no repeat, nothing else.
  [ -s "$1" ] || die "$1 is empty"
  [ "$(tail -c1 "$1" | od -An -c | tr -d ' ')" = '\n' ] || die "$1 does not end in a newline"
  if grep -q -v -E '^[0-9a-f]{64}  [A-Za-z0-9._+-]+$' "$1"; then
    die "$1 holds a line that is not '<sha256>  <bare file name>'; sign only the SHA256SUMS that scripts/release_assemble.sh wrote"
  fi
  want="$(scripts/release_assemble.sh --names github ${SFR_RELEASE_VERSION:+"$SFR_RELEASE_VERSION"})" || die "cannot work out the release file names"
  [ "$(awk '{ print $2 }' "$1" | sort)" = "$want" ] \
    || die "$1 does not list exactly the release files: $(printf '%s' "$want" | tr '\n' ' ')"
  openssl pkeyutl -sign -inkey "$2" -rawin -in "$1" -out "$1.sig"
  [ "$(wc -c < "$1.sig")" -eq 64 ] || die "$1.sig is not a 64-byte Ed25519 signature"
  verify "$1" "$3"
  echo "signed $1 -> $1.sig"
}

self_test() {
  local t out
  t="$(mktemp -d)"
  trap 'rm -rf "$t"' RETURN
  # a SHA256SUMS of the six release files (the names scripts/release_assemble.sh --names lists)
  scripts/release_assemble.sh --names github | while IFS= read -r n; do
    printf '%s  %s\n' "$(printf '%s' "$n" | sha256sum | cut -d' ' -f1)" "$n"
  done > "$t/SHA256SUMS"
  [ "$(wc -l < "$t/SHA256SUMS")" -eq 6 ] || die "self-test: the fixture does not list six files"
  keygen "$t/test.key" "$t/test.pub" > /dev/null
  [ "$(stat -c %a "$t/test.key")" = 600 ] || die "self-test: the private key is not mode 0600"
  if (keygen "$t/test.key" "$t/other.pub" > /dev/null 2>&1); then die "self-test: keygen overwrote a key"; fi
  sign "$t/SHA256SUMS" "$t/test.key" "$t/test.pub" > /dev/null
  out="$(verify "$t/SHA256SUMS" "$t/test.pub")"
  [ "$out" = "Signature Verified Successfully" ] || die "self-test: verify printed: $out"
  cp "$t/SHA256SUMS" "$t/SHA256SUMS.orig"
  printf '0' >> "$t/SHA256SUMS"
  if verify "$t/SHA256SUMS" "$t/test.pub" > /dev/null 2>&1; then die "self-test: a changed SHA256SUMS verifies"; fi
  cp "$t/SHA256SUMS.orig" "$t/SHA256SUMS"
  # Flip one bit of byte 10, so the signature always changes (writing a fixed byte left it
  # unchanged whenever the random key's signature already held that byte there).
  b="$(od -An -tu1 -j10 -N1 "$t/SHA256SUMS.sig" | tr -d ' ')"
  printf "$(printf '\\%03o' $((b ^ 1)))" | dd of="$t/SHA256SUMS.sig" bs=1 seek=10 conv=notrunc 2> /dev/null
  if verify "$t/SHA256SUMS" "$t/test.pub" > /dev/null 2>&1; then die "self-test: a changed signature verifies"; fi
  (umask 077 && openssl genpkey -algorithm ed25519 -out "$t/other.key")
  public_of "$t/other.key" > "$t/other.pub"
  sign "$t/SHA256SUMS" "$t/test.key" "$t/test.pub" > /dev/null
  if verify "$t/SHA256SUMS" "$t/other.pub" > /dev/null 2>&1; then die "self-test: another key verifies"; fi
  if (sign "$t/SHA256SUMS" "$t/other.key" "$t/test.pub" > /dev/null 2>&1); then die "self-test: sign accepted a key that is not the release key"; fi
  # What may be signed: bare names only, no repeats, not empty.
  printf '%s  ../escape.tar.gz\n' "$(printf a | sha256sum | cut -d' ' -f1)" > "$t/BAD1"
  if (sign "$t/BAD1" "$t/test.key" "$t/test.pub" > /dev/null 2>&1); then die "self-test: sign accepted a path in SHA256SUMS"; fi
  { cat "$t/SHA256SUMS.orig"; cat "$t/SHA256SUMS.orig"; } > "$t/BAD2"
  if (sign "$t/BAD2" "$t/test.key" "$t/test.pub" > /dev/null 2>&1); then die "self-test: sign accepted a repeated name"; fi
  : > "$t/BAD3"
  if (sign "$t/BAD3" "$t/test.key" "$t/test.pub" > /dev/null 2>&1); then die "self-test: sign accepted an empty SHA256SUMS"; fi
  head -5 "$t/SHA256SUMS.orig" > "$t/BAD5"
  if (sign "$t/BAD5" "$t/test.key" "$t/test.pub" > /dev/null 2>&1); then die "self-test: sign accepted a list with a release file missing"; fi
  { cat "$t/SHA256SUMS.orig"; printf '%s  extra.tar.gz\n' "$(printf a | sha256sum | cut -d' ' -f1)"; } > "$t/BAD6"
  if (sign "$t/BAD6" "$t/test.key" "$t/test.pub" > /dev/null 2>&1); then die "self-test: sign accepted a list with an extra file"; fi
  cur="$(scripts/release_assemble.sh --names github | head -1 | sed -E 's/^sfr-([0-9]+\.[0-9]+\.[0-9]+)-.*/\1/')"
  sed "s/sfr-$cur-/sfr-9.9.9-/" "$t/SHA256SUMS.orig" > "$t/BAD7"
  if (sign "$t/BAD7" "$t/test.key" "$t/test.pub" > /dev/null 2>&1); then die "self-test: sign accepted another version's list"; fi
  head -c -1 "$t/SHA256SUMS.orig" > "$t/BAD8"
  if (sign "$t/BAD8" "$t/test.key" "$t/test.pub" > /dev/null 2>&1); then die "self-test: sign accepted a list without a final newline"; fi
  printf 'not a checksum line\n' > "$t/BAD4"
  if (sign "$t/BAD4" "$t/test.key" "$t/test.pub" > /dev/null 2>&1); then die "self-test: sign accepted a line that is not a checksum"; fi
  [ ! -e "$t/BAD1.sig" ] && [ ! -e "$t/BAD4.sig" ] || die "self-test: a refused file was still signed"
  echo "release_sign.sh self-test: ok"
}

# pubkey_arg <args...>: the --pubkey value, else the committed release key.
pubkey_arg() {
  if [ "${1:-}" = --pubkey ]; then [ -n "${2:-}" ] || die "--pubkey needs a file"; abs "$2"; else echo "$release_pub"; fi
}

case "${1:-}" in
  keygen) [ $# -eq 2 ] || die "usage: $0 keygen <private-key-file>"; keygen "$(abs "$2")" "$release_pub" ;;
  sign) [ $# -eq 3 ] || [ $# -eq 5 ] || die "usage: $0 sign <SHA256SUMS> <private-key-file> [--pubkey <file>]"
    sign "$(abs "$2")" "$(abs "$3")" "$(pubkey_arg "${@:4}")" ;;
  verify) [ $# -eq 2 ] || [ $# -eq 4 ] || die "usage: $0 verify <SHA256SUMS> [--pubkey <file>]"
    verify "$(abs "$2")" "$(pubkey_arg "${@:3}")" ;;
  --self-test) self_test ;;
  *) die "usage: $0 keygen <private-key-file> | sign <SHA256SUMS> <private-key-file> [--pubkey <file>] | verify <SHA256SUMS> [--pubkey <file>] | --self-test" ;;
esac
