#!/usr/bin/env bash
# check_crypto_graph.sh: one crypto stack on every target (SPEC B1.10 Crypto).
#
# The shipped crate (sfr) takes SHA-256 from sha2, Ed25519 from
# ed25519-dalek, and BLAKE3 from blake3, on every target platform, and contain no other
# implementation of those primitives (AWS-LC, ring, OpenSSL, BoringSSL), so a record is
# byte-identical wherever it is sealed.
#
# Usage: scripts/check_crypto_graph.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

status=0
for pkg in sfr; do
  tree="$(cargo tree -p "$pkg" --locked --target all -e normal --prefix none)"
  for want in sha2 ed25519-dalek blake3; do
    grep -qE "^${want} v" <<<"$tree" || { echo "  $pkg: $want is missing from the dependency graph"; status=1; }
  done
  if other="$(grep -E '^(aws-lc[a-z0-9-]*|ring|openssl[a-z0-9-]*|boring[a-z0-9-]*) v' <<<"$tree")"; then
    echo "  $pkg: another crypto implementation is in the dependency graph:"
    printf '    %s\n' $other
    status=1
  fi
  echo "  $pkg: $(grep -E '^(sha2|ed25519-dalek|blake3) v' <<<"$tree" | sort -u | tr '\n' ' ')"
done
exit $status
