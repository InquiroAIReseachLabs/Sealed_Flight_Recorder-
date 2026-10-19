#!/usr/bin/env bash
# check_no_private_keys.sh: no private key in the repository (SPEC B1.10 Releases: the release
# key stays offline; evaluation keys are made at run time). Fails if any tracked or untracked,
# not ignored, file holds a PEM private key block ("-----BEGIN ... PRIVATE KEY-----"), except
# crates/sfr-core/src/keys.rs, whose unit test decodes the published RFC 8410 section 10.3
# example key, and this script.
#
# Usage: scripts/check_no_private_keys.sh [--self-test]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
pattern='-----BEGIN ([A-Z0-9]+ )?PRIVATE KEY-----'
allowed='crates/sfr-core/src/keys.rs'
self='scripts/check_no_private_keys.sh'

# Prints the files under work tree $1 that hold a private key block.
scan() {
  (cd "$1" && git ls-files -z --cached --others --exclude-standard \
    | grep -zv -x -F -e "$allowed" -e "$self" \
    | xargs -0 -r grep -l -I -E -- "$pattern" 2> /dev/null || true)
}

if [ "${1:-}" = --self-test ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  git -C "$tmp" init -q
  mkdir -p "$tmp/release" "$tmp/crates/sfr-core/src"
  printf -- '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n' > "$tmp/release/sfr-release.pem"
  printf -- '-----BEGIN EC PRIVATE KEY-----\nAAAA\n' > "$tmp/notes.txt"
  printf -- '-----BEGIN PRIVATE KEY-----\n' > "$tmp/$allowed"
  printf -- '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n' > "$tmp/release/sfr-release.pub"
  printf 'ignored.key\n' > "$tmp/.gitignore"
  printf -- '-----BEGIN PRIVATE KEY-----\n' > "$tmp/ignored.key"
  out="$(scan "$tmp")"
  [ "$(printf '%s\n' "$out" | sort | tr '\n' ' ')" = "notes.txt release/sfr-release.pem " ] \
    || { echo "FAIL: self-test: found [$out]"; exit 1; }
  echo "PASS: private key self-test (untracked and tracked files, PKCS#8 and EC, allow list, ignored files)"
  exit 0
fi

hits="$(scan .)"
if [ -n "$hits" ]; then
  echo "FAIL: private key block in:"
  printf '  %s\n' $hits
  exit 1
fi
echo "PASS: no private key in the repository"
