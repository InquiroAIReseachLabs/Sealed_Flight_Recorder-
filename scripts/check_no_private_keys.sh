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

# Prints the files under work tree $1 that hold a private key block. Returns 1, after a message,
# when git cannot list the files or a file cannot be read: a scan that did not run is no pass.
scan() {
  local list f rc
  list="$(mktemp)"
  git -C "$1" ls-files -z --cached --others --exclude-standard > "$list" \
    || { echo "check_no_private_keys.sh: git cannot list the files of $1" >&2; rm -f "$list"; return 1; }
  while IFS= read -r -d '' f; do
    case "$f" in "$allowed" | "$self") continue ;; esac
    [ -f "$1/$f" ] || continue # deleted from the work tree, not yet from the index
    rc=0
    grep -q -I -E -- "$pattern" "$1/$f" || rc=$?
    case "$rc" in
      0) printf '%s\n' "$f" ;;
      1) ;;
      *) echo "check_no_private_keys.sh: cannot read $1/$f" >&2; rm -f "$list"; return 1 ;;
    esac
  done < "$list"
  rm -f "$list"
}

if [ "${1:-}" = --self-test ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp" "$tmp.out"' EXIT
  git -C "$tmp" init -q
  mkdir -p "$tmp/release" "$tmp/crates/sfr-core/src"
  printf -- '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n' > "$tmp/release/sfr-release.pem"
  printf -- '-----BEGIN EC PRIVATE KEY-----\nAAAA\n' > "$tmp/notes.txt"
  printf -- '-----BEGIN PRIVATE KEY-----\n' > "$tmp/$allowed"
  printf -- '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n' > "$tmp/release/sfr-release.pub"
  printf 'ignored.key\n' > "$tmp/.gitignore"
  printf -- '-----BEGIN PRIVATE KEY-----\n' > "$tmp/ignored.key"
  scan "$tmp" > "$tmp.out" || { echo "FAIL: self-test: the scan did not run"; exit 1; }
  [ "$(sort "$tmp.out" | tr '\n' ' ')" = "notes.txt release/sfr-release.pem " ] \
    || { echo "FAIL: self-test: found [$(cat "$tmp.out")]"; exit 1; }
  rm -rf "$tmp/.git"
  if scan "$tmp" > /dev/null 2>&1; then echo "FAIL: self-test: a directory git cannot list passes"; exit 1; fi
  echo "PASS: private key self-test (untracked and tracked files, PKCS#8 and EC, allow list, ignored files, no git)"
  exit 0
fi

hits="$(mktemp)"
trap 'rm -f "$hits"' EXIT
scan . > "$hits" || { echo "FAIL: the private key scan did not run"; exit 1; }
if [ -s "$hits" ]; then
  echo "FAIL: private key block in:"
  sed 's/^/  /' "$hits"
  exit 1
fi
echo "PASS: no private key in the repository"
