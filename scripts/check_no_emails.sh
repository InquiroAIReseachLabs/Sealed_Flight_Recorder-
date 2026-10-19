#!/usr/bin/env bash
# check_no_emails.sh: no email address in the repository (personal information). Fails if any
# tracked, or untracked and not ignored, text file holds an email address, except at the reserved
# example domains example.com and example.org (RFC 2606). A name may stay; an address goes.
#
# Usage: scripts/check_no_emails.sh [--self-test]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
pattern='[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}'

# Prints path:line:address for every address under work tree $1 outside the example domains.
# Returns 1, after a message, when git cannot list the files: a scan that did not run is no pass.
scan() {
  local list
  list="$(mktemp)"
  git -C "$1" --git-dir=.git --work-tree=. ls-files -z --cached --others --exclude-standard > "$list" \
    || { echo "check_no_emails.sh: git cannot list the files of $1" >&2; rm -f "$list"; return 1; }
  (cd "$1" && xargs -0 -r grep -I -n -o -E -- "$pattern" < "$list" 2> /dev/null || true) \
    | grep -v -i -E '@example\.(com|org)$' || true
  rm -f "$list"
}

if [ "${1:-}" = --self-test ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  git -C "$tmp" init -q
  at='@'
  mkdir -p "$tmp/docs"
  printf 'Contact: person%sexample.net for help\n' "$at" > "$tmp/docs/a.md"
  printf 'author = "A. Person <a.person%smail.co.uk>"\n' "$at" > "$tmp/b.toml"
  printf 'examples: ops%sexample.com, Team%sExample.ORG\n' "$at" "$at" > "$tmp/c.md"
  printf 'not addresses: @scope/package, user@host, a@b\n' > "$tmp/d.txt"
  printf 'person%sexample.net\n' "$at" > "$tmp/ignored.env"
  printf '*.env\n' > "$tmp/.gitignore"
  found="$(scan "$tmp" | cut -d: -f1 | sort -u | tr '\n' ' ')"
  [ "$found" = "b.toml docs/a.md " ] || { echo "FAIL: self-test: found [$found]"; exit 1; }
  rm -rf "$tmp/.git"
  if (scan "$tmp" > /dev/null 2>&1); then echo "FAIL: self-test: a directory git cannot list passes"; exit 1; fi
  echo "PASS: email self-test (addresses found in tracked and untracked files, example domains allowed, ignored files and non-addresses skipped, no git)"
  exit 0
fi

hits="$(scan .)" || { echo "FAIL: the email scan did not run"; exit 1; }
if [ -n "$hits" ]; then
  echo "FAIL: email address in:"
  printf '%s\n' "$hits" | sed 's/^/  /'
  exit 1
fi
echo "PASS: no email address in the repository (example.com and example.org addresses aside)"
