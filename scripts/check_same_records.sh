#!/usr/bin/env bash
# check_same_records.sh: two sfr builds seal byte-identical records (SPEC B1.10 Crypto).
#
# Seals every golden log (scripts/testdata/regenerate.sh list) with each build, using one
# evaluation key, the default rules, the log's golden baseline, and one --seal-time, and
# compares the records byte for byte. CI runs it with the x86_64 build and the armv7 build
# (under QEMU) to show that a record does not depend on where it is sealed.
#
# Usage: scripts/check_same_records.sh <sfr-a> <sfr-b>
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ $# -eq 2 ] || { echo "usage: $0 <sfr-a> <sfr-b>" >&2; exit 2; }
a="$1" b="$2"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"$a" keygen --evaluation-only --out "$work/key" > /dev/null
same=0 total=0 status=0
while read -r name log; do
  total=$((total + 1))
  for side in a b; do
    bin="$a"; [ "$side" = b ] && bin="$b"
    mkdir -p "$work/$side/$name"
    # A failing rule exits 1 or 2 and still writes the record; anything else is a failure.
    rc=0
    "$bin" seal "$log" --rules examples/rules.default.toml --baseline "testdata/baselines/$name.params" \
      --key "$work/key/sfr.key" --evaluation-only --seal-time 2026-10-18T15:00:00Z \
      --out "$work/$side/$name" > "$work/$side/$name.out" 2>&1 || rc=$?
    if [ "$rc" -gt 2 ]; then
      echo "  $name: $bin exited $rc"; cat "$work/$side/$name.out"; status=1
    fi
  done
  ra="$(find "$work/a/$name" -name '*.sfr')" rb="$(find "$work/b/$name" -name '*.sfr')"
  if [ -n "$ra" ] && [ -n "$rb" ] && cmp -s "$ra" "$rb"; then
    same=$((same + 1))
  else
    echo "  $name: the records differ or are missing"; status=1
  fi
done < <(scripts/testdata/regenerate.sh list)
echo "byte-identical records: $same of $total golden logs"
[ "$total" -gt 0 ] || status=1
exit $status
