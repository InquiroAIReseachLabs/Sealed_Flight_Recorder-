#!/usr/bin/env bash
# check_reproducible.sh: build one target twice from clean and compare (Chunk 5 task 7).
#
# Runs scripts/build_release.sh twice in the same build directory, deleting it before each build,
# and compares the two binaries and the two tarballs byte for byte. Prints one line per artifact,
# "identical <sha256>" or "DIFFERENT <sha256> <sha256>", and keeps the first build's tarball in
# <out-dir>. It reports; it does not claim more than two builds on one machine prove. Exits 1 if
# either artifact differs.
#
# Usage: scripts/check_reproducible.sh <target> <out-dir>
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ $# -eq 2 ] || { echo "usage: $0 <target> <out-dir>" >&2; exit 2; }
target="$1" out="$2"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
build_dir="${CARGO_TARGET_DIR:-$(pwd -P)/target/reproducible}"

for n in 1 2; do
  rm -rf "$build_dir"
  mkdir -p "$work/$n"
  tarball="$(CARGO_TARGET_DIR="$build_dir" scripts/build_release.sh "$target" "$work/$n")"
  cp "$build_dir/$target/release/sfr" "$work/$n/sfr"
done
name="$(basename "$tarball")"
status=0
for artifact in sfr "$name"; do
  a="$(sha256sum "$work/1/$artifact" | cut -d' ' -f1)"
  b="$(sha256sum "$work/2/$artifact" | cut -d' ' -f1)"
  label="$target $artifact"
  [ "$artifact" = sfr ] && label="$target bin/sfr"
  if [ "$a" = "$b" ]; then
    echo "reproducible: $label: identical $a"
  else
    echo "reproducible: $label: DIFFERENT $a $b"
    status=1
  fi
done
cp "$work/1/$name" "$out/$name"
exit $status
