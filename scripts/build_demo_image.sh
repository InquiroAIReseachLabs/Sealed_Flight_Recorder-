#!/usr/bin/env bash
# build_demo_image.sh: the sfr demo image, x86_64, from the x86_64 release tarball.
#
# The image holds /sfr/bin/sfr from the tarball, /sfr/scripts/run_demo.sh, the two golden logs
# the demo uses (testdata/sitl/v1.17.0/vtol_transition.ulg and gz_quadtailsitter_transition.ulg)
# with their provenance files and testdata/README.md (their license and provenance notices),
# their two baselines, and examples/rules.default.toml, on busybox (docker/Dockerfile). Writes
# the image tag sfr-demo:<version> and saves it as <out-dir>/sfr-<version>-demo-image.tar.gz.
#
# Usage: scripts/build_demo_image.sh <sfr-<version>-x86_64-unknown-linux-musl.tar.gz> <out-dir>
# Prints the saved image path.
set -euo pipefail
caller="$PWD"
# A relative path argument is relative to the directory the script was started in.
abs() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$caller/$1" ;; esac; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
die() { echo "build_demo_image.sh: $*" >&2; exit 1; }
[ $# -eq 2 ] || die "usage: $0 <x86_64 release tarball> <out-dir>"
tarball="$(abs "$1")" out="$(abs "$2")"
command -v docker > /dev/null || die "docker is required"
name="$(basename "$tarball" .tar.gz)"
[[ "$name" =~ ^sfr-(.+)-x86_64-unknown-linux-musl$ ]] || die "not an x86_64 release tarball: $tarball"
version="${BASH_REMATCH[1]}"
mkdir -p "$out"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

tar -C "$stage" -xzf "$tarball" "$name/bin/sfr"
ctx="$stage/context"
mkdir -p "$ctx/sfr/bin" "$ctx/sfr/scripts" "$ctx/sfr/examples" "$ctx/sfr/testdata/baselines" \
  "$ctx/sfr/testdata/sitl/v1.17.0"
install -m 0755 "$stage/$name/bin/sfr" "$ctx/sfr/bin/sfr"
install -m 0755 scripts/run_demo.sh "$ctx/sfr/scripts/run_demo.sh"
install -m 0644 examples/rules.default.toml "$ctx/sfr/examples/"
install -m 0644 testdata/README.md "$ctx/sfr/testdata/"
for log in vtol_transition gz_quadtailsitter_transition; do
  install -m 0644 "testdata/sitl/v1.17.0/$log.ulg" "testdata/sitl/v1.17.0/$log.provenance.md" \
    "$ctx/sfr/testdata/sitl/v1.17.0/"
  install -m 0644 "testdata/baselines/v1.17.0_$log.params" "$ctx/sfr/testdata/baselines/"
done
cp docker/Dockerfile "$ctx/Dockerfile"
docker build --network=none --pull=false --build-arg "SFR_VERSION=$version" -t "sfr-demo:$version" "$ctx" >&2
image="$out/sfr-$version-demo-image.tar.gz"
docker save "sfr-demo:$version" | gzip -n -6 > "$image"
echo "$image"
