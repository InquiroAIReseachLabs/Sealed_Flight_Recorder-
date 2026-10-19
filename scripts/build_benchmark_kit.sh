#!/usr/bin/env bash
# build_benchmark_kit.sh: the benchmark kit tarball, for any architecture (Chunk 5).
#
# scripts/benchmark.sh needs no build tools, but it needs the golden logs. The kit holds:
#
#   sfr-<version>-benchmark/README.md                       docs/BENCHMARK.md: how to run it
#   sfr-<version>-benchmark/scripts/benchmark.sh
#   sfr-<version>-benchmark/scripts/benchmark/vtol_transition.segments
#   sfr-<version>-benchmark/scripts/testdata/golden_logs.sh
#   sfr-<version>-benchmark/examples/rules.default.toml
#   sfr-<version>-benchmark/testdata/                      every golden log with its license or
#                                                           provenance notice, the baselines, and
#                                                           the golden rules files
#
# Run it with the sfr of a release tarball: docs/BENCHMARK.md. Same tarball conventions as
# scripts/build_release.sh: sorted names, modes 755 and 644, the commit time as every mtime, owner
# 0, no gzip time.
#
# Usage: scripts/build_benchmark_kit.sh <out-dir>    Prints the tarball path.
set -euo pipefail
caller="$PWD"
# A relative path argument is relative to the directory the script was started in.
abs() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$caller/$1" ;; esac; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ $# -eq 1 ] || { echo "usage: $0 <out-dir>" >&2; exit 2; }
out="$(abs "$1")"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)"
[ -n "$version" ] || { echo "build_benchmark_kit.sh: no version in Cargo.toml" >&2; exit 1; }
epoch="$(git log -1 --format=%ct HEAD)"
mkdir -p "$out"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
name="sfr-$version-benchmark"
kit="$stage/$name"
mkdir -p "$kit/scripts/benchmark" "$kit/scripts/testdata" "$kit/examples" "$kit/testdata"
install -m 0644 docs/BENCHMARK.md "$kit/README.md"
install -m 0755 scripts/benchmark.sh "$kit/scripts/"
install -m 0644 scripts/benchmark/vtol_transition.segments "$kit/scripts/benchmark/"
install -m 0644 scripts/testdata/golden_logs.sh "$kit/scripts/testdata/"
install -m 0644 examples/rules.default.toml "$kit/examples/"
# Every golden log and its notice, by the same list benchmark.sh reads.
# shellcheck source=scripts/testdata/golden_logs.sh
. scripts/testdata/golden_logs.sh
install -m 0644 -D testdata/README.md "$kit/testdata/README.md"
install -m 0644 -D testdata/pyulog/NOTICE.md "$kit/testdata/pyulog/NOTICE.md"
install -m 0644 -D testdata/pyulog/LICENSE.md "$kit/testdata/pyulog/LICENSE.md"
while read -r golden log; do
  install -m 0644 -D "$log" "$kit/$log"
  notice="${log%.ulg}.provenance.md"
  if [ -f "$notice" ]; then install -m 0644 -D "$notice" "$kit/$notice"; fi
  install -m 0644 -D "testdata/baselines/$golden.params" "$kit/testdata/baselines/$golden.params"
  rules="$(golden_rules_for "$golden")"
  [ "$rules" = examples/rules.default.toml ] || install -m 0644 -D "$rules" "$kit/$rules"
done < <(golden_logs)
# Every log the kit holds carries its license or provenance notice.
while read -r log; do
  [ -f "${log%.ulg}.provenance.md" ] || [ "$(dirname "$log")" = "$kit/testdata/pyulog" ] \
    || { echo "build_benchmark_kit.sh: $log has no notice" >&2; exit 1; }
done < <(find "$kit/testdata" -name '*.ulg')
tarball="$out/$name.tar.gz"
tar -C "$stage" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner --mode='u=rwX,go=rX' \
  --format=gnu -cf - "$name" | gzip -n -6 > "$tarball"
echo "$tarball"
