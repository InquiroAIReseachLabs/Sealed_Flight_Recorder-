#!/usr/bin/env bash
# release_assemble.sh: check that a directory holds every release artifact, then write SHA256SUMS
# over all of them (SPEC B1.10 Releases). Nothing is signed or published here: the release key holder signs
# SHA256SUMS offline with scripts/release_sign.sh (docs/RELEASE.md).
#
# The artifacts, for the version in Cargo.toml:
#   sfr-<version>-x86_64-unknown-linux-musl.tar.gz       scripts/build_release.sh
#   sfr-<version>-aarch64-unknown-linux-musl.tar.gz
#   sfr-<version>-armv7-unknown-linux-musleabihf.tar.gz
#   sfr-<version>-benchmark.tar.gz                       scripts/build_benchmark_kit.sh
#   sfr-<version>-demo-image.tar.gz                      scripts/build_demo_image.sh
#   sfr-<version>-<target>.cdx.json, one per target     scripts/release_sbom.sh
# Any other file in the directory is an error, so SHA256SUMS covers exactly the release.
#
# With --set github, the set is the one the GitHub release holds (.github/workflows/release.yml):
# the three tarballs and the three SBOMs, without the benchmark kit and the demo image.
#
# Usage: scripts/release_assemble.sh [--set github] <dir>     Writes <dir>/SHA256SUMS and prints it.
#        scripts/release_assemble.sh --names github [<version>]   Prints the file names the GitHub
#            release's SHA256SUMS lists, one per line, for the version in Cargo.toml (or <version>);
#            scripts/release_sign.sh sign signs a SHA256SUMS that lists exactly these.
set -euo pipefail
caller="$PWD"
# A relative path argument is relative to the directory the script was started in.
abs() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$caller/$1" ;; esac; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
die() { echo "release_assemble.sh: $*" >&2; exit 1; }
if [ "${1:-}" = --names ]; then
  [ "${2:-}" = github ] || die "--names takes github"
  names_version="${3:-$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)}"
  [[ "$names_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "no x.y.z version"
  for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf; do
    printf 'sfr-%s-%s.tar.gz\nsfr-%s-%s.cdx.json\n' "$names_version" "$target" "$names_version" "$target"
  done | sort
  exit 0
fi
set_name=all
if [ "${1:-}" = --set ]; then
  [ "${2:-}" = github ] || die "--set takes github"
  set_name=github
  shift 2
fi
[ $# -eq 1 ] || { echo "usage: $0 [--set github] <dir>" >&2; exit 2; }
dir="$(abs "$1")"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)"
[ -n "$version" ] || die "no version in Cargo.toml"
expected=()
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf; do
  expected+=("sfr-$version-$target.tar.gz" "sfr-$version-$target.cdx.json")
done
[ "$set_name" = github ] || expected+=("sfr-$version-benchmark.tar.gz" "sfr-$version-demo-image.tar.gz")
for f in "${expected[@]}"; do
  [ -s "$dir/$f" ] || die "missing or empty: $dir/$f"
done
rm -f "$dir/SHA256SUMS"
present="$(cd "$dir" && find . -maxdepth 1 -type f -printf '%f\n' | sort)"
want="$(printf '%s\n' "${expected[@]}" | sort)"
[ "$present" = "$want" ] || die "$dir holds files that are not release artifacts: $(comm -23 <(echo "$present") <(echo "$want") | tr '\n' ' ')"
(cd "$dir" && printf '%s\n' "${expected[@]}" | sort | xargs sha256sum > SHA256SUMS)
(cd "$dir" && sha256sum --quiet -c SHA256SUMS) || die "SHA256SUMS does not check"
[ "$(wc -l < "$dir/SHA256SUMS")" -eq "${#expected[@]}" ] || die "SHA256SUMS does not list every artifact"
cat "$dir/SHA256SUMS"
