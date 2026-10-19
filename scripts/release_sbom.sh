#!/usr/bin/env bash
# release_sbom.sh: a CycloneDX SBOM of the sfr binary for each release target (SPEC B1.10 Supply
# chain), from Cargo.lock with cargo-cyclonedx (cargo install cargo-cyclonedx --locked).
#
# Writes <out-dir>/sfr-<version>-<target>.cdx.json (CycloneDX 1.5 JSON) for
# x86_64-unknown-linux-musl, aarch64-unknown-linux-musl and armv7-unknown-linux-musleabihf: the
# resolved dependency graph of sfr for that target (cargo metadata, so a superset of the crates
# linked: optional dependencies of toml appear too), each crate with its version, license, and the
# SHA-256 that Cargo.lock holds; build-time crates are listed with scope "excluded", and the
# workspace crate sfr-core has neither a license nor a hash (no license is set). Then checks each file
# names its target and lists sha2, ed25519-dalek and blake3. SOURCE_DATE_EPOCH (the commit time)
# fixes the timestamp.
#
# Usage: scripts/release_sbom.sh <out-dir>     Prints the SBOM paths.
set -euo pipefail
caller="$PWD"
# A relative path argument is relative to the directory the script was started in.
abs() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$caller/$1" ;; esac; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
die() { echo "release_sbom.sh: $*" >&2; exit 1; }
[ $# -eq 1 ] || { echo "usage: $0 <out-dir>" >&2; exit 2; }
out="$(abs "$1")"
command -v cargo-cyclonedx > /dev/null || die "cargo-cyclonedx is required: cargo install cargo-cyclonedx --version 0.5.9 --locked"
command -v jq > /dev/null || die "jq is required"
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)"
[ -n "$version" ] || die "no version in Cargo.toml"
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)"
mkdir -p "$out"
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf; do
  cargo cyclonedx --manifest-path crates/sfr/Cargo.toml --format json --spec-version 1.5 \
    --describe binaries --target "$target" --target-in-filename -q
  made="crates/sfr/sfr_bin_$target.cdx.json"
  [ -f "$made" ] || die "cargo-cyclonedx did not write $made"
  sbom="$out/sfr-$version-$target.cdx.json"
  mv "$made" "$sbom"
  # cargo-cyclonedx describes every workspace binary; only sfr ships in a release tarball.
  find crates -name "*_$target.cdx.json" -delete
  jq -e --arg t "$target" '
    .bomFormat == "CycloneDX" and .metadata.component.name == "sfr"
    and any(.metadata.properties[]; .name == "cdx:rustc:sbom:target:triple" and .value == $t)
    and ([.components[] | select(.scope == "required") | .name] | contains(["sha2", "ed25519-dalek", "blake3"]))
  ' "$sbom" > /dev/null || die "$sbom does not describe sfr for $target with sha2, ed25519-dalek and blake3"
  echo "$sbom"
done
