#!/usr/bin/env bash
# build_release.sh: the static release tarball of sfr for one musl target (SPEC B1.10 Static
# binaries, Releases).
#
# Builds with rust-lld as the linker and the target's own musl startup files, as the armv7 CI job
# does, so no C cross toolchain is needed (aarch64 builds blake3 without its C NEON code; see
# crates/sfr-core/Cargo.toml). Then checks the SPEC B1.10 static criteria: `readelf -lW` shows no
# INTERP program header, `readelf -dW` no NEEDED entry, and for armv7 `file` reports a statically
# linked 32-bit ARM executable. Packs:
#
#   sfr-<version>-<target>/bin/sfr
#   sfr-<version>-<target>/README.md
#   sfr-<version>-<target>/examples/        rules files and the example records and reports
#   sfr-<version>-<target>/examples/sample/ a 1.3 KB synthetic log and its baseline, for the quickstart
#   sfr-<version>-<target>/BUILDINFO        version, target, commit, toolchain, binary SHA-256
#
# The build is meant not to depend on where it runs (scripts/check_reproducible.sh compares two
# builds on one machine): --remap-path-prefix replaces the checkout, the Cargo home, and the target
# directory in the binary; SFR_BUILD_COMMIT is the checkout's commit; the tarball has sorted
# names, modes 755 and 644 whatever the umask or a setgid temporary directory, the commit time as
# every mtime, owner 0, and no gzip timestamp.
# scripts/check_reproducible.sh builds a target twice from clean and compares.
#
# Usage: scripts/build_release.sh <target> <out-dir>
# Prints the tarball path. CARGO_TARGET_DIR, when set, is the build directory.
set -euo pipefail
caller="$PWD"
# A relative path argument is relative to the directory the script was started in.
abs() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$caller/$1" ;; esac; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
root="$(pwd -P)"

die() { echo "build_release.sh: $*" >&2; exit 1; }
[ $# -eq 2 ] || die "usage: $0 <target> <out-dir>"
target="$1" out="$(abs "$2")"
case "$target" in
  x86_64-unknown-linux-musl | aarch64-unknown-linux-musl | armv7-unknown-linux-musleabihf) ;;
  *) die "unknown target $target (x86_64-unknown-linux-musl, aarch64-unknown-linux-musl, armv7-unknown-linux-musleabihf)" ;;
esac
for tool in cargo rustc git readelf file sha256sum tar gzip; do
  command -v "$tool" > /dev/null || die "$tool is required"
done
# rust-toolchain.toml lists no cross targets, so a plain build installs only the host's.
if command -v rustup > /dev/null && ! rustup target list --installed | grep -q -x -F "$target"; then
  die "the target $target is not installed: run  rustup target add $target"
fi

version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)"
[ -n "$version" ] || die "no [workspace.package] version in Cargo.toml"
commit="$(git rev-parse HEAD)"
epoch="$(git log -1 --format=%ct HEAD)"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
mkdir -p "$target_dir" "$out"
target_dir="$(cd "$target_dir" && pwd -P)"
cargo_home="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"

# CARGO_ENCODED_RUSTFLAGS: flags separated by 0x1f, so a path with a space stays one flag.
flags=(
  "--remap-path-prefix=$root=/build/sfr"
  "--remap-path-prefix=$cargo_home=/build/cargo"
  "--remap-path-prefix=$target_dir=/build/target"
)
CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\x1f'; printf '%s' "${flags[*]}")"
linker_var="CARGO_TARGET_$(printf '%s' "$target" | tr 'a-z-' 'A-Z_')_LINKER"
export CARGO_ENCODED_RUSTFLAGS SFR_BUILD_COMMIT="$commit" CARGO_TARGET_DIR="$target_dir"
export "$linker_var=rust-lld"
cargo build --release --locked -p sfr --target "$target" >&2
bin="$target_dir/$target/release/sfr"

# SPEC B1.10 Static binaries.
if readelf -lW "$bin" | grep -q INTERP; then die "$bin has an INTERP program header (dynamically linked)"; fi
if readelf -dW "$bin" | grep -q NEEDED; then die "$bin has a NEEDED entry (links a shared library)"; fi
kind="$(file -b "$bin")"
case "$target" in
  x86_64-*) [[ "$kind" == "ELF 64-bit LSB "*"x86-64"* ]] || die "$bin: $kind" ;;
  aarch64-*) [[ "$kind" == "ELF 64-bit LSB "*"ARM aarch64"* ]] || die "$bin: $kind" ;;
  armv7-*)
    [[ "$kind" == "ELF 32-bit LSB executable, ARM"* ]] || die "$bin: $kind"
    [[ "$kind" == *"statically linked"* ]] || die "$bin: $kind" ;;
esac
[[ "$kind" == *"static"* ]] || die "$bin is not statically linked: $kind"
echo "static: $target: $kind" >&2

name="sfr-$version-$target"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
pkg="$stage/$name"
mkdir -p "$pkg/bin" "$pkg/examples/reports" "$pkg/examples/sample"
install -m 0755 "$bin" "$pkg/bin/sfr"
install -m 0644 README.md "$pkg/README.md"
install -m 0644 examples/rules.default.toml examples/rules.extended.toml "$pkg/examples/"
install -m 0644 examples/reports/* "$pkg/examples/reports/"
# The quickstart seals this log (docs: README.md). It is synthetic: written by
# scripts/testdata/make_synthetic_logs.py, not a flight and not a third-party log.
install -m 0644 testdata/synthetic/custom_detection.ulg "$pkg/examples/sample/sample.ulg"
install -m 0644 testdata/baselines/synthetic_custom_detection.params "$pkg/examples/sample/sample.params"
printf '%s\n' \
  'sample.ulg is a synthetic PX4 log of 1,338 bytes. It is not a flight and not a third-party log.' \
  'sample.params is its baseline. Seal it with the default rules (see README.md, Quickstart):' \
  '  bin/sfr seal examples/sample/sample.ulg --rules examples/rules.default.toml \' \
  '    --baseline examples/sample/sample.params --key <your evaluation key> --evaluation-only --out out' \
  > "$pkg/examples/sample/README.txt"
chmod 0644 "$pkg/examples/sample/README.txt"
{
  echo "name: sfr"
  echo "version: $version (evaluation release)"
  echo "target: $target"
  echo "commit: $commit"
  echo "rustc: $(rustc -V)"
  echo "cargo: $(cargo -V)"
  echo "linker: rust-lld"
  echo "file: $kind"
  echo "sha256 bin/sfr: $(sha256sum "$bin" | cut -d' ' -f1)"
} > "$pkg/BUILDINFO"
chmod 0644 "$pkg/BUILDINFO"
tarball="$out/$name.tar.gz"
tar -C "$stage" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner --mode='u=rwX,go=rX,a-s' \
  --format=gnu -cf - "$name" | gzip -n -9 > "$tarball"
echo "$tarball"
