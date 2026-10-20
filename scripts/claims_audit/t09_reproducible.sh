#!/usr/bin/env bash
# T9 Reproducible build: build the static x86_64 binary twice from clean (scripts/check_reproducible.sh) and
# compare the checksums, then once more from a clone in another directory. Scope: one machine, one toolchain
# (the pinned one), one commit. Builds in fresh clones of A_REPO under A_WORK; A_REPO itself is not touched.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
T=x86_64-unknown-linux-musl; W="$A_WORK/t09"; rm -rf "$W"; mkdir -p "$W"
commit="$(git -C "$A_REPO" rev-parse HEAD)"; echo "commit $commit"
echo "machine: $(uname -srm); rustc $(rustc --version); cargo $(cargo --version | cut -d' ' -f2); ld: $(ld --version | head -1)"
git clone -q --no-hardlinks "$A_REPO" "$W/one" && git clone -q --no-hardlinks "$A_REPO" "$W/two" || exit 1
git -C "$W/one" checkout -q "$commit"; git -C "$W/two" checkout -q "$commit"
(cd "$W/one" && rustup target add $T 2>&1 | tail -1)
echo; echo "### scripts/check_reproducible.sh $T: build twice from clean in one directory"
(cd "$W/one" && CARGO_TARGET_DIR="$W/target-one" scripts/check_reproducible.sh $T "$W/out-one") 2>&1 | grep -E '^(reproducible|static)'
a="$(sha256sum "$W/target-one/reproducible/$T/release/sfr" | cut -d' ' -f1)"; ta="$(sha256sum "$W/out-one/"*.tar.gz | cut -d' ' -f1)"
check "the two builds in one directory are byte-identical (binary and tarball)" "$(cd "$W/one" && CARGO_TARGET_DIR="$W/target-one" scripts/check_reproducible.sh $T "$W/out-one" > /dev/null 2>&1; echo $?)"
echo; echo "### the same commit built from a clone in another directory"
mkdir -p "$W/out-two"; (cd "$W/two" && CARGO_TARGET_DIR="$W/target-two" scripts/build_release.sh $T "$W/out-two" > /dev/null 2>&1)
b="$(sha256sum "$W/target-two/$T/release/sfr" | cut -d' ' -f1)"; tb="$(sha256sum "$W/out-two/"*.tar.gz | cut -d' ' -f1)"
echo "binary  $a"; echo "binary  $b"; echo "tarball $ta"; echo "tarball $tb"
check "another directory gives the same binary and tarball" "$([ "$a" = "$b" ] && [ "$ta" = "$tb" ]; echo $?)"
echo; echo "scope: one machine, the pinned toolchain (rust-toolchain.toml), commit $commit. Not shown: another machine, another operating system."
finish
