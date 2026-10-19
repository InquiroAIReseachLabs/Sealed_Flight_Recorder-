#!/usr/bin/env bash
# build_engine.sh: the engine bundle for a web page (docs/SANDBOX.md; SPEC B1.2 crates/sfr-wasm,
# B1.10 Sandbox).
#
# Builds crates/sfr-wasm for wasm32-unknown-unknown in the release profile, with
# SFR_BUILD_COMMIT set to the checkout's commit and the build paths remapped as
# scripts/build_release.sh does, so its records name the same tool build as a CLI built from the
# same commit. Generates the JavaScript glue with wasm-bindgen-cli of exactly the version
# Cargo.lock pins, and writes <out-dir>:
#
#   sfr.js, sfr-worker.js, README.md         crates/sfr-wasm/js/: the API module and its worker
#   pkg/sfr_wasm.js, pkg/sfr_wasm_bg.wasm     the engine and its glue
#   rules/rules.default.toml, rules.extended.toml   examples/
#   samples/<log>.ulg.gz                      the tamper demo's log, gzip -9 -n
#   samples/<baseline>.params                 its baseline
#   samples/<log>.provenance.md, NOTICE.md, TESTDATA.md   its provenance and license notices
#   samples/samples.json                      its name, path, size, SHA-256 and compressed size
#   BUILDINFO                                 version, source commit, toolchain, wasm-bindgen
#   SHA256SUMS                                the SHA-256 of every other file
#
# wasm-bindgen is $WASM_BINDGEN, else wasm-bindgen on PATH. Prints a one-line summary.
#
# Usage: scripts/build_engine.sh <out-dir>
set -euo pipefail
caller="$PWD"
abs() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$caller/$1" ;; esac; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
root="$(pwd -P)"

die() { echo "build_engine.sh: $*" >&2; exit 1; }
[ $# -eq 1 ] || die "usage: $0 <out-dir>"
out="$(abs "$1")"
wasm_bindgen="${WASM_BINDGEN:-wasm-bindgen}"
for tool in cargo rustc git gzip sha256sum stat sed awk find sort "$wasm_bindgen"; do
  command -v "$tool" > /dev/null || die "$tool is required"
done
want="$(awk '/^name = "wasm-bindgen"$/ { getline; sub(/^version = "/, ""); sub(/"$/, ""); print; exit }' Cargo.lock)"
[ -n "$want" ] || die "Cargo.lock has no wasm-bindgen"
have="$("$wasm_bindgen" --version | awk '{ print $2 }')"
[ "$have" = "$want" ] || die "wasm-bindgen-cli $have does not match the wasm-bindgen $want in Cargo.lock"

version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)"
commit="${SFR_BUILD_COMMIT:-$(git rev-parse HEAD)}"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
mkdir -p "$target_dir"
target_dir="$(cd "$target_dir" && pwd -P)"
cargo_home="$(cd "${CARGO_HOME:-$HOME/.cargo}" && pwd -P)"
flags=(
  "--remap-path-prefix=$root=/build/sfr"
  "--remap-path-prefix=$cargo_home=/build/cargo"
  "--remap-path-prefix=$target_dir=/build/target"
)
CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\x1f'; printf '%s' "${flags[*]}")"
export CARGO_ENCODED_RUSTFLAGS SFR_BUILD_COMMIT="$commit" CARGO_TARGET_DIR="$target_dir"
# rust-toolchain.toml lists no cross targets, so this one is added on purpose.
if command -v rustup > /dev/null && ! rustup target list --installed | grep -q -x -F wasm32-unknown-unknown; then
  echo "build_engine.sh: the target wasm32-unknown-unknown is not installed: run  rustup target add wasm32-unknown-unknown" >&2
  exit 1
fi
cargo build --release --locked -p sfr-wasm --target wasm32-unknown-unknown >&2

rm -rf "$out"
mkdir -p "$out/pkg" "$out/rules" "$out/samples"
"$wasm_bindgen" --target web --no-typescript --out-dir "$out/pkg" \
  "$target_dir/wasm32-unknown-unknown/release/sfr_wasm.wasm"
cp crates/sfr-wasm/js/sfr.js crates/sfr-wasm/js/sfr-worker.js crates/sfr-wasm/js/README.md "$out/"
cp examples/rules.default.toml examples/rules.extended.toml "$out/rules/"

# The tamper demo's sample: the smallest golden log that shows both changes (a COMMAND event
# in the record, a float parameter at log start in the log), with every rule passing.
log=testdata/sitl/v1.17.0/mc_flight_1.ulg
baseline=testdata/baselines/v1.17.0_mc_flight_1.params
parameter=MPC_XY_VEL_MAX
name="$(basename "$log")" provenance="$(basename "${log%.ulg}").provenance.md"
gzip -9 -n -c "$log" > "$out/samples/$name.gz"
cp "$baseline" "$out/samples/"
cp "${log%.ulg}.provenance.md" "$out/samples/$provenance"
cp testdata/README.md "$out/samples/TESTDATA.md"
size="$(stat -c %s "$log")" gz_size="$(stat -c %s "$out/samples/$name.gz")" sha="$(sha256sum "$log" | cut -d' ' -f1)"
cat > "$out/samples/NOTICE.md" <<NOTICE
# Sample log notices

- \`$name\` (in the Sealed Flight Record repository: \`$log\`, SHA-256 \`$sha\`, $size bytes) and its compressed copy \`$name.gz\`: generated for the Sealed Flight Record project in PX4 v1.17.0 SITL with the built-in SIH simulator; not a third-party log. How it was made: \`$provenance\`.
- \`$(basename "$baseline")\`: the baseline it is sealed against, written for the project (\`$baseline\`).
- \`TESTDATA.md\`: the license and provenance of every golden log in the repository (\`testdata/README.md\`).
NOTICE
cat > "$out/samples/samples.json" <<JSON
{"sample": {"log": "$name", "path": "$log", "size": $size, "sha256": "$sha", "gz": "$name.gz", "gz_size": $gz_size, "baseline": "$(basename "$baseline")", "baseline_path": "$baseline", "provenance": "$provenance", "parameter": "$parameter"}}
JSON

{
  echo "name sfr-engine"
  echo "version $version"
  echo "commit $commit"
  echo "rustc $(rustc --version)"
  echo "wasm-bindgen $have"
  echo "sample $log $sha"
} > "$out/BUILDINFO"
(cd "$out" && find . -type f ! -name SHA256SUMS -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum > SHA256SUMS)
echo "engine bundle: $out ($(find "$out" -type f | wc -l) files), version $version, commit $commit; sample $name $size bytes, gzip $gz_size bytes" >&2
