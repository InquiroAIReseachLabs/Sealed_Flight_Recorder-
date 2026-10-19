#!/usr/bin/env bash
# build_site.sh: the sandbox page, ready to serve (SPEC B1.2 site/, B1.10 Sandbox;
# docs/SANDBOX.md).
#
# Builds crates/sfr-wasm for wasm32-unknown-unknown in the release profile, with
# SFR_BUILD_COMMIT set to the checkout's commit and the build paths remapped as
# scripts/build_release.sh does, so its records name the same tool build as a CLI built from the
# same commit. Generates the JavaScript glue with wasm-bindgen-cli of exactly the version
# Cargo.lock pins, and writes <out-dir>:
#
#   index.html app.js worker.js markdown.js style.css _headers   site/
#   pkg/sfr_wasm.js pkg/sfr_wasm_bg.wasm                           the engine
#   rules/rules.default.toml rules/rules.extended.toml             examples/
#   samples/<log>.ulg.gz                                           the two golden logs the tamper demo uses
#                                                                  (scripts/run_demo.sh), gzip -9 -n
#   samples/<log>.provenance.md, samples/<baseline>.params         their notices and baselines
#   samples/samples.json                                           names, sizes and SHA-256 of the logs
#
# The largest file is under 25 MiB, the per-file limit of Cloudflare Pages. wasm-bindgen is
# $WASM_BINDGEN, else wasm-bindgen on PATH.
#
# Usage: scripts/build_site.sh <out-dir>
set -euo pipefail
caller="$PWD"
abs() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$caller/$1" ;; esac; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
root="$(pwd -P)"

die() { echo "build_site.sh: $*" >&2; exit 1; }
[ $# -eq 1 ] || die "usage: $0 <out-dir>"
out="$(abs "$1")"
wasm_bindgen="${WASM_BINDGEN:-wasm-bindgen}"
for tool in cargo git gzip sha256sum stat sed awk "$wasm_bindgen"; do
  command -v "$tool" > /dev/null || die "$tool is required"
done
want="$(awk '/^name = "wasm-bindgen"$/ { getline; sub(/^version = "/, ""); sub(/"$/, ""); print; exit }' Cargo.lock)"
[ -n "$want" ] || die "Cargo.lock has no wasm-bindgen"
have="$("$wasm_bindgen" --version | awk '{ print $2 }')"
[ "$have" = "$want" ] || die "wasm-bindgen-cli $have does not match the wasm-bindgen $want in Cargo.lock"

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
cargo build --release --locked -p sfr-wasm --target wasm32-unknown-unknown >&2

rm -rf "$out"
mkdir -p "$out/pkg" "$out/rules" "$out/samples"
"$wasm_bindgen" --target web --no-typescript --out-dir "$out/pkg" \
  "$target_dir/wasm32-unknown-unknown/release/sfr_wasm.wasm"
cp site/index.html site/app.js site/worker.js site/markdown.js site/style.css site/_headers "$out/"
cp examples/rules.default.toml examples/rules.extended.toml "$out/rules/"

# The tamper demo's logs and baselines, as scripts/run_demo.sh names them.
samples=(
  "vtol testdata/sitl/v1.17.0/vtol_transition.ulg testdata/baselines/v1.17.0_vtol_transition.params"
  "tailsitter testdata/sitl/v1.17.0/gz_quadtailsitter_transition.ulg testdata/baselines/v1.17.0_gz_quadtailsitter_transition.params"
)
{
  echo '{"samples": ['
  sep=""
  for s in "${samples[@]}"; do
    read -r id log baseline <<< "$s"
    name="$(basename "$log")"
    gzip -9 -n -c "$log" > "$out/samples/$name.gz"
    cp "$baseline" "$out/samples/"
    cp "${log%.ulg}.provenance.md" "$out/samples/"
    printf '%s  {"id": "%s", "log": "%s", "path": "%s", "gz": "%s.gz", "size": %s, "sha256": "%s", "baseline": "%s", "baseline_path": "%s"}\n' \
      "$sep" "$id" "$name" "$log" "$name" "$(stat -c %s "$log")" "$(sha256sum "$log" | cut -d' ' -f1)" \
      "$(basename "$baseline")" "$baseline"
    sep=","
  done
  echo ']}'
} > "$out/samples/samples.json"

largest="$(find "$out" -type f -printf '%s %p\n' | sort -n | tail -1)"
[ "${largest%% *}" -lt $((25 * 1024 * 1024)) ] || die "$largest is over the 25 MiB per-file limit of Cloudflare Pages"
echo "site: $out ($(find "$out" -type f | wc -l) files, largest $(( ${largest%% *} / 1024 )) KiB: ${largest#* }), sfr build $commit" >&2
