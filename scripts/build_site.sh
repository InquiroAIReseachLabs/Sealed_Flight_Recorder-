#!/usr/bin/env bash
# build_site.sh: the sandbox test harness page around the engine bundle (docs/SANDBOX.md). The
# harness is a plain page for CI's browser gate (tests/browser/sandbox.test.mjs); the production
# page lives elsewhere and uses the engine bundle alone.
#
# Writes <out-dir>/index.html, app.js, markdown.js, style.css (site/) and <out-dir>/engine/
# (scripts/build_engine.sh).
#
# Usage: scripts/build_site.sh <out-dir>
set -euo pipefail
caller="$PWD"
abs() { case "$1" in /*) printf '%s\n' "$1" ;; *) printf '%s\n' "$caller/$1" ;; esac; }
cd "$(dirname "${BASH_SOURCE[0]}")/.."
[ $# -eq 1 ] || { echo "usage: $0 <out-dir>" >&2; exit 1; }
out="$(abs "$1")"
rm -rf "$out"
scripts/build_engine.sh "$out/engine"
cp site/index.html site/app.js site/markdown.js site/style.css "$out/"
echo "site: $out" >&2
