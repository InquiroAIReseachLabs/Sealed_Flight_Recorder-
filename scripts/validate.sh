#!/usr/bin/env bash
# validate.sh: CLAUDEME pre-commit gate. RUN THIS BEFORE EVERY COMMIT.
# Runs the checks of every CI job except those that need their own build or tools: the fuzz job
# (pinned nightly and cargo-fuzz), the release-build verify timing gate, the armv7 job (QEMU),
# and the release jobs (static builds twice from clean, SBOMs, demo image under docker, aarch64
# records under QEMU, benchmark, SHA256SUMS); scripts/build_release.sh, scripts/run_demo.sh and
# docs/RELEASE.md run those by hand. Exits non-zero on any FAIL.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

echo "=== CLAUDEME compliance check: Sealed Flight Record ==="
failures=0
run() {
  local name="$1"; shift
  if "$@"; then echo "PASS: $name"; else echo "FAIL: $name"; failures=$((failures + 1)); fi
}

# 1. Every Inquiro crate forbids unsafe at its root (SPEC B1.10, "No unsafe").
check_forbid_unsafe() {
  local ok=0
  for f in crates/*/src/lib.rs crates/*/src/main.rs; do
    [ -f "$f" ] || continue
    grep -q '^#!\[forbid(unsafe_code)\]' "$f" || { echo "  missing #![forbid(unsafe_code)]: $f"; ok=1; }
  done
  return $ok
}
run "forbid(unsafe_code) in every crate root" check_forbid_unsafe

# 2. Formatting, lints as errors, tests, all --locked (SPEC B1.10, "Code quality").
run "rustfmt --check" cargo fmt --all --check
run "clippy -D warnings" cargo clippy --workspace --all-targets --locked --quiet -- -D warnings
run "cargo test --locked" cargo test --workspace --locked --quiet
run "golden files agree with the independent oracle" scripts/testdata/regenerate.sh compare

# 3. No networking or async-runtime crates; no std::net (SPEC B1.10, "No network").
run "deny-list self-test" scripts/check_deny_list.sh --self-test
run "deny-list check" scripts/check_deny_list.sh

# 4. Language rules (SPEC B1.12).
run "language self-test" scripts/check_language.sh --self-test
run "language check" scripts/check_language.sh
run "README numbers script self-test" scripts/regen_readme_numbers.sh --self-test
run "README numbers match docs/receipts/ci-run.txt" scripts/regen_readme_numbers.sh --check

# 4c. Release scripts (Chunk 5): no private key in the repository, the signing script's own
# test, the benchmark segment manifest, and every script parses.
run "no private key self-test" scripts/check_no_private_keys.sh --self-test
run "no private key in the repository" scripts/check_no_private_keys.sh
run "release signing self-test" scripts/release_sign.sh --self-test
run "benchmark segment manifest matches the golden VTOL flight" python3 -I scripts/benchmark/make_segments.py \
  --check scripts/benchmark/vtol_transition.segments testdata/sitl/v1.17.0/vtol_transition.ulg \
  testdata/sitl/v1.17.0/vtol_transition.ulg
check_script_syntax() {
  local f ok=0
  for f in scripts/*.sh scripts/testdata/*.sh; do bash -n "$f" || { echo "  bash -n: $f"; ok=1; }; done
  sh -n scripts/run_demo.sh || { echo "  sh -n: scripts/run_demo.sh"; ok=1; }
  return $ok
}
run "every script parses" check_script_syntax

# 4b. One crypto stack on every target: sha2, ed25519-dalek, blake3 (SPEC B1.10, "Crypto").
run "one crypto stack on every target" scripts/check_crypto_graph.sh

# 5. Supply chain: licenses, advisories, bans, sources (SPEC B1.10, "Supply chain").
# A missing tool is a failure, never a skip: validate.sh must keep every check it shares with CI.
check_cargo_deny() {
  command -v cargo-deny >/dev/null 2>&1 \
    || { echo "  cargo-deny not installed. Install: cargo install cargo-deny --locked"; return 1; }
  cargo deny --all-features check licenses advisories bans sources
}
run "cargo deny check" check_cargo_deny

echo "=== $failures failure(s) ==="
[ "$failures" -eq 0 ]
