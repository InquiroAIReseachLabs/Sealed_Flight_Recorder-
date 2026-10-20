#!/usr/bin/env bash
# validate.sh: the pre-commit gate. RUN THIS BEFORE EVERY COMMIT.
# Runs the checks of every CI job except those that need their own build or tools: the fuzz job
# (pinned nightly and cargo-fuzz), the release-build verify timing gate, the armv7 job (QEMU),
# the release jobs (static builds twice from clean, SBOMs, demo image under docker, aarch64 and
# armv7 records under QEMU, benchmark, SHA256SUMS), the release and post-release workflows
# themselves (they run on a tag, after a release, and by hand), and the sandbox browser gate (wasm-bindgen-cli
# and three browsers), and the hardware key custody job (SoftHSM v2 and swtpm: scripts/hardware_keys.sh);
# scripts/build_release.sh, scripts/run_demo.sh, scripts/build_site.sh with
# tests/browser/sandbox.test.mjs, and docs/RELEASE.md run those by hand. Exits non-zero on any FAIL.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

echo "=== pre-commit checks: Sealed Flight Record ==="
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
# rust-toolchain.toml lists no cross targets; the wasm32 target is added here, as the sandbox CI job does.
run "wasm32 target installed" rustup target add wasm32-unknown-unknown
run "clippy -D warnings, sfr-wasm for wasm32 (the page's bindings)" \
  cargo clippy -p sfr-wasm --target wasm32-unknown-unknown --locked --quiet -- -D warnings
run "cargo test --locked" cargo test --workspace --locked --quiet
# fuzz/ is outside the workspace, so the commands above never compile its targets; the fuzz CI job
# does, on nightly. A type check on the pinned toolchain catches a changed engine API at once.
run "fuzz targets type-check (fuzz/ is not in the workspace)" \
  cargo check --manifest-path fuzz/Cargo.toml --locked --bins --quiet
run "golden files agree with the independent oracle" scripts/testdata/regenerate.sh compare
run "reference verifier vectors (tools/reference_verifier)" python3 -I tools/reference_verifier/sfr_ref_verify.py --self-test
run "reference verifier vectors are what their generator writes" python3 -I tools/reference_verifier/make_vectors.py --check
run "test certificates match their script (testdata/pki)" scripts/testdata/make_test_pki.sh --check

# 3. No networking or async-runtime crates; no std::net (SPEC B1.10, "No network").
run "deny-list self-test" scripts/check_deny_list.sh --self-test
run "deny-list check" scripts/check_deny_list.sh

# 4. Language rules (SPEC B1.12).
run "language self-test" scripts/check_language.sh --self-test
run "language check" scripts/check_language.sh
# The Unicode format characters the report and the terminal output show instead of acting on.
run "format-character table self-test" python3 -I scripts/check_format_characters.py --self-test
run "format-character table matches the Unicode database" python3 -I scripts/check_format_characters.py
run "README numbers script self-test" scripts/regen_readme_numbers.sh --self-test
run "README numbers match docs/receipts/ci-run.txt" scripts/regen_readme_numbers.sh --check
# Docs tests (the docs CI job): every doc command runs (b3sum and openssl 3 must be installed),
# outputs match, every number has a source, every relative link resolves.
run "docs tests self-test" python3 -I scripts/check_docs.py --self-test
run "docs tests (scripts/check_docs.py)" python3 -I scripts/check_docs.py

# 4c. Release scripts: no private key in the repository, the signing script's own
# test, the benchmark segment manifest, and every script parses.
run "no private key self-test" scripts/check_no_private_keys.sh --self-test
run "no private key in the repository" scripts/check_no_private_keys.sh
run "no email address self-test" scripts/check_no_emails.sh --self-test
run "no email address in the repository" scripts/check_no_emails.sh
run "engine bundle check self-test" scripts/check_engine_bundle.sh --self-test
run "release signing self-test" scripts/release_sign.sh --self-test
# The release workflows: their rules, the hygiene scan of
# every release file, and the whole offline signing flow with eight attacks on it. The hygiene
# scan needs exiftool (apt-get install libimage-exiftool-perl); a missing tool is a failure.
run "workflow rules self-test" scripts/check_workflows.sh --self-test
run "workflow rules (pinned actions, no secret, no signing, only the draft job writes)" scripts/check_workflows.sh
run "release hygiene self-test" scripts/check_release_hygiene.sh --self-test
run "offline signing flow and its attacks" scripts/check_release_flow.sh
run "benchmark segment manifest matches the golden VTOL flight" python3 -I scripts/benchmark/make_segments.py \
  --check scripts/benchmark/vtol_transition.segments testdata/sitl/v1.17.0/vtol_transition.ulg \
  testdata/sitl/v1.17.0/vtol_transition.ulg
check_script_syntax() {
  local f ok=0
  for f in scripts/*.sh scripts/testdata/*.sh scripts/claims_audit/*.sh; do bash -n "$f" || { echo "  bash -n: $f"; ok=1; }; done
  sh -n scripts/run_demo.sh || { echo "  sh -n: scripts/run_demo.sh"; ok=1; }
  python3 -I -c 'import ast, sys
for f in sys.argv[1:]:
    ast.parse(open(f).read(), f)' scripts/claims_audit/*.py tools/reference_verifier/*.py || { echo "  python parse: scripts/claims_audit"; ok=1; }
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
