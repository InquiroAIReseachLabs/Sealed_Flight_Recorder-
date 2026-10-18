#!/usr/bin/env bash
# validate.sh: CLAUDEME pre-commit gate. RUN THIS BEFORE EVERY COMMIT.
# Runs the same checks CI runs. Exits non-zero on any FAIL.
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

# 3. No networking or async-runtime crates; no std::net (SPEC B1.10, "No network").
run "deny-list self-test" scripts/check_deny_list.sh --self-test
run "deny-list check" scripts/check_deny_list.sh

# 4. Language rules (SPEC B1.12).
run "language self-test" scripts/check_language.sh --self-test
run "language check" scripts/check_language.sh

# 4b. The shipped graph takes SHA-256 and Ed25519 only from the FIPS module (SPEC B1.10, "Crypto").
check_crypto_graph() {
  local tree
  tree="$(cargo tree -p sfr --locked --prefix none)" || return 1
  if grep -E '^(sha2|ed25519-dalek) ' <<<"$tree"; then
    echo "  sfr's dependency graph contains a SHA-256 or Ed25519 crate outside the FIPS module"
    return 1
  fi
  grep -qE '^aws-lc-fips-sys v' <<<"$tree" || { echo "  aws-lc-fips-sys missing from sfr's graph"; return 1; }
}
run "cargo tree -p sfr: no sha2 or ed25519-dalek" check_crypto_graph

# 5. Supply chain: licenses, advisories, bans, sources (SPEC B1.10, "Supply chain").
# A missing tool is a failure, never a skip: validate.sh must stay a superset of CI.
check_cargo_deny() {
  command -v cargo-deny >/dev/null 2>&1 \
    || { echo "  cargo-deny not installed. Install: cargo install cargo-deny --locked"; return 1; }
  cargo deny --all-features check licenses advisories bans sources
}
run "cargo deny check" check_cargo_deny

echo "=== $failures failure(s) ==="
[ "$failures" -eq 0 ]
