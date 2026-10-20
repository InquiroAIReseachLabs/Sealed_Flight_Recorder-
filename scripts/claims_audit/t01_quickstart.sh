#!/usr/bin/env bash
# T1 Quickstart: README "Path 2: build from source" from a clean machine state, timed. A fresh HOME,
# CARGO_HOME and RUSTUP_HOME (so Rust is installed again), a fresh shallow clone, then the README
# commands in its order. Network needed: the Rust toolchain, crates.io and the clone URL.
#   A_CLONE_URL  what to clone (default: the origin of A_REPO, else A_REPO itself)
#   A_COMMIT_FOR_T1  the commit to build (default: the head of the clone's default branch)
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
url="${A_CLONE_URL:-$(git -C "$A_REPO" remote get-url origin 2> /dev/null || echo "$A_REPO")}"
export HOME="$A_WORK/t01/home" CARGO_HOME="$A_WORK/t01/home/.cargo" RUSTUP_HOME="$A_WORK/t01/home/.rustup"
unset CARGO_TARGET_DIR RUSTFLAGS CARGO_INCREMENTAL
export PATH="$CARGO_HOME/bin:/usr/local/bin:/usr/bin:/bin"
rm -rf "$A_WORK/t01"; mkdir -p "$HOME"
t0=$(date +%s)
step() { echo; echo "### $(( $(date +%s) - t0 )) s elapsed: $*"; }
echo "machine: $(uname -srm); $(nproc) CPUs; $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //'); $(free -g | awk '/Mem/{print $2" GiB"}') memory"
step "README step 0: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none > "$A_WORK/t01/rustup.txt" 2>&1; then
  echo "rustup installed with the README command"
else
  echo "DEVIATION: https://sh.rustup.rs could not be fetched here; the same installer, rustup-init, from static.rust-lang.org"
  curl -sSf -o "$HOME/rustup-init" https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init && chmod +x "$HOME/rustup-init" \
    && "$HOME/rustup-init" -y --profile minimal --default-toolchain none > "$A_WORK/t01/rustup.txt" 2>&1
fi
check "rustup is installed" "$([ -x "$CARGO_HOME/bin/rustup" ]; echo $?)"
step "README step 1: git clone --depth 1"
clone="$A_WORK/t01/clone"; git clone --depth 1 "$url" "$clone" 2>&1 | tail -1; cd "$clone" || exit 1
# The audit's commit, when it is not the head of the default branch the clone took.
if [ -n "${A_COMMIT_FOR_T1:-}" ] && [ "$(git rev-parse HEAD)" != "$A_COMMIT_FOR_T1" ]; then
  echo "DEVIATION: the README clones the default branch; the audited commit $A_COMMIT_FOR_T1 is fetched and checked out"
  git fetch -q --depth 1 origin "$A_COMMIT_FOR_T1" && git checkout -q FETCH_HEAD
fi
echo "commit $(git rev-parse HEAD)"
check "the clone is the audited commit" "$([ -z "${A_COMMIT_FOR_T1:-}" ] || [ "$(git rev-parse HEAD)" = "$A_COMMIT_FOR_T1" ]; echo $?)"
step "README step 2: cargo build --release --locked (rust-toolchain.toml installs the pinned toolchain)"
cargo build --release --locked 2>&1 | grep -v -E '^\s*(Compiling|Downloaded|Downloading)' | tail -6
check "target/release/sfr exists" "$([ -x target/release/sfr ]; echo $?)"
step "README step 3: verify a record sealed earlier, against its log"
out="$(target/release/sfr verify examples/reports/vtol_transition.sfr --pubkey examples/reports/sfr.pub --allow-evaluation-key --ulog testdata/sitl/v1.17.0/vtol_transition.ulg)"; rc=$?
echo "$out" | sed -n 1,3p; echo "exit $rc"
check "Integrity: VERIFIED (record and log), Rule checks: WARN (R4) as README step 3 shows, exit 0" "$([ $rc -eq 0 ] && grep -q '^Integrity: VERIFIED (record and log)' <<< "$out" && grep -qx 'Rule checks: WARN (R4)' <<< "$out"; echo $?)"
step "README step 5: keygen and seal"
mkdir -p try; target/release/sfr keygen --evaluation-only --out try/keys > try/keygen.txt; head -1 try/keygen.txt
target/release/sfr seal testdata/sitl/v1.17.0/vtol_transition.ulg --rules examples/rules.default.toml \
  --baseline testdata/baselines/v1.17.0_vtol_transition.params --key try/keys/sfr.key --evaluation-only --out try/out > try/seal.txt; rc=$?
grep -E '^(R[0-9] |status|record|report)' try/seal.txt
check "seal exit 0 and status WARN, as README step 5 shows" "$([ $rc -eq 0 ] && grep -qx 'status    WARN' try/seal.txt; echo $?)"
step "README step 6: verify the record just sealed"
out="$(target/release/sfr verify try/out/vtol_transition.sfr --pubkey try/keys/sfr.pub --allow-evaluation-key --ulog testdata/sitl/v1.17.0/vtol_transition.ulg)"; rc=$?
echo "$out" | grep -E '^(EVALUATION|Integrity|Rule checks)'
check "Integrity: VERIFIED (record and log)" "$([ $rc -eq 0 ] && grep -q '^Integrity: VERIFIED (record and log)' <<< "$out"; echo $?)"
step "done: cold start (Rust install + clone + build + seal + verify) took $(( $(date +%s) - t0 )) s"
cp target/release/sfr "$A_WORK/sfr-from-t01"
finish
