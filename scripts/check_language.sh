#!/usr/bin/env bash
# check_language.sh: enforce the SPEC B1.12 language rules that a script can enforce.
#
#   1. No em-dash (U+2014) in Markdown, the sandbox page, scripts, or Rust sources (the
#      .sfr.md report and CLI tables are generated from Rust string literals).
#   2. If a local, git-ignored file named .forbidden-terms exists (one term per line: target
#      company, aircraft, customer names, internal codenames), none of them appears in any
#      tracked or untracked-but-not-ignored file, case-insensitively. The terms file itself
#      must never be committed, which is why the scan is optional and .gitignore lists it.
#
# Files scanned: tracked plus untracked files that .gitignore does not exclude, so a new doc
# fails locally before it is committed, the same way it would fail in CI.
#
# Usage: scripts/check_language.sh [--self-test]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
em_dash=$'\xe2\x80\x94'

# Files in a git work tree that the rules apply to, NUL separated.
candidate_files() {
  git -C "$1" ls-files -z -co --exclude-standard
}

# Prints em-dash hits (path:line:text) under a work tree; returns 1 if any.
scan_em_dash() {
  local dir="$1" hits
  hits="$(cd "$dir" && candidate_files . \
    | grep -zE '\.(md|rs|html|css|js|sh|toml|ya?ml|txt)$|^scripts/|^site/' \
    | xargs -0 -r grep -n -F -- "$em_dash" 2>/dev/null || true)"
  if [ -n "$hits" ]; then printf '%s\n' "$hits"; return 1; fi
  return 0
}

# Prints forbidden-term hits under a work tree; returns 1 if any. Blank lines and lines
# starting with # in the terms file are ignored (an empty pattern would match everything).
scan_terms() {
  local dir="$1" terms="$2" patterns hits
  patterns="$(mktemp)"
  grep -Ev '^\s*(#|$)' "$terms" > "$patterns" || true
  if [ ! -s "$patterns" ]; then rm -f "$patterns"; return 0; fi
  hits="$(cd "$dir" && candidate_files . \
    | grep -zv -x -F -- "$(basename "$terms")" \
    | xargs -0 -r grep -n -i -F -f "$patterns" 2>/dev/null || true)"
  rm -f "$patterns"
  if [ -n "$hits" ]; then printf '%s\n' "$hits"; return 1; fi
  return 0
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  git -C "$tmp" init -q
  printf 'clean line\n' > "$tmp/clean.md"
  # Untracked files must be scanned too.
  printf 'bad %s line\n' "$em_dash" > "$tmp/new_doc.md"
  printf 'pub const S: &str = "a %s b";\n' "$em_dash" > "$tmp/report.rs"
  printf 'ignored.md\n.forbidden-terms\n' > "$tmp/.gitignore"
  printf 'bad %s but ignored\n' "$em_dash" > "$tmp/ignored.md"

  out="$(scan_em_dash "$tmp" || true)"
  printf '%s\n' "$out" | grep -q '^new_doc.md:1:' || { echo "FAIL: self-test: untracked .md em-dash missed"; exit 1; }
  printf '%s\n' "$out" | grep -q '^report.rs:1:'  || { echo "FAIL: self-test: .rs em-dash missed"; exit 1; }
  printf '%s\n' "$out" | grep -q 'ignored.md'     && { echo "FAIL: self-test: git-ignored file scanned"; exit 1; }

  # Forbidden terms: a trailing blank line must not match everything; the term must be found
  # case-insensitively; the terms file itself is never reported.
  printf 'AcmeTarget\n\n# comment\n' > "$tmp/.forbidden-terms"
  printf 'nothing here\n' > "$tmp/clean2.md"
  scan_terms "$tmp" "$tmp/.forbidden-terms" >/dev/null || { echo "FAIL: self-test: blank line in terms matched clean files"; exit 1; }
  printf 'we fly for acmetarget\n' > "$tmp/leak.md"
  out="$(scan_terms "$tmp" "$tmp/.forbidden-terms" || true)"
  printf '%s\n' "$out" | grep -q '^leak.md:1:' || { echo "FAIL: self-test: forbidden term missed"; exit 1; }
  [ "$(printf '%s\n' "$out" | grep -c .)" -eq 1 ] || { echo "FAIL: self-test: unexpected term hits: $out"; exit 1; }

  echo "PASS: language self-test (em-dash in tracked, untracked, and .rs files; forbidden terms)"
  exit 0
fi

status=0
# A scan over zero files cannot fail, so it is not a gate.
nfiles="$(candidate_files "$root" | tr -cd '\0' | wc -c)"
[ "$nfiles" -gt 0 ] || { echo "FAIL: git listed no files under $root; nothing was scanned"; exit 1; }

if hits="$(scan_em_dash "$root")"; then
  echo "PASS: no em-dash in docs, site, scripts, or Rust sources"
else
  echo "FAIL: em-dash found (SPEC B1.12):"
  printf '%s\n' "$hits"
  status=1
fi

terms="${SFR_FORBIDDEN_TERMS_FILE:-$root/.forbidden-terms}"
if [ -f "$terms" ]; then
  if git -C "$root" ls-files --error-unmatch "$terms" >/dev/null 2>&1; then
    echo "FAIL: $terms is tracked by git; it must stay local"
    status=1
  fi
  if hits="$(scan_terms "$root" "$terms")"; then
    echo "PASS: no forbidden term from $(basename "$terms") in the work tree"
  else
    echo "FAIL: forbidden term found (SPEC B1.12):"
    printf '%s\n' "$hits"
    status=1
  fi
else
  echo "SKIP: no .forbidden-terms file; forbidden-term scan not run (create it locally, never commit it)"
fi

exit $status
