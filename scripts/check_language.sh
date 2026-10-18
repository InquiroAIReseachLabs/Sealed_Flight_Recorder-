#!/usr/bin/env bash
# check_language.sh: enforce the SPEC B1.12 language rules that a script can enforce.
#
#   1. No em-dash (U+2014) in any Markdown file, the sandbox page, or script output text.
#   2. If a local, git-ignored file named .forbidden-terms exists (one term per line:
#      target company, aircraft, customer names, internal codenames), none of them appears
#      in any tracked file, case-insensitively. The file itself must never be committed,
#      which is why the check is optional and the .gitignore lists it.
#
# Usage: scripts/check_language.sh [--self-test]
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

em_dash=$'\xe2\x80\x94'

# Files subject to the em-dash rule: docs, README, CLAUDEME, the sandbox, and scripts.
text_files() {
  git ls-files -- '*.md' 'site/**' 'scripts/**' 2>/dev/null
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp)"
  printf 'a %s b\n' "$em_dash" > "$tmp"
  if ! grep -q "$em_dash" "$tmp"; then echo "FAIL: self-test: em-dash not detected"; rm -f "$tmp"; exit 1; fi
  rm -f "$tmp"
  echo "PASS: language self-test"
  exit 0
fi

status=0

if hits="$(text_files | xargs -r grep -n "$em_dash" 2>/dev/null)" && [ -n "$hits" ]; then
  echo "FAIL: em-dash found (SPEC B1.12):"
  printf '%s\n' "$hits"
  status=1
else
  echo "PASS: no em-dash in docs, site, or scripts"
fi

terms="${SFR_FORBIDDEN_TERMS_FILE:-.forbidden-terms}"
if [ -f "$terms" ]; then
  if git ls-files --error-unmatch "$terms" >/dev/null 2>&1; then
    echo "FAIL: $terms is tracked by git; it must stay local"
    status=1
  fi
  if hits="$(git ls-files -z | xargs -0 grep -n -i -F -f "$terms" 2>/dev/null)" && [ -n "$hits" ]; then
    echo "FAIL: forbidden term found (SPEC B1.12):"
    printf '%s\n' "$hits"
    status=1
  else
    echo "PASS: no forbidden term from $terms in tracked files"
  fi
else
  echo "SKIP: no $terms file; forbidden-term scan not run (create it locally, never commit it)"
fi

exit $status
