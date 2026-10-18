#!/usr/bin/env bash
# check_language.sh: enforce the SPEC B1.12 language rules that a script can enforce.
#
#   1. No em-dash (U+2014) in Markdown, the sandbox page, scripts, or Rust sources (the
#      .sfr.md report and CLI tables are generated from Rust string literals).
#   2. No weapon or strike terminology in any text file (Change Order 01 language gate). This
#      script is the one file exempt, because it holds the list.
#   3. If a local, git-ignored file named .forbidden-terms exists (one term per line: target
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

# Compliance phrasing that SPEC B1.12 forbids anywhere in docs or output text (case-insensitive).
# SPEC.md and CLAUDEME.md are exempt: they state the rule and must quote the phrases. So is
# docs/DIAGNOSTIC.md, the internal research record, which quotes certificates and security
# policies. A claim pairs a regime (FIPS, IL4, IL5, 800-171, CMMC, FedRAMP, DoDD) with a status
# word (compliant, certified, accredited, authorized, validated), in either order, within one
# clause. No FIPS, validated, or compliant claim is permitted anywhere (founder ruling, Change
# Order 01), so no sentence is exempt.
REGIME='(FIPS|IL ?[45]|800-171|CMMC|FedRAMP|DoDD)'
STATUS='(compliant|compliance|certified|accredited|authori[sz]ed|validated)'
COMPLIANCE_RE="${REGIME}[^.;:]{0,40}\\b${STATUS}\\b|\\b${STATUS}[^.;:]{0,25}${REGIME}"

# Prints forbidden compliance phrasing under a work tree; returns 1 if any.
scan_compliance() {
  local dir="$1" hits
  hits="$(cd "$dir" && candidate_files . \
    | grep -zE '\.(md|rs|html|js|txt)$' | grep -zvE '^(docs/SPEC\.md|docs/DIAGNOSTIC\.md|CLAUDEME\.md)$' \
    | xargs -0 -r grep -n -i -E -- "$COMPLIANCE_RE" 2>/dev/null || true)"
  if [ -n "$hits" ]; then printf '%s\n' "$hits"; return 1; fi
  return 0
}

# Weapon and strike terminology (case-insensitive, whole words), banned in every text file of the
# repository: code, tests, examples, docs, and test data. Generic words that PX4 uses for other
# meanings ("target", "payload", "release") are not on the list.
WEAPON_RE='\b(weapon(s|ry|i[sz]e[sd]?|i[sz]ation)?|(am)?munitions?|warheads?|ordnance|missiles?|bomb(s|ed|ing|er|ers)?|kill[ -]?chains?|lethal(ity)?|air ?strikes?|strik(e|es|ing)|struck|combat(ants?)?|battlefields?|explosives?|grenades?|artillery|kamikazes?)\b'

# Prints weapon or strike terminology under a work tree; returns 1 if any.
scan_weapon() {
  local dir="$1" hits
  hits="$(cd "$dir" && candidate_files . \
    | grep -zvE '\.(ulg|sfr|png|jpe?g|gif|ico|wasm|pdf)$' | grep -zv -x -F -- 'scripts/check_language.sh' \
    | xargs -0 -r grep -n -i -I -E -- "$WEAPON_RE" 2>/dev/null || true)"
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

  # Compliance phrasing: caught in a doc, allowed in SPEC.md where the rule quotes it.
  mkdir -p "$tmp/docs"
  printf 'This tool is FIPS-compliant.\nThe binary is IL4/IL5 compliant.\nIt is compliant with NIST SP 800-171.\nsfr is FedRAMP authorized.\n' > "$tmp/docs/README.md"
  printf 'Never say FIPS compliant.\n' > "$tmp/docs/SPEC.md"
  printf 'sfr uses FIPS 140-3 validated cryptography to support integration into IL4/IL5 and NIST SP 800-171 environments.\nIts signatures are FIPS-validated.\n' > "$tmp/docs/FORMERLY_APPROVED.md"
  printf 'pub const BANNER: &str = "IL5 certified flight recorder";\n' > "$tmp/cli.rs"
  out="$(scan_compliance "$tmp" || true)"
  for n in 1 2 3 4; do
    printf '%s\n' "$out" | grep -q "^docs/README.md:$n:" || { echo "FAIL: self-test: compliance claim on README line $n missed"; exit 1; }
  done
  printf '%s\n' "$out" | grep -q '^cli.rs:1:' || { echo "FAIL: self-test: compliance claim in Rust output text missed"; exit 1; }
  printf '%s\n' "$out" | grep -q 'docs/SPEC.md' && { echo "FAIL: self-test: SPEC.md should be exempt"; exit 1; }
  for n in 1 2; do
    printf '%s\n' "$out" | grep -q "^docs/FORMERLY_APPROVED.md:$n:" || { echo "FAIL: self-test: validated claim on line $n missed"; exit 1; }
  done

  # Weapon and strike terms: caught in a doc, a test, and a rules example, inflected and
  # hyphenated forms too; words that only contain a term ("strikethrough", "combative") and
  # PX4's generic words are not.
  printf 'A loitering munition test.\n' > "$tmp/docs/USES.md"
  printf '// simulate a strike\n' > "$tmp/flight_test.rs"
  printf '# combat profile\n' > "$tmp/rules.example.toml"
  for w in ammunition bombed Striking kill-chain combatant explosives grenade artillery; do
    printf 'the %s case\n' "$w" > "$tmp/term_$w.md"
  done
  printf 'strikethrough text, a combative tone, target_system, payload release\n' > "$tmp/fine.md"
  out="$(scan_weapon "$tmp" || true)"
  printf '%s\n' "$out" | grep -q '^docs/USES.md:1:' || { echo "FAIL: self-test: munition missed"; exit 1; }
  printf '%s\n' "$out" | grep -q '^flight_test.rs:1:' || { echo "FAIL: self-test: strike missed"; exit 1; }
  printf '%s\n' "$out" | grep -q '^rules.example.toml:1:' || { echo "FAIL: self-test: combat missed"; exit 1; }
  for w in ammunition bombed Striking kill-chain combatant explosives grenade artillery; do
    printf '%s\n' "$out" | grep -q "^term_$w.md:1:" || { echo "FAIL: self-test: $w missed"; exit 1; }
  done
  printf '%s\n' "$out" | grep -q '^fine.md' && { echo "FAIL: self-test: false positive on fine.md"; exit 1; }

  echo "PASS: language self-test (em-dash in tracked, untracked, and .rs files; forbidden terms; compliance phrasing; weapon and strike terms)"
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

if hits="$(scan_compliance "$root")"; then
  echo "PASS: no compliance claims (SPEC B1.12)"
else
  echo "FAIL: compliance claim found (SPEC B1.12):"
  printf '%s\n' "$hits"
  status=1
fi

if hits="$(scan_weapon "$root")"; then
  echo "PASS: no weapon or strike terminology"
else
  echo "FAIL: weapon or strike terminology found (Change Order 01):"
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
