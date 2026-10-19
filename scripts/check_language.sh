#!/usr/bin/env bash
# check_language.sh: enforce the SPEC B1.12 language rules that a script can enforce.
#
#   1. No em-dash (U+2014) in Markdown, the sandbox page, scripts, or Rust sources (the
#      .sfr.md report and CLI tables are generated from Rust string literals).
#   2. No weapon or strike terminology in any text file (language gate). This
#      script is the one file exempt, because it holds the list.
#   3. If a local, git-ignored file named .forbidden-terms exists (one term per line: target
#      company, aircraft, customer names, internal codenames), none of them appears in any
#      tracked or untracked-but-not-ignored file, case-insensitively. The terms file itself
#      must never be committed, which is why the scan is optional and .gitignore lists it. CI
#      writes it from the repository secret SFR_FORBIDDEN_TERMS when that secret is set.
#   4. No text file names an internal codename or work-order label ("Chunk <n>", a change
#      order, its short form, the name of the internal standard); record files (.sfr) and this
#      script are exempt. Public docs (every Markdown file except docs/SPEC.md, which states the
#      rules below and must quote them) hold no compliance,
#      certification, FIPS or "validated" wording at all, claim or not; say "production" only
#      inside double quotes or inline code, or as "not production" / "not for production"; and
#      name no company by its legal form (Inc, LLC, Ltd, GmbH, Corp, Corporation, PLC, Pty).
#   5. No public file says "counsel", "lawyer", "to be supplied", "placeholder", "TBD" or "coming
#      soon": the repository states what exists, not what is promised. An HTML `placeholder=`
#      attribute is markup, not wording. This script is exempt, because it holds the list.
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
# docs/SPEC.md is exempt: it states the rule and must quote the phrases. A claim pairs a regime (FIPS, IL4, IL5, 800-171, CMMC, FedRAMP, DoDD) with a status
# word (compliant, certified, accredited, authorized, validated), in either order, within one
# clause. No FIPS, validated, or compliant claim is permitted anywhere, so no sentence is
# exempt.
REGIME='(FIPS|IL ?[45]|800-171|CMMC|FedRAMP|DoDD)'
STATUS='(compliant|compliance|certified|accredited|authori[sz]ed|validated)'
COMPLIANCE_RE="${REGIME}[^.;:]{0,40}\\b${STATUS}\\b|\\b${STATUS}[^.;:]{0,25}${REGIME}"

# Prints forbidden compliance phrasing under a work tree; returns 1 if any.
scan_compliance() {
  local dir="$1" hits
  hits="$(cd "$dir" && candidate_files . \
    | grep -zE '\.(md|rs|html|js|txt)$' | grep -zvE '^docs/SPEC\.md$' \
    | xargs -0 -r grep -n -i -E -- "$COMPLIANCE_RE" 2>/dev/null || true)"
  if [ -n "$hits" ]; then printf '%s\n' "$hits"; return 1; fi
  return 0
}

# Weapon and strike terminology (case-insensitive, whole words), banned in every text file of the
# repository: code, tests, examples, docs, and test data. Generic words that PX4 uses for other
# meanings ("target", "payload", "release") are not on the list.
WEAPON_RE='\b(weapon(s|ry|i[sz](e[sd]?|ing)|i[sz]ation)?|(am)?munitions?|warheads?|ordnance|missiles?|bomb(s|ed|ings?|ers?)?|kill[ -]?chains?|lethal(ity)?|air ?strikes?|strik(e|es|ing)|struck|combat(s|ed|ing|ants?)?|battlefields?|explosives?|grenades?|artillery|kamikazes?)\b'

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

# Public docs under a work tree, NUL separated: Markdown, except docs/SPEC.md.
public_docs() {
  candidate_files "$1" | grep -z '\.md$' | grep -zvE '^docs/SPEC\.md$' || true
}

# Prints hits of an extended regex in public docs, after a sed program blanks what is allowed;
# returns 1 if any. scan_public <dir> <regex> [<sed program>]
scan_public() {
  local dir="$1" re="$2" allow="${3:-}" hits
  hits="$(cd "$dir" && public_docs . | while IFS= read -r -d '' f; do
      sed -E -e "$allow" -- "$f" | grep -n -i -E -- "$re" | sed "s|^|$f:|" || true
    done)"
  if [ -n "$hits" ]; then printf '%s\n' "$hits"; return 1; fi
  return 0
}

CODENAME_RE='claudeme|\bchunk [0-9]+\b|change[ _-]*orders?\b|\bco ?01\b'
CLAIM_RE='\b(compliant|compliance|certified|certification|validated|fips)\b'
# "production" is allowed only inside double quotes or inline code, or as "not (for) production".
PRODUCTION_RE='\bproduction\b'
PRODUCTION_ALLOW='s/"[^"]*"//g; s/`[^`]*`//g; s/\bnot (for )?production\b//gI'
COMPANY_RE='\b(Inc|LLC|Ltd|GmbH|Corp|Corporation|PLC|Pty)\b'

# Promise and pending-work wording, banned in every text file (rule 5).
PENDING_RE='\b(counsel|lawyers?|to be supplied|placeholders?|tbd|coming soon)\b'
scan_pending() {
  local dir="$1" hits
  hits="$(cd "$dir" && candidate_files . \
    | grep -zvE '\.(ulg|png|jpe?g|gif|ico|wasm|pdf|gz)$' | grep -zv -x -F -- 'scripts/check_language.sh' \
    | xargs -0 -r grep -n -i -I -E -- "$PENDING_RE" 2>/dev/null | grep -v -E ':[0-9]+:.*<[^>]* placeholder="' || true)"
  if [ -n "$hits" ]; then printf '%s\n' "$hits"; return 1; fi
  return 0
}

# Codenames, in every text file (rule 4): record files and this script are exempt.
scan_codenames() {
  local dir="$1" hits
  hits="$(cd "$dir" && candidate_files . \
    | grep -zvE '\.(ulg|sfr|png|jpe?g|gif|ico|wasm|pdf|gz)$' | grep -zv -x -F -- 'scripts/check_language.sh' \
    | xargs -0 -r grep -n -i -I -E -- "$CODENAME_RE" 2>/dev/null || true)"
  if [ -n "$hits" ]; then printf '%s
' "$hits"; return 1; fi
  return 0
}
scan_claims() { scan_public "$1" "$CLAIM_RE"; }
scan_production() { scan_public "$1" "$PRODUCTION_RE" "$PRODUCTION_ALLOW"; }
# Case matters for legal forms ("inc" and "corp" are ordinary in code words), so grep -i is undone.
scan_companies() {
  local dir="$1" hits
  hits="$(cd "$dir" && public_docs . | xargs -0 -r grep -n -E -- "$COMPANY_RE" 2>/dev/null || true)"
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
  for w in ammunition bombed bombings Striking struck kill-chain combatant combats combating weaponizing explosives grenade artillery kamikaze; do
    printf 'the %s case\n' "$w" > "$tmp/term_$w.md"
  done
  printf 'strikethrough text, a combative tone, target_system, payload release\n' > "$tmp/fine.md"
  out="$(scan_weapon "$tmp" || true)"
  printf '%s\n' "$out" | grep -q '^docs/USES.md:1:' || { echo "FAIL: self-test: munition missed"; exit 1; }
  printf '%s\n' "$out" | grep -q '^flight_test.rs:1:' || { echo "FAIL: self-test: strike missed"; exit 1; }
  printf '%s\n' "$out" | grep -q '^rules.example.toml:1:' || { echo "FAIL: self-test: combat missed"; exit 1; }
  for w in ammunition bombed bombings Striking struck kill-chain combatant combats combating weaponizing explosives grenade artillery kamikaze; do
    printf '%s\n' "$out" | grep -q "^term_$w.md:1:" || { echo "FAIL: self-test: $w missed"; exit 1; }
  done
  printf '%s\n' "$out" | grep -q '^fine.md' && { echo "FAIL: self-test: false positive on fine.md"; exit 1; }

  # Codenames in any text file; claim words, "production", legal forms in public docs; SPEC.md is
  # exempt from the public-doc rules, record files from the codename rule.
  rm -f "$tmp"/*.md "$tmp"/docs/*.md
  printf 'Built to the CLAUDEME standard.\nDone in Chunk 7.\nPer change order 2.\nThe CO01 flights.\n' > "$tmp/docs/CODE.md"
  printf '// Change-Order 01 gate\n' > "$tmp/gate.rs"
  printf '{"text":"Chunk 7"}\n' > "$tmp/old.sfr"
  printf 'Uses validated crypto.\nNo FIPS claim.\nSee the compliance notes.\nIt is certified.\n' > "$tmp/docs/CLAIM.md"
  printf 'Ready for production.\nThe production page.\n' > "$tmp/docs/PROD.md"
  printf 'This is not production code.\nIt is not for production use.\nThe flag is "production".\nSet `mode = production`.\n' > "$tmp/docs/PROD_OK.md"
  printf 'Built for Example Widgets Inc.\nA GmbH partner.\n' > "$tmp/docs/CO.md"
  printf 'chunked uploads; an increment; corpus files; incoming/\n' > "$tmp/docs/FINE.md"
  printf 'FIPS validated, production, Acme Inc.\n' > "$tmp/docs/SPEC.md"
  out="$(scan_codenames "$tmp" || true)"
  for n in 1 2 3 4; do printf '%s\n' "$out" | grep -q "^docs/CODE.md:$n:" || { echo "FAIL: self-test: codename on line $n missed"; exit 1; }; done
  printf '%s\n' "$out" | grep -q '^gate.rs:1:' || { echo "FAIL: self-test: codename in a source file missed"; exit 1; }
  printf '%s\n' "$out" | grep -q 'old.sfr' && { echo "FAIL: self-test: a record file was scanned for codenames"; exit 1; }
  out="$(scan_claims "$tmp" || true)"
  for n in 1 2 3 4; do printf '%s\n' "$out" | grep -q "^docs/CLAIM.md:$n:" || { echo "FAIL: self-test: claim word on line $n missed"; exit 1; }; done
  out="$(scan_production "$tmp" || true)"
  for n in 1 2; do printf '%s\n' "$out" | grep -q "^docs/PROD.md:$n:" || { echo "FAIL: self-test: production on line $n missed"; exit 1; }; done
  printf '%s\n' "$out" | grep -q 'PROD_OK' && { echo "FAIL: self-test: allowed production wording flagged: $out"; exit 1; }
  out="$(scan_companies "$tmp" || true)"
  for n in 1 2; do printf '%s\n' "$out" | grep -q "^docs/CO.md:$n:" || { echo "FAIL: self-test: legal form on line $n missed"; exit 1; }; done
  printf 'License terms will come from counsel.\nThresholds are placeholders.\nDetails TBD, coming soon.\nTo be supplied later.\n' > "$tmp/docs/PEND.md"
  printf '<input id="t" placeholder="the current time">\n' > "$tmp/docs/form.html"
  printf 'pub const X: &str = "a lawyer";\n' > "$tmp/pend.rs"
  out="$(scan_pending "$tmp" || true)"
  for n in 1 2 3 4; do printf '%s\n' "$out" | grep -q "^docs/PEND.md:$n:" || { echo "FAIL: self-test: pending wording on line $n missed"; exit 1; }; done
  printf '%s\n' "$out" | grep -q '^pend.rs:1:' || { echo "FAIL: self-test: pending wording in a source file missed"; exit 1; }
  printf '%s\n' "$out" | grep -q 'form.html' && { echo "FAIL: self-test: an HTML placeholder attribute was flagged"; exit 1; }
  for scan in scan_codenames scan_claims scan_production scan_companies; do
    out="$($scan "$tmp" || true)"
    printf '%s\n' "$out" | grep -q -E 'FINE.md|SPEC.md' && { echo "FAIL: self-test: $scan flagged an allowed or exempt file: $out"; exit 1; }
  done

  echo "PASS: language self-test (em-dash in tracked, untracked, and .rs files; forbidden terms; compliance phrasing; weapon and strike terms; public-doc codenames, claim words, production, legal forms; pending wording)"
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
  echo "FAIL: weapon or strike terminology found:"
  printf '%s\n' "$hits"
  status=1
fi

for rule in "codenames:no internal codename or change-order wording in any file" "claims:no compliance, certification, FIPS or validated wording in a public doc" \
  "production:production only quoted or as not production in a public doc" "companies:no company legal form in a public doc" \
  "pending:no counsel, lawyer, to be supplied, placeholder, TBD or coming soon wording in any file"; do
  name="${rule%%:*}" what="${rule#*:}"
  if hits="$("scan_$name" "$root")"; then
    echo "PASS: $what"
  else
    echo "FAIL: $what:"
    printf '%s\n' "$hits"
    status=1
  fi
done

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
