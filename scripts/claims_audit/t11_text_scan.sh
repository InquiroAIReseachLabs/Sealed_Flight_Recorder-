#!/usr/bin/env bash
# T11 Public text scan: README, docs, examples, the page under site/, and every other tracked text file.
# Lists, with file and line: internal wording (a person's role, review or ticket references, series labels),
# personal information (e-mail addresses, home paths, names), compliance-sounding language, internal codenames,
# and the strong-claim words that need a test behind them. The first four must have no hits; the claim words
# are listed for a person to check against T1 to T10 (docs/CLAIMS_AUDIT.md). Reads the checkout only.
# Not covered: a website outside this repository. Run `scripts/claims_audit/t11_text_scan.sh --text <file>` on a
# saved copy of a page to scan its text with the same rules.
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"
cd "$A_REPO" || exit 1
if [ "${1:-}" = "--text" ]; then files="$2"; else
  files="$(git ls-files | grep -v -E '\.(ulg|sfr|png|ico|wasm|gz|pub|pem|crl)$|^testdata/(sitl|pyulog)|^fuzz/seeds|^Cargo\.lock$|^fuzz/Cargo\.lock$|node_modules|^deny-list\.txt$|^scripts/claims_audit/t11_text_scan\.sh$|^scripts/check_language\.sh$')"
fi
echo "commit $(git rev-parse HEAD 2> /dev/null); $(echo "$files" | wc -l) text files scanned"
hits() { # <title> <regex> [<regex of hits to allow>]
  local title="$1" re="$2" allow="${3:-^$}" n=0 out=""
  while IFS= read -r f; do
    [ -f "$f" ] || continue
    r="$(grep -n -I -i -E -- "$re" "$f" 2> /dev/null | grep -v -i -E -- "$allow" | sed "s|^|$f:|" | cut -c1-200)"
    [ -n "$r" ] && out="$out$r"$'\n'
  done <<< "$files"
  n="$(printf '%s' "$out" | grep -c .)"
  echo; echo "=== $title: $n hit(s)"; printf '%s' "$out" | head -${LIMIT:-40}
  HITS="$n"
}
hits "internal wording (roles, review and ticket references, series labels)" '\b(founder|co-?founder|ceo|cto|red[ -]?team|grok|chief|committee)\b|issue #?[0-9]+|(^|[^a-z])#[0-9]{2,3}\b|\bA-series\b|\bthe series\b|\bfinding F[0-9]|\bpull request #[0-9]|\bPR #[0-9]|for the (founder|owner)' 'into a link\) still does so'
check "no internal wording" "$([ "$HITS" -eq 0 ]; echo $?)"
hits "personal information (e-mail addresses other than example domains, home paths, phone numbers)" '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}|/home/[a-z][a-z0-9_-]*/|/Users/[A-Za-z]+/|\b[0-9]{3}[-. ][0-9]{3}[-. ][0-9]{4}\b' '@example\.(com|org)|/home/(someone|runner)/|/Users/someone/|users\.noreply'
check "no personal information" "$([ "$HITS" -eq 0 ]; echo $?)"
hits "internal codenames and work-order labels" 'claudeme|\bchunk [0-9]+\b|change[ _-]*orders?\b|\bco ?01\b'
check "no internal codename" "$([ "$HITS" -eq 0 ]; echo $?)"
hits "compliance-sounding words (a disclaimer that denies a claim is listed too; read each)" '\b(compliant|compliance|certified|certification|validated|fips|cmvp|nist|dodd|ndaa|itar|stig|cmmc|fedramp|soc ?2|accredited|airworthy|airworthiness)\b'
echo "(listed for review: each is a denial, a standard cited for a hash function, or a test name; none may be a claim)"
hits "strong-claim words to check against T1 to T10" '\b(tamper[ -]?proof|tamper[ -]?evident|unforgeable|guarantee[sd]?|immutable|unhackable|bulletproof|military|mission[ -]critical|cannot be (forged|changed|faked))\b' 'turn on immutable releases|A guarantee that what was hidden|The three guarantees above do not hold'
echo "(reviewed and allowed: the GitHub setting named Immutable releases in docs/RELEASE.md, and two denials in docs/design/B5_ACCESS.md)"
check "no strong-claim word without a test (none expected)" "$([ "$HITS" -eq 0 ]; echo $?)"
finish
