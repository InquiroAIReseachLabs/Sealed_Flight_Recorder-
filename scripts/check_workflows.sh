#!/usr/bin/env bash
# check_workflows.sh: rules for the release workflows that a script can enforce (CLAUDEME
# section 5: actions pinned to a full commit SHA; docs/RELEASE.md: no key and no secret in CI).
#
#   For every file in .github/workflows/:
#     0. it parses as YAML (a workflow that does not parse fails every push with no job);
#     1. each `uses:` is a local path or owner/repo[/path]@<40 hex> with a version comment;
#     2. no `pull_request_target` trigger.
#   For release.yml, post-release-check.yml and benchmark-aarch64.yml:
#     3. no `secrets.` reference (the run's own `github.token` is the only token);
#     4. a top-level `permissions:` block;
#     5. no signing: no `release_sign.sh sign` or `release_sign.sh keygen`, no `pkeyutl -sign`,
#        no `genpkey`, no `-----BEGIN`, so the release key cannot be in or made by CI.
#   For release.yml:
#     6. triggers are a v* tag push and workflow_dispatch only;
#     7. a write permission (`contents: write`, `id-token: write`, `attestations: write`) appears
#        only in the draft-release job;
#     8. the release is created only as a draft pre-release (`gh release create ... --draft
#        --prerelease`), and nothing publishes (`gh release edit`, `--draft=false`).
#
# Usage: scripts/check_workflows.sh [--self-test]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# check_dir <workflows dir>: prints a line per violation; returns 1 if any.
check_dir() {
  local dir="$1" bad=0 f name
  say() { echo "FAIL: $*"; bad=1; }
  [ -d "$dir" ] || { echo "FAIL: no directory $dir"; return 1; }
  for f in "$dir"/*.yml; do
    [ -f "$f" ] || continue
    name="$(basename "$f")"
    python3 -I -c 'import sys, yaml; yaml.safe_load(open(sys.argv[1]))' "$f" 2> /dev/null || say "$name: not valid YAML"
    while IFS= read -r line; do
      ref="$(printf '%s' "$line" | sed -E 's/^[[:space:]-]*uses:[[:space:]]*([^[:space:]#]+).*/\1/')"
      case "$ref" in
        ./*) ;;
        *@*) [[ "$ref" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$ ]] || say "$name: action not pinned to a full commit SHA: $ref"
             printf '%s' "$line" | grep -q '# v' || say "$name: pinned action without a version comment: $ref" ;;
        *) say "$name: action without a version: $ref" ;;
      esac
    done < <(grep -E '^[[:space:]-]*uses:' "$f" || true)
    grep -q 'pull_request_target' "$f" && say "$name: pull_request_target"
    case "$name" in
      release.yml | post-release-check.yml | benchmark-aarch64.yml)
        grep -n 'secrets\.' "$f" | grep -v '^[0-9]*:[[:space:]]*#' | grep -q . && say "$name: a secrets. reference"
        grep -q '^permissions:' "$f" || say "$name: no top-level permissions:"
        if grep -n -E 'release_sign\.sh[[:space:]]+(sign|keygen)|pkeyutl[[:space:]]+-sign|genpkey|-----BEGIN' "$f" | grep -v -E '^[0-9]+:[[:space:]]*#' | grep -q .; then
          say "$name: signs or makes a key"
        fi ;;
    esac
  done
  local r="$dir/release.yml"
  if [ -f "$r" ]; then
    awk '/^on:/{p=1;next} /^[a-z]/{p=0} p' "$r" | grep -q -E 'pull_request|branches' && say "release.yml: a trigger other than a tag push and workflow_dispatch"
    awk '/^on:/{p=1;next} /^[a-z]/{p=0} p' "$r" | grep -q -E 'tags:[[:space:]]*\["v\*"\]' || say "release.yml: no v* tag trigger"
    awk '/^on:/{p=1;next} /^[a-z]/{p=0} p' "$r" | grep -q 'workflow_dispatch' || say "release.yml: no workflow_dispatch"
    # a write permission outside the draft-release job
    awk '
      /^  [a-z][a-z0-9-]*:[[:space:]]*$/ { job = $1; sub(/:$/, "", job) }
      /^[a-z]/ { job = "" }
      /(contents|id-token|attestations|packages|issues|pull-requests|actions):[[:space:]]*write/ && job != "draft-release" { print FILENAME ": " $0 }
    ' "$r" | grep -q . && say "release.yml: a write permission outside the draft-release job"
    grep -q -E 'gh release create .*--draft' "$r" && grep -q -E -- '--prerelease' "$r" || say "release.yml: the release is not created as a draft pre-release"
    grep -n -E 'gh release (edit|upload)|--draft=false|--latest|gh release create' "$r" | grep -v -E -- '--draft' | grep -v -E '^[0-9]+:[[:space:]]*#' | grep -q . && say "release.yml: a command that could publish or change a release"
  else
    say "no release.yml"
  fi
  return "$bad"
}

self_test() {
  local t good
  t="$(mktemp -d)"
  trap 'rm -rf "$t"' RETURN
  mkdir -p "$t/ok"
  cp .github/workflows/release.yml "$t/ok/release.yml"
  check_dir "$t/ok" > /dev/null || die_st "the real release.yml fails: $(check_dir "$t/ok")"
  local label from to
  while IFS='|' read -r label from to; do
    mkdir -p "$t/$label"
    sed "s|$from|$to|" .github/workflows/release.yml > "$t/$label/release.yml"
    if (check_dir "$t/$label" > "$t/$label.out" 2>&1); then die_st "$label was not caught"; fi
  done <<'EOT'
tag-pin|actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0|actions/checkout@v5
short-sha|actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4 # v5.0.0|actions/upload-artifact@330a01c # v5.0.0
no-comment|actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53 # v6.0.0|actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53
secret|GH_TOKEN: ${{ github.token }}|GH_TOKEN: ${{ secrets.RELEASE_TOKEN }}
push-trigger|    tags: \["v\*"\]|    tags: ["v*"]\n    branches: [main]
publish|--draft --prerelease|--prerelease
EOT
  mkdir -p "$t/yaml"
  sed 's|^      - name: cargo test --locked|      - name: cargo test: locked|' .github/workflows/release.yml > "$t/yaml/release.yml"
  if (check_dir "$t/yaml" > /dev/null 2>&1); then die_st "a workflow that is not valid YAML was not caught"; fi
  mkdir -p "$t/write"
  sed 's|^  meta:|  meta:\n    permissions:\n      contents: write|' .github/workflows/release.yml > "$t/write/release.yml"
  if (check_dir "$t/write" > /dev/null 2>&1); then die_st "a write permission outside draft-release was not caught"; fi
  mkdir -p "$t/sign"
  { cat .github/workflows/release.yml; printf '      - run: scripts/release_sign.sh sign dist/SHA256SUMS key\n'; } > "$t/sign/release.yml"
  if (check_dir "$t/sign" > /dev/null 2>&1); then die_st "signing in the workflow was not caught"; fi
  echo "check_workflows.sh self-test: ok"
}
die_st() { echo "check_workflows.sh self-test: $*" >&2; exit 1; }

if [ "${1:-}" = --self-test ]; then self_test; exit 0; fi
[ $# -eq 0 ] || { echo "usage: $0 [--self-test]" >&2; exit 2; }
if check_dir .github/workflows; then echo "PASS: workflow rules (actions pinned by SHA, no secret, no signing, only the draft-release job writes)"; else exit 1; fi
