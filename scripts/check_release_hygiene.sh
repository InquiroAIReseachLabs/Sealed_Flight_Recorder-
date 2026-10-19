#!/usr/bin/env bash
# check_release_hygiene.sh: no trace of the build machine or the people behind it in a release
# (SPEC B1.10 Releases). Run by .github/workflows/release.yml on every release file, and by
# scripts/validate.sh with --self-test.
#
#   scripts/check_release_hygiene.sh [--forbid <literal>]... <dir>
#       For every file in <dir>:
#         - a tarball: its member names are relative and inside one folder, every member is owned
#           by 0/0, and every member is unpacked and checked as below;
#         - every other file, and every unpacked member: `strings -a` (binaries) and the raw text
#           are searched for the patterns below, and `exiftool` is run on it and its output is
#           searched too.
#       Patterns that fail the check: a home directory path (/home/, /Users/, /root/, C:\Users),
#       a GitHub runner name, an email address, a session or tool path (/tmp/claude, .claude/,
#       claude.ai, a session id), the words CLAUDEME and "change order", and every --forbid
#       literal of four characters or more (the build machines' user name and host name, which
#       the release workflow passes in).
#       Exit 0 only when nothing matches. A missing tool (tar, strings, exiftool, grep) fails.
#       A hit is printed as file, class and line, with the matched text cut to its first two
#       characters, so the log does not repeat what it found.
#   scripts/check_release_hygiene.sh --self-test
#       Builds a clean fixture release and one fixture per class above; the clean one passes and
#       every other one fails with its class named.
set -euo pipefail
export LC_ALL=C

die() { echo "check_release_hygiene.sh: $*" >&2; exit 2; }
for tool in tar strings exiftool grep sed find sort; do
  command -v "$tool" > /dev/null || die "$tool is required (exiftool: apt-get install libimage-exiftool-perl)"
done

# class|extended regex. Words are assembled from parts so this file does not hold them whole.
c1='CLAUDE''ME'
c2='change''[ _-]*order'
classes=(
  "home-directory|(/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._-]+|/root/|[A-Za-z]:\\\\Users\\\\)"
  "runner-name|(/home/runner|runneradmin|runnervm|fv-az[0-9]+-[0-9]+)"
  "email-address|[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
  "session-path|(/tmp/claude|/\.claude/|claude\.ai/|session_[0-9A-Za-z]{12,}|/scratchpad)"
  "internal-word|($c1|$c2)"
)

forbid=()
scan_text() { # scan_text <label> <file> <extra grep -E regex or empty>: prints a line per hit; returns 1 if any
  local label="$1" f="$2" hits=0 spec class re out
  for spec in "${classes[@]}"; do
    class="${spec%%|*}" re="${spec#*|}"
    out="$(grep -a -n -o -i -E -- "$re" "$f" 2> /dev/null | head -3 || true)"
    if [ -n "$out" ]; then
      while IFS= read -r line; do
        echo "HIT $label: $class: line ${line%%:*}: ${line#*:}" | sed -E 's/(: line [0-9]+: .{2}).*/\1.../'
        hits=1
      done <<< "$out"
    fi
  done
  local lit
  for lit in "${forbid[@]+"${forbid[@]}"}"; do
    if grep -a -q -i -F -- "$lit" "$f" 2> /dev/null; then
      echo "HIT $label: build-identity: the text of --forbid \"${lit:0:2}...\" ($((${#lit})) characters)"
      hits=1
    fi
  done
  return "$hits"
}

scan_file() { # scan_file <label> <path>: the raw bytes, the strings of them, and the exiftool report
  local label="$1" f="$2" rc=0 tmp
  tmp="$(mktemp)"
  scan_text "$label" "$f" || rc=1
  strings -a -n 4 "$f" > "$tmp" 2> /dev/null || true
  scan_text "$label (strings)" "$tmp" || rc=1
  exiftool "$f" 2> /dev/null | grep -v -E '^(File Name|Directory|File Size|File (Modification|Access|Inode Change) Date/Time|File Permissions) ' > "$tmp" \
    || true
  [ -s "$tmp" ] || { rm -f "$tmp"; echo "FAIL $label: exiftool printed nothing" >&2; return 1; }
  scan_text "$label (exiftool)" "$tmp" || rc=1
  rm -f "$tmp"
  return "$rc"
}

check_tarball() { # check_tarball <path>
  local tb="$1" rc=0 name top stage bad
  name="$(basename "$tb")"
  while IFS= read -r m; do
    case "$m" in /* | ../* | */../* | .. ) echo "HIT $name: tar-member: not a relative path inside the folder: ${m:0:12}..."; rc=1 ;; esac
  done < <(tar -tzf "$tb")
  top="$(tar -tzf "$tb" | sed -n '1s#/.*##p')"
  [ -n "$top" ] && [ "$(tar -tzf "$tb" | grep -c -v -E "^$top(/|\$)")" -eq 0 ] \
    || { echo "HIT $name: tar-member: members are not all inside one folder"; rc=1; }
  bad="$(tar -tvzf "$tb" | awk '$2 != "0/0"' | wc -l)"
  [ "$bad" -eq 0 ] || { echo "HIT $name: tar-owner: $bad member(s) not owned by 0/0"; rc=1; }
  stage="$(mktemp -d)"
  tar -C "$stage" --no-same-owner --no-same-permissions -xzf "$tb" 2> /dev/null || { rm -rf "$stage"; echo "HIT $name: tar-unpack: cannot unpack" >&2; return 1; }
  scan_file "$name" "$tb" || rc=1
  while IFS= read -r -d '' f; do
    scan_file "$name:${f#"$stage"/}" "$f" || rc=1
  done < <(find "$stage" -type f -print0 | sort -z)
  rm -rf "$stage"
  return "$rc"
}

check_dir() { # check_dir <dir>
  local dir="$1" rc=0 n=0 f
  [ -d "$dir" ] || die "no directory $dir"
  while IFS= read -r -d '' f; do
    n=$((n + 1))
    case "$f" in
      *.tar.gz) check_tarball "$f" || rc=1 ;;
      *) scan_file "$(basename "$f")" "$f" || rc=1 ;;
    esac
  done < <(find "$dir" -maxdepth 1 -type f -print0 | sort -z)
  [ "$n" -gt 0 ] || die "$dir holds no file: a scan that looked at nothing is no pass"
  if [ "$rc" -eq 0 ]; then echo "PASS: release hygiene: $n file(s) and their unpacked members hold no home path, runner name, email address, session path, internal word or build identity"; fi
  return "$rc"
}

self_test() {
  local t d bin at='@'
  t="$(mktemp -d)"
  trap 'rm -rf "$t"' RETURN
  bin() { printf '\177ELF....sfr static binary\nsrc/main.rs\n/build/sfr/crates/sfr/src/main.rs\nVERSION 0.1.0\n'; } # a clean binary's strings
  make_release() { # make_release <dir> <extra line for the binary, or empty> <tar owner flags...>
    local dir="$1" extra="$2"; shift 2
    mkdir -p "$dir/pkg/sfr-0.1.0-x/bin"
    { bin; [ -z "$extra" ] || printf '%s\n' "$extra"; } > "$dir/pkg/sfr-0.1.0-x/bin/sfr"
    printf 'name: sfr\nversion: 0.1.0\n' > "$dir/pkg/sfr-0.1.0-x/BUILDINFO"
    tar -C "$dir/pkg" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner "$@" -czf "$dir/sfr-0.1.0-x.tar.gz" sfr-0.1.0-x
    rm -rf "$dir/pkg"
    printf '%s  sfr-0.1.0-x.tar.gz\n' "$(sha256sum "$dir/sfr-0.1.0-x.tar.gz" | cut -d' ' -f1)" > "$dir/SHA256SUMS"
  }
  make_release "$t/clean" ""
  check_dir "$t/clean" > /dev/null || die "self-test: a clean release failed"
  local label line
  while IFS='|' read -r label line; do
    d="$t/case-$label"
    make_release "$d" "$line"
    if (check_dir "$d" > "$d.out" 2>&1); then die "self-test: $label was not caught"; fi
    grep -q -- "$label" "$d.out" || die "self-test: $label failed but the class is not named: $(cat "$d.out")"
  done <<EOF
home-directory|built in /home/someone/work/sfr
home-directory|path /Users/someone/sfr
home-directory|path /root/.cargo/registry
runner-name|machine fv-az1234-567
email-address|written by someone${at}example.com
session-path|file /tmp/claude-1/scratch
session-path|id session_01ABCDEFGHIJKLMNOP
internal-word|see the $c1 standard
internal-word|per Change Order 01
EOF
  # a build-identity literal passed with --forbid
  make_release "$t/ident" "compiled by buildmaster7"
  forbid=(buildmaster7)
  if (check_dir "$t/ident" > "$t/ident.out" 2>&1); then die "self-test: a --forbid literal was not caught"; fi
  grep -q build-identity "$t/ident.out" || die "self-test: --forbid failure not named"
  grep -q buildmaster7 "$t/ident.out" && die "self-test: the log repeated the forbidden text"
  forbid=()
  # an email address in a non-tarball file, and a hit that must not be echoed whole
  mkdir -p "$t/plain"
  printf '{"author":"someone%sexample.com"}\n' "$at" > "$t/plain/sbom.cdx.json"
  if (check_dir "$t/plain" > "$t/plain.out" 2>&1); then die "self-test: an address in an SBOM was not caught"; fi
  grep -q 'example.com' "$t/plain.out" && die "self-test: the log repeated an address"
  # a tarball owned by a person, and one with an absolute member name
  make_release "$t/owned" ""
  mkdir -p "$t/owned2/pkg/sfr-0.1.0-x"; printf 'x\n' > "$t/owned2/pkg/sfr-0.1.0-x/f"
  tar -C "$t/owned2/pkg" --owner=1000 --group=1000 --numeric-owner -czf "$t/owned2/sfr-0.1.0-x.tar.gz" sfr-0.1.0-x
  rm -rf "$t/owned2/pkg"
  if (check_dir "$t/owned2" > "$t/owned2.out" 2>&1); then die "self-test: a tarball owned by 1000 passed"; fi
  grep -q tar-owner "$t/owned2.out" || die "self-test: tar-owner not named"
  mkdir -p "$t/abs/pkg/sfr-0.1.0-x"; printf 'x\n' > "$t/abs/pkg/sfr-0.1.0-x/f"
  tar -C "$t/abs/pkg" --owner=0 --group=0 --numeric-owner -czf "$t/abs/sfr-0.1.0-x.tar.gz" -P --transform 's,^,/etc/,' sfr-0.1.0-x/f 2> /dev/null
  if (check_dir "$t/abs" > "$t/abs.out" 2>&1); then die "self-test: a tarball with an absolute member passed"; fi
  grep -q tar-member "$t/abs.out" || die "self-test: tar-member not named"
  # an empty directory is no pass
  mkdir -p "$t/empty"
  if (check_dir "$t/empty" > /dev/null 2>&1); then die "self-test: an empty directory passed"; fi
  echo "check_release_hygiene.sh self-test: ok"
}

if [ "${1:-}" = --self-test ]; then self_test; exit 0; fi
while [ "${1:-}" = --forbid ]; do
  [ -n "${2:-}" ] || die "--forbid needs a literal"
  # Short literals match too much (a user name such as "me" is in every word).
  if [ "${#2}" -ge 4 ]; then forbid+=("$2"); fi
  shift 2
done
[ $# -eq 1 ] || die "usage: $0 [--forbid <literal>]... <dir> | --self-test"
check_dir "$1"
