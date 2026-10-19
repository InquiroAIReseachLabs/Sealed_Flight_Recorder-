#!/usr/bin/env bash
# check_release_flow.sh: the whole offline signing flow of a release, end to end, with a throwaway
# key (docs/RELEASE.md). The release key is never used here and never enters CI.
#
#   1. CI side:      six fake release files, then scripts/release_assemble.sh --set github writes
#                    SHA256SUMS over exactly them.
#   2. Founder side: in another directory that holds only SHA256SUMS, scripts/release_sign.sh sign
#                    writes SHA256SUMS.sig; the public key file is the key's public half.
#   3. Engineer side: in a third directory holding the download, the commands of docs/RELEASE.md
#                    (openssl pkeyutl -verify, sha256sum --check) pass, and the key's fingerprint
#                    equals the one published separately.
#   4. Attacks, each of which must fail at the step that docs/RELEASE.md says catches it:
#        a tarball changed after signing; SHA256SUMS changed after signing; a signature cut short;
#        a signature from a different key; an attacker's own SHA256SUMS, signature and key (the
#        signature verifies, the fingerprint does not match); a file the signed SHA256SUMS does not
#        list (swapped in under another name); an extra file in a directory checked as a whole;
#        a SHA256SUMS that lists a file twice with different sums.
#
# Usage: scripts/check_release_flow.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
repo="$(pwd)"
die() { echo "check_release_flow.sh: $*" >&2; exit 1; }
version="$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"$/\1/p' Cargo.toml)"
[ -n "$version" ] || die "no version in Cargo.toml"
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT

fingerprint() { openssl pkey -pubin -in "$1" -outform DER | sha256sum | cut -d' ' -f1; }
# The two commands of docs/RELEASE.md, in a directory that holds the download. $1 is the public key file.
verify_signature() { openssl pkeyutl -verify -pubin -inkey "$1" -rawin -in SHA256SUMS -sigfile SHA256SUMS.sig > /dev/null 2>&1; }
verify_files() { sha256sum --check --strict SHA256SUMS > /dev/null 2>&1; }
verify_one() { sha256sum --check --strict --ignore-missing SHA256SUMS > /dev/null 2>&1; }
# The whole check an engineer makes: key fingerprint, signature, checksums.
engineer() { # engineer <dir> <expected fingerprint> [all|one]
  (cd "$1" && [ "$(fingerprint sfr-release.pub)" = "$2" ] && verify_signature sfr-release.pub && if [ "${3:-all}" = one ]; then verify_one; else verify_files; fi)
}

# 1. CI side
ci="$t/ci"; mkdir -p "$ci"
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf; do
  printf 'binary for %s\n' "$target" | gzip -n > "$ci/sfr-$version-$target.tar.gz"
  printf '{"sbom":"%s"}\n' "$target" > "$ci/sfr-$version-$target.cdx.json"
done
scripts/release_assemble.sh --set github "$ci" > /dev/null
[ "$(wc -l < "$ci/SHA256SUMS")" -eq 6 ] || die "SHA256SUMS does not list the six files"

# 2. Founder side: only SHA256SUMS comes to the offline machine
founder="$t/founder"; mkdir -p "$founder"
cp "$ci/SHA256SUMS" "$founder/"
(umask 077 && openssl genpkey -algorithm ed25519 -out "$t/release.key")
openssl pkey -in "$t/release.key" -pubout -out "$t/sfr-release.pub"
scripts/release_sign.sh sign "$founder/SHA256SUMS" "$t/release.key" --pubkey "$t/sfr-release.pub" > /dev/null
published_fp="$(fingerprint "$t/sfr-release.pub")"

# 3. Engineer side
download() { # download <dir>: what the published release holds
  rm -rf "$1"; mkdir -p "$1"
  cp "$ci"/sfr-* "$1/"; cp "$ci/SHA256SUMS" "$1/"; cp "$founder/SHA256SUMS.sig" "$1/"; cp "$t/sfr-release.pub" "$1/"
}
e="$t/engineer"; download "$e"
engineer "$e" "$published_fp" all || die "the honest release does not verify"
engineer "$e" "$published_fp" one || die "the honest release does not verify with --ignore-missing"
(cd "$e" && mkdir one && cp sfr-*-x86_64-unknown-linux-musl.tar.gz SHA256SUMS SHA256SUMS.sig sfr-release.pub one/) 
engineer "$e/one" "$published_fp" one || die "one tarball and the signed SHA256SUMS do not verify"

# 4. Attacks
must_fail() { # must_fail <label> <dir> <expected fingerprint> [all|one]
  if engineer "$2" "$3" "${4:-all}"; then die "attack accepted: $1"; fi
}
download "$e"; echo tampered >> "$e/sfr-$version-x86_64-unknown-linux-musl.tar.gz"
must_fail "a tarball changed after signing" "$e" "$published_fp"
(cd "$e" && ! verify_files) || die "sha256sum did not catch the changed tarball"
(cd "$e" && verify_signature sfr-release.pub) || die "the signature should still verify: only the tarball changed"

download "$e"; echo "0000  extra" >> "$e/SHA256SUMS"
must_fail "SHA256SUMS changed after signing" "$e" "$published_fp"
(cd "$e" && ! verify_signature sfr-release.pub) || die "the signature should fail on a changed SHA256SUMS"

download "$e"; head -c 63 "$e/SHA256SUMS.sig" > "$e/cut.sig"; mv "$e/cut.sig" "$e/SHA256SUMS.sig"
must_fail "a signature cut short" "$e" "$published_fp"

download "$e"; (umask 077 && openssl genpkey -algorithm ed25519 -out "$t/other.key")
openssl pkeyutl -sign -inkey "$t/other.key" -rawin -in "$e/SHA256SUMS" -out "$e/SHA256SUMS.sig"
must_fail "a signature from a different key, checked against the real key" "$e" "$published_fp"

# an attacker supplies their own files, signature and key: the signature verifies, the fingerprint does not
download "$e"; echo tampered >> "$e/sfr-$version-x86_64-unknown-linux-musl.tar.gz"
(cd "$e" && sha256sum "sfr-$version"-* > SHA256SUMS.new && mv SHA256SUMS.new SHA256SUMS)
openssl pkeyutl -sign -inkey "$t/other.key" -rawin -in "$e/SHA256SUMS" -out "$e/SHA256SUMS.sig"
openssl pkey -in "$t/other.key" -pubout -out "$e/sfr-release.pub"
(cd "$e" && verify_signature sfr-release.pub && verify_files) || die "self-test setup: the attacker's release should verify against the attacker's own key"
must_fail "an attacker's own SHA256SUMS, signature and key" "$e" "$published_fp"

# a tarball swapped in under a name the signed SHA256SUMS does not list: --ignore-missing must not pass it
download "$e"; mkdir "$e/one"; cp "$e/sfr-$version-x86_64-unknown-linux-musl.tar.gz" "$e/one/sfr-$version-evil.tar.gz"
cp "$e/SHA256SUMS" "$e/SHA256SUMS.sig" "$e/sfr-release.pub" "$e/one/"
rm "$e/one/sfr-$version-x86_64-unknown-linux-musl.tar.gz" 2> /dev/null || true
must_fail "a file the signed SHA256SUMS does not list" "$e/one" "$published_fp" one

# an extra file next to a verified download is not covered by SHA256SUMS: the instructions say to
# use only the files SHA256SUMS lists, so this test documents that the check does not look at it
download "$e"; echo evil > "$e/sfr-$version-extra.tar.gz"
engineer "$e" "$published_fp" all || die "an unlisted extra file should not break the check of the listed ones"
[ "$(grep -c "extra" "$e/SHA256SUMS")" -eq 0 ] || die "the unlisted file is in SHA256SUMS"

# the same file listed twice with different sums fails
download "$e"; printf '%s  %s\n' "$(printf evil | sha256sum | cut -d' ' -f1)" "sfr-$version-x86_64-unknown-linux-musl.tar.gz" >> "$e/SHA256SUMS"
must_fail "a file listed twice with different sums" "$e" "$published_fp"

# no private key was written into the repository
git -C "$repo" status --porcelain | grep -q -E '\.key$|release/' && die "the flow wrote a key or release file into the repository"
echo "check_release_flow.sh: ok (honest release verifies; 8 attacks each fail where docs/RELEASE.md says)"
