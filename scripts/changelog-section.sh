#!/usr/bin/env bash
# Print the body of one version's section from a Keep a Changelog file, for the release notes.
# Usage: scripts/changelog-section.sh 0.1.0-alpha.1 [CHANGELOG.md]
# Every release needs its own entry: exits 1 (and prints why) unless the file has a
# "## [<version>] - YYYY-MM-DD" heading with a non-empty body and a "[<version>]: <url>" link.
# There is no fallback to Unreleased, so a tag without an entry fails before anything is built.
set -euo pipefail
version="${1:?version required (without leading v)}"
file="${2:-CHANGELOG.md}"

fail() {
  echo "changelog-section: $*" >&2
  echo "Add a '## [$version] - YYYY-MM-DD' section (move the Unreleased entries into it)" >&2
  echo "and a '[$version]: https://github.com/solutionforest/cairn/releases/tag/v$version' link." >&2
  exit 1
}

[ -f "$file" ] || fail "$file not found"

heading="$(grep -E "^## \[${version//./\\.}\]" "$file" || true)"
[ -n "$heading" ] || fail "no section for $version in $file"
[ "$(printf '%s\n' "$heading" | wc -l)" -eq 1 ] || fail "more than one section for $version"
printf '%s\n' "$heading" | grep -Eq '^## \[[^]]+\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$' ||
  fail "section heading must read '## [$version] - YYYY-MM-DD', found: $heading"
grep -Eq "^\[${version//./\\.}\]: https?://" "$file" || fail "no '[$version]: <url>' link line"

body="$(awk -v want="$version" '
  /^## \[/ {
    if (found) exit
    hdr = $0; sub(/^## \[/, "", hdr); sub(/\].*$/, "", hdr)
    if (hdr == want) { found = 1; next }
  }
  found && !/^\[[^]]+\]: / { print }
' "$file")"
[ -n "${body//[[:space:]]/}" ] || fail "section for $version is empty"

printf '%s\n' "$body"
