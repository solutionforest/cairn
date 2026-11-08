#!/usr/bin/env bash
# Print the body of one version's section from a Keep a Changelog file.
# Usage: scripts/changelog-section.sh 0.1.0-alpha.1 [CHANGELOG.md]
# Falls back to the "Unreleased" section, then to a pointer at the file, so a release never
# ships with empty notes.
set -euo pipefail
version="${1:?version required (without leading v)}"
file="${2:-CHANGELOG.md}"

section() {
  awk -v want="$1" '
    /^## \[/ {
      if (found) exit
      hdr = $0; sub(/^## \[/, "", hdr); sub(/\].*$/, "", hdr)
      if (hdr == want) { found = 1; next }
    }
    found && !/^\[[^]]+\]: / { print }
  ' "$file"
}

body="$(section "$version")"
[ -n "${body//[[:space:]]/}" ] || body="$(section Unreleased)"
[ -n "${body//[[:space:]]/}" ] || body="See CHANGELOG.md for details."
printf '%s\n' "$body"
