#!/usr/bin/env bash
# Tests for scripts/changelog-section.sh: the release gate must fail on every malformed entry.
# Run: scripts/tests/changelog_test.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
script=scripts/changelog-section.sh
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=0

good='# Changelog

## [Unreleased]

## [1.2.0] - 2026-01-02

### Fixed
- a thing

## [1.1.0] - 2025-12-01

- older

[1.2.0]: https://github.com/solutionforest/tidemark/releases/tag/v1.2.0
[1.1.0]: https://github.com/solutionforest/tidemark/releases/tag/v1.1.0
'

expect_ok() { # name, version, file content, expected substring
  printf '%s' "$3" >"$tmp/c.md"
  if out="$("$script" "$2" "$tmp/c.md" 2>&1)" && [[ "$out" == *"$4"* ]] && [[ "$out" != *older* ]]; then
    echo "ok   $1"
  else
    echo "FAIL $1: $out"; fails=$((fails + 1))
  fi
}

expect_fail() { # name, version, file content, expected message
  printf '%s' "$3" >"$tmp/c.md"
  if out="$("$script" "$2" "$tmp/c.md" 2>&1)"; then
    echo "FAIL $1: exited 0"; fails=$((fails + 1))
  elif [[ "$out" != *"$4"* ]]; then
    echo "FAIL $1: wrong message: $out"; fails=$((fails + 1))
  else
    echo "ok   $1"
  fi
}

expect_ok "extracts only its own section" 1.2.0 "$good" "a thing"
expect_fail "missing section" 9.9.9 "$good" "no section for 9.9.9"
expect_fail "no date" 1.2.0 "${good/'## [1.2.0] - 2026-01-02'/'## [1.2.0]'}" "must read"
expect_fail "missing link line" 1.2.0 "${good/'[1.2.0]: https'/'[x]: https'}" "link line"
expect_fail "empty section" 1.2.0 "${good/'### Fixed
- a thing'/}" "is empty"
expect_fail "duplicate section" 1.2.0 "$good
## [1.2.0] - 2026-01-03
" "more than one section"
expect_fail "dots are literal" 1.2.0 "${good//1.2.0/1x2x0}" "no section for 1.2.0"
expect_fail "missing file" 1.2.0 "" "no section"
rm -f "$tmp/c.md"
if "$script" 1.2.0 "$tmp/none.md" >/dev/null 2>&1; then echo "FAIL missing file exits 0"; fails=$((fails + 1)); fi

latest="$(grep -m1 -oE '^## \[[0-9][^]]*\]' CHANGELOG.md | tr -d '#[] ')"
if "$script" "$latest" CHANGELOG.md >/dev/null; then echo "ok   committed CHANGELOG.md has $latest"; else fails=$((fails + 1)); fi

[ "$fails" -eq 0 ] && echo "all changelog tests passed" || { echo "$fails changelog test(s) failed"; exit 1; }
