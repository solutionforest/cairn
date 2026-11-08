#!/usr/bin/env bash
# Check whether a project name is free on crates.io, Docker Hub and GitHub.
# Usage: scripts/name-check.sh [name ...]      (default: cairn and the fallback candidates)
# Needs curl and python3; uses `gh api` for GitHub when available (higher rate limit).
# Trademarks are not checked automatically: search https://tmsearch.uspto.gov and
# https://euipo.europa.eu/eSearch (class 9/42) by hand before a public tag.
set -euo pipefail

names=("$@")
[ ${#names[@]} -gt 0 ] || names=(cairn cairn-s3 cairnstore cairn-server cairn-cli cairn-core)
ua="cairn-name-check/1 (https://github.com/solutionforest/cairn)"

http_json() { curl -fsS --max-time 20 -A "$ua" "$1" 2>/dev/null || true; }
py() { python3 -I -c "$1"; }

crates() {
  local j; j="$(http_json "https://crates.io/api/v1/crates/$1")"
  if [ -z "$j" ]; then echo "free"; return; fi
  printf '%s' "$j" | py '
import json, sys
c = json.load(sys.stdin).get("crate") or {}
if not c: print("free"); sys.exit()
desc = (c.get("description") or "").strip().replace("\n", " ")[:40]
ver, dl, upd = c.get("max_version"), c.get("downloads", 0), str(c.get("updated_at", ""))[:10]
print(f"TAKEN v{ver}, {dl} dl, updated {upd}: {desc}")'
}

dockerhub() {
  local out=() j
  # Official image (library/<name>) and a user/org namespace of that name.
  j="$(http_json "https://hub.docker.com/v2/repositories/library/$1/")"
  [ -n "$j" ] && out+=("official image exists")
  j="$(http_json "https://hub.docker.com/v2/repositories/$1/?page_size=1")"
  if [ -n "$j" ]; then
    local cnt; cnt="$(printf '%s' "$j" | py 'import json,sys; print(json.load(sys.stdin).get("count", 0))')"
    [ "$cnt" = 0 ] || out+=("namespace $1/ has $cnt repos")
  fi
  j="$(http_json "https://hub.docker.com/v2/search/repositories/?query=$1&page_size=100")"
  if [ -n "$j" ]; then
    out+=("$(printf '%s' "$j" | NAME="$1" py '
import json, os, sys
n = os.environ["NAME"]
rs = json.load(sys.stdin).get("results", [])
exact = [r for r in rs if r.get("repo_name", "").split("/")[-1] == n]
top = max(exact, key=lambda r: r.get("pull_count", 0), default=None)
s = f"{len(exact)} repos named {n}"
if top:
    name, pulls = top["repo_name"], top.get("pull_count", 0)
    s += f" (top {name}, {pulls} pulls)"
print(s)')")
  fi
  if [ ${#out[@]} -eq 0 ]; then echo free; return; fi
  local joined; joined="$(printf '%s; ' "${out[@]}")"; echo "${joined%; }"
}

github() {
  local j user
  if command -v gh >/dev/null 2>&1; then
    j="$(gh api -X GET search/repositories -f q="$1 in:name" -f sort=stars -f per_page=100 2>/dev/null || true)"
    user="$(gh api "users/$1" --jq '.type + " @" + .login' 2>/dev/null)" || user="no user/org"
  else
    j="$(http_json "https://api.github.com/search/repositories?q=$1+in:name&sort=stars&per_page=100")"
    user="$(http_json "https://api.github.com/users/$1" | py 'import json,sys; d=json.load(sys.stdin); print(d["type"]+" @"+d["login"])' 2>/dev/null || echo "no user/org")"
  fi
  printf '%s' "$j" | NAME="$1" USERLINE="$user" py '
import json, os, sys
n = os.environ["NAME"].lower()
try: rs = json.load(sys.stdin).get("items", [])
except Exception: rs = []
exact = [r for r in rs if r["name"].lower() == n]
top = exact[0] if exact else None
s = f"{len(exact)} repos named {n}"
if top:
    name, stars = top["full_name"], top["stargazers_count"]
    s += f" (top {name}, {stars} stars)"
print(s + "; " + os.environ["USERLINE"])'
}

printf '| %-12s | %-60s | %-55s | %-45s |\n' name "crates.io" "Docker Hub" "GitHub"
printf '|%s|%s|%s|%s|\n' "$(printf -- '-%.0s' {1..14})" "$(printf -- '-%.0s' {1..62})" "$(printf -- '-%.0s' {1..57})" "$(printf -- '-%.0s' {1..47})"
for n in "${names[@]}"; do
  printf '| %-12s | %-60s | %-55s | %-45s |\n' "$n" "$(crates "$n")" "$(dockerhub "$n")" "$(github "$n")"
  sleep 1
done
echo
echo "checked $(date -u +%Y-%m-%dT%H:%MZ)"
