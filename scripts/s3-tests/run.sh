#!/usr/bin/env bash
# Run a tagged subset of ceph/s3-tests against a running Cairn and gate on expected-pass.txt:
# exit 1 if any listed test does not pass; unlisted new passes are reported, never fatal.
#
# Usage: run.sh                    gate on expected-pass.txt (every push)
#        run.sh --write-expected   rewrite expected-pass.txt from this run (baseline / promote)
#        S3_TESTS_FULL=1 run.sh    weekly sweep: no marker/-k deselection, report only (exit 0)
#
# Required env:  S3_ENDPOINT (e.g. http://127.0.0.1:9000)
#                S3_MAIN_ACCESS_KEY S3_MAIN_SECRET_KEY
# Optional env:  S3_ALT_ACCESS_KEY S3_ALT_SECRET_KEY   (second principal; default = main)
#                S3_TENANT_ACCESS_KEY S3_TENANT_SECRET_KEY (default = alt)
#                S3_TESTS_REPO     (default https://github.com/ceph/s3-tests.git)
#                S3_TESTS_COMMIT   (default: pinned below)
#                S3_TESTS_WORKDIR  (default: ./target/s3-tests)
#                S3_TESTS_MARKERS  (pytest -m expression; default: DEFAULT_MARKERS below)
#                S3_TESTS_PATHS    (default: s3tests/functional/test_s3.py s3tests/functional/test_headers.py)
#                S3_TESTS_DESELECT (pytest -k expression; default: DEFAULT_DESELECT below)
#                S3_TESTS_EXTRA    (extra pytest args, e.g. "-x -vv")
set -euo pipefail
mode=gate
[ "${1:-}" = "--write-expected" ] && mode=write
[ "${S3_TESTS_FULL:-0}" = 1 ] && mode=full

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"

# Last commit of ceph/s3-tests (2026-10-12). Upstream has since moved the suite into the
# ceph/ceph repository; switch S3_TESTS_REPO/COMMIT when we follow it there.
PINNED_COMMIT=5b3987116eca0b4b8fa57d6b10f3db57bab196b6

# Features Cairn does not implement (or that are RGW-specific) are deselected; see README.md.
DEFAULT_MARKERS="not fails_on_aws and not fails_with_subdomain \
and not appendobject and not bucket_logging and not bucket_logging_cleanup \
and not fails_without_logging_rollover and not cloud_transition and not cloud_restore \
and not target_by_bucket and not lifecycle_transition and not storage_class \
and not s3select and not s3website and not s3website_routing_rules \
and not s3website_redirect_location and not sns and not s3control \
and not iam_account and not iam_cross_account and not iam_role and not iam_tenant \
and not iam_user and not group and not group_policy and not role_policy \
and not session_policy and not user_policy and not abac_test and not test_of_sts \
and not webidentity_test and not token_claims_trust_policy_test \
and not token_principal_tag_role_policy_test and not token_request_tag_trust_policy_test \
and not token_resource_tags_test and not token_role_tags_test and not token_tag_keys_test \
and not auth_aws2 \
and not object_lock and not encryption"

# Shelved in v0.1 (DESIGN §0) without a marker of their own: CORS, PostObject (browser form upload),
# and the Object Lock tests upstream left without the `object_lock` marker (matched by name).
DEFAULT_DESELECT="not cors and not post_object and not object_lock"

: "${S3_ENDPOINT:?set S3_ENDPOINT, e.g. http://127.0.0.1:9000}"
: "${S3_MAIN_ACCESS_KEY:?set S3_MAIN_ACCESS_KEY}"
: "${S3_MAIN_SECRET_KEY:?set S3_MAIN_SECRET_KEY}"
alt_ak="${S3_ALT_ACCESS_KEY:-$S3_MAIN_ACCESS_KEY}"
alt_sk="${S3_ALT_SECRET_KEY:-$S3_MAIN_SECRET_KEY}"
ten_ak="${S3_TENANT_ACCESS_KEY:-$alt_ak}"
ten_sk="${S3_TENANT_SECRET_KEY:-$alt_sk}"
repo="${S3_TESTS_REPO:-https://github.com/ceph/s3-tests.git}"
commit="${S3_TESTS_COMMIT:-$PINNED_COMMIT}"
work="${S3_TESTS_WORKDIR:-$repo_root/target/s3-tests}"
markers="${S3_TESTS_MARKERS:-$DEFAULT_MARKERS}"
deselect="${S3_TESTS_DESELECT:-$DEFAULT_DESELECT}"
if [ "$mode" = full ]; then markers="not fails_with_subdomain"; deselect=""; fi
paths="${S3_TESTS_PATHS:-s3tests/functional/test_s3.py s3tests/functional/test_headers.py}"
expected="$here/expected-pass.txt"

# Parse scheme://host:port
proto="${S3_ENDPOINT%%://*}"
hostport="${S3_ENDPOINT#*://}"; hostport="${hostport%%/*}"
host="${hostport%%:*}"
if [ "$hostport" = "$host" ]; then
  port=$([ "$proto" = https ] && echo 443 || echo 80)
else
  port="${hostport##*:}"
fi
secure=$([ "$proto" = https ] && echo True || echo False)

mkdir -p "$work"
src="$work/src"
if [ "$(cat "$src/.cairn-commit" 2>/dev/null || true)" != "$commit" ]; then
  rm -rf "$src"; mkdir -p "$src"
  if [ "$repo" = https://github.com/ceph/s3-tests.git ]; then
    curl -fsSL --retry 3 "https://codeload.github.com/ceph/s3-tests/tar.gz/$commit" \
      | tar -xz -C "$src" --strip-components=1
  else
    git -C "$src" init -q
    git -C "$src" fetch -q --depth 1 "$repo" "$commit"
    git -C "$src" checkout -q --detach FETCH_HEAD
  fi
  echo "$commit" > "$src/.cairn-commit"
fi

conf="$work/s3tests.conf"
umask 077
cat > "$conf" <<CONF
[DEFAULT]
host = $host
port = $port
is_secure = $secure
ssl_verify = False

[fixtures]
bucket prefix = cairn-s3t-{random}-

[s3 main]
# Cairn reports the principal id as both Owner ID and DisplayName.
display_name = root
user_id = root
email = main@cairn.invalid
api_name = default
access_key = $S3_MAIN_ACCESS_KEY
secret_key = $S3_MAIN_SECRET_KEY

[s3 alt]
display_name = cairn alt
user_id = alt
email = alt@cairn.invalid
access_key = $alt_ak
secret_key = $alt_sk

[s3 tenant]
display_name = cairn tenant
user_id = tenant
email = tenant@cairn.invalid
tenant = cairn
access_key = $ten_ak
secret_key = $ten_sk

# The suite reads these at import time; IAM/STS tests are deselected by DEFAULT_MARKERS.
[iam]
display_name = cairn iam
user_id = root
email = main@cairn.invalid
access_key = $S3_MAIN_ACCESS_KEY
secret_key = $S3_MAIN_SECRET_KEY

[iam root]
user_id = root
email = main@cairn.invalid
access_key = $S3_MAIN_ACCESS_KEY
secret_key = $S3_MAIN_SECRET_KEY

[iam alt root]
user_id = alt
email = alt@cairn.invalid
access_key = $alt_ak
secret_key = $alt_sk
CONF
umask 022

report="$work/report"
mkdir -p "$report"
junit="$report/junit.xml"
rm -f "$junit"

kargs=()
[ -n "$deselect" ] && kargs=(-k "$deselect")
# Tests that need ACL grants to someone other than the bucket owner: S3 refuses them on its
# default BucketOwnerEnforced buckets, and Cairn has no other ownership mode (acl-grants.txt).
# Exact names via cairn_deselect.py: pytest's --deselect matches by prefix.
deselect_file=
[ "$mode" != full ] && deselect_file="$here/acl-grants.txt"
kargs+=(-p cairn_deselect)
# shellcheck disable=SC2086 # $paths and $S3_TESTS_EXTRA are intentionally word-split
pytest_args=(-p no:cacheprovider -o junit_family=xunit2 --junitxml="$junit" -m "$markers" "${kargs[@]}" ${S3_TESTS_EXTRA:-} $paths)
venv="$work/venv"
if [ ! -x "$venv/bin/pytest" ]; then
  rm -rf "$venv"
  python3 -m venv "$venv" && "$venv/bin/pip" install -q -r "$src/requirements.txt" pytest \
    || { rm -rf "$venv"; echo "virtualenv setup failed (Debian: apt install python3-venv)" >&2; exit 2; }
fi
echo "running s3-tests@${commit:0:12} ($mode)"
(cd "$src" && PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$here${PYTHONPATH:+:$PYTHONPATH}" CAIRN_DESELECT_FILE="$deselect_file" \
  S3TEST_CONF="$conf" S3_USE_SIGV4=true "$venv/bin/pytest" "${pytest_args[@]}") || true

[ -s "$junit" ] || { echo "no junit report produced (collection error?)" >&2; exit 2; }
case "$mode" in
  write) python3 -I "$here/compare.py" --write "$junit" "$expected" "$report" ;;
  full)  python3 -I "$here/compare.py" "$junit" "$expected" "$report" || true ;;
  *)     python3 -I "$here/compare.py" "$junit" "$expected" "$report" ;;
esac
