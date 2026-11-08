#!/usr/bin/env bash
# Start a throwaway Cairn for s3-tests: init a fresh data dir with a fixed root credential,
# serve it in the background, create a second user (`s3alt`, allowed `s3:*`: the suite's setup
# lists and deletes the alt principal's buckets, so a policy-less user errors every test) and
# print the env for run.sh. Cairn has one account; alt is a second IAM user in it, so tests that
# expect cross-account denial without a policy are expected to fail.
#
# Usage: eval "$(scripts/s3-tests/start-cairn.sh [path/to/cairn])"
# Env:   S3T_PORT (9000), S3T_DATA (mktemp), S3T_LOG (cairn.log in the data dir's parent)
# Prints: export S3_ENDPOINT=... S3_MAIN_*=... S3_ALT_*=... CAIRN_PID=...
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
cairn="${1:-$root/target/debug/cairn}"
[ -x "$cairn" ] || { echo "cairn binary not found at $cairn" >&2; exit 2; }
port="${S3T_PORT:-9000}"
data="${S3T_DATA:-$(mktemp -d /tmp/cairn-s3t.XXXXXX)/data}"
log="${S3T_LOG:-$(dirname "$data")/cairn.log}"
ak=s3testsroot
sk=s3testsroot-secret-0123456789abcdef
ep="http://127.0.0.1:$port"

CAIRN_ROOT_ACCESS_KEY="$ak" CAIRN_ROOT_SECRET="$sk" \
  "$cairn" init --data-dir "$data" --listen "127.0.0.1:$port" >&2
nohup "$cairn" serve --config "$data/cairn.toml" > "$log" 2>&1 &
pid=$!
for _ in $(seq 1 120); do
  curl -fs "$ep/readyz" > /dev/null 2>&1 && break
  sleep 0.5
done
curl -fs "$ep/readyz" > /dev/null || { echo "cairn did not become ready" >&2; cat "$log" >&2; exit 2; }

export CAIRN_ENDPOINT="$ep" CAIRN_ACCESS_KEY="$ak" CAIRN_SECRET_KEY="$sk"
"$cairn" admin user add s3alt > /dev/null
printf '%s' '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}' \
  | "$cairn" admin user policy put s3alt s3-all - > /dev/null
alt_json="$("$cairn" admin --json key create s3alt)"
alt_ak="$(printf '%s' "$alt_json" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["access_key_id"])')"
alt_sk="$(printf '%s' "$alt_json" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["secret_access_key"])')"

cat <<ENV
export S3_ENDPOINT=$ep
export S3_MAIN_ACCESS_KEY=$ak S3_MAIN_SECRET_KEY=$sk
export S3_ALT_ACCESS_KEY=$alt_ak S3_ALT_SECRET_KEY=$alt_sk
export CAIRN_PID=$pid CAIRN_LOG=$log
ENV
