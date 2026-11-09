#!/usr/bin/env bash
# Start a throwaway Tidemark for s3-tests: init a fresh data dir with a fixed root credential,
# serve it in the background, create a second user (`s3alt`, allowed `s3:*`: the suite's setup
# lists and deletes the alt principal's buckets, so a policy-less user errors every test) and
# print the env for run.sh. Tidemark has one account; alt is a second IAM user in it, so tests that
# expect cross-account denial without a policy are expected to fail.
#
# Usage: eval "$(scripts/s3-tests/start-tidemark.sh [path/to/tidemark])"
# Env:   S3T_PORT (9000), S3T_DATA (mktemp), S3T_LOG (tidemark.log in the data dir's parent)
# Prints: export S3_ENDPOINT=... S3_MAIN_*=... S3_ALT_*=... TIDEMARK_PID=...
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
tidemark="${1:-$root/target/debug/tidemark}"
[ -x "$tidemark" ] || { echo "tidemark binary not found at $tidemark" >&2; exit 2; }
port="${S3T_PORT:-9000}"
data="${S3T_DATA:-$(mktemp -d /tmp/tidemark-s3t.XXXXXX)/data}"
log="${S3T_LOG:-$(dirname "$data")/tidemark.log}"
ak=s3testsroot
sk=s3testsroot-secret-0123456789abcdef
ep="http://127.0.0.1:$port"

TIDEMARK_ROOT_ACCESS_KEY="$ak" TIDEMARK_ROOT_SECRET="$sk" \
  "$tidemark" init --data-dir "$data" --listen "127.0.0.1:$port" >&2
# Encrypt at rest with the keys/master.key `init` created, so the suite's sse_s3 tests (bucket
# encryption, AES256 PUT/GET) run against an encrypted store, as a production SSE-S3 setup would.
TIDEMARK_STORAGE_ENCRYPT_AT_REST=true \
  nohup "$tidemark" serve --config "$data/tidemark.toml" > "$log" 2>&1 &
pid=$!
for _ in $(seq 1 120); do
  curl -fs "$ep/readyz" > /dev/null 2>&1 && break
  sleep 0.5
done
curl -fs "$ep/readyz" > /dev/null || { echo "tidemark did not become ready" >&2; cat "$log" >&2; exit 2; }

export TIDEMARK_ENDPOINT="$ep" TIDEMARK_ACCESS_KEY="$ak" TIDEMARK_SECRET_KEY="$sk"
"$tidemark" admin user add s3alt > /dev/null
printf '%s' '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}' \
  | "$tidemark" admin user policy put s3alt s3-all - > /dev/null
alt_json="$("$tidemark" admin --json key create s3alt)"
alt_ak="$(printf '%s' "$alt_json" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["access_key_id"])')"
alt_sk="$(printf '%s' "$alt_json" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["secret_access_key"])')"

cat <<ENV
export S3_ENDPOINT=$ep
export S3_MAIN_ACCESS_KEY=$ak S3_MAIN_SECRET_KEY=$sk
export S3_ALT_ACCESS_KEY=$alt_ak S3_ALT_SECRET_KEY=$alt_sk
export TIDEMARK_PID=$pid TIDEMARK_LOG=$log
ENV
