#!/usr/bin/env bash
# Upgrade test (BUILD-PLAN 1.2): data written by OLD must read back identically with NEW.
#
#   scripts/upgrade-test.sh OLD_BINARY NEW_BINARY [WORKDIR]
#
# For a plain and an encrypted (`encrypt_at_rest`) data directory, OLD writes a mixed workload
# (versioned overwrites and delete markers, an unversioned overwrite + delete into the trash, a
# deleted bucket, multipart, metadata, tags, a bucket policy, an IAM user with a key) and records
# a snapshot: every version's id/etag/size/sha256, metadata, tags, policy, trash, a time-travel
# read and a listing as of an instant before the overwrites. NEW then runs `migrate --dry-run`,
# `fsck --verify full` and `serve`; the same snapshot must be byte-identical, the user's key and
# the root key (sealed in the credential store) must still authenticate, the deleted bucket must
# restore, and NEW must accept new writes. Needs bash, curl (with --aws-sigv4), jq and the aws CLI.
set -euo pipefail

old=$(realpath "${1:?usage: upgrade-test.sh OLD_BINARY NEW_BINARY [WORKDIR]}")
new=$(realpath "${2:?usage: upgrade-test.sh OLD_BINARY NEW_BINARY [WORKDIR]}")
work=${3:-$(mktemp -d)}
mkdir -p "$work"
work=$(realpath "$work")
port=${UPGRADE_TEST_PORT:-19400}
ep=http://127.0.0.1:$port
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 AWS_PAGER= AWS_EC2_METADATA_DISABLED=true
server_pid=
empty_sha=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

say() { printf '==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
s3() { aws --endpoint-url "$ep" "$@"; }
stop_server() {
  [ -n "$server_pid" ] || return 0
  kill -TERM "$server_pid" 2>/dev/null || true
  wait "$server_pid" 2>/dev/null || true
  server_pid=
}
trap stop_server EXIT

start_server() { # bin dir log
  if curl -s -o /dev/null "$ep/"; then fail "something already listens on $ep; set UPGRADE_TEST_PORT"; fi
  "$1" serve --config "$2/tidemark.toml" >>"$3" 2>&1 &
  server_pid=$!
  for _ in $(seq 100); do
    curl -fs -o /dev/null "$ep/readyz" && return 0
    kill -0 "$server_pid" 2>/dev/null || { tail -20 "$3" >&2; fail "server exited ($1)"; }
    sleep 0.2
  done
  tail -20 "$3" >&2
  fail "server not ready ($1)"
}

as_root() { export AWS_ACCESS_KEY_ID=$root_ak AWS_SECRET_ACCESS_KEY=$root_sk; }

# curl with SigV4, for the custom x-tidemark-as-of header the aws CLI cannot send.
signed_curl() {
  curl -fsS --aws-sigv4 "aws:amz:us-east-1:s3" --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY" \
    -H "x-amz-content-sha256: $empty_sha" "$@"
}

workload() { # dir
  local d=$1 mid
  s3 s3api create-bucket --bucket vers >/dev/null
  s3 s3api put-bucket-versioning --bucket vers --versioning-configuration Status=Enabled
  s3 s3api create-bucket --bucket plain >/dev/null
  s3 s3api create-bucket --bucket doomed >/dev/null

  printf 'version one\n' >"$d/k1.v1"
  printf 'version two, longer\n' >"$d/k1.v2"
  head -c 12582912 /dev/urandom >"$d/big"               # 12 MiB: multipart with the CLI defaults
  head -c 300000 /dev/urandom >"$d/meta"
  s3 s3api put-object --bucket vers --key k1 --body "$d/k1.v1" >/dev/null
  s3 s3api put-object --bucket vers --key dir/meta.bin --body "$d/meta" \
    --metadata colour=blue,owner=upgrade-test --content-type application/x-test \
    --tagging 'team=storage&tier=gold' >/dev/null
  s3 s3 cp "$d/big" s3://vers/big.bin --only-show-errors
  s3 s3api put-object --bucket plain --key a --body "$d/k1.v1" >/dev/null
  s3 s3api put-object --bucket doomed --key c --body "$d/k1.v1" >/dev/null
  s3 s3api put-bucket-policy --bucket vers --policy \
    '{"Version":"2012-10-17","Statement":[{"Sid":"DenyDelete","Effect":"Deny","Principal":"*","Action":"s3:DeleteBucket","Resource":"arn:aws:s3:::vers"}]}'

  sleep 1.1
  mid=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  echo "$mid" >"$d/mid"
  sleep 1.1

  s3 s3api put-object --bucket vers --key k1 --body "$d/k1.v2" >/dev/null
  s3 s3api delete-object --bucket vers --key k1 >/dev/null                        # delete marker
  s3 s3api put-object --bucket plain --key a --body "$d/k1.v2" >/dev/null          # unversioned overwrite
  s3 s3api delete-object --bucket plain --key a >/dev/null                         # into the trash
  s3 s3api put-object --bucket plain --key b --body "$d/meta" >/dev/null
  s3 s3api delete-object --bucket doomed --key c >/dev/null
  s3 s3api delete-bucket --bucket doomed                                           # bucket into the trash

  "$bin" admin user add alice >/dev/null
  "$bin" admin --json key create alice >"$d/alice.json"
}

snapshot() { # out
  local out=$1 b
  {
    echo "## buckets"
    s3 s3api list-buckets --query 'Buckets[].Name' --output json
    for b in vers plain; do
      echo "## versions $b"
      s3 s3api list-object-versions --bucket "$b" --output json |
        jq -S '{v: [(.Versions // [])[] | {Key, VersionId, ETag, Size, IsLatest, LastModified}],
                d: [(.DeleteMarkers // [])[] | {Key, VersionId, IsLatest, LastModified}]}'
      s3 s3api list-object-versions --bucket "$b" --output json |
        jq -r '(.Versions // [])[] | "\(.Key)\t\(.VersionId)"' |
        while IFS=$'\t' read -r k v; do
          s3 s3api get-object --bucket "$b" --key "$k" --version-id "$v" "$work/obj" >/dev/null
          echo "$k $v $(sha256sum <"$work/obj" | cut -c1-64)"
        done
    done
    echo "## head + tags"
    s3 s3api head-object --bucket vers --key dir/meta.bin --output json |
      jq -S '{ContentType, ContentLength, ETag, Metadata, VersionId}'
    s3 s3api get-object-tagging --bucket vers --key dir/meta.bin --output json | jq -S '.TagSet | sort_by(.Key)'
    echo "## policy"
    s3 s3api get-bucket-policy --bucket vers --query Policy --output text | jq -S .
    echo "## versioning"
    s3 s3api get-bucket-versioning --bucket vers --output json | jq -S .
    echo "## trash"
    "$bin" admin --json trash ls --bucket plain | jq -S 'if type == "array" then sort_by(.key, .version_id) else . end'
    echo "## time travel to $(cat "$work/$name/mid")"
    signed_curl -H "x-tidemark-as-of: $(cat "$work/$name/mid")" "$ep/vers/k1" | sha256sum | cut -c1-64
    signed_curl -H "x-tidemark-as-of: $(cat "$work/$name/mid")" "$ep/plain/a" | sha256sum | cut -c1-64
    signed_curl -H "x-tidemark-as-of: $(cat "$work/$name/mid")" "$ep/vers?list-type=2" |
      grep -o '<Key>[^<]*</Key>' | sort
  } >"$out"
}

run_case() { # name encrypt(true|false)
  name=$1
  local d=$work/$1 log=$work/$1/server.log
  rm -rf "$d"
  mkdir -p "$d"
  say "[$name] init with $("$old" --version)"
  "$old" init --data-dir "$d/data" >"$d/init.out" 2>&1
  root_ak=$(awk '/access key:/{print $3}' "$d/init.out")
  root_sk=$(awk '/secret key:/{print $3}' "$d/init.out")
  [ -n "$root_ak" ] && [ -n "$root_sk" ] || fail "[$name] no root credentials in init output"
  sed -i "s|^listen = .*|listen = \"127.0.0.1:$port\"|" "$d/data/tidemark.toml"
  sed -i "s|^encrypt_at_rest = .*|encrypt_at_rest = $2|" "$d/data/tidemark.toml"
  export TIDEMARK_ENDPOINT=$ep TIDEMARK_ACCESS_KEY=$root_ak TIDEMARK_SECRET_KEY=$root_sk
  as_root

  bin=$old
  start_server "$old" "$d/data" "$log"
  say "[$name] workload with the old binary"
  workload "$d"
  snapshot "$d/before.txt"
  stop_server
  if [ "$2" = true ]; then
    find "$d/data/blobs" -type f ! -name '*.enc' | grep -q . && fail "[$name] plaintext blob in an encrypted store"
  fi

  say "[$name] new binary: migrate --dry-run, fsck --verify full"
  "$new" migrate --dry-run --data-dir "$d/data" >"$d/migrate.out" 2>&1 || { cat "$d/migrate.out"; fail "[$name] migrate --dry-run"; }
  "$new" fsck --verify full --data-dir "$d/data" >"$d/fsck.out" 2>&1 || { cat "$d/fsck.out"; fail "[$name] fsck found problems"; }

  bin=$new
  start_server "$new" "$d/data" "$log"
  say "[$name] snapshot with $("$new" --version)"
  snapshot "$d/after.txt"
  if ! diff -u "$d/before.txt" "$d/after.txt"; then
    fail "[$name] state differs after upgrade (see diff above)"
  fi

  say "[$name] old credentials still authenticate"
  export AWS_ACCESS_KEY_ID=$(jq -r '.access_key_id // .access_key' "$d/alice.json")
  export AWS_SECRET_ACCESS_KEY=$(jq -r '.secret_access_key // .secret_key' "$d/alice.json")
  [ "$AWS_ACCESS_KEY_ID" != null ] || fail "[$name] could not read alice's key: $(cat "$d/alice.json")"
  out=$(s3 s3api list-buckets 2>&1 || true)
  case $out in *InvalidAccessKeyId* | *SignatureDoesNotMatch*) fail "[$name] alice's key no longer authenticates: $out" ;; esac
  as_root

  say "[$name] restore the deleted bucket, write with the new binary"
  "$new" admin trash restore --bucket doomed >/dev/null
  s3 s3api get-object --bucket doomed --key c "$d/c.back" >/dev/null
  cmp -s "$d/c.back" "$d/k1.v1" || fail "[$name] restored object differs"
  s3 s3api put-object --bucket vers --key after-upgrade --body "$d/k1.v2" >/dev/null
  s3 s3api get-object --bucket vers --key after-upgrade "$d/after.back" >/dev/null
  cmp -s "$d/after.back" "$d/k1.v2" || fail "[$name] write after upgrade"
  stop_server
  "$new" fsck --data-dir "$d/data" >>"$d/fsck.out" 2>&1 || { cat "$d/fsck.out"; fail "[$name] fsck after new writes"; }
  say "[$name] OK ($(grep -c . "$d/before.txt") snapshot lines identical)"
}

run_case plain false
run_case encrypted true
say "upgrade test passed: $("$old" --version) -> $("$new" --version)"
