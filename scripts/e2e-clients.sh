#!/usr/bin/env bash
# End-to-end run of real S3 clients (aws CLI, rclone, MinIO mc) against a throwaway `cairn serve`.
# Prints a markdown results table (paste it into docs/COMPAT.md "Manual client runs") and exits
# non-zero if any step failed. PRODUCTION-READINESS A8.
#
# Usage: scripts/e2e-clients.sh [path/to/cairn]     (default: target/release/cairn, else target/debug/cairn)
# Env:   E2E_PORT (default 9100), E2E_CLIENTS ("aws rclone mc"), E2E_BIG_MIB (24, multipart size),
#        E2E_KEEP=1 keeps the temp dir.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cairn="${1:-}"
if [ -z "$cairn" ]; then
  for c in "$root/target/release/cairn" "$root/target/debug/cairn"; do
    [ -x "$c" ] && { cairn="$c"; break; }
  done
fi
[ -x "${cairn:-}" ] || { echo "cairn binary not found; build with cargo build -p cairn-cli" >&2; exit 2; }
port="${E2E_PORT:-9100}"
clients="${E2E_CLIENTS:-aws rclone mc}"
big_mib="${E2E_BIG_MIB:-24}"
ep="http://127.0.0.1:$port"

work="$(mktemp -d /tmp/cairn-e2e.XXXXXX)"
srv_pid=""
cleanup() {
  [ -n "$srv_pid" ] && kill "$srv_pid" 2>/dev/null && wait "$srv_pid" 2>/dev/null
  [ "${E2E_KEEP:-0}" = 1 ] && echo "kept $work" >&2 || rm -rf "$work"
}
trap cleanup EXIT

"$cairn" init --data-dir "$work/data" --listen "127.0.0.1:$port" > "$work/init.txt" || exit 2
ak="$(sed -n 's/^ *access key: *//p' "$work/init.txt")"
sk="$(sed -n 's/^ *secret key: *//p' "$work/init.txt")"
[ -n "$ak" ] && [ -n "$sk" ] || { echo "could not parse root credentials" >&2; exit 2; }
"$cairn" serve --config "$work/data/cairn.toml" > "$work/server.log" 2>&1 &
srv_pid=$!
for _ in $(seq 1 100); do
  curl -fs "$ep/healthz" > /dev/null 2>&1 && break
  sleep 0.2
done
curl -fs "$ep/readyz" > /dev/null || { echo "server did not become ready" >&2; cat "$work/server.log" >&2; exit 2; }

# Test data: a tree of small files, one file with spaces/unicode in its name, one multipart-sized file.
src="$work/src"
mkdir -p "$src/sub/deeper"
for i in $(seq 1 20); do head -c $((i * 1000)) /dev/urandom > "$src/small-$i.bin"; done
echo "hello cairn" > "$src/sub/hello.txt"
echo "nested" > "$src/sub/deeper/nested.txt"
echo "odd name" > "$src/sub/with space & ünïcode.txt"
head -c $((big_mib * 1024 * 1024)) /dev/urandom > "$work/big.bin"

results=()
fails=0
step() {
  local client="$1" what="$2"; shift 2
  local log="$work/step.log"
  if "$@" > "$log" 2>&1; then
    results+=("| $client | $what | pass |")
  else
    results+=("| $client | $what | **FAIL** (\`$(tail -1 "$log" | tr '|' '/' | cut -c1-120)\`) |")
    fails=$((fails + 1))
    { echo "---- $client: $what"; tail -20 "$log"; } >&2
  fi
}
same_tree() { diff -r "$1" "$2"; }

export AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_DEFAULT_REGION=us-east-1 AWS_REGION=us-east-1
# aws CLI v1 presigns with SigV2 unless told otherwise; Cairn is SigV4-only (COMPAT.md).
printf '[default]\ns3 =\n    signature_version = s3v4\n' > "$work/aws-config"
export AWS_CONFIG_FILE="$work/aws-config" AWS_SHARED_CREDENTIALS_FILE=/dev/null

run_aws() {
  local a=(aws --endpoint-url "$ep")
  local b=s3://e2e-aws
  step aws "s3 mb" "${a[@]}" s3 mb "$b"
  step aws "s3 ls (buckets)" sh -c "$(printf '%q ' "${a[@]}") s3 ls | grep -q e2e-aws"
  step aws "s3 cp upload (small)" "${a[@]}" s3 cp "$src/sub/hello.txt" "$b/hello.txt"
  step aws "s3 cp upload (${big_mib} MiB, multipart)" "${a[@]}" s3 cp "$work/big.bin" "$b/big.bin"
  step aws "s3 cp download + cmp (multipart)" sh -c "$(printf '%q ' "${a[@]}") s3 cp $b/big.bin $work/aws-big.bin && cmp $work/big.bin $work/aws-big.bin"
  step aws "s3 cp - (stdin stream)" sh -c "echo streamed | $(printf '%q ' "${a[@]}") s3 cp - $b/stream.txt && $(printf '%q ' "${a[@]}") s3 cp $b/stream.txt - | grep -q streamed"
  step aws "s3 cp --recursive" "${a[@]}" s3 cp --recursive "$src" "$b/rec/"
  step aws "s3 sync up" "${a[@]}" s3 sync "$src" "$b/sync/"
  step aws "s3 sync up again (no-op)" sh -c "test -z \"\$($(printf '%q ' "${a[@]}") s3 sync $src $b/sync/)\""
  step aws "s3 sync down + diff" sh -c "$(printf '%q ' "${a[@]}") s3 sync $b/sync/ $work/aws-down && diff -r $src $work/aws-down"
  step aws "s3 ls --recursive (count)" sh -c "test \"\$($(printf '%q ' "${a[@]}") s3 ls --recursive $b/sync/ | wc -l)\" -eq 23"
  step aws "s3 ls prefix (delimiter)" sh -c "$(printf '%q ' "${a[@]}") s3 ls $b/sync/sub/ | grep -q 'PRE deeper/'"
  rm "$src/small-1.bin"
  step aws "s3 sync --delete" sh -c "$(printf '%q ' "${a[@]}") s3 sync --delete $src $b/sync/ | grep -q 'delete: $b/sync/small-1.bin'"
  head -c 1000 /dev/urandom > "$src/small-1.bin"
  step aws "s3 mv" "${a[@]}" s3 mv "$b/hello.txt" "$b/moved.txt"
  step aws "s3 cp (server-side copy)" "${a[@]}" s3 cp "$b/moved.txt" "$b/copied.txt"
  step aws "s3 presign (SigV2 URL) → refused" sh -c "! curl -fs \"\$(AWS_CONFIG_FILE=/dev/null $(printf '%q ' "${a[@]}") s3 presign $b/copied.txt)\""
  step aws "s3 presign (SigV4) + curl GET" sh -c "curl -fs \"\$($(printf '%q ' "${a[@]}") s3 presign $b/copied.txt)\" | grep -q 'hello cairn'"
  step aws "s3api head-object" "${a[@]}" s3api head-object --bucket e2e-aws --key big.bin
  step aws "s3 rm" "${a[@]}" s3 rm "$b/copied.txt"
  step aws "s3 rm --recursive" "${a[@]}" s3 rm --recursive "$b/rec/"
  step aws "s3 rb (non-empty → refused)" sh -c "! $(printf '%q ' "${a[@]}") s3 rb $b"
  step aws "s3 rb --force" "${a[@]}" s3 rb --force "$b"
  step aws "s3 ls (bucket gone)" sh -c "! $(printf '%q ' "${a[@]}") s3 ls | grep -q e2e-aws"
}

run_rclone() {
  export RCLONE_CONFIG=/dev/null RCLONE_CONFIG_CAIRN_TYPE=s3 RCLONE_CONFIG_CAIRN_PROVIDER=Other \
    RCLONE_CONFIG_CAIRN_ACCESS_KEY_ID="$ak" RCLONE_CONFIG_CAIRN_SECRET_ACCESS_KEY="$sk" \
    RCLONE_CONFIG_CAIRN_ENDPOINT="$ep" RCLONE_CONFIG_CAIRN_REGION=us-east-1 \
    RCLONE_CONFIG_CAIRN_FORCE_PATH_STYLE=true
  local r=(rclone --retries 1 --low-level-retries 1)
  step rclone "mkdir" "${r[@]}" mkdir cairn:e2e-rclone
  step rclone "sync up" "${r[@]}" sync "$src" cairn:e2e-rclone/sync
  step rclone "check (size + md5)" "${r[@]}" check "$src" cairn:e2e-rclone/sync
  step rclone "sync up again (0 transfers)" sh -c "rclone --retries 1 sync -v $src cairn:e2e-rclone/sync 2>&1 | grep -Eq 'There was nothing to transfer|Transferred: *0 / 0'"
  step rclone "sync down + diff" sh -c "rclone --retries 1 sync cairn:e2e-rclone/sync $work/rc-down && diff -r $src $work/rc-down"
  step rclone "copyto (${big_mib} MiB, multipart 5 MiB chunks)" "${r[@]}" copyto --s3-upload-cutoff 5M --s3-chunk-size 5M "$work/big.bin" cairn:e2e-rclone/big.bin
  step rclone "cat + cmp (multipart)" sh -c "rclone cat cairn:e2e-rclone/big.bin | cmp - $work/big.bin"
  step rclone "lsf -R (count)" sh -c "test \"\$(rclone lsf -R --files-only cairn:e2e-rclone/sync | wc -l)\" -eq 23"
  rm "$src/small-2.bin"
  step rclone "sync (deletes extraneous)" sh -c "rclone --retries 1 sync $src cairn:e2e-rclone/sync && ! rclone lsf cairn:e2e-rclone/sync | grep -qx small-2.bin"
  head -c 2000 /dev/urandom > "$src/small-2.bin"
  step rclone "moveto (server-side copy + delete)" "${r[@]}" moveto cairn:e2e-rclone/big.bin cairn:e2e-rclone/big2.bin
  step rclone "delete" "${r[@]}" delete cairn:e2e-rclone/sync
  step rclone "purge (bucket)" "${r[@]}" purge cairn:e2e-rclone
  step rclone "lsd (bucket gone)" sh -c "! rclone lsd cairn: | grep -q e2e-rclone"
}

run_mc() {
  local cfg="$work/mc"
  local m=(mc --config-dir "$cfg" --no-color)
  step mc "alias set" "${m[@]}" alias set cairn "$ep" "$ak" "$sk" --api S3v4 --path on
  step mc "admin-free ping (ls)" "${m[@]}" ls cairn
  step mc "mb" "${m[@]}" mb cairn/e2e-mc
  step mc "cp (small)" "${m[@]}" cp "$src/sub/hello.txt" cairn/e2e-mc/hello.txt
  step mc "cp (${big_mib} MiB, multipart)" "${m[@]}" cp "$work/big.bin" cairn/e2e-mc/big.bin
  step mc "cat + cmp (multipart)" sh -c "$(printf '%q ' "${m[@]}") cat cairn/e2e-mc/big.bin | cmp - $work/big.bin"
  step mc "pipe (stdin stream)" sh -c "echo piped | $(printf '%q ' "${m[@]}") pipe cairn/e2e-mc/piped.txt && $(printf '%q ' "${m[@]}") cat cairn/e2e-mc/piped.txt | grep -q piped"
  step mc "cp --recursive" "${m[@]}" cp --recursive "$src/" cairn/e2e-mc/rec/
  step mc "mirror up" "${m[@]}" mirror "$src" cairn/e2e-mc/mirror
  step mc "mirror down + diff" sh -c "$(printf '%q ' "${m[@]}") mirror cairn/e2e-mc/mirror $work/mc-down && diff -r $src $work/mc-down"
  step mc "diff (no differences)" sh -c "test -z \"\$($(printf '%q ' "${m[@]}") diff $src cairn/e2e-mc/mirror)\""
  step mc "ls --recursive (count)" sh -c "test \"\$($(printf '%q ' "${m[@]}") ls --recursive cairn/e2e-mc/mirror | wc -l)\" -eq 23"
  step mc "stat" "${m[@]}" stat cairn/e2e-mc/big.bin
  step mc "tag set / list" sh -c "$(printf '%q ' "${m[@]}") tag set cairn/e2e-mc/hello.txt 'k=v' && $(printf '%q ' "${m[@]}") tag list cairn/e2e-mc/hello.txt | grep -q k"
  step mc "version enable + info" sh -c "$(printf '%q ' "${m[@]}") version enable cairn/e2e-mc && $(printf '%q ' "${m[@]}") version info cairn/e2e-mc | grep -qi enabled"
  step mc "ls --versions" sh -c "$(printf '%q ' "${m[@]}") cp $src/sub/hello.txt cairn/e2e-mc/hello.txt && test \"\$($(printf '%q ' "${m[@]}") ls --versions cairn/e2e-mc/hello.txt | wc -l)\" -ge 2"
  step mc "share download + curl" sh -c "curl -fs \"\$($(printf '%q ' "${m[@]}") share download --json cairn/e2e-mc/piped.txt | python3 -I -c 'import json,sys; print(json.load(sys.stdin)[\"share\"])')\" | grep -q piped"
  step mc "rm" "${m[@]}" rm cairn/e2e-mc/piped.txt
  step mc "rm --recursive --force" "${m[@]}" rm --recursive --force cairn/e2e-mc/rec
  step mc "rb --force (versioned bucket)" "${m[@]}" rb --force cairn/e2e-mc
  step mc "ls (bucket gone)" sh -c "! $(printf '%q ' "${m[@]}") ls cairn | grep -q e2e-mc"
}

versions=()
for c in $clients; do
  case "$c" in
    aws) versions+=("$(aws --version 2>&1 | head -1)"); run_aws ;;
    rclone) versions+=("$(rclone version 2>&1 | head -1)"); run_rclone ;;
    mc) versions+=("mc $(mc --version 2>&1 | head -1 | awk '{print $3}')"); run_mc ;;
    *) echo "unknown client $c" >&2; exit 2 ;;
  esac
done

if grep -Eq ' (ERROR|panicked)' "$work/server.log"; then
  echo "server log has errors:" >&2; grep -E ' (ERROR|panicked)' "$work/server.log" | head -20 >&2
fi

echo
echo "Run $(date -u +%Y-%m-%dT%H:%MZ), cairn $("$cairn" --version | awk '{print $2}') @ $(git -C "$root" rev-parse --short HEAD) ($(basename "$(dirname "$cairn")") build)"
printf -- '- %s\n' "${versions[@]}"
echo
echo "| Client | Step | Result |"
echo "|---|---|---|"
printf '%s\n' "${results[@]}"
echo
echo "$(( ${#results[@]} - fails ))/${#results[@]} steps passed"
[ "$fails" -eq 0 ]
