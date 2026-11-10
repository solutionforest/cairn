#!/usr/bin/env bash
# Soak test (BUILD-PLAN 1.3): one Tidemark under `warp mixed` load plus an rclone "ledger" of
# acknowledged uploads, kill -9 at the end of every segment, and one disk-full window.
#
# Each segment: start the server, run warp mixed in the background, upload a fresh ledger batch
# with rclone, `rclone check` every earlier batch (acknowledged writes must survive every kill),
# sample RSS, then kill -9 the server while warp is still writing.
# Disk-full segment (the middle one by default): a ballast file on the data filesystem leaves less
# free space than `storage.min_free`. Uploads must fail with 507, reads and checks must work, and
# uploads must work again once the ballast is gone.
# End: restart, `rclone check --download` of the whole ledger (byte compare), graceful stop,
# `tidemark fsck --verify full` must be clean.
#
# Usage: scripts/soak.sh [path/to/tidemark]   (default target/release/tidemark)
# Env:   SOAK_DURATION (2h; s/m/h), SOAK_SEGMENT (10m: time between kills),
#        SOAK_FULL_SEGMENT (middle segment index, 0-based; -1 = no disk-full window),
#        SOAK_CONC (8, warp concurrency), SOAK_MAX_RSS_MIB (256), SOAK_PORT (9320),
#        SOAK_DIR (mktemp; must be on the disk under test), SOAK_KEEP=1, WARP, RCLONE
# Output: a markdown report on stdout (segments, RSS, verdict); logs in $SOAK_DIR. Exit 1 on any
#         lost or corrupted object, a write accepted during the full window, fsck findings, or RSS
#         over budget.
# Needs: warp (1.3.0), rclone, curl, fallocate, python3.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
tidemark="${1:-$root/target/release/tidemark}"
warp="${WARP:-warp}"
rclone="${RCLONE:-rclone}"
[ -x "$tidemark" ] || { echo "binary not found: $tidemark" >&2; exit 2; }
for t in "$warp" "$rclone" curl fallocate python3; do
  command -v "$t" > /dev/null || { echo "missing tool: $t" >&2; exit 2; }
done

secs() {
  case "$1" in
    *h) echo $((${1%h} * 3600)) ;;
    *m) echo $((${1%m} * 60)) ;;
    *s) echo "${1%s}" ;;
    *) echo "$1" ;;
  esac
}
total=$(secs "${SOAK_DURATION:-2h}")
seg=$(secs "${SOAK_SEGMENT:-10m}")
segments=$(((total + seg - 1) / seg))
full_seg="${SOAK_FULL_SEGMENT:-$((segments / 2))}"
conc="${SOAK_CONC:-8}"
max_rss="${SOAK_MAX_RSS_MIB:-256}"
port="${SOAK_PORT:-9320}"
work="${SOAK_DIR:-$(mktemp -d /tmp/tidemark-soak.XXXXXX)}"
mkdir -p "$work"
ep="http://127.0.0.1:$port"
ak=soakroot
sk=soakroot-secret-0123456789abcdef
pid=""
wpid=""
run=0
fail=0

cleanup() {
  [ -n "$wpid" ] && kill "$wpid" 2> /dev/null || true
  [ -n "$pid" ] && kill -9 "$pid" 2> /dev/null || true
  rm -f "$work/data/ballast"
  [ "${SOAK_KEEP:-0}" = 1 ] && echo "kept $work" >&2 || rm -rf "$work"
}
trap cleanup EXIT
log() { echo "[$(date -u +%H:%M:%S)] $*" >&2; }
bad() {
  log "FAIL: $*"
  echo "- FAIL: $*" >> "$work/failures.md"
  fail=1
}

if (exec 3<> "/dev/tcp/127.0.0.1/$port") 2> /dev/null; then
  echo "port $port is already in use; set SOAK_PORT" >&2
  exit 2
fi

export RCLONE_CONFIG_TM_TYPE=s3 RCLONE_CONFIG_TM_PROVIDER=Other RCLONE_CONFIG_TM_ENDPOINT="$ep" \
  RCLONE_CONFIG_TM_ACCESS_KEY_ID=$ak RCLONE_CONFIG_TM_SECRET_ACCESS_KEY=$sk \
  RCLONE_CONFIG_TM_REGION=us-east-1 RCLONE_CONFIG_TM_FORCE_PATH_STYLE=true
rc() { "$rclone" --config /dev/null --retries 1 --low-level-retries 2 --stats 0 "$@"; }

TIDEMARK_ROOT_ACCESS_KEY=$ak TIDEMARK_ROOT_SECRET=$sk \
  "$tidemark" init --data-dir "$work/data" --listen "127.0.0.1:$port" > /dev/null

# start: serve with JSON logs into server-<run>.log (one file per process, for per-segment counts).
start() {
  run=$((run + 1))
  "$tidemark" serve --log-format json --config "$work/data/tidemark.toml" > "$work/server-$run.log" 2>&1 &
  pid=$!
  for _ in $(seq 1 240); do
    curl -fs "$ep/readyz" > /dev/null 2>&1 && return 0
    kill -0 "$pid" 2> /dev/null || break
    sleep 0.5
  done
  bad "server did not become ready (see server-$run.log)"
  tail -20 "$work/server-$run.log" >&2
  exit 1
}

rss_mib() { awk '/^VmRSS:/ {printf "%.1f", $2 / 1024}' "/proc/$pid/status"; }
metric() { curl -fs "$ep/metrics" | awk -v m="$1" '$1 == m {printf "%.0f", $2 / 1048576}'; }

# batch N: 40 files, 1 KiB to 8 MiB, random content, in $work/ledger/bN.
batch() {
  python3 -I - "$work/ledger/b$1" "$1" << 'PY'
import os, random, sys
d, n = sys.argv[1], int(sys.argv[2])
os.makedirs(d, exist_ok=True)
r = random.Random(n)
for i in range(40):
    size = int(1024 * (8192 ** r.random()))
    with open(os.path.join(d, f"f{i:02d}.bin"), "wb") as f:
        f.write(os.urandom(size))
PY
}

start
rc mkdir tm:ledger
echo "| segment | phase | requests | MiB in / out | 5xx (of which 507) | ledger batches verified | RSS at kill (MiB) |" > "$work/segments.md"
echo "|---|---|---|---|---|---|---|" >> "$work/segments.md"
rss_values=()
verified=()

for s in $(seq 0 $((segments - 1))); do
  phase=load
  [ "$s" = "$full_seg" ] && phase=disk-full
  log "segment $((s + 1))/$segments ($phase)"
  "$warp" mixed --host "127.0.0.1:$port" --access-key $ak --secret-key $sk --region us-east-1 \
    --lookup path --no-color --duration "$((seg + 60))s" --concurrent "$conc" --obj.size 256KiB \
    --objects 500 --bucket soak-mixed --noclear --benchdata "$work/warp-$s" > "$work/warp-$s.log" 2>&1 &
  wpid=$!
  t0=$(date +%s)

  if [ "$phase" = disk-full ]; then
    free=$(df -B1 --output=avail "$work/data" | tail -1)
    min_free=$(awk -F= '/^min_free/ {gsub(/[ _]/, "", $2); print $2}' "$work/data/tidemark.toml")
    min_free="${min_free:-1073741824}"
    fallocate -l $((free - min_free / 2)) "$work/data/ballast"
    log "ballast: $(df -h --output=avail "$work/data" | tail -1 | tr -d ' ') left (reserve $((min_free / 1048576)) MiB)"
    batch "$s"
    if rc copy "$work/ledger/b$s" "tm:ledger/b$s" > "$work/full-copy.log" 2>&1; then
      bad "uploads were accepted while the disk was full"
    elif ! grep -q "507\|InsufficientStorage" "$work/full-copy.log"; then
      bad "upload during disk-full failed without a 507 (see full-copy.log)"
    fi
    for b in "${verified[@]}"; do
      rc check "$work/ledger/b$b" "tm:ledger/b$b" > /dev/null 2>&1 || bad "batch $b unreadable while disk full"
    done
    curl -fs "$ep/readyz" > /dev/null || bad "server not ready while disk full"
    sleep $((seg / 2))
    rm -f "$work/data/ballast"
    log "ballast removed"
    sleep 5
  else
    batch "$s"
  fi
  if rc copy "$work/ledger/b$s" "tm:ledger/b$s" > "$work/copy-$s.log" 2>&1; then
    verified+=("$s")
  else
    bad "segment $s: ledger upload failed (see copy-$s.log)"
  fi
  for b in "${verified[@]}"; do
    rc check "$work/ledger/b$b" "tm:ledger/b$b" > "$work/check-$s-$b.log" 2>&1 \
      || bad "segment $s: batch $b differs after restart (see check-$s-$b.log)"
  done

  left=$((seg - ($(date +%s) - t0)))
  [ "$left" -gt 0 ] && sleep "$left"
  rss=$(rss_mib)
  io="$(metric tidemark_bytes_in_total) / $(metric tidemark_bytes_out_total)"
  rss_values+=("$rss")
  kill -9 "$pid"
  wait "$pid" 2> /dev/null || true
  kill "$wpid" 2> /dev/null || true
  wait "$wpid" 2> /dev/null || true
  wpid=""
  slog="$work/server-$run.log"
  reqs=$(grep -c '"finished processing request"' "$slog" || true)
  e5=$(grep -c '"status":5[0-9][0-9]' "$slog" || true)
  e507=$(grep -c '"status":507' "$slog" || true)
  [ "$e5" -gt "$e507" ] && bad "segment $((s + 1)): $((e5 - e507)) responses with 5xx other than 507 (see $(basename "$slog"))"
  [ "$phase" = disk-full ] && [ "$e507" -eq 0 ] && bad "segment $((s + 1)): no 507 while the disk was full"
  echo "| $((s + 1)) | $phase | $reqs | $io | $e5 ($e507) | ${#verified[@]} | $rss |" >> "$work/segments.md"
  log "killed -9 at RSS $rss MiB"
  start
done

log "final: byte-compare the whole ledger"
for b in "${verified[@]}"; do
  rc check --download "$work/ledger/b$b" "tm:ledger/b$b" > "$work/final-$b.log" 2>&1 \
    || bad "final: batch $b differs (see final-$b.log)"
done
kill "$pid"
wait "$pid" 2> /dev/null || true
pid=""
if "$tidemark" fsck --config "$work/data/tidemark.toml" --verify full > "$work/fsck.log" 2>&1; then
  fsck=clean
else
  fsck="findings (exit $?)"
  bad "fsck --verify full: $(tail -5 "$work/fsck.log" | tr '\n' ' ')"
fi

peak=$(printf '%s\n' "${rss_values[@]}" | sort -n | tail -1)
awk -v p="$peak" -v m="$max_rss" 'BEGIN { exit !(p > m) }' && bad "RSS $peak MiB over budget $max_rss MiB"

echo "## Soak $(date -u +%Y-%m-%d) — $segments x $((seg / 60)) min, kill -9 between segments"
echo
echo "Machine: $(nproc) CPU, $(awk '/MemTotal/ {printf "%.0f GiB", $2 / 1048576}' /proc/meminfo) RAM, $(uname -sr), data on $(df -T "$work" | awk 'NR == 2 {print $2}')"
echo "Tidemark: $("$tidemark" --version) ($(git -C "$root" rev-parse --short HEAD 2> /dev/null || echo "?")), warp mixed c=$conc 256 KiB, rclone ledger of $((${#verified[@]} * 40)) files"
echo
cat "$work/segments.md"
echo
echo "fsck --verify full: $fsck. RSS at kill: max $peak MiB (budget $max_rss MiB)."
if [ "$fail" = 0 ]; then
  echo "Verdict: PASS"
else
  echo "Verdict: FAIL"
  cat "$work/failures.md"
fi
exit "$fail"
