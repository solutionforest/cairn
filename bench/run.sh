#!/usr/bin/env bash
# Cairn benchmark harness: drives MinIO's `warp` against a running Cairn and records the host
# description next to the results. Method and targets: bench/README.md, DESIGN §13.
#
# Required env: BENCH_ENDPOINT (host:port, no scheme), BENCH_ACCESS_KEY, BENCH_SECRET_KEY
# Optional env: BENCH_TLS=1, BENCH_REGION (us-east-1), BENCH_DURATION (60s),
#               BENCH_CONCURRENCY (32), BENCH_LARGE_SIZE (1GiB), BENCH_LARGE_CONCURRENCY (4),
#               BENCH_LIST_OBJECTS (100000), BENCH_DATA_DIR (Cairn data dir, for the fs line),
#               BENCH_SCENARIOS ("put-small get-small mixed-small put-large get-large list"),
#               WARP (path to warp; default: `warp` on PATH, else the minio/warp container)
set -euo pipefail

WARP_VERSION=v1.8.2
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${BENCH_ENDPOINT:?set BENCH_ENDPOINT=host:port}"
: "${BENCH_ACCESS_KEY:?set BENCH_ACCESS_KEY}"
: "${BENCH_SECRET_KEY:?set BENCH_SECRET_KEY}"
duration="${BENCH_DURATION:-60s}"
conc="${BENCH_CONCURRENCY:-32}"
large="${BENCH_LARGE_SIZE:-1GiB}"
large_conc="${BENCH_LARGE_CONCURRENCY:-4}"
list_objects="${BENCH_LIST_OBJECTS:-100000}"
scenarios="${BENCH_SCENARIOS:-put-small get-small mixed-small put-large get-large list}"

if [ -n "${WARP:-}" ]; then
  warp=("$WARP")
elif command -v warp >/dev/null 2>&1; then
  warp=(warp)
elif command -v docker >/dev/null 2>&1; then
  warp=(docker run --rm --network host -v "$PWD:/work" -w /work "minio/warp:$WARP_VERSION")
else
  echo "warp not found: go install github.com/minio/warp@$WARP_VERSION, or install docker" >&2
  exit 2
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
out="$here/results/$stamp"
mkdir -p "$out"
cd "$out"

{
  echo "# Host"
  echo
  echo "- date (UTC): $stamp"
  echo "- cairn: $(cairn --version 2>/dev/null || echo unknown) @ $(git -C "$here" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "- warp: $("${warp[@]}" --version 2>/dev/null | head -1 || echo "$WARP_VERSION")"
  echo "- cpu: $(lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1) ($(nproc) vCPU)"
  echo "- memory: $(free -h 2>/dev/null | awk '/^Mem:/ {print $2}')"
  echo "- kernel: $(uname -sr)"
  if [ -n "${BENCH_DATA_DIR:-}" ]; then
    echo "- data dir fs: $(df -hT "$BENCH_DATA_DIR" | awk 'NR==2 {print $2, $3" total on", $1}')"
    dev="$(df --output=source "$BENCH_DATA_DIR" | tail -1)"
    echo "- disk: $(lsblk -no MODEL,ROTA,SIZE "$dev" 2>/dev/null | head -1 || echo unknown)"
  fi
  echo "- endpoint: $BENCH_ENDPOINT (tls=${BENCH_TLS:-0}), client on the same host: $( [ "${BENCH_ENDPOINT%%:*}" = 127.0.0.1 ] && echo yes || echo no)"
} > host.md
cat host.md

common=(--host "$BENCH_ENDPOINT" --access-key "$BENCH_ACCESS_KEY" --secret-key "$BENCH_SECRET_KEY"
        --region "${BENCH_REGION:-us-east-1}" --duration "$duration")
[ "${BENCH_TLS:-0}" = 1 ] && common+=(--tls --insecure)

run() {
  local name="$1"; shift
  echo "== $name: warp $*"
  "${warp[@]}" "$@" "${common[@]}" --bucket "bench-$name" --benchdata "$name" 2>&1 | tee "$name.txt"
}

for s in $scenarios; do
  case "$s" in
    put-small)   run put-small   put   --obj.size 4KiB  --concurrent "$conc" ;;
    get-small)   run get-small   get   --obj.size 4KiB  --objects 10000 --concurrent "$conc" ;;
    mixed-small) run mixed-small mixed --obj.size 64KiB --objects 5000  --concurrent "$conc" ;;
    put-large)   run put-large   put   --obj.size "$large" --concurrent "$large_conc" ;;
    get-large)   run get-large   get   --obj.size "$large" --objects 8 --concurrent "$large_conc" ;;
    list)        run list        list  --obj.size 1KiB  --objects "$list_objects" --concurrent "$conc" ;;
    *) echo "unknown scenario $s" >&2; exit 2 ;;
  esac
done

echo
echo "raw results in $out; copy the summary lines into bench/RESULTS.md"
