#!/usr/bin/env bash
# Throughput and latency of one Tidemark node under MinIO's `warp` (PRODUCTION-READINESS, BUILD-PLAN
# 1.7) and a markdown table on stdout. Five runs against a fresh `tidemark init` data dir:
#   small PUT and GET (4 KiB, BENCH_SMALL_CONC), large PUT and GET (64 MiB, BENCH_LARGE_CONC),
#   and LIST (10 000 x 1 KiB objects, 1 000-key pages).
# Numbers only mean something for a release build on a quiet machine with local disk. Always
# report the machine next to them (the script prints nproc, memory and the kernel).
#
# Usage: scripts/bench.sh [path/to/tidemark]   (default target/release/tidemark)
# Env:   BENCH_DURATION (60s per run), BENCH_SMALL_CONC (16), BENCH_LARGE_CONC (4),
#        BENCH_PORT (9310), BENCH_DIR (mktemp; the data dir must be on the disk under test),
#        BENCH_KEEP=1 (keep the work dir with warp's raw .csv.zst data), WARP (warp binary)
# Needs: warp (github.com/minio/warp; 1.3.0 is the last release with a plain Linux tarball), curl.
#        Linux and macOS (bash 3.2 is enough).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
# shellcheck source=scripts/host.sh
. "$here/host.sh"
tidemark="${1:-$root/target/release/tidemark}"
warp="${WARP:-warp}"
[ -x "$tidemark" ] || { echo "binary not found: $tidemark (cargo build --release -p tidemark-cli)" >&2; exit 2; }
command -v "$warp" > /dev/null || { echo "warp not found (set WARP=/path/to/warp)" >&2; exit 2; }
dur="${BENCH_DURATION:-60s}"
small_c="${BENCH_SMALL_CONC:-16}"
large_c="${BENCH_LARGE_CONC:-4}"
port="${BENCH_PORT:-9310}"
work="${BENCH_DIR:-$(mktemp -d /tmp/tidemark-bench.XXXXXX)}"
mkdir -p "$work"
ak=benchroot
sk=benchroot-secret-0123456789abcdef
pid=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2> /dev/null && wait "$pid" 2> /dev/null || true
  [ "${BENCH_KEEP:-0}" = 1 ] && echo "kept $work" >&2 || rm -rf "$work"
}
trap cleanup EXIT

if (exec 3<> "/dev/tcp/127.0.0.1/$port") 2> /dev/null; then
  echo "port $port is already in use; set BENCH_PORT" >&2
  exit 2
fi
TIDEMARK_ROOT_ACCESS_KEY=$ak TIDEMARK_ROOT_SECRET=$sk \
  "$tidemark" init --data-dir "$work/data" --listen "127.0.0.1:$port" > /dev/null
"$tidemark" serve --config "$work/data/tidemark.toml" > "$work/server.log" 2>&1 &
pid=$!
for _ in $(seq 1 120); do
  curl -fs "http://127.0.0.1:$port/readyz" > /dev/null 2>&1 && break
  sleep 0.5
done
curl -fs "http://127.0.0.1:$port/readyz" > /dev/null || { cat "$work/server.log" >&2; exit 2; }

# run NAME OP CONC ARGS...: one warp run; prints "| NAME | CONC | MiB/s | obj/s | p50 | p99 |".
run() {
  local name=$1 op=$2 conc=$3
  shift 3
  local log="$work/$name.log"
  echo "== $name ($op, concurrency $conc, $dur)" >&2
  "$warp" "$op" --host "127.0.0.1:$port" --access-key $ak --secret-key $sk --region us-east-1 \
    --lookup path --no-color --duration "$dur" --concurrent "$conc" \
    --bucket "bench-$name" --benchdata "$work/$name" "$@" > "$log" 2>&1 || {
    cat "$log" >&2
    exit 1
  }
  local OP
  OP=$(printf '%s' "$op" | tr '[:lower:]' '[:upper:]')
  awk -v name="$name" -v conc="$conc" -v op="$OP" '
    $0 ~ "^Report: " op "\\." { on = 1; next }
    on && /\* Average:/ {
      mib = "-"
      if (match($0, /[0-9.]+ [KMGT]?i?B\/s/)) mib = substr($0, RSTART, RLENGTH)
      if (match($0, /[0-9.]+ obj\/s/)) obj = substr($0, RSTART, RLENGTH - 6)
      if (op == "LIST") { mib = obj " keys/s"; obj = "-" }
    }
    on && /\* Reqs:/ {
      match($0, /50%: [^,]+/); p50 = substr($0, RSTART + 5, RLENGTH - 5)
      match($0, /99%: [^,]+/); p99 = substr($0, RSTART + 5, RLENGTH - 5)
      on = 0
    }
    END {
      if (obj == "") { print "no " op " report in warp output" > "/dev/stderr"; exit 1 }
      printf "| %s | %s | %s | %s | %s | %s |\n", name, conc, mib, obj, p50, p99
    }' "$log"
}

echo "Machine: $(host_line "$work")"
echo "Tidemark: $("$tidemark" --version 2>/dev/null || echo unknown), warp: $("$warp" --version | head -1)"
echo
echo "| workload | concurrency | throughput | ops/s | p50 | p99 |"
echo "|---|---|---|---|---|---|"
run put-4k put "$small_c" --obj.size 4KiB
run get-4k get "$small_c" --obj.size 4KiB --objects 2500
run put-64m put "$large_c" --obj.size 64MiB
run get-64m get "$large_c" --obj.size 64MiB --objects 32
run list list "$large_c" --obj.size 1KiB --objects 10000 --max-keys 1000
