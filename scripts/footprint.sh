#!/usr/bin/env bash
# Measure Cairn's footprint (PRODUCTION-READINESS E1, E2) and print a markdown table:
#   1. binary size (bytes / MiB) and whether it is statically linked;
#   2. idle RSS after a settle period (default 110 s, the method VaultS3 publishes) on a fresh
#      `cairn init` data dir, read from /proc/<pid>/status (VmRSS);
#   3. peak RSS (VmHWM, or 0.2 s VmRSS sampling where VmHWM is missing) while streaming a FOOTPRINT_GIB (default 10) GiB object up and back down
#      through `aws s3 cp -` (multipart, never materialised on disk client-side), with the
#      download checked byte-for-byte via sha256.
# Numbers only mean something for a release build: `cargo build --release -p cairn-cli`
# (static musl for the published number: --target x86_64-unknown-linux-musl).
#
# Usage: scripts/footprint.sh [path/to/cairn]   (default target/release/cairn)
# Env:   FOOTPRINT_SETTLE (110), FOOTPRINT_GIB (10), FOOTPRINT_PORT (0 = ephemeral),
#        FOOTPRINT_MIB (overrides GIB, for smoke runs), FOOTPRINT_SKIP_TRANSFER=1 (idle + size only), FOOTPRINT_KEEP=1 (keep temp dir)
#        FOOTPRINT_MAX_BINARY_BYTES, FOOTPRINT_MAX_IDLE_MIB, FOOTPRINT_MAX_PEAK_MIB: exit 1 when exceeded (CI budget)
# gVisor (dmesg/uname show it) keeps the whole binary resident and faults anonymous memory in
# coarse chunks, so its idle RSS is high and noisy; budget numbers come from a regular kernel.
# Needs: aws CLI, sha256sum, curl. Linux only (/proc).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cairn="${1:-$root/target/release/cairn}"
[ -x "$cairn" ] || { echo "binary not found: $cairn (cargo build --release -p cairn-cli)" >&2; exit 2; }
settle="${FOOTPRINT_SETTLE:-110}"
gib="${FOOTPRINT_GIB:-10}"
port="${FOOTPRINT_PORT:-0}"

work="$(mktemp -d /tmp/cairn-footprint.XXXXXX)"
pid=""
sampler=""
cleanup() {
  [ -n "$sampler" ] && kill "$sampler" 2>/dev/null || true
  [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null || true
  [ "${FOOTPRINT_KEEP:-0}" = 1 ] && echo "kept $work" >&2 || rm -rf "$work"
}
trap cleanup EXIT

kib() { awk '/^'"$1"':/ {print $2}' "/proc/$pid/status"; }
mib() { awk -v k="$1" 'BEGIN { printf "%.1f", k / 1024 }'; }

size=$(stat -c %s "$cairn")
if file -b "$cairn" 2>/dev/null | grep -qE 'static(ally|-pie) linked'; then linkage=static
elif ldd "$cairn" 2>&1 | grep -qE 'not a dynamic|statically linked'; then linkage=static
else linkage=dynamic; fi
profile="$(basename "$(dirname "$cairn")")"

ak=footprintroot
sk=footprint-secret-0123456789abcdef
CAIRN_ROOT_ACCESS_KEY="$ak" CAIRN_ROOT_SECRET="$sk" \
  "$cairn" init --data-dir "$work/data" --listen "127.0.0.1:$port" > /dev/null
"$cairn" --log-format json serve --config "$work/data/cairn.toml" > "$work/server.log" 2>&1 &
pid=$!
addr=""
for _ in $(seq 1 100); do
  kill -0 "$pid" 2>/dev/null || { echo "server exited:" >&2; cat "$work/server.log" >&2; exit 2; }
  addr=$(sed -n 's/.*"cairn listening".*"addr":"\([^"]*\)".*/\1/p; s/.*"addr":"\([^"]*\)".*"cairn listening".*/\1/p' "$work/server.log" | head -1)
  [ -n "$addr" ] && curl -fs "http://$addr/readyz" > /dev/null 2>&1 && break
  sleep 0.2
done
[ -n "$addr" ] || { echo "server did not become ready" >&2; cat "$work/server.log" >&2; exit 2; }
ep="http://$addr"
start_rss=$(kib VmRSS)
echo "idle settle ${settle}s ..." >&2
sleep "$settle"
idle_rss=$(kib VmRSS)

peak_rss=""
up_s="" down_s=""
if [ "${FOOTPRINT_SKIP_TRANSFER:-0}" != 1 ]; then
  export AWS_ACCESS_KEY_ID="$ak" AWS_SECRET_ACCESS_KEY="$sk" AWS_DEFAULT_REGION=us-east-1 \
    AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null
  aws=(aws --endpoint-url "$ep")
  "${aws[@]}" s3 mb s3://footprint > /dev/null
  bytes=$(( ${FOOTPRINT_MIB:-$((gib * 1024))} * 1024 * 1024 ))
  # Pseudo-random, incompressible, reproducible stream: no 10 GiB file on the client side.
  command -v openssl > /dev/null || { echo "needs openssl (reproducible stream)" >&2; exit 2; }
  # openssl dies of SIGPIPE when head has enough; that is expected, not a failure.
  stream() { { openssl enc -aes-128-ctr -nosalt -pass pass:cairn-footprint -in /dev/zero 2>/dev/null || true; } | head -c "$bytes"; }
  (while kill -0 "$pid" 2>/dev/null; do kib VmRSS >> "$work/rss.samples"; sleep 0.2; done) &
  sampler=$!
  echo "uploading $((bytes / 1048576)) MiB ..." >&2
  t0=$(date +%s)
  stream | "${aws[@]}" s3 cp - s3://footprint/big --expected-size "$bytes"
  t1=$(date +%s)
  echo "downloading $((bytes / 1048576)) MiB ..." >&2
  down_sum=$("${aws[@]}" s3 cp s3://footprint/big - | sha256sum | cut -d' ' -f1)
  t2=$(date +%s)
  up_s=$((t1 - t0)); down_s=$((t2 - t1))
  up_sum=$(stream | sha256sum | cut -d' ' -f1)
  [ "$up_sum" = "$down_sum" ] || { echo "download checksum mismatch" >&2; exit 1; }
  kill "$sampler" 2>/dev/null || true; sampler=""
  max_sample=$(sort -n "$work/rss.samples" | tail -1)
  # VmHWM is the kernel's exact peak; some sandboxes (gVisor) do not expose it.
  peak_rss=$(kib VmHWM)
  hwm_note="VmHWM"
  [ -n "$peak_rss" ] || { peak_rss=$max_sample; hwm_note="max of 0.2 s VmRSS samples; VmHWM unavailable"; }
fi

echo
echo "Run $(date -u +%Y-%m-%dT%H:%MZ), cairn $("$cairn" --version | awk '{print $2}') @ $(git -C "$root" rev-parse --short HEAD), $profile build, $(uname -m), $(nproc) vCPU, kernel $(uname -r)"
echo
echo "| Measure | Value |"
echo "|---|---|"
echo "| Binary size | $size bytes ($(mib $((size / 1024))) MiB), $linkage |"
echo "| RSS at ready | $(mib "$start_rss") MiB |"
echo "| Idle RSS after ${settle} s | $(mib "$idle_rss") MiB |"
if [ -n "$peak_rss" ]; then
  echo "| Peak RSS ($hwm_note), $((bytes / 1048576)) MiB upload + download | $(mib "$peak_rss") MiB |"
  echo "| Max sampled RSS (0.2 s interval) during transfer | $(mib "$max_sample") MiB |"
  echo "| Upload / download wall time | ${up_s} s / ${down_s} s |"
  echo "| Round-trip sha256 | match |"
fi

over=0
budget() { # name actual limit unit
  [ -n "$3" ] || return 0
  if awk -v a="$2" -v l="$3" 'BEGIN { exit !(a > l) }'; then
    echo "over budget: $1 $2 $4 > $3 $4" >&2; over=1
  fi
}
budget "binary size" "$size" "${FOOTPRINT_MAX_BINARY_BYTES:-}" bytes
budget "idle RSS" "$(mib "$idle_rss")" "${FOOTPRINT_MAX_IDLE_MIB:-}" MiB
[ -n "$peak_rss" ] && budget "peak RSS" "$(mib "$peak_rss")" "${FOOTPRINT_MAX_PEAK_MIB:-}" MiB
exit "$over"
