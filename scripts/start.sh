#!/usr/bin/env bash
# Start Tidemark on this machine with one command.
#
#   scripts/start.sh            # S3 server on http://127.0.0.1:9000
#   scripts/start.sh --ui       # plus the admin UI on http://127.0.0.1:9080
#
# First run: finds or downloads the `tidemark` binary, creates ./tidemark-data with fresh random root
# credentials and saves them to ./tidemark-data/credentials.env (mode 0600). Later runs reuse both.
# Ctrl-C stops everything. For a long-running install use deploy/tidemark.service or Docker instead.
#
# Options: --ui, --data-dir DIR (./tidemark-data), --port N (9000), --ui-port N (9080),
#          --version vX.Y.Z (release to download when no binary is found)
# Env:     TIDEMARK_BIN=/path/to/tidemark to use a specific binary.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
repo=solutionforest/tidemark
version=v0.1.0-beta.1
data=./tidemark-data
port=9000
ui_port=9080
ui=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ui) ui=1 ;;
    --data-dir) data="$2"; shift ;;
    --port) port="$2"; shift ;;
    --ui-port) ui_port="$2"; shift ;;
    --version) version="$2"; shift ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

say() { printf '\033[1m==>\033[0m %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
rand() { LC_ALL=C tr -dc "$1" </dev/urandom | head -c "$2" || true; }

find_binary() {
  for c in "${TIDEMARK_BIN:-}" "$root/target/release/tidemark" "./tidemark" "$(command -v tidemark 2>/dev/null || true)"; do
    [ -n "$c" ] && [ -x "$c" ] && { echo "$c"; return; }
  done
  [ "$(uname -s)" = Linux ] || die "no tidemark binary found; release binaries are Linux-only, use Docker or set TIDEMARK_BIN"
  local target="$(uname -m)-unknown-linux-musl" name dir
  case "$target" in x86_64-*|aarch64-*) ;; *) die "no release binary for $(uname -m); build from source";; esac
  name="tidemark-$version-$target"
  dir="$(mktemp -d)"
  say "Downloading $name" >&2
  local base="https://github.com/$repo/releases/download/$version"
  curl -fsSL -o "$dir/$name.tar.gz" "$base/$name.tar.gz" \
    && curl -fsSL -o "$dir/SHA256SUMS" "$base/SHA256SUMS" \
    || die "download failed from $base"
  (cd "$dir" && grep " $name.tar.gz\$" SHA256SUMS | sha256sum -c - >/dev/null) || die "checksum mismatch for $name.tar.gz"
  tar xzf "$dir/$name.tar.gz" -C "$dir"
  install -m 0755 "$dir/$name/tidemark" ./tidemark
  rm -rf "$dir"
  echo ./tidemark
}

tidemark="$(find_binary)"
say "Using $tidemark ($("$tidemark" --version))"

creds="$data/credentials.env"
if [ ! -f "$data/tidemark.toml" ]; then
  ak="TDMK$(rand 'A-Z2-7' 16)"
  sk="$(rand 'A-Za-z0-9' 40)"
  say "Creating $data"
  TIDEMARK_ROOT_ACCESS_KEY="$ak" TIDEMARK_ROOT_SECRET="$sk" \
    "$tidemark" init --data-dir "$data" --listen "127.0.0.1:$port" >/dev/null
  (umask 077; cat >"$creds" <<EOF
# Root credentials for this Tidemark data directory, created by scripts/start.sh.
# Keep this file private. Use it with: source $creds
export AWS_ACCESS_KEY_ID='$ak'
export AWS_SECRET_ACCESS_KEY='$sk'
export AWS_REGION=us-east-1
export AWS_ENDPOINT_URL=http://127.0.0.1:$port
export TIDEMARK_ENDPOINT=http://127.0.0.1:$port
export TIDEMARK_ACCESS_KEY='$ak'
export TIDEMARK_SECRET_KEY='$sk'
EOF
  )
  unset sk
fi

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT
trap 'exit 130' INT TERM

log="$data/server.log"
TIDEMARK_SERVER_LISTEN="127.0.0.1:$port" "$tidemark" serve --config "$data/tidemark.toml" >>"$log" 2>&1 &
pids+=($!)
for _ in $(seq 60); do
  curl -fs -o /dev/null "http://127.0.0.1:$port/readyz" && break
  kill -0 "${pids[0]}" 2>/dev/null || { tail -n 20 "$log" >&2; die "tidemark exited during startup (log: $log)"; }
  sleep 0.5
done
curl -fs -o /dev/null "http://127.0.0.1:$port/readyz" || die "tidemark did not become ready (log: $log)"

if [ "$ui" = 1 ]; then
  [ -f "$creds" ] || die "--ui needs $creds (only data dirs created by this script have one)"
  # shellcheck disable=SC1090
  (set -a; . "$creds"; export TIDEMARK_UI_PORT="$ui_port"
   if command -v python3 >/dev/null; then exec python3 "$root/admin-ui/server.py" 2>>"$data/ui.log"
   elif command -v php >/dev/null; then exec php -S "127.0.0.1:$ui_port" "$root/admin-ui/server.php" 2>>"$data/ui.log"
   else echo "admin UI needs python3 or php" >&2; exit 1; fi) &
  pids+=($!)
fi

extra=""
[ -f "$creds" ] || extra=" (none: this data dir was not created by start.sh)"
[ "$ui" = 1 ] && extra="$extra
  Admin UI      http://127.0.0.1:$ui_port"
cat <<EOF

  Tidemark is running.
  S3 endpoint   http://127.0.0.1:$port   (region us-east-1, path-style)
  Server log    $log
  Credentials   $creds$extra

  Try it in another terminal:
    source $creds
    aws s3 mb s3://photos
    aws s3 cp ./cat.jpg s3://photos/

  Press Ctrl-C to stop.
EOF
wait "${pids[0]}"
