# shellcheck shell=bash
# Host helpers shared by bench.sh and soak.sh. Linux and macOS; bash 3.2 compatible.
# Source it: . "$here/host.sh"

host_os=$(uname -s)

# host_line DIR: "N CPU, M GiB RAM, <kernel>, data on <fstype>" for the report header.
host_line() {
  local cpus mem fs
  cpus=$(getconf _NPROCESSORS_ONLN 2> /dev/null || echo "?")
  case "$host_os" in
    Darwin)
      mem=$(sysctl -n hw.memsize | awk '{printf "%.0f GiB", $1 / 1073741824}')
      fs=$(df -P "$1" | awk 'NR == 2 {print $6}')
      fs=$(mount | awk -v m="$fs" '$3 == m {sub(/^\(/, "", $4); sub(/,$/, "", $4); print $4; exit}')
      ;;
    *)
      mem=$(awk '/MemTotal/ {printf "%.0f GiB", $2 / 1048576}' /proc/meminfo)
      fs=$(df -T "$1" | awk 'NR == 2 {print $2}')
      ;;
  esac
  echo "$cpus CPU, $mem RAM, $(uname -sr), data on ${fs:-?}"
}

# rss_of PID: resident set size in MiB, one decimal.
rss_of() {
  if [ -r "/proc/$1/status" ]; then
    awk '/^VmRSS:/ {printf "%.1f", $2 / 1024}' "/proc/$1/status"
  else
    ps -o rss= -p "$1" | awk '{printf "%.1f", $1 / 1024}'
  fi
}

# free_bytes DIR: bytes available to unprivileged writers on DIR's filesystem.
free_bytes() { df -Pk "$1" | awk 'NR == 2 {printf "%.0f", $4 * 1024}'; }

# ballast PATH BYTES: allocate BYTES of real disk space at PATH without writing them.
# Linux: fallocate. macOS: fcntl(F_PREALLOCATE) + ftruncate (APFS and HFS+).
ballast() {
  if command -v fallocate > /dev/null; then
    fallocate -l "$2" "$1"
  elif [ "$host_os" = Darwin ]; then
    python3 -I - "$1" "$2" << 'PY'
import fcntl, os, struct, sys
path, size = sys.argv[1], int(sys.argv[2])
F_PREALLOCATE, F_ALLOCATEALL, F_PEOFPOSMODE = 42, 0x4, 3
fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
try:
    # struct fstore { u32 flags; i32 posmode; off_t offset; off_t length; off_t bytesalloc; }
    fcntl.fcntl(fd, F_PREALLOCATE, struct.pack("=Iiqqq", F_ALLOCATEALL, F_PEOFPOSMODE, 0, size, 0))
    os.ftruncate(fd, size)
finally:
    os.close(fd)
PY
  else
    echo "no way to allocate a ballast file on $host_os (need fallocate)" >&2
    return 1
  fi
}
