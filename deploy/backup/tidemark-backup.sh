#!/usr/bin/env bash
# Hourly Tidemark backup of a running server: incremental into this ISO week's set, rotate old
# sets, mirror off-site.
#
# The server makes the backup itself (`tidemark admin backup start`), because the offline
# `tidemark backup` cannot open a data directory a running server holds. The server needs
# `[backup] dir = "<BACKUP_ROOT>"` (and `passphrase_file` to encrypt) in tidemark.toml.
#
# One set per ISO week (BACKUP_ROOT/2026-W46). The first run of a week uploads everything, later
# runs only new blobs. Pruning inside a set is not implemented, so whole sets rotate: the newest
# KEEP_SETS stay. Any manifest in any kept set restores on its own:
#   tidemark backup ls --from BACKUP_ROOT/2026-W46
#   tidemark restore --from BACKUP_ROOT/2026-W46 --data-dir /srv/tidemark-restored [--id <manifest>]
#
# Settings (environment, or /etc/default/tidemark-backup):
#   TIDEMARK_BIN         tidemark binary                     (default: tidemark)
#   TIDEMARK_ENDPOINT    server URL                          (default: http://127.0.0.1:9000)
#   TIDEMARK_ACCESS_KEY  key of a user allowed tidemark:Backup and tidemark:GetServerInfo
#   TIDEMARK_SECRET_KEY  its secret
#   BACKUP_ROOT          the server's backup.dir             (default: /var/backups/tidemark)
#   KEEP_SETS            weekly sets to keep                 (default: 4)
#   RCLONE_REMOTE        e.g. offsite:tidemark-backup; mirror BACKUP_ROOT there (default: unset)
# The server exports tidemark_backup_last_success_timestamp_seconds; the TidemarkBackupStale
# alert in deploy/prometheus/ fires when it is older than 2 h.
set -euo pipefail

# shellcheck source=/dev/null
[[ -r /etc/default/tidemark-backup ]] && . /etc/default/tidemark-backup

TIDEMARK_BIN=${TIDEMARK_BIN:-tidemark}
BACKUP_ROOT=${BACKUP_ROOT:-/var/backups/tidemark}
KEEP_SETS=${KEEP_SETS:-4}
RCLONE_REMOTE=${RCLONE_REMOTE:-}
export TIDEMARK_ENDPOINT=${TIDEMARK_ENDPOINT:-http://127.0.0.1:9000}
export TIDEMARK_ACCESS_KEY=${TIDEMARK_ACCESS_KEY:?set TIDEMARK_ACCESS_KEY}
export TIDEMARK_SECRET_KEY=${TIDEMARK_SECRET_KEY:?set TIDEMARK_SECRET_KEY}

log() { printf '%s tidemark-backup: %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
on_exit() {
  local rc=$?
  [[ $rc == 0 ]] || log "FAILED (exit $rc)"
}
trap on_exit EXIT

set_name=$(date -u +%G-W%V)
log "backing up into set $set_name"
"$TIDEMARK_BIN" admin backup start --set "$set_name" --wait >/dev/null

# Rotate: keep the newest KEEP_SETS weekly sets (names sort chronologically).
mapfile -t sets < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d \
  -name '[0-9][0-9][0-9][0-9]-W[0-9][0-9]' -printf '%f\n' | sort)
if (( ${#sets[@]} > KEEP_SETS )); then
  for old in "${sets[@]:0:${#sets[@]}-KEEP_SETS}"; do
    log "removing old set $old"
    rm -rf -- "${BACKUP_ROOT:?}/$old"
  done
fi

if [[ -n $RCLONE_REMOTE ]]; then
  log "mirroring to $RCLONE_REMOTE"
  rclone sync "$BACKUP_ROOT" "$RCLONE_REMOTE"
fi
log "ok"
