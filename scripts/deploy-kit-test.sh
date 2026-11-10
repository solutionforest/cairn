#!/usr/bin/env bash
# Operations kit test (BUILD-PLAN 2.2): deploy/ against a real server and a real Prometheus.
#
#   scripts/deploy-kit-test.sh TIDEMARK_BINARY PROMETHEUS_DIR [WORKDIR]
#
# PROMETHEUS_DIR holds the `prometheus` and `promtool` binaries from a release tarball.
# 1. promtool: the alert rules load and their unit tests pass.
# 2. The offline `tidemark backup` refuses a live data dir and names the server-side command.
# 3. A user with only deploy/backup/backup-user-policy.json runs deploy/backup/tidemark-backup.sh
#    twice against the live server (one manifest each), rotation keeps KEEP_SETS sets, a bad key
#    fails loudly, and the newest set restores into a directory that passes `fsck --verify full`.
# 4. Prometheus scrapes the server with the rules loaded: every
#    Grafana dashboard query is valid, the health and storage queries return data, the rule
#    groups evaluate without errors, and nothing fires on a healthy server.
# Needs bash, curl, jq and the aws CLI.
set -euo pipefail

bin=$(realpath "${1:?usage: deploy-kit-test.sh TIDEMARK_BINARY PROMETHEUS_DIR [WORKDIR]}")
prom=$(realpath "${2:?usage: deploy-kit-test.sh TIDEMARK_BINARY PROMETHEUS_DIR [WORKDIR]}")
work=${3:-$(mktemp -d)}
mkdir -p "$work"
work=$(realpath "$work")
repo=$(cd "$(dirname "$0")/.." && pwd)
port=${DEPLOY_TEST_PORT:-19500}
prom_port=$((port + 1))
ep=http://127.0.0.1:$port
pq=http://127.0.0.1:$prom_port/api/v1
export AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 AWS_PAGER='' AWS_EC2_METADATA_DISABLED=true
pids=()

say() { printf '==> %s\n' "$*"; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done; }
trap cleanup EXIT
for p in $port $prom_port; do
  curl -s -o /dev/null "http://127.0.0.1:$p/" && fail "port $p is busy; set DEPLOY_TEST_PORT"
done

say "promtool: rules load and unit tests pass"
"$prom/promtool" check rules "$repo/deploy/prometheus/tidemark-alerts.yml" >/dev/null
"$prom/promtool" test rules "$repo/deploy/prometheus/tidemark-alerts.test.yml" >/dev/null

say "server with a 1 GiB reserve, a 1 s stats interval and backup.dir"
data=$work/data broot=$work/backups
"$bin" init --data-dir "$data" >"$work/init.out" 2>&1
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
AWS_ACCESS_KEY_ID=$(awk '/access key:/{print $3}' "$work/init.out")
AWS_SECRET_ACCESS_KEY=$(awk '/secret key:/{print $3}' "$work/init.out")
cfg=$data/tidemark.toml
printf 'correct horse battery staple\n' >"$work/pass"
sed -i "s|^listen = .*|listen = \"127.0.0.1:$port\"|; s|^stats_interval = .*|stats_interval = \"1s\"|" "$cfg"
sed -i "s|^\[backup\]\$|[backup]\ndir = \"$broot\"\npassphrase_file = \"$work/pass\"|" "$cfg"
grep -q "^dir = \"$broot\"" "$cfg" || fail "could not set backup.dir in $cfg"
"$bin" serve --config "$cfg" >"$work/server.log" 2>&1 &
pids+=($!)
for _ in $(seq 100); do curl -fs -o /dev/null "$ep/readyz" && break; sleep 0.2; done
curl -fs -o /dev/null "$ep/readyz" || { tail -20 "$work/server.log"; fail "server not ready"; }
aws --endpoint-url "$ep" s3api create-bucket --bucket kit >/dev/null
for i in 1 2 3; do
  head -c 100000 /dev/urandom >"$work/obj$i"
  aws --endpoint-url "$ep" s3api put-object --bucket kit --key "obj$i" --body "$work/obj$i" >/dev/null
done
aws --endpoint-url "$ep" s3api delete-object --bucket kit --key obj3 >/dev/null

say "offline backup of a live data dir points at the server-side path"
if "$bin" backup --data-dir "$data" --to "$work/offline" >"$work/offline.out" 2>&1; then
  fail "offline backup opened a data dir the server holds"
fi
grep -q 'tidemark admin backup start' "$work/offline.out" || fail "no hint: $(cat "$work/offline.out")"

say "backup user with deploy/backup/backup-user-policy.json"
adm() { TIDEMARK_ENDPOINT=$ep TIDEMARK_ACCESS_KEY=$AWS_ACCESS_KEY_ID TIDEMARK_SECRET_KEY=$AWS_SECRET_ACCESS_KEY "$bin" admin --json "$@"; }
adm user add backup >/dev/null
adm user policy put backup backup "$repo/deploy/backup/backup-user-policy.json" >/dev/null
adm key create backup >"$work/backup-key.json"
bak_ak=$(jq -r .access_key_id "$work/backup-key.json")
bak_sk=$(jq -r .secret_access_key "$work/backup-key.json")
[ -n "$bak_ak" ] && [ "$bak_ak" != null ] || fail "no backup key: $(cat "$work/backup-key.json")"
if TIDEMARK_ENDPOINT=$ep TIDEMARK_ACCESS_KEY=$bak_ak TIDEMARK_SECRET_KEY=$bak_sk "$bin" admin user ls >/dev/null 2>&1; then
  fail "the backup user can list users"
fi

say "backup script: two runs while serving, rotation, restore"
mkdir -p "$broot/2020-W01" "$broot/2020-W02" "$broot/2020-W03"
run_backup() {
  TIDEMARK_BIN=$bin TIDEMARK_ENDPOINT=$ep TIDEMARK_ACCESS_KEY=$bak_ak TIDEMARK_SECRET_KEY=$bak_sk \
    BACKUP_ROOT=$broot KEEP_SETS=2 "$repo/deploy/backup/tidemark-backup.sh"
}
run_backup 2>>"$work/backup.log" || { cat "$work/backup.log"; fail "first backup run"; }
aws --endpoint-url "$ep" s3api put-object --bucket kit --key obj4 --body "$work/obj1" >/dev/null
run_backup 2>>"$work/backup.log" || { cat "$work/backup.log"; fail "second backup run"; }
set_dir=$broot/$(date -u +%G-W%V)
n=$("$bin" backup ls --from "$set_dir" | grep -c .)
[ "$n" = 2 ] || fail "want 2 manifests in $set_dir, got $n"
mapfile -t kept < <(find "$broot" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
[ "${kept[*]}" = "2020-W03 $(basename "$set_dir")" ] || fail "rotation kept: ${kept[*]}"
if TIDEMARK_BIN=$bin TIDEMARK_ENDPOINT=$ep TIDEMARK_ACCESS_KEY=$bak_ak TIDEMARK_SECRET_KEY=wrong-secret-0000 \
  BACKUP_ROOT=$broot "$repo/deploy/backup/tidemark-backup.sh" 2>>"$work/backup.log"; then
  fail "backup with a bad key succeeded"
fi
grep -q 'FAILED' "$work/backup.log" || fail "failure not logged"
"$bin" restore --from "$set_dir" --data-dir "$work/restored" --passphrase-file "$work/pass" >/dev/null 2>&1 \
  || fail "restore failed"
"$bin" fsck --data-dir "$work/restored" --verify full >"$work/fsck.out" 2>&1 \
  || { cat "$work/fsck.out"; fail "fsck of the restored directory"; }

say "Prometheus scrapes the server with the rules loaded"
cat >"$work/prometheus.yml" <<EOF
global: { scrape_interval: 2s, evaluation_interval: 2s }
rule_files: ["$repo/deploy/prometheus/tidemark-alerts.yml"]
scrape_configs:
  - job_name: tidemark
    static_configs: [{ targets: ["127.0.0.1:$port"] }]
EOF
"$prom/prometheus" --config.file="$work/prometheus.yml" --storage.tsdb.path="$work/tsdb" \
  --web.listen-address="127.0.0.1:$prom_port" >"$work/prometheus.log" 2>&1 &
pids+=($!)
q() { curl -fsS --get "$pq/query" --data-urlencode "query=$1"; }
for _ in $(seq 60); do
  [ "$(q 'tidemark_disk_free_bytes' 2>/dev/null | jq '.data.result | length')" = 1 ] \
    && [ "$(q 'tidemark_backup_last_success_timestamp_seconds' 2>/dev/null | jq '.data.result | length')" = 1 ] && break
  sleep 1
done
sleep 6 # a few samples for rate()

dash=$repo/deploy/grafana/tidemark-dashboard.json
jq -e '.panels | length > 0' "$dash" >/dev/null || fail "dashboard has no panels"
must_have_data='Up|Damaged blobs|Free above reserve|Live data|Trash \+ history|Since last backup|Requests by operation|Disk free vs reserve|Blobs on disk'
checked=0
while IFS=$'\t' read -r title expr; do
  e=${expr//\$__rate_interval/30s}
  e=${e//\$instance/.*}
  r=$(q "$e") || fail "[$title] query rejected: $e"
  [ "$(jq -r .status <<<"$r")" = success ] || fail "[$title] $r"
  if [[ $title =~ ^($must_have_data)$ ]] && [ "$(jq '.data.result | length' <<<"$r")" = 0 ]; then
    fail "[$title] returned no data: $e"
  fi
  checked=$((checked + 1))
done < <(jq -r '.panels[] | select(.type != "row") | .title as $t | .targets[] | [$t, .expr] | @tsv' "$dash")
v=$(jq -r '.templating.list[] | select(.name == "instance") | .query.query' "$dash")
[ "$v" = 'label_values(tidemark_blobs, instance)' ] || fail "instance variable: $v"
[ "$(q 'tidemark_blobs' | jq '.data.result | length')" = 1 ] || fail "instance variable source has no series"
free=$(q 'tidemark_disk_free_bytes' | jq -r '.data.result[0].value[1]')
reserve=$(q 'tidemark_disk_reserve_bytes' | jq -r '.data.result[0].value[1]')
[ "$reserve" = 1073741824 ] || fail "reserve gauge $reserve, want the 1 GiB default"
[ "${free%.*}" -gt 0 ] || fail "free gauge $free"

rules=$(curl -fsS "$pq/rules")
bad=$(jq -r '[.data.groups[].rules[] | select(.health != "ok") | "\(.name): \(.lastError)"] | join("; ")' <<<"$rules")
[ -z "$bad" ] || fail "rules failing to evaluate: $bad"
nrules=$(jq '[.data.groups[].rules[]] | length' <<<"$rules")
firing=$(curl -fsS "$pq/alerts" | jq -r '[.data.alerts[] | .labels.alertname] | unique | join(",")')
# DiskNearReserve legitimately fires on a nearly full CI disk; anything else is a false alarm.
firing=${firing//TidemarkDiskNearReserve/}
[ -z "${firing//,/}" ] || fail "alerts firing on a healthy server: $firing"

say "PASS: rules tested, backup + restore ok, $checked dashboard queries valid, $nrules rules healthy"
