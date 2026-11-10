# deploy/

| Path | What |
|------|------|
| `Dockerfile`, `tidemark.service`, `tidemark.example.toml` | Container image, systemd unit, example config |
| `prometheus/scrape.yml` | Scrape job to paste into `prometheus.yml` |
| `prometheus/tidemark-alerts.yml` | Alert rules (disk, damage, trash, GC, errors, events, audit, backups); unit-tested by `tidemark-alerts.test.yml` |
| `grafana/tidemark-dashboard.json` | Dashboard: import it, pick the Prometheus data source |
| `backup/` | Hourly backup of a running server into weekly sets, rotation, `rclone` mirror; least-privilege policy for the backup user |

Alerts and the backup flow are described in [OPERATIONS.md](../docs/OPERATIONS.md#monitoring).
`scripts/deploy-kit-test.sh <tidemark> <prometheus-dir>` runs all of it against a real server.
