# Cairn

Lightweight, self-hosted, S3-compatible object storage in Rust. AGPL-3.0.

A single binary and one data directory. High S3 compatibility (built on the `s3s` protocol
adapter), IAM-style policies and STS, encryption at rest, and a safety net MinIO does not have:
soft delete for everything, shadow versioning, point-in-time recovery, read-only time travel,
Object Lock, async replication, and a built-in MCP server so AI agents can use your storage under
the same policies as everyone else.

Status: pre-alpha, under active construction. See `docs/DESIGN.md` and `docs/BUILD-PLAN.md`.

```
cairn init --data-dir /srv/cairn      # prints root credentials once
cairn serve --data-dir /srv/cairn     # S3 on :9000, admin + MCP on the same port
```

## Licence
AGPL-3.0-only. Commercial licensing may be offered later by the maintainers.
