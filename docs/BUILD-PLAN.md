# Cairn — Build plan (v0.1)

Scope lives in `docs/DESIGN.md` (§0 says what is in and out of v0.1). Done means every row in
`docs/PRODUCTION-READINESS.md` is checked. Decisions and their reasons are in `docs/DECISIONS.md`.
Dates are UTC.

## The one sentence

Cairn v0.1 is **a single-binary S3 server you cannot lose data on**: one box, one data directory,
every delete reversible, every bucket readable as of any time in its retention window, blobs
deduplicated, and an MCP server that obeys the same policies as S3. Nothing else ships in v0.1.

## Environment
- Build host: 1 vCPU, 32 GB RAM, Rust stable 1.99. Iterate with `cargo check -p` / `cargo test -p`;
  run `cargo test --workspace` only at milestones. Never `--release` while developing.
- One checkout, several agents: Cargo serialises on the target-dir lock; do not delete `target/`.
- Tests use temp dirs and `127.0.0.1:0`; no network.

## Fixed decisions
`s3s` 0.17 protocol layer · `redb` metadata · BLAKE3 content-addressed blobs on the filesystem ·
`hyper`/`axum`/`rustls` (no OpenSSL) · `postcard` records with a schema byte · `tokio` ·
`rmcp` 3 for MCP · edition 2024 · `#![forbid(unsafe_code)]` · AGPL-3.0-only.
Crate API contracts are documented in each crate's `lib.rs` rustdoc.

## What is built (2026-11-08)

| Crate | State | Lines |
|---|---|---|
| core, meta, blob | done; PITR `head_at`, GC index, AEAD blobs | 7k |
| auth | done; 143-case policy evaluator, credential store, STS, SigV4, s3s bridge | 12k |
| engine | done for v0.1 ops; recovery, GC, trash, PITR diff, fsck, scrub, backup | 11k |
| s3, server, cli | 29 S3 ops, healthz/readyz, graceful shutdown, `init`/`serve`; auth not wired | 8k |
| admin, mcp | libraries done; not mounted in the server | 6k |
| events | library done; **shelved** (not wired, not in v0.1) | 3.5k |

## Remaining work

Three lanes, disjoint files. Each lane commits at every green step and pushes nothing; the
orchestrator pushes.

| # | Lane | Work | Closes |
|---|------|------|--------|
| 1 | **Wire** (server/cli) | Mount `CairnS3Auth`/`CairnS3Access`, STS router, admin router with a real `AdminEngine`, MCP HTTP router + `cairn mcp --stdio`; `cairn init` seals root creds in the credential store; `migrate()` at start + `cairn migrate --dry-run`; CLI: `admin`, `fsck`, `scrub`, `backup`, `restore` | B1 B2 B3 B4 C3 C4 C5 C7 D6 D7 |
| 2 | **Prove recovery** (engine/server tests) | Integration tests for trash list/restore/purge, PITR restore, retention GC, `x-cairn-as-of`; kill-9 fault injection during put / multipart complete / delete; disk-full 507 with GET/DELETE/GC still working; SSE-S3 at rest with key from file/env; lifecycle expiration + abort-mpu with a fake clock | A5 C1 C2 C6 B5 D4 |
| 3 | **Ship** (scripts/docs/CI) | `scripts/e2e-clients.sh` run (aws/rclone/mc) recorded in COMPAT.md; ceph `s3-tests` subset with allowed-failure list; `/metrics` minimal set; JSON logs + audit JSONL; `cairn config check`; 10 GiB upload RSS check; README quickstart verified on a clean VM; rename decision; first `v0.1.0-alpha` tag | A3 A4 D1 D2 D3 E1 F1–F4 |

Lane 1 is the critical path; 2 and 3 can start now against the existing engine/server.

## Shelved (code may exist; not wired, not tested in CI, not documented as features)
Replication · blob tiering · events outbox, webhooks, function sinks, SSE stream · OIDC federation ·
Object Lock · SSE-C / KMS · rate limiting · TLS hot reload · bucket quotas · CORS · PostObject ·
bench harness · admin UI · `ai` feature · Helm. Each returns only with a DESIGN.md entry saying why.

## Working agreements
- Lane 1 owns `cairn-server`, `cairn-cli`; lane 2 owns `cairn-engine`, `cairn-blob`, tests under
  `crates/cairn-server/tests/`; lane 3 owns `scripts/`, `.github/`, `deploy/`, `docs/`, `bench/`.
  Touching another lane's files: additive only, say so in the commit message.
- `docs/COMPAT.md` and `docs/EXTENSIONS.md` are updated in the same commit as the behaviour.
- A DESIGN change gets a dated entry in `docs/DECISIONS.md` in the same commit.
