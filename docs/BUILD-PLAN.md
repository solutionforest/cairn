# Cairn — Build plan (v0.1)

Scope lives in `docs/DESIGN.md` (§0 says what is in, what is out, and the four claims). Done means
every row in `docs/PRODUCTION-READINESS.md` is checked. Decisions and their reasons are in
`docs/DECISIONS.md`. Dates are UTC.

## The one sentence

Cairn v0.1 is **a single-binary S3 server you cannot lose data on**: one box, one data directory,
every delete reversible with nothing configured, every bucket readable as of any time in its
retention window, blobs deduplicated, and an MCP server that obeys the same policies as S3.
Nothing else ships in v0.1.

## The competitor that matters

VaultS3 (Go, AGPL, single binary, 1.7k stars, v5, externally audited, 17 MiB idle) already ships
everything we shelved plus a dashboard. We will not out-feature it. We ship four claims it cannot
make (DESIGN §0) and prove each one with a test or a published number. Any work item that does not
serve a claim, a table-stakes row, or the release itself is out.

## Environment
- Build host: 1 vCPU, 32 GB RAM, Rust stable 1.99. Iterate with `cargo check -p` / `cargo test -p`;
  run `cargo test --workspace` only at milestones. Never `--release` while developing.
- One checkout, several agents: Cargo serialises on the target-dir lock; do not delete `target/`.
- Tests use temp dirs and `127.0.0.1:0`; no network.

## Fixed decisions
`s3s` 0.17 protocol layer · `redb` metadata · BLAKE3 content-addressed blobs on the filesystem ·
`hyper`/`axum`/`rustls` (no OpenSSL) · `postcard` records with a schema byte · `tokio` ·
`rmcp` 3 for MCP · edition 2024 · `#![forbid(unsafe_code)]` · AGPL-3.0-only · DCO, no CLA.
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
orchestrator pushes. Lane 2 is ordered claim-first: the tests that would embarrass us if they
failed in public come before polish.

| # | Lane | Work | Closes |
|---|------|------|--------|
| 1 | **Wire** (server/cli) | Mount `CairnS3Auth`/`CairnS3Access`, STS router, admin router with a real `AdminEngine`, MCP HTTP router + `cairn mcp --stdio`; `cairn init` seals root creds in the credential store; `migrate()` at start + `cairn migrate --dry-run`; CLI: `admin`, `fsck`, `scrub`, `backup`, `restore`, `trash`, `pitr` | B1 B2 B3 B4 C3 C4 C5 C7 D6 D7 |
| 2 | **Prove the claims** (engine/server tests) | **Claim 1** zero-config undo: fresh bucket, versioning never touched, overwrite + delete object + delete bucket, restore all, bytes identical (A6). **Claim 2** `x-cairn-as-of` and `cairn pitr restore` to an instant with no prior snapshot, including across a bucket delete (A5). **Claim 3** dedup: N identical uploads → one blob file; copy, trash restore and PITR restore add zero blob bytes (A7). **Claim 4** a principal denied `s3:GetObject` is denied the same object through MCP `get_object`; `cairn:TimeTravel` gates `as_of` tools (D7 test half). Then: retention GC, kill-9 fault injection during put / multipart complete / delete, disk-full 507 with GET/DELETE/GC still working, SSE-S3 with key from file/env, lifecycle + abort-mpu with a fake clock | A5 A6 A7 C1 C2 C6 B5 D4 |
| 3 | **Ship** (scripts/docs/CI) | ceph `s3-tests` on every push gating on `expected-pass.txt`, weekly full sweep (A4); `scripts/e2e-clients.sh` run (aws/rclone/mc) recorded in COMPAT.md (A3); `scripts/footprint.sh` (idle RSS, 10 GiB RSS, binary size) with numbers in README (E1 E2); `/metrics` minimal set; JSON logs + audit JSONL; `cairn config check`; README rewrite around the four claims and the §0 competitor table; `CONTRIBUTING.md` with DCO (F5); quickstart verified on a clean VM; rename decision; first `v0.1.0-alpha` tag | A3 A4 D1 D2 D3 D5 E1 E2 F1–F5 |

Lane 1 is the critical path; 2 and 3 can start now against the existing engine/server.

## Shelved (code may exist; not wired, not tested in CI, not documented as features)
Replication · blob tiering · events outbox, webhooks, function sinks, SSE stream · OIDC federation ·
Object Lock · SSE-C / KMS · rate limiting · TLS hot reload · bucket quotas · CORS · PostObject ·
erasure coding · compression · full-text / vector search · FUSE · S3 Select · bench harness ·
built-in admin UI · `ai` feature · Helm · multi-node. Each returns only with a DESIGN.md entry saying which
§0 claim it serves.

An optional local admin UI lives in `admin-ui/`: one HTML/JS page plus a single-file Python or PHP
backend that holds the keys and signs admin API calls. Nothing is added to the server binary.

## Working agreements
- Lane 1 owns `cairn-server`, `cairn-cli`; lane 2 owns `cairn-engine`, `cairn-blob`, tests under
  `crates/cairn-server/tests/`; lane 3 owns `scripts/`, `.github/`, `deploy/`, `docs/`, `bench/`,
  `README.md`, `CONTRIBUTING.md`. Touching another lane's files: additive only, say so in the
  commit message.
- `docs/COMPAT.md` and `docs/EXTENSIONS.md` are updated in the same commit as the behaviour.
- A DESIGN change gets a dated entry in `docs/DECISIONS.md` in the same commit.
- Commits carry `Signed-off-by` (DCO). No CLA, ever.
