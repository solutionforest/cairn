# Cairn — agent guide

Read `docs/DESIGN.md` §0 (v0.1 scope: what is in, what is shelved), `docs/BUILD-PLAN.md` (lanes and
remaining work) and `docs/PRODUCTION-READINESS.md` (definition of done) before touching code.
Dated reasons for decisions go in `docs/DECISIONS.md`. Do not build shelved features.
Cairn competes with VaultS3 on four claims (DESIGN §0), not on feature count: if a task does not
serve a claim or a readiness row, stop and ask. Commits are DCO-signed (`git commit -s`).

## Hard constraints
- 1 vCPU build host. Iterate with `cargo check -p <crate>` and `cargo test -p <crate>`; run the whole
  workspace only at milestones. No `--release` builds during development.
- Pure Rust dependency policy: rustls only (no `openssl`/`native-tls`), no RocksDB, no C/C++ build
  deps. Add new dependencies through `[workspace.dependencies]` in the root `Cargo.toml`.
- `#![forbid(unsafe_code)]`, `#![warn(clippy::all)]`; clippy clean before commit.
- Edition 2024, `license = "AGPL-3.0-only"` in every crate.
- Never log secrets; redact `Authorization`, secret keys, session tokens.
- No network access from tests. Tests use temp dirs (`tempfile`) and `127.0.0.1:0`.

## Conventions
- Library crates: `thiserror` error enums that convert into `cairn_core::S3Error` where relevant.
  Binary: `anyhow`.
- Public types documented with a one-line `///`; no comment noise inside functions.
- Metadata records carry a leading schema-version byte; add a migration when you change one.
- Every S3 operation implemented gets: an integration test in `crates/cairn-server/tests/` using `aws-sdk-s3`, and a
  row in `docs/COMPAT.md`.
- Custom headers are `x-cairn-*`, custom IAM actions are `cairn:*`, documented in
  `docs/EXTENSIONS.md`.
- Commit at green milestones with a message that names the phase (e.g. `phase 1a: redb meta store
  with head_at PITR query`). Do not push; the orchestrator pushes to `origin`.
- Respect crate ownership in BUILD-PLAN "Working agreements" when several agents run at once.

## Layout
`crates/cairn-{core,meta,blob,auth,engine,s3,admin,events,mcp,server,cli}` — see DESIGN §3 for
responsibilities and the dependency direction `core ← meta/blob/auth ← engine ← s3/admin/events/mcp ← server ← cli`.
