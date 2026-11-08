# Cairn v0.1 — Definition of done

Twenty-two rows. Each `[x]` names its proof (test file, CI job, or doc). The first public tag
waits for every row. Shelved features (BUILD-PLAN "Shelved") have no rows here on purpose.

Legend: `[ ]` todo · `[~]` partial · `[x]` done.

## A. S3 compatibility
- [x] A1 `cairn init` + `cairn serve` boot from one TOML file. (crates/cairn-cli/tests/cli.rs)
- [x] A2 Every S3 op in COMPAT.md has an `aws-sdk-s3` integration test: bucket CRUD, Put/Get/Head/Delete(s), Copy, List v1/v2/versions, versioning, 7 multipart ops, tagging, metadata, Range + conditionals, 5 checksum algorithms, AWS-shaped error XML with request ids. (crates/cairn-server/tests/*.rs)
- [ ] A3 `aws s3 cp/sync/ls/rm`, `rclone sync`, `mc` pass `scripts/e2e-clients.sh`; results table in COMPAT.md.
- [ ] A4 ceph `s3-tests` subset ≥ 80% with an allowed-failure list. (scripts/s3-tests/)
- [~] A5 Soft delete, trash list/restore/purge, PITR `head_at`/diff/restore, `x-cairn-as-of`, retention GC — all integration-tested through the server. (soft delete + as-of: crates/cairn-server/tests/pitr.rs; trash/retention engine-only: crates/cairn-engine/tests/engine.rs)

## B. Security
- [~] B1 SigV4 header + presigned verification with credential-store lookup; expired presign rejected. (bridge + STS sessions done in cairn-auth; server wiring + expired-presign test pending)
- [~] B2 Policy evaluation on every S3, admin and MCP request: identity ∪ group ∪ bucket policy ∪ PublicAccessBlock; explicit deny wins. (cairn-auth/src/s3s_bridge/tests.rs 19 tests; server wiring pending)
- [~] B3 STS `AssumeRole` / `GetSessionToken`; sessions expire and are revocable. (cairn-auth/src/sts/tests.rs; router not mounted)
- [~] B4 Root credentials sealed in the credential store at `cairn init`, never logged; secrets zeroized and redacted. (cairn-admin/src/tests.rs::secrets_never_logged; `ensure_root` not called from init)
- [ ] B5 SSE-S3 at rest with a master key from file or env; plaintext blobs never written when enabled.
- [x] B6 `cargo deny` + `cargo audit` in CI, `SECURITY.md`, `forbid(unsafe_code)` everywhere. (.github/workflows/security.yml, deny.toml)
- [x] B7 Admin API requires root or `cairn:*` policy; CORS default-deny. (cairn-admin/src/tests.rs)

## C. Durability and recovery
- [~] C1 Crash consistency: kill -9 during put / multipart complete / delete leaves nothing half-committed; recovery sweeps `tmp/`. (recovery test exists; fault-injection test pending)
- [x] C2 GC never deletes a referenced blob. (crates/cairn-engine/tests/engine.rs::gc_never_deletes_referenced_blobs)
- [~] C3 `cairn fsck` detects orphan / missing / corrupt blobs and refcount drift; `--repair` fixes what is safe; GET of a damaged version fails loudly. (crates/cairn-engine/tests/fsck.rs 6 tests; subcommand + GET check pending)
- [~] C4 `cairn scrub` verifies blob hashes on a schedule with an IO budget. (crates/cairn-engine/tests/scrub.rs; not spawned from serve)
- [~] C5 `cairn backup` (full + incremental, encrypted) and `cairn restore` round-trip. (crates/cairn-engine/tests/backup.rs 5 tests; subcommands pending)
- [~] C6 Disk full → `507`, server stays up, GET/DELETE/GC still work. (cairn-blob SpaceGuard tested; put-path wiring + server test pending)
- [~] C7 Schema migrations with pre-upgrade snapshot and `cairn migrate --dry-run`. (cairn_meta::migrate + v1 fixture; subcommand pending)
- [x] C8 Graceful shutdown on SIGTERM drains requests and closes redb cleanly. (crates/cairn-cli/tests/cli.rs, crates/cairn-server/tests/server.rs)

## D. Operability
- [x] D1 `/healthz` and `/readyz`. (crates/cairn-server/tests/server.rs)
- [ ] D2 `/metrics`: requests by op/status, latency, bytes in/out, blob count/bytes, trash bytes, gc runs.
- [ ] D3 JSON logs with request-id correlation; audit JSONL for mutating and denied requests.
- [ ] D4 Lifecycle expiration + abort-incomplete-multipart and GC run on schedule; tested with a fake clock.
- [ ] D5 `cairn config check` prints the effective config with secrets masked; every key has a default and a `CAIRN_*` env override.
- [~] D6 Admin CLI: users, keys, groups, policies, roles, buckets, trash, pitr; `--json`. (cairn_admin::cli + loopback e2e test; not mounted in the binary)
- [~] D7 MCP server (stdio + HTTP) with the DESIGN §11 tools under policy. (crates/cairn-mcp/tests/tools.rs 10 tests; not mounted)

## E. Limits
- [ ] E1 A 10 GiB upload and download complete with RSS under 256 MiB (streaming end to end); number recorded in OPERATIONS.md.

## F. Release
- [x] F1 fmt, clippy `-D warnings`, tests, docs green on every push. (.github/workflows/ci.yml, self-hosted while private)
- [~] F2 Tag → static musl x86_64 + aarch64 binaries, GHCR image, SBOM, checksums. (.github/workflows/release.yml; never exercised)
- [~] F3 README quickstart passes on a clean machine from a release binary; COMPAT.md, EXTENSIONS.md, OPERATIONS.md current. (README written; not verified against a binary)
- [~] F4 Name decided (crates.io `cairn`, `cairn-cli`, `cairn-core` are taken; see DECISIONS.md name check); rename done if needed before the tag.
