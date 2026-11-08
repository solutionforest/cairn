# Cairn — Production readiness checklist

Definition of done for "production ready standard". Every box must be checked, with the proving
artefact named (test file, CI job, doc), before the first public tag. Status is updated by the
orchestrator; agents report which rows they closed in commit messages.

Legend: `[ ]` todo · `[~]` partial · `[x]` done (proof in parentheses).

## A. Correctness and S3 compatibility
- [x] A1 Server boots from `cairn init` + `cairn serve` with one TOML file; data dir layout per DESIGN §4. (crates/cairn-cli/tests/cli.rs)
- [x] A2 Every S3 operation in BUILD-PLAN 1c has an `aws-sdk-s3` integration test in `crates/cairn-server/tests/` and a row in `docs/COMPAT.md`. (crates/cairn-server/tests/*.rs, docs/COMPAT.md)
- [x] A3 Multipart: 7 ops, part size/count limits, `UploadPartCopy` ranges, abort cleans parts, complete validates ETags and order. (crates/cairn-server/tests/multipart.rs)
- [x] A4 Conditional requests (`If-Match`, `If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`) on GET/HEAD/PUT/Copy; `Range` incl. suffix ranges; `412`/`304`/`416` correct. (crates/cairn-server/tests/range_conditional.rs)
- [x] A5 Checksums: CRC32, CRC32C, SHA1, SHA256, CRC64NVME on put/get/multipart (composite), `x-amz-checksum-mode`. (crates/cairn-server/tests/objects.rs, multipart.rs)
- [x] A6 Versioning semantics match AWS: delete markers, `versionId=null` for unversioned, `ListObjectVersions` ordering, suspended state. (crates/cairn-server/tests/versioning.rs)
- [x] A7 Error XML bodies match AWS shape (Code/Message/Resource/RequestId) for every error path; `x-amz-request-id` on every response. (crates/cairn-server/tests/buckets.rs)
- [ ] A8 `aws s3 cp/sync/ls/rm/mb/rb`, `rclone sync`, `mc` (MinIO client) work end-to-end (manual run recorded in `docs/COMPAT.md`).
- [ ] A9 ceph `s3-tests` tagged subset ≥ 80% pass with an allowed-failure list (`scripts/s3-tests/`).
- [~] A10 Soft delete, trash list/restore/purge, PITR `head_at` + `x-cairn-as-of`, retention window GC all have integration tests. (soft delete + `x-cairn-as-of` + `x-cairn-include-trash`: crates/cairn-server/tests/pitr.rs; trash list/restore/purge and retention GC are engine-tested only (crates/cairn-engine/tests/engine.rs) until the admin API / `x-cairn-restore` surface lands)

## B. Security
- [~] B1 SigV4 header and query (presigned) verification via `s3s` + `cairn-auth` secret lookup; clock skew ±15 min; replay of expired presign rejected. (B side: `CairnS3Auth` secret lookup incl. STS sessions, token check in `CairnS3Access`, s3s enforces skew/presign expiry; own verifier for STS/admin tested in `cairn-auth/src/sigv4/tests.rs`. Remains: A wires it into the server + aws-sdk test with an expired presign.)
- [~] B2 Policy evaluation on every S3 and admin request: identity ∪ group ∪ bucket policy ∪ PublicAccessBlock; explicit deny wins; anonymous only via bucket policy. (Evaluator + bridge done: `cairn-auth/src/s3s_bridge/tests.rs`, 19 tests incl. 45-row op→action table, deny/allow/anonymous/PAB/conditions/copy/DeleteObjects; admin requests evaluated per `cairn:*` action. Remains: server wiring + `crates/cairn-server/tests/` policy tests.)
- [~] B3 STS `AssumeRole` / `GetSessionToken`; session tokens expire and are revocable. (`cairn_auth::sts::router`: AssumeRole/GetSessionToken/GetCallerIdentity, `cairn-auth/src/sts/tests.rs`; expiry + revocation via `revoke_session` / admin `DELETE /_cairn/v1/sessions/{id}`, revoked on user/role delete; phase 3c adds OIDC `AssumeRoleWithWebIdentity` (`StsState::with_oidc`, `cairn-auth/src/oidc/tests.rs`: local JWKS, RS256/ES256, expired/wrong-aud/wrong-iss/unknown-kid/rotation/trust conditions) and `CredentialStore::authenticate_secret` used by MCP. Remains: A mounts the STS router (with OIDC providers from config) in the server + an aws-sdk STS round-trip test.)
- [~] B4 Root credentials bootstrapped at `cairn init`, never logged; all secrets `zeroize`d; `Authorization`, `x-amz-security-token`, secret keys redacted in logs (test asserts). (Secrets are `SecretString`/`MasterKey`/s3s `SecretKey`, zeroized and redacted in `Debug`; `cairn-admin/src/tests.rs::secrets_never_logged` asserts no secret/token/signature in TRACE logs. Remains: root bootstrap in `cairn init` (A, `CredentialStore::ensure_root` ready); response bodies carrying new secrets are plain `String`s.)
- [ ] B5 Rate limiting per key / per IP / anonymous (DESIGN §8.3), `503 SlowDown`, configurable; request body size limits; header count/size limits.
- [ ] B6 TLS via rustls with PEM reload; HTTP→HTTPS not assumed (document reverse-proxy mode, trust `X-Forwarded-For` only from configured CIDRs).
- [ ] B7 SSE-S3 (server master key from file/env), SSE-C with key-scoped blob ids (DESIGN §15 Q5); keys never persisted in metadata in plaintext.
- [ ] B8 Object Lock governance/compliance + legal hold enforced on delete/overwrite/GC.
- [x] B9 `cargo deny` (licenses, advisories, bans) and `cargo audit` in CI; `SECURITY.md` with disclosure policy; no `unsafe`. (`.github/workflows/security.yml` on push + weekly; `deny.toml` with reasoned exceptions; local run 2026-11-08: `cargo deny check` advisories/bans/licenses/sources ok, `cargo audit` 0 vulnerabilities; `SECURITY.md`; `#![forbid(unsafe_code)]` in every crate root. Enable GitHub private vulnerability reporting when the repo goes public.)
- [x] B10 Admin API (`/_cairn/v1`) requires root or `cairn:*` policy; CORS default-deny; no debug endpoints exposed by default. (`cairn-admin/src/tests.rs`: `policy_controls_admin_access`, `unauthenticated_and_bad_signature_get_error_envelope`, `cors_default_deny_and_unknown_routes`; the auth layer is inside `cairn_admin::router`, so it holds wherever A mounts it.)

## C. Durability and recovery
- [~] C1 Crash consistency: kill -9 during put / multipart complete / delete leaves no half-committed object or orphan visible (test injects abort between blob fsync and meta commit; recovery sweeps `tmp/`). (recovery after unclean shutdown (tmp sweep, orphan blob sweep, orphan uploads, `latest` repair): crates/cairn-engine/tests/engine.rs `recovery_after_unclean_shutdown`; no fault-injection kill -9 test yet)
- [x] C2 GC never deletes a referenced blob (property test over random op sequences + gc ticks). (crates/cairn-engine/tests/engine.rs `gc_never_deletes_referenced_blobs`)
- [ ] C3 `cairn fsck` detects orphan blobs, missing blobs, refcount drift, corrupt blobs (injected), and `--repair` fixes what is safe.
- [ ] C4 `cairn scrub` verifies blob hashes on a schedule with IO throttling.
- [ ] C5 `cairn backup` (snapshot + incremental blobs, encrypted) and `cairn restore` round-trip test.
- [ ] C6 Async replication to a second Cairn / any S3 endpoint with a durable cursor; round-trip test between two in-process servers.
- [~] C7 Metadata schema migrations: version in `kv`, pre-upgrade snapshot, `cairn migrate --dry-run`, test from a committed v1 fixture. (`cairn_meta::migrate` + `docs/OPERATIONS.md` "Upgrades"; tests incl. committed `crates/cairn-meta/tests/fixtures/meta-v1.redb`. Remains: `cairn migrate --dry-run` subcommand and calling `migrate()` at server start, A.)
- [ ] C8 Disk-full handling: writes fail with `507 InsufficientStorage`/`SlowDown`, server stays up, GC can run.
- [x] C9 Graceful shutdown: in-flight requests drain with timeout; writer thread flushes; redb closes cleanly; `SIGTERM` test. (crates/cairn-cli/tests/cli.rs (SIGTERM), crates/cairn-server/tests/server.rs)

## D. Operability
- [x] D1 `/healthz` (process up) and `/readyz` (meta open, blob dir writable, not shutting down) with tests. (crates/cairn-server/tests/server.rs)
- [ ] D2 `/metrics` Prometheus: request count/latency by op and status, bytes in/out, blob count/bytes, trash bytes, gc runs, outbox depth, replication lag.
- [ ] D3 Structured `tracing` logs (JSON option), request id correlation, audit JSONL for mutating + auth-denied ops with rotation.
- [ ] D4 Config: full reference generated by `cairn config schema`; every key has a default; env overlay `CAIRN_*`; `cairn config check` validates and prints effective config with secrets masked.
- [ ] D5 Lifecycle worker (expiration, noncurrent expiration, abort-incomplete-mpu) and GC worker run on schedule, are observable in metrics, and are tested with a fake clock.
- [ ] D6 Bucket quotas (`507`) and per-bucket retention windows enforced and visible in admin API.
- [~] D7 Events: durable outbox, webhook + function sinks with retry/backoff/DLQ, exactly-the-committed-set-after-crash test. (Library done: `crates/cairn-events/tests/outbox.rs::crash_mid_batch_delivers_exactly_the_committed_set`, `tests/sinks.rs` per auth mode, 30 tests. Remaining: engine calls `Outbox::append` in its commit closures (A), `Put/GetBucketNotificationConfiguration` in cairn-s3 (A), server spawns `DeliveryWorker`s from `[[events.sinks]]` (A, needs `EventsConfig.sinks`), SSE router mounted under admin auth (B), outbox depth/DLQ metrics wired to `/metrics`.)
- [~] D8 Admin CLI covers users/keys/groups/policies/roles/buckets/trash/pitr/quota/lock; `--json` output. (`cairn_admin::cli` covers all listed areas + sessions/service accounts, `--json`; e2e test `cli_end_to_end_over_loopback`. Remains: mount in cairn-cli and a real `AdminEngine` for buckets/trash/pitr.)
- [~] D9 MCP server (stdio + streamable HTTP) exposing DESIGN §11.1 tools under policy; tested with an rmcp client. (`cairn-mcp`: 14 tools, `serve_stdio` / `http_router` at `/_cairn/mcp`, per-call IAM with `cairn:McpTool`; `crates/cairn-mcp/tests/tools.rs`: 10 tests with an in-process rmcp client against a real `CairnEngine` under restricted policies (allow/deny, `cairn:McpTool`, bucket policy, caps, PITR restore, revocation) and HTTP bearer/STS/SigV4; docs/MCP.md. Remains: A mounts `http_router` and adds `cairn mcp --stdio`; dropped tools listed in docs/MCP.md.)

## E. Performance
- [~] E1 `bench/` harness runs on the dev host; results committed as markdown with host description. (`bench/run.sh` (warp v1.8.2), `bench/README.md` method, `bench/RESULTS.md` template with host fields. Remaining: first run once `cairn serve` exists.)
- [ ] E2 Small-object PUT/GET ≥ 5k req/s on a 4-vCPU reference host or documented shortfall; large-object throughput saturates disk; p99 recorded.
- [ ] E3 No unbounded memory: streaming bodies end-to-end, bounded channel sizes, list paging capped, verified under a 10 GiB upload with RSS recorded.

## F. Release and docs
- [ ] F1 `cargo fmt`, clippy `-D warnings`, `cargo test --workspace`, `cargo doc` (no warnings) green in CI on every push.
- [~] F2 Release workflow: tag → static musl x86_64 + aarch64 binaries, Docker image to GHCR (non-root, distroless/alpine), SBOM, SHA256SUMS, GitHub Release notes from `CHANGELOG.md`. (`.github/workflows/release.yml`, actionlint-clean; zigbuild + cargo-auditable, syft CycloneDX, SHA256SUMS, `scripts/changelog-section.sh`, distroless/static:nonroot multi-arch image. Remaining: exercised by the first tag, F6.)
- [x] F3 `deploy/Dockerfile` multi-stage, `docker compose` example, systemd unit example, Helm chart deferred (phase 4). (`deploy/Dockerfile` (musl build → distroless/static:nonroot, uid 65532, `release` target for prebuilt binaries), `deploy/docker-compose.yml` (`docker compose config` valid, read-only rootfs, cap_drop ALL), `deploy/cairn.service` (hardened; `systemd-analyze verify` clean apart from the binary not being installed), `deploy/cairn.example.toml` checked against `Config::default()` by `crates/cairn-events/tests/deploy_example_config.rs`. Image build first runs in release.yml; no Docker daemon on the dev host.)
- [~] F4 README: 60-second quickstart, feature matrix vs MinIO, compatibility statement, licence; `docs/COMPAT.md`, `docs/EXTENSIONS.md`, `docs/OPERATIONS.md` (backup, restore, upgrade, DR runbook), `docs/CONFIG.md` (generated). (README done 2026-11-08 (Agent C). Remaining: COMPAT.md/EXTENSIONS.md (A, 1c), OPERATIONS.md runbooks, CONFIG.md from `cairn config schema`.)
- [~] F5 Name check on crates.io / Docker Hub / GitHub / trademarks recorded in `docs/BUILD-PLAN.md`; rename done if needed before tag. (`scripts/name-check.sh` run 2026-11-08, table in BUILD-PLAN decisions log: crates.io `cairn`, `cairn-cli`, `cairn-core` taken; two same-category GitHub projects named Cairn. Recommendation: rename before the first public tag. Remaining: maintainer decision, manual trademark search, rename.)
- [ ] F6 `v0.1.0-alpha` tag produces downloadable binaries that pass the quickstart on a clean machine.
