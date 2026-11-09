# Cairn — Decisions log

Dated (UTC) design and implementation decisions, newest last. Moved out of `BUILD-PLAN.md` on
2026-11-08 so the plan stays short. Add a line here whenever a DESIGN decision changes.

- **2026-11-08 (Agent A) — `cairn-meta` write API is closure-based, not a `WriteTxn` future.**
  The contract sketched `fn write(&self) -> impl Future<Output = WriteTxn>`. redb write
  transactions are `!Send`-hostile across awaits and must stay on one thread, so the store runs a
  dedicated `cairn-meta-writer` thread instead. API:
  `RedbMetaStore::open(path)`, `store.read() -> ReadTxn` (`MetaStore` trait),
  `store.write(|txn: &WriteTxn| -> Result<T, E> { .. }).await` where `E: From<MetaError>`.
  Group commit: the writer drains up to 128 queued jobs into one redb transaction; if any job
  returns `Err` (or panics) the batch is aborted and each job is re-run alone, so **write closures
  must be `FnMut` and deterministic over the state they read** (no side effects outside the txn).
  Results resolve only after the commit is durable.
- **2026-11-08 (Agent A) — every table is `&[u8] → &[u8]`.** `Table` enum (`cairn_meta::Table`)
  lists all tables from DESIGN §4.3 plus `blob_gc_idx` (`unref_at ‖ BlobId`, so GC finds
  refcount-0 blobs without a full scan) and `bucket_trash_idx`. Values are
  `[SCHEMA_VERSION=1] ‖ postcard(record)` via `cairn_meta::records::{encode, decode}`. Generic
  access: `Reader::{get, scan, scan_prefix}` (implemented by both `ReadTxn` and `WriteTxn`, scans
  can `Flow::Seek` to skip subtrees) and `WriteTxn::{put, del}`. Agent B: `principals`,
  `access_keys`, `policies`, `sessions` tables exist for `cairn-auth`; use `encode`/`decode` with
  your own record types.
- **2026-11-08 (Agent A) — `latest` stores the full `VersionRecord` inline** (DESIGN §15 Q3:
  yes). It always equals the newest `Live` version of the key (may be a delete marker) and is
  recomputed with `WriteTxn::refresh_latest` after every mutation of that key. `BucketNotEmpty`
  is therefore an O(1) prefix probe of `latest`.
- **2026-11-08 (Agent A) — object keys may not contain NUL.** `versions` keys are
  `BucketId ‖ key ‖ 0x00 ‖ VersionId`; a NUL inside a key would break per-key range scans. S3
  technically allows it; no real client relies on it. Rejected with `InvalidArgument`.
- **2026-11-08 (Agent A) — VersionId string form is 40 lowercase hex chars** (order-preserving).
- **2026-11-08 (Agent A) — blob encryption layout.** Encrypted blobs are stored as
  `blobs/ab/cd/<hex>.enc` (plaintext blobs have no suffix and no header, so they stay
  `sendfile`-able): 48-byte header (`CRNB`, version, 32-byte salt, plaintext size) then 64 KiB
  chunks sealed with AES-256-GCM, per-blob key = BLAKE3-derive(data key ‖ salt),
  nonce = `0u32 ‖ index`, AAD = `blob id ‖ index`. Because the blob id (BLAKE3 of plaintext) is
  only known at the end of the stream, the writer first seals chunks into `tmp/` with an
  ephemeral random key, then re-seals them under the final key/AAD in `finish()` — plaintext never
  touches disk, at the cost of a second crypto pass. Dedup is by plaintext hash, so an existing
  blob wins regardless of encryption; per-customer keys (SSE-C) will need key-scoped blob ids in
  phase 2.
- **2026-11-08 (Agent A) — phase-1 crates do not depend on `cairn-auth` / `cairn-admin` /
  `cairn-events` / `cairn-mcp`.** These edges were removed from `cairn-engine`, `cairn-s3` and
  `cairn-server` so that Agent A's builds are not broken by in-progress work in parallel crates.
  Re-add them in phase 2 when wiring `S3Access` and the admin API.
- **2026-11-08 (orchestrator) — scale and serverless posture.** v1 stays single-writer; HA is
  active-passive via replication; blob tiering to remote S3 moves from post-v1 to phase 3b;
  multi-node (Raft + hashing) remains post-v1 behind unchanged `MetaStore`/`BlobStore` traits.
  Cairn-as-a-function is a non-goal; Cairn-calls-functions is first-class via function sinks
  (`sigv4-lambda`, `bearer`, `cf-access` auth modes) so `LambdaFunctionConfigurations` works
  unchanged. Object Lambda (GET-time transform) is out of scope for v1.
- **2026-11-08 (orchestrator) — phase 1b auth rewrite and partial engine committed as-is.** Agent
  B's uncommitted rewrite (store/sts/sigv4 tests, 3.2k lines) and Agent A's engine
  bucket/object/multipart/commit modules compiled and passed tests, so they were committed to
  give phase 1c a clean baseline. `recovery.rs` is an empty placeholder owned by A.
- **2026-11-08 (Agent C) — `cairn-events` sits beside `cairn-meta`, below the engine; engine
  hook.** `cairn-events` depends on `cairn-core` + `cairn-meta` only (the `cairn-engine` edge was
  removed), so the engine can depend on it and emit events inside its commit closure. DESIGN §3
  dependency line updated. The hook A calls (one per committed mutation, same closure, then wake
  the workers after the write resolves):
  ```rust
  // cairn_events::Outbox (cheap Clone; one per server, built with Outbox::new(capture_all))
  pub fn append(&self, txn: &cairn_meta::WriteTxn, bucket: cairn_core::BucketId,
                event: &cairn_events::Event) -> Result<Option<u64>, cairn_events::EventsError>;
  pub fn notify(&self);
  // e.g. store.write(move |txn| { /* mutate */ ob.append(txn, b, &ev)?; Ok(r) }).await?; ob.notify();
  ```
  `append` reads the bucket's notification configuration from the same transaction, so it is
  deterministic under group-commit re-runs, and returns `None` (writes nothing) when no rule
  matches and `capture_all` is false (set it true when the SSE stream is enabled). The engine
  error type needs `From<EventsError>`. `Event::new(name, bucket, key)` plus the public fields
  (`size`, `etag`, `version_id`, `principal`, `source_ip`, `request_id`, `region`, `time`,
  `extra`) build the record. `cairn-s3` maps `Put/GetBucketNotificationConfiguration` with
  `cairn_events::notification::{store, load, remove}` (kv, keyed by `BucketId`) and
  `NotificationConfiguration::{from_xml, to_xml, validate_destinations}`; call `remove` when a
  bucket is purged. Admin (B) mounts `cairn_events::sse_router(SseBroadcast)` behind its auth layer.
- **2026-11-08 (Agent C) — outbox layout, no new tables.** The brief said `events_outbox`; the
  existing `events_queue` table (DESIGN §4.3) is used instead so `cairn-meta` needed no change:
  `0x01 ‖ seq:u64be → OutboxRecord {event, targets, only_sink}`, DLQ rows
  `0x02 ‖ sink ‖ 0x00 ‖ seq:u64be → DlqRecord`. `kv` holds `events/seq` (last sequence),
  `events/cursor/<sink>` and `events/notification/<BucketId>`. Delivery is at-least-once of
  exactly the committed set: the cursor advances only after the destination accepts a batch or
  the batch is dead-lettered; receivers dedupe on the idempotency key (16-hex sequence, in
  `cairn.id` of each record and the `x-cairn-idempotency-key` header, comma-joined for batches).
  Rows below the minimum cursor of all sinks are removed by `worker::compact_outbox`. Backoff:
  `base·2^(n-1)` capped, equal jitter; defaults 8 attempts, 500 ms → 5 min. 4xx other than
  408/429 is permanent (straight to DLQ); redirects are not followed.
- **2026-11-08 (Agent C) — wire formats for sinks.** Body = S3 event message
  `{"Records":[…]}` (schema 2.1; `eventSource` is `aws:s3` for S3 event types so existing Lambda
  handlers work, `cairn:s3` for `cairn:*`; keys form-URL-encoded with `/` kept, like AWS).
  HMAC: `x-cairn-timestamp: <unix s>`, `x-cairn-signature: v1=hex(HMAC-SHA256(secret,
  "<timestamp>.<body>"))`. `sigv4-lambda`: `POST /2015-03-31/functions/<fn>/invocations` on
  `lambda.<region>.amazonaws.com` (or `url` override), `X-Amz-Invocation-Type: Event` default,
  signed with the in-crate SigV4 signer (AWS test-suite vectors in `sigv4.rs`). Function sinks
  default to one record per request (Lambda semantics), webhooks to 10. Sink definitions
  deserialize as `cairn_events::SinkConfig` (TOML `[[events.sinks]]`, `auth = { mode = … }`);
  **request to A:** add `sinks: Vec<toml::Table>` (or similar passthrough) to
  `cairn_core::EventsConfig` so the server can hand each entry to `WebhookSink::from_config`
  (core cannot depend on events). Secrets are a deserialize-only `Secret` (zeroized, redacted
  `Debug`), outbound credential headers are marked sensitive.
- **2026-11-08 (Agent C) — release engineering choices.** Release builds use **cargo-zigbuild**
  (not `cross`: no Docker-in-Docker, zig cross-compiles `ring`'s C/asm for aarch64-musl) wrapped
  by `cargo auditable`, on **GitHub-hosted `ubuntu-latest`** (tags only; >1 vCPU for LTO, Docker
  daemon for GHCR), while `ci.yml`/`security.yml`/`s3-tests.yml` stay on `self-hosted`. Images
  are `distroless/static:nonroot` (uid 65532) built from the released binaries
  (`deploy/Dockerfile --target release`), so nothing compiles under QEMU. SBOM = CycloneDX from
  syft over the auditable binary. Release-workflow actions are pinned by commit SHA. Workspace
  `rust-version` raised 1.85 → **1.88** (let-chains are already used; ctutils 0.4.8 needs ≥ 1.87)
  and internal path deps carry `version = "0.1.0"` (cargo-deny wildcard ban). `cargo deny` ignores
  three unmaintained-only advisories with reasons in `deny.toml` (atomic-polyfill via postcard,
  pin-utils via aws-sdk dev-dep, **rustls-pemfile — direct dep of cairn-server, A should move to
  `rustls-pki-types` `PemObject` in 2a**). GitHub private vulnerability reporting cannot be
  enabled while the repo is private (API 404); enable it when the repo goes public (SECURITY.md
  already points to it).
- **2026-11-08 (Agent C) — name check (`scripts/name-check.sh`, run 2026-11-08 12:19 UTC).**
  | name | crates.io | Docker Hub | GitHub |
  |------|-----------|------------|--------|
  | `cairn` | **taken** (v0.0.0, "build-gated version control", 256 dl) | 10 repos named cairn (top `wabarc/cairn`, 21k pulls); no official image | 62 repos (top `oritera/Cairn`, 4.9k★, AI pentest engine, also AGPL); org `@cairn` exists |
  | `cairn-s3` | free | free | free |
  | `cairnstore` | free | free | free |
  | `cairn-server` | free | 1 repo (196 pulls) | 4 small repos |
  | `cairn-cli` | **taken** (v0.1.6) | free | 5 small repos |
  | `cairn-core` | **taken** (v0.1.0) | free | 1 repo; org `@cairn-core` exists |
  Also found by search: `Harsh-2002/Cairn`, "self-hosted, S3-compatible object storage" (6★) and
  `bdarwin/cairn` (S3 server in Java) — same product category. Trademarks not checked (manual:
  USPTO/EUIPO classes 9/42). **Recommendation: rename before the first public tag.** The bare
  name is crowded in exactly our category and three of our crate names are taken on crates.io,
  so publishing crates would be impossible as-is. If the brand is kept, distribution names
  become `cairnstore` (crates `cairnstore-*`, binary `cairn` is fine, image
  `ghcr.io/solutionforest/cairn` is namespaced and fine); otherwise pick a new name and re-run
  `scripts/name-check.sh <name>`. Decision belongs to the maintainers; PRODUCTION-READINESS F5
  stays open until then.
- **2026-11-08 (Agent C) — conformance and benchmark tooling.** `ceph/s3-tests` upstream has
  moved into `ceph/ceph`; `scripts/s3-tests/run.sh` pins the last standalone commit
  (`5b39871`, 2026-10-12) and deselects unimplemented feature markers (list in its README).
  Benchmarks use MinIO `warp` v1.8.2 via `bench/run.sh` rather than a custom Rust harness (no
  extra compile on the 1-vCPU host, results comparable with published MinIO numbers).
- **2026-11-08 (Agent B) — `cairn-auth` depends on `cairn-meta`, `s3s`, `axum`, `http`,
  `async-trait`, always on (no cargo feature).** The only consumer that links cairn-auth is the
  server binary, which links s3s and axum anyway; a feature gate would only add a test matrix on
  a 1-vCPU host. `async-trait` added to `[workspace.dependencies]` (s3s traits need it).
- **2026-11-08 (Agent B) — IAM persistence layout.** `MetaCredentialBackend` (redb
  `CredentialBackend`) routes the store's key prefixes to the DESIGN §4.3 tables: `u/ g/ r/` →
  `principals`, `k/ x/` → `access_keys`, `p/` → `policies` (managed policies), `s/` → `sessions`.
  Bucket policies and PublicAccessBlock live in `policies` under `b/<bucket>`
  (`BucketPolicyStore`), not in the engine's bucket record; the bridge reads them through the
  `BucketAuthzSource` trait so the engine can become the source later without touching the
  bridge. The backend trait is synchronous, so writes `block_on` the cairn-meta writer future on
  the calling thread (safe: the writer is an OS thread, not a tokio task); this blocks one tokio
  worker for one commit on IAM writes and STS issuance, which are rare.
- **2026-11-08 (Agent B) — s3s does not check `x-amz-security-token`.** `CairnS3Access::check`
  re-resolves the access key and verifies the session token in constant time (`InvalidToken`),
  so STS credentials are only usable with their token. `CairnS3Auth` maps unknown / inactive /
  expired / revoked / orphaned keys to `InvalidAccessKeyId`; a key that disappears between
  signature check and access check yields `ExpiredToken`. Clock skew (±15 min) and presign
  expiry stay with s3s (`presigned_url_max_skew_time_secs` default 900).
- **2026-11-08 (Agent B) — S3 authorisation details.** Resource ARNs: `arn:aws:s3:::*` for
  ListBuckets, `arn:aws:s3:::bucket` for bucket ops, `arn:aws:s3:::bucket/key` for object ops;
  `?versionId=` selects the `*Version*` action. CopyObject/UploadPartCopy also require
  `s3:GetObject[Version]` on the copy source. `DeleteObjects` is checked per key in the
  `delete_objects` access hook and is **all-or-nothing** (any denied key → `AccessDenied` for the
  request; AWS reports per-key errors instead). `BlockPublicAcls` rejects public canned ACLs and
  `x-amz-grant-*` to AllUsers/AuthenticatedUsers on ACL-carrying ops; `BlockPublicPolicy` is
  enforced in `BucketPolicyStore::put_policy`; `RestrictPublicBuckets` in the evaluator.
  s3s operations without an IAM mapping are allowed for root and denied for everyone else.
  `s3:ExistingObjectTag/*` is not populated (needs an engine lookup; phase 2a+).
- **2026-11-08 (Agent B) — STS and admin authentication.** STS is served on `GET /?Action=` and
  form-encoded `POST /` (`cairn_auth::sts::is_sts_request` decides, before s3s); also implements
  `GetCallerIdentity`. AssumeRole on a missing role answers `AccessDenied` (no existence leak).
  STS and the admin API share `cairn_auth::sts::authenticate` (Cairn's own SigV4 verifier: host
  must be signed, body hash computed server-side, ±15 min skew, presign ≤ 7 days). The admin API
  answers authentication failures with **401** (AWS-style codes in the JSON envelope) and policy
  denials with 403. Admin actions are evaluated on `arn:cairn:admin:::server`, bucket-scoped ones
  (trash, purge, PITR, quota, retention) on `arn:aws:s3:::bucket` (restore on the object ARN).
  New actions: `cairn:UpdatePolicy`, `cairn:ListSessions`, `cairn:RevokeSession`.
- **2026-11-08 (Agent B) — `cairn-admin` does not depend on `cairn-engine` in phase 2b.** Storage
  operations go through `cairn_admin::AdminEngine` (DTOs use RFC 3339 strings); A implements it
  for `CairnEngine` when wiring. The CLI module returns `anyhow::Result` because only the binary
  consumes it.
- **2026-11-08 (Agent B) — migrations API takes the database path.** `cairn_meta::migrate::
  migrate(path, dry_run)` (not `migrate(store, …)`): it must copy the redb file before any write
  and redb holds an exclusive lock, so it opens/closes the store itself and must run before the
  server opens it. `schema_version` is a raw big-endian `u32` in `kv` (not a postcard record); a
  database with data but no stamp is v1; an empty one is stamped with `CURRENT_SCHEMA`.
  Committed fixture: `crates/cairn-meta/tests/fixtures/meta-v1.redb` (force-added past the
  `*.redb` ignore rule).
- **2026-11-08 (Agent B) — phase 2b wiring for Agent A.** (1) `RedbMetaStore` → run
  `cairn_meta::migrate::migrate(&db_path, false)` before `open`; `cairn migrate --dry-run` =
  `migrate(&db_path, true)` printing the report. (2) `let store = Arc::new(CredentialStore::new(
  Arc::new(MetaCredentialBackend::new(meta.clone())), master_key))`; `store.ensure_root(ak, &sk)`
  at boot/`cairn init`. (3) `let policies = Arc::new(BucketPolicyStore::new(meta.clone()))`;
  `builder.set_auth(CairnS3Auth::new(store.clone()))`, `builder.set_access(CairnS3Access::new(
  store.clone(), policies.clone()))`; insert `cairn_auth::RequestMeta { source_ip, secure }` into
  request extensions before s3s; read `cairn_auth::AuthenticatedCaller` from
  `S3Request::extensions` in ops. Put/Get/DeleteBucketPolicy, GetBucketPolicyStatus and
  Put/Get/DeletePublicAccessBlock call `BucketPolicyStore` (map `AuthError::Policy` →
  `MalformedPolicy`, `AccessDenied` → `AccessDenied`); call `forget_bucket` on bucket purge.
  (4) Route `cairn_auth::sts::is_sts_request(..)` requests to
  `cairn_auth::sts::router(StsState::new(store.clone()))`. (5) Merge
  `cairn_admin::router(AdminState::new(store, Arc::new(<engine impl AdminEngine>)))` (paths
  already start with `/_cairn/v1`). (6) In cairn-cli: `.subcommand(cairn_admin::cli())`; on
  `("admin", m)`: `let c = cairn_admin::cli::client_from_matches(m)?; cairn_admin::cli::run(m,
  &c).await`.
- **2026-11-08 (Agent A) — phase 1c engine/S3/server contract notes.**
  (1) Engine additions: `list_objects(bucket, &ListReq)`, `list_object_versions(bucket,
  &ListVersionsReq)`, `recover(full) -> RecoveryReport` (call after `open`, before serving),
  `cleanup_orphan_uploads`, `check_latest(sample)`, `sweep_orphan_blobs(min_age)`,
  `gc_tick(now: Ts) -> GcStats` (explicit clock so tests can fake time), `trash_list`,
  `trash_restore`, `trash_purge`, `pitr_head_at`, `pitr_diff`, `data_dir()`, `is_shut_down()`.
  `CreateUploadReq` gained `full_object_checksum`, `CompletePart` gained `checksum`.
  (2) **Trash restore writes a new version** sharing the hidden version's blobs (DESIGN §7.3
  "always creates a new latest pointer"); it never flips a version back to Live, so stale
  `trash_idx` rows are harmless. GC re-derives each hidden version's due time from the bucket's
  *current* retention and re-queues entries that are not due (or are locked).
  (3) Unclean-shutdown detection is a `meta/RUNNING` marker file written at `open` and removed by
  `shutdown()`; when present at startup, recovery also sweeps unreferenced blob files.
  (4) FULL_OBJECT multipart checksums are marked by `MultipartRecord.template.checksum =
  Some(StoredChecksum { value: "", composite: false })` — no record schema change. The final
  value is computed at Complete by re-reading the assembled object (O(object) extra read, only
  when requested; CRC64NVME uploads always use it, as AWS does).
  (5) `ready()` used to call `clean_tmp()`, which deleted in-flight uploads' temp files; it now
  probes `tmp/` writability instead.
  (6) s3s 0.17 does not emit `<Resource>`/`<RequestId>` in error XML nor any request-id header:
  `cairn-server` generates a 16-hex request id per request (`cairn_s3::RequestId` in request
  extensions), stamps `x-amz-request-id`/`x-amz-id-2` on every response and splices missing
  `Resource`/`RequestId` into error bodies.
  (7) `cairn-s3` caller identity: a `cairn_core::PrincipalId` in the request extensions wins
  (Agent B's `S3Access` should insert one); otherwise the root key → `root`, any other key →
  `user:<access key>`, unsigned → `anonymous`. Hooks: `CairnS3Builder::with_auth(Arc<dyn
  S3Auth>)` and `with_access(impl S3Access)` (generic, so per-operation `S3Access` hooks are kept).
  (8) `/healthz` and `/readyz` are answered only for unsigned, query-less GET/HEAD so buckets with
  those names stay reachable. `cairn_server::ConnInfo { peer, secure }` is in request extensions
  for the auth bridge's `RequestMeta`.
  (9) New config key `server.shutdown_grace` (default 30s); `Config::validate()` and
  `Config::to_redacted_toml()` back `cairn config check`. Until phase 2b moves root credentials
  into the credential store, `cairn init` writes them to `cairn.toml` (mode 0600).
  (10) `x-cairn-blob-hash` is emitted only for single-blob objects.
- **2026-11-08 (Agent B) — MCP authorisation model.** Each tool authorises the IAM action and
  resource of its S3 / admin equivalent through `CairnS3Access::authorize_action` (bucket policy
  and PAB included) with `cairn:McpTool` = tool name, `aws:SecureTransport`, `aws:SourceIp` (HTTP)
  and the S3 keys the equivalent request would carry (`s3:prefix`, `s3:VersionId`,
  `s3:RequestObjectTag/*`, `cairn:AsOf`). Time travel (`as_of` without a version id,
  `pitr_head_at`) needs the base read action **and** `cairn:TimeTravel` on the same resource, with
  `cairn:AsOf` in the context; the s3s bridge now enforces the same for `x-cairn-as-of` on
  Get/HeadObject and ListObjects(V2) (it was documented in EXTENSIONS but not checked);
  trash/PITR use the admin API's actions (`cairn:ListTrash` / `cairn:Restore` on the object /
  `cairn:PitrDiff` / `cairn:Pitr`). Authorisation runs before any lookup, so a denied call is
  always `AccessDenied` (no bucket/key existence oracle). `list_buckets` needs
  `s3:ListAllMyBuckets` and then returns only buckets where `list_objects` would be allowed.
  Tool failures are `isError: true` results with `{"error": <S3 code>, "message"}`; bad JSON
  arguments are JSON-RPC errors.
- **2026-11-08 (Agent B) — MCP transports and session binding.** HTTP authenticates *every*
  request (bearer `ak:secret[:token]` via `CredentialStore::authenticate_secret`, or SigV4 via
  `sts::authenticate` with the body buffered up to `max_http_body`); the resolved `McpCaller` goes
  into request extensions and tools read it from the `http::request::Parts` rmcp injects. The
  `Mcp-Session-Id` is not a credential. rmcp's Host allow-list (DNS-rebinding guard) is disabled
  by default because credentials are mandatory; `McpConfig::allowed_hosts` re-enables it. stdio
  holds the env credentials (zeroized) and re-verifies them on every call so revocation is
  immediate. Path is `/_cairn/mcp` (DESIGN §11.1 said `/mcp`; changed so all Cairn extensions
  live under `/_cairn/`).
- **2026-11-08 (Agent B) — MCP tool set.** Shipped: `list_buckets`, `list_objects`, `get_object`
  (text/base64/auto, 1 MiB cap with truncation, ranges), `head_object`, `put_object` (≤ 4 MiB),
  `delete_object`, `copy_object`, `search` (metadata scan, ≤ 10k keys/call), `trash_list`,
  `trash_restore`, `pitr_head_at`, `pitr_diff`, `pitr_restore` (dry-run default, `confirm`
  required, ≤ 1000 changes/call), `bucket_info`. The engine has no PITR-restore primitive, so
  `pitr_restore` applies `pitr_diff` with existing writes: hidden "then" versions via
  `trash_restore`, still-live ones (versioned buckets) via `copy_object` with `src_version`,
  removals via `delete_object` — each a normal new version, so the restore is reversible. When A
  adds `CairnEngine::pitr_restore` for the admin API, switch the tool to it. Dropped: `presign` and
  `get_object mode=url` (the MCP server does not know the client-facing S3 endpoint),
  `storage_stats` (needs the admin stats source), `set_bucket_policy` (use S3/admin), tag/metadata
  filters in `search` (would leak tag values to callers without `s3:GetObjectTagging`), semantic
  search (phase 4), MCP resources and prompts.
- **2026-11-08 (Agent B) — OIDC federation.** `jsonwebtoken` 11 with the RustCrypto backend
  (`rust_crypto`; no OpenSSL / aws-lc). It pulls `rsa` 0.9 (RUSTSEC-2023-0071, Marvin) and
  `crypto-bigint` 0.5 (RUSTSEC-2026-0387); both concern secret-key timing and Cairn only verifies
  with public keys, so they are ignored in `deny.toml` and `security.yml` with that reason
  (re-check when jsonwebtoken moves to rsa 0.10). Accepted algorithms: RS256/384/512,
  PS256/384/512, ES256/384; JWKs must be asymmetric and not `use: enc`. No OIDC discovery:
  `jwks_url` or inline `jwks` is required. Trust evaluation is separate from `PolicySet` because
  the caller is not a Cairn principal: Allow needs an explicit `Federated` match (issuer URL,
  provider id, or `oidc-provider` ARN), `Principal: "*"` never grants, Deny (federated or `*`)
  wins. Condition keys follow AWS: `<provider>:sub|aud|iss|azp|amr|email`,
  `aws:FederatedProvider`, `aws:RequestTag/*`, `aws:TagKeys`; mapped claims become session tags
  (`Principal.tags`, `aws:PrincipalTag/<k>` in `AuthzEngine::enrich`, caller-supplied values
  stripped). Sessions are `SessionKind::WebIdentity` — an appended enum variant, so existing
  records decode unchanged and no migration is needed (older binaries cannot read the new
  variant; downgrade = revoke those sessions first).
- **2026-11-08 (Agent B) — phase 3c wiring for Agent A.** (1) MCP over HTTP:
  `let mcp = cairn_mcp::McpState::new(engine.clone(), store.clone(), policies.clone())` with
  `engine: CairnEngine`, `store: Arc<CredentialStore>`, `policies: Arc<BucketPolicyStore>` (any
  `Arc<dyn BucketAuthzSource>`); optionally `.with_config(cairn_mcp::McpConfig { .. })`; when
  `[mcp] enabled`, `app = app.merge(cairn_mcp::http_router(mcp))` — it serves
  `cairn_mcp::MCP_PATH` = `/_cairn/mcp` (POST/GET/DELETE) and must be routed *before* s3s (a
  bucket named `_cairn` is invalid anyway). Insert `cairn_auth::RequestMeta` into request
  extensions upstream, as for s3s. Update the `[mcp]` doc comment in cairn-core config (`/mcp` →
  `/_cairn/mcp`). (2) stdio: `cairn mcp --stdio [--config]` opens the engine + credential store
  like `serve` (no listener) and calls `cairn_mcp::serve_stdio(mcp).await` (`Result<(),
  cairn_mcp::McpError>`); it reads `CAIRN_ACCESS_KEY_ID` / `CAIRN_SECRET_ACCESS_KEY` /
  `CAIRN_SESSION_TOKEN`. Logs must go to stderr in this mode (stdout is the protocol). (3) OIDC:
  add `[[auth.oidc_providers]]` to `AuthConfig` with fields `issuer: String`,
  `audiences: Vec<String>`, `jwks_url: Option<String>`, `jwks: Option<String>` (inline JSON),
  `claim_tags: BTreeMap<String, String>`; convert each to `cairn_auth::OidcProviderConfig` (same
  field names; `jwks` accepts a JSON string), then `let v = Arc::new(cairn_auth::OidcVerifier::
  new(providers)?)` (validates at boot: https-only, ≥ 1 audience) and mount
  `cairn_auth::sts::router(StsState::new(store.clone()).with_oidc(v))` instead of the plain STS
  state when the list is non-empty. `AssumeRoleWithWebIdentity` is unsigned, so STS routing must
  not require SigV4 before dispatch (`is_sts_request` already matches it). (4) PostObject is
  still A's (BUILD-PLAN 3c row).
- **2026-11-08 (Agent D) — phase 3b storage layout: no new tables.** `cairn-meta`'s `Table` enum
  is A's, so everything new lives in existing tables. `repl_cursor` (already in DESIGN §4.3, used
  instead of the brief's `kv` key): `BucketId ‖ destination ARN` → `ReplCursor {since, watermark,
  recent, delivered, failed, last_error, last_success}`. `kv`: `repl/target/<arn>` → target
  (endpoint, region, bucket, access key, ChaCha20-Poly1305-sealed secret, AAD = ARN, key =
  BLAKE3-derive of a caller key), `damaged/b/<BlobId>` and `damaged/v/<versions key>` →
  `DamageRecord {blob, kind: Missing|Corrupt, detected_at, source}` (the "x-cairn-damaged flag":
  `VersionRecord` is not changed, so no migration), `scrub/cursor` → `ScrubCursor`,
  `scrub/at/<BlobId>` → `ts_bytes(last verified)`. The replication config document is the bucket's
  `configs["replication"]` (AWS XML, so `bucket_history` keeps revisions).
- **2026-11-08 (Agent D) — replication reads `versions`, not `events_queue`.** DESIGN §9 said the
  worker consumes `events_queue`; the outbox only holds rows when a notification rule matches or
  SSE capture is on, and engine hooks were not wired, so the worker instead scans the bucket's
  `versions` rows each tick and selects `created_at > watermark − overlap (5 s)` minus the
  `recent` set (version ids are time-ordered; the overlap absorbs wall-clock steps; Live versions
  only). Cost is O(versions of replicated buckets) per tick (2 s); an engine-maintained change
  index can replace the scan later without changing the cursor. Cursor advances only past
  delivered / permanently failed versions and is checkpointed every 32, so delivery is
  at-least-once with idempotent Cairn peers. Target ARNs are registered out-of-band
  (`TargetRegistry`, like `mc admin bucket remote add`); Put requires source versioning Enabled
  and seeds cursors at "now" unless `ExistingObjectReplication` is Enabled. Replicas keep version
  id, `created_at`, metadata, tags and the part layout (same ETag); blob ids are equal on both
  sides (BLAKE3 of plaintext), which `put_replica` checks. Not replicated: version deletes, Object
  Lock state, `is_null` (replicas are regular versions).
- **2026-11-08 (Agent D) — backup format.** Logical dump (`CAIRNMETA1`, rows `[name len][table
  Debug name][u32 k][k][u32 v][v]`, trailer with row count) of every table from one `ReadTxn`, not
  a redb file copy: `RedbMetaStore` does not expose the `Database`, and a logical dump survives
  redb format changes. Restore replays it through `RedbMetaStore::write` in 4096-row jobs.
  Encryption is passphrase-based (argon2id + ChaCha20-Poly1305 STREAM, per-file BLAKE3 subkey)
  because no X25519 crate is in the workspace; an age-style X25519 recipient can be added as a
  second `kdf` kind in `cairn-backup.json` without changing the file container. Plaintext blobs
  are uploaded as-is (`sendfile`-friendly), `.enc` blobs and cold stubs as stored.
- **2026-11-08 (Agent D) — tiering stubs and last-access clock.** A cold blob leaves
  `blobs/ab/cd/<hex>.cold` (`cairn-cold 1 <size> <enc>`), so `exists`/`size`/fsck/GC walks never
  touch the network; the existing orphan sweep ignores `.cold` names (they do not parse as blob
  ids). Last access = file mtime (blobs are immutable), bumped on hot reads at most once per
  `touch_interval`. `ColdStore` trait has `RemoteBlobStore` (S3) and `DirColdStore` (mounted dir,
  test fake).
- **2026-11-08 (Agent D) — `cairn-engine` dev-depends on `cairn-server`.** Only for
  `tests/replication_http.rs` (S3Target and the S3 cold tier against `test_support::spawn`). Cargo
  allows the dev-dependency cycle; integration tests link one `cairn-engine` rlib. Cost: `cargo
  test -p cairn-engine` also builds the server. Remove the edge if it gets in A's way and move the
  file to `crates/cairn-server/tests/`.
- **2026-11-08 (Agent D) — phase 3b wiring for Agent A.** All functions exist and are tested;
  each item is a call site, not new logic.
  1. *Disk full (C8)* — already in progress in A's tree (`EngineExtras.space`): `SpaceGuard::new(
     data_dir, cfg.storage.min_free)`, `guard.check(content_length.unwrap_or(0))?` before ingest
     in put/upload_part/upload_part_copy/copy/complete, `space::is_enospc(&io_err)` →
     `StorageFull`. `impl From<StorageFull> for S3Error` picks `S3ErrorCode::parse(
     "InsufficientStorage")` and falls back to `QuotaExceeded` (also 507): **add
     `InsufficientStorage = 507, "Insufficient storage space."` to `cairn-core` codes** and the
     right code appears automatically. Add `min_free` (bytes, default
     `cairn_blob::space::DEFAULT_RESERVE`) to `StorageConfig`.
  2. *Damaged versions (C3)* — GET/HEAD after resolving `v`:
     `if cairn_engine::fsck::version_damage(&read_txn, bucket.id, &v)?.is_some() { return
     Err(cairn_engine::fsck::damaged_error(key)) }`.
  3. *S3 replication ops (C6)* — `PutBucketReplication` → `engine.put_bucket_replication(bucket,
     &xml_body)`; `GetBucketReplication` → `engine.get_bucket_replication(bucket)?` →
     `cfg.to_xml()` or `ReplicationConfigurationNotFoundError`; `DeleteBucketReplication` →
     `engine.delete_bucket_replication(bucket)`. Refuse `PutBucketVersioning Suspended` while
     `get_bucket_replication` is `Some` (`InvalidBucketState`). HEAD/GET: header
     `x-amz-replication-status` = `engine.replication_status(&bucket, &v)?.map(|s| s.as_str())`.
     Requests carrying `x-cairn-version-id` (PUT, DELETE without versionId, and
     CompleteMultipartUpload) from a principal allowed `cairn:ReplicateObject`: build the
     `VersionRecord` (key, `version_id` = header parsed as `VersionId`, `created_at =
     version_id.created_at()`, body from the request) and call `engine.put_replica(bucket, &rec,
     Some(&source))` / `put_replica(bucket, &marker, None)`; for multipart, complete into a
     temporary record and pass its parts. Then un-ignore
     `crates/cairn-engine/tests/replication.rs::two_server_http_round_trip` (move it to
     `crates/cairn-server/tests/` with two `spawn()`s).
  4. *Replication worker (C6)* — at serve: `let targets = Arc::new(TargetRegistry::new(&engine,
     blake3::derive_key("cairn replication targets", master_key)))`;
     `tokio::spawn(ReplicationWorker::new(engine.clone(), targets.clone()).with_observer(metrics)
     .run(shutdown))`. Admin/CLI: `targets.put(&TargetConfig{..})`, `targets.list()`,
     `targets.remove(arn)`; status = the `DestinationStatus` values the observer receives (or
     `replication::load_cursor`). On bucket purge, `delete_bucket_replication` semantics apply
     (drop `repl_cursor` rows with the `BucketId` prefix).
  5. *Scrub (C4)* — `tokio::spawn(Scrubber::new(engine.clone(), ScrubConfig{..}).run(idle,
     shutdown))` when `[storage.scrub] enabled`; `cairn scrub --once` = `run_pass().await`.
  6. *fsck / backup / restore CLI (C3, C5)* — `engine.fsck(FsckOptions{verify, orphan_min_age,
     repair}).await -> FsckReport` (serde `Serialize`, `is_clean()`);
     `backup::backup(&engine, &BackupLocation::Dir|S3(S3Endpoint), &BackupOptions{mode,
     passphrase, kdf, include_keys}).await -> BackupReport`; `backup::restore(&src, &data_dir,
     &RestoreOptions{manifest, passphrase}).await -> RestoreReport` (run before opening the
     engine); `backup::list_backups(&src)`. Subcommand shapes are in OPERATIONS.md.
  7. *Tiering* — make the engine's blob store `TieredBlobStore<RemoteBlobStore>` when
     `[storage.tiering]` is on: `incref_checked` must use `TieredBlobStore::exists_sync` (stub
     counts as present), and GC's `unlink_blob` must also remove `<hex>.cold` stubs and delete the
     remote object (`tiered.delete(&id).await` after the GC write job, for ids whose stub
     existed); spawn `tiered.tier_tick(SystemTime::now(), 10_000)` every `interval`. Reads already
     go through `BlobStore::open`.

- **2026-11-08 (orchestrator) — VaultS3 is the closest competitor; positioning narrowed to four
  provable claims.** Compared against Kodiqa's VaultS3 (Go, AGPL-3.0, single binary, v5.0.x,
  1.7k stars, external white-box audit Aug 2026, 17 MiB idle, ceph s3-tests gated in CI). It
  already ships everything we shelved on 2026-11-08 (EC, Raft, replication, OIDC, Object Lock,
  SSE-C/KMS, rate limiting, quotas, CORS, dashboard, search, FUSE, S3 Select, notifications) and
  has git-like version diff/rollback and bucket snapshots. What it does not have, and cannot add
  without changing its storage model: always-on history (its versioning is per-bucket opt-in and
  its snapshots are an explicit commit), continuous point-in-time reads, content-addressed dedup,
  and an in-process MCP under IAM. DESIGN §0 now states these as the four claims; each has a
  readiness row (A6, A5, A7, D7) whose test would fail if the claim were false, and lane 2 of the
  build plan runs claim tests before polish. Consequences: (1) "lightweight" is no longer a
  differentiator we may assert without a number; goal 2 and §13 now carry idle RSS ≤ 25 MiB and
  binary ≤ 20 MB measured by `scripts/footprint.sh` using VaultS3's published method (E2).
  (2) s3-tests moves from nightly-with-allowed-failures to gating every push on an
  `expected-pass.txt` plus a weekly sweep (A4), matching the bar VaultS3 sets. (3) Governance is
  the fifth difference: VaultS3 uses a CLA and says in its README that the owner could relicense;
  Cairn takes DCO, no CLA, no telemetry, no paid tier for the core (`CONTRIBUTING.md`, F5).
  (4) README comparison table rewritten against VaultS3/RustFS/Garage instead of MinIO; the old
  table listed shelved features as "planned" phases and is gone. Shelved list extended with EC,
  compression, search, FUSE, S3 Select so nobody proposes them to "catch up".

- **2026-11-08 — Release profile optimises for size (E2).** `opt-level = "z"`, fat LTO, one
  codegen unit, stripped: the static musl binary goes from 29.4 MiB to 17.3 MiB. Most of idle RSS
  is the mapped executable, so this is also the main idle-memory lever. Measured cost: server CPU
  per GiB put/get with `aws s3 cp` was inside run-to-run noise for opt-level 3, `s` and `z`
  (BLAKE3, SHA-2 and CRC run on SIMD/assembly paths regardless). Not `panic = "abort"`: a panic
  in one request must not take the server down. Idle RSS cannot be measured on the gVisor dev
  host (it keeps the whole binary resident and faults anonymous memory in coarse chunks), so a
  `footprint` CI job on the self-hosted runner gates size ≤ 20 MB and idle ≤ 25 MiB.

- **2026-11-08 — ACLs are disabled (BucketOwnerEnforced), not emulated.** S3 itself made this the
  default for new buckets in April 2023, and MinIO never implemented grants. Get*Acl returns the
  bucket owner with FULL_CONTROL; Put*Acl succeeds for owner-only ACLs and answers
  `AccessControlListNotSupported` for anything wider, so nobody believes an object is public when
  it is not; ownership controls are always `BucketOwnerEnforced`. ACL headers that arrive *with a
  write* (`x-amz-acl: public-read` on PutObject, CreateBucket, CopyObject, CreateMultipartUpload)
  are accepted and ignored, because apps such as Mastodon send them on every upload and grant
  public reads with a bucket policy; rejecting them broke 9 previously passing s3-tests and would
  break those apps. Public access is a bucket policy, gated by PublicAccessBlock. Open question
  for the owner: whether the 51 ceph s3-tests that need ACL grants count against A4 (72.1%
  today) or are deselected like CORS (82.0%).

- **2026-11-09 — ACL-grant s3-tests are deselected from the A4 gate (answers the open question
  above).** The 53 tests in `scripts/s3-tests/acl-grants.txt` need an ACL grant to someone other
  than the owner, or an ownership mode other than `BucketOwnerEnforced`. S3 answers them with
  `AccessControlListNotSupported` on its own default buckets, so counting them measures
  compatibility with pre-2023 S3, not with S3. They are deselected by name, the way CORS is,
  with the reason per line; the weekly full sweep still runs them, and the readiness row
  reports both the gated rate and the rate over every executed test. Tests that fail because
  Cairn has one account (`[s3 alt]` is a second IAM user with `s3:*`, not a second account)
  stay in the denominator as failures. Reversible: delete the file.

- **2026-11-09 — Crates are not published; the name stays "Cairn" (F4).** Cairn ships as a
  static binary and a container image, never as a library, so `publish = false` is set
  workspace-wide and the crates.io conflicts (`cairn`, `cairn-cli`, `cairn-core` taken) stop
  mattering. Distribution names are namespaced: binary `cairn`, image
  `ghcr.io/solutionforest/cairn`, release assets `cairn-<tag>-<target>.tar.gz`. The GitHub
  name is crowded (two other S3 servers called Cairn, 6★ and Java) and trademarks were not
  checked; a rename stays possible before 1.0 and would touch the image name, binary name and
  docs only.

- **2026-11-09 — Startup refuses a master key that cannot unseal the credential store.**
  Found while enabling SSE-S3 in the s3-tests harness: `serve` with a `CAIRN_STORAGE_MASTER_KEY`
  other than the `keys/master.key` used at `cairn init` started, then answered every admin and
  STS call with 500 (`secret decryption failed`). The server now unseals the root credential
  once at startup and exits with a message naming the key source. Test:
  `crates/cairn-server/tests/sse.rs::wrong_master_key_refuses_to_start`.

- **2026-11-09 — Re-creating your own bucket in `us-east-1` is a 200 no-op**, as on AWS; other
  regions keep `409 BucketAlreadyOwnedByYou`. Idempotent provisioning (Terraform, `aws s3 mb`
  retries, app start-up "ensure bucket") expects the AWS answer; the earlier everywhere-409 was
  a deviation with no safety benefit, since the bucket and its contents are untouched either way.

- **2026-11-09 — Two startup/shutdown bugs found by the wrong-master-key test.** (1) A
  `ShutdownTrigger` fired before `Server::run_until` subscribed was lost: `watch::Sender::send`
  drops the value when no receiver exists, so the server never stopped. `trigger` now uses
  `send_replace`. (2) A `Server::bind` that failed after opening the engine left the metadata
  database locked for the rest of the process; a drop guard now shuts the engine down on every
  early return. Neither affects the `cairn serve` binary (a failed start exits the process, and
  SIGTERM goes through the signal future), but both affect embedders and tests. Test:
  `crates/cairn-server/tests/server.rs::shutdown_triggered_before_run_still_stops_and_failed_bind_releases_the_store`,
  checked to fail with each fix reverted.

- **2026-11-09 — The s3-tests deselect list matches exact names.** pytest's `--deselect`
  matches node ids by prefix, so listing `test_100_continue` also dropped
  `test_100_continue_error_retry` and five other passing tests. `scripts/s3-tests/cairn_deselect.py`
  (a pytest plugin) deselects only exact `module::name` matches.

- **2026-11-09 — The remaining s3-tests failures are triaged; 100% is not a target.** Fixed
  where Ceph and AWS agree: lifecycle rules echo the shape they were sent in (legacy `Prefix`
  vs `Filter`; adds `LifecycleRule::legacy_prefix` to the stored record, safe only because no
  release has shipped), V1 ListObjects echoes `Prefix` verbatim under `encoding-type=url`, and
  S3 `OPTIONS` preflights answer 400/403 like a bucket without CORS instead of falling through
  to auth. Left failing on purpose, because Cairn matches AWS and the suite expects Ceph RGW:
  negative or > 7-day `X-Amz-Expires` (400 `AuthorizationQueryParametersError`, suite wants
  403), `partNumber` past the last part (416, suite wants 400), PUT with chunked
  `Transfer-Encoding` and no `Content-Length` (411), RFC 2047-encoded non-ASCII metadata on
  GET, `GetBucketPolicyStatus` with no policy (`NoSuchBucketPolicy`), no `x-amz-delete-marker`
  on a non-versioned 404, duplicate part numbers in CompleteMultipartUpload, and torrents
  (501). Left failing because they need something v0.1 does not have: a second account for
  `[s3 alt]` (~28 tests), a lifecycle debug clock, and SigV4 signed with `Date` instead of
  `X-Amz-Date` (s3s rejects the unsigned `x-amz-date` a shim would add, which is the right
  security behaviour).
- **2026-11-09 — aarch64 release binaries use thin LTO.** The `v0.1.0-alpha.1` aarch64 build was
  killed twice on the self-hosted runners while linking with fat LTO. Measured locally
  (`cargo zigbuild --release`, aarch64 musl): fat peaks at 6.1 GB RSS and gives 13.7 MiB; thin
  peaks at 2.4 GB and gives 16.5 MiB, still under the E2 20 MB budget. `release.yml` sets
  `CARGO_PROFILE_RELEASE_LTO` per target; x86_64 keeps fat, the profile E2 is measured on.
- **2026-11-09 — Optional admin UI outside the binary.** `admin-ui/` is one HTML page with plain
  JavaScript plus a one-file backend (Python stdlib or PHP, no packages) that holds the keys and
  signs admin API calls, so the browser never sees a secret. Both bind to loopback, check Host and
  Origin, and allow only status, list, enable/disable and trash-restore calls. It serves claim 1
  (one-click undo) without adding a dashboard to the server; browsing and uploading stay with
  existing S3 clients. Not in the alpha release archive.
- **2026-11-09 — `scripts/start.sh` saves quickstart credentials to a file.** `cairn init` keeps
  the root secret sealed and prints it once, which is right for servers but makes a first run
  awkward: the admin UI, `cairn admin` and aws-cli all need it in another terminal. The script
  generates the credentials itself, passes them to `init` through `CAIRN_ROOT_*`, and writes
  `cairn-data/credentials.env` with mode 0600. The README tells people to delete it once the
  credentials are stored elsewhere and to use systemd or Docker for long-running installs.
- **2026-11-09 — `compose.yaml` at the repository root, admin UI as a profile.** `docker compose
  up -d` from a checkout is the shortest path to a server that restarts on boot, so the compose
  file moved from `deploy/docker-compose.yml` to the root and reads the root credential from a
  `.env` the README generates with one `printf` (ignored by git and by the Docker build
  context). The admin UI runs as `--profile ui` in `python:3.13-alpine` with `admin-ui/` mounted
  read-only; inside the container it binds `0.0.0.0` (new `CAIRN_UI_BIND`, default `127.0.0.1`)
  and the port is published on the host's loopback only, so the Host/Origin checks still apply.
  `build:` sits next to `image:` so people without GHCR access can `--build`. The dev host
  (gVisor) cannot run containers, so `.github/workflows/compose.yml` proves the file on the
  self-hosted runners: pull, up, S3 round trip, UI lists the bucket and the trashed object,
  foreign Host refused, restart keeps data.
- **2026-11-09 — Public repository, GitHub-hosted CI, issues instead of pull requests.** The repo,
  release assets and GHCR image are public from `v0.1.0-alpha.2`, the first release built on
  GitHub-hosted `ubuntu-latest` (all workflows moved off the org's self-hosted runners, which
  were only for the private phase). Contributions come in as issues: templates for bug, S3
  compatibility and feature requests, blank issues off, security routed to private advisories.
  `pr-policy.yml` closes pull requests from non-members with a pointer to the tracker, using
  `pull_request_target` without checking out PR code. The maintainers' AI agent reproduces each
  issue in a test and writes the fix; a maintainer reviews it. Reason: one review path, every fix
  starts from a reproduction, and the narrow scope (DESIGN §0) is enforced at the issue, before
  anyone writes code. `compose.yml` also runs after each release, and a push run skips when its
  pinned image is not published yet, so a version bump does not race the release.
- **2026-11-09 — No release without its own changelog entry.** `scripts/changelog-section.sh`
  used to fall back to the `Unreleased` section and then to "See CHANGELOG.md", so a tag cut
  without an entry would still publish, with notes for the wrong version. It now exits 1 unless
  the tag's version has a dated `## [X.Y.Z] - YYYY-MM-DD` section with a body and a link line,
  and `release.yml` runs it as a first `changelog` job that `build` needs, so a missing entry
  fails in seconds instead of after the 90-minute build. Both published pre-releases pass.
