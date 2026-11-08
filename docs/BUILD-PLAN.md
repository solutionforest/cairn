# Cairn — Build Plan

Source of truth for scope: `docs/DESIGN.md`. This file tracks phases, ownership and status.
Update the status column when a milestone lands. Dates are absolute (UTC).

## Environment constraints (read first)
- Build host: **1 vCPU**, 32 GB RAM, 512 GB disk, Debian 12, Rust stable 1.99, no cross tools.
  Compiles are slow. Use `cargo check -p <crate>` while iterating, `cargo test -p <crate>` for the
  crate you touch, and run the full `cargo test --workspace` only at milestone boundaries.
  Never `cargo build --release` during development. Keep `debug = 0` in the dev profile for deps.
- Several agents may build concurrently in one checkout; Cargo serialises on the target-dir lock.
  That is expected — do not delete `target/` or use a separate target dir.
- No network-dependent tests. Integration tests live in `crates/cairn-server/tests/` and boot the server in-process on `127.0.0.1:0`.

## Fixed decisions (do not relitigate without updating DESIGN.md)
- Protocol layer: `s3s` 0.17 (+ `s3s-aws` for the aws-sdk-s3 bridge in tests).
- Metadata: `redb` 4.x. Blobs: filesystem, BLAKE3-addressed, temp+fsync+rename.
- HTTP: `hyper` 1 / `axum` 0.8 / `tower-http`; TLS: `rustls` (no OpenSSL anywhere — enable
  `rustls-tls` features on `reqwest`, disable default features).
- Serialisation: `serde`; metadata records with `postcard` (schema versioned by a leading u8).
- Async: `tokio` (multi-thread runtime). Errors: `thiserror` in libraries, `anyhow` in binaries.
- Logging: `tracing`. CLI: `clap` derive. Config: `serde` + `toml` + `figment`-free manual env
  overlay. Time: `jiff` (or `time` if jiff gives trouble). IDs: `uuid` v7 for upload ids.
- Hashes/crypto: `blake3`, `md-5`, `sha1`, `sha2`, `crc32fast`, `crc32c`, `crc64fast-nvme`,
  `hmac`, `aes-gcm`, `chacha20poly1305`, `subtle`, `rand`.
- MCP: `rmcp` 3.x with `server` + `transport-io` + `transport-streamable-http-server` features.
- Edition 2024. `#![forbid(unsafe_code)]` in every crate except where a measured hot path needs it.
- Licence header not required per file; `LICENSE` is AGPL-3.0-only; every `Cargo.toml` has
  `license = "AGPL-3.0-only"`.

## Public API contracts between crates (agreed up front so crates can be built in parallel)

### `cairn-core`
```rust
pub struct BucketName(String);  impl TryFrom<&str>  // S3 naming rules
pub struct ObjectKey(String);   impl TryFrom<&str>  // 1..=1024 bytes UTF-8
pub struct BucketId(u128); pub struct VersionId([u8; 20]); pub struct BlobId([u8; 32]);
pub struct PrincipalId(String);  // "root", "user:<name>", "role:<name>/<session>", "anonymous"
pub struct Ts(i128 /* unix nanos */);
pub enum S3ErrorCode { NoSuchBucket, NoSuchKey, AccessDenied, ... } // full S3 list + http status
pub struct S3Error { code, message, resource, request_id }
pub struct Config { server, storage, retention, auth, limits, events, mcp, metrics, log }
```

### `cairn-auth` (owned by Agent B; consumed by cairn-s3 / cairn-admin / cairn-mcp)
```rust
pub struct CredentialStore { .. }            // backed by MetaStore tables principals/access_keys/sessions
impl CredentialStore {
    pub async fn lookup(&self, access_key_id: &str) -> Result<Option<Credential>>;  // includes STS sessions
    pub async fn create_user / delete_user / create_access_key / revoke_access_key / rotate_root ...
    pub async fn assume_role(&self, caller: &Principal, role: &str, duration: Duration) -> Result<StsCredentials>;
    pub async fn get_session_token(&self, caller: &Principal, duration: Duration) -> Result<StsCredentials>;
}
pub struct Credential { pub access_key_id: String, pub secret_key: SecretString, pub principal: Principal,
                        pub session: Option<SessionInfo> /* token, expiry */ }
pub struct Principal { pub id: PrincipalId, pub arn: String, pub groups: Vec<String>, pub is_root: bool }

pub struct PolicyDocument(..);  impl FromStr /* JSON */  + validate() -> Result<(), PolicyError>
pub struct PolicySet { .. }      // compiled identity policies ∪ group policies ∪ bucket policy ∪ PAB
pub struct AuthzRequest<'a> { pub principal: Option<&'a Principal>, pub action: &'a str,
                              pub resource: &'a str /* ARN */, pub context: &'a ConditionContext }
pub enum Decision { Allow, Deny /* explicit */, Implicit }
impl PolicySet { pub fn evaluate(&self, req: &AuthzRequest) -> Decision; }
pub struct ConditionContext { map: HashMap<String, Vec<String>> }  // e.g. "aws:SourceIp" -> ["1.2.3.4"]
pub fn presign(cred: &Credential, method, url, headers, expires: Duration, now: Ts, region: &str) -> Url;
```
`cairn-auth` depends on `cairn-core` and `cairn-meta` (for persistence via `MetaStore` typed
tables), nothing else internal. SigV4 *verification* is done by `s3s` given the secret from
`lookup`; `cairn-auth` only needs SigV4 *signing* for `presign`.

### `cairn-meta`
```rust
pub trait MetaStore: Send + Sync {  // one impl: RedbMetaStore
    fn read(&self) -> ReadTxn;  fn write(&self) -> impl Future<Output = WriteTxn>;  // write serialised
    // typed table accessors are generated per table in DESIGN §4.3
}
```
Plus `pitr::head_at(txn, bucket, key, at) -> Option<Version>` and list iterators with
prefix/delimiter skipping.

### `cairn-blob`
```rust
pub trait BlobStore: Send + Sync {
    async fn begin_write(&self, opts: WriteOpts) -> BlobWriter;   // streaming, hashing, optional AEAD
    async fn open(&self, id: &BlobId, range: Range<u64>, key: Option<&DataKey>) -> BlobReader;
    async fn exists / delete / size / verify(&self, id) -> ..;
}
pub struct BlobWriter { .. } impl AsyncWrite; fn finish(self) -> Result<BlobDigest { blob_id, md5, sha256, size, checksum: Option<Checksum> }>
```

### `cairn-engine`
`CairnEngine` exposes async methods mirroring S3 operations with plain Rust types
(`put_object(PutObjectReq) -> PutObjectRes` etc.), plus `trash_*`, `pitr_*`, `lifecycle_tick`,
`gc_tick`. `cairn-s3` is a thin mapping from `s3s` types to these.

## Phases

Three agents work in one checkout: **A** = storage/S3/server (critical path), **B** = auth/admin/
MCP, **C** = events/replication-adjacent/tooling. Status dates are UTC.

| # | Scope | Owner | Status | Acceptance |
|---|-------|-------|--------|------------|
| 0 | Workspace scaffold, `cairn-core` types/errors/config, CI, Dockerfile skeleton | A | **done** 2026-11-08 | `cargo check --workspace` green |
| 1a | `cairn-meta` (redb tables, writer thread, list iterators, `head_at`), `cairn-blob` (fs, hashing writer, range reader, AEAD, GC primitives) | A | **done** 2026-11-08 | tests green |
| 1b | `cairn-auth`: policy parse/validate/compile/evaluate, credential store, STS sessions, SigV4 + presign | B | **done** 2026-11-08 (143 evaluator cases, store + sigv4 tests) | tests green |
| 1c | `cairn-engine` (bucket/object/multipart/commit landed; **recovery, GC tick, lifecycle hooks pending**) + `cairn-s3` (s3s impl) + `cairn-server` + `cairn-cli serve/init`: bucket CRUD, Put/Get/Head/Delete(s), Copy, ListObjects v1/v2, ListObjectVersions, versioning, multipart (7 ops), tagging, metadata, range/conditional, checksums, soft delete + shadow versioning, root-only `S3Auth`. Create `docs/COMPAT.md` and `docs/EXTENSIONS.md`, example `cairn.toml`. | A | in progress | `crates/cairn-server/tests/` with aws-sdk-s3 cover every op; `aws s3 cp/sync/ls/rm` and `rclone` work manually |
| 2a | Engine/S3 features: trash list/restore/purge, PITR restore + `x-cairn-as-of`, lifecycle worker (expiration, noncurrent, abort-mpu), GC worker, Object Lock (governance/compliance/legal hold), SSE-S3 / SSE-C (key-scoped blob ids, DESIGN §15 Q5) / named KMS keys, CORS, PublicAccessBlock, bucket quota (507), rate limiting (§8.3), `/metrics` `/healthz` `/readyz`, audit JSONL, graceful shutdown | A | todo | integration tests per feature; `s3-tests` tagged subset ≥ 80% |
| 2b | Wire `cairn-auth` into s3s `S3Auth`/`S3Access` (bucket policy ∪ identity ∪ PAB); Put/Get/Delete BucketPolicy + GetBucketPolicyStatus; STS endpoint (`/?Action=AssumeRole|GetSessionToken`); `cairn-admin` REST API (`/_cairn/v1/...`) + `cairn admin` CLI (users/keys/groups/policies/roles/buckets/trash/pitr/quota/lock); metadata **migrations framework** (schema version in `kv`, pre-upgrade snapshot, `cairn migrate --dry-run`) | B | todo | policy/STS/admin integration tests; migration test from a v1 fixture |
| 3a | `cairn-events`: event types (S3 schema 2.1 + `cairn:`), durable outbox + cursor, delivery worker with backoff + DLQ, sinks: webhook (HMAC), **function sinks** (bearer / sigv4-lambda / cf-access, §10), SSE stream `/_cairn/v1/events`; `Put/GetBucketNotificationConfiguration` mapping incl. `LambdaFunctionConfigurations` | C | todo | outbox delivers exactly the committed set after crash (test); fake HTTP sink tests per auth mode |
| 3b | Replication worker + Put/Get/DeleteBucketReplication, `x-cairn-version-id` on Cairn→Cairn; **blob tiering** `BlobStore` (hot local / cold remote S3, age+size rules, transparent read-through); `cairn backup/restore` (snapshot + incremental blobs, age-style encryption); `cairn fsck` / `cairn scrub` | A | todo | replication round-trip between two in-process servers; tiered GET of a cold blob; fsck detects an injected orphan and a corrupt blob |
| 3c | `cairn-mcp` (stdio + streamable HTTP, tools in DESIGN §11.1, `cairn:McpTool` condition key); OIDC federation for STS (`AssumeRoleWithWebIdentity`); PostObject (browser form upload) | B | todo | MCP tools exercised with an rmcp client under a restricted policy; OIDC test with a local JWKS |
| 3d | Tooling: `bench/` harness (warp or custom, reproducing §13 targets, results committed as markdown); `s3-tests` (ceph) runner script + tag list + CI job (nightly, allowed-failure list); config reference generator (`cairn config schema`) | C | todo | bench runs on the dev host; `s3-tests` subset ≥ 95% by end of phase 3 |
| R | Release engineering: `cargo deny` + `cargo audit` in CI; release workflow (tags → static musl x86_64/aarch64, Docker image to GHCR, SBOM, checksums); CHANGELOG; **name check** on crates.io / Docker Hub / GitHub before first public tag; `SECURITY.md` with disclosure policy | C | todo | `v0.1.0-alpha` tag produces downloadable binaries |
| 4 | Admin UI (`/_cairn/ui`); `ai` feature (extraction, embeddings, search); ACME; otel; WASM GET-hook experiment; Helm; docs site | later | todo | |

### Gaps closed on 2026-11-08 (second planning pass)
Added after reviewing the first plan: scaling path / HA posture (DESIGN §12.1), function sinks for
serverless targets (§10), rate limiting (§8.3), key-scoped blob ids for SSE-C (§15 Q5),
migrations framework (2b), bench + `s3-tests` harness (3d), release engineering (R), blob
tiering pulled into 3b, phase 2 split so A and B do not touch the same files.

## Working agreements
- Commit locally at each green milestone with a descriptive message. Agents do not push; the
  orchestrator pushes `master` to `origin` (private `solutionforest/cairn`) at phase boundaries.
- File ownership while phases run in parallel: A owns `cairn-core/meta/blob/engine/s3/server/cli`,
  B owns `cairn-auth/admin/mcp`, C owns `cairn-events`, `bench/`, `scripts/`, `.github/`,
  `deploy/`. Touching another agent's crate: additive only (new module/function), say so in the
  commit message, never reformat or rename. Shared docs (`COMPAT.md`, `EXTENSIONS.md`,
  `BUILD-PLAN.md`) are append-only rows.
- Keep `docs/COMPAT.md` (operation → status + notes) and `docs/EXTENSIONS.md` (x-cairn headers)
  current as behaviour lands.
- When a DESIGN decision proves wrong, change DESIGN.md in the same commit and say why in
  §15 "Open questions" → "Decisions log".

## Decisions log

Entries are dated (UTC) and name the author. Newest last.

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
