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

| # | Scope | Owner | Status | Acceptance |
|---|-------|-------|--------|------------|
| 0 | Workspace scaffold, `cairn-core` types/errors/config, CI (`cargo fmt/clippy/test/deny`), Dockerfile skeleton | Agent A | 2026-11-08 scaffold created by orchestrator; types in progress | `cargo check --workspace` green |
| 1a | `cairn-meta` (redb tables, txn wrapper, list iterators, `head_at`), `cairn-blob` (fs, hashing writer, range reader, GC primitives) with unit + proptest | Agent A | todo | `cargo test -p cairn-meta -p cairn-blob` green; `head_at` property test |
| 1b | `cairn-auth`: policy language parse/validate/compile/evaluate (AWS table tests), credential store, STS sessions, presign (AWS test vectors) | Agent B | todo | `cargo test -p cairn-auth` green; ≥ 60 policy evaluator cases |
| 1c | `cairn-engine` + `cairn-s3` (s3s impl) + `cairn-server` + `cairn-cli serve/init`: bucket CRUD, Put/Get/Head/Delete(s), Copy, ListObjects v1/v2, ListObjectVersions, versioning, multipart (all 7 ops), tagging, metadata, range/conditional, checksums, soft delete + shadow versioning, root-only auth via `S3Auth` | Agent A | todo | `tests/` with aws-sdk-s3 cover every op; `aws s3 cp/sync/ls/rm` and `rclone` work manually |
| 2 | Wire `cairn-auth` into `S3Access`; bucket policy APIs; STS endpoint (`/?Action=AssumeRole`); admin API + `cairn admin` CLI (users/keys/policies/buckets/trash/pitr/quota); PITR restore + `x-cairn-as-of`; lifecycle worker; Object Lock; SSE-S3/SSE-C/KMS-named-keys; CORS; PublicAccessBlock; metrics/health; audit JSONL | A + B | todo | integration tests for policies/STS/trash/PITR/lock/encryption; `s3-tests` tagged subset ≥ 80% |
| 3 | Events outbox + webhooks; bucket notifications; replication worker + APIs; backup/restore CLI; fsck/scrub; `cairn-mcp` (stdio + HTTP, tools in DESIGN §11.1); PostObject; OIDC STS | A + B + C | todo | replication round-trip test between two in-process servers; MCP tools tested via rmcp client; `s3-tests` subset ≥ 95% |
| 4 | Admin UI; `ai` feature (extraction, embeddings, search); SSE event stream; ACME; otel; packaging (musl, Docker, systemd); docs site | later | todo | |

## Working agreements
- Commit locally at each green milestone with a descriptive message; never push without the
  owner's explicit instruction. Branch `master` is fine for now.
- Keep `docs/COMPAT.md` (operation → status + notes) and `docs/EXTENSIONS.md` (x-cairn headers)
  current as behaviour lands.
- When a DESIGN decision proves wrong, change DESIGN.md in the same commit and say why in
  §15 "Open questions" → "Decisions log".
