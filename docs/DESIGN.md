# Tidemark — Design Document

> Lightweight, self-hosted, S3-compatible object storage. Rust. AGPL-3.0.
> Positioned as the lightweight alternative to MinIO for people who run one box (or a few).

Status: v0 design, 2026-11-08. Project name "Tidemark" is a working title (a tidemark is a stack of
stones that marks the path and survives the weather — stacked immutable objects, durable, simple).

---

## 0. Scope of v0.1 (2026-11-08, supersedes the v1 phrasing below)

### Where Tidemark sits

| | RustFS | VaultS3 | Garage | **Tidemark** |
|---|---|---|---|---|
| Shape | distributed cluster, Apache-2.0, Rust | single binary, AGPL, Go, 100+ features incl. dashboard, EC, Raft, OIDC, search | small replicated store, AGPL, Rust | single binary, AGPL, Rust |
| Versioning | per-bucket opt-in | per-bucket opt-in; snapshots are an explicit commit | none | **always on internally** |
| Undo after a delete you did not plan for | no | only if versioning was already on | no | **yes, every bucket, zero setup** |
| Read a bucket as it was at time T | no | snapshot you took earlier | no | **any T in the retention window** |
| Identical bytes stored once | no | no | no | **yes (BLAKE3 content addressing)** |
| MCP for agents | separate server, plain S3 creds | none | none | **in-process, same IAM policies** |

VaultS3 is the closest competitor: same niche (lightweight, one binary, "MinIO without the paid
tier"), same licence, already shipped, externally audited, 17 MiB idle. We do not compete with it
on breadth, and we do not compete with RustFS on scale-out. Tidemark wins on exactly four claims,
each of which must be proven by a test or a published measurement before anything is public:

1. **You cannot lose data, even if you configured nothing.** Shadow versioning is always on;
   every delete (object, version, bucket) is a reversible metadata change; restore is one command.
2. **Any bucket is readable and restorable as of any instant** in its retention window, without
   having taken a snapshot first (`x-tidemark-as-of`, `tidemark pitr`).
3. **Identical content costs disk once.** Copy, restore and PITR write no new blob bytes.
4. **AI agents get the same storage under the same rules.** MCP is in the binary and every tool
   call is a policy decision (`tidemark:McpTool`, `tidemark:TimeTravel`), not a bearer token with
   root.

Everything else is table stakes we must match (S3 conformance, SigV4, IAM, STS, SSE-S3,
lifecycle, metrics, logs, backup, fsck) or breadth we deliberately leave to others.

### Governance (the fifth, non-technical difference)
No contributor licence agreement: contributions are accepted under the Developer Certificate of
Origin, so no single party can relicense the core. No telemetry, no account, no licence key, no
feature of the core moves behind a paid tier. These are stated in `CONTRIBUTING.md` and the
README and are commitments, not aspirations.

### In and out

- **In v0.1:** the S3 operations in `docs/COMPAT.md`; IAM/bucket policies, STS, SigV4; shadow
  versioning, soft delete, trash, PITR and `x-tidemark-as-of` time travel; content-addressed
  dedup; SSE-S3 at rest; lifecycle expiration + GC; fsck, scrub, backup/restore; healthz,
  readyz, metrics, JSON + audit logs; MCP server under policy; one binary, one TOML, one CLI.
- **Optional local tool:** `admin-ui/` is a separate admin page (status, buckets, users, access
  keys, trash restore). The page is plain HTML/JS; a single-file Python or PHP backend keeps
  the credentials and signs `/_tidemark/v1` calls. It accepts loopback clients only and is not
  part of the Tidemark server binary or the alpha release archive.
- **Shelved (code may exist, nothing ships or is documented as a feature):** replication,
  tiering, events/webhooks/function sinks, OIDC, Object Lock, SSE-C/KMS, rate limiting, TLS hot
  reload, quotas, CORS, PostObject, built-in admin UI, `ai` feature, Helm, multi-node, erasure coding,
  compression, search, FUSE, S3 Select. VaultS3 ships most of these; that is the point. A
  shelved feature returns only with a DECISIONS.md entry saying which of the four claims it
  serves.

Where later sections describe a shelved feature, they are design notes for a future version, not
v0.1 commitments. The build plan is `docs/BUILD-PLAN.md`; dated reasons are in
`docs/DECISIONS.md`.

---

## 1. Goals and non-goals

### Goals
1. **High S3 compatibility.** Works unmodified with aws-cli, boto3, aws-sdk-*, rclone, restic,
   s3cmd, mc, Cyberduck, Terraform/Pulumi state backends, Velero, Loki/Tempo/Mimir, Nextcloud,
   Immich, Mastodon, Gitea/Forgejo LFS, Postgres/pgBackRest, Duplicati, Kopia. Measured against
   the Ceph `s3-tests` suite.
2. **Lightweight.** Single static binary (< 20 MB), one data directory, zero external services,
   idle RSS ≤ 25 MiB measured the way VaultS3 publishes its 17 MiB (container working set after
   a 110 s idle settle, `scripts/footprint.sh`), starts in < 1 s, runs fine on a Raspberry Pi 4 /
   1 vCPU VPS / NAS. "Lightweight" is not a differentiator until the number is published.
3. **Security by default.** SigV4 everywhere, IAM-style policies, bucket policies, STS temporary
   credentials, encryption at rest, audit log, TLS via rustls, no anonymous access unless granted.
4. **Never lose data by accident, with nothing configured.** Soft delete for everything
   (objects, versions, buckets), shadow versioning even on "unversioned" buckets, point-in-time
   recovery (PITR) and read-only time travel without a prior snapshot, bit-rot detection, scrub,
   consistent backups. (Object Lock and async replication: shelved, see §0.)
5. **AI-native.** Built-in MCP server (stdio + Streamable HTTP) whose tools are governed by the
   same IAM policies as S3; event hooks; metadata/tag search; optional content extraction and
   embeddings behind a feature flag.
6. **Boring operations.** `tidemark serve` + a TOML file. Prometheus metrics, health endpoints,
   structured logs, one CLI for admin (`tidemark admin …`).

### Non-goals (v1)
- Multi-node consensus / distributed erasure coding across machines. v1 is single-node with
  async replication to any S3 endpoint (active-passive DR). The storage traits are designed so a
  clustered backend can be added later without touching the S3 layer.
- S3 Select, Glacier/transition storage classes, Requester Pays, website hosting redirects,
  BitTorrent, Analytics/Inventory/Metrics configuration APIs (accepted and stored where cheap,
  otherwise `NotImplemented`).
- Replacing a filesystem. Tidemark stores blobs as files and recommends ZFS/btrfs/ext4+RAID for
  device-level redundancy. Local multi-disk erasure coding is a later phase (see §12).

---

## 2. Architecture overview

```
                 ┌──────────────────────────────────────────────────────────────┐
  S3 clients ───►│  HTTP (hyper/axum, rustls)                                   │
  MCP clients ──►│   ├── /            S3 API   (s3s protocol adapter → TidemarkS3) │
  Browser ──────►│   ├── /_tidemark/v1/  Admin API (axum, bearer/SigV4)            │
  Prometheus ───►│   ├── /mcp         MCP Streamable HTTP (rmcp)                │
                 │   └── /metrics /healthz /readyz                              │
                 ├──────────────────────────────────────────────────────────────┤
                 │  tidemark-auth   SigV4 · credentials · IAM policy engine · STS  │
                 ├──────────────────────────────────────────────────────────────┤
                 │  tidemark-engine  buckets · objects · versions · multipart ·    │
                 │                soft-delete · PITR · lifecycle · lock · tags  │
                 ├───────────────────────────┬──────────────────────────────────┤
                 │  tidemark-meta (redb)        │  tidemark-blob (filesystem)         │
                 │  ACID metadata, indexes   │  immutable content-addressed     │
                 │  version history, trash   │  blobs, streaming hash, AEAD     │
                 ├───────────────────────────┴──────────────────────────────────┤
                 │  tidemark-events  bus → webhooks · replication · audit · MCP    │
                 └──────────────────────────────────────────────────────────────┘
                                 one data directory on disk
```

**Key decision: protocol layer = `s3s` crate (Apache-2.0).** `s3s` is generated from the AWS
Smithy model and gives us the full S3 operation set as a Rust trait, request/response XML
(de)serialisation, SigV4 verification hooks (`S3Auth`), access hooks (`S3Access`), and virtual-host
/ path-style routing. Hand-rolling this is months of work and the #1 source of compatibility bugs.
Tidemark's value is in everything beneath the trait. Fallback if `s3s` blocks us: a hand-written axum
router for the affected operations mounted in front of `s3s` (it supports custom routes).

**Key decision: metadata in `redb`, blobs on the filesystem.** Pure-Rust, ACID, single-file B-tree
with MVCC readers and savepoints. No C++ dependency (RocksDB would double build time and binary
size). Blobs are immutable files named by BLAKE3 content hash, so dedup, copy, PITR restore and
backups are all cheap and crash-safe (write temp → fsync → rename).

**Key decision: every bucket is versioned internally ("shadow versioning").** The S3 API shows
versioning as off/on per bucket exactly as S3 does, but the engine always records history and
never overwrites in place. This is what makes soft delete, PITR and time travel uniform and cheap.
Disk usage is bounded by the bucket's retention window (§7).

---

## 3. Crate layout (Cargo workspace)

```
tidemark/
├── Cargo.toml                  workspace, shared [workspace.dependencies], lto/strip in release
├── crates/
│   ├── tidemark-core/             domain types (BucketName, ObjectKey, VersionId, ETag, Checksums),
│   │                           S3 error codes, config structs (serde+TOML), time helpers
│   ├── tidemark-meta/             MetaStore trait + redb implementation, key layout, PITR queries
│   ├── tidemark-blob/             BlobStore trait + fs implementation, streaming hashing writer,
│   │                           chunked AEAD encryption, GC / scrub
│   ├── tidemark-auth/             SigV4 (+ presign, chunked payloads), credential store, IAM policy
│   │                           language + evaluator, bucket policies, STS, session tokens
│   ├── tidemark-engine/           the object store: orchestrates meta+blob, versioning, multipart,
│   │                           soft delete, trash, PITR, lifecycle, object lock, tagging
│   ├── tidemark-s3/               implements `s3s::S3` for TidemarkEngine; header extensions
│   ├── tidemark-admin/            admin REST API (axum) + audit log sink
│   ├── tidemark-events/           event bus (tokio broadcast + durable queue in redb),
│   │                           webhook sink, replication worker, lifecycle scheduler
│   ├── tidemark-mcp/              MCP server (rmcp): tools/resources over stdio + Streamable HTTP
│   ├── tidemark-server/           wires everything: hyper service composition, TLS, metrics
│   └── tidemark-cli/              `tidemark` binary: serve, admin client, mcp --stdio, backup, fsck
├── crates/tidemark-server/tests/  black-box integration tests (aws-sdk-s3 against in-process server)
├── docs/                       DESIGN.md (this), BUILD-PLAN.md, API extensions, ops guide
├── deploy/                     Dockerfile (distroless/scratch), systemd unit, example config
└── compose.yaml                single-node stack: tidemark + optional admin UI (`--profile ui`)
```

Dependency direction: `core ← meta, blob, auth ← engine ← s3, admin, mcp ← server ← cli`, with
`events` depending only on `core` + `meta` so the engine can append to the outbox inside its
commit transaction (`core ← meta ← events ← engine`; BUILD-PLAN decisions log 2026-11-08).
`tidemark-auth` and the storage crates do not depend on each other; both are pure logic with unit
tests and can be built in parallel.

---

## 4. Data model

### 4.1 Identifiers
- `BucketName`: S3 rules (3–63 chars, DNS-compatible). Stored with a `BucketId` (u64 or 16-byte
  random) so that a deleted-and-recreated bucket never collides with a trashed one.
- `ObjectKey`: UTF-8, 1–1024 bytes (as S3).
- `VersionId`: 20 bytes = 8-byte big-endian **inverted** `created_at` nanos (so newest sorts first
  in the B-tree) + 12 random bytes; rendered base32/hex to clients. "null" is accepted and mapped
  per S3 semantics for buckets that were unversioned when the object was written.
- `BlobId`: 32-byte BLAKE3 of plaintext content. Content-addressed.

### 4.2 Records (serialised with `postcard`/`bincode`-style compact serde; schema-versioned)

```rust
struct Bucket {
    id: BucketId, name: BucketName, created_at: Ts, owner: PrincipalId,
    versioning: Off | Enabled | Suspended,
    retention: RetentionPolicy,            // soft-delete window etc. (§7)
    object_lock: Option<ObjectLockConfig>,
    encryption: Option<SseConfig>,         // default SSE
    lifecycle: Option<LifecycleConfig>,
    policy: Option<PolicyDocument>, cors, tags, notifications, replication,
    public_access_block, acl: CannedAcl,
    state: Active | Trashed { at: Ts, by: PrincipalId } ,
    config_seq: u64,                       // bumps on every config change (history kept, §7.4)
}

struct Version {
    key: ObjectKey, version_id: VersionId, created_at: Ts,
    kind: Object(ObjectBody) | DeleteMarker,
    state: Live | Superseded { at: Ts }          // overwritten in an unversioned bucket (hidden from S3)
         | SoftDeleted { at: Ts, by: PrincipalId, reason: Api | Lifecycle | Admin },
    lock: Option<{ mode: Governance | Compliance, retain_until: Ts }>,
    legal_hold: bool,
}

struct ObjectBody {
    size: u64, etag: ETag, checksums: Checksums,     // md5-etag + optional CRC32/CRC32C/SHA1/SHA256/CRC64NVME
    content_type, cache_control, content_disposition, content_encoding, content_language, expires,
    user_metadata: BTreeMap<String, String>,         // x-amz-meta-*
    tags: BTreeMap<String, String>,
    storage_class: Standard,                         // accepted, single class in v1
    sse: None | S3 { key_id } | KMS { key_id } | C { key_md5 },
    parts: SmallVec<Part>,                           // 1 part for simple PUT; N for multipart
}
struct Part { blob: BlobId, size: u64, etag: ETag, offset: u64 }

struct MultipartUpload { id, bucket, key, initiated_at, owner, body_template, parts: BTreeMap<u16, Part> }
struct BlobRef { refcount: u32, size: u64, last_unref_at: Option<Ts> }   // for GC
```

### 4.3 redb tables (key → value; all keys big-endian so ranges are lexicographic)

| Table            | Key                                             | Value         | Purpose |
|------------------|-------------------------------------------------|---------------|---------|
| `buckets`        | `name`                                          | `BucketId`    | name resolution (only Active) |
| `bucket_meta`    | `BucketId`                                      | `Bucket`      | |
| `bucket_history` | `BucketId ‖ config_seq`                         | `Bucket`      | config PITR |
| `versions`       | `BucketId ‖ key ‖ 0x00 ‖ VersionId`             | `Version`     | newest-first per key |
| `latest`         | `BucketId ‖ key`                                | `VersionId`   | hot path for GET / list (points at current S3-visible head) |
| `uploads`        | `BucketId ‖ upload_id`                          | `Multipart`   | |
| `uploads_by_key` | `BucketId ‖ key ‖ upload_id`                    | `()`          | ListMultipartUploads |
| `blobs`          | `BlobId`                                        | `BlobRef`     | refcount / GC |
| `trash_idx`      | `expires_at ‖ BucketId ‖ key ‖ VersionId`       | `()`          | purge scheduler |
| `lifecycle_idx`  | `BucketId ‖ due_at ‖ key ‖ VersionId`           | rule id       | lifecycle scheduler |
| `principals`     | `PrincipalId`                                   | `User/Role`   | IAM |
| `access_keys`    | `access_key_id`                                 | `Credential`  | secret (hashed with argon2id? no — SigV4 needs the raw secret; store AEAD-encrypted with master key) |
| `policies`       | `policy_name`                                   | `PolicyDoc`   | managed policies |
| `sessions`       | `session_token`                                 | `StsSession`  | STS temp creds, TTL |
| `events_queue`   | `seq`                                           | `Event`       | durable outbox for webhooks/replication |
| `repl_cursor`    | `BucketId ‖ target_id`                          | `seq`         | replication progress |
| `audit`          | `Ts ‖ seq`                                      | `AuditRecord` | optional (default to JSONL file) |
| `kv`             | `str`                                           | bytes         | schema version, cluster id, master key check value |

Listing with prefix/delimiter uses a range scan on `latest` (fast) and on `versions` for
ListObjectVersions. Common-prefix skipping: after emitting a common prefix, seek to
`prefix ‖ delimiter ‖ 0xFF…` to skip the subtree (crucial for buckets with millions of keys in
one "directory").

Write transactions in redb are single-writer; the engine serialises metadata commits through one
`tokio::sync::Mutex`-guarded writer task with batching (group commit). Blob I/O is fully
concurrent and happens *before* the metadata commit, so the critical section is microseconds.

### 4.4 On-disk layout

```
<data_dir>/
├── tidemark.toml                 (optional; CLI flag/env override)
├── meta/tidemark.redb            metadata
├── meta/tidemark.redb.snapshots/ periodic consistent copies for backup (§9)
├── blobs/ab/cd/abcdef…        immutable blobs, 2-level fan-out by hash prefix
├── tmp/                       in-flight uploads (same filesystem → atomic rename)
├── keys/master.key            32-byte master key (0600) unless provided via env/KMS
└── audit/2026-11-08.jsonl     audit log (rotated)
```

Multiple data volumes (`[[storage.volume]] path=…`) are supported for *capacity* spreading only:
blob placement = `blake3[0] % volumes`. Redundancy is the filesystem's job in v1.

---

## 5. Request lifecycle: PUT /bucket/key

1. hyper accepts; router sends to `s3s` service. `s3s` parses the request into
   `PutObjectInput`, calls `TidemarkAuth::verify` (SigV4 header or presigned query; checks clock skew
   ±15 min, resolves access key → principal; supports `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` and
   `UNSIGNED-PAYLOAD`; STS session tokens via `x-amz-security-token`).
2. `TidemarkAccess::check` evaluates IAM: principal's identity policies ∪ bucket policy ∪ public
   access block → Allow/Deny for `s3:PutObject` on `arn:aws:s3:::bucket/key` with condition
   context (source IP, acl, sse headers, tags, time, `s3:x-amz-copy-source`…).
3. Engine checks bucket state, Object Lock (`x-amz-object-lock-*` headers, bucket defaults),
   conditional headers (`If-None-Match: *`, `If-Match` on overwrite — S3 supports these since
   2024; we support them for "create-if-absent" semantics), quota.
4. `BlobWriter` streams the body to `tmp/<uuid>`: computes BLAKE3 (blob id), MD5 (ETag), the
   requested `x-amz-checksum-*` algorithm, and the SHA-256 when the request is signed with a
   content hash (verifies trailer/`x-amz-content-sha256`); optionally encrypts with chunked
   AES-256-GCM (64 KiB chunks, nonce = key-random prefix ‖ chunk index; AAD = blob id ‖ index) so
   that ranged reads decrypt only the needed chunks. Enforces `Content-Length` / `Content-MD5`.
5. fsync tmp → rename to `blobs/ab/cd/<hash>` (if it already exists: unlink tmp, dedup hit).
6. One redb write txn: `blobs[blob].refcount += 1`; create `Version` (newest sort order);
   if the bucket is unversioned → mark the previous head `Superseded{now}` and put it in
   `trash_idx` with `now + retention`; update `latest`; append `events_queue` (`s3:ObjectCreated:Put`).
7. Respond 200 with `ETag`, `x-amz-version-id` (only if versioning enabled), checksum headers,
   `x-amz-server-side-encryption*`.
8. Post-commit: broadcast on the in-process bus (webhooks, replication worker, MCP subscriptions,
   metrics, audit).

GET does the inverse: `latest` → `Version` → parts → `BlobReader` (range → part/chunk math) →
streaming body with correct `Content-Range`, `Accept-Ranges`, conditional headers (`If-Match`,
`If-None-Match`, `If-Modified-Since`, `If-Unmodified-Since`), `response-*` override query
params, `partNumber` support, and checksum headers when `x-amz-checksum-mode: ENABLED`.
Optional `verify_on_read` recomputes BLAKE3 while streaming and logs/metrics a bit-rot event if it
mismatches (the response is already streaming, so the client gets a truncated body + error trailer;
scrub exists for proactive detection).

---

## 6. S3 API surface

Legend: ✅ v1 (Phase 1–2) · 🟡 Phase 3 · ⚪ accepted/stored but no behaviour · ❌ `NotImplemented`

**Service / Bucket**: ListBuckets ✅ · CreateBucket ✅ (LocationConstraint ignored, ObjectLock
enabled flag ✅) · DeleteBucket ✅ (→ trash) · HeadBucket ✅ · GetBucketLocation ✅ ·
Get/Put/DeleteBucketVersioning ✅ · Get/Put/DeleteBucketTagging ✅ ·
Get/Put/DeleteBucketPolicy ✅ · GetBucketPolicyStatus ✅ · Get/Put/DeleteBucketLifecycle ✅ ·
Get/Put/DeleteBucketCors ✅ · Get/Put/DeleteBucketEncryption ✅ ·
Get/Put/DeleteBucketOwnershipControls ⚪ · Get/Put/DeletePublicAccessBlock ✅ ·
Get/PutBucketAcl ⚪ (canned only; returns owner FULL_CONTROL) · Get/PutBucketNotificationConfiguration 🟡 ·
Get/Put/DeleteBucketReplication 🟡 · Get/PutObjectLockConfiguration ✅ ·
Get/Put/DeleteBucketWebsite ❌ · Logging/Accelerate/RequestPayment/Analytics/Inventory/Metrics/
IntelligentTiering ❌ · ListDirectoryBuckets ❌

**Object**: PutObject ✅ · GetObject ✅ (range, partNumber, response-* overrides, conditional) ·
HeadObject ✅ · DeleteObject ✅ (delete marker / version soft-delete / bypass-governance) ·
DeleteObjects ✅ (quiet mode) · CopyObject ✅ (metadata directive, tagging directive, conditional
source headers, same-key metadata update, cross-bucket, versionId source) · ListObjects ✅ ·
ListObjectsV2 ✅ (continuation tokens, start-after, fetch-owner, encoding-type=url) ·
ListObjectVersions ✅ · Get/Put/DeleteObjectTagging ✅ · GetObjectAttributes ✅ ·
Get/PutObjectAcl ⚪ · Get/PutObjectRetention ✅ · Get/PutObjectLegalHold ✅ ·
PostObject (browser form, policy signature) 🟡 · RestoreObject ❌ · SelectObjectContent ❌ ·
WriteGetObjectResponse ❌

**Multipart**: CreateMultipartUpload ✅ · UploadPart ✅ · UploadPartCopy ✅ (range) ·
CompleteMultipartUpload ✅ (ETag `md5(md5s)-N`, part validation, `If-None-Match`) ·
AbortMultipartUpload ✅ · ListParts ✅ · ListMultipartUploads ✅ · lifecycle
`AbortIncompleteMultipartUpload` ✅

**Auth**: SigV4 header ✅ · SigV4 presigned (query) ✅ · streaming chunked signing ✅ · trailing
checksums ✅ · SigV2 ❌ (not accepted; it is deprecated and weak) · anonymous via policy ✅ ·
STS `AssumeRole`, `GetSessionToken` ✅ · `AssumeRoleWithWebIdentity` (OIDC) 🟡

**Checksums**: CRC32, CRC32C, SHA1, SHA256 ✅, CRC64NVME ✅, `x-amz-checksum-mode`, full-object vs
composite (multipart) ✅.

**Encryption**: SSE-S3 (AES256, internal master key) ✅ · SSE-C ✅ · SSE-KMS → maps to internal
named keys (`tidemark admin kms create-key`) ✅; external KMS 🟡.

**Tidemark extensions (all opt-in, namespaced `x-tidemark-*`, documented in `docs/EXTENSIONS.md`)**:
- `x-tidemark-as-of: <RFC3339 | unix-nanos>` on GetObject/HeadObject/ListObjectsV2 → read the
  bucket as it was at that instant (time travel). Policy action `tidemark:TimeTravel`.
- `x-tidemark-include-trash: true` on ListObjectVersions → include soft-deleted versions
  (`tidemark:ListTrash`).
- `?x-tidemark-restore=<version-id>` POST → restore from trash (`tidemark:Restore`).
- Response header `x-tidemark-blob-hash: blake3:<hex>` on HEAD/GET (always safe to expose).

Conformance: CI runs a curated subset of Ceph `s3-tests` (tagged list in `tests/s3-tests.toml`)
plus smoke tests with aws-cli, rclone, restic and mc. Goal for v1.0: 100% of the tagged subset;
the untagged remainder is tracked in `docs/COMPAT.md`.

---

## 7. Soft delete, recovery, PITR, time travel

### 7.1 Principles
- **Nothing is physically destroyed on a user request.** Every destructive S3 operation produces
  a reversible metadata transition; physical reclamation only happens in the GC after the
  retention window, or by an explicit admin `purge` (which itself is audited and policy-gated).
- Retention is **per bucket** (`RetentionPolicy { soft_delete: Duration (default 30d),
  shadow_history: Duration (default = soft_delete), min_versions_kept: u32 (default 1) }`),
  with a server-wide default and an admin override. `0s` disables (hard delete) for buckets like
  caches; this requires `tidemark:SetRetention` and is logged loudly.

### 7.2 Transitions

| S3 operation                                    | Versioned bucket                           | Unversioned bucket |
|-------------------------------------------------|--------------------------------------------|--------------------|
| PutObject on existing key                       | new Version; old stays Live (S3 semantics) | new Version; old → `Superseded`, trash_idx |
| DeleteObject (no versionId)                     | DeleteMarker version (S3 semantics)        | head → `SoftDeleted`; `latest` removed |
| DeleteObject?versionId=…                        | that version → `SoftDeleted` (S3 says "permanently deleted"; we comply from the API's point of view: it vanishes from all S3 responses) | same |
| Lifecycle expiration                            | DeleteMarker / `SoftDeleted{Lifecycle}`    | `SoftDeleted{Lifecycle}` |
| DeleteBucket                                    | bucket → `Trashed`, name released          | same |
| Object Lock active                              | delete refused as S3 requires; Compliance mode also blocks admin purge until `retain_until` | same |

A `SoftDeleted`/`Superseded` version is invisible to every S3 operation (including
ListObjectVersions) unless `x-tidemark-include-trash` is set. A `Trashed` bucket is invisible to
ListBuckets; its name can be reused immediately (new `BucketId`).

### 7.3 Recovery operations (admin API, CLI, MCP tools; each mapped to a `tidemark:*` action)
- `trash ls [--bucket] [--prefix] [--deleted-after/--before] [--by]`
- `trash restore --bucket b --key k [--version v]` → the version becomes `Live` again and, if it
  is newer than the current head (or there is none), becomes head; always creates a new
  `latest` pointer rather than rewriting history. Restored objects get a `s3:ObjectRestore` event.
- `trash restore-bucket --id <BucketId> [--as newname]`
- `trash purge …` (irreversible; refuses under Compliance lock; requires `--yes`)
- `gc` runs continuously: walks `trash_idx` by `expires_at`, decrements blob refcounts, unlinks
  blobs with `refcount == 0` after an extra grace period (so a crash between the two steps is safe).

### 7.4 Point-in-time recovery
Because history is complete within the retention window, *the state of a bucket at time T is a
pure query*:

```
head_at(key, T) = newest Version v of key with v.created_at <= T
                   and not (v.state is Superseded{at} with at <= T)
                   and not (v.state is SoftDeleted{at} with at <= T)
                   ; if v.kind == DeleteMarker → key absent at T
```

Implemented as a range scan over `versions` with the per-key seek pattern above. Used by:
- `x-tidemark-as-of` time travel (read-only, zero copies).
- `tidemark pitr restore --bucket b --at T [--prefix p] [--to-bucket b2] [--dry-run]`: for every key,
  compute `head_at`, and if it differs from the current head, create a **new** version pointing at
  the same blobs (refcount++, no data copy) or a DeleteMarker. The restore is itself a batch of
  normal writes → fully reversible, audited, and replicated like any other write. `--dry-run`
  emits a diff (added/changed/removed) as JSON/NDJSON.
- Bucket configuration PITR via `bucket_history` (`tidemark pitr show-config --at T`).
The PITR horizon is `min(soft_delete, shadow_history)` of that bucket; the CLI prints it.

### 7.5 Versioning edge cases
- Suspended versioning writes `null` version ids per S3; internally they still get a real
  `VersionId`, and `null` is mapped to "the version whose `is_null` flag is set" (one per key).
- Versioned bucket with `min_versions_kept` + lifecycle `NoncurrentVersionExpiration` behaves per
  S3 but goes through soft delete.

---

## 8. Security and permissions

### 8.1 Principals and credentials
- **Root** credential (from config/env on first boot; can be rotated; cannot be denied).
- **Users** with long-lived access keys (max N keys per user), optional expiry, optional
  `allowed_source_cidrs`.
- **Roles** (assumable via STS with a trust policy of principals) → temporary credentials with
  session token, 15 min – 12 h.
- **Service accounts** = user with a single inline policy, convenient for apps (`tidemark admin sa create --for-bucket photos --rw`).
- **Groups** attach policies to many users.
- Secrets at rest: AEAD-encrypted with the master key. Access key ids look like `TDMK…`
  (20 chars) so they are recognisable in logs; `AKIA…` is also accepted for drop-in migration.

### 8.2 Policy language
AWS IAM JSON policy grammar, evaluated per AWS rules (explicit Deny > Allow > implicit Deny;
bucket policy ∪ identity policy; public access block vetoes). Supported:
- `Action` / `NotAction` with wildcards (`s3:Get*`, `s3:*`, `tidemark:*`), `Resource` / `NotResource`
  with ARNs `arn:aws:s3:::bucket[/key-pattern]` and `*`, `Principal` (`*`, `{"AWS": [ids|arns]}`),
  `Condition` operators: String{Equals,NotEquals,Like,NotLike}[IfExists], Numeric*, Date*, Bool,
  IpAddress/NotIpAddress, Null, ArnLike/ArnEquals; condition keys: `aws:SourceIp`,
  `aws:CurrentTime`, `aws:EpochTime`, `aws:username`, `aws:userid`, `aws:PrincipalArn`,
  `aws:SecureTransport`, `aws:Referer`, `aws:UserAgent`, `s3:prefix`, `s3:delimiter`, `s3:max-keys`,
  `s3:x-amz-acl`, `s3:x-amz-server-side-encryption`, `s3:x-amz-copy-source`, `s3:VersionId`,
  `s3:ExistingObjectTag/<k>`, `s3:RequestObjectTag/<k>`, `s3:object-lock-*`, `s3:signatureAge`,
  `s3:authType`, `tidemark:AsOf`, `tidemark:McpTool`.
- Policy variables `${aws:username}`, `${aws:userid}`.
- Policy documents are validated on write (unknown actions → error, size limit 20 KiB).
- Compiled once into a matcher struct (globs → compact automata) and cached by policy version.

Admin-only actions are in the `tidemark:` namespace (`tidemark:CreateUser`, `tidemark:ListTrash`,
`tidemark:Restore`, `tidemark:Purge`, `tidemark:TimeTravel`, `tidemark:Pitr`, `tidemark:ManageReplication`, …).

### 8.3 Transport and hardening
- rustls TLS with PEM certs (hot-reload on SIGHUP / file change); optional built-in ACME (HTTP-01)
  in Phase 4; HTTP→HTTPS redirect; HSTS.
- Request limits: max object 5 TiB, max part 5 GiB, min part 5 MiB (except last), 10 000 parts,
  header size caps, per-key concurrent-request and bytes/s limits (token bucket), connection
  limits, slowloris timeouts (tower-http `TimeoutLayer`, hyper header read timeout).
- Clock skew ±15 min; presigned URL max 7 days; replay protection for STS.
- Path normalisation and `..` rejection at the blob layer (defence in depth: blobs are never
  addressed by client-provided names anyway).
- Constant-time secret comparison; secrets never logged; `Authorization` header redacted in traces.
- Audit log: every authenticated request (who, what, resource, result, latency, source IP,
  request id) as JSONL, with optional webhook sink. Admin actions always audited.
- Supply chain: `cargo deny` (licenses/advisories), `cargo audit` in CI, locked deps, reproducible
  Dockerfile, SBOM.
- Threat model documented in `docs/SECURITY.md`; `SECURITY.md` disclosure policy.

- **Rate limiting and abuse controls**: token-bucket limits per access key, per source IP and
  per bucket (`[limits] rps_per_key`, `rps_per_ip`, `concurrent_per_key`, `anonymous_rps`); excess
  returns `503 SlowDown` with `Retry-After`, matching AWS. Hard caps on request body for non-object
  calls (1 MiB), header count/size, multipart part count (10 000), list page size (1 000),
  concurrent multipart uploads per bucket, and total open connections. Anonymous access is off
  unless a bucket policy grants it; anonymous requests get a separate, lower bucket.

---

## 9. Durability, backup and disaster recovery

- **Write path safety**: blob fsync + rename; redb is crash-safe (copy-on-write B-tree, no WAL
  replay surprises). Metadata commit happens after the blob is durable, so a crash leaves at most
  orphaned blobs (cleaned by GC) — never dangling references.
- **Integrity**: BLAKE3 per blob; `tidemark fsck` (metadata ↔ blob consistency, refcounts, orphans) and
  `tidemark scrub` (re-hash all/sampled blobs, throttled; reports and quarantines corrupt blobs,
  marks affected versions `Damaged` so GET returns a clear error and replication can heal them
  from a replica).
- **Backup**: `tidemark backup <dest>` where dest is a local path or `s3://…` (any S3 endpoint).
  Takes a consistent redb snapshot (redb `Database::compact` into a copy or savepoint-based
  export) then syncs new blobs (immutable → trivially incremental). `tidemark restore <src>` rebuilds a
  data dir. Backups are encrypted (age-style X25519/ChaCha20-Poly1305) when a recipient key is
  configured.
- **Replication (Phase 3)**: per-bucket rules to one or more targets (endpoint, credentials, prefix,
  filter by tags, `delete_marker_replication`, `existing_objects`). A worker consumes
  `events_queue` from `repl_cursor`, PUTs versions with original `x-amz-meta-*` and tags, and
  writes `x-amz-replication-status`. Targets can be another Tidemark (which also preserves version
  ids via the `x-tidemark-version-id` extension) or AWS/Backblaze/etc. Failover = point clients at
  the replica; fail back = reverse rule + `existing_objects`. Replication of trash restores and
  PITR restores is automatic because they are ordinary writes.
- **Quotas**: per-bucket size/object-count quota (`tidemark admin quota`); 507 when exceeded.

---

## 10. Events and extensions

- In-process bus: every committed mutation emits an `Event` (S3 event JSON schema 2.1 compatible,
  plus `tidemark:` events for trash/restore/pitr/lock/config). Durable outbox table guarantees
  at-least-once delivery to external sinks with exponential backoff and a dead-letter view.
- Sinks: **webhook** (HTTP POST, HMAC-SHA256 signature header, batching) ✅; **SSE stream**
  `/_tidemark/v1/events?filter=…` for lightweight external extensions (any language) 🟡; **NATS /
  MQTT / Kafka** 🟡 behind cargo features; **AMQP** ❌.
- **Function sinks (serverless targets)**: `arn:tidemark:sink::fn-<name>` is a webhook sink with a
  pluggable auth mode so bucket notifications can call serverless functions directly, exactly as
  S3 → Lambda does: `hmac` (default, signature header), `bearer` (static token), `sigv4-lambda`
  (signs an AWS Lambda `Invoke` call with stored credentials; `LambdaFunctionConfigurations`
  in the notification XML maps `LambdaFunctionArn` to the sink), `cf-access` (Cloudflare Access
  service token for Workers). Payload is the S3 event record; delivery is the same outbox,
  retries and DLQ. Object Lambda-style GET-time transforms are *not* in scope: do them in a
  sidecar that writes a derived object, or wait for the Phase 4 WASM experiment.
- Bucket notification configuration (`PutBucketNotificationConfiguration`) maps `TopicArn`/
  `QueueArn` to named Tidemark sinks (`arn:tidemark:sink::webhook-1`).
- Extension model: "sidecars", not in-process plugins. A sidecar subscribes to the SSE stream with
  a scoped credential, reacts (thumbnailing, virus scan, indexing, embedding) and writes results
  back through the S3/admin API. Keeps the core small and the ABI stable. WASM in-process hooks
  are a Phase 4 experiment (wasmtime, feature `wasm`), not a commitment.

---

## 11. AI integration

### 11.1 MCP server (`tidemark-mcp`, rmcp)
Transports: `tidemark mcp --stdio` (local agents; authenticates with an access key from env/config)
and Streamable HTTP at `/_tidemark/mcp` (remote agents; every request carries
`Authorization: Bearer <access-key-id>:<secret>[:<session-token>]` or SigV4; see `docs/MCP.md`). Every tool call is turned into an IAM authorisation with
`tidemark:McpTool` = tool name as a condition key, so an agent can be given
"read-only on bucket `docs/*`, never `purge`" with ordinary policies.

Tools (names are stable API):
| Tool | Maps to | Notes |
|------|---------|-------|
| `list_buckets`, `list_objects(bucket, prefix, delimiter, as_of?)` | S3 list | paginated, returns sizes/etags/content-types |
| `get_object(bucket, key, version?, as_of?, range?, mode=text\|base64\|url)` | GET | text mode decodes UTF-8 (and, with feature `extract`, pdf/docx/html→text) up to a size cap; `url` returns a short-lived presigned URL instead of bytes |
| `put_object(bucket, key, content\|content_base64, content_type?, metadata?, tags?)` | PUT | |
| `delete_object`, `copy_object`, `head_object` | | |
| `presign(bucket, key, method, expires)` | | |
| `search(bucket?, query, filters: {prefix, tags, metadata, size, modified})` | metadata index | with feature `ai`: semantic search over embeddings |
| `trash_list`, `trash_restore`, `pitr_diff(bucket, at)`, `pitr_restore(bucket, at, dry_run)` | §7 | `pitr_restore` requires `confirm: true` |
| `bucket_info`, `storage_stats`, `set_bucket_policy` (admin-scoped) | admin | |
Resources: `s3://bucket/key` (read via `resources/read`, list via templates), `tidemark://trash/…`.
Prompts: `summarize_bucket`, `audit_access`.
Phase 3c shipped the object, search (metadata), trash and PITR tools plus `bucket_info`, and
`pitr_head_at`; deferred: `get_object` `mode=url` / `presign` (server does not know the
client-facing endpoint), `storage_stats`, `set_bucket_policy`, resources and prompts (BUILD-PLAN
decisions log, 2026-11-08 Agent B).

### 11.2 Optional `ai` feature (Phase 4)
- Content extraction for text-like objects (markdown, json, csv, pdf, docx) into a derived
  `text/plain` preview stored as a sidecar blob (`derived:` namespace, never counted as user data,
  reaped when the source goes).
- Embeddings via any OpenAI-compatible `/v1/embeddings` endpoint (so Ollama/LM Studio work
  offline); vectors in `hnsw_rs` index persisted under `meta/vectors/<bucket>/`; `search` tool
  blends BM25 over extracted text (tantivy is too heavy — use a simple inverted index in redb) with
  vector similarity.
- Natural-language policy helper in the admin UI/CLI (`tidemark admin policy draft "…"`) that calls a
  configured LLM and shows the JSON for approval — never applied automatically.

---

## 12. Operations

- Config: `tidemark.toml` (+ `TIDEMARK_*` env overrides, + flags). Sections: `[server]` (listen, tls,
  domain for virtual-host style, region name), `[storage]` (data_dir, volumes, fsync policy,
  verify_on_read), `[retention]` defaults, `[auth]` (root key, session limits), `[limits]`,
  `[events]`, `[mcp]`, `[metrics]`, `[log]`.
- First run: `tidemark init --data-dir /srv/tidemark` prints root credentials once (or reads
  `TIDEMARK_ROOT_ACCESS_KEY/SECRET`). `tidemark serve` afterwards.
- Observability: `/metrics` (request counts/latency by op and status, bytes in/out, bucket sizes,
  blob count, GC/trash stats, replication lag, events DLQ depth), `/healthz` (process),
  `/readyz` (meta open + data dir writable), `tracing` JSON logs, OpenTelemetry export behind
  feature `otel`.
- Upgrades: metadata schema version in `kv`; migrations run on start with an automatic pre-upgrade
  snapshot; downgrade documented.
- Packaging: static musl binary for x86_64/aarch64, Docker image (`FROM scratch`), Helm chart
  (later), systemd unit, `brew`/`nix` later.
- Admin UI (Phase 4): small embedded SPA (Preact + htm, no build step heavier than esbuild) served
  at `/_tidemark/ui`: buckets, browse, trash, PITR timeline slider, users/policies, replication
  status, metrics summary.

### 12.1 Scaling path and HA posture

Tidemark v1 is deliberately **scale-up, single-writer**. Capacity goes as far as the host's
filesystem (ZFS/btrfs/LVM over many disks, hundreds of TB); throughput targets are in §13. The
promise that stays fixed across every stage below is that the S3 layer, `tidemark-engine`, IAM and
the MCP server never change — only `MetaStore` / `BlobStore` implementations do.

| Stage | What | Availability | Status |
|-------|------|--------------|--------|
| v1 | One node, one data dir, `redb` + fs blobs | Restart = seconds of downtime; no automatic failover | Phase 1–2 |
| v1.x | Async replication to another Tidemark or any S3 (§9); clients repointed on failure | Active-passive, manual or DNS/LB failover, RPO = replication lag | Phase 3 |
| v1.x | **Blob tiering**: `BlobStore` that keeps hot blobs local and moves cold blobs to remote S3 by age/size rule, metadata stays local | Capacity beyond the host; unchanged write path | Phase 3 |
| v2 | Multi-node: `openraft` replicated metadata, consistent-hash blob placement, optional local erasure coding (`reed-solomon-simd`) | Active-active, automatic failover | Post-v1, only if demand is real |

Running Tidemark *as* a serverless function is a non-goal: it owns local disk and a single metadata
writer. It runs well in any container platform with a persistent volume (Fly.io, Railway,
Kubernetes StatefulSet with one replica). Tidemark *calling* serverless functions is first-class via
function sinks (§10).

---

## 13. Performance targets (single node, NVMe, 4 cores)
- Small-object PUT/GET: > 5 000 req/s each at p99 < 10 ms (metadata-bound; group commit matters).
- Large-object streaming: saturate 10 GbE with 4 concurrent 1 GiB PUTs; zero-copy `sendfile`-ish via
  `tokio::fs` + large buffers; hashing is the CPU cost (BLAKE3 + MD5 ≈ 1.5 GB/s per core).
- ListObjectsV2 on 10 M keys with a delimiter: < 50 ms per page thanks to prefix skipping.
- Memory: no per-object in-memory index; redb page cache is the only cache (configurable).
- Footprint (published, not assumed): idle RSS ≤ 25 MiB, RSS under a 10 GiB upload/download
  ≤ 256 MiB, static binary ≤ 20 MB. `scripts/footprint.sh` measures all three the same way on
  every release; the numbers go in the README next to the competitor table.

---

## 14. Testing strategy
- Unit tests per crate (policy evaluator table tests, SigV4 test vectors from AWS docs, key-order
  properties with `proptest`, PITR `head_at` property: replaying history and querying any T equals
  the materialised state at T).
- Integration: `crates/tidemark-server/tests/` boots the server in-process on a random port and drives it with
  `aws-sdk-s3` (dev-dep) — covers every ✅ operation incl. multipart, versioning, soft delete,
  PITR, presign, STS, policies, encryption.
- Conformance: ceph `s3-tests` runs on every push against a committed expected-pass list
  (`scripts/s3-tests/`); a test leaving that list fails CI. A weekly full sweep reports newly
  passing tests to promote. Plus `aws`, `rclone`, `mc` via `scripts/e2e-clients.sh`.
- Claims: each of the four §0 claims has a named test that would fail if the claim were false
  (PRODUCTION-READINESS rows A5, A6, A7, D7).
- Crash safety: a `crash-sim` test injects failures between blob rename and meta commit and asserts
  fsck finds only orphans.
- Fuzz: `cargo fuzz` targets for XML parsing inputs that reach our code, policy JSON, key layouts.
- Load: `warp` (MinIO's benchmark tool) and `s3-benchmark` scripts under `bench/`.

---

## 15. Open questions (decide during Phase 1, note in BUILD-PLAN)
1. `s3s` 0.17 auth hook granularity — confirm we can see raw headers for `x-tidemark-*` in handlers
   (expected via `S3Request::headers`) and that it handles `aws-chunked` + trailers.
2. redb write throughput with group commit on 1 vCPU — if < 2 000 commits/s, batch across
   requests with a 1–2 ms window.
3. Whether `latest` should also cache the small `ObjectBody` to make HEAD/list one lookup (likely
   yes; store `Version` inline in `latest` and keep `versions` as the history).
4. Name: "Tidemark" collides with a few small projects; check crates.io/Docker Hub before 1.0.
5. Dedup across encryption keys (SSE-C / per-tenant KMS keys): blob ids are plaintext BLAKE3, so a
   second tenant uploading the same bytes under a different key would hit the first tenant's
   blob. Phase 2 must scope blob ids by key id for customer-keyed blobs; decide whether SSE-S3
   blobs stay globally deduplicated (likely yes).
6. Rate-limiter placement: tower middleware before SigV4 verification (cheap, per-IP only) plus a
   second per-key check after auth. Confirm `s3s` lets us run middleware at both points.
