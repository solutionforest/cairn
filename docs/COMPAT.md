# Cairn — S3 compatibility

Status of every S3 operation. Proving tests live in `crates/cairn-server/tests/` (aws-sdk-s3
against an in-process server). Engine-level behaviour is additionally covered by
`crates/cairn-engine/tests/engine.rs`.

Legend: ✅ implemented and tested · 🟡 partial (see notes) · ❌ returns `501 NotImplemented`.

## Service and bucket

| Operation | Status | Test | Notes / deviations |
|---|---|---|---|
| ListBuckets | ✅ | `buckets.rs` | `prefix`, `max-buckets`, `continuation-token` supported; Owner = caller principal id. |
| CreateBucket | ✅ | `buckets.rs` | `LocationConstraint` stored and echoed, never enforced. Re-creating your own bucket returns 200 and changes nothing when its region is `us-east-1`, as AWS does there; elsewhere `409 BucketAlreadyOwnedByYou`. `x-amz-bucket-object-lock-enabled` turns versioning on; lock enforcement is phase 2a. ACL headers (`x-amz-acl`, `x-amz-grant-*`) accepted and ignored; `x-amz-object-ownership` other than `BucketOwnerEnforced` → `InvalidArgument`. |
| HeadBucket | ✅ | `buckets.rs` | Returns `x-amz-bucket-region`. |
| DeleteBucket | ✅ | `buckets.rs` | Must be empty (`409 BucketNotEmpty`); bucket moves to the trash and the name is released immediately; open multipart uploads are aborted. |
| GetBucketLocation | ✅ | `buckets.rs` | Empty `LocationConstraint` for `us-east-1`. |
| Put/Get/DeleteBucketTagging | ✅ | `buckets.rs` | ≤ 50 tags; `NoSuchTagSet` when empty. |
| Put/GetBucketVersioning | ✅ | `buckets.rs`, `versioning.rs` | `MFADelete=Enabled` → `NotImplemented`. Suspending a bucket created with Object Lock → `InvalidBucketState`. In a suspended bucket, writes (PUT, Copy, Complete) do not echo the `null` version id, as S3 does. |
| Put/Get/DeleteBucketPolicy, GetBucketPolicyStatus | ✅ | `bucket_config.rs`, `auth_wire.rs` | IAM policy grammar (DESIGN §8); enforced on every S3, admin and MCP request. Status `IsPublic` follows AWS's public-policy rules; no policy → `NoSuchBucketPolicy`. |
| Put/Get/DeletePublicAccessBlock | ✅ | `bucket_config.rs`, `auth_wire.rs` | Bucket-level; `BlockPublicPolicy` refuses public policies, `RestrictPublicBuckets` ignores them. ACL flags are accepted (ACLs are disabled anyway). |
| Put/Get/DeleteBucketLifecycle(Configuration) | ✅ | `bucket_config.rs`, `lifecycle.rs` | Expiration (days, or a date at midnight GMT), noncurrent expiration, expired delete markers, abort incomplete multipart; prefix/tag/size filters. `Status` must be `Enabled` or `Disabled` (`MalformedXML`). Transitions → `NotImplemented` (one storage class). A rule sent without an `ID` gets one (`rule-N`). Rules come back in the shape they were sent: legacy top-level `Prefix` stays `Prefix`, `Filter` stays `Filter`. PUT, GET and HEAD of a current version a rule will expire carry `x-amz-expiration` (`expiry-date` = creation + Days rounded up to midnight UTC, the instant the lifecycle worker uses, and `rule-id`). |
| Get/PutBucketAcl | ✅ | `acl_attributes.rs` | ACLs are disabled, as on an S3 bucket with `BucketOwnerEnforced` (the S3 default since April 2023): Get returns the bucket owner with FULL_CONTROL; Put succeeds as a no-op for `private` or an owner-only FULL_CONTROL policy and answers `400 AccessControlListNotSupported` for anything that grants someone else. Access is IAM + bucket policy only. |
| Get/PutBucketOwnershipControls | ✅ | `acl_attributes.rs` | Always `BucketOwnerEnforced`; Put accepts only that value (`InvalidArgument` otherwise). DeleteBucketOwnershipControls → `NotImplemented`. |
| Put/Get/DeleteBucketEncryption | ✅ | `sse.rs` | SSE-S3 (`AES256`) only; `aws:kms` → `NotImplemented`. Accepted only when `storage.encrypt_at_rest` is on (else `InvalidRequest`): the master key is store-wide, so every blob is already encrypted and the document records that. No configuration → `ServerSideEncryptionConfigurationNotFoundError`. |
| CORS / website / logging / object-lock configuration | ❌ | `server.rs` | Shelved for v0.1 (DESIGN §0). S3 `OPTIONS` preflights are answered as S3 does for a bucket with no CORS configuration: 400 without `Origin` / `Access-Control-Request-Method`, else 403 `AccessForbidden`. |
| Notification / replication configuration | 🟡 | — | Shelved for v0.1 (DESIGN §0): the handlers from the pre-scope-cut code still answer, but they are unsupported, outside the readiness gate and may change or be removed. |

## Objects

| Operation | Status | Test | Notes / deviations |
|---|---|---|---|
| PutObject | ✅ | `objects.rs`, `range_conditional.rs` | Content-Type/Cache-Control/Content-Disposition/Content-Encoding/Content-Language/Expires, `x-amz-meta-*` (names lowercased, 2 KiB limit), `x-amz-tagging`, `x-amz-website-redirect-location`, storage class (stored and echoed; one physical class). `Content-MD5` and `x-amz-checksum-*` verified (header or aws-chunked trailer); a malformed checksum value → `BadDigest`, a Content-MD5 that is not 16 bytes → `InvalidDigest`. The `aws-chunked` token is stripped from the stored `Content-Encoding`. `If-None-Match: *` and `If-Match` supported. SSE-C, SSE-KMS, Object Lock headers and `x-amz-write-offset-bytes` → `NotImplemented`; `x-amz-server-side-encryption: AES256` accepted only when `storage.encrypt_at_rest` is on. |
| GetObject | ✅ | `objects.rs`, `range_conditional.rs`, `multipart.rs` | `Range` (first-last, open-ended, suffix; single range), `partNumber`, `response-*` overrides, `If-Match`/`If-None-Match`/`If-Modified-Since`/`If-Unmodified-Since` (RFC 7232 precedence), `versionId` incl. `null`, `x-amz-checksum-mode: ENABLED` (checksum only on full-object reads; a `partNumber` read always reports that part's checksum), `x-cairn-as-of`. Default Content-Type `binary/octet-stream`. |
| HeadObject | ✅ | `objects.rs`, `range_conditional.rs` | Same as GetObject without body. |
| DeleteObject | ✅ | `objects.rs`, `versioning.rs` | Versioned → delete marker; unversioned → soft delete; `versionId` → that version leaves every S3 view (kept in the trash for the retention window). |
| DeleteObjects | ✅ | `objects.rs` | ≤ 1000 keys; `Quiet`; per-key errors (e.g. malformed version id) reported in `<Error>`. |
| CopyObject | ✅ | `objects.rs`, `range_conditional.rs` | `x-amz-metadata-directive`, `x-amz-tagging-directive`, `x-amz-copy-source-if-*` (all failures 412), destination `If-Match`/`If-None-Match`, source `versionId`, cross-bucket, in-place metadata update. Server-side: the new version shares the source blobs (no data copy). Access-point copy sources → `NotImplemented`. |
| ListObjects (v1) | ✅ | `listing.rs` | `prefix`, `delimiter`, `marker`, `max-keys` (≤ 1000), `encoding-type=url` (encodes `Key`, `Marker`, `NextMarker`, `Delimiter`, `CommonPrefixes`; `Prefix` is echoed verbatim, as SDKs expect for V1). `NextMarker` returned whenever truncated. |
| ListObjectsV2 | ✅ | `listing.rs`, `pitr.rs` | Opaque continuation tokens, `start-after`, `fetch-owner`, `encoding-type=url`, `x-cairn-as-of`. |
| ListObjectVersions | ✅ | `versioning.rs`, `pitr.rs` | Newest first per key; `key-marker` + `version-id-marker`; `x-cairn-include-trash`. Versions and delete markers are serialised as two lists (as the S3 schema allows). |
| Get/Put/DeleteObjectTagging | ✅ | `objects.rs` | ≤ 10 tags; tagging is metadata, so it updates the version in place. |
| GetObjectAttributes | ✅ | `acl_attributes.rs` | `ETag` (unquoted), `ObjectSize`, `StorageClass`, `Checksum` (with `ChecksumType`), `ObjectParts` for multipart objects with per-part size and checksum, `max-parts` / `part-number-marker` paging; `versionId`, `x-cairn-as-of`. |
| Get/PutObjectAcl | ✅ | `acl_attributes.rs` | Same model as Get/PutBucketAcl: the bucket owner owns every object. |
| Get/PutObjectRetention, Get/PutObjectLegalHold, RestoreObject, SelectObjectContent, PostObject, WriteGetObjectResponse | ❌ | — | Shelved for v0.1 or out of scope (DESIGN §0, §6). |

## Multipart

| Operation | Status | Test | Notes / deviations |
|---|---|---|---|
| CreateMultipartUpload | ✅ | `multipart.rs` | Metadata, tags, storage class and checksum algorithm are applied on completion. `x-amz-checksum-type: FULL_OBJECT` supported for CRC32/CRC32C/CRC64NVME (CRC64NVME is always full-object, as in AWS). |
| UploadPart | ✅ | `multipart.rs` | Part numbers 1..=10000, ≤ 5 GiB, `Content-MD5` and checksums verified. |
| UploadPartCopy | ✅ | `multipart.rs` | `x-amz-copy-source-range` (past the end of the source → `InvalidRange`), source conditions. A whole single-part source reuses the source blob. |
| CompleteMultipartUpload | ✅ | `multipart.rs` | Ascending order (`InvalidPartOrder`), ETag match (`InvalidPart`), 5 MiB minimum for non-final parts (`EntityTooSmall`), per-part checksum match, `If-Match`/`If-None-Match`. ETag = `md5(concat(part md5s))-N`. Composite checksum = `checksum(concat(part checksums))-N`; FULL_OBJECT checksums are computed by re-reading the assembled object. No keep-alive whitespace is streamed for very slow completions. Repeating a completed Complete with the same part list returns 200 and the object it produced (recognised by the multipart ETag; nothing is written); any other part list → `NoSuchUpload`. |
| AbortMultipartUpload | ✅ | `multipart.rs` | Releases part blobs to GC. |
| ListParts | ✅ | `multipart.rs` | `part-number-marker`, `max-parts`. Part `LastModified` is the upload initiation time. |
| ListMultipartUploads | ✅ | `multipart.rs` | `prefix`, `delimiter`, `key-marker`, `upload-id-marker`, `max-uploads`. |

## Protocol

| Feature | Status | Test | Notes |
|---|---|---|---|
| SigV4 header auth | ✅ | `buckets.rs` | Root credential only in phase 1c (`SignatureDoesNotMatch`, `InvalidAccessKeyId`); IAM users/STS arrive with phase 2b. |
| Unsigned requests | ✅ | `buckets.rs` | `403 AccessDenied`. |
| aws-chunked uploads with trailing checksums | ✅ | `objects.rs` | Default aws-sdk behaviour over HTTP. |
| Error bodies | ✅ | `buckets.rs` | `<Error><Code/><Message/><Resource/><RequestId/></Error>`; `x-amz-request-id` and `x-amz-id-2` on every response. |
| Path-style addressing | ✅ | all | Virtual-host style when `server.domain` is set (not yet integration-tested). |
| Checksums | ✅ | `objects.rs`, `multipart.rs` | CRC32, CRC32C, CRC64NVME, SHA1, SHA256. SHA512/MD5/XXHASH checksum headers → `NotImplemented`. |

## Manual client runs

Real clients against a throwaway `cairn serve` (PRODUCTION-READINESS A3). Re-run with
`scripts/e2e-clients.sh [path/to/cairn]` and paste its output here.

Run 2026-11-08T17:45Z by `scripts/e2e-clients.sh`, cairn 0.1.0 debug build of `target/debug/cairn` built 17:17Z (tree at about 523a207), SigV4 auth on with the root credential printed by `cairn init`, 1 vCPU gVisor host. Clients:
- aws-cli/1.46.3 Python/3.12.1 Linux/4.19.0-gvisor botocore/1.43.62
- rclone v1.76.0
- mc RELEASE.2025-08-13T08-35-41Z

| Client | Step | Result |
|---|---|---|
| aws | s3 mb | pass |
| aws | s3 ls (buckets) | pass |
| aws | s3 cp upload (small) | pass |
| aws | s3 cp upload (24 MiB, multipart) | pass |
| aws | s3 cp download + cmp (multipart) | pass |
| aws | s3 cp - (stdin stream) | pass |
| aws | s3 cp --recursive | pass |
| aws | s3 sync up | pass |
| aws | s3 sync up again (no-op) | pass |
| aws | s3 sync down + diff | pass |
| aws | s3 ls --recursive (count) | pass |
| aws | s3 ls prefix (delimiter) | pass |
| aws | s3 sync --delete | pass |
| aws | s3 mv | pass |
| aws | s3 cp (server-side copy) | pass |
| aws | s3 presign (SigV2 URL) → refused | pass |
| aws | s3 presign (SigV4) + curl GET | pass |
| aws | s3api head-object | pass |
| aws | s3 rm | pass |
| aws | s3 rm --recursive | pass |
| aws | s3 rb (non-empty → refused) | pass |
| aws | s3 rb --force | pass |
| aws | s3 ls (bucket gone) | pass |
| rclone | mkdir | pass |
| rclone | sync up | pass |
| rclone | check (size + md5) | pass |
| rclone | sync up again (0 transfers) | pass |
| rclone | sync down + diff | pass |
| rclone | copyto (24 MiB, multipart 5 MiB chunks) | pass |
| rclone | cat + cmp (multipart) | pass |
| rclone | lsf -R (count) | pass |
| rclone | sync (deletes extraneous) | pass |
| rclone | moveto (server-side copy + delete) | pass |
| rclone | delete | pass |
| rclone | purge (bucket) | pass |
| rclone | lsd (bucket gone) | pass |
| mc | alias set | pass |
| mc | admin-free ping (ls) | pass |
| mc | mb | pass |
| mc | cp (small) | pass |
| mc | cp (24 MiB, multipart) | pass |
| mc | cat + cmp (multipart) | pass |
| mc | pipe (stdin stream) | pass |
| mc | cp --recursive | pass |
| mc | mirror up | pass |
| mc | mirror down + diff | pass |
| mc | diff (no differences) | pass |
| mc | ls --recursive (count) | pass |
| mc | stat | pass |
| mc | tag set / list | pass |
| mc | version enable + info | pass |
| mc | ls --versions | pass |
| mc | share download + curl | pass |
| mc | rm | pass |
| mc | rm --recursive --force | pass |
| mc | rb --force (versioned bucket) | pass |
| mc | ls (bucket gone) | pass |

57/57 steps passed

Server-log notes from this run: the SigV2 presign step is refused by design
(`AccessDenied: Signature Version 2 is disabled`); `mc` probes `GetObjectLockConfiguration` on
`ls`/`stat`/`rb` and gets `501 NotImplemented` (Object Lock is shelved for v0.1, DESIGN §0), which
`mc` tolerates. Both are logged at `ERROR` level by the s3s/tower-http layers even though they
are expected client errors.

