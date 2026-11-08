# Cairn — S3 compatibility

Status of every S3 operation. Proving tests live in `crates/cairn-server/tests/` (aws-sdk-s3
against an in-process server). Engine-level behaviour is additionally covered by
`crates/cairn-engine/tests/engine.rs`.

Legend: ✅ implemented and tested · 🟡 partial (see notes) · ❌ returns `501 NotImplemented`.

## Service and bucket

| Operation | Status | Test | Notes / deviations |
|---|---|---|---|
| ListBuckets | ✅ | `buckets.rs` | `prefix`, `max-buckets`, `continuation-token` supported; Owner = caller principal id. |
| CreateBucket | ✅ | `buckets.rs` | `LocationConstraint` stored and echoed, never enforced. Re-creating your own bucket returns `409 BucketAlreadyOwnedByYou` in every region (AWS returns 200 in us-east-1). `x-amz-bucket-object-lock-enabled` turns versioning on; lock enforcement is phase 2a. ACL headers accepted and ignored. |
| HeadBucket | ✅ | `buckets.rs` | Returns `x-amz-bucket-region`. |
| DeleteBucket | ✅ | `buckets.rs` | Must be empty (`409 BucketNotEmpty`); bucket moves to the trash and the name is released immediately; open multipart uploads are aborted. |
| GetBucketLocation | ✅ | `buckets.rs` | Empty `LocationConstraint` for `us-east-1`. |
| Put/Get/DeleteBucketTagging | ✅ | `buckets.rs` | ≤ 50 tags; `NoSuchTagSet` when empty. |
| Put/GetBucketVersioning | ✅ | `buckets.rs`, `versioning.rs` | `MFADelete=Enabled` → `NotImplemented`. Suspending a bucket created with Object Lock → `InvalidBucketState`. |
| Bucket policy / lifecycle / CORS / encryption / PAB / notification / replication / object-lock configuration / ACL / website / logging / etc. | ❌ | — | Phase 2/3 (see BUILD-PLAN). |

## Objects

| Operation | Status | Test | Notes / deviations |
|---|---|---|---|
| PutObject | ✅ | `objects.rs`, `range_conditional.rs` | Content-Type/Cache-Control/Content-Disposition/Content-Encoding/Content-Language/Expires, `x-amz-meta-*` (names lowercased, 2 KiB limit), `x-amz-tagging`, `x-amz-website-redirect-location`, storage class (stored and echoed; one physical class). `Content-MD5` and `x-amz-checksum-*` verified (header or aws-chunked trailer). `If-None-Match: *` and `If-Match` supported. SSE-C, SSE-KMS, Object Lock headers and `x-amz-write-offset-bytes` → `NotImplemented`; `x-amz-server-side-encryption: AES256` accepted only when `storage.encrypt_at_rest` is on. |
| GetObject | ✅ | `objects.rs`, `range_conditional.rs`, `multipart.rs` | `Range` (first-last, open-ended, suffix; single range), `partNumber`, `response-*` overrides, `If-Match`/`If-None-Match`/`If-Modified-Since`/`If-Unmodified-Since` (RFC 7232 precedence), `versionId` incl. `null`, `x-amz-checksum-mode: ENABLED` (checksum only on full-object reads), `x-cairn-as-of`. Default Content-Type `binary/octet-stream`. |
| HeadObject | ✅ | `objects.rs`, `range_conditional.rs` | Same as GetObject without body. |
| DeleteObject | ✅ | `objects.rs`, `versioning.rs` | Versioned → delete marker; unversioned → soft delete; `versionId` → that version leaves every S3 view (kept in the trash for the retention window). |
| DeleteObjects | ✅ | `objects.rs` | ≤ 1000 keys; `Quiet`; per-key errors (e.g. malformed version id) reported in `<Error>`. |
| CopyObject | ✅ | `objects.rs`, `range_conditional.rs` | `x-amz-metadata-directive`, `x-amz-tagging-directive`, `x-amz-copy-source-if-*` (all failures 412), destination `If-Match`/`If-None-Match`, source `versionId`, cross-bucket, in-place metadata update. Server-side: the new version shares the source blobs (no data copy). Access-point copy sources → `NotImplemented`. |
| ListObjects (v1) | ✅ | `listing.rs` | `prefix`, `delimiter`, `marker`, `max-keys` (≤ 1000), `encoding-type=url`. `NextMarker` returned whenever truncated. |
| ListObjectsV2 | ✅ | `listing.rs`, `pitr.rs` | Opaque continuation tokens, `start-after`, `fetch-owner`, `encoding-type=url`, `x-cairn-as-of`. |
| ListObjectVersions | ✅ | `versioning.rs`, `pitr.rs` | Newest first per key; `key-marker` + `version-id-marker`; `x-cairn-include-trash`. Versions and delete markers are serialised as two lists (as the S3 schema allows). |
| Get/Put/DeleteObjectTagging | ✅ | `objects.rs` | ≤ 10 tags; tagging is metadata, so it updates the version in place. |
| GetObjectAttributes, Get/PutObjectRetention, Get/PutObjectLegalHold, Get/PutObjectAcl, RestoreObject, SelectObjectContent, PostObject, WriteGetObjectResponse | ❌ | — | Phase 2a/3c or out of scope (DESIGN §6). |

## Multipart

| Operation | Status | Test | Notes / deviations |
|---|---|---|---|
| CreateMultipartUpload | ✅ | `multipart.rs` | Metadata, tags, storage class and checksum algorithm are applied on completion. `x-amz-checksum-type: FULL_OBJECT` supported for CRC32/CRC32C/CRC64NVME (CRC64NVME is always full-object, as in AWS). |
| UploadPart | ✅ | `multipart.rs` | Part numbers 1..=10000, ≤ 5 GiB, `Content-MD5` and checksums verified. |
| UploadPartCopy | ✅ | `multipart.rs` | `x-amz-copy-source-range`, source conditions. A whole single-part source reuses the source blob. |
| CompleteMultipartUpload | ✅ | `multipart.rs` | Ascending order (`InvalidPartOrder`), ETag match (`InvalidPart`), 5 MiB minimum for non-final parts (`EntityTooSmall`), per-part checksum match, `If-Match`/`If-None-Match`. ETag = `md5(concat(part md5s))-N`. Composite checksum = `checksum(concat(part checksums))-N`; FULL_OBJECT checksums are computed by re-reading the assembled object. No keep-alive whitespace is streamed for very slow completions. |
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

Not yet recorded (PRODUCTION-READINESS A8): `aws s3 cp/sync/ls/rm/mb/rb`, `rclone`, `mc`.
