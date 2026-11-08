//! Plain-Rust request/response types mirroring S3 operations.

use bytes::Bytes;
use cairn_core::{ChecksumAlgo, PrincipalId, S3Error, Ts, VersionId};
use cairn_meta::{BucketRecord, VersionRecord};
use futures::Stream;
use std::collections::BTreeMap;
use std::pin::Pin;
use std::task::{Context, Poll};

/// Request body stream.
pub type Body = Pin<Box<dyn Stream<Item = Result<Bytes, S3Error>> + Send>>;

/// Build a [`Body`] from bytes (tests, small payloads).
pub fn body_from_bytes(b: impl Into<Bytes>) -> Body {
    let b = b.into();
    Box::pin(futures::stream::iter(if b.is_empty() { vec![] } else { vec![Ok(b)] }))
}

/// Response body stream (`Send + Sync`, as `s3s::StreamingBlob` requires).
pub struct BodyStream {
    pub(crate) rx: tokio::sync::mpsc::Receiver<std::io::Result<Bytes>>,
    pub(crate) len: u64,
}

impl BodyStream {
    /// Exact number of bytes the stream yields.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the stream is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Stream for BodyStream {
    type Item = std::io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

/// Late-bound checksum value (trailing headers are only known after the body).
pub type LateValue = Box<dyn FnOnce() -> Option<String> + Send + Sync>;

/// Requested `x-amz-checksum-*` handling.
#[derive(Default)]
pub enum ChecksumInput {
    /// None requested.
    #[default]
    None,
    /// Compute and store, nothing to verify.
    Compute(ChecksumAlgo),
    /// Verify against this base64 value.
    Value(ChecksumAlgo, String),
    /// Verify against a trailer read after the body is consumed.
    Trailer(ChecksumAlgo, LateValue),
}

impl ChecksumInput {
    /// The algorithm, if any.
    pub fn algo(&self) -> Option<ChecksumAlgo> {
        match self {
            ChecksumInput::None => None,
            ChecksumInput::Compute(a) | ChecksumInput::Value(a, _) | ChecksumInput::Trailer(a, _) => Some(*a),
        }
    }
}

/// HTTP/user metadata stored with an object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectMeta {
    /// Content-Type.
    pub content_type: Option<String>,
    /// Cache-Control.
    pub cache_control: Option<String>,
    /// Content-Disposition.
    pub content_disposition: Option<String>,
    /// Content-Encoding.
    pub content_encoding: Option<String>,
    /// Content-Language.
    pub content_language: Option<String>,
    /// Expires.
    pub expires: Option<String>,
    /// `x-amz-meta-*`.
    pub user_metadata: BTreeMap<String, String>,
    /// Storage class.
    pub storage_class: Option<String>,
    /// Website redirect.
    pub website_redirect: Option<String>,
}

/// Write preconditions (`If-Match` / `If-None-Match` on PUT / Complete).
#[derive(Debug, Clone, Default)]
pub struct WriteConditions {
    /// Require the current object's ETag to match (`*` = any).
    pub if_match: Option<String>,
    /// Require no current object (`*`) or a different ETag.
    pub if_none_match: Option<String>,
}

/// Read preconditions.
#[derive(Debug, Clone, Default)]
pub struct ReadConditions {
    /// If-Match.
    pub if_match: Option<String>,
    /// If-None-Match.
    pub if_none_match: Option<String>,
    /// If-Modified-Since.
    pub if_modified_since: Option<Ts>,
    /// If-Unmodified-Since.
    pub if_unmodified_since: Option<Ts>,
}

/// PutObject.
pub struct PutObjectReq {
    /// Bucket.
    pub bucket: String,
    /// Key.
    pub key: String,
    /// Payload.
    pub body: Body,
    /// Declared length.
    pub content_length: Option<u64>,
    /// Base64 Content-MD5.
    pub content_md5: Option<String>,
    /// Checksum handling.
    pub checksum: ChecksumInput,
    /// Metadata.
    pub meta: ObjectMeta,
    /// Tags.
    pub tags: BTreeMap<String, String>,
    /// Preconditions.
    pub conditions: WriteConditions,
    /// Caller.
    pub owner: PrincipalId,
}

/// PutObject / Copy / Complete result.
#[derive(Debug, Clone)]
pub struct PutObjectRes {
    /// ETag (unquoted).
    pub etag: String,
    /// S3 version id (`None` when versioning was never enabled).
    pub version_id: Option<String>,
    /// Stored checksum.
    pub checksum: Option<(ChecksumAlgo, String)>,
    /// Size.
    pub size: u64,
    /// The created version.
    pub version: VersionRecord,
}

/// Byte range request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeSpec {
    /// `bytes=first-last` (last inclusive, optional).
    Int {
        /// First byte.
        first: u64,
        /// Last byte inclusive.
        last: Option<u64>,
    },
    /// `bytes=-len`.
    Suffix(u64),
}

/// GetObject / HeadObject.
#[derive(Debug, Clone, Default)]
pub struct GetObjectReq {
    /// Bucket.
    pub bucket: String,
    /// Key.
    pub key: String,
    /// Version id (`null` allowed).
    pub version_id: Option<String>,
    /// Range.
    pub range: Option<RangeSpec>,
    /// Part number.
    pub part_number: Option<u32>,
    /// Preconditions.
    pub conditions: ReadConditions,
    /// Time travel (`x-cairn-as-of`).
    pub as_of: Option<Ts>,
}

/// GetObject / HeadObject result.
pub struct GetObjectRes {
    /// The resolved version.
    pub version: VersionRecord,
    /// S3 version id to report.
    pub version_id: Option<String>,
    /// Body (None for HEAD).
    pub body: Option<BodyStream>,
    /// Returned byte range (`start..end`) when partial.
    pub range: Option<(u64, u64)>,
    /// Content length of the response.
    pub content_length: u64,
    /// Total object size.
    pub size: u64,
    /// Number of parts (when partNumber was requested or object is multipart).
    pub parts_count: Option<u32>,
}

/// DeleteObject result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeleteRes {
    /// A delete marker was created or deleted.
    pub delete_marker: bool,
    /// Version id of the marker or deleted version.
    pub version_id: Option<String>,
}

/// Metadata directive for copies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Directive {
    /// Copy from source.
    #[default]
    Copy,
    /// Replace with request values.
    Replace,
}

/// CopyObject.
#[derive(Debug, Clone, Default)]
pub struct CopyObjectReq {
    /// Source bucket.
    pub src_bucket: String,
    /// Source key.
    pub src_key: String,
    /// Source version.
    pub src_version: Option<String>,
    /// Source preconditions (all failures → 412).
    pub src_conditions: ReadConditions,
    /// Destination bucket.
    pub bucket: String,
    /// Destination key.
    pub key: String,
    /// Metadata directive.
    pub metadata_directive: Directive,
    /// Replacement metadata.
    pub meta: ObjectMeta,
    /// Tagging directive.
    pub tagging_directive: Directive,
    /// Replacement tags.
    pub tags: BTreeMap<String, String>,
    /// Destination preconditions.
    pub conditions: WriteConditions,
    /// Recompute this checksum for the destination.
    pub checksum_algo: Option<ChecksumAlgo>,
    /// Caller.
    pub owner: PrincipalId,
}

/// CopyObject result.
#[derive(Debug, Clone)]
pub struct CopyObjectRes {
    /// Destination result.
    pub put: PutObjectRes,
    /// Source version id reported back.
    pub src_version_id: Option<String>,
}

/// Listing request.
#[derive(Debug, Clone, Default)]
pub struct ListReq {
    /// Prefix.
    pub prefix: String,
    /// Delimiter.
    pub delimiter: Option<String>,
    /// Exclusive start key.
    pub after: Option<String>,
    /// Max keys (clamped to 1000).
    pub max: usize,
    /// Time travel.
    pub as_of: Option<Ts>,
}

/// One listed object / version.
#[derive(Debug, Clone)]
pub struct ListedVersion {
    /// Record.
    pub version: VersionRecord,
    /// S3 version id string (`null` for null versions).
    pub version_id: String,
    /// Current head.
    pub is_latest: bool,
}

/// Listing result.
#[derive(Debug, Clone, Default)]
pub struct ListRes {
    /// Objects / versions.
    pub objects: Vec<ListedVersion>,
    /// Common prefixes.
    pub prefixes: Vec<String>,
    /// More results.
    pub truncated: bool,
    /// Next key marker.
    pub next_key: Option<String>,
    /// Next version-id marker.
    pub next_version: Option<String>,
}

/// ListObjectVersions request.
#[derive(Debug, Clone, Default)]
pub struct ListVersionsReq {
    /// Prefix/delimiter/max; `after` = key marker.
    pub list: ListReq,
    /// Version-id marker.
    pub version_marker: Option<String>,
    /// Include soft-deleted/superseded versions.
    pub include_trash: bool,
}

/// CreateMultipartUpload.
#[derive(Debug, Clone, Default)]
pub struct CreateUploadReq {
    /// Bucket.
    pub bucket: String,
    /// Key.
    pub key: String,
    /// Metadata.
    pub meta: ObjectMeta,
    /// Tags.
    pub tags: BTreeMap<String, String>,
    /// Checksum algorithm for parts.
    pub checksum_algo: Option<ChecksumAlgo>,
    /// Caller.
    pub owner: PrincipalId,
}

/// UploadPart.
pub struct UploadPartReq {
    /// Bucket.
    pub bucket: String,
    /// Key.
    pub key: String,
    /// Upload id.
    pub upload_id: String,
    /// Part number 1..=10000.
    pub part_number: u32,
    /// Payload.
    pub body: Body,
    /// Declared length.
    pub content_length: Option<u64>,
    /// Content-MD5.
    pub content_md5: Option<String>,
    /// Checksum.
    pub checksum: ChecksumInput,
}

/// UploadPart result.
#[derive(Debug, Clone)]
pub struct UploadPartRes {
    /// Part ETag (unquoted hex).
    pub etag: String,
    /// Part checksum.
    pub checksum: Option<(ChecksumAlgo, String)>,
    /// Last modified.
    pub last_modified: Ts,
}

/// UploadPartCopy.
#[derive(Debug, Clone, Default)]
pub struct UploadPartCopyReq {
    /// Source bucket.
    pub src_bucket: String,
    /// Source key.
    pub src_key: String,
    /// Source version.
    pub src_version: Option<String>,
    /// Source preconditions.
    pub src_conditions: ReadConditions,
    /// Source byte range (inclusive first/last).
    pub range: Option<(u64, u64)>,
    /// Destination bucket.
    pub bucket: String,
    /// Destination key.
    pub key: String,
    /// Upload id.
    pub upload_id: String,
    /// Part number.
    pub part_number: u32,
}

/// One part named in CompleteMultipartUpload.
#[derive(Debug, Clone)]
pub struct CompletePart {
    /// Part number.
    pub number: u32,
    /// ETag as sent (quotes tolerated).
    pub etag: String,
}

/// CompleteMultipartUpload.
#[derive(Debug, Clone, Default)]
pub struct CompleteReq {
    /// Bucket.
    pub bucket: String,
    /// Key.
    pub key: String,
    /// Upload id.
    pub upload_id: String,
    /// Parts in request order.
    pub parts: Vec<CompletePart>,
    /// Preconditions.
    pub conditions: WriteConditions,
    /// Caller.
    pub owner: PrincipalId,
}

/// ListParts result.
#[derive(Debug, Clone, Default)]
pub struct ListPartsRes {
    /// Upload record (for initiator/key/checksum).
    pub upload: Option<cairn_meta::MultipartRecord>,
    /// Parts.
    pub parts: Vec<(cairn_meta::PartRef, Ts)>,
    /// More.
    pub truncated: bool,
    /// Next part marker.
    pub next_marker: Option<u32>,
}

/// ListMultipartUploads result.
#[derive(Debug, Clone, Default)]
pub struct ListUploadsRes {
    /// Uploads.
    pub uploads: Vec<cairn_meta::MultipartRecord>,
    /// Common prefixes.
    pub prefixes: Vec<String>,
    /// More.
    pub truncated: bool,
    /// Next key marker.
    pub next_key: Option<String>,
    /// Next upload id marker.
    pub next_upload: Option<String>,
}

/// A soft-deleted or superseded version.
#[derive(Debug, Clone)]
pub struct TrashEntry {
    /// Bucket name.
    pub bucket: String,
    /// Version record.
    pub version: VersionRecord,
    /// When it left Live.
    pub hidden_at: Ts,
    /// When GC may purge it.
    pub expires_at: Ts,
}

/// Change kinds in a PITR diff (from the current state back to `at`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    /// Key existed at `at` but not now (restore re-creates it).
    Recreate,
    /// Key exists in both but content differs (restore overwrites it).
    Revert,
    /// Key exists now but not at `at` (restore deletes it).
    Remove,
}

/// One PITR diff entry.
#[derive(Debug, Clone)]
pub struct DiffEntry {
    /// Key.
    pub key: String,
    /// Kind.
    pub kind: DiffKind,
    /// Head at `at`.
    pub then: Option<VersionId>,
    /// Current head.
    pub now: Option<VersionId>,
}

/// GC tick statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GcStats {
    /// Version rows purged.
    pub versions_purged: u64,
    /// Blob files unlinked.
    pub blobs_deleted: u64,
    /// Buckets purged.
    pub buckets_purged: u64,
}

/// Bucket info for listings.
pub type BucketInfo = BucketRecord;
