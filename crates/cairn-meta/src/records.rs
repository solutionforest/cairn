//! Metadata records (DESIGN §4.2). Encoded as `[SCHEMA_VERSION] ‖ postcard(record)`.

use cairn_core::{BlobId, BucketId, PrincipalId, Ts, VersionId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::MetaError;

/// Current schema version byte for every record type.
pub const SCHEMA_VERSION: u8 = 1;

/// Encode a record with its leading schema-version byte.
pub fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    let mut out = vec![SCHEMA_VERSION];
    out.extend(
        postcard::to_allocvec(v).expect("postcard serialisation of in-memory record cannot fail"),
    );
    out
}

/// Decode a record, checking the schema-version byte.
pub fn decode<T: DeserializeOwned>(b: &[u8]) -> Result<T, MetaError> {
    match b.split_first() {
        Some((&SCHEMA_VERSION, rest)) => {
            postcard::from_bytes(rest).map_err(|e| MetaError::Corrupt(e.to_string()))
        }
        Some((v, _)) => Err(MetaError::Corrupt(format!("unknown schema version {v}"))),
        None => Err(MetaError::Corrupt("empty record".into())),
    }
}

/// Bucket versioning state as S3 exposes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Versioning {
    /// Never enabled (shadow versioning only).
    #[default]
    Off,
    /// Enabled.
    Enabled,
    /// Suspended after having been enabled.
    Suspended,
}

/// Per-bucket retention override; `None` fields fall back to the server default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RetentionPolicy {
    /// Soft-delete window in seconds.
    pub soft_delete_secs: Option<u64>,
    /// Shadow-history window in seconds.
    pub shadow_history_secs: Option<u64>,
    /// Minimum versions kept per key.
    pub min_versions_kept: Option<u32>,
}

/// Bucket lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BucketState {
    /// Visible and usable.
    Active,
    /// Deleted through the API; restorable until purged.
    Trashed {
        /// When.
        at: Ts,
        /// By whom.
        by: PrincipalId,
    },
}

/// A bucket record (`bucket_meta`, `bucket_history`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketRecord {
    /// Identity.
    pub id: BucketId,
    /// Name at creation.
    pub name: String,
    /// Creation time.
    pub created_at: Ts,
    /// Owner.
    pub owner: PrincipalId,
    /// Versioning state.
    pub versioning: Versioning,
    /// Object Lock enabled at creation.
    pub object_lock_enabled: bool,
    /// Retention override.
    pub retention: RetentionPolicy,
    /// Bucket tags.
    pub tags: BTreeMap<String, String>,
    /// Region / location constraint reported back.
    pub location: Option<String>,
    /// Opaque configuration documents keyed by kind (`policy`, `lifecycle`, `cors`, `encryption`,
    /// `object_lock`, `public_access_block`, `notification`, `replication`, ...). Phase 2 fills these.
    pub configs: BTreeMap<String, Vec<u8>>,
    /// State.
    pub state: BucketState,
    /// Bumped on each configuration change.
    pub config_seq: u64,
}

/// Why a version was soft-deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeleteReason {
    /// S3 API request.
    Api,
    /// Lifecycle expiration.
    Lifecycle,
    /// Admin action.
    Admin,
}

/// Visibility state of a version (DESIGN §7.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionState {
    /// Visible to S3.
    Live,
    /// Overwritten in an unversioned bucket (hidden).
    Superseded {
        /// When.
        at: Ts,
    },
    /// Deleted (hidden), restorable until purged.
    SoftDeleted {
        /// When.
        at: Ts,
        /// By whom.
        by: PrincipalId,
        /// Why.
        reason: DeleteReason,
    },
}

impl VersionState {
    /// Whether the version is hidden at instant `t` given this state.
    pub fn hidden_at(&self, t: Ts) -> bool {
        match self {
            VersionState::Live => false,
            VersionState::Superseded { at } | VersionState::SoftDeleted { at, .. } => *at <= t,
        }
    }

    /// When it left the Live state.
    pub fn hidden_since(&self) -> Option<Ts> {
        match self {
            VersionState::Live => None,
            VersionState::Superseded { at } | VersionState::SoftDeleted { at, .. } => Some(*at),
        }
    }
}

pub use cairn_core::ChecksumAlgo;

/// A stored checksum value (base64 of the big-endian digest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredChecksum {
    /// Algorithm.
    pub algo: ChecksumAlgo,
    /// Base64 value; composite values carry a `-N` suffix.
    pub value: String,
    /// Whether this is a composite (checksum-of-checksums) value.
    pub composite: bool,
}

/// Server-side encryption applied to the object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Sse {
    /// None requested (blobs may still be encrypted at rest).
    #[default]
    None,
    /// SSE-S3.
    S3,
    /// SSE-KMS with a named internal key.
    Kms {
        /// Key id.
        key_id: String,
    },
    /// SSE-C.
    C {
        /// MD5 of the customer key (base64).
        key_md5: String,
    },
}

/// One stored part of an object body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartRef {
    /// Part number (1 for simple PUT).
    pub number: u32,
    /// Blob holding the bytes.
    pub blob: BlobId,
    /// Size in bytes.
    pub size: u64,
    /// Offset of this part within the object.
    pub offset: u64,
    /// Hex MD5 of the part.
    pub etag: String,
    /// Part checksum (base64), if one was requested.
    pub checksum: Option<String>,
}

/// Object payload and HTTP metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ObjectBody {
    /// Total size.
    pub size: u64,
    /// ETag without quotes (`hex` or `hex-N`).
    pub etag: String,
    /// Optional `x-amz-checksum-*`.
    pub checksum: Option<StoredChecksum>,
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
    /// Expires (raw header value).
    pub expires: Option<String>,
    /// `x-amz-meta-*` (lowercased names, without prefix).
    pub user_metadata: BTreeMap<String, String>,
    /// Object tags.
    pub tags: BTreeMap<String, String>,
    /// Storage class (accepted; single class).
    pub storage_class: Option<String>,
    /// SSE mode.
    pub sse: Sse,
    /// Website redirect location.
    pub website_redirect: Option<String>,
    /// Parts in order.
    pub parts: Vec<PartRef>,
}

/// Version payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VersionKind {
    /// Object data.
    Object(Box<ObjectBody>),
    /// Delete marker.
    DeleteMarker,
}

/// Object Lock retention on a version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockRetention {
    /// `true` = Compliance, `false` = Governance.
    pub compliance: bool,
    /// Retain until.
    pub retain_until: Ts,
}

/// One version of a key (`versions` table; inlined in `latest`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRecord {
    /// Key.
    pub key: String,
    /// Internal version id.
    pub version_id: VersionId,
    /// Creation time (equals `version_id.created_at()`).
    pub created_at: Ts,
    /// Written while versioning was Off/Suspended: S3 calls it `null`.
    pub is_null: bool,
    /// Payload.
    pub kind: VersionKind,
    /// Visibility.
    pub state: VersionState,
    /// Object Lock retention.
    pub lock: Option<LockRetention>,
    /// Legal hold.
    pub legal_hold: bool,
    /// Writer.
    pub owner: PrincipalId,
}

impl VersionRecord {
    /// Object body if not a delete marker.
    pub fn body(&self) -> Option<&ObjectBody> {
        match &self.kind {
            VersionKind::Object(b) => Some(b),
            VersionKind::DeleteMarker => None,
        }
    }

    /// Whether this is a delete marker.
    pub fn is_delete_marker(&self) -> bool {
        matches!(self.kind, VersionKind::DeleteMarker)
    }

    /// Whether the version is S3-visible.
    pub fn is_live(&self) -> bool {
        self.state == VersionState::Live
    }

    /// Blobs referenced by this version.
    pub fn blobs(&self) -> Vec<BlobId> {
        self.body()
            .map(|b| b.parts.iter().map(|p| p.blob).collect())
            .unwrap_or_default()
    }
}

/// An in-progress multipart upload (`uploads`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultipartRecord {
    /// Upload id (uuid v7 string).
    pub upload_id: String,
    /// Bucket.
    pub bucket: BucketId,
    /// Key.
    pub key: String,
    /// Initiated.
    pub initiated_at: Ts,
    /// Initiator.
    pub owner: PrincipalId,
    /// Metadata applied on completion (parts empty).
    pub template: ObjectBody,
    /// Checksum algorithm requested at create time.
    pub checksum_algo: Option<ChecksumAlgo>,
    /// Uploaded parts by number.
    pub parts: BTreeMap<u32, PartRef>,
}

/// Blob reference count (`blobs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRef {
    /// Number of versions/uploads referencing the blob.
    pub refcount: u32,
    /// Plaintext size.
    pub size: u64,
    /// When the refcount last dropped to zero.
    pub last_unref_at: Option<Ts>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_version_byte() {
        let v = VersionRecord {
            key: "a/b".into(),
            version_id: VersionId::new(Ts(5)),
            created_at: Ts(5),
            is_null: true,
            kind: VersionKind::Object(Box::new(ObjectBody {
                size: 3,
                etag: "abc".into(),
                ..Default::default()
            })),
            state: VersionState::SoftDeleted {
                at: Ts(9),
                by: PrincipalId::root(),
                reason: DeleteReason::Api,
            },
            lock: None,
            legal_hold: false,
            owner: PrincipalId::root(),
        };
        let b = encode(&v);
        assert_eq!(b[0], SCHEMA_VERSION);
        assert_eq!(decode::<VersionRecord>(&b).unwrap(), v);
        let mut bad = b.clone();
        bad[0] = 99;
        assert!(decode::<VersionRecord>(&bad).is_err());
    }
}
