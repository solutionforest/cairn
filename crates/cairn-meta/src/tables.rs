//! Table definitions and typed accessors.

use crate::MetaError;
use crate::keys;
use crate::records::*;
use crate::store::{Flow, Reader, WriteTxn};
use cairn_core::{BlobId, BucketId, Ts, VersionId};
use redb::TableDefinition;

macro_rules! tables {
    ($($v:ident => $name:literal),* $(,)?) => {
        /// Every metadata table (all `&[u8] -> &[u8]`).
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Table { $(#[doc = $name] $v,)* }
        impl Table {
            /// All tables, created at open.
            pub const ALL: &'static [Table] = &[$(Table::$v,)*];
            /// redb definition.
            pub fn def(self) -> TableDefinition<'static, &'static [u8], &'static [u8]> {
                match self { $(Table::$v => TableDefinition::new($name),)* }
            }
        }
    };
}

tables! {
    Buckets => "buckets",
    BucketMeta => "bucket_meta",
    BucketHistory => "bucket_history",
    Versions => "versions",
    Latest => "latest",
    Uploads => "uploads",
    UploadsByKey => "uploads_by_key",
    Blobs => "blobs",
    BlobGcIdx => "blob_gc_idx",
    TrashIdx => "trash_idx",
    BucketTrashIdx => "bucket_trash_idx",
    LifecycleIdx => "lifecycle_idx",
    Principals => "principals",
    AccessKeys => "access_keys",
    Policies => "policies",
    Sessions => "sessions",
    EventsQueue => "events_queue",
    ReplCursor => "repl_cursor",
    Audit => "audit",
    Kv => "kv",
}

/// Typed read helpers available on both read and write transactions.
pub trait ReadExt: Reader {
    /// Active bucket id by name.
    fn bucket_id(&self, name: &str) -> Result<Option<BucketId>, MetaError> {
        Ok(self
            .get(Table::Buckets, name.as_bytes())?
            .and_then(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
            .map(BucketId::from_bytes))
    }

    /// Bucket record by id.
    fn bucket(&self, id: BucketId) -> Result<Option<BucketRecord>, MetaError> {
        self.get(Table::BucketMeta, &id.to_bytes())?
            .map(|b| decode(&b))
            .transpose()
    }

    /// Active bucket record by name.
    fn bucket_by_name(&self, name: &str) -> Result<Option<BucketRecord>, MetaError> {
        match self.bucket_id(name)? {
            Some(id) => self.bucket(id),
            None => Ok(None),
        }
    }

    /// All active buckets ordered by name.
    fn active_buckets(&self) -> Result<Vec<BucketRecord>, MetaError> {
        let mut ids = Vec::new();
        self.scan(
            Table::Buckets,
            std::ops::Bound::Unbounded,
            std::ops::Bound::Unbounded,
            &mut |_, v| {
                if let Ok(a) = <[u8; 16]>::try_from(v) {
                    ids.push(BucketId::from_bytes(a));
                }
                Ok(Flow::Continue)
            },
        )?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(b) = self.bucket(id)? {
                out.push(b);
            }
        }
        Ok(out)
    }

    /// One version.
    fn version(
        &self,
        b: BucketId,
        key: &str,
        vid: &VersionId,
    ) -> Result<Option<VersionRecord>, MetaError> {
        self.get(Table::Versions, &keys::version_key(b, key, vid))?
            .map(|v| decode(&v))
            .transpose()
    }

    /// The S3-visible head of a key (may be a delete marker).
    fn latest(&self, b: BucketId, key: &str) -> Result<Option<VersionRecord>, MetaError> {
        self.get(Table::Latest, &keys::bucket_key(b, key))?
            .map(|v| decode(&v))
            .transpose()
    }

    /// All versions of a key, newest first (every state).
    fn versions_of(&self, b: BucketId, key: &str) -> Result<Vec<VersionRecord>, MetaError> {
        let mut out = Vec::new();
        self.scan_prefix(Table::Versions, &keys::versions_of(b, key), &mut |_, v| {
            out.push(decode(v)?);
            Ok(Flow::Continue)
        })?;
        Ok(out)
    }

    /// Newest Live version of a key (what `latest` must hold).
    fn newest_live(&self, b: BucketId, key: &str) -> Result<Option<VersionRecord>, MetaError> {
        let mut found = None;
        self.scan_prefix(Table::Versions, &keys::versions_of(b, key), &mut |_, v| {
            let r: VersionRecord = decode(v)?;
            if r.is_live() {
                found = Some(r);
                return Ok(Flow::Stop);
            }
            Ok(Flow::Continue)
        })?;
        Ok(found)
    }

    /// The version S3 calls `null` for this key, if any (in any state).
    fn null_version(
        &self,
        b: BucketId,
        key: &str,
        include_hidden: bool,
    ) -> Result<Option<VersionRecord>, MetaError> {
        let mut found = None;
        self.scan_prefix(Table::Versions, &keys::versions_of(b, key), &mut |_, v| {
            let r: VersionRecord = decode(v)?;
            if r.is_null && (include_hidden || r.is_live()) {
                found = Some(r);
                return Ok(Flow::Stop);
            }
            Ok(Flow::Continue)
        })?;
        Ok(found)
    }

    /// Whether any S3-visible version (object or delete marker) exists in the bucket.
    /// `latest` holds the newest Live version of every key, so it is non-empty iff one exists.
    fn bucket_has_live_entries(&self, b: BucketId) -> Result<bool, MetaError> {
        let mut any = false;
        self.scan_prefix(Table::Latest, &b.to_bytes(), &mut |_, _| {
            any = true;
            Ok(Flow::Stop)
        })?;
        Ok(any)
    }

    /// Multipart upload record.
    fn upload(&self, b: BucketId, upload_id: &str) -> Result<Option<MultipartRecord>, MetaError> {
        self.get(Table::Uploads, &keys::upload_key(b, upload_id))?
            .map(|v| decode(&v))
            .transpose()
    }

    /// Blob refcount record.
    fn blob_ref(&self, id: &BlobId) -> Result<Option<BlobRef>, MetaError> {
        self.get(Table::Blobs, id.as_bytes())?
            .map(|v| decode(&v))
            .transpose()
    }
}

impl<R: Reader + ?Sized> ReadExt for R {}

impl WriteTxn {
    /// Insert/replace a bucket record and append it to `bucket_history`.
    pub fn put_bucket(&self, b: &BucketRecord) -> Result<(), MetaError> {
        let enc = encode(b);
        self.put(Table::BucketMeta, &b.id.to_bytes(), &enc)?;
        self.put(
            Table::BucketHistory,
            &keys::bucket_history_key(b.id, b.config_seq),
            &enc,
        )
    }

    /// Point a name at a bucket id.
    pub fn bind_bucket_name(&self, name: &str, id: BucketId) -> Result<(), MetaError> {
        self.put(Table::Buckets, name.as_bytes(), &id.to_bytes())
    }

    /// Release a bucket name.
    pub fn unbind_bucket_name(&self, name: &str) -> Result<(), MetaError> {
        self.del(Table::Buckets, name.as_bytes()).map(|_| ())
    }

    /// Insert/replace a version record (does not touch `latest`; call [`Self::refresh_latest`]).
    pub fn put_version(&self, b: BucketId, v: &VersionRecord) -> Result<(), MetaError> {
        self.put(
            Table::Versions,
            &keys::version_key(b, &v.key, &v.version_id),
            &encode(v),
        )
    }

    /// Delete a version row.
    pub fn del_version(&self, b: BucketId, key: &str, vid: &VersionId) -> Result<(), MetaError> {
        self.del(Table::Versions, &keys::version_key(b, key, vid))
            .map(|_| ())
    }

    /// Recompute `latest` for a key from `versions` (newest Live version, or absent).
    pub fn refresh_latest(
        &self,
        b: BucketId,
        key: &str,
    ) -> Result<Option<VersionRecord>, MetaError> {
        let head = self.newest_live(b, key)?;
        let k = keys::bucket_key(b, key);
        match &head {
            Some(v) => self.put(Table::Latest, &k, &encode(v))?,
            None => {
                self.del(Table::Latest, &k)?;
            }
        }
        Ok(head)
    }

    /// Add a version to the trash index.
    pub fn trash_add(
        &self,
        expires: Ts,
        b: BucketId,
        key: &str,
        vid: &VersionId,
    ) -> Result<(), MetaError> {
        self.put(Table::TrashIdx, &keys::trash_key(expires, b, key, vid), &[])
    }

    /// Remove a version from the trash index.
    pub fn trash_remove(
        &self,
        expires: Ts,
        b: BucketId,
        key: &str,
        vid: &VersionId,
    ) -> Result<(), MetaError> {
        self.del(Table::TrashIdx, &keys::trash_key(expires, b, key, vid))
            .map(|_| ())
    }

    /// Insert/replace a multipart upload and its by-key index.
    pub fn put_upload(&self, u: &MultipartRecord) -> Result<(), MetaError> {
        self.put(
            Table::Uploads,
            &keys::upload_key(u.bucket, &u.upload_id),
            &encode(u),
        )?;
        self.put(
            Table::UploadsByKey,
            &keys::upload_by_key(u.bucket, &u.key, &u.upload_id),
            &[],
        )
    }

    /// Remove a multipart upload.
    pub fn del_upload(&self, u: &MultipartRecord) -> Result<(), MetaError> {
        self.del(Table::Uploads, &keys::upload_key(u.bucket, &u.upload_id))?;
        self.del(
            Table::UploadsByKey,
            &keys::upload_by_key(u.bucket, &u.key, &u.upload_id),
        )
        .map(|_| ())
    }

    /// Increment a blob's refcount (creating the record). Returns the previous record.
    pub fn blob_incref(&self, id: &BlobId, size: u64) -> Result<Option<BlobRef>, MetaError> {
        let prev = self.blob_ref(id)?;
        let mut r = prev.unwrap_or(BlobRef {
            refcount: 0,
            size,
            last_unref_at: None,
        });
        if let Some(at) = r.last_unref_at.take() {
            self.del(Table::BlobGcIdx, &keys::blob_gc_key(at, id))?;
        }
        r.refcount = r.refcount.saturating_add(1);
        self.put(Table::Blobs, id.as_bytes(), &encode(&r))?;
        Ok(prev)
    }

    /// Decrement a blob's refcount; at zero it enters the GC index stamped `now`.
    pub fn blob_decref(&self, id: &BlobId, now: Ts) -> Result<(), MetaError> {
        let Some(mut r) = self.blob_ref(id)? else {
            return Ok(());
        };
        r.refcount = r.refcount.saturating_sub(1);
        if r.refcount == 0 && r.last_unref_at.is_none() {
            r.last_unref_at = Some(now);
            self.put(Table::BlobGcIdx, &keys::blob_gc_key(now, id), &[])?;
        }
        self.put(Table::Blobs, id.as_bytes(), &encode(&r))
    }

    /// Forget a blob entirely (after its file was unlinked).
    pub fn blob_forget(&self, id: &BlobId) -> Result<(), MetaError> {
        if let Some(r) = self.blob_ref(id)?
            && let Some(at) = r.last_unref_at
        {
            self.del(Table::BlobGcIdx, &keys::blob_gc_key(at, id))?;
        }
        self.del(Table::Blobs, id.as_bytes()).map(|_| ())
    }
}
