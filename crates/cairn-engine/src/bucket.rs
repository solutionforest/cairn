//! Bucket operations.

use crate::commit::{active_bucket, retention};
use crate::{CairnEngine, resolve_bucket};
use cairn_core::{BucketId, BucketName, PrincipalId, S3Error, S3ErrorCode, S3Result, Ts};
use cairn_meta::{
    BucketRecord, BucketState, Flow, ReadExt, Reader, RetentionPolicy, Table, Versioning, decode,
    keys,
};
use std::collections::BTreeMap;

impl CairnEngine {
    /// CreateBucket.
    pub async fn create_bucket(
        &self,
        name: &str,
        owner: &PrincipalId,
        object_lock: bool,
        location: Option<String>,
    ) -> S3Result<BucketRecord> {
        BucketName::try_from(name)?;
        let rec = BucketRecord {
            id: BucketId::random(),
            name: name.to_string(),
            created_at: Ts::now(),
            owner: owner.clone(),
            versioning: if object_lock {
                Versioning::Enabled
            } else {
                Versioning::Off
            },
            object_lock_enabled: object_lock,
            retention: RetentionPolicy::default(),
            tags: BTreeMap::new(),
            location,
            configs: BTreeMap::new(),
            state: BucketState::Active,
            config_seq: 0,
        };
        let owner = owner.clone();
        self.inner
            .meta
            .write(move |txn| {
                if let Some(existing) = txn.bucket_by_name(&rec.name)? {
                    let code = if existing.owner == owner {
                        S3ErrorCode::BucketAlreadyOwnedByYou
                    } else {
                        S3ErrorCode::BucketAlreadyExists
                    };
                    return Err(S3Error::code(code).with_resource(rec.name.clone()));
                }
                txn.put_bucket(&rec)?;
                txn.bind_bucket_name(&rec.name, rec.id)?;
                Ok(rec.clone())
            })
            .await
    }

    /// HeadBucket.
    pub fn head_bucket(&self, name: &str) -> S3Result<BucketRecord> {
        self.bucket(name)
    }

    /// ListBuckets (active only, by name).
    pub fn list_buckets(&self) -> S3Result<Vec<BucketRecord>> {
        Ok(self.read()?.active_buckets()?)
    }

    /// DeleteBucket: must be empty; the bucket moves to Trashed and its name is released.
    /// In-progress multipart uploads are aborted.
    pub async fn delete_bucket(&self, name: &str, by: &PrincipalId) -> S3Result<()> {
        let b = self.bucket(name)?;
        let (id, name, by) = (b.id, name.to_string(), by.clone());
        let soft = retention(&b, &self.inner.cfg).0;
        self.inner
            .meta
            .write(move |txn| {
                let mut b = active_bucket(txn, id, &name)?;
                if txn.bucket_has_live_entries(id)? {
                    return Err(
                        S3Error::code(S3ErrorCode::BucketNotEmpty).with_resource(name.clone())
                    );
                }
                let now = Ts::now();
                let mut uploads = Vec::new();
                txn.scan_prefix(Table::Uploads, &id.to_bytes(), &mut |_, v| {
                    uploads.push(decode::<cairn_meta::MultipartRecord>(v)?);
                    Ok(Flow::Continue)
                })?;
                for u in &uploads {
                    for p in u.parts.values() {
                        txn.blob_decref(&p.blob, now)?;
                    }
                    txn.del_upload(u)?;
                }
                b.state = BucketState::Trashed {
                    at: now,
                    by: by.clone(),
                };
                b.config_seq += 1;
                txn.put_bucket(&b)?;
                txn.unbind_bucket_name(&name)?;
                let mut k = keys::ts_bytes(now.plus(soft)).to_vec();
                k.extend_from_slice(&id.to_bytes());
                txn.put(Table::BucketTrashIdx, &k, &[])?;
                Ok(())
            })
            .await
    }

    async fn update_bucket(
        &self,
        name: &str,
        f: impl Fn(&mut BucketRecord) -> S3Result<()> + Send + Sync + 'static,
    ) -> S3Result<BucketRecord> {
        let id = self.bucket(name)?.id;
        let name = name.to_string();
        self.inner
            .meta
            .write(move |txn| {
                let mut b = active_bucket(txn, id, &name)?;
                f(&mut b)?;
                b.config_seq += 1;
                txn.put_bucket(&b)?;
                Ok(b)
            })
            .await
    }

    /// PutBucketVersioning (`Enabled` / `Suspended`).
    pub async fn put_bucket_versioning(&self, name: &str, enabled: bool) -> S3Result<()> {
        self.update_bucket(name, move |b| {
            if !enabled && b.object_lock_enabled {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidBucketState,
                    "An Object Lock configuration is present on this bucket, so the versioning state cannot be changed.",
                ));
            }
            b.versioning = if enabled { Versioning::Enabled } else { Versioning::Suspended };
            Ok(())
        })
        .await
        .map(|_| ())
    }

    /// GetBucketVersioning.
    pub fn get_bucket_versioning(&self, name: &str) -> S3Result<Versioning> {
        Ok(self.bucket(name)?.versioning)
    }

    /// PutBucketTagging.
    pub async fn put_bucket_tagging(
        &self,
        name: &str,
        tags: BTreeMap<String, String>,
    ) -> S3Result<()> {
        crate::util::validate_tags(&tags, 50)?;
        self.update_bucket(name, move |b| {
            b.tags = tags.clone();
            Ok(())
        })
        .await
        .map(|_| ())
    }

    /// GetBucketTagging (`NoSuchTagSet` when empty).
    pub fn get_bucket_tagging(&self, name: &str) -> S3Result<BTreeMap<String, String>> {
        let b = self.bucket(name)?;
        if b.tags.is_empty() {
            return Err(S3Error::code(S3ErrorCode::NoSuchTagSet));
        }
        Ok(b.tags)
    }

    /// DeleteBucketTagging.
    pub async fn delete_bucket_tagging(&self, name: &str) -> S3Result<()> {
        self.update_bucket(name, |b| {
            b.tags.clear();
            Ok(())
        })
        .await
        .map(|_| ())
    }

    /// Store an opaque bucket configuration document (phase 2 APIs build on this).
    pub async fn put_bucket_config(
        &self,
        name: &str,
        kind: &str,
        doc: Option<Vec<u8>>,
    ) -> S3Result<()> {
        let kind = kind.to_string();
        self.update_bucket(name, move |b| {
            match &doc {
                Some(d) => b.configs.insert(kind.clone(), d.clone()),
                None => b.configs.remove(&kind),
            };
            Ok(())
        })
        .await
        .map(|_| ())
    }

    /// Override retention windows for a bucket (`None` = server default).
    pub async fn set_bucket_retention(&self, name: &str, policy: RetentionPolicy) -> S3Result<()> {
        self.update_bucket(name, move |b| {
            b.retention = policy.clone();
            Ok(())
        })
        .await
        .map(|_| ())
    }

    /// Trashed buckets (most recent first).
    pub fn trashed_buckets(&self) -> S3Result<Vec<BucketRecord>> {
        let r = self.read()?;
        let mut out = Vec::new();
        r.scan(
            Table::BucketMeta,
            std::ops::Bound::Unbounded,
            std::ops::Bound::Unbounded,
            &mut |_, v| {
                let b: BucketRecord = decode(v)?;
                if matches!(b.state, BucketState::Trashed { .. }) {
                    out.push(b);
                }
                Ok(Flow::Continue)
            },
        )?;
        out.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        Ok(out)
    }

    /// Restore a trashed bucket under its old name or `as_name`.
    pub async fn restore_bucket(
        &self,
        id: BucketId,
        as_name: Option<String>,
    ) -> S3Result<BucketRecord> {
        self.inner
            .meta
            .write(move |txn| {
                let mut b = txn
                    .bucket(id)?
                    .ok_or_else(|| S3Error::code(S3ErrorCode::NoSuchBucket))?;
                if !matches!(b.state, BucketState::Trashed { .. }) {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidBucketState,
                        "bucket is not in the trash",
                    ));
                }
                let name = as_name.clone().unwrap_or_else(|| b.name.clone());
                BucketName::try_from(name.as_str())?;
                if txn.bucket_id(&name)?.is_some() {
                    return Err(S3Error::code(S3ErrorCode::BucketAlreadyExists).with_resource(name));
                }
                let mut stale = Vec::new();
                txn.scan(
                    Table::BucketTrashIdx,
                    std::ops::Bound::Unbounded,
                    std::ops::Bound::Unbounded,
                    &mut |k, _| {
                        if k.len() == 32 && k[16..] == id.to_bytes() {
                            stale.push(k.to_vec());
                        }
                        Ok(Flow::Continue)
                    },
                )?;
                for k in stale {
                    txn.del(Table::BucketTrashIdx, &k)?;
                }
                b.name = name.clone();
                b.state = BucketState::Active;
                b.config_seq += 1;
                txn.put_bucket(&b)?;
                txn.bind_bucket_name(&name, id)?;
                Ok::<_, S3Error>(b)
            })
            .await
    }

    /// Bucket record as of a config sequence (bucket configuration history).
    pub fn bucket_history(&self, name: &str) -> S3Result<Vec<BucketRecord>> {
        let b = resolve_bucket(&self.read()?, name)?;
        let r = self.read()?;
        let mut out = Vec::new();
        r.scan_prefix(Table::BucketHistory, &b.id.to_bytes(), &mut |_, v| {
            out.push(decode(v)?);
            Ok(Flow::Continue)
        })?;
        Ok(out)
    }
}
