//! Object operations: put/get/head/delete/copy/tagging.

use crate::commit::{
    active_bucket, check_lock, commit_replica, commit_version, now_for_key, soft_delete,
};
use crate::types::*;
use crate::util::*;
use crate::{CairnEngine, resolve_bucket};
use cairn_blob::{BlobDigest, BlobStore, WriteOpts};
use cairn_core::{ChecksumAlgo, ObjectKey, PrincipalId, S3Error, S3ErrorCode, S3Result, VersionId};
use cairn_events::EventName;
use cairn_meta::{
    ObjectBody, PartRef, ReadExt, StoredChecksum, VersionKind, VersionRecord, Versioning, pitr,
};
use futures::StreamExt;
use std::collections::BTreeMap;
use tokio::io::AsyncWriteExt;

/// Ingested payload.
pub(crate) struct Ingested {
    pub digest: BlobDigest,
    pub checksum: Option<(ChecksumAlgo, String)>,
}

pub(crate) fn delete_marker_err(
    code: S3ErrorCode,
    v: &VersionRecord,
    versioning: Versioning,
) -> S3Error {
    let mut e = S3Error::code(code).with_header("x-amz-delete-marker", "true");
    if let Some(id) = s3_version_id(v, versioning) {
        e = e.with_header("x-amz-version-id", id);
    }
    e
}

impl CairnEngine {
    /// Stream a body into a new blob, verifying length, Content-MD5 and checksum.
    pub(crate) async fn ingest(
        &self,
        mut body: Body,
        content_length: Option<u64>,
        max: u64,
        content_md5: Option<&str>,
        checksum: ChecksumInput,
    ) -> S3Result<Ingested> {
        if content_length.is_some_and(|n| n > max) {
            return Err(S3Error::code(S3ErrorCode::EntityTooLarge));
        }
        if let Some(g) = &self.inner.space {
            g.check(content_length.unwrap_or(0))?;
        }
        let algo = checksum.algo();
        let opts = WriteOpts {
            sha256: false,
            checksum: algo,
            key: self.inner.cfg.at_rest_key.clone(),
        };
        let mut w = self.inner.blobs.begin_write(opts).await?;
        let mut n = 0u64;
        while let Some(chunk) = body.next().await {
            let c = chunk?;
            n += c.len() as u64;
            if n > max {
                return Err(S3Error::code(S3ErrorCode::EntityTooLarge));
            }
            if let Err(e) = w.write_all(&c).await {
                if cairn_blob::space::is_enospc(&e) {
                    return Err(cairn_blob::space::StorageFull {
                        available: 0,
                        reserve: 0,
                        needed: content_length.unwrap_or(0),
                    }
                    .into());
                }
                return Err(e.into());
            }
            failpoint!("ingest.mid_body");
        }
        if content_length.is_some_and(|cl| cl != n) {
            return Err(S3Error::code(S3ErrorCode::IncompleteBody));
        }
        let digest = w.finish().await?;
        let verdict = (|| {
            if let Some(m) = content_md5 {
                let want = unb64(m).ok_or_else(|| S3Error::code(S3ErrorCode::InvalidDigest))?;
                if want != digest.md5 {
                    return Err(S3Error::code(S3ErrorCode::BadDigest));
                }
            }
            let computed = digest
                .checksum
                .as_ref()
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            match checksum {
                ChecksumInput::Value(a, v) => verify_checksum(a, &computed, &v)?,
                ChecksumInput::Trailer(a, late) => {
                    if let Some(v) = late() {
                        verify_checksum(a, &computed, &v)?;
                    }
                }
                _ => {}
            }
            Ok(())
        })();
        if let Err(e) = verdict {
            self.discard_blob(digest.blob_id).await;
            return Err(e);
        }
        let checksum = digest.checksum.as_ref().map(|(a, v)| (*a, b64(v)));
        Ok(Ingested { digest, checksum })
    }

    /// Remove a just-written blob if nothing references it (serialised with GC on the writer).
    pub(crate) async fn discard_blob(&self, id: cairn_core::BlobId) {
        let blobs = self.inner.blobs.clone();
        let _ = self
            .inner
            .meta
            .write(move |txn| -> Result<(), cairn_meta::MetaError> {
                if txn.blob_ref(&id)?.is_none() {
                    crate::commit::unlink_blob(&blobs, &id);
                }
                Ok(())
            })
            .await;
    }

    /// PutObject.
    pub async fn put_object(&self, req: PutObjectReq) -> S3Result<PutObjectRes> {
        self.put_object_with(req, None).await
    }

    /// PutObject writing a replica with the given version id (`x-cairn-version-id`).
    pub async fn put_object_replica(
        &self,
        req: PutObjectReq,
        version_id: VersionId,
    ) -> S3Result<PutObjectRes> {
        self.put_object_with(req, Some(version_id)).await
    }

    async fn put_object_with(
        &self,
        req: PutObjectReq,
        replica: Option<VersionId>,
    ) -> S3Result<PutObjectRes> {
        ObjectKey::try_from(req.key.as_str())?;
        validate_tags(&req.tags, 10)?;
        let bucket = self.bucket(&req.bucket)?;
        if req.conditions.if_none_match.as_deref() == Some("*")
            && self
                .read()?
                .latest(bucket.id, &req.key)?
                .is_some_and(|v| !v.is_delete_marker())
        {
            return Err(S3Error::code(S3ErrorCode::PreconditionFailed));
        }
        let max = self.inner.cfg.limits.max_object_size;
        let ing = self
            .ingest(
                req.body,
                req.content_length,
                max,
                req.content_md5.as_deref(),
                req.checksum,
            )
            .await?;
        failpoint!("put.blob_placed");
        let body = ObjectBody {
            size: ing.digest.size,
            etag: hex::encode(ing.digest.md5),
            checksum: ing.checksum.as_ref().map(|(a, v)| StoredChecksum {
                algo: *a,
                value: v.clone(),
                composite: false,
            }),
            content_type: req.meta.content_type,
            cache_control: req.meta.cache_control,
            content_disposition: req.meta.content_disposition,
            content_encoding: req.meta.content_encoding,
            content_language: req.meta.content_language,
            expires: req.meta.expires,
            user_metadata: req.meta.user_metadata,
            tags: req.tags,
            storage_class: req.meta.storage_class,
            sse: Default::default(),
            website_redirect: req.meta.website_redirect,
            parts: vec![PartRef {
                number: 1,
                blob: ing.digest.blob_id,
                size: ing.digest.size,
                offset: 0,
                etag: hex::encode(ing.digest.md5),
                checksum: ing.checksum.as_ref().map(|(_, v)| v.clone()),
            }],
        };
        let res = self
            .commit_object(
                bucket.id,
                &req.bucket,
                &req.key,
                body,
                &req.owner,
                req.conditions,
                EventName::ObjectCreatedPut,
                replica,
            )
            .await;
        if res.is_err() && !ing.digest.deduped {
            self.discard_blob(ing.digest.blob_id).await;
        }
        res
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn commit_object(
        &self,
        bucket_id: cairn_core::BucketId,
        bucket_name: &str,
        key: &str,
        body: ObjectBody,
        owner: &PrincipalId,
        conds: WriteConditions,
        ev: EventName,
        replica: Option<VersionId>,
    ) -> S3Result<PutObjectRes> {
        let inner = self.inner.clone();
        let em = self.emitter(owner);
        let (bn, k, o) = (bucket_name.to_string(), key.to_string(), owner.clone());
        let (v, b) = self
            .inner
            .meta
            .write(move |txn| {
                let kind = VersionKind::Object(Box::new(body.clone()));
                if let Some(vid) = replica {
                    let (v, b) =
                        commit_replica(txn, &inner.blobs, bucket_id, &bn, &k, kind, &o, vid)?;
                    return match v {
                        Some(v) => {
                            em.emit(txn, &b, ev, &k, Some(&v), Vec::new())?;
                            Ok((v, b))
                        }
                        None => {
                            let v = txn
                                .version(bucket_id, &k, &vid)?
                                .ok_or_else(|| S3Error::code(S3ErrorCode::InternalError))?;
                            Ok((v, b))
                        }
                    };
                }
                let (v, b) = commit_version(
                    txn,
                    &inner.blobs,
                    &inner.cfg,
                    bucket_id,
                    &bn,
                    &k,
                    kind,
                    &o,
                    &conds,
                )?;
                em.emit(txn, &b, ev, &k, Some(&v), Vec::new())?;
                failpoint!("put.in_txn");
                Ok::<_, S3Error>((v, b))
            })
            .await?;
        failpoint!("put.committed");
        self.notify();
        let body = v.body().expect("object version");
        Ok(PutObjectRes {
            etag: body.etag.clone(),
            version_id: s3_version_id(&v, b.versioning),
            checksum: body.checksum.as_ref().map(|c| (c.algo, c.value.clone())),
            size: body.size,
            version: v,
        })
    }

    fn resolve_read(&self, req: &GetObjectReq) -> S3Result<(VersionRecord, Versioning)> {
        let r = self.read()?;
        let bucket = resolve_bucket(&r, &req.bucket)?;
        let vg = bucket.versioning;
        let v = if let Some(vid) = &req.version_id {
            let v = resolve_version(&r, bucket.id, &req.key, vid)?;
            if v.is_delete_marker() {
                return Err(
                    delete_marker_err(S3ErrorCode::MethodNotAllowed, &v, vg).with_header(
                        "last-modified",
                        v.created_at
                            .to_jiff()
                            .strftime("%a, %d %b %Y %H:%M:%S GMT")
                            .to_string(),
                    ),
                );
            }
            v
        } else {
            let head = match req.as_of {
                Some(at) => pitr::visible_at(&r, bucket.id, &req.key, at)?,
                None => r.latest(bucket.id, &req.key)?,
            };
            match head {
                None => {
                    return Err(
                        S3Error::code(S3ErrorCode::NoSuchKey).with_resource(req.key.clone())
                    );
                }
                Some(v) if v.is_delete_marker() => {
                    return Err(delete_marker_err(S3ErrorCode::NoSuchKey, &v, vg));
                }
                Some(v) => v,
            }
        };
        if crate::fsck::version_damage(&r, bucket.id, &v)?.is_some() {
            return Err(crate::fsck::damaged_error(&req.key));
        }
        Ok((v, vg))
    }

    /// GetObject (`with_body = true`) or HeadObject.
    pub async fn get_object(&self, req: GetObjectReq, with_body: bool) -> S3Result<GetObjectRes> {
        let (v, vg) = self.resolve_read(&req)?;
        let body = v.body().expect("not a delete marker").clone();
        check_read_conditions(&req.conditions, &body.etag, v.created_at)?;
        let mut parts_count = (body.parts.len() > 1).then_some(body.parts.len() as u32);
        let range = match (req.part_number, req.range) {
            (Some(_), Some(_)) => {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    "Cannot specify both Range header and partNumber query parameter",
                ));
            }
            (Some(n), None) => {
                let p = body
                    .parts
                    .get((n as usize).wrapping_sub(1))
                    .ok_or_else(|| S3Error::code(S3ErrorCode::InvalidPartNumber))?;
                parts_count = Some(body.parts.len() as u32);
                (body.parts.len() > 1 || n != 1).then_some((p.offset, p.offset + p.size))
            }
            (None, Some(r)) => Some(resolve_range(r, body.size)?),
            (None, None) => None,
        };
        let (start, end) = range.unwrap_or((0, body.size));
        if with_body {
            for p in &body.parts {
                if p.offset + p.size > start
                    && p.offset < end
                    && !self.inner.blobs.exists(&p.blob).await
                {
                    tracing::error!(key = %req.key, blob = %p.blob.to_hex(), "GET of a version whose blob is missing");
                    return Err(crate::fsck::damaged_error(&req.key));
                }
            }
        }
        let stream = if with_body {
            Some(self.stream_object(&body, start, end))
        } else {
            None
        };
        Ok(GetObjectRes {
            version_id: s3_version_id(&v, vg),
            version: v,
            body: stream,
            range,
            content_length: end - start,
            size: body.size,
            parts_count,
        })
    }

    /// Stream `start..end` of an object across its parts.
    pub(crate) fn stream_object(&self, body: &ObjectBody, start: u64, end: u64) -> BodyStream {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let parts: Vec<PartRef> = body.parts.clone();
        let blobs = self.inner.blobs.clone();
        let key = self.inner.cfg.at_rest_key.clone();
        tokio::spawn(async move {
            for p in parts {
                let (ps, pe) = (p.offset, p.offset + p.size);
                if pe <= start || ps >= end {
                    continue;
                }
                let local = start.max(ps) - ps..end.min(pe) - ps;
                // A whole-blob read is checked against its BLAKE3 id; the last chunk is held
                // back until the hash matches, so a damaged blob never streams to completion.
                let mut hasher =
                    (local.start == 0 && local.end == p.size).then(blake3::Hasher::new);
                let mut rd = match blobs.open(&p.blob, local, key.as_ref()).await {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx.send(Err(std::io::Error::other(e.to_string()))).await;
                        return;
                    }
                };
                let mut held: Option<bytes::Bytes> = None;
                while let Some(item) = rd.next().await {
                    let chunk = match item {
                        Ok(c) => c,
                        Err(e) => {
                            let _ = tx.send(Err(e)).await;
                            return;
                        }
                    };
                    let Some(h) = hasher.as_mut() else {
                        if tx.send(Ok(chunk)).await.is_err() {
                            return;
                        }
                        continue;
                    };
                    h.update(&chunk);
                    if let Some(prev) = held.replace(chunk)
                        && tx.send(Ok(prev)).await.is_err()
                    {
                        return;
                    }
                }
                if let Some(h) = hasher
                    && h.finalize().as_bytes() != p.blob.as_bytes()
                {
                    tracing::error!(blob = %p.blob.to_hex(), "blob content does not match its hash; aborting GET");
                    let _ = tx
                        .send(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("blob {} is damaged (see `cairn fsck`)", p.blob.to_hex()),
                        )))
                        .await;
                    return;
                }
                if let Some(last) = held
                    && tx.send(Ok(last)).await.is_err()
                {
                    return;
                }
            }
        });
        BodyStream {
            rx,
            len: end - start,
        }
    }

    /// DeleteObject.
    pub async fn delete_object(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<String>,
        by: &PrincipalId,
    ) -> S3Result<DeleteRes> {
        let b = self.bucket(bucket)?;
        if let Some(v) = &version_id
            && v != "null"
        {
            v.parse::<VersionId>()?;
        }
        let inner = self.inner.clone();
        let em = self.emitter(by);
        let (id, bn, key, by) = (b.id, bucket.to_string(), key.to_string(), by.clone());
        let res = self
            .inner
            .meta
            .write(move |txn| {
                let b = active_bucket(txn, id, &bn)?;
                let now = now_for_key(txn, id, &key)?;
                if let Some(vid) = &version_id {
                    let found = if vid == "null" {
                        txn.null_version(id, &key, false)?
                    } else {
                        txn.version(id, &key, &vid.parse()?)?
                            .filter(|v| v.is_live())
                    };
                    let Some(v) = found else {
                        return Ok(DeleteRes {
                            delete_marker: false,
                            version_id: Some(vid.clone()),
                        });
                    };
                    check_lock(&v, now)?;
                    let dm = v.is_delete_marker();
                    em.emit(
                        txn,
                        &b,
                        EventName::ObjectRemovedDelete,
                        &key,
                        Some(&v),
                        Vec::new(),
                    )?;
                    soft_delete(txn, &b, &inner.cfg, v, now, &by)?;
                    txn.refresh_latest(id, &key)?;
                    return Ok(DeleteRes {
                        delete_marker: dm,
                        version_id: Some(vid.clone()),
                    });
                }
                match b.versioning {
                    Versioning::Off => {
                        if let Some(head) = txn.latest(id, &key)? {
                            em.emit(
                                txn,
                                &b,
                                EventName::ObjectRemovedDelete,
                                &key,
                                Some(&head),
                                Vec::new(),
                            )?;
                            soft_delete(txn, &b, &inner.cfg, head, now, &by)?;
                            txn.refresh_latest(id, &key)?;
                            failpoint!("delete.in_txn");
                        }
                        Ok(DeleteRes::default())
                    }
                    Versioning::Suspended | Versioning::Enabled => {
                        if b.versioning == Versioning::Suspended
                            && let Some(old) = txn.null_version(id, &key, false)?
                        {
                            soft_delete(txn, &b, &inner.cfg, old, now, &by)?;
                        }
                        let (v, b) = commit_version(
                            txn,
                            &inner.blobs,
                            &inner.cfg,
                            id,
                            &bn,
                            &key,
                            VersionKind::DeleteMarker,
                            &by,
                            &WriteConditions::default(),
                        )?;
                        em.emit(
                            txn,
                            &b,
                            EventName::ObjectRemovedDeleteMarkerCreated,
                            &key,
                            Some(&v),
                            Vec::new(),
                        )?;
                        Ok(DeleteRes {
                            delete_marker: true,
                            version_id: s3_version_id(&v, b.versioning),
                        })
                    }
                }
            })
            .await;
        if res.is_ok() {
            failpoint!("delete.committed");
            self.notify();
        }
        res
    }

    /// DeleteObjects: per-key results in request order.
    pub async fn delete_objects(
        &self,
        bucket: &str,
        keys: Vec<(String, Option<String>)>,
        by: &PrincipalId,
    ) -> S3Result<Vec<(String, S3Result<DeleteRes>)>> {
        self.bucket(bucket)?;
        let mut out = Vec::with_capacity(keys.len());
        for (k, v) in keys {
            let r = self.delete_object(bucket, &k, v, by).await;
            out.push((k, r));
        }
        Ok(out)
    }

    /// Resolve a copy source (Live, not a delete marker) and check its preconditions.
    pub(crate) fn resolve_source(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&str>,
        conds: &ReadConditions,
    ) -> S3Result<(VersionRecord, Versioning)> {
        let r = self.read()?;
        let b = resolve_bucket(&r, bucket)?;
        let v = match version {
            Some(vid) => {
                let v = resolve_version(&r, b.id, key, vid)?;
                if v.is_delete_marker() {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidRequest,
                        "The source of a copy request may not specifically refer to a delete marker by version id.",
                    ));
                }
                v
            }
            None => match r.latest(b.id, key)? {
                Some(v) if !v.is_delete_marker() => v,
                _ => {
                    return Err(
                        S3Error::code(S3ErrorCode::NoSuchKey).with_resource(key.to_string())
                    );
                }
            },
        };
        let body = v.body().expect("object");
        check_copy_source_conditions(conds, &body.etag, v.created_at)?;
        Ok((v, b.versioning))
    }

    /// CopyObject (server-side; the new version shares the source blobs).
    pub async fn copy_object(&self, req: CopyObjectReq) -> S3Result<CopyObjectRes> {
        ObjectKey::try_from(req.key.as_str())?;
        let (src, src_vg) = self.resolve_source(
            &req.src_bucket,
            &req.src_key,
            req.src_version.as_deref(),
            &req.src_conditions,
        )?;
        let dst = self.bucket(&req.bucket)?;
        let same = req.src_bucket == req.bucket && req.src_key == req.key;
        if same
            && req.metadata_directive == Directive::Copy
            && req.meta.storage_class.is_none()
            && req.tagging_directive == Directive::Copy
        {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "This copy request is illegal because it is trying to copy an object to itself without changing the object's metadata, storage class, website redirect location or encryption attributes.",
            ));
        }
        let mut body = src.body().expect("object").clone();
        if req.metadata_directive == Directive::Replace {
            let m = req.meta.clone();
            body.content_type = m.content_type;
            body.cache_control = m.cache_control;
            body.content_disposition = m.content_disposition;
            body.content_encoding = m.content_encoding;
            body.content_language = m.content_language;
            body.expires = m.expires;
            body.user_metadata = m.user_metadata;
            body.website_redirect = m.website_redirect;
        }
        if let Some(sc) = &req.meta.storage_class {
            body.storage_class = Some(sc.clone());
        }
        if req.tagging_directive == Directive::Replace {
            validate_tags(&req.tags, 10)?;
            body.tags = req.tags.clone();
        }
        let put = self
            .commit_object(
                dst.id,
                &req.bucket,
                &req.key,
                body,
                &req.owner,
                req.conditions.clone(),
                EventName::ObjectCreatedCopy,
                None,
            )
            .await?;
        Ok(CopyObjectRes {
            put,
            src_version_id: s3_version_id(&src, src_vg),
        })
    }

    fn tag_target(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&str>,
    ) -> S3Result<(cairn_core::BucketId, VersionRecord, Versioning)> {
        let r = self.read()?;
        let b = resolve_bucket(&r, bucket)?;
        let v = match version {
            Some(vid) => resolve_version(&r, b.id, key, vid)?,
            None => r.latest(b.id, key)?.ok_or_else(|| {
                S3Error::code(S3ErrorCode::NoSuchKey).with_resource(key.to_string())
            })?,
        };
        if v.is_delete_marker() {
            return Err(delete_marker_err(
                if version.is_some() {
                    S3ErrorCode::MethodNotAllowed
                } else {
                    S3ErrorCode::NoSuchKey
                },
                &v,
                b.versioning,
            ));
        }
        Ok((b.id, v, b.versioning))
    }

    /// GetObjectTagging → (tags, version id).
    pub fn get_object_tagging(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&str>,
    ) -> S3Result<(BTreeMap<String, String>, Option<String>)> {
        let (_, v, vg) = self.tag_target(bucket, key, version)?;
        Ok((
            v.body().expect("object").tags.clone(),
            s3_version_id(&v, vg),
        ))
    }

    /// PutObjectTagging (in place on the version; tags are not content) → version id.
    pub async fn put_object_tagging(
        &self,
        bucket: &str,
        key: &str,
        version: Option<&str>,
        tags: BTreeMap<String, String>,
    ) -> S3Result<Option<String>> {
        validate_tags(&tags, 10)?;
        let (id, v, vg) = self.tag_target(bucket, key, version)?;
        let reported = s3_version_id(&v, vg);
        let (bn, key, vid) = (bucket.to_string(), key.to_string(), v.version_id);
        self.inner
            .meta
            .write(move |txn| {
                active_bucket(txn, id, &bn)?;
                let mut v = txn
                    .version(id, &key, &vid)?
                    .filter(|v| v.is_live())
                    .ok_or_else(|| S3Error::code(S3ErrorCode::NoSuchKey))?;
                if let VersionKind::Object(b) = &mut v.kind {
                    b.tags = tags.clone();
                }
                txn.put_version(id, &v)?;
                txn.refresh_latest(id, &key)?;
                Ok::<_, S3Error>(())
            })
            .await?;
        Ok(reported)
    }

    /// Write a replicated delete marker with the given version id (`x-cairn-version-id` on a
    /// DELETE without `versionId`). Idempotent.
    pub async fn delete_marker_replica(
        &self,
        bucket: &str,
        key: &str,
        version_id: VersionId,
        by: &PrincipalId,
    ) -> S3Result<DeleteRes> {
        let b = self.bucket(bucket)?;
        let inner = self.inner.clone();
        let em = self.emitter(by);
        let (id, bn, key, by) = (b.id, bucket.to_string(), key.to_string(), by.clone());
        let res = self
            .inner
            .meta
            .write(move |txn| {
                let (v, b) = commit_replica(
                    txn,
                    &inner.blobs,
                    id,
                    &bn,
                    &key,
                    VersionKind::DeleteMarker,
                    &by,
                    version_id,
                )?;
                if let Some(v) = &v {
                    em.emit(
                        txn,
                        &b,
                        EventName::ObjectRemovedDeleteMarkerCreated,
                        &key,
                        Some(v),
                        Vec::new(),
                    )?;
                }
                Ok::<_, S3Error>(DeleteRes {
                    delete_marker: true,
                    version_id: Some(version_id.to_string()),
                })
            })
            .await?;
        self.notify();
        Ok(res)
    }
}
