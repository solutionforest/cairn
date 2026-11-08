//! Multipart uploads.

use crate::commit::{active_bucket, commit_version, incref_checked};
use crate::types::*;
use crate::util::*;
use crate::{CairnEngine, resolve_bucket};
use cairn_core::{ChecksumAlgo, ObjectKey, S3Error, S3ErrorCode, S3Result, Ts};
use cairn_meta::{
    Flow, MultipartRecord, ObjectBody, PartRef, ReadExt, Reader, StoredChecksum, Table,
    VersionKind, decode, keys,
};
use md5::{Digest, Md5};
use std::collections::BTreeMap;

fn no_such_upload(id: &str) -> S3Error {
    S3Error::code(S3ErrorCode::NoSuchUpload).with_resource(id.to_string())
}

fn check_part_number(n: u32, max: u32) -> S3Result<()> {
    if n == 0 || n > max {
        return Err(S3Error::new(
            S3ErrorCode::InvalidArgument,
            format!("Part number must be an integer between 1 and {max}, inclusive"),
        ));
    }
    Ok(())
}

impl CairnEngine {
    /// CreateMultipartUpload → upload record.
    pub async fn create_multipart_upload(&self, req: CreateUploadReq) -> S3Result<MultipartRecord> {
        ObjectKey::try_from(req.key.as_str())?;
        validate_tags(&req.tags, 10)?;
        let b = self.bucket(&req.bucket)?;
        let full = req.full_object_checksum || req.checksum_algo == Some(ChecksumAlgo::Crc64Nvme);
        if full && req.checksum_algo.is_some_and(|a| !a.is_crc()) {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "The FULL_OBJECT checksum type cannot be used with the SHA1 or SHA256 checksum algorithm.",
            ));
        }
        if req.full_object_checksum && req.checksum_algo.is_none() {
            return Err(S3Error::new(
                S3ErrorCode::InvalidRequest,
                "The x-amz-checksum-type header can only be used with the x-amz-checksum-algorithm header.",
            ));
        }
        let m = req.meta;
        let rec = MultipartRecord {
            upload_id: uuid::Uuid::now_v7().simple().to_string(),
            bucket: b.id,
            key: req.key,
            initiated_at: Ts::now(),
            owner: req.owner,
            template: ObjectBody {
                content_type: m.content_type,
                cache_control: m.cache_control,
                content_disposition: m.content_disposition,
                content_encoding: m.content_encoding,
                content_language: m.content_language,
                expires: m.expires,
                user_metadata: m.user_metadata,
                tags: req.tags,
                storage_class: m.storage_class,
                website_redirect: m.website_redirect,
                checksum: req.checksum_algo.map(|algo| StoredChecksum {
                    algo,
                    value: String::new(),
                    composite: !full,
                }),
                ..Default::default()
            },
            checksum_algo: req.checksum_algo,
            parts: BTreeMap::new(),
        };
        let name = req.bucket;
        self.inner
            .meta
            .write(move |txn| {
                active_bucket(txn, rec.bucket, &name)?;
                txn.put_upload(&rec)?;
                Ok::<_, S3Error>(rec.clone())
            })
            .await
    }

    fn upload_for(&self, bucket: &str, key: &str, upload_id: &str) -> S3Result<MultipartRecord> {
        let r = self.read()?;
        let b = resolve_bucket(&r, bucket)?;
        match r.upload(b.id, upload_id)? {
            Some(u) if u.key == key => Ok(u),
            _ => Err(no_such_upload(upload_id)),
        }
    }

    async fn attach_part(
        &self,
        bucket: &str,
        upload: &MultipartRecord,
        part: PartRef,
        fresh: bool,
    ) -> S3Result<()> {
        let inner = self.inner.clone();
        let (bn, bid, uid) = (bucket.to_string(), upload.bucket, upload.upload_id.clone());
        let blob = part.blob;
        let r = self
            .inner
            .meta
            .write(move |txn| {
                active_bucket(txn, bid, &bn)?;
                let mut u = txn.upload(bid, &uid)?.ok_or_else(|| no_such_upload(&uid))?;
                incref_checked(txn, &inner.blobs, &part.blob, part.size)?;
                if let Some(old) = u.parts.insert(part.number, part.clone()) {
                    txn.blob_decref(&old.blob, Ts::now())?;
                }
                txn.put_upload(&u)?;
                Ok::<_, S3Error>(())
            })
            .await;
        if r.is_err() && fresh {
            self.discard_blob(blob).await;
        }
        r
    }

    /// UploadPart.
    pub async fn upload_part(&self, req: UploadPartReq) -> S3Result<UploadPartRes> {
        let limits = &self.inner.cfg.limits;
        check_part_number(req.part_number, limits.max_parts)?;
        let upload = self.upload_for(&req.bucket, &req.key, &req.upload_id)?;
        let checksum = match (req.checksum, upload.checksum_algo) {
            (ChecksumInput::None, Some(a)) => ChecksumInput::Compute(a),
            (c, Some(a)) if c.algo().is_some_and(|b| b != a) => {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidRequest,
                    format!(
                        "Checksum Type mismatch occurred, expected checksum Type: {}",
                        a.as_str().to_lowercase()
                    ),
                ));
            }
            (c, _) => c,
        };
        let ing = self
            .ingest(
                req.body,
                req.content_length,
                limits.max_part_size,
                req.content_md5.as_deref(),
                checksum,
            )
            .await?;
        let etag = hex::encode(ing.digest.md5);
        let part = PartRef {
            number: req.part_number,
            blob: ing.digest.blob_id,
            size: ing.digest.size,
            offset: 0,
            etag: etag.clone(),
            checksum: ing.checksum.as_ref().map(|(_, v)| v.clone()),
        };
        self.attach_part(&req.bucket, &upload, part, !ing.digest.deduped)
            .await?;
        Ok(UploadPartRes {
            etag,
            checksum: ing.checksum,
            last_modified: Ts::now(),
        })
    }

    /// UploadPartCopy. Whole single-part sources reuse the source blob (no data copy).
    pub async fn upload_part_copy(&self, req: UploadPartCopyReq) -> S3Result<UploadPartRes> {
        check_part_number(req.part_number, self.inner.cfg.limits.max_parts)?;
        let upload = self.upload_for(&req.bucket, &req.key, &req.upload_id)?;
        let (src, _) = self.resolve_source(
            &req.src_bucket,
            &req.src_key,
            req.src_version.as_deref(),
            &req.src_conditions,
        )?;
        let body = src.body().expect("object").clone();
        let (start, end) = match req.range {
            Some((first, last)) => {
                if last >= body.size {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidRange,
                        format!(
                            "Range specified is not valid for source object of size: {}",
                            body.size
                        ),
                    ));
                }
                if first > last {
                    return Err(S3Error::new(
                        S3ErrorCode::InvalidArgument,
                        "The x-amz-copy-source-range value must be of the form bytes=first-last where first and last are the zero-based offsets of the first and last bytes to copy",
                    ));
                }
                (first, last + 1)
            }
            None => (0, body.size),
        };
        if start == 0 && end == body.size && body.parts.len() == 1 && upload.checksum_algo.is_none()
        {
            let p = &body.parts[0];
            let part = PartRef {
                number: req.part_number,
                offset: 0,
                ..p.clone()
            };
            let etag = part.etag.clone();
            self.attach_part(&req.bucket, &upload, part, false).await?;
            return Ok(UploadPartRes {
                etag,
                checksum: None,
                last_modified: Ts::now(),
            });
        }
        let stream = self.stream_object(&body, start, end);
        let as_body: Body = Box::pin(futures::StreamExt::map(stream, |r| {
            r.map_err(S3Error::internal)
        }));
        let checksum = upload
            .checksum_algo
            .map_or(ChecksumInput::None, ChecksumInput::Compute);
        let ing = self
            .ingest(
                as_body,
                Some(end - start),
                self.inner.cfg.limits.max_part_size,
                None,
                checksum,
            )
            .await?;
        let etag = hex::encode(ing.digest.md5);
        let part = PartRef {
            number: req.part_number,
            blob: ing.digest.blob_id,
            size: ing.digest.size,
            offset: 0,
            etag: etag.clone(),
            checksum: ing.checksum.as_ref().map(|(_, v)| v.clone()),
        };
        self.attach_part(&req.bucket, &upload, part, !ing.digest.deduped)
            .await?;
        Ok(UploadPartRes {
            etag,
            checksum: ing.checksum,
            last_modified: Ts::now(),
        })
    }

    /// CompleteMultipartUpload: validates parts, assembles the object, ETag = `md5(md5s)-N`.
    pub async fn complete_multipart_upload(&self, req: CompleteReq) -> S3Result<PutObjectRes> {
        self.complete_multipart_upload_with(req, None).await
    }

    /// CompleteMultipartUpload writing a replica with the given version id.
    pub async fn complete_multipart_upload_replica(
        &self,
        req: CompleteReq,
        version_id: cairn_core::VersionId,
    ) -> S3Result<PutObjectRes> {
        self.complete_multipart_upload_with(req, Some(version_id))
            .await
    }

    /// S3 answers a repeated CompleteMultipartUpload with 200 and the object it produced. The
    /// upload record is gone by then, so a retry is recognised by its part list: the multipart
    /// ETag those part ETags produce must equal the current object's. Nothing is written.
    async fn already_completed(&self, req: &CompleteReq) -> Option<PutObjectRes> {
        if req.parts.is_empty() {
            return None;
        }
        let mut md5s = Md5::new();
        for cp in &req.parts {
            md5s.update(hex::decode(norm_etag(&cp.etag)).ok()?);
        }
        let etag = format!("{}-{}", hex::encode(md5s.finalize()), req.parts.len());
        let cur = self
            .get_object(
                GetObjectReq {
                    bucket: req.bucket.clone(),
                    key: req.key.clone(),
                    ..Default::default()
                },
                false,
            )
            .await
            .ok()?;
        let body = cur.version.body()?;
        (body.etag == etag).then(|| PutObjectRes {
            etag: body.etag.clone(),
            version_id: cur.version_id.clone(),
            checksum: body.checksum.as_ref().map(|c| (c.algo, c.value.clone())),
            size: body.size,
            version: cur.version.clone(),
        })
    }

    async fn complete_multipart_upload_with(
        &self,
        req: CompleteReq,
        replica: Option<cairn_core::VersionId>,
    ) -> S3Result<PutObjectRes> {
        let upload = match self.upload_for(&req.bucket, &req.key, &req.upload_id) {
            Ok(u) => u,
            Err(e) if e.code == S3ErrorCode::NoSuchUpload && replica.is_none() => {
                return match self.already_completed(&req).await {
                    Some(done) => Ok(done),
                    None => Err(e),
                };
            }
            Err(e) => return Err(e),
        };
        if req.parts.is_empty() {
            return Err(S3Error::new(
                S3ErrorCode::MalformedXML,
                "You must specify at least one part",
            ));
        }
        let min = self.inner.cfg.limits.min_part_size;
        let mut chosen: Vec<PartRef> = Vec::with_capacity(req.parts.len());
        let mut last = 0u32;
        for (i, cp) in req.parts.iter().enumerate() {
            if cp.number <= last {
                return Err(S3Error::code(S3ErrorCode::InvalidPartOrder));
            }
            last = cp.number;
            let p = upload
                .parts
                .get(&cp.number)
                .ok_or_else(|| S3Error::code(S3ErrorCode::InvalidPart))?;
            if norm_etag(&cp.etag) != p.etag {
                return Err(S3Error::code(S3ErrorCode::InvalidPart));
            }
            if let (Some(sent), Some(have)) = (&cp.checksum, &p.checksum)
                && sent.trim() != have
            {
                return Err(S3Error::new(
                    S3ErrorCode::InvalidPart,
                    format!("The checksum of part {} does not match", cp.number),
                ));
            }
            if i + 1 < req.parts.len() && p.size < min {
                return Err(S3Error::new(
                    S3ErrorCode::EntityTooSmall,
                    "Your proposed upload is smaller than the minimum allowed object size.",
                ));
            }
            chosen.push(p.clone());
        }
        let mut md5s = Md5::new();
        let mut offset = 0u64;
        let mut ck_concat = Vec::new();
        for p in &mut chosen {
            md5s.update(hex::decode(&p.etag).map_err(S3Error::internal)?);
            p.offset = offset;
            offset += p.size;
            if let Some(c) = &p.checksum {
                ck_concat.extend(unb64(c).unwrap_or_default());
            }
        }
        let n = chosen.len();
        let etag = format!("{}-{n}", hex::encode(md5s.finalize()));
        let mut body = ObjectBody {
            size: offset,
            etag,
            checksum: None,
            parts: chosen,
            ..upload.template.clone()
        };
        body.checksum = match &upload.template.checksum {
            Some(c) if !c.composite => Some(StoredChecksum {
                algo: c.algo,
                value: b64(&self.full_object_checksum(&body, c.algo).await?),
                composite: false,
            }),
            Some(c) if body.parts.iter().all(|p| p.checksum.is_some()) => Some(StoredChecksum {
                algo: c.algo,
                value: format!(
                    "{}-{n}",
                    b64(&cairn_blob::hash::checksum(c.algo, &ck_concat))
                ),
                composite: true,
            }),
            _ => None,
        };
        let inner = self.inner.clone();
        let em = self.emitter(&req.owner);
        let (bn, key, uid, owner, conds, bid) = (
            req.bucket.clone(),
            req.key.clone(),
            req.upload_id.clone(),
            req.owner.clone(),
            req.conditions.clone(),
            upload.bucket,
        );
        let (v, b) = self
            .inner
            .meta
            .write(move |txn| {
                let u = txn.upload(bid, &uid)?.ok_or_else(|| no_such_upload(&uid))?;
                let kind = VersionKind::Object(Box::new(body.clone()));
                let r = match replica {
                    Some(vid) => {
                        let (v, b) = crate::commit::commit_replica(
                            txn,
                            &inner.blobs,
                            bid,
                            &bn,
                            &key,
                            kind,
                            &owner,
                            vid,
                        )?;
                        let v = match v {
                            Some(v) => v,
                            None => txn
                                .version(bid, &key, &vid)?
                                .ok_or_else(|| S3Error::code(S3ErrorCode::InternalError))?,
                        };
                        (v, b)
                    }
                    None => commit_version(
                        txn,
                        &inner.blobs,
                        &inner.cfg,
                        bid,
                        &bn,
                        &key,
                        kind,
                        &owner,
                        &conds,
                    )?,
                };
                let now = Ts::now();
                for p in u.parts.values() {
                    txn.blob_decref(&p.blob, now)?;
                }
                txn.del_upload(&u)?;
                em.emit(
                    txn,
                    &r.1,
                    cairn_events::EventName::ObjectCreatedCompleteMultipartUpload,
                    &key,
                    Some(&r.0),
                    Vec::new(),
                )?;
                failpoint!("complete.in_txn");
                Ok::<_, S3Error>(r)
            })
            .await?;
        failpoint!("complete.committed");
        self.notify();
        let body = v.body().expect("object");
        Ok(PutObjectRes {
            etag: body.etag.clone(),
            version_id: s3_version_id(&v, b.versioning),
            checksum: body.checksum.as_ref().map(|c| (c.algo, c.value.clone())),
            size: body.size,
            version: v,
        })
    }

    /// Checksum of the assembled object, read back from its parts.
    async fn full_object_checksum(
        &self,
        body: &ObjectBody,
        algo: ChecksumAlgo,
    ) -> S3Result<Vec<u8>> {
        let mut st = cairn_blob::hash::ChecksumState::new(algo);
        let mut s = self.stream_object(body, 0, body.size);
        while let Some(c) = futures::StreamExt::next(&mut s).await {
            st.update(&c.map_err(S3Error::internal)?);
        }
        Ok(st.finish())
    }

    /// AbortMultipartUpload.
    pub async fn abort_multipart_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> S3Result<()> {
        let u = self.upload_for(bucket, key, upload_id)?;
        let (bid, uid) = (u.bucket, u.upload_id);
        self.inner
            .meta
            .write(move |txn| {
                let u = txn.upload(bid, &uid)?.ok_or_else(|| no_such_upload(&uid))?;
                let now = Ts::now();
                for p in u.parts.values() {
                    txn.blob_decref(&p.blob, now)?;
                }
                txn.del_upload(&u)?;
                Ok::<_, S3Error>(())
            })
            .await
    }

    /// ListParts.
    pub fn list_parts(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        marker: Option<u32>,
        max: usize,
    ) -> S3Result<ListPartsRes> {
        let u = self.upload_for(bucket, key, upload_id)?;
        let max = max.clamp(1, 1000);
        let mut parts: Vec<_> = u
            .parts
            .values()
            .filter(|p| marker.is_none_or(|m| p.number > m))
            .cloned()
            .collect();
        let truncated = parts.len() > max;
        parts.truncate(max);
        let next_marker = truncated.then(|| parts.last().map(|p| p.number)).flatten();
        let at = u.initiated_at;
        Ok(ListPartsRes {
            parts: parts.into_iter().map(|p| (p, at)).collect(),
            truncated,
            next_marker,
            upload: Some(u),
        })
    }

    /// ListMultipartUploads.
    pub fn list_multipart_uploads(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        key_marker: Option<&str>,
        upload_marker: Option<&str>,
        max: usize,
    ) -> S3Result<ListUploadsRes> {
        let r = self.read()?;
        let b = resolve_bucket(&r, bucket)?;
        let max = max.clamp(1, 1000);
        let mut res = ListUploadsRes::default();
        let mut entries: Vec<(String, Option<MultipartRecord>)> = Vec::new();
        let mut err = None;
        r.scan_prefix(
            Table::UploadsByKey,
            &keys::bucket_key(b.id, prefix),
            &mut |k, _| {
                let Some((key, uid)) = keys::split_upload_by_key(k) else {
                    return Ok(Flow::Continue);
                };
                if let Some(km) = key_marker {
                    let after = match upload_marker {
                        Some(um) => (key, uid) > (km, um),
                        None => key > km,
                    };
                    if !after {
                        return Ok(Flow::Continue);
                    }
                }
                if let Some(d) = delimiter.filter(|d| !d.is_empty())
                    && let Some(i) = key[prefix.len()..].find(d)
                {
                    let cp = key[..prefix.len() + i + d.len()].to_string();
                    if key_marker.is_none_or(|km| cp.as_str() > km)
                        && entries.last().is_none_or(|(k, _)| *k != cp)
                    {
                        entries.push((cp, None));
                    }
                    return Ok(Flow::Continue);
                }
                match r.get(Table::Uploads, &keys::upload_key(b.id, uid)) {
                    Ok(Some(v)) => entries.push((key.to_string(), Some(decode(&v)?))),
                    Ok(None) => {}
                    Err(e) => {
                        err = Some(e);
                        return Ok(Flow::Stop);
                    }
                }
                Ok(if entries.len() > max {
                    Flow::Stop
                } else {
                    Flow::Continue
                })
            },
        )?;
        if let Some(e) = err {
            return Err(e.into());
        }
        if entries.len() > max {
            entries.truncate(max);
            res.truncated = true;
            if let Some((k, u)) = entries.last() {
                res.next_key = Some(k.clone());
                res.next_upload = u.as_ref().map(|u| u.upload_id.clone());
            }
        }
        for (k, u) in entries {
            match u {
                Some(u) => res.uploads.push(u),
                None => res.prefixes.push(k),
            }
        }
        Ok(res)
    }
}
