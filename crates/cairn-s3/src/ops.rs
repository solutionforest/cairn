//! `impl s3s::S3 for CairnS3`: one engine call per operation.

use crate::CairnS3;
use crate::convert::*;
use base64::Engine as _;
use cairn_core::{ChecksumAlgo, PrincipalId, S3ErrorCode as Code, S3Result as CResult};
use cairn_engine::cairn_meta::{self, ObjectBody, Versioning};
use cairn_engine::{
    CompletePart, CompleteReq, CopyObjectReq, CreateUploadReq, Directive, GetObjectReq, ListReq,
    ListVersionsReq, PutObjectReq, RangeSpec, UploadPartCopyReq, UploadPartReq,
};
use http::{HeaderMap, HeaderValue};
use s3s::dto::*;
use s3s::{S3, S3Request, S3Response, S3Result};

type Res<T> = CResult<S3Response<T>>;

fn ok<T>(t: T) -> Res<T> {
    Ok(S3Response::new(t))
}

macro_rules! set_checksum {
    ($out:expr, $ck:expr) => {
        if let Some((algo, v)) = $ck {
            let v: String = v;
            match algo {
                ChecksumAlgo::Crc32 => $out.checksum_crc32 = Some(v),
                ChecksumAlgo::Crc32c => $out.checksum_crc32c = Some(v),
                ChecksumAlgo::Crc64Nvme => $out.checksum_crc64nvme = Some(v),
                ChecksumAlgo::Sha1 => $out.checksum_sha1 = Some(v),
                ChecksumAlgo::Sha256 => $out.checksum_sha256 = Some(v),
            }
        }
    };
}

fn checksum_type(value: &str) -> ChecksumType {
    let composite = value
        .rsplit_once('-')
        .is_some_and(|(_, n)| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    ChecksumType::from_static(if composite {
        ChecksumType::COMPOSITE
    } else {
        ChecksumType::FULL_OBJECT
    })
}

fn owner(p: &PrincipalId) -> Owner {
    Owner {
        display_name: Some(p.as_str().to_string()),
        id: Some(p.as_str().to_string()),
    }
}

fn max_keys(m: Option<i32>) -> CResult<usize> {
    match m {
        None => Ok(1000),
        Some(n) if n < 0 => Err(err(
            Code::InvalidArgument,
            "max-keys must be a non-negative integer",
        )),
        Some(n) => Ok(n as usize),
    }
}

fn not_implemented(what: &str) -> cairn_core::S3Error {
    err(
        Code::NotImplemented,
        format!("{what} is not implemented yet"),
    )
}

fn bool_header(h: &HeaderMap, name: &str) -> bool {
    h.get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

fn copy_source(cs: &CopySource) -> CResult<(String, String, Option<String>)> {
    match cs {
        CopySource::Bucket {
            bucket,
            key,
            version_id,
        } => Ok((
            bucket.to_string(),
            key.to_string(),
            version_id.as_ref().map(|v| v.to_string()),
        )),
        _ => Err(not_implemented("Access point copy sources")),
    }
}

fn reject_sse_c(alg: Option<&String>) -> CResult<()> {
    if alg.is_some() {
        return Err(not_implemented("SSE-C"));
    }
    Ok(())
}

fn reject_lock<T>(mode: Option<&T>, hold: Option<&ObjectLockLegalHoldStatus>) -> CResult<()> {
    if mode.is_some() || hold.is_some() {
        return Err(not_implemented("Object Lock"));
    }
    Ok(())
}

fn token_encode(key: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.as_bytes())
}

fn token_decode(t: &str) -> CResult<String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(t)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or_else(|| {
            err(
                Code::InvalidArgument,
                "The continuation token provided is incorrect",
            )
        })
}

impl CairnS3 {
    fn sse_out(
        &self,
        requested: Option<&ServerSideEncryption>,
    ) -> CResult<Option<ServerSideEncryption>> {
        match requested.map(|s| s.as_str()) {
            None => Ok(None),
            Some("AES256") if self.engine.config().at_rest_key.is_some() => Ok(requested.cloned()),
            Some(_) => Err(not_implemented("Per-object server-side encryption")),
        }
    }

    /// `x-amz-expiration` for a current version: the lifecycle rule that will expire it and when.
    fn expiration(&self, bucket: &str, key: &str, v: &cairn_meta::VersionRecord) -> Option<String> {
        let b = self.engine.bucket(bucket).ok()?;
        let cfg = cairn_engine::lifecycle::bucket_lifecycle(&b).ok()??;
        let (at, rule) = cfg.current_expiry(key, v)?;
        Some(format!(
            "expiry-date=\"{}\", rule-id=\"{}\"",
            at.to_jiff().strftime("%a, %d %b %Y %H:%M:%S GMT"),
            rule.unwrap_or_default()
        ))
    }

    fn max_meta(&self) -> usize {
        self.engine.config().limits.max_metadata_size
    }

    async fn do_create_bucket(&self, req: S3Request<CreateBucketInput>) -> Res<CreateBucketOutput> {
        let who = self.principal(&req);
        let i = req.input;
        if let Some(o) = &i.object_ownership
            && o.as_str() != "BucketOwnerEnforced"
        {
            return Err(err(
                Code::InvalidArgument,
                "Cairn buckets are always BucketOwnerEnforced; ACL-based ownership is not supported",
            ));
        }
        let location = i
            .create_bucket_configuration
            .as_ref()
            .and_then(|c| c.location_constraint.as_ref())
            .map(|l| l.as_str().to_string());
        let legacy_region = location.as_deref().unwrap_or(&self.region) == "us-east-1";
        match self
            .engine
            .create_bucket(
                &i.bucket,
                &who,
                i.object_lock_enabled_for_bucket.unwrap_or(false),
                location,
            )
            .await
        {
            Ok(_) => {}
            // AWS us-east-1 answers 200 and changes nothing when you re-create a bucket you own.
            Err(e) if e.code == Code::BucketAlreadyOwnedByYou && legacy_region => {}
            Err(e) => return Err(e),
        }
        ok(CreateBucketOutput {
            location: Some(format!("/{}", i.bucket)),
            ..Default::default()
        })
    }

    async fn do_head_bucket(&self, req: S3Request<HeadBucketInput>) -> Res<HeadBucketOutput> {
        let b = self.engine.head_bucket(&req.input.bucket)?;
        ok(HeadBucketOutput {
            bucket_region: Some(b.location.unwrap_or_else(|| self.region.clone())),
            ..Default::default()
        })
    }

    async fn do_delete_bucket(&self, req: S3Request<DeleteBucketInput>) -> Res<DeleteBucketOutput> {
        let who = self.principal(&req);
        self.engine.delete_bucket(&req.input.bucket, &who).await?;
        if let Some(p) = &self.policies
            && let Err(e) = p.forget_bucket(&req.input.bucket).await
        {
            tracing::warn!(bucket = %req.input.bucket, error = %e, "could not drop bucket policy");
        }
        ok(DeleteBucketOutput::default())
    }

    async fn do_list_buckets(&self, req: S3Request<ListBucketsInput>) -> Res<ListBucketsOutput> {
        let who = self.principal(&req);
        let i = req.input;
        let after = i
            .continuation_token
            .as_deref()
            .map(token_decode)
            .transpose()?;
        let max = match i.max_buckets {
            Some(n) if !(1..=10_000).contains(&n) => {
                return Err(err(
                    Code::InvalidArgument,
                    "max-buckets must be between 1 and 10000",
                ));
            }
            Some(n) => n as usize,
            None => usize::MAX,
        };
        let mut all: Vec<_> = self
            .engine
            .list_buckets()?
            .into_iter()
            .filter(|b| i.prefix.as_deref().is_none_or(|p| b.name.starts_with(p)))
            .filter(|b| after.as_deref().is_none_or(|a| b.name.as_str() > a))
            .collect();
        let next = (all.len() > max).then(|| token_encode(&all[max - 1].name));
        all.truncate(max);
        let buckets = all
            .into_iter()
            .map(|b| Bucket {
                name: Some(b.name),
                creation_date: Some(ts_out(b.created_at)),
                bucket_region: Some(b.location.unwrap_or_else(|| self.region.clone())),
                ..Default::default()
            })
            .collect();
        ok(ListBucketsOutput {
            buckets: Some(buckets),
            owner: Some(owner(&who)),
            continuation_token: next,
            prefix: i.prefix,
        })
    }

    async fn do_get_bucket_location(
        &self,
        req: S3Request<GetBucketLocationInput>,
    ) -> Res<GetBucketLocationOutput> {
        let b = self.engine.head_bucket(&req.input.bucket)?;
        let loc = b.location.unwrap_or_else(|| self.region.clone());
        ok(GetBucketLocationOutput {
            location_constraint: (loc != "us-east-1").then(|| BucketLocationConstraint::from(loc)),
        })
    }

    async fn do_put_bucket_tagging(
        &self,
        req: S3Request<PutBucketTaggingInput>,
    ) -> Res<PutBucketTaggingOutput> {
        let tags = tags_in(&req.input.tagging.tag_set)?;
        self.engine
            .put_bucket_tagging(&req.input.bucket, tags)
            .await?;
        ok(PutBucketTaggingOutput::default())
    }

    async fn do_get_bucket_tagging(
        &self,
        req: S3Request<GetBucketTaggingInput>,
    ) -> Res<GetBucketTaggingOutput> {
        let tags = self.engine.get_bucket_tagging(&req.input.bucket)?;
        ok(GetBucketTaggingOutput {
            tag_set: tags_out(&tags),
        })
    }

    async fn do_delete_bucket_tagging(
        &self,
        req: S3Request<DeleteBucketTaggingInput>,
    ) -> Res<DeleteBucketTaggingOutput> {
        self.engine.delete_bucket_tagging(&req.input.bucket).await?;
        ok(DeleteBucketTaggingOutput::default())
    }

    async fn do_put_bucket_versioning(
        &self,
        req: S3Request<PutBucketVersioningInput>,
    ) -> Res<PutBucketVersioningOutput> {
        let c = &req.input.versioning_configuration;
        if c.mfa_delete
            .as_ref()
            .is_some_and(|m| m.as_str() == "Enabled")
        {
            return Err(not_implemented("MFA delete"));
        }
        match c.status.as_ref().map(|s| s.as_str()) {
            Some(BucketVersioningStatus::ENABLED) => {
                self.engine
                    .put_bucket_versioning(&req.input.bucket, true)
                    .await?
            }
            Some(BucketVersioningStatus::SUSPENDED) => {
                if self
                    .engine
                    .get_bucket_replication(&req.input.bucket)?
                    .is_some()
                {
                    return Err(err(
                        Code::InvalidBucketState,
                        "Versioning cannot be suspended while a replication configuration is present.",
                    ));
                }
                self.engine
                    .put_bucket_versioning(&req.input.bucket, false)
                    .await?
            }
            None => {
                self.engine.head_bucket(&req.input.bucket)?;
            }
            Some(_) => {
                return Err(err(
                    Code::IllegalVersioningConfigurationException,
                    "The Versioning element must be specified",
                ));
            }
        }
        ok(PutBucketVersioningOutput::default())
    }

    async fn do_get_bucket_versioning(
        &self,
        req: S3Request<GetBucketVersioningInput>,
    ) -> Res<GetBucketVersioningOutput> {
        let status = match self.engine.get_bucket_versioning(&req.input.bucket)? {
            Versioning::Off => None,
            Versioning::Enabled => Some(BucketVersioningStatus::ENABLED),
            Versioning::Suspended => Some(BucketVersioningStatus::SUSPENDED),
        };
        ok(GetBucketVersioningOutput {
            status: status.map(BucketVersioningStatus::from_static),
            ..Default::default()
        })
    }

    async fn do_put_object(&self, req: S3Request<PutObjectInput>) -> Res<PutObjectOutput> {
        let who = self.principal(&req);
        let i = req.input;
        reject_sse_c(i.sse_customer_algorithm.as_ref())?;
        reject_lock(
            i.object_lock_mode.as_ref(),
            i.object_lock_legal_hold_status.as_ref(),
        )?;
        if i.write_offset_bytes.is_some() {
            return Err(not_implemented("Appending with x-amz-write-offset-bytes"));
        }
        let sse = self.sse_out(i.server_side_encryption.as_ref())?;
        let checksum = checksum_in(
            ChecksumHeaders {
                algorithm: i.checksum_algorithm.as_ref(),
                crc32: i.checksum_crc32.as_ref(),
                crc32c: i.checksum_crc32c.as_ref(),
                crc64nvme: i.checksum_crc64nvme.as_ref(),
                sha1: i.checksum_sha1.as_ref(),
                sha256: i.checksum_sha256.as_ref(),
                unsupported: i.checksum_sha512.is_some()
                    || i.checksum_md5.is_some()
                    || i.checksum_xxhash3.is_some()
                    || i.checksum_xxhash64.is_some()
                    || i.checksum_xxhash128.is_some(),
            },
            &req.headers,
            req.trailing_headers.clone(),
        )?;
        let meta = object_meta(
            i.content_type.as_ref(),
            i.cache_control.as_ref(),
            i.content_disposition.as_ref(),
            i.content_encoding.as_ref(),
            i.content_language.as_ref(),
            i.expires.clone(),
            i.metadata.as_ref(),
            i.storage_class.as_ref(),
            i.website_redirect_location.as_ref(),
            self.max_meta(),
        )?;
        let replica = self
            .replica_version(&req.headers, &req.extensions, &i.bucket, &i.key)
            .await?;
        let preq = PutObjectReq {
            bucket: i.bucket,
            key: i.key,
            body: body_in(i.body),
            content_length: i.content_length.and_then(|n| u64::try_from(n).ok()),
            content_md5: i.content_md5,
            checksum,
            meta,
            tags: parse_tagging(i.tagging.as_deref())?,
            conditions: write_conditions(i.if_match.as_ref(), i.if_none_match.as_ref()),
            owner: who,
        };
        let (bucket, key) = (preq.bucket.clone(), preq.key.clone());
        let r = match replica {
            Some(vid) => self.engine.put_object_replica(preq, vid).await?,
            None => self.engine.put_object(preq).await?,
        };
        let mut out = PutObjectOutput {
            e_tag: Some(etag_out(&r.etag)),
            expiration: self.expiration(&bucket, &key, &r.version),
            version_id: r.version_id,
            server_side_encryption: sse,
            ..Default::default()
        };
        if let Some((_, v)) = &r.checksum {
            out.checksum_type = Some(checksum_type(v));
        }
        set_checksum!(out, r.checksum);
        ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    async fn read_object(
        &self,
        headers: &HeaderMap,
        bucket: String,
        key: String,
        version_id: Option<String>,
        range: Option<Range>,
        part_number: Option<i32>,
        conditions: cairn_engine::ReadConditions,
        sse_c: Option<&String>,
        with_body: bool,
    ) -> CResult<cairn_engine::GetObjectRes> {
        reject_sse_c(sse_c)?;
        let part_number = match part_number {
            None => None,
            Some(n) if n >= 1 => Some(n as u32),
            Some(_) => {
                return Err(err(
                    Code::InvalidArgument,
                    "Part number must be an integer between 1 and 10000, inclusive",
                ));
            }
        };
        let range = range.map(|r| match r {
            Range::Int { first, last } => RangeSpec::Int { first, last },
            Range::Suffix { length } => RangeSpec::Suffix(length),
        });
        self.engine
            .get_object(
                GetObjectReq {
                    bucket,
                    key,
                    version_id,
                    range,
                    part_number,
                    conditions,
                    as_of: as_of(headers)?,
                },
                with_body,
            )
            .await
    }

    async fn do_get_object(&self, req: S3Request<GetObjectInput>) -> Res<GetObjectOutput> {
        let i = req.input;
        let part_no = i.part_number;
        let bucket = i.bucket.clone();
        let conds = read_conditions(
            i.if_match.as_ref(),
            i.if_none_match.as_ref(),
            i.if_modified_since.as_ref(),
            i.if_unmodified_since.as_ref(),
        );
        let checksum_mode = i
            .checksum_mode
            .as_ref()
            .is_some_and(|m| m.as_str() == "ENABLED");
        let key = i.key.clone();
        let mut r = self
            .read_object(
                &req.headers,
                bucket.clone(),
                i.key,
                i.version_id,
                i.range,
                i.part_number,
                conds,
                i.sse_customer_algorithm.as_ref(),
                true,
            )
            .await?;
        let body = r.version.body().expect("object").clone();
        let mut out = GetObjectOutput {
            body: r.body.take().map(StreamingBlob::wrap),
            ..Default::default()
        };
        fill_read!(out, r, body, checksum_mode, part_no);
        out.replication_status = self.replication_status(&bucket, &r.version);
        out.expiration = self.expiration(&bucket, &key, &r.version);
        let mut resp = S3Response::new(out);
        add_blob_hash(&mut resp.headers, &body);
        Ok(resp)
    }

    async fn do_head_object(&self, req: S3Request<HeadObjectInput>) -> Res<HeadObjectOutput> {
        let i = req.input;
        let part_no = i.part_number;
        let bucket = i.bucket.clone();
        let conds = read_conditions(
            i.if_match.as_ref(),
            i.if_none_match.as_ref(),
            i.if_modified_since.as_ref(),
            i.if_unmodified_since.as_ref(),
        );
        let checksum_mode = i
            .checksum_mode
            .as_ref()
            .is_some_and(|m| m.as_str() == "ENABLED");
        let key = i.key.clone();
        let r = self
            .read_object(
                &req.headers,
                bucket.clone(),
                i.key,
                i.version_id,
                i.range,
                i.part_number,
                conds,
                i.sse_customer_algorithm.as_ref(),
                false,
            )
            .await?;
        let body = r.version.body().expect("object").clone();
        let mut out = HeadObjectOutput::default();
        fill_read!(out, r, body, checksum_mode, part_no);
        out.replication_status = self.replication_status(&bucket, &r.version);
        out.expiration = self.expiration(&bucket, &key, &r.version);
        let mut resp = S3Response::new(out);
        add_blob_hash(&mut resp.headers, &body);
        Ok(resp)
    }

    async fn do_delete_object(&self, req: S3Request<DeleteObjectInput>) -> Res<DeleteObjectOutput> {
        let who = self.principal(&req);
        let replica = match &req.input.version_id {
            None => {
                self.replica_version(
                    &req.headers,
                    &req.extensions,
                    &req.input.bucket,
                    &req.input.key,
                )
                .await?
            }
            Some(_) => None,
        };
        let i = req.input;
        let d = match replica {
            Some(vid) => {
                self.engine
                    .delete_marker_replica(&i.bucket, &i.key, vid, &who)
                    .await?
            }
            None => {
                self.engine
                    .delete_object(&i.bucket, &i.key, i.version_id, &who)
                    .await?
            }
        };
        ok(DeleteObjectOutput {
            delete_marker: d.delete_marker.then_some(true),
            version_id: d.version_id,
            ..Default::default()
        })
    }

    async fn do_delete_objects(
        &self,
        req: S3Request<DeleteObjectsInput>,
    ) -> Res<DeleteObjectsOutput> {
        let who = self.principal(&req);
        let i = req.input;
        if i.delete.objects.len() > 1000 {
            return Err(err(
                Code::MalformedXML,
                "The number of keys in a DeleteObjects request cannot exceed 1000",
            ));
        }
        let quiet = i.delete.quiet.unwrap_or(false);
        let keys = i
            .delete
            .objects
            .into_iter()
            .map(|o| (o.key, o.version_id))
            .collect::<Vec<_>>();
        let requested: Vec<Option<String>> = keys.iter().map(|(_, v)| v.clone()).collect();
        let results = self.engine.delete_objects(&i.bucket, keys, &who).await?;
        let mut deleted = Vec::new();
        let mut errors = Vec::new();
        for ((key, r), asked) in results.into_iter().zip(requested) {
            match r {
                Ok(d) => {
                    if quiet {
                        continue;
                    }
                    deleted.push(DeletedObject {
                        key: Some(key),
                        version_id: asked.clone(),
                        delete_marker: d.delete_marker.then_some(true),
                        delete_marker_version_id: if d.delete_marker { d.version_id } else { None },
                    });
                }
                Err(e) => errors.push(Error {
                    code: Some(e.code.as_str().to_string()),
                    key: Some(key),
                    message: Some(e.message),
                    version_id: asked,
                }),
            }
        }
        ok(DeleteObjectsOutput {
            deleted: Some(deleted),
            errors: Some(errors),
            ..Default::default()
        })
    }

    async fn do_copy_object(&self, req: S3Request<CopyObjectInput>) -> Res<CopyObjectOutput> {
        let who = self.principal(&req);
        let i = req.input;
        reject_sse_c(i.sse_customer_algorithm.as_ref())?;
        reject_sse_c(i.copy_source_sse_customer_algorithm.as_ref())?;
        reject_lock(
            i.object_lock_mode.as_ref(),
            i.object_lock_legal_hold_status.as_ref(),
        )?;
        let sse = self.sse_out(i.server_side_encryption.as_ref())?;
        let (src_bucket, src_key, src_version) = copy_source(&i.copy_source)?;
        let directive = |d: Option<&str>| match d {
            None | Some("COPY") => Ok(Directive::Copy),
            Some("REPLACE") => Ok(Directive::Replace),
            Some(_) => Err(err(Code::InvalidArgument, "Unknown directive")),
        };
        let metadata_directive = directive(i.metadata_directive.as_ref().map(|d| d.as_str()))?;
        let tagging_directive = directive(i.tagging_directive.as_ref().map(|d| d.as_str()))?;
        let meta = object_meta(
            i.content_type.as_ref(),
            i.cache_control.as_ref(),
            i.content_disposition.as_ref(),
            i.content_encoding.as_ref(),
            i.content_language.as_ref(),
            i.expires.clone(),
            i.metadata.as_ref(),
            i.storage_class.as_ref(),
            i.website_redirect_location.as_ref(),
            self.max_meta(),
        )?;
        let r = self
            .engine
            .copy_object(CopyObjectReq {
                src_bucket,
                src_key,
                src_version,
                src_conditions: read_conditions(
                    i.copy_source_if_match.as_ref(),
                    i.copy_source_if_none_match.as_ref(),
                    i.copy_source_if_modified_since.as_ref(),
                    i.copy_source_if_unmodified_since.as_ref(),
                ),
                bucket: i.bucket,
                key: i.key,
                metadata_directive,
                meta,
                tagging_directive,
                tags: parse_tagging(i.tagging.as_deref())?,
                conditions: write_conditions(i.if_match.as_ref(), i.if_none_match.as_ref()),
                checksum_algo: algo_in(i.checksum_algorithm.as_ref())?,
                owner: who,
            })
            .await?;
        let mut result = CopyObjectResult {
            e_tag: Some(etag_out(&r.put.etag)),
            last_modified: Some(ts_out(r.put.version.created_at)),
            ..Default::default()
        };
        if let Some((_, v)) = &r.put.checksum {
            result.checksum_type = Some(checksum_type(v));
        }
        set_checksum!(result, r.put.checksum.clone());
        ok(CopyObjectOutput {
            copy_object_result: Some(result),
            copy_source_version_id: r.src_version_id,
            version_id: r.put.version_id,
            server_side_encryption: sse,
            ..Default::default()
        })
    }

    fn list_entry(
        &self,
        b: &ObjectBody,
        key: String,
        at: cairn_core::Ts,
        who: Option<&PrincipalId>,
        url: bool,
    ) -> Object {
        Object {
            key: Some(if url { url_encode(&key) } else { key }),
            last_modified: Some(ts_out(at)),
            e_tag: Some(etag_out(&b.etag)),
            size: Some(b.size as i64),
            storage_class: Some(ObjectStorageClass::from(storage_class_name(b))),
            owner: who.map(owner),
            checksum_algorithm: b
                .checksum
                .as_ref()
                .map(|c| vec![ChecksumAlgorithm::from(c.algo.as_str().to_string())]),
            checksum_type: b.checksum.as_ref().map(|c| checksum_type(&c.value)),
            ..Default::default()
        }
    }

    async fn do_list_objects(&self, req: S3Request<ListObjectsInput>) -> Res<ListObjectsOutput> {
        let i = req.input;
        let url = encoding_url(i.encoding_type.as_ref())?;
        let max = max_keys(i.max_keys)?;
        let r = self.engine.list_objects(
            &i.bucket,
            &ListReq {
                prefix: i.prefix.clone().unwrap_or_default(),
                delimiter: i.delimiter.clone().filter(|d| !d.is_empty()),
                after: i.marker.clone().filter(|m| !m.is_empty()),
                max,
                as_of: as_of(&req.headers)?,
            },
        )?;
        let contents = r
            .objects
            .iter()
            .map(|o| {
                let b = o.version.body().expect("object");
                self.list_entry(
                    b,
                    o.version.key.clone(),
                    o.version.created_at,
                    Some(&o.version.owner),
                    url,
                )
            })
            .collect();
        let enc = |s: Option<String>| if url { s.map(|s| url_encode(&s)) } else { s };
        ok(ListObjectsOutput {
            name: Some(i.bucket),
            prefix: Some(enc(i.prefix).unwrap_or_default()),
            marker: Some(enc(i.marker).unwrap_or_default()),
            max_keys: Some(max as i32),
            is_truncated: Some(r.truncated),
            contents: Some(contents),
            common_prefixes: Some(prefixes_out(r.prefixes, url)),
            delimiter: enc(i.delimiter.filter(|d| !d.is_empty())),
            next_marker: if r.truncated { enc(r.next_key) } else { None },
            encoding_type: i.encoding_type,
            ..Default::default()
        })
    }

    async fn do_list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> Res<ListObjectsV2Output> {
        let i = req.input;
        let url = encoding_url(i.encoding_type.as_ref())?;
        let max = max_keys(i.max_keys)?;
        let token_key = i
            .continuation_token
            .as_deref()
            .map(token_decode)
            .transpose()?;
        let after = match (token_key, i.start_after.clone().filter(|s| !s.is_empty())) {
            (Some(t), Some(s)) => Some(t.max(s)),
            (t, s) => t.or(s),
        };
        let r = self.engine.list_objects(
            &i.bucket,
            &ListReq {
                prefix: i.prefix.clone().unwrap_or_default(),
                delimiter: i.delimiter.clone().filter(|d| !d.is_empty()),
                after,
                max,
                as_of: as_of(&req.headers)?,
            },
        )?;
        let fetch_owner = i.fetch_owner.unwrap_or(false);
        let contents: Vec<Object> = r
            .objects
            .iter()
            .map(|o| {
                let b = o.version.body().expect("object");
                self.list_entry(
                    b,
                    o.version.key.clone(),
                    o.version.created_at,
                    fetch_owner.then_some(&o.version.owner),
                    url,
                )
            })
            .collect();
        let key_count = (contents.len() + r.prefixes.len()) as i32;
        let enc = |s: Option<String>| if url { s.map(|s| url_encode(&s)) } else { s };
        ok(ListObjectsV2Output {
            name: Some(i.bucket),
            prefix: Some(enc(i.prefix).unwrap_or_default()),
            max_keys: Some(max as i32),
            key_count: Some(key_count),
            continuation_token: i.continuation_token,
            is_truncated: Some(r.truncated),
            next_continuation_token: if r.truncated {
                r.next_key.as_deref().map(token_encode)
            } else {
                None
            },
            contents: Some(contents),
            common_prefixes: Some(prefixes_out(r.prefixes, url)),
            delimiter: enc(i.delimiter.filter(|d| !d.is_empty())),
            encoding_type: i.encoding_type,
            start_after: enc(i.start_after),
            ..Default::default()
        })
    }

    async fn do_list_object_versions(
        &self,
        req: S3Request<ListObjectVersionsInput>,
    ) -> Res<ListObjectVersionsOutput> {
        let i = req.input;
        let url = encoding_url(i.encoding_type.as_ref())?;
        let max = max_keys(i.max_keys)?;
        let key_marker = i.key_marker.clone().filter(|m| !m.is_empty());
        let version_marker = i.version_id_marker.clone().filter(|m| !m.is_empty());
        if version_marker.is_some() && key_marker.is_none() {
            return Err(err(
                Code::InvalidArgument,
                "A version-id marker cannot be specified without a key marker.",
            ));
        }
        let r = self.engine.list_object_versions(
            &i.bucket,
            &ListVersionsReq {
                list: ListReq {
                    prefix: i.prefix.clone().unwrap_or_default(),
                    delimiter: i.delimiter.clone().filter(|d| !d.is_empty()),
                    after: key_marker,
                    max,
                    as_of: None,
                },
                version_marker,
                include_trash: bool_header(&req.headers, "x-cairn-include-trash"),
            },
        )?;
        let enc = |s: Option<String>| if url { s.map(|s| url_encode(&s)) } else { s };
        let mut versions = Vec::new();
        let mut markers = Vec::new();
        for o in r.objects {
            let v = o.version;
            let key = enc(Some(v.key.clone()));
            match v.body() {
                None => markers.push(DeleteMarkerEntry {
                    is_latest: Some(o.is_latest),
                    key,
                    last_modified: Some(ts_out(v.created_at)),
                    owner: Some(owner(&v.owner)),
                    version_id: Some(o.version_id),
                }),
                Some(b) => versions.push(ObjectVersion {
                    is_latest: Some(o.is_latest),
                    key,
                    last_modified: Some(ts_out(v.created_at)),
                    owner: Some(owner(&v.owner)),
                    version_id: Some(o.version_id),
                    e_tag: Some(etag_out(&b.etag)),
                    size: Some(b.size as i64),
                    storage_class: Some(ObjectVersionStorageClass::from_static(
                        ObjectVersionStorageClass::STANDARD,
                    )),
                    checksum_algorithm: b
                        .checksum
                        .as_ref()
                        .map(|c| vec![ChecksumAlgorithm::from(c.algo.as_str().to_string())]),
                    checksum_type: b.checksum.as_ref().map(|c| checksum_type(&c.value)),
                    ..Default::default()
                }),
            }
        }
        ok(ListObjectVersionsOutput {
            name: Some(i.bucket),
            prefix: Some(enc(i.prefix).unwrap_or_default()),
            key_marker: Some(enc(i.key_marker).unwrap_or_default()),
            version_id_marker: Some(i.version_id_marker.unwrap_or_default()),
            max_keys: Some(max as i32),
            delimiter: enc(i.delimiter.filter(|d| !d.is_empty())),
            is_truncated: Some(r.truncated),
            next_key_marker: if r.truncated { enc(r.next_key) } else { None },
            next_version_id_marker: if r.truncated { r.next_version } else { None },
            versions: Some(versions),
            delete_markers: Some(markers),
            common_prefixes: Some(prefixes_out(r.prefixes, url)),
            encoding_type: i.encoding_type,
            ..Default::default()
        })
    }

    async fn do_get_object_tagging(
        &self,
        req: S3Request<GetObjectTaggingInput>,
    ) -> Res<GetObjectTaggingOutput> {
        let i = req.input;
        let (tags, vid) =
            self.engine
                .get_object_tagging(&i.bucket, &i.key, i.version_id.as_deref())?;
        ok(GetObjectTaggingOutput {
            tag_set: tags_out(&tags),
            version_id: vid,
        })
    }

    async fn do_put_object_tagging(
        &self,
        req: S3Request<PutObjectTaggingInput>,
    ) -> Res<PutObjectTaggingOutput> {
        let i = req.input;
        let tags = tags_in(&i.tagging.tag_set)?;
        let vid = self
            .engine
            .put_object_tagging(&i.bucket, &i.key, i.version_id.as_deref(), tags)
            .await?;
        ok(PutObjectTaggingOutput { version_id: vid })
    }

    async fn do_delete_object_tagging(
        &self,
        req: S3Request<DeleteObjectTaggingInput>,
    ) -> Res<DeleteObjectTaggingOutput> {
        let i = req.input;
        let vid = self
            .engine
            .put_object_tagging(
                &i.bucket,
                &i.key,
                i.version_id.as_deref(),
                Default::default(),
            )
            .await?;
        ok(DeleteObjectTaggingOutput { version_id: vid })
    }

    async fn do_create_multipart_upload(
        &self,
        req: S3Request<CreateMultipartUploadInput>,
    ) -> Res<CreateMultipartUploadOutput> {
        let who = self.principal(&req);
        let i = req.input;
        reject_sse_c(i.sse_customer_algorithm.as_ref())?;
        reject_lock(
            i.object_lock_mode.as_ref(),
            i.object_lock_legal_hold_status.as_ref(),
        )?;
        let sse = self.sse_out(i.server_side_encryption.as_ref())?;
        let algo = algo_in(i.checksum_algorithm.as_ref())?;
        let full = match i.checksum_type.as_ref().map(|t| t.as_str()) {
            None | Some(ChecksumType::COMPOSITE) => false,
            Some(ChecksumType::FULL_OBJECT) => true,
            Some(_) => return Err(err(Code::InvalidRequest, "Unknown x-amz-checksum-type")),
        };
        let meta = object_meta(
            i.content_type.as_ref(),
            i.cache_control.as_ref(),
            i.content_disposition.as_ref(),
            i.content_encoding.as_ref(),
            i.content_language.as_ref(),
            i.expires.clone(),
            i.metadata.as_ref(),
            i.storage_class.as_ref(),
            i.website_redirect_location.as_ref(),
            self.max_meta(),
        )?;
        let u = self
            .engine
            .create_multipart_upload(CreateUploadReq {
                bucket: i.bucket.clone(),
                key: i.key.clone(),
                meta,
                tags: parse_tagging(i.tagging.as_deref())?,
                checksum_algo: algo,
                full_object_checksum: full,
                owner: who,
            })
            .await?;
        let ck_type = u.template.checksum.as_ref().map(|c| {
            ChecksumType::from_static(if c.composite {
                ChecksumType::COMPOSITE
            } else {
                ChecksumType::FULL_OBJECT
            })
        });
        ok(CreateMultipartUploadOutput {
            bucket: Some(i.bucket),
            key: Some(i.key),
            upload_id: Some(u.upload_id),
            checksum_algorithm: i.checksum_algorithm,
            checksum_type: ck_type,
            server_side_encryption: sse,
            ..Default::default()
        })
    }

    async fn do_upload_part(&self, req: S3Request<UploadPartInput>) -> Res<UploadPartOutput> {
        let i = req.input;
        reject_sse_c(i.sse_customer_algorithm.as_ref())?;
        let checksum = checksum_in(
            ChecksumHeaders {
                algorithm: i.checksum_algorithm.as_ref(),
                crc32: i.checksum_crc32.as_ref(),
                crc32c: i.checksum_crc32c.as_ref(),
                crc64nvme: i.checksum_crc64nvme.as_ref(),
                sha1: i.checksum_sha1.as_ref(),
                sha256: i.checksum_sha256.as_ref(),
                unsupported: i.checksum_sha512.is_some()
                    || i.checksum_md5.is_some()
                    || i.checksum_xxhash3.is_some()
                    || i.checksum_xxhash64.is_some()
                    || i.checksum_xxhash128.is_some(),
            },
            &req.headers,
            req.trailing_headers.clone(),
        )?;
        let part_number = part_no(i.part_number)?;
        let r = self
            .engine
            .upload_part(UploadPartReq {
                bucket: i.bucket,
                key: i.key,
                upload_id: i.upload_id,
                part_number,
                body: body_in(i.body),
                content_length: i.content_length.and_then(|n| u64::try_from(n).ok()),
                content_md5: i.content_md5,
                checksum,
            })
            .await?;
        let mut out = UploadPartOutput {
            e_tag: Some(etag_out(&r.etag)),
            ..Default::default()
        };
        set_checksum!(out, r.checksum);
        ok(out)
    }

    async fn do_upload_part_copy(
        &self,
        req: S3Request<UploadPartCopyInput>,
    ) -> Res<UploadPartCopyOutput> {
        let i = req.input;
        reject_sse_c(i.sse_customer_algorithm.as_ref())?;
        reject_sse_c(i.copy_source_sse_customer_algorithm.as_ref())?;
        let (src_bucket, src_key, src_version) = copy_source(&i.copy_source)?;
        let range = i.copy_source_range.as_deref().map(copy_range).transpose()?;
        let r = self
            .engine
            .upload_part_copy(UploadPartCopyReq {
                src_bucket: src_bucket.clone(),
                src_key: src_key.clone(),
                src_version: src_version.clone(),
                src_conditions: read_conditions(
                    i.copy_source_if_match.as_ref(),
                    i.copy_source_if_none_match.as_ref(),
                    i.copy_source_if_modified_since.as_ref(),
                    i.copy_source_if_unmodified_since.as_ref(),
                ),
                range,
                bucket: i.bucket,
                key: i.key,
                upload_id: i.upload_id,
                part_number: part_no(i.part_number)?,
            })
            .await?;
        let src_vid = match src_version {
            Some(v) => Some(v),
            None => self
                .engine
                .bucket(&src_bucket)
                .ok()
                .filter(|b| b.versioning != Versioning::Off)
                .and(None),
        };
        let mut result = CopyPartResult {
            e_tag: Some(etag_out(&r.etag)),
            last_modified: Some(ts_out(r.last_modified)),
            ..Default::default()
        };
        set_checksum!(result, r.checksum);
        ok(UploadPartCopyOutput {
            copy_part_result: Some(result),
            copy_source_version_id: src_vid,
            ..Default::default()
        })
    }

    async fn do_complete_multipart_upload(
        &self,
        req: S3Request<CompleteMultipartUploadInput>,
    ) -> Res<CompleteMultipartUploadOutput> {
        let who = self.principal(&req);
        let replica = self
            .replica_version(
                &req.headers,
                &req.extensions,
                &req.input.bucket,
                &req.input.key,
            )
            .await?;
        let i = req.input;
        reject_sse_c(i.sse_customer_algorithm.as_ref())?;
        let parts = i
            .multipart_upload
            .and_then(|m| m.parts)
            .unwrap_or_default()
            .into_iter()
            .map(|p| {
                let number = p
                    .part_number
                    .and_then(|n| u32::try_from(n).ok())
                    .ok_or_else(|| err(Code::MalformedXML, "PartNumber is required"))?;
                let etag = p
                    .e_tag
                    .map(|e| e.value().to_string())
                    .ok_or_else(|| err(Code::MalformedXML, "ETag is required"))?;
                let checksum = p
                    .checksum_crc32
                    .or(p.checksum_crc32c)
                    .or(p.checksum_crc64nvme)
                    .or(p.checksum_sha1)
                    .or(p.checksum_sha256);
                Ok(CompletePart {
                    number,
                    etag,
                    checksum,
                })
            })
            .collect::<CResult<Vec<_>>>()?;
        let creq = CompleteReq {
            bucket: i.bucket.clone(),
            key: i.key.clone(),
            upload_id: i.upload_id,
            parts,
            conditions: write_conditions(i.if_match.as_ref(), i.if_none_match.as_ref()),
            owner: who,
        };
        let r = match replica {
            Some(vid) => {
                self.engine
                    .complete_multipart_upload_replica(creq, vid)
                    .await?
            }
            None => self.engine.complete_multipart_upload(creq).await?,
        };
        let mut out = CompleteMultipartUploadOutput {
            location: Some(format!("/{}/{}", i.bucket, i.key)),
            bucket: Some(i.bucket),
            key: Some(i.key),
            e_tag: Some(etag_out(&r.etag)),
            version_id: r.version_id,
            ..Default::default()
        };
        if let Some((_, v)) = &r.checksum {
            out.checksum_type = Some(checksum_type(v));
        }
        set_checksum!(out, r.checksum);
        ok(out)
    }

    async fn do_abort_multipart_upload(
        &self,
        req: S3Request<AbortMultipartUploadInput>,
    ) -> Res<AbortMultipartUploadOutput> {
        let i = req.input;
        self.engine
            .abort_multipart_upload(&i.bucket, &i.key, &i.upload_id)
            .await?;
        ok(AbortMultipartUploadOutput::default())
    }

    async fn do_list_parts(&self, req: S3Request<ListPartsInput>) -> Res<ListPartsOutput> {
        let i = req.input;
        let max = match i.max_parts {
            None => 1000,
            Some(n) if n < 0 => {
                return Err(err(Code::InvalidArgument, "max-parts must be non-negative"));
            }
            Some(n) => n as usize,
        };
        let marker = i
            .part_number_marker
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0);
        let r = self
            .engine
            .list_parts(&i.bucket, &i.key, &i.upload_id, marker, max)?;
        let u = r.upload.as_ref().expect("upload");
        let algo = u.checksum_algo;
        let parts = r
            .parts
            .iter()
            .map(|(p, at)| {
                let mut part = Part {
                    part_number: Some(p.number as i32),
                    e_tag: Some(etag_out(&p.etag)),
                    size: Some(p.size as i64),
                    last_modified: Some(ts_out(*at)),
                    ..Default::default()
                };
                if let Some(a) = algo {
                    set_checksum!(part, p.checksum.clone().map(|v| (a, v)));
                }
                part
            })
            .collect();
        ok(ListPartsOutput {
            bucket: Some(i.bucket),
            key: Some(i.key),
            upload_id: Some(i.upload_id),
            parts: Some(parts),
            is_truncated: Some(r.truncated),
            next_part_number_marker: r.next_marker.map(|n| n as i32),
            part_number_marker: i.part_number_marker,
            max_parts: Some(max.clamp(1, 1000) as i32),
            initiator: Some(Initiator {
                display_name: Some(u.owner.as_str().to_string()),
                id: Some(u.owner.as_str().to_string()),
            }),
            owner: Some(owner(&u.owner)),
            storage_class: Some(StorageClass::from(
                u.template
                    .storage_class
                    .clone()
                    .unwrap_or_else(|| "STANDARD".to_string()),
            )),
            checksum_algorithm: algo.map(|a| ChecksumAlgorithm::from(a.as_str().to_string())),
            checksum_type: u.template.checksum.as_ref().map(|c| {
                ChecksumType::from_static(if c.composite {
                    ChecksumType::COMPOSITE
                } else {
                    ChecksumType::FULL_OBJECT
                })
            }),
            ..Default::default()
        })
    }

    async fn do_list_multipart_uploads(
        &self,
        req: S3Request<ListMultipartUploadsInput>,
    ) -> Res<ListMultipartUploadsOutput> {
        let i = req.input;
        let url = encoding_url(i.encoding_type.as_ref())?;
        let max = match i.max_uploads {
            None => 1000,
            Some(n) if n < 0 => {
                return Err(err(
                    Code::InvalidArgument,
                    "max-uploads must be non-negative",
                ));
            }
            Some(n) => n as usize,
        };
        let r = self.engine.list_multipart_uploads(
            &i.bucket,
            i.prefix.as_deref().unwrap_or(""),
            i.delimiter.as_deref().filter(|d| !d.is_empty()),
            i.key_marker.as_deref().filter(|m| !m.is_empty()),
            i.upload_id_marker.as_deref().filter(|m| !m.is_empty()),
            max,
        )?;
        let enc = |s: Option<String>| if url { s.map(|s| url_encode(&s)) } else { s };
        let uploads = r
            .uploads
            .into_iter()
            .map(|u| MultipartUpload {
                key: enc(Some(u.key)),
                upload_id: Some(u.upload_id),
                initiated: Some(ts_out(u.initiated_at)),
                initiator: Some(Initiator {
                    display_name: Some(u.owner.as_str().to_string()),
                    id: Some(u.owner.as_str().to_string()),
                }),
                owner: Some(owner(&u.owner)),
                storage_class: Some(StorageClass::from(
                    u.template
                        .storage_class
                        .unwrap_or_else(|| "STANDARD".to_string()),
                )),
                checksum_algorithm: u
                    .checksum_algo
                    .map(|a| ChecksumAlgorithm::from(a.as_str().to_string())),
                ..Default::default()
            })
            .collect();
        ok(ListMultipartUploadsOutput {
            bucket: Some(i.bucket),
            prefix: Some(enc(i.prefix).unwrap_or_default()),
            delimiter: enc(i.delimiter.filter(|d| !d.is_empty())),
            key_marker: Some(enc(i.key_marker).unwrap_or_default()),
            upload_id_marker: Some(i.upload_id_marker.unwrap_or_default()),
            max_uploads: Some(max.clamp(1, 1000) as i32),
            is_truncated: Some(r.truncated),
            next_key_marker: enc(r.next_key),
            next_upload_id_marker: r.next_upload,
            uploads: Some(uploads),
            common_prefixes: Some(prefixes_out(r.prefixes, url)),
            encoding_type: i.encoding_type,
            ..Default::default()
        })
    }
}

impl CairnS3 {
    fn replication_status(
        &self,
        bucket: &str,
        v: &cairn_meta::VersionRecord,
    ) -> Option<ReplicationStatus> {
        let b = self.engine.bucket(bucket).ok()?;
        match self.engine.replication_status(&b, v) {
            Ok(s) => s.map(|s| ReplicationStatus::from(s.as_str().to_string())),
            Err(e) => {
                tracing::warn!(error = %e, "replication status lookup failed");
                None
            }
        }
    }

    /// `x-cairn-version-id` on a write: the replica version id, after checking that the caller
    /// may perform `cairn:ReplicateObject` on the object.
    pub(crate) async fn replica_version(
        &self,
        headers: &HeaderMap,
        ext: &http::Extensions,
        bucket: &str,
        key: &str,
    ) -> CResult<Option<cairn_core::VersionId>> {
        let Some(h) = headers.get(cairn_engine::replication::VERSION_ID_HEADER) else {
            return Ok(None);
        };
        let vid: cairn_core::VersionId = h
            .to_str()
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| err(Code::InvalidArgument, "invalid x-cairn-version-id"))?;
        let caller = ext.get::<cairn_auth::AuthenticatedCaller>();
        let allowed = match (caller, &self.access) {
            (Some(c), _) if c.principal.as_ref().is_some_and(|p| p.is_root) => true,
            (Some(c), Some(a)) => {
                let ctx = cairn_auth::ConditionContext::new();
                a.authorize_action(
                    c,
                    "cairn:ReplicateObject",
                    Some(bucket),
                    &cairn_auth::arn::object(bucket, key),
                    &ctx,
                )
                .await
                .is_ok()
            }
            (None, None) => true,
            _ => false,
        };
        if !allowed {
            return Err(err(
                Code::AccessDenied,
                "cairn:ReplicateObject is required to write replicas",
            ));
        }
        Ok(Some(vid))
    }

    async fn do_put_bucket_replication(
        &self,
        req: S3Request<PutBucketReplicationInput>,
    ) -> Res<PutBucketReplicationOutput> {
        let i = req.input;
        let mut buf = Vec::new();
        {
            let mut ser = s3s::xml::Serializer::new(&mut buf);
            s3s::xml::Serialize::serialize(&i.replication_configuration, &mut ser)
                .map_err(cairn_core::S3Error::internal)?;
        }
        let xml = String::from_utf8(buf).map_err(cairn_core::S3Error::internal)?;
        self.engine.put_bucket_replication(&i.bucket, &xml).await?;
        ok(PutBucketReplicationOutput::default())
    }

    async fn do_get_bucket_replication(
        &self,
        req: S3Request<GetBucketReplicationInput>,
    ) -> Res<GetBucketReplicationOutput> {
        let b = req.input.bucket;
        let Some(cfg) = self.engine.get_bucket_replication(&b)? else {
            return Err(
                cairn_core::S3Error::code(Code::ReplicationConfigurationNotFoundError)
                    .with_resource(b),
            );
        };
        let xml = cfg.to_xml();
        let mut de = s3s::xml::Deserializer::new(xml.as_bytes());
        let rc: ReplicationConfiguration =
            s3s::xml::Deserialize::deserialize(&mut de).map_err(cairn_core::S3Error::internal)?;
        ok(GetBucketReplicationOutput {
            replication_configuration: Some(rc),
        })
    }

    async fn do_delete_bucket_replication(
        &self,
        req: S3Request<DeleteBucketReplicationInput>,
    ) -> Res<DeleteBucketReplicationOutput> {
        self.engine
            .delete_bucket_replication(&req.input.bucket)
            .await?;
        ok(DeleteBucketReplicationOutput::default())
    }
}

fn part_no(n: i32) -> CResult<u32> {
    u32::try_from(n).ok().filter(|n| *n >= 1).ok_or_else(|| {
        err(
            Code::InvalidArgument,
            "Part number must be an integer between 1 and 10000, inclusive",
        )
    })
}

fn encoding_url(e: Option<&EncodingType>) -> CResult<bool> {
    match e.map(|e| e.as_str()) {
        None => Ok(false),
        Some(EncodingType::URL) => Ok(true),
        Some(_) => Err(err(
            Code::InvalidArgument,
            "Invalid Encoding Method specified in Request",
        )),
    }
}

fn prefixes_out(p: Vec<String>, url: bool) -> Vec<CommonPrefix> {
    p.into_iter()
        .map(|p| CommonPrefix {
            prefix: Some(if url { url_encode(&p) } else { p }),
        })
        .collect()
}

fn add_blob_hash(h: &mut HeaderMap, b: &ObjectBody) {
    if let [p] = b.parts.as_slice()
        && let Ok(v) = HeaderValue::from_str(&format!("blake3:{}", p.blob.to_hex()))
    {
        h.insert("x-cairn-blob-hash", v);
    }
}

/// Fill the fields GetObjectOutput and HeadObjectOutput share.
macro_rules! fill_read {
    ($out:ident, $r:ident, $body:ident, $checksum_mode:ident, $part:expr) => {{
        $out.accept_ranges = Some("bytes".to_string());
        $out.content_length = Some($r.content_length as i64);
        if let Some((s, e)) = $r.range {
            $out.content_range = Some(format!("bytes {}-{}/{}", s, e - 1, $r.size));
        }
        $out.e_tag = Some(etag_out(&$body.etag));
        $out.last_modified = Some(ts_out($r.version.created_at));
        $out.version_id = $r.version_id.clone();
        $out.content_type = Some(
            $body
                .content_type
                .clone()
                .unwrap_or_else(|| "binary/octet-stream".to_string()),
        );
        $out.cache_control = $body.cache_control.clone();
        $out.content_disposition = $body.content_disposition.clone();
        $out.content_encoding = $body.content_encoding.clone();
        $out.content_language = $body.content_language.clone();
        $out.expires = $body.expires.clone();
        $out.website_redirect_location = $body.website_redirect.clone();
        if !$body.user_metadata.is_empty() {
            $out.metadata = Some($body.user_metadata.clone().into_iter().collect());
        }
        $out.storage_class = $body.storage_class.clone().map(StorageClass::from);
        if !$body.tags.is_empty() {
            $out.tag_count = Some($body.tags.len() as i32);
        }
        $out.parts_count = $r.parts_count.map(|n| n as i32);
        if $checksum_mode && $r.range.is_none() {
            if let Some(c) = &$body.checksum {
                $out.checksum_type = Some(checksum_type(&c.value));
                set_checksum!($out, Some((c.algo, c.value.clone())));
            }
        }
        // A part read reports that part's checksum (S3 does so without x-amz-checksum-mode).
        if let (Some(n), Some(c)) = ($part, &$body.checksum)
            && let Some(v) = $body
                .parts
                .get((n as usize).wrapping_sub(1))
                .and_then(|p| p.checksum.clone())
                .or_else(|| ($body.parts.len() == 1).then(|| c.value.clone()))
        {
            $out.checksum_type = Some(checksum_type(&c.value));
            set_checksum!($out, Some((c.algo, v)));
        }
    }};
}
use fill_read;

impl CairnS3 {
    async fn do_get_object_attributes(
        &self,
        req: S3Request<GetObjectAttributesInput>,
    ) -> Res<GetObjectAttributesOutput> {
        let i = req.input;
        reject_sse_c(i.sse_customer_algorithm.as_ref())?;
        let want = |a: &str| {
            i.object_attributes
                .iter()
                .flat_map(|x| x.as_str().split(','))
                .any(|x| x.trim() == a)
        };
        let r = self
            .engine
            .get_object(
                GetObjectReq {
                    bucket: i.bucket.clone(),
                    key: i.key.clone(),
                    version_id: i.version_id.clone(),
                    as_of: as_of(&req.headers)?,
                    ..Default::default()
                },
                false,
            )
            .await?;
        let body = r.version.body().expect("object").clone();
        let mut out = GetObjectAttributesOutput {
            last_modified: Some(ts_out(r.version.created_at)),
            version_id: r.version_id.clone(),
            ..Default::default()
        };
        if want(ObjectAttributes::ETAG) {
            out.e_tag = Some(ETag::Strong(body.etag.split('"').collect()));
        }
        if want(ObjectAttributes::OBJECT_SIZE) {
            out.object_size = Some(body.size as i64);
        }
        if want(ObjectAttributes::STORAGE_CLASS) {
            out.storage_class = Some(StorageClass::from(
                body.storage_class
                    .clone()
                    .unwrap_or_else(|| StorageClass::STANDARD.to_string()),
            ));
        }
        if want(ObjectAttributes::CHECKSUM)
            && let Some(c) = &body.checksum
        {
            let mut ck = Checksum {
                checksum_type: Some(checksum_type(&c.value)),
                ..Default::default()
            };
            set_checksum!(ck, Some((c.algo, c.value.clone())));
            out.checksum = Some(ck);
        }
        let multipart = body.etag.contains('-');
        if want(ObjectAttributes::OBJECT_PARTS) && multipart {
            let marker = i.part_number_marker.unwrap_or(0).max(0) as u32;
            let max = i.max_parts.unwrap_or(1000).clamp(0, 1000) as usize;
            let rest: Vec<_> = body.parts.iter().filter(|p| p.number > marker).collect();
            let page = &rest[..rest.len().min(max)];
            let algo = body.checksum.as_ref().map(|c| c.algo);
            let parts = page
                .iter()
                .map(|p| {
                    let mut op = ObjectPart {
                        part_number: Some(p.number as i32),
                        size: Some(p.size as i64),
                        ..Default::default()
                    };
                    if let (Some(a), Some(v)) = (algo, &p.checksum) {
                        set_checksum!(op, Some((a, v.clone())));
                    }
                    op
                })
                .collect();
            out.object_parts = Some(GetObjectAttributesParts {
                is_truncated: Some(rest.len() > page.len()),
                max_parts: Some(max as i32),
                next_part_number_marker: page.last().map(|p| p.number as i32),
                part_number_marker: Some(marker as i32),
                parts: Some(parts),
                total_parts_count: Some(body.parts.len() as i32),
            });
        }
        Ok(S3Response::new(out))
    }
}

macro_rules! forward {
    ($($name:ident => $imp:ident : $in:ty => $out:ty;)*) => {
        #[async_trait::async_trait]
        impl S3 for CairnS3 {
            $(
                async fn $name(&self, req: S3Request<$in>) -> S3Result<S3Response<$out>> {
                    let id = req.extensions.get::<RequestId>().cloned();
                    let ctx = cairn_engine::RequestCtx {
                        request_id: id.as_ref().map(|r| r.0.clone()).unwrap_or_default(),
                        source_ip: req
                            .extensions
                            .get::<cairn_auth::RequestMeta>()
                            .and_then(|m| m.source_ip)
                            .map(|ip| ip.to_string()),
                    };
                    cairn_engine::with_request_ctx(ctx, self.$imp(req))
                        .await
                        .map_err(|e| to_s3s(e, id.as_ref()))
                }
            )*
        }
    };
}

forward! {
    create_bucket => do_create_bucket: CreateBucketInput => CreateBucketOutput;
    head_bucket => do_head_bucket: HeadBucketInput => HeadBucketOutput;
    delete_bucket => do_delete_bucket: DeleteBucketInput => DeleteBucketOutput;
    list_buckets => do_list_buckets: ListBucketsInput => ListBucketsOutput;
    get_bucket_location => do_get_bucket_location: GetBucketLocationInput => GetBucketLocationOutput;
    put_bucket_tagging => do_put_bucket_tagging: PutBucketTaggingInput => PutBucketTaggingOutput;
    get_bucket_tagging => do_get_bucket_tagging: GetBucketTaggingInput => GetBucketTaggingOutput;
    delete_bucket_tagging => do_delete_bucket_tagging: DeleteBucketTaggingInput => DeleteBucketTaggingOutput;
    put_bucket_versioning => do_put_bucket_versioning: PutBucketVersioningInput => PutBucketVersioningOutput;
    get_bucket_versioning => do_get_bucket_versioning: GetBucketVersioningInput => GetBucketVersioningOutput;
    put_object => do_put_object: PutObjectInput => PutObjectOutput;
    get_object => do_get_object: GetObjectInput => GetObjectOutput;
    head_object => do_head_object: HeadObjectInput => HeadObjectOutput;
    delete_object => do_delete_object: DeleteObjectInput => DeleteObjectOutput;
    delete_objects => do_delete_objects: DeleteObjectsInput => DeleteObjectsOutput;
    copy_object => do_copy_object: CopyObjectInput => CopyObjectOutput;
    list_objects => do_list_objects: ListObjectsInput => ListObjectsOutput;
    list_objects_v2 => do_list_objects_v2: ListObjectsV2Input => ListObjectsV2Output;
    list_object_versions => do_list_object_versions: ListObjectVersionsInput => ListObjectVersionsOutput;
    get_object_tagging => do_get_object_tagging: GetObjectTaggingInput => GetObjectTaggingOutput;
    put_object_tagging => do_put_object_tagging: PutObjectTaggingInput => PutObjectTaggingOutput;
    delete_object_tagging => do_delete_object_tagging: DeleteObjectTaggingInput => DeleteObjectTaggingOutput;
    create_multipart_upload => do_create_multipart_upload: CreateMultipartUploadInput => CreateMultipartUploadOutput;
    upload_part => do_upload_part: UploadPartInput => UploadPartOutput;
    upload_part_copy => do_upload_part_copy: UploadPartCopyInput => UploadPartCopyOutput;
    complete_multipart_upload => do_complete_multipart_upload: CompleteMultipartUploadInput => CompleteMultipartUploadOutput;
    abort_multipart_upload => do_abort_multipart_upload: AbortMultipartUploadInput => AbortMultipartUploadOutput;
    list_parts => do_list_parts: ListPartsInput => ListPartsOutput;
    list_multipart_uploads => do_list_multipart_uploads: ListMultipartUploadsInput => ListMultipartUploadsOutput;
    put_bucket_policy => do_put_bucket_policy: PutBucketPolicyInput => PutBucketPolicyOutput;
    get_bucket_policy => do_get_bucket_policy: GetBucketPolicyInput => GetBucketPolicyOutput;
    delete_bucket_policy => do_delete_bucket_policy: DeleteBucketPolicyInput => DeleteBucketPolicyOutput;
    get_bucket_policy_status => do_get_bucket_policy_status: GetBucketPolicyStatusInput => GetBucketPolicyStatusOutput;
    put_public_access_block => do_put_public_access_block: PutPublicAccessBlockInput => PutPublicAccessBlockOutput;
    get_public_access_block => do_get_public_access_block: GetPublicAccessBlockInput => GetPublicAccessBlockOutput;
    delete_public_access_block => do_delete_public_access_block: DeletePublicAccessBlockInput => DeletePublicAccessBlockOutput;
    put_bucket_notification_configuration => do_put_bucket_notification_configuration: PutBucketNotificationConfigurationInput => PutBucketNotificationConfigurationOutput;
    get_bucket_notification_configuration => do_get_bucket_notification_configuration: GetBucketNotificationConfigurationInput => GetBucketNotificationConfigurationOutput;
    put_bucket_lifecycle_configuration => do_put_bucket_lifecycle_configuration: PutBucketLifecycleConfigurationInput => PutBucketLifecycleConfigurationOutput;
    get_bucket_lifecycle_configuration => do_get_bucket_lifecycle_configuration: GetBucketLifecycleConfigurationInput => GetBucketLifecycleConfigurationOutput;
    delete_bucket_lifecycle => do_delete_bucket_lifecycle: DeleteBucketLifecycleInput => DeleteBucketLifecycleOutput;
    put_bucket_encryption => do_put_bucket_encryption: PutBucketEncryptionInput => PutBucketEncryptionOutput;
    get_bucket_encryption => do_get_bucket_encryption: GetBucketEncryptionInput => GetBucketEncryptionOutput;
    delete_bucket_encryption => do_delete_bucket_encryption: DeleteBucketEncryptionInput => DeleteBucketEncryptionOutput;
    get_object_attributes => do_get_object_attributes: GetObjectAttributesInput => GetObjectAttributesOutput;
    get_bucket_acl => do_get_bucket_acl: GetBucketAclInput => GetBucketAclOutput;
    put_bucket_acl => do_put_bucket_acl: PutBucketAclInput => PutBucketAclOutput;
    get_object_acl => do_get_object_acl: GetObjectAclInput => GetObjectAclOutput;
    put_object_acl => do_put_object_acl: PutObjectAclInput => PutObjectAclOutput;
    get_bucket_ownership_controls => do_get_bucket_ownership_controls: GetBucketOwnershipControlsInput => GetBucketOwnershipControlsOutput;
    put_bucket_ownership_controls => do_put_bucket_ownership_controls: PutBucketOwnershipControlsInput => PutBucketOwnershipControlsOutput;
    put_bucket_replication => do_put_bucket_replication: PutBucketReplicationInput => PutBucketReplicationOutput;
    get_bucket_replication => do_get_bucket_replication: GetBucketReplicationInput => GetBucketReplicationOutput;
    delete_bucket_replication => do_delete_bucket_replication: DeleteBucketReplicationInput => DeleteBucketReplicationOutput;
}
