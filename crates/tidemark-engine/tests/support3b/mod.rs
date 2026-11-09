//! Shared helpers for the phase-3b engine tests (fsck, scrub, backup, replication).
#![allow(dead_code)]

use bytes::Bytes;
use futures::StreamExt;
use std::collections::BTreeMap;
use std::time::Duration;
use tidemark_core::config::{LimitsConfig, RetentionConfig};
use tidemark_core::{PrincipalId, S3ErrorCode};
use tidemark_engine::*;

pub const DAY: Duration = Duration::from_secs(86400);

pub fn cfg() -> EngineConfig {
    EngineConfig {
        retention: RetentionConfig {
            soft_delete: DAY,
            shadow_history: DAY,
            gc_grace: Duration::from_secs(60),
            ..Default::default()
        },
        limits: LimitsConfig {
            min_part_size: 5,
            ..Default::default()
        },
        at_rest_key: None,
        fsync: false,
    }
}

pub fn open(dir: &std::path::Path) -> TidemarkEngine {
    TidemarkEngine::open(dir, cfg()).unwrap()
}

pub fn root() -> PrincipalId {
    PrincipalId::root()
}

pub async fn bucket(e: &TidemarkEngine, name: &str, versioned: bool) {
    e.create_bucket(name, &root(), false, None).await.unwrap();
    if versioned {
        e.put_bucket_versioning(name, true).await.unwrap();
    }
}

pub async fn put_meta(
    e: &TidemarkEngine,
    b: &str,
    k: &str,
    data: &[u8],
    meta: ObjectMeta,
    tags: BTreeMap<String, String>,
) -> PutObjectRes {
    e.put_object(PutObjectReq {
        bucket: b.into(),
        key: k.into(),
        body: body_from_bytes(Bytes::copy_from_slice(data)),
        content_length: Some(data.len() as u64),
        content_md5: None,
        checksum: ChecksumInput::None,
        meta,
        tags,
        conditions: WriteConditions::default(),
        owner: root(),
    })
    .await
    .unwrap()
}

pub async fn put(e: &TidemarkEngine, b: &str, k: &str, data: &[u8]) -> PutObjectRes {
    put_meta(e, b, k, data, ObjectMeta::default(), BTreeMap::new()).await
}

pub async fn read_all(s: BodyStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut s = s;
    while let Some(c) = s.next().await {
        out.extend_from_slice(&c.unwrap());
    }
    out
}

pub async fn get_version(
    e: &TidemarkEngine,
    b: &str,
    k: &str,
    version: Option<String>,
) -> Result<(Vec<u8>, GetObjectRes), S3ErrorCode> {
    match e
        .get_object(
            GetObjectReq {
                bucket: b.into(),
                key: k.into(),
                version_id: version,
                ..Default::default()
            },
            true,
        )
        .await
    {
        Ok(mut r) => {
            let body = read_all(r.body.take().unwrap()).await;
            Ok((body, r))
        }
        Err(e) => Err(e.code),
    }
}

pub async fn get(e: &TidemarkEngine, b: &str, k: &str) -> Result<Vec<u8>, S3ErrorCode> {
    get_version(e, b, k, None).await.map(|(d, _)| d)
}

/// Multipart upload with the given part payloads; returns the completed version.
pub async fn put_multipart(
    e: &TidemarkEngine,
    b: &str,
    k: &str,
    parts: &[Vec<u8>],
) -> PutObjectRes {
    let up = e
        .create_multipart_upload(CreateUploadReq {
            bucket: b.into(),
            key: k.into(),
            owner: root(),
            ..Default::default()
        })
        .await
        .unwrap();
    let mut done = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        let r = e
            .upload_part(UploadPartReq {
                bucket: b.into(),
                key: k.into(),
                upload_id: up.upload_id.clone(),
                part_number: i as u32 + 1,
                body: body_from_bytes(Bytes::copy_from_slice(p)),
                content_length: Some(p.len() as u64),
                content_md5: None,
                checksum: ChecksumInput::None,
            })
            .await
            .unwrap();
        done.push(CompletePart {
            number: i as u32 + 1,
            etag: r.etag,
            checksum: None,
        });
    }
    e.complete_multipart_upload(CompleteReq {
        bucket: b.into(),
        key: k.into(),
        upload_id: up.upload_id,
        parts: done,
        owner: root(),
        ..Default::default()
    })
    .await
    .unwrap()
}

pub fn data(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
        .collect()
}
