//! Engine-level tests: object CRUD, versioning, delete markers, copy, listing, multipart,
//! PITR, trash, GC and recovery.

use bytes::Bytes;
use cairn_core::config::{LimitsConfig, RetentionConfig};
use cairn_core::{PrincipalId, S3ErrorCode, Ts};
use cairn_engine::cairn_meta::{MetaStore, ReadExt, Versioning, keys};
use cairn_engine::*;
use futures::StreamExt;
use std::collections::BTreeMap;
use std::time::Duration;

const DAY: Duration = Duration::from_secs(86400);

fn cfg() -> EngineConfig {
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

fn open(dir: &std::path::Path) -> CairnEngine {
    CairnEngine::open(dir, cfg()).unwrap()
}

fn root() -> PrincipalId {
    PrincipalId::root()
}

async fn put(e: &CairnEngine, b: &str, k: &str, data: &'static [u8]) -> PutObjectRes {
    e.put_object(PutObjectReq {
        bucket: b.into(),
        key: k.into(),
        body: body_from_bytes(Bytes::from_static(data)),
        content_length: Some(data.len() as u64),
        content_md5: None,
        checksum: ChecksumInput::None,
        meta: ObjectMeta::default(),
        tags: BTreeMap::new(),
        conditions: WriteConditions::default(),
        owner: root(),
    })
    .await
    .unwrap()
}

async fn read_all(s: BodyStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut s = s;
    while let Some(c) = s.next().await {
        out.extend_from_slice(&c.unwrap());
    }
    out
}

async fn get(e: &CairnEngine, b: &str, k: &str) -> Result<Vec<u8>, S3ErrorCode> {
    get_req(
        e,
        GetObjectReq {
            bucket: b.into(),
            key: k.into(),
            ..Default::default()
        },
    )
    .await
}

async fn get_req(e: &CairnEngine, req: GetObjectReq) -> Result<Vec<u8>, S3ErrorCode> {
    match e.get_object(req, true).await {
        Ok(r) => Ok(read_all(r.body.unwrap()).await),
        Err(e) => Err(e.code),
    }
}

async fn setup() -> (tempfile::TempDir, CairnEngine) {
    let d = tempfile::tempdir().unwrap();
    let e = open(d.path());
    e.create_bucket("bkt", &root(), false, None).await.unwrap();
    (d, e)
}

#[tokio::test]
async fn bucket_lifecycle() {
    let (_d, e) = setup().await;
    let err = e
        .create_bucket("bkt", &root(), false, None)
        .await
        .unwrap_err();
    assert_eq!(err.code, S3ErrorCode::BucketAlreadyOwnedByYou);
    assert!(
        e.create_bucket("Bad_Name", &root(), false, None)
            .await
            .is_err()
    );
    e.create_bucket("abc", &root(), false, None).await.unwrap();
    let names: Vec<_> = e
        .list_buckets()
        .unwrap()
        .into_iter()
        .map(|b| b.name)
        .collect();
    assert_eq!(names, vec!["abc", "bkt"]);
    put(&e, "bkt", "k", b"x").await;
    let err = e.delete_bucket("bkt", &root()).await.unwrap_err();
    assert_eq!(err.code, S3ErrorCode::BucketNotEmpty);
    e.delete_object("bkt", "k", None, &root()).await.unwrap();
    e.delete_bucket("bkt", &root()).await.unwrap();
    assert_eq!(
        e.head_bucket("bkt").unwrap_err().code,
        S3ErrorCode::NoSuchBucket
    );
    assert_eq!(e.trashed_buckets().unwrap().len(), 1);
    e.create_bucket("bkt", &root(), false, None).await.unwrap();
    assert_eq!(get(&e, "bkt", "k").await, Err(S3ErrorCode::NoSuchKey));
    e.put_bucket_tagging("abc", BTreeMap::from([("a".into(), "1".into())]))
        .await
        .unwrap();
    assert_eq!(e.get_bucket_tagging("abc").unwrap().len(), 1);
    e.delete_bucket_tagging("abc").await.unwrap();
    assert_eq!(
        e.get_bucket_tagging("abc").unwrap_err().code,
        S3ErrorCode::NoSuchTagSet
    );
}

#[tokio::test]
async fn put_get_range_conditions() {
    let (_d, e) = setup().await;
    let r = put(&e, "bkt", "k", b"0123456789").await;
    assert_eq!(r.etag, "781e5e245d69b566979b86e28d23f2c7");
    assert_eq!(r.version_id, None);
    assert_eq!(get(&e, "bkt", "k").await.unwrap(), b"0123456789");
    let rq = |range| GetObjectReq {
        bucket: "bkt".into(),
        key: "k".into(),
        range: Some(range),
        ..Default::default()
    };
    let g = |range| get_req(&e, rq(range));
    assert_eq!(
        g(RangeSpec::Int {
            first: 2,
            last: Some(4)
        })
        .await
        .unwrap(),
        b"234"
    );
    assert_eq!(g(RangeSpec::Suffix(3)).await.unwrap(), b"789");
    assert_eq!(
        g(RangeSpec::Int {
            first: 8,
            last: None
        })
        .await
        .unwrap(),
        b"89"
    );
    assert_eq!(
        g(RangeSpec::Int {
            first: 10,
            last: None
        })
        .await,
        Err(S3ErrorCode::InvalidRange)
    );
    let cond = |c: ReadConditions| GetObjectReq {
        bucket: "bkt".into(),
        key: "k".into(),
        conditions: c,
        ..Default::default()
    };
    let etag = format!("\"{}\"", r.etag);
    assert!(
        get_req(
            &e,
            cond(ReadConditions {
                if_match: Some(etag.clone()),
                ..Default::default()
            })
        )
        .await
        .is_ok()
    );
    assert_eq!(
        get_req(
            &e,
            cond(ReadConditions {
                if_none_match: Some(etag.clone()),
                ..Default::default()
            })
        )
        .await,
        Err(S3ErrorCode::NotModified)
    );
    assert_eq!(
        get_req(
            &e,
            cond(ReadConditions {
                if_match: Some("\"nope\"".into()),
                ..Default::default()
            })
        )
        .await,
        Err(S3ErrorCode::PreconditionFailed)
    );
    let err = e
        .put_object(PutObjectReq {
            bucket: "bkt".into(),
            key: "k".into(),
            body: body_from_bytes("new"),
            content_length: Some(3),
            content_md5: None,
            checksum: ChecksumInput::None,
            meta: ObjectMeta::default(),
            tags: BTreeMap::new(),
            conditions: WriteConditions {
                if_none_match: Some("*".into()),
                ..Default::default()
            },
            owner: root(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code, S3ErrorCode::PreconditionFailed);
    let err = e
        .put_object(PutObjectReq {
            bucket: "bkt".into(),
            key: "k2".into(),
            body: body_from_bytes("abc"),
            content_length: Some(3),
            content_md5: None,
            checksum: ChecksumInput::Value(cairn_core::ChecksumAlgo::Crc32, "AAAAAA==".into()),
            meta: ObjectMeta::default(),
            tags: BTreeMap::new(),
            conditions: WriteConditions::default(),
            owner: root(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code, S3ErrorCode::BadDigest);
    let ok = e
        .put_object(PutObjectReq {
            bucket: "bkt".into(),
            key: "k2".into(),
            body: body_from_bytes("abc"),
            content_length: Some(3),
            content_md5: None,
            checksum: ChecksumInput::Compute(cairn_core::ChecksumAlgo::Crc32c),
            meta: ObjectMeta::default(),
            tags: BTreeMap::new(),
            conditions: WriteConditions::default(),
            owner: root(),
        })
        .await
        .unwrap();
    assert_eq!(
        ok.checksum,
        Some((cairn_core::ChecksumAlgo::Crc32c, "Nks/tw==".into()))
    );
}

#[tokio::test]
async fn unversioned_overwrite_delete_pitr_and_trash() {
    let (_d, e) = setup().await;
    put(&e, "bkt", "k", b"one").await;
    let t1 = Ts::now();
    put(&e, "bkt", "k", b"two").await;
    let t2 = Ts::now();
    e.delete_object("bkt", "k", None, &root()).await.unwrap();
    assert_eq!(get(&e, "bkt", "k").await, Err(S3ErrorCode::NoSuchKey));
    let at = |t| GetObjectReq {
        bucket: "bkt".into(),
        key: "k".into(),
        as_of: Some(t),
        ..Default::default()
    };
    assert_eq!(get_req(&e, at(t1)).await.unwrap(), b"one");
    assert_eq!(get_req(&e, at(t2)).await.unwrap(), b"two");
    assert_eq!(
        get_req(&e, at(Ts::now())).await,
        Err(S3ErrorCode::NoSuchKey)
    );
    assert!(e.pitr_head_at("bkt", "k", t1).unwrap().is_some());
    let listed = e
        .list_objects(
            "bkt",
            &ListReq {
                max: 1000,
                as_of: Some(t2),
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(listed.objects.len(), 1);
    let diff = e.pitr_diff("bkt", "", t1).unwrap();
    assert_eq!(diff.len(), 1);
    assert_eq!(diff[0].kind, DiffKind::Recreate);
    let trash = e.trash_list("bkt", "", 100).unwrap();
    assert_eq!(trash.len(), 2);
    let versions = e
        .list_object_versions(
            "bkt",
            &ListVersionsReq {
                list: ListReq {
                    max: 1000,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    assert!(versions.objects.is_empty());
    e.trash_restore("bkt", "k", None, &root()).await.unwrap();
    assert_eq!(get(&e, "bkt", "k").await.unwrap(), b"two");
}

#[tokio::test]
async fn versioning_and_delete_markers() {
    let (_d, e) = setup().await;
    put(&e, "bkt", "k", b"null-version").await;
    e.put_bucket_versioning("bkt", true).await.unwrap();
    assert_eq!(e.get_bucket_versioning("bkt").unwrap(), Versioning::Enabled);
    let v1 = put(&e, "bkt", "k", b"v1").await;
    let v2 = put(&e, "bkt", "k", b"v2").await;
    let (v1, v2) = (v1.version_id.unwrap(), v2.version_id.unwrap());
    assert_ne!(v1, v2);
    let d = e.delete_object("bkt", "k", None, &root()).await.unwrap();
    assert!(d.delete_marker);
    let dm = d.version_id.unwrap();
    let err = e
        .get_object(
            GetObjectReq {
                bucket: "bkt".into(),
                key: "k".into(),
                ..Default::default()
            },
            false,
        )
        .await
        .err()
        .unwrap();
    assert_eq!(err.code, S3ErrorCode::NoSuchKey);
    assert!(
        err.headers
            .iter()
            .any(|(k, v)| k == "x-amz-delete-marker" && v == "true")
    );
    let by = |v: &str| GetObjectReq {
        bucket: "bkt".into(),
        key: "k".into(),
        version_id: Some(v.into()),
        ..Default::default()
    };
    assert_eq!(get_req(&e, by(&v1)).await.unwrap(), b"v1");
    assert_eq!(get_req(&e, by("null")).await.unwrap(), b"null-version");
    assert_eq!(
        get_req(&e, by(&dm)).await,
        Err(S3ErrorCode::MethodNotAllowed)
    );
    let vs = e
        .list_object_versions(
            "bkt",
            &ListVersionsReq {
                list: ListReq {
                    max: 1000,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    let ids: Vec<_> = vs.objects.iter().map(|o| o.version_id.clone()).collect();
    assert_eq!(ids, vec![dm.clone(), v2.clone(), v1.clone(), "null".into()]);
    assert!(vs.objects[0].is_latest && vs.objects[0].version.is_delete_marker());
    assert!(!vs.objects[1].is_latest);
    // Paging through versions with a version-id marker.
    let p1 = e
        .list_object_versions(
            "bkt",
            &ListVersionsReq {
                list: ListReq {
                    max: 2,
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
    assert!(p1.truncated);
    assert_eq!(p1.next_version.as_deref(), Some(v2.as_str()));
    let p2 = e
        .list_object_versions(
            "bkt",
            &ListVersionsReq {
                list: ListReq {
                    max: 2,
                    after: p1.next_key.clone(),
                    ..Default::default()
                },
                version_marker: p1.next_version.clone(),
                ..Default::default()
            },
        )
        .unwrap();
    let ids: Vec<_> = p2.objects.iter().map(|o| o.version_id.clone()).collect();
    assert_eq!(ids, vec![v1.clone(), "null".to_string()]);
    // Deleting the marker makes v2 current again.
    let d = e
        .delete_object("bkt", "k", Some(dm.clone()), &root())
        .await
        .unwrap();
    assert!(d.delete_marker);
    assert_eq!(get(&e, "bkt", "k").await.unwrap(), b"v2");
    // Version-specific delete of the current version falls back to v1.
    e.delete_object("bkt", "k", Some(v2.clone()), &root())
        .await
        .unwrap();
    assert_eq!(get(&e, "bkt", "k").await.unwrap(), b"v1");
    // Suspended: writes replace the single null version.
    e.put_bucket_versioning("bkt", false).await.unwrap();
    let s = put(&e, "bkt", "k", b"s1").await;
    assert_eq!(s.version_id.as_deref(), Some("null"));
    put(&e, "bkt", "k", b"s2").await;
    assert_eq!(get_req(&e, by("null")).await.unwrap(), b"s2");
    assert_eq!(get_req(&e, by(&v1)).await.unwrap(), b"v1");
}

#[tokio::test]
async fn copy_and_tagging() {
    let (_d, e) = setup().await;
    e.put_object(PutObjectReq {
        bucket: "bkt".into(),
        key: "src".into(),
        body: body_from_bytes("payload"),
        content_length: None,
        content_md5: None,
        checksum: ChecksumInput::None,
        meta: ObjectMeta {
            content_type: Some("text/plain".into()),
            user_metadata: BTreeMap::from([("a".into(), "1".into())]),
            ..Default::default()
        },
        tags: BTreeMap::from([("t".into(), "1".into())]),
        conditions: WriteConditions::default(),
        owner: root(),
    })
    .await
    .unwrap();
    let c = e
        .copy_object(CopyObjectReq {
            src_bucket: "bkt".into(),
            src_key: "src".into(),
            bucket: "bkt".into(),
            key: "dst".into(),
            owner: root(),
            ..Default::default()
        })
        .await
        .unwrap();
    let h = e
        .get_object(
            GetObjectReq {
                bucket: "bkt".into(),
                key: "dst".into(),
                ..Default::default()
            },
            true,
        )
        .await
        .unwrap();
    let body = h.version.body().unwrap().clone();
    assert_eq!(body.content_type.as_deref(), Some("text/plain"));
    assert_eq!(body.user_metadata.get("a").map(String::as_str), Some("1"));
    assert_eq!(c.put.etag, body.etag);
    assert_eq!(read_all(h.body.unwrap()).await, b"payload");
    let err = e
        .copy_object(CopyObjectReq {
            src_bucket: "bkt".into(),
            src_key: "src".into(),
            bucket: "bkt".into(),
            key: "src".into(),
            owner: root(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code, S3ErrorCode::InvalidRequest);
    e.copy_object(CopyObjectReq {
        src_bucket: "bkt".into(),
        src_key: "src".into(),
        bucket: "bkt".into(),
        key: "src".into(),
        metadata_directive: Directive::Replace,
        meta: ObjectMeta {
            content_type: Some("application/json".into()),
            ..Default::default()
        },
        owner: root(),
        ..Default::default()
    })
    .await
    .unwrap();
    let (tags, _) = e.get_object_tagging("bkt", "src", None).unwrap();
    assert_eq!(tags.len(), 1);
    e.put_object_tagging("bkt", "src", None, BTreeMap::new())
        .await
        .unwrap();
    assert!(
        e.get_object_tagging("bkt", "src", None)
            .unwrap()
            .0
            .is_empty()
    );
    let err = e
        .copy_object(CopyObjectReq {
            src_bucket: "bkt".into(),
            src_key: "src".into(),
            src_conditions: ReadConditions {
                if_none_match: Some("*".into()),
                ..Default::default()
            },
            bucket: "bkt".into(),
            key: "x".into(),
            owner: root(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code, S3ErrorCode::PreconditionFailed);
}

#[tokio::test]
async fn listing_prefix_delimiter_paging() {
    let (_d, e) = setup().await;
    for k in ["a/1", "a/2", "b", "c/x/1", "c/y", "d"] {
        put(&e, "bkt", k, b"z").await;
    }
    let l = |prefix: &str, delim: Option<&str>, after: Option<&str>, max| {
        e.list_objects(
            "bkt",
            &ListReq {
                prefix: prefix.into(),
                delimiter: delim.map(Into::into),
                after: after.map(Into::into),
                max,
                as_of: None,
            },
        )
        .unwrap()
    };
    let r = l("", Some("/"), None, 1000);
    let keys: Vec<_> = r.objects.iter().map(|o| o.version.key.clone()).collect();
    assert_eq!(keys, vec!["b", "d"]);
    assert_eq!(r.prefixes, vec!["a/", "c/"]);
    let r = l("c/", Some("/"), None, 1000);
    assert_eq!(r.prefixes, vec!["c/x/"]);
    assert_eq!(r.objects.len(), 1);
    let r = l("", Some("/"), None, 2);
    assert!(r.truncated);
    assert_eq!(r.next_key.as_deref(), Some("b"));
    let r2 = l("", Some("/"), r.next_key.as_deref(), 2);
    assert_eq!(r2.prefixes, vec!["c/"]);
    assert_eq!(r2.objects.len(), 1);
    assert!(!r2.truncated);
    assert!(l("", None, None, 0).objects.is_empty());
}

#[tokio::test]
async fn multipart_upload() {
    let (_d, e) = setup().await;
    put(&e, "bkt", "src", b"0123456789").await;
    let u = e
        .create_multipart_upload(CreateUploadReq {
            bucket: "bkt".into(),
            key: "big".into(),
            meta: ObjectMeta {
                content_type: Some("x/y".into()),
                ..Default::default()
            },
            owner: root(),
            ..Default::default()
        })
        .await
        .unwrap();
    let part = |n, data: &'static [u8]| UploadPartReq {
        bucket: "bkt".into(),
        key: "big".into(),
        upload_id: u.upload_id.clone(),
        part_number: n,
        body: body_from_bytes(data),
        content_length: Some(data.len() as u64),
        content_md5: None,
        checksum: ChecksumInput::None,
    };
    let p1 = e.upload_part(part(1, b"aaaaa")).await.unwrap();
    let p3 = e.upload_part(part(3, b"cc")).await.unwrap();
    let p2 = e
        .upload_part_copy(UploadPartCopyReq {
            src_bucket: "bkt".into(),
            src_key: "src".into(),
            range: Some((2, 7)),
            bucket: "bkt".into(),
            key: "big".into(),
            upload_id: u.upload_id.clone(),
            part_number: 2,
            ..Default::default()
        })
        .await
        .unwrap();
    let lp = e.list_parts("bkt", "big", &u.upload_id, None, 2).unwrap();
    assert_eq!(lp.parts.len(), 2);
    assert!(lp.truncated);
    assert_eq!(lp.next_marker, Some(2));
    let ups = e
        .list_multipart_uploads("bkt", "", None, None, None, 1000)
        .unwrap();
    assert_eq!(ups.uploads.len(), 1);
    let cp = |n, et: &str| CompletePart {
        number: n,
        etag: format!("\"{et}\""),
        checksum: None,
    };
    let err = e
        .complete_multipart_upload(CompleteReq {
            bucket: "bkt".into(),
            key: "big".into(),
            upload_id: u.upload_id.clone(),
            parts: vec![cp(2, &p2.etag), cp(1, &p1.etag)],
            owner: root(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code, S3ErrorCode::InvalidPartOrder);
    let err = e
        .complete_multipart_upload(CompleteReq {
            bucket: "bkt".into(),
            key: "big".into(),
            upload_id: u.upload_id.clone(),
            parts: vec![cp(1, "deadbeef")],
            owner: root(),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code, S3ErrorCode::InvalidPart);
    let done = e
        .complete_multipart_upload(CompleteReq {
            bucket: "bkt".into(),
            key: "big".into(),
            upload_id: u.upload_id.clone(),
            parts: vec![cp(1, &p1.etag), cp(2, &p2.etag), cp(3, &p3.etag)],
            owner: root(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(done.etag.ends_with("-3"));
    assert_eq!(get(&e, "bkt", "big").await.unwrap(), b"aaaaa234567cc");
    let r = e
        .get_object(
            GetObjectReq {
                bucket: "bkt".into(),
                key: "big".into(),
                part_number: Some(2),
                ..Default::default()
            },
            true,
        )
        .await
        .unwrap();
    assert_eq!(r.parts_count, Some(3));
    assert_eq!(read_all(r.body.unwrap()).await, b"234567");
    let ranged = get_req(
        &e,
        GetObjectReq {
            bucket: "bkt".into(),
            key: "big".into(),
            range: Some(RangeSpec::Int {
                first: 3,
                last: Some(11),
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(ranged, b"aa234567c");
    let err = e
        .abort_multipart_upload("bkt", "big", &u.upload_id)
        .await
        .unwrap_err();
    assert_eq!(err.code, S3ErrorCode::NoSuchUpload);
    // Abort releases parts.
    let u2 = e
        .create_multipart_upload(CreateUploadReq {
            bucket: "bkt".into(),
            key: "aborted".into(),
            owner: root(),
            ..Default::default()
        })
        .await
        .unwrap();
    e.upload_part(UploadPartReq {
        upload_id: u2.upload_id.clone(),
        key: "aborted".into(),
        ..part(1, b"unique-part-bytes")
    })
    .await
    .unwrap();
    e.abort_multipart_upload("bkt", "aborted", &u2.upload_id)
        .await
        .unwrap();
    assert!(
        e.list_multipart_uploads("bkt", "", None, None, None, 1000)
            .unwrap()
            .uploads
            .is_empty()
    );
}

#[tokio::test]
async fn gc_purges_expired_trash_and_unreferenced_blobs() {
    let (_d, e) = setup().await;
    put(&e, "bkt", "k", b"old-content").await;
    put(&e, "bkt", "k", b"new-content").await;
    put(&e, "bkt", "gone", b"deleted-content").await;
    e.delete_object("bkt", "gone", None, &root()).await.unwrap();
    let blob_count = || {
        let r = e.meta().read().unwrap();
        let mut n = 0;
        use cairn_engine::cairn_meta::{Flow, Reader, Table};
        r.scan(
            Table::Blobs,
            std::ops::Bound::Unbounded,
            std::ops::Bound::Unbounded,
            &mut |_, _| {
                n += 1;
                Ok(Flow::Continue)
            },
        )
        .unwrap();
        n
    };
    assert_eq!(blob_count(), 3);
    let s = e.gc_tick(Ts::now()).await.unwrap();
    assert_eq!(s, GcStats::default());
    let later = Ts::now().plus(DAY * 2);
    let s = e.gc_tick(later).await.unwrap();
    assert_eq!(s.versions_purged, 2);
    assert_eq!(s.blobs_deleted, 0, "grace period not yet over");
    let s = e
        .gc_tick(later.plus(Duration::from_secs(61)))
        .await
        .unwrap();
    assert_eq!(s.blobs_deleted, 2);
    assert_eq!(blob_count(), 1);
    assert_eq!(get(&e, "bkt", "k").await.unwrap(), b"new-content");
    assert!(e.trash_list("bkt", "", 10).unwrap().is_empty());
    // Trashed buckets are purged after their window.
    e.delete_object("bkt", "k", None, &root()).await.unwrap();
    e.delete_bucket("bkt", &root()).await.unwrap();
    let s = e.gc_tick(later.plus(DAY * 3)).await.unwrap();
    assert_eq!(s.buckets_purged, 1);
    assert!(e.trashed_buckets().unwrap().is_empty());
    e.gc_tick(later.plus(DAY * 4)).await.unwrap();
    assert_eq!(blob_count(), 0);
}

/// C2: random operation sequences interleaved with GC ticks never lose a referenced blob.
#[tokio::test]
async fn gc_never_deletes_referenced_blobs() {
    let (_d, e) = setup().await;
    e.create_bucket("ver", &root(), false, None).await.unwrap();
    e.put_bucket_versioning("ver", true).await.unwrap();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    const CONTENTS: [&[u8]; 4] = [b"alpha", b"bravo", b"charlie", b"delta"];
    let mut clock = Ts::now();
    let mut upload: Option<(String, String)> = None;
    for step in 0..300 {
        let bucket = if rnd(2) == 0 { "bkt" } else { "ver" };
        let key = format!("k{}", rnd(4));
        match rnd(8) {
            0..=2 => {
                put(&e, bucket, &key, CONTENTS[rnd(4) as usize]).await;
            }
            3 => {
                e.delete_object(bucket, &key, None, &root()).await.unwrap();
            }
            4 => {
                let _ = e
                    .copy_object(CopyObjectReq {
                        src_bucket: bucket.into(),
                        src_key: key.clone(),
                        bucket: bucket.into(),
                        key: format!("k{}", rnd(4)),
                        metadata_directive: Directive::Replace,
                        owner: root(),
                        ..Default::default()
                    })
                    .await;
            }
            5 => match upload.take() {
                None => {
                    let u = e
                        .create_multipart_upload(CreateUploadReq {
                            bucket: bucket.into(),
                            key: key.clone(),
                            owner: root(),
                            ..Default::default()
                        })
                        .await
                        .unwrap();
                    e.upload_part(UploadPartReq {
                        bucket: bucket.into(),
                        key: key.clone(),
                        upload_id: u.upload_id.clone(),
                        part_number: 1,
                        body: body_from_bytes(CONTENTS[rnd(4) as usize]),
                        content_length: None,
                        content_md5: None,
                        checksum: ChecksumInput::None,
                    })
                    .await
                    .unwrap();
                    upload = Some((bucket.to_string(), u.upload_id));
                }
                Some((b, id)) => {
                    let u = e.list_parts(&b, "", &id, None, 10);
                    if u.is_err() {
                        let key = e
                            .list_multipart_uploads(&b, "", None, None, None, 10)
                            .unwrap()
                            .uploads
                            .into_iter()
                            .find(|x| x.upload_id == id)
                            .unwrap()
                            .key;
                        let lp = e.list_parts(&b, &key, &id, None, 10).unwrap();
                        let parts = lp
                            .parts
                            .iter()
                            .map(|(p, _)| CompletePart {
                                number: p.number,
                                etag: p.etag.clone(),
                                checksum: None,
                            })
                            .collect();
                        e.complete_multipart_upload(CompleteReq {
                            bucket: b.clone(),
                            key,
                            upload_id: id,
                            parts,
                            owner: root(),
                            ..Default::default()
                        })
                        .await
                        .unwrap();
                    }
                }
            },
            _ => {
                clock = clock.plus(Duration::from_secs(rnd(3) * 43_200));
                e.gc_tick(clock).await.unwrap();
            }
        }
        // Invariant: every blob referenced by any stored version or open upload exists on disk.
        let r = e.meta().read().unwrap();
        for b in e.list_buckets().unwrap() {
            use cairn_engine::cairn_meta::{
                Flow, MultipartRecord, Reader, Table, VersionRecord, decode,
            };
            let mut refs = Vec::new();
            r.scan_prefix(Table::Versions, &b.id.to_bytes(), &mut |_, v| {
                refs.extend(decode::<VersionRecord>(v)?.blobs());
                Ok(Flow::Continue)
            })
            .unwrap();
            r.scan_prefix(Table::Uploads, &b.id.to_bytes(), &mut |_, v| {
                refs.extend(decode::<MultipartRecord>(v)?.parts.values().map(|p| p.blob));
                Ok(Flow::Continue)
            })
            .unwrap();
            for id in refs {
                assert!(
                    e.blobs().exists_sync(&id),
                    "step {step}: referenced blob {id} missing"
                );
                assert!(r.blob_ref(&id).unwrap().is_some_and(|x| x.refcount > 0));
            }
        }
    }
    for b in ["bkt", "ver"] {
        let l = e
            .list_objects(
                b,
                &ListReq {
                    max: 1000,
                    ..Default::default()
                },
            )
            .unwrap();
        for o in l.objects {
            get(&e, b, &o.version.key).await.unwrap();
        }
    }
}

#[tokio::test]
async fn recovery_after_unclean_shutdown() {
    let d = tempfile::tempdir().unwrap();
    let orphan_upload;
    {
        let e = open(d.path());
        e.create_bucket("bkt", &root(), false, None).await.unwrap();
        e.create_bucket("dead", &root(), false, None).await.unwrap();
        put(&e, "bkt", "k", b"committed").await;
        let u = e
            .create_multipart_upload(CreateUploadReq {
                bucket: "dead".into(),
                key: "x".into(),
                owner: root(),
                ..Default::default()
            })
            .await
            .unwrap();
        orphan_upload = u.upload_id.clone();
        e.upload_part(UploadPartReq {
            bucket: "dead".into(),
            key: "x".into(),
            upload_id: u.upload_id,
            part_number: 1,
            body: body_from_bytes("orphan-part"),
            content_length: None,
            content_md5: None,
            checksum: ChecksumInput::None,
        })
        .await
        .unwrap();
        // Simulate a crash: the bucket became trashed without its uploads being aborted, and the
        // `latest` row of `k` was lost.
        let dead = e.bucket("dead").unwrap();
        let bkt = e.bucket("bkt").unwrap();
        e.meta()
            .write(
                move |txn| -> Result<(), cairn_engine::cairn_meta::MetaError> {
                    let mut b = dead.clone();
                    b.state = cairn_engine::cairn_meta::BucketState::Trashed {
                        at: Ts::now(),
                        by: PrincipalId::root(),
                    };
                    txn.put_bucket(&b)?;
                    txn.unbind_bucket_name("dead")?;
                    txn.del(
                        cairn_engine::cairn_meta::Table::Latest,
                        &keys::bucket_key(bkt.id, "k"),
                    )?;
                    Ok(())
                },
            )
            .await
            .unwrap();
        // Stop the writer without a clean engine shutdown (RUNNING marker stays behind).
        e.meta().shutdown();
    }
    std::fs::write(d.path().join("tmp").join("half-written"), b"partial").unwrap();
    let orphan = d.path().join("blobs").join("ab").join("cd");
    std::fs::create_dir_all(&orphan).unwrap();
    let orphan = orphan.join(format!("abcd{}", "0".repeat(60)));
    std::fs::write(&orphan, b"orphan blob").unwrap();

    let e = open(d.path());
    let rep = e.recover(false).await.unwrap();
    assert!(rep.unclean_shutdown);
    assert_eq!(rep.tmp_removed, 1);
    assert_eq!(rep.uploads_aborted, 1);
    assert_eq!(rep.latest_repaired, 1);
    assert_eq!(rep.orphan_blobs_removed, 1);
    assert!(!orphan.exists());
    assert_eq!(get(&e, "bkt", "k").await.unwrap(), b"committed");
    let mut uploads = Vec::new();
    {
        use cairn_engine::cairn_meta::{Flow, Reader, Table};
        e.meta()
            .read()
            .unwrap()
            .scan(
                Table::Uploads,
                std::ops::Bound::Unbounded,
                std::ops::Bound::Unbounded,
                &mut |k, _| {
                    uploads.push(k.to_vec());
                    Ok(Flow::Continue)
                },
            )
            .unwrap();
    }
    assert!(
        uploads.is_empty(),
        "orphan upload {orphan_upload} still present"
    );
    e.shutdown();
    drop(e);
    let e = open(d.path());
    let rep = e.recover(false).await.unwrap();
    assert!(!rep.unclean_shutdown);
    assert_eq!(
        rep,
        RecoveryReport {
            latest_checked: rep.latest_checked,
            ..Default::default()
        }
    );
    e.shutdown();
}

#[tokio::test]
async fn multipart_checksums_composite_and_full_object() {
    use cairn_core::ChecksumAlgo;
    let (_d, e) = setup().await;
    for (algo, full) in [
        (ChecksumAlgo::Crc32, false),
        (ChecksumAlgo::Crc64Nvme, true),
    ] {
        let key = format!("ck-{}", algo.as_str());
        let u = e
            .create_multipart_upload(CreateUploadReq {
                bucket: "bkt".into(),
                key: key.clone(),
                checksum_algo: Some(algo),
                owner: root(),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut parts = Vec::new();
        for (n, data) in [(1u32, &b"hello"[..]), (2, &b"world"[..])] {
            let r = e
                .upload_part(UploadPartReq {
                    bucket: "bkt".into(),
                    key: key.clone(),
                    upload_id: u.upload_id.clone(),
                    part_number: n,
                    body: body_from_bytes(Bytes::from_static(data)),
                    content_length: None,
                    content_md5: None,
                    checksum: ChecksumInput::None,
                })
                .await
                .unwrap();
            parts.push(CompletePart {
                number: n,
                etag: r.etag,
                checksum: r.checksum.map(|c| c.1),
            });
        }
        let bad = e
            .complete_multipart_upload(CompleteReq {
                bucket: "bkt".into(),
                key: key.clone(),
                upload_id: u.upload_id.clone(),
                parts: vec![CompletePart {
                    checksum: Some("AAAAAA==".into()),
                    ..parts[0].clone()
                }],
                owner: root(),
                ..Default::default()
            })
            .await
            .unwrap_err();
        assert_eq!(bad.code, S3ErrorCode::InvalidPart);
        let done = e
            .complete_multipart_upload(CompleteReq {
                bucket: "bkt".into(),
                key: key.clone(),
                upload_id: u.upload_id.clone(),
                parts,
                owner: root(),
                ..Default::default()
            })
            .await
            .unwrap();
        let (a, v) = done.checksum.unwrap();
        assert_eq!(a, algo);
        if full {
            let whole = cairn_blob_checksum(algo, b"helloworld");
            assert_eq!(v, whole);
        } else {
            assert!(v.ends_with("-2"), "{v}");
        }
    }
}

fn cairn_blob_checksum(algo: cairn_core::ChecksumAlgo, data: &[u8]) -> String {
    use base64::Engine as _;
    let mut st = match algo {
        cairn_core::ChecksumAlgo::Crc64Nvme => crc64fast_nvme::Digest::new(),
        _ => unreachable!(),
    };
    st.write(data);
    base64::engine::general_purpose::STANDARD.encode(st.sum64().to_be_bytes())
}
