//! `tidemark fsck`: inject each fault into a temp-dir engine, assert detection and safe repair.

mod support3b;

use std::time::Duration;
use support3b::*;
use tidemark_blob::{BlobStore, WriteOpts};
use tidemark_core::{BlobId, Ts};
use tidemark_engine::fsck::{DamageKind, FsckOptions, VerifyMode, version_damage};
use tidemark_engine::tidemark_meta::{BlobRef, MetaError, MetaStore, ReadExt, Table, encode, keys};
use tokio::io::AsyncWriteExt;

fn opts(repair: bool) -> FsckOptions {
    FsckOptions {
        verify: VerifyMode::Full,
        orphan_min_age: Duration::ZERO,
        repair,
    }
}

#[tokio::test]
async fn clean_store_is_clean() {
    let d = tempfile::tempdir().unwrap();
    let e = open(d.path());
    bucket(&e, "bkt", true).await;
    put(&e, "bkt", "a", b"hello").await;
    put(&e, "bkt", "a", b"hello2").await;
    put_multipart(&e, "bkt", "mp", &[data(10, 1), data(7, 2)]).await;
    e.delete_object("bkt", "a", None, &root()).await.unwrap();
    let r = e.fsck(opts(false)).await.unwrap();
    assert!(r.is_clean(), "{r:#?}");
    assert_eq!(r.blobs_verified, 4);
    assert_eq!(r.versions_scanned, 4);
}

#[tokio::test]
async fn orphan_blob_is_indexed_for_gc() {
    let d = tempfile::tempdir().unwrap();
    let e = open(d.path());
    bucket(&e, "bkt", false).await;
    put(&e, "bkt", "k", b"referenced").await;
    let mut w = e.blobs().begin_write(WriteOpts::default()).await.unwrap();
    w.write_all(b"nobody points at me").await.unwrap();
    let orphan = w.finish().await.unwrap().blob_id;
    let young = e.fsck(FsckOptions::default()).await.unwrap();
    assert!(
        young.orphan_blobs.is_empty(),
        "young files are in-flight uploads"
    );
    let r = e.fsck(opts(true)).await.unwrap();
    assert_eq!(r.orphan_blobs, vec![orphan]);
    assert_eq!(r.repaired.orphans_indexed, 1);
    assert!(e.blobs().exists_sync(&orphan), "fsck never unlinks");
    let row = e.meta().read().unwrap().blob_ref(&orphan).unwrap().unwrap();
    assert_eq!(row.refcount, 0);
    assert!(e.fsck(opts(false)).await.unwrap().is_clean());
    let st = e
        .gc_tick(Ts::now().plus(Duration::from_secs(120)))
        .await
        .unwrap();
    assert_eq!(st.blobs_deleted, 1);
    assert!(!e.blobs().exists_sync(&orphan));
    assert_eq!(get(&e, "bkt", "k").await.unwrap(), b"referenced");
}

#[tokio::test]
async fn missing_blob_marks_version_damaged() {
    let d = tempfile::tempdir().unwrap();
    let e = open(d.path());
    bucket(&e, "bkt", true).await;
    let v = put(&e, "bkt", "k", b"soon gone").await;
    let blob = v.version.blobs()[0];
    std::fs::remove_file(e.blobs().plain_path(&blob)).unwrap();
    let r = e.fsck(opts(true)).await.unwrap();
    assert_eq!(r.missing_blobs.len(), 1);
    assert_eq!(r.missing_blobs[0].blob, blob);
    assert_eq!(r.missing_blobs[0].versions[0].key, "k");
    assert_eq!(r.repaired.blobs_marked_damaged, 1);
    assert_eq!(r.repaired.versions_marked_damaged, 1);
    assert_eq!(r.damaged.len(), 1);
    assert_eq!(r.damaged[0].kind, DamageKind::Missing);
    let rd = e.meta().read().unwrap();
    let b = e.bucket("bkt").unwrap();
    let cur = rd.latest(b.id, "k").unwrap().unwrap();
    assert!(version_damage(&rd, b.id, &cur).unwrap().is_some());
    assert!(cur.is_live(), "the version is flagged, never deleted");
    let again = e.fsck(opts(true)).await.unwrap();
    assert_eq!(again.repaired.blobs_marked_damaged, 0, "idempotent");
}

#[tokio::test]
async fn refcount_drift_is_recounted() {
    let d = tempfile::tempdir().unwrap();
    let e = open(d.path());
    bucket(&e, "bkt", true).await;
    let a = put(&e, "bkt", "a", b"shared").await.version.blobs()[0];
    put(&e, "bkt", "a2", b"shared").await;
    let c = put(&e, "bkt", "c", b"other").await.version.blobs()[0];
    e.meta()
        .write(move |txn| -> Result<(), MetaError> {
            let bad = BlobRef {
                refcount: 7,
                size: 6,
                last_unref_at: None,
            };
            txn.put(Table::Blobs, a.as_bytes(), &encode(&bad))?;
            txn.del(Table::Blobs, c.as_bytes())?;
            Ok(())
        })
        .await
        .unwrap();
    let r = e.fsck(opts(true)).await.unwrap();
    let mut drift: Vec<(BlobId, Option<u32>, u32)> = r
        .refcount_drift
        .iter()
        .map(|d| (d.blob, d.stored, d.actual))
        .collect();
    drift.sort();
    let mut want = vec![(a, Some(7), 2), (c, None, 1)];
    want.sort();
    assert_eq!(drift, want);
    assert_eq!(r.repaired.refcounts_fixed, 2);
    let rd = e.meta().read().unwrap();
    assert_eq!(rd.blob_ref(&a).unwrap().unwrap().refcount, 2);
    assert_eq!(rd.blob_ref(&c).unwrap().unwrap().refcount, 1);
    drop(rd);
    assert!(e.fsck(opts(false)).await.unwrap().is_clean());
}

#[tokio::test]
async fn corrupt_blob_detected_flagged_and_cleared_when_healed() {
    let d = tempfile::tempdir().unwrap();
    let e = open(d.path());
    bucket(&e, "bkt", true).await;
    let v = put(&e, "bkt", "k", b"precious bytes").await;
    let blob = v.version.blobs()[0];
    let path = e.blobs().plain_path(&blob);
    std::fs::write(&path, b"precioUs bytes").unwrap();
    let quick = e.fsck(FsckOptions::default()).await.unwrap();
    assert!(
        quick.corrupt_blobs.is_empty(),
        "no re-hash in VerifyMode::None"
    );
    let r = e.fsck(opts(true)).await.unwrap();
    assert_eq!(r.corrupt_blobs.len(), 1);
    assert_eq!(r.corrupt_blobs[0].blob, blob);
    assert_eq!(r.damaged[0].kind, DamageKind::Corrupt);
    let sample = e
        .fsck(FsckOptions {
            verify: VerifyMode::Sample(10),
            orphan_min_age: Duration::ZERO,
            repair: false,
        })
        .await
        .unwrap();
    assert_eq!(sample.corrupt_blobs.len(), 1);
    std::fs::write(&path, b"precious bytes").unwrap();
    let healed = e.fsck(opts(true)).await.unwrap();
    assert_eq!(healed.repaired.damage_cleared, 1);
    assert!(healed.damaged.is_empty());
    let rd = e.meta().read().unwrap();
    let b = e.bucket("bkt").unwrap();
    assert!(version_damage(&rd, b.id, &v.version).unwrap().is_none());
}

#[tokio::test]
async fn dangling_upload_and_latest_mismatch_repaired() {
    let d = tempfile::tempdir().unwrap();
    let e = open(d.path());
    bucket(&e, "bkt", true).await;
    put(&e, "bkt", "k", b"v1").await;
    let up = e
        .create_multipart_upload(tidemark_engine::CreateUploadReq {
            bucket: "bkt".into(),
            key: "up".into(),
            owner: root(),
            ..Default::default()
        })
        .await
        .unwrap();
    let bid = e.bucket("bkt").unwrap().id;
    let uid = up.upload_id.clone();
    e.meta()
        .write(move |txn| -> Result<(), MetaError> {
            txn.del(Table::UploadsByKey, &keys::upload_by_key(bid, "up", &uid))?;
            txn.del(Table::Latest, &keys::bucket_key(bid, "k"))?;
            Ok(())
        })
        .await
        .unwrap();
    let r = e.fsck(opts(true)).await.unwrap();
    assert_eq!(r.dangling_uploads.len(), 1);
    assert_eq!(r.dangling_uploads[0].upload_id, up.upload_id);
    assert_eq!(r.latest_mismatch, vec![(bid, "k".to_string())]);
    assert!(r.repaired.uploads_cleaned >= 1);
    assert_eq!(r.repaired.latest_fixed, 1);
    assert!(e.fsck(opts(false)).await.unwrap().is_clean());
    assert_eq!(get(&e, "bkt", "k").await.unwrap(), b"v1");
}
