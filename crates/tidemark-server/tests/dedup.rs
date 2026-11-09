//! Claim 3 (A7): identical content costs disk once. N uploads of the same bytes leave one blob
//! file; CopyObject, trash restore and PITR restore add zero blob bytes. The same holds with
//! encryption at rest.

mod common;
use common::*;
use serde_json::json;

fn payload() -> Vec<u8> {
    (0..300_000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

async fn prove_dedup(node: &Node, dir: &std::path::Path) {
    let s3 = &node.s3;
    let data = payload();
    node.bucket("one").await;
    node.bucket("two").await;
    assert_eq!(blob_files(dir), (0, 0));

    // N identical uploads across keys and buckets: one blob file.
    for i in 0..5 {
        node.put("one", &format!("copy-{i}"), data.clone()).await;
        node.put("two", &format!("dir/{i}"), data.clone()).await;
    }
    let (files, bytes) = blob_files(dir);
    assert_eq!(files, 1, "ten identical uploads -> one blob file");
    assert!(bytes >= data.len() as u64);
    let baseline = (files, bytes);

    // Overwriting with the same bytes adds nothing either.
    node.put("one", "copy-0", data.clone()).await;
    assert_eq!(blob_files(dir), baseline);

    // CopyObject within and across buckets.
    s3.copy_object()
        .bucket("one")
        .key("copied")
        .copy_source("one/copy-1")
        .send()
        .await
        .unwrap();
    s3.copy_object()
        .bucket("two")
        .key("copied")
        .copy_source("one/copy-2")
        .send()
        .await
        .unwrap();
    assert_eq!(node.get("two", "copied").await, data);
    assert_eq!(blob_files(dir), baseline, "CopyObject wrote blob bytes");

    // Delete, then restore from the trash.
    let t_before_delete = instant().await;
    for k in ["copy-3", "copy-4"] {
        s3.delete_object()
            .bucket("one")
            .key(k)
            .send()
            .await
            .unwrap();
    }
    node.admin(
        "POST",
        "/trash/restore",
        Some(json!({ "bucket": "one", "key": "copy-3" })),
    )
    .await;
    assert_eq!(node.get("one", "copy-3").await, data);
    assert_eq!(blob_files(dir), baseline, "trash restore wrote blob bytes");

    // PITR restore in place and into another bucket.
    node.admin(
        "POST",
        "/pitr/restore",
        Some(json!({ "bucket": "one", "as_of": t_before_delete })),
    )
    .await;
    assert_eq!(node.get("one", "copy-4").await, data);
    node.bucket("three").await;
    node.admin(
        "POST",
        "/pitr/restore",
        Some(json!({
            "bucket": "one",
            "as_of": t_before_delete,
            "target_bucket": "three",
        })),
    )
    .await;
    assert_eq!(node.get("three", "copy-0").await, data);
    assert_eq!(blob_files(dir), baseline, "PITR restore wrote blob bytes");

    // Different bytes do cost a new blob (the walk is not vacuous).
    node.put("one", "different", b"something else".to_vec())
        .await;
    assert_eq!(blob_files(dir).0, 2);
}

#[tokio::test]
async fn identical_content_costs_disk_once() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path()).await;
    prove_dedup(&node, dir.path()).await;
    node.stop().await;
}

#[tokio::test]
async fn encrypted_store_dedups_and_never_writes_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = tidemark_server::test_support::test_config(dir.path());
    cfg.storage.encrypt_at_rest = true;
    let node = Node::start(cfg).await;
    prove_dedup(&node, dir.path()).await;
    let needle = &payload()[1000..1064];
    assert!(
        !tree_contains(&dir.path().join("blobs"), needle),
        "plaintext found in blobs/"
    );
    node.stop().await;
}
