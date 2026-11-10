//! C6: when free space falls below `storage.min_free`, writes of new bytes get `507` while the
//! server stays up and GET, DELETE, copy (no new bytes), trash restore and GC keep working.

mod common;
use aws_sdk_s3::primitives::ByteStream;
use common::*;
use serde_json::json;

#[tokio::test]
async fn disk_full_returns_507_and_reads_deletes_gc_keep_working() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = tidemark_server::test_support::test_config(dir.path());
    cfg.storage.min_free = 0;
    let node = Node::start(cfg.clone()).await;
    node.bucket("full").await;
    node.put("full", "keep", "kept bytes").await;
    node.put("full", "drop", "dropped bytes").await;
    node.stop().await;

    // Same data directory, but now the reserve can never be met: the disk is "full".
    cfg.storage.min_free = u64::MAX / 4;
    cfg.retention.gc_interval = std::time::Duration::from_millis(50);
    let clock = std::sync::Arc::new(tidemark_server::OffsetClock::new());
    let node = Node::start_with_clock(cfg.clone(), clock.clone()).await;
    let s3 = &node.s3;

    let r = s3
        .put_object()
        .bucket("full")
        .key("new")
        .body(ByteStream::from_static(b"new bytes"))
        .send()
        .await;
    assert_eq!(status(r), 507);
    let up = s3
        .create_multipart_upload()
        .bucket("full")
        .key("mpu")
        .send()
        .await
        .unwrap();
    let r = s3
        .upload_part()
        .bucket("full")
        .key("mpu")
        .upload_id(up.upload_id().unwrap())
        .part_number(1)
        .body(ByteStream::from_static(b"part bytes"))
        .send()
        .await;
    assert_eq!(status(r), 507);
    s3.abort_multipart_upload()
        .bucket("full")
        .key("mpu")
        .upload_id(up.upload_id().unwrap())
        .send()
        .await
        .unwrap();

    // Reads, deletes, metadata-only writes and restores still work.
    assert_eq!(node.get("full", "keep").await, b"kept bytes");
    s3.copy_object()
        .bucket("full")
        .key("keep-copy")
        .copy_source("full/keep")
        .send()
        .await
        .unwrap();
    assert_eq!(node.get("full", "keep-copy").await, b"kept bytes");
    s3.delete_object()
        .bucket("full")
        .key("drop")
        .send()
        .await
        .unwrap();
    node.admin(
        "POST",
        "/trash/restore",
        Some(json!({ "bucket": "full", "key": "drop" })),
    )
    .await;
    assert_eq!(node.get("full", "drop").await, b"dropped bytes");
    s3.delete_object()
        .bucket("full")
        .key("drop")
        .send()
        .await
        .unwrap();
    let ready = reqwest::get(format!("http://{}/readyz", node.addr))
        .await
        .unwrap();
    assert!(ready.status().is_success());

    // GC frees space: past retention and grace the deleted blob is unlinked.
    let before = blob_files(dir.path()).0;
    clock.advance(std::time::Duration::from_secs(31 * 86_400));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    clock.advance(std::time::Duration::from_secs(3_601));
    let mut ok = false;
    for _ in 0..300 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if blob_files(dir.path()).0 == before - 1 {
            ok = true;
            break;
        }
    }
    assert!(
        ok,
        "gc did not unlink on a full disk: {:?}",
        blob_files(dir.path())
    );
    assert_eq!(node.get("full", "keep").await, b"kept bytes");
    node.stop().await;

    cfg.storage.min_free = 0;
    let node = Node::start(cfg).await;
    assert_eq!(node.get("full", "keep").await, b"kept bytes");
    assert_eq!(node.get("full", "keep-copy").await, b"kept bytes");
    node.put("full", "after-recovery", "new bytes").await;
    assert_eq!(node.get("full", "after-recovery").await, b"new bytes");
    node.stop().await;
}
