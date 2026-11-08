//! D4 lifecycle on a schedule: the server's lifecycle worker expires objects and aborts
//! incomplete multipart uploads by rule, and the GC worker then purges and unlinks their blobs.
//! Time is a fake clock handed to the workers; the test jumps it by days and waits only for
//! counted worker passes (`cairn_lifecycle_runs_total`, `cairn_gc_runs_total`), never for
//! wall-clock time to elapse.

mod common;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{
    AbortIncompleteMultipartUpload, BucketLifecycleConfiguration, ExpirationStatus,
    LifecycleExpiration, LifecycleRule, LifecycleRuleFilter,
};
use common::*;
use std::sync::Arc;
use std::time::{Duration, Instant};

const DAY: Duration = Duration::from_secs(86_400);

fn bytes(tag: &str) -> Vec<u8> {
    format!("{tag}:")
        .into_bytes()
        .into_iter()
        .cycle()
        .take(4096)
        .collect()
}

/// Wait until `c` has counted `n` more passes than it had on entry.
async fn passes(c: &prometheus::IntCounter, n: u64) {
    let want = c.get() + n;
    let deadline = Instant::now() + Duration::from_secs(30);
    while c.get() < want {
        assert!(Instant::now() < deadline, "worker stopped ticking");
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Two full lifecycle passes, then two full GC passes, all started after the clock moved.
async fn settle(node: &Node) {
    passes(&node.metrics.lifecycle_runs, 2).await;
    passes(&node.metrics.gc_runs, 2).await;
}

async fn uploads(node: &Node) -> Vec<String> {
    let mut keys: Vec<String> = node
        .s3
        .list_multipart_uploads()
        .bucket("lcy")
        .send()
        .await
        .unwrap()
        .uploads
        .unwrap_or_default()
        .into_iter()
        .map(|u| u.key.unwrap())
        .collect();
    keys.sort();
    keys
}

async fn exists(node: &Node, key: &str) -> bool {
    match node.s3.head_object().bucket("lcy").key(key).send().await {
        Ok(_) => true,
        Err(e) => {
            assert_eq!(status(Err::<(), _>(e)), 404);
            false
        }
    }
}

async fn start_upload(node: &Node, key: &str, data: Vec<u8>) {
    let id = node
        .s3
        .create_multipart_upload()
        .bucket("lcy")
        .key(key)
        .send()
        .await
        .unwrap()
        .upload_id
        .unwrap();
    node.s3
        .upload_part()
        .bucket("lcy")
        .key(key)
        .upload_id(id)
        .part_number(1)
        .body(ByteStream::from(data))
        .send()
        .await
        .unwrap();
}

async fn trash(node: &Node) -> String {
    node.admin
        .call("GET", "/trash", &[("bucket", "lcy".into())], None)
        .await
        .unwrap()
        .to_string()
}

fn on_disk(dir: &std::path::Path, tag: &str) -> bool {
    tree_contains(&dir.join("blobs"), &bytes(tag)[..64])
}

#[tokio::test]
async fn expiration_and_abort_mpu_run_on_schedule_then_gc_unlinks() {
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(cairn_server::OffsetClock::new());
    let mut cfg = cairn_server::test_support::test_config(dir.path());
    cfg.retention.lifecycle_interval = Duration::from_millis(20);
    cfg.retention.gc_interval = Duration::from_millis(20);
    cfg.retention.soft_delete = DAY;
    cfg.retention.gc_grace = Duration::from_secs(3600);
    let node = Node::start_with_clock(cfg, clock.clone()).await;
    let d = dir.path();

    node.bucket("lcy").await;
    node.put("lcy", "logs/old", bytes("expire-me")).await;
    node.put("lcy", "keep/x", bytes("keep-me")).await;
    start_upload(&node, "logs/mpu", bytes("abort-me")).await;
    start_upload(&node, "keep/mpu", bytes("keep-upload")).await;
    node.s3
        .put_bucket_lifecycle_configuration()
        .bucket("lcy")
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(
                    LifecycleRule::builder()
                        .id("logs")
                        .status(ExpirationStatus::Enabled)
                        .filter(LifecycleRuleFilter::builder().prefix("logs/").build())
                        .expiration(LifecycleExpiration::builder().days(30).build())
                        .abort_incomplete_multipart_upload(
                            AbortIncompleteMultipartUpload::builder()
                                .days_after_initiation(7)
                                .build(),
                        )
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let rules = node
        .s3
        .get_bucket_lifecycle_configuration()
        .bucket("lcy")
        .send()
        .await
        .unwrap()
        .rules
        .unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].expiration.as_ref().unwrap().days, Some(30));
    let all = ["expire-me", "keep-me", "abort-me", "keep-upload"];
    let present = |tags: &[&str]| all.iter().all(|t| on_disk(d, t) == tags.contains(t));

    // Day 0: workers run, nothing is due.
    settle(&node).await;
    assert!(exists(&node, "logs/old").await);
    assert_eq!(uploads(&node).await, ["keep/mpu", "logs/mpu"]);
    assert!(present(&all));

    // Day 8: the matching incomplete upload is aborted; objects are not yet due.
    clock.advance(8 * DAY);
    settle(&node).await;
    assert_eq!(uploads(&node).await, ["keep/mpu"]);
    assert!(exists(&node, "logs/old").await);
    assert!(exists(&node, "keep/x").await);

    // Day 31: `logs/old` expires into the trash (restorable for `soft_delete`); the aborted
    // upload's part blob has outlived `gc_grace` and is unlinked.
    clock.advance(23 * DAY);
    settle(&node).await;
    assert!(!exists(&node, "logs/old").await);
    assert!(exists(&node, "keep/x").await);
    assert_eq!(node.get("lcy", "keep/x").await, bytes("keep-me"));
    assert!(present(&["expire-me", "keep-me", "keep-upload"]));
    let listed = trash(&node).await;
    assert!(listed.contains("logs/old"), "{listed}");

    // Day 33: past the soft-delete window GC purges the expired version; its blob waits out
    // `gc_grace` measured from the purge.
    clock.advance(2 * DAY);
    settle(&node).await;
    let listed = trash(&node).await;
    assert!(!listed.contains("logs/old"), "{listed}");
    assert!(on_disk(d, "expire-me"), "unlinked inside gc_grace");

    // Two hours later the blob is gone; everything outside the rule is untouched.
    clock.advance(Duration::from_secs(2 * 3600));
    settle(&node).await;
    assert!(present(&["keep-me", "keep-upload"]));
    assert_eq!(blob_files(d).0, 2);
    assert_eq!(uploads(&node).await, ["keep/mpu"]);
    assert_eq!(node.get("lcy", "keep/x").await, bytes("keep-me"));
    node.stop().await;
}
