//! Claim 1 (A6): zero-config undo. A bucket whose versioning was never touched loses nothing to
//! an overwrite, an object delete and a bucket delete; the admin API brings back the bucket and
//! every version byte-identical.

mod common;
use common::*;
use serde_json::json;

#[tokio::test]
async fn zero_config_undo_restores_bucket_and_every_version() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path()).await;
    let s3 = &node.s3;
    node.bucket("photos").await;
    let v = s3
        .get_bucket_versioning()
        .bucket("photos")
        .send()
        .await
        .unwrap();
    assert!(v.status().is_none(), "versioning must never have been set");

    let v1: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    let v2: Vec<u8> = b"the overwrite that was a mistake".to_vec();
    let other: Vec<u8> = b"another key".to_vec();
    node.put("photos", "cat.jpg", v1.clone()).await;
    node.put("photos", "dog.jpg", other.clone()).await;
    node.put("photos", "cat.jpg", v2.clone()).await;
    s3.delete_object()
        .bucket("photos")
        .key("cat.jpg")
        .send()
        .await
        .unwrap();
    s3.delete_object()
        .bucket("photos")
        .key("dog.jpg")
        .send()
        .await
        .unwrap();
    s3.delete_bucket().bucket("photos").send().await.unwrap();
    assert_eq!(
        code(s3.head_bucket().bucket("photos").send().await),
        "NotFound"
    );

    // The bucket is in the trash; restore it through the admin API.
    let buckets = node.admin("GET", "/buckets", None).await;
    let trashed: Vec<_> = buckets["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|b| b["name"] == "photos" && b["trashed"] == true)
        .collect();
    assert_eq!(trashed.len(), 1, "{buckets}");
    let id = trashed[0]["id"].as_str().unwrap().to_string();
    node.admin(
        "POST",
        "/trash/restore-bucket",
        Some(json!({ "bucket_id": id })),
    )
    .await;
    s3.head_bucket().bucket("photos").send().await.unwrap();

    // Every version that ever existed is in the trash.
    let trash = node
        .admin
        .call("GET", "/trash", &[("bucket", "photos".into())], None)
        .await
        .unwrap();
    let entries = trash["entries"].as_array().unwrap();
    let cat: Vec<_> = entries.iter().filter(|e| e["key"] == "cat.jpg").collect();
    assert_eq!(cat.len(), 2, "{trash}");
    let size_of = |e: &serde_json::Value| e["size"].as_u64().unwrap() as usize;
    let old = cat.iter().find(|e| size_of(e) == v1.len()).unwrap();
    let new = cat.iter().find(|e| size_of(e) == v2.len()).unwrap();
    assert_eq!(old["reason"], "Superseded");
    assert_eq!(new["reason"], "Api");

    // Restore the oldest version first, then the newest: both byte-identical.
    for (entry, want) in [(old, &v1), (new, &v2)] {
        node.admin(
            "POST",
            "/trash/restore",
            Some(json!({
                "bucket": "photos",
                "key": "cat.jpg",
                "version_id": entry["version_id"],
            })),
        )
        .await;
        assert_eq!(&node.get("photos", "cat.jpg").await, want);
    }
    node.admin(
        "POST",
        "/trash/restore",
        Some(json!({ "bucket": "photos", "key": "dog.jpg" })),
    )
    .await;
    assert_eq!(node.get("photos", "dog.jpg").await, other);

    // The restored history is still there: v1 is the superseded version of v2 again.
    let lv = s3.list_objects_v2().bucket("photos").send().await.unwrap();
    let keys: Vec<_> = lv.contents().iter().map(|o| o.key().unwrap()).collect();
    assert_eq!(keys, vec!["cat.jpg", "dog.jpg"]);
    let trash = node
        .admin
        .call(
            "GET",
            "/trash",
            &[("bucket", "photos".into()), ("prefix", "cat".into())],
            None,
        )
        .await
        .unwrap();
    assert!(
        trash["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| size_of(e) == v1.len()),
        "{trash}"
    );
    node.stop().await;
}

#[tokio::test]
async fn restored_bucket_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path()).await;
    node.bucket("logs").await;
    node.put("logs", "a", "alpha").await;
    node.s3
        .delete_object()
        .bucket("logs")
        .key("a")
        .send()
        .await
        .unwrap();
    node.s3.delete_bucket().bucket("logs").send().await.unwrap();
    node.stop().await;

    let node = Node::open(dir.path()).await;
    let buckets = node.admin("GET", "/buckets", None).await;
    let id = buckets["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == "logs" && b["trashed"] == true)
        .unwrap()["id"]
        .clone();
    node.admin(
        "POST",
        "/trash/restore-bucket",
        Some(json!({ "bucket_id": id })),
    )
    .await;
    node.admin(
        "POST",
        "/trash/restore",
        Some(json!({ "bucket": "logs", "key": "a" })),
    )
    .await;
    assert_eq!(node.get("logs", "a").await, b"alpha");
    node.stop().await;
}
