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

/// The CLI leg of claim 1: `tidemark admin trash restore --bucket NAME` (no `--key`) undoes a
/// bucket delete in one command, bringing back the bucket and every version of every key.
/// Driven through the same argument parser and client the `tidemark` binary mounts as `admin`.
#[tokio::test]
async fn cli_trash_restore_brings_back_whole_bucket_in_one_command() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path()).await;
    let s3 = &node.s3;
    node.bucket("photos").await;
    let v1: Vec<u8> = (0..50_000u32).map(|i| (i % 253) as u8).collect();
    node.put("photos", "cat.jpg", v1.clone()).await;
    node.put("photos", "cat.jpg", "cat v2").await;
    node.put("photos", "dir/dog.jpg", "dog").await;
    for k in ["cat.jpg", "dir/dog.jpg"] {
        s3.delete_object()
            .bucket("photos")
            .key(k)
            .send()
            .await
            .unwrap();
    }
    s3.delete_bucket().bucket("photos").send().await.unwrap();
    let blobs = blob_files(dir.path());

    let endpoint = format!("http://{}", node.addr);
    let args = [
        "admin",
        "--endpoint",
        endpoint.as_str(),
        "--access-key",
        tidemark_server::test_support::TEST_ACCESS_KEY,
        "--secret-key",
        tidemark_server::test_support::TEST_SECRET_KEY,
        "--json",
        "trash",
        "restore",
        "--bucket",
        "photos",
    ];
    let m = tidemark_admin::cli::cli()
        .try_get_matches_from(args)
        .unwrap();
    let client = tidemark_admin::cli::client_from_matches(&m).unwrap();
    let mut out = String::new();
    tidemark_admin::cli::run_to(&m, &client, &mut out)
        .await
        .unwrap();
    assert!(out.contains("\"photos\""), "{out}");

    // Current state is what it was right before the deletes.
    assert_eq!(node.get("photos", "cat.jpg").await, b"cat v2");
    assert_eq!(node.get("photos", "dir/dog.jpg").await, b"dog");
    // Every version is back in the key's history: the replayed copy of v1 sits in the trash
    // as the version v2 superseded, and comes back byte-identical.
    let trash = node
        .admin
        .call(
            "GET",
            "/trash",
            &[("bucket", "photos".into()), ("prefix", "cat.jpg".into())],
            None,
        )
        .await
        .unwrap();
    let v1_entries: Vec<_> = trash["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["size"] == v1.len())
        .collect();
    assert_eq!(v1_entries.len(), 2, "original + replayed v1: {trash}");
    for e in v1_entries {
        node.admin(
            "POST",
            "/trash/restore",
            Some(json!({ "bucket": "photos", "key": "cat.jpg", "version_id": e["version_id"] })),
        )
        .await;
        assert_eq!(node.get("photos", "cat.jpg").await, v1);
    }
    assert_eq!(blob_files(dir.path()), blobs, "undo wrote blob bytes");
    node.stop().await;
}
