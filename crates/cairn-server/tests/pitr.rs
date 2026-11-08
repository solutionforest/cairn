//! Soft delete, shadow versions and time travel via `x-cairn-as-of`.

mod common;
use common::*;

fn now_nanos() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    d.as_nanos().to_string()
}

#[tokio::test]
async fn soft_delete_then_time_travel_read() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("ttx").await;
    env.put("ttx", "doc", "version one").await;
    env.put("ttx", "other", "unrelated").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let t1 = now_nanos();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    env.put("ttx", "doc", "version two").await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let t2 = now_nanos();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    s3.delete_object()
        .bucket("ttx")
        .key("doc")
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(s3.get_object().bucket("ttx").key("doc").send().await),
        "NoSuchKey"
    );

    let as_of = |t: String| {
        move |req: &mut aws_sdk_s3::config::http::HttpRequest| {
            req.headers_mut().insert("x-cairn-as-of", t.clone());
        }
    };
    let read_at = |t: String| {
        let s3 = s3.clone();
        async move {
            s3.get_object()
                .bucket("ttx")
                .key("doc")
                .customize()
                .mutate_request(as_of(t))
                .send()
                .await
        }
    };
    let g = read_at(t1.clone()).await.unwrap();
    assert_eq!(
        g.body.collect().await.unwrap().into_bytes().as_ref(),
        b"version one"
    );
    let g = read_at(t2.clone()).await.unwrap();
    assert_eq!(
        g.body.collect().await.unwrap().into_bytes().as_ref(),
        b"version two"
    );
    assert_eq!(code(read_at(now_nanos()).await), "NoSuchKey");

    // HEAD and ListObjectsV2 honour the header too.
    let h = s3
        .head_object()
        .bucket("ttx")
        .key("doc")
        .customize()
        .mutate_request(as_of(t1.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(h.content_length(), Some(11));
    let l = s3
        .list_objects_v2()
        .bucket("ttx")
        .customize()
        .mutate_request(as_of(t2.clone()))
        .send()
        .await
        .unwrap();
    let keys: Vec<_> = l.contents().iter().map(|o| o.key().unwrap()).collect();
    assert_eq!(keys, vec!["doc", "other"]);
    let l = s3.list_objects_v2().bucket("ttx").send().await.unwrap();
    assert_eq!(l.contents().len(), 1);

    // RFC 3339 form is accepted; garbage is rejected.
    let g = read_at("2000-01-01T00:00:00Z".into()).await;
    assert_eq!(code(g), "NoSuchKey");
    assert_eq!(code(read_at("yesterday".into()).await), "InvalidArgument");

    // x-cairn-include-trash lists soft-deleted and superseded versions.
    let lv = s3
        .list_object_versions()
        .bucket("ttx")
        .prefix("doc")
        .customize()
        .mutate_request(|r| {
            r.headers_mut().insert("x-cairn-include-trash", "true");
        })
        .send()
        .await
        .unwrap();
    assert_eq!(lv.versions().len(), 2);
    let lv = s3
        .list_object_versions()
        .bucket("ttx")
        .prefix("doc")
        .send()
        .await
        .unwrap();
    assert!(lv.versions().is_empty());
    env.stop().await;
}

fn pitr_body(bucket: &str, as_of: &str) -> serde_json::Value {
    serde_json::json!({ "bucket": bucket, "as_of": as_of })
}

/// Id of the trashed bucket `name` (admin API).
async fn trashed_id(node: &Node, name: &str) -> String {
    let v = node.admin("GET", "/buckets", None).await;
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == name && b["trashed"] == true)
        .unwrap_or_else(|| panic!("no trashed bucket {name}: {v}"))["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Claim 2 (A5): no snapshot was ever taken; a restore reaches an instant before a bucket
/// delete. The deleted bucket is addressed by identity (its id), never by name.
#[tokio::test]
async fn pitr_restore_to_instant_before_bucket_delete() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path()).await;
    let s3 = &node.s3;
    node.bucket("proj").await;
    node.put("proj", "a", "A1").await;
    node.put("proj", "b", "B1").await;
    let t0 = instant().await;
    node.put("proj", "a", "A2-longer").await;
    node.put("proj", "c", "C1").await;
    s3.delete_object()
        .bucket("proj")
        .key("b")
        .send()
        .await
        .unwrap();
    let t1 = instant().await;
    for k in ["a", "c"] {
        s3.delete_object()
            .bucket("proj")
            .key(k)
            .send()
            .await
            .unwrap();
    }
    s3.delete_bucket().bucket("proj").send().await.unwrap();
    let id = trashed_id(&node, "proj").await;

    // By name the bucket is gone, also for time travel.
    assert_eq!(
        node.get_as_of("proj", "a", &t0).await.unwrap_err(),
        "NoSuchBucket"
    );
    // By identity its history is intact.
    let bid: cairn_core::BucketId = id.parse().unwrap();
    let ts = |t: &str| cairn_core::Ts(t.parse::<jiff::Timestamp>().unwrap().as_nanosecond());
    let e = node.engine();
    assert!(
        e.pitr_head_at_id(bid, "a", ts(&t0))
            .unwrap()
            .unwrap()
            .body()
            .unwrap()
            .size
            == 2
    );
    assert!(e.pitr_head_at_id(bid, "b", ts(&t1)).unwrap().is_none());

    // Dry run plans the restore without bringing the bucket back.
    let mut dry = pitr_body("proj", &t0);
    dry["bucket_id"] = id.clone().into();
    dry["dry_run"] = true.into();
    let plan = node.admin("POST", "/pitr/restore", Some(dry)).await;
    assert_eq!(plan["changes"].as_array().unwrap().len(), 2, "{plan}");
    assert_eq!(
        code(s3.head_bucket().bucket("proj").send().await),
        "NotFound"
    );

    // Restore to t0: the bucket comes back with a=A1, b=B1 and no c.
    let blobs_before = blob_files(dir.path());
    let mut body = pitr_body("proj", &t0);
    body["bucket_id"] = id.clone().into();
    node.admin("POST", "/pitr/restore", Some(body)).await;
    assert_eq!(node.get("proj", "a").await, b"A1");
    assert_eq!(node.get("proj", "b").await, b"B1");
    assert_eq!(
        code(s3.get_object().bucket("proj").key("c").send().await),
        "NoSuchKey"
    );
    // Now it is live again, x-cairn-as-of by name works on it.
    assert_eq!(
        node.get_as_of("proj", "a", &t1).await.unwrap(),
        b"A2-longer"
    );

    // Then forward to t1, in place by name: a=A2, c=C1, b gone.
    node.admin("POST", "/pitr/restore", Some(pitr_body("proj", &t1)))
        .await;
    assert_eq!(node.get("proj", "a").await, b"A2-longer");
    assert_eq!(node.get("proj", "c").await, b"C1");
    assert_eq!(
        code(s3.get_object().bucket("proj").key("b").send().await),
        "NoSuchKey"
    );
    assert_eq!(
        blob_files(dir.path()),
        blobs_before,
        "PITR writes no blob bytes"
    );
    node.stop().await;
}

/// The bucket name was reused after the delete. A time-travel read by name resolves the bucket
/// that holds the name now and never leaks the old bucket's objects (whose policies may differ);
/// the old bucket is reachable only by identity. `cairn:TimeTravel` is still required.
#[tokio::test]
async fn time_travel_never_crosses_bucket_identity() {
    let dir = tempfile::tempdir().unwrap();
    let node = Node::open(dir.path()).await;
    let s3 = &node.s3;
    node.bucket("site").await;
    node.put("site", "index.html", "old site").await;
    node.put("site", "logo.png", "old logo").await;
    let t0 = instant().await;
    for k in ["index.html", "logo.png"] {
        s3.delete_object()
            .bucket("site")
            .key(k)
            .send()
            .await
            .unwrap();
    }
    s3.delete_bucket().bucket("site").send().await.unwrap();
    let old_id = trashed_id(&node, "site").await;
    node.bucket("site").await;
    node.put("site", "index.html", "new site").await;

    // By name: the new bucket did not exist at t0, so there is nothing to read.
    assert_eq!(node.get("site", "index.html").await, b"new site");
    assert_eq!(
        node.get_as_of("site", "index.html", &t0).await.unwrap_err(),
        "NoSuchKey"
    );
    let now = instant().await;
    assert_eq!(
        node.get_as_of("site", "index.html", &now).await.unwrap(),
        b"new site"
    );
    let t0c = t0.clone();
    let l = s3
        .list_objects_v2()
        .bucket("site")
        .customize()
        .mutate_request(move |r| {
            r.headers_mut().insert("x-cairn-as-of", t0c.clone());
        })
        .send()
        .await
        .unwrap();
    assert!(l.contents().is_empty(), "as-of list leaked the old bucket");

    // By identity: the old bucket's objects, restored into another bucket.
    let bid: cairn_core::BucketId = old_id.parse().unwrap();
    let at = cairn_core::Ts(t0.parse::<jiff::Timestamp>().unwrap().as_nanosecond());
    assert!(
        node.engine()
            .pitr_head_at_id(bid, "logo.png", at)
            .unwrap()
            .is_some()
    );
    node.bucket("site-old").await;
    let mut body = pitr_body("site", &t0);
    body["bucket_id"] = old_id.clone().into();
    body["target_bucket"] = "site-old".into();
    node.admin("POST", "/pitr/restore", Some(body)).await;
    assert_eq!(node.get("site-old", "index.html").await, b"old site");
    assert_eq!(node.get("site-old", "logo.png").await, b"old logo");
    assert_eq!(node.get("site", "index.html").await, b"new site");

    // A bucket id must belong to the bucket the request was authorized for.
    let mut body = pitr_body("site-old", &t0);
    body["bucket_id"] = old_id.into();
    body["target_bucket"] = "site-old".into();
    assert!(
        node.admin
            .call("POST", "/pitr/restore", &[], Some(&body))
            .await
            .is_err()
    );

    // Without cairn:TimeTravel a principal can read the present but not the past.
    let (reader, _) = node
        .user_with_policy(
            "reader",
            serde_json::json!({
                "Version": "2012-10-17",
                "Statement": [{ "Effect": "Allow", "Action": "s3:*", "Resource": "*" }]
            }),
        )
        .await;
    let body = reader
        .get_object()
        .bucket("site")
        .key("index.html")
        .send()
        .await
        .unwrap();
    assert_eq!(
        body.body.collect().await.unwrap().into_bytes().as_ref(),
        b"new site"
    );
    let nowc = now.clone();
    let r = reader
        .get_object()
        .bucket("site")
        .key("index.html")
        .customize()
        .mutate_request(move |r| {
            r.headers_mut().insert("x-cairn-as-of", nowc.clone());
        })
        .send()
        .await;
    assert_eq!(code(r), "AccessDenied");
    node.stop().await;
}

/// Retention GC: hidden versions and trashed buckets survive inside the window and are purged
/// (with their blobs) once it has passed; live data is never touched.
#[tokio::test]
async fn retention_gc_purges_after_window_only() {
    let dir = tempfile::tempdir().unwrap();
    let clock = std::sync::Arc::new(cairn_server::OffsetClock::new());
    let mut cfg = cairn_server::test_support::test_config(dir.path());
    cfg.retention.gc_interval = std::time::Duration::from_millis(50);
    let node = Node::start_with_clock(cfg, clock.clone()).await;
    let s3 = &node.s3;
    node.bucket("keep").await;
    node.bucket("gone").await;
    node.put("keep", "live", "live bytes").await;
    node.put("keep", "doc", "doc v1 superseded").await;
    node.put("keep", "doc", "doc v2 current").await;
    node.put("keep", "tmp", "deleted bytes").await;
    s3.delete_object()
        .bucket("keep")
        .key("tmp")
        .send()
        .await
        .unwrap();
    node.put("gone", "x", "bucket bytes").await;
    s3.delete_object()
        .bucket("gone")
        .key("x")
        .send()
        .await
        .unwrap();
    s3.delete_bucket().bucket("gone").send().await.unwrap();
    let t_old = instant().await;
    let (files_before, _) = blob_files(dir.path());
    assert_eq!(files_before, 5);

    let trash_len = |node: &Node| {
        let a = node.admin.clone();
        async move {
            a.call("GET", "/trash", &[("bucket", "keep".into())], None)
                .await
                .unwrap()["entries"]
                .as_array()
                .unwrap()
                .len()
        }
    };
    let trashed_buckets = |node: &Node| {
        let a = node.admin.clone();
        async move {
            a.call("GET", "/buckets", &[], None).await.unwrap()["items"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|b| b["trashed"] == true)
                .count()
        }
    };

    // Inside the 30-day window nothing goes.
    clock.advance(std::time::Duration::from_secs(29 * 86_400));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(trash_len(&node).await, 2);
    assert_eq!(trashed_buckets(&node).await, 1);
    assert_eq!(blob_files(dir.path()).0, 5);

    // Past it, GC purges hidden versions and the trashed bucket; blob files outlive their
    // last reference by `gc_grace`, then go too.
    clock.advance(std::time::Duration::from_secs(2 * 86_400));
    let mut ok = false;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if trash_len(&node).await == 0 && trashed_buckets(&node).await == 0 {
            ok = true;
            break;
        }
    }
    assert!(ok, "trash and trashed buckets purged");
    assert_eq!(blob_files(dir.path()).0, 5, "blobs kept for gc_grace");
    clock.advance(std::time::Duration::from_secs(3_601));
    let mut ok = false;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if blob_files(dir.path()).0 == 2 {
            ok = true;
            break;
        }
    }
    assert!(ok, "blobs={:?}", blob_files(dir.path()));
    assert_eq!(node.get("keep", "live").await, b"live bytes");
    assert_eq!(node.get("keep", "doc").await, b"doc v2 current");
    assert_eq!(
        node.get_as_of("keep", "tmp", &t_old).await.unwrap_err(),
        "NoSuchKey"
    );
    node.stop().await;
}
