//! Versioning semantics: null versions, delete markers, ListObjectVersions ordering, suspended
//! state, version-specific reads and deletes.

mod common;
use aws_sdk_s3::types::{BucketVersioningStatus, VersioningConfiguration};
use common::*;

async fn set_versioning(env: &Env, b: &str, on: bool) {
    let st = if on {
        BucketVersioningStatus::Enabled
    } else {
        BucketVersioningStatus::Suspended
    };
    env.s3
        .put_bucket_versioning()
        .bucket(b)
        .versioning_configuration(VersioningConfiguration::builder().status(st).build())
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn versioning_and_delete_marker_lifecycle() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("ver").await;
    env.put("ver", "k", "pre-versioning").await;
    set_versioning(&env, "ver", true).await;
    let v1 = s3
        .put_object()
        .bucket("ver")
        .key("k")
        .body("one".as_bytes().to_vec().into())
        .send()
        .await
        .unwrap()
        .version_id
        .unwrap();
    let v2 = s3
        .put_object()
        .bucket("ver")
        .key("k")
        .body("two".as_bytes().to_vec().into())
        .send()
        .await
        .unwrap()
        .version_id
        .unwrap();
    assert_ne!(v1, v2);
    assert_eq!(env.get("ver", "k").await, b"two");

    // DeleteObject without a version creates a delete marker.
    let d = s3
        .delete_object()
        .bucket("ver")
        .key("k")
        .send()
        .await
        .unwrap();
    assert_eq!(d.delete_marker(), Some(true));
    let dm = d.version_id.unwrap();
    let e = s3
        .get_object()
        .bucket("ver")
        .key("k")
        .send()
        .await
        .unwrap_err();
    let raw = e.raw_response().unwrap();
    assert_eq!(raw.status().as_u16(), 404);
    assert_eq!(raw.headers().get("x-amz-delete-marker"), Some("true"));
    assert_eq!(raw.headers().get("x-amz-version-id"), Some(dm.as_str()));
    // GET of the marker by version id → 405.
    assert_eq!(
        status(
            s3.get_object()
                .bucket("ver")
                .key("k")
                .version_id(&dm)
                .send()
                .await
        ),
        405
    );
    // Older versions stay readable.
    let g = s3
        .get_object()
        .bucket("ver")
        .key("k")
        .version_id(&v1)
        .send()
        .await
        .unwrap();
    assert_eq!(g.version_id(), Some(v1.as_str()));
    let g = s3
        .get_object()
        .bucket("ver")
        .key("k")
        .version_id("null")
        .send()
        .await
        .unwrap();
    assert_eq!(
        g.body.collect().await.unwrap().into_bytes().as_ref(),
        b"pre-versioning"
    );
    let l = s3.list_objects_v2().bucket("ver").send().await.unwrap();
    assert_eq!(l.key_count(), Some(0));

    // ListObjectVersions: newest first, delete markers separate, IsLatest on the marker.
    let lv = s3
        .list_object_versions()
        .bucket("ver")
        .send()
        .await
        .unwrap();
    let vids: Vec<_> = lv
        .versions()
        .iter()
        .map(|v| v.version_id().unwrap().to_string())
        .collect();
    assert_eq!(vids, vec![v2.clone(), v1.clone(), "null".to_string()]);
    assert!(lv.versions().iter().all(|v| v.is_latest() == Some(false)));
    assert_eq!(lv.delete_markers().len(), 1);
    assert_eq!(lv.delete_markers()[0].version_id(), Some(dm.as_str()));
    assert_eq!(lv.delete_markers()[0].is_latest(), Some(true));

    // Paging with key/version-id markers.
    let p1 = s3
        .list_object_versions()
        .bucket("ver")
        .max_keys(2)
        .send()
        .await
        .unwrap();
    assert_eq!(p1.is_truncated(), Some(true));
    let p2 = s3
        .list_object_versions()
        .bucket("ver")
        .max_keys(2)
        .key_marker(p1.next_key_marker().unwrap())
        .version_id_marker(p1.next_version_id_marker().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(p2.versions().len() + p2.delete_markers().len(), 2);
    assert_eq!(p2.is_truncated(), Some(false));

    // Removing the delete marker restores v2 as current.
    let d = s3
        .delete_object()
        .bucket("ver")
        .key("k")
        .version_id(&dm)
        .send()
        .await
        .unwrap();
    assert_eq!(d.delete_marker(), Some(true));
    assert_eq!(d.version_id(), Some(dm.as_str()));
    assert_eq!(env.get("ver", "k").await, b"two");
    // Version-specific delete of the current version.
    s3.delete_object()
        .bucket("ver")
        .key("k")
        .version_id(&v2)
        .send()
        .await
        .unwrap();
    assert_eq!(env.get("ver", "k").await, b"one");
    assert_eq!(
        code(
            s3.get_object()
                .bucket("ver")
                .key("k")
                .version_id(&v2)
                .send()
                .await
        ),
        "NoSuchVersion"
    );

    // Suspended: new writes get version id "null" and replace the previous null version.
    set_versioning(&env, "ver", false).await;
    let p = s3
        .put_object()
        .bucket("ver")
        .key("k")
        .body("s1".as_bytes().to_vec().into())
        .send()
        .await
        .unwrap();
    assert_eq!(p.version_id(), Some("null"));
    s3.put_object()
        .bucket("ver")
        .key("k")
        .body("s2".as_bytes().to_vec().into())
        .send()
        .await
        .unwrap();
    let lv = s3
        .list_object_versions()
        .bucket("ver")
        .send()
        .await
        .unwrap();
    let vids: Vec<_> = lv
        .versions()
        .iter()
        .map(|v| v.version_id().unwrap().to_string())
        .collect();
    assert_eq!(vids, vec!["null".to_string(), v1.clone()]);
    assert_eq!(lv.versions()[0].is_latest(), Some(true));
    // Unversioned buckets report no version ids.
    env.bucket("plain").await;
    let p = s3
        .put_object()
        .bucket("plain")
        .key("k")
        .body("x".as_bytes().to_vec().into())
        .send()
        .await
        .unwrap();
    assert!(p.version_id().is_none());
    let lv = s3
        .list_object_versions()
        .bucket("plain")
        .send()
        .await
        .unwrap();
    assert_eq!(lv.versions()[0].version_id(), Some("null"));
    env.stop().await;
}
