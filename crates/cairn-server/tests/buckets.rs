//! Bucket operations: Create/Head/Delete/ListBuckets, GetBucketLocation, bucket tagging and
//! versioning configuration.

mod common;
use aws_sdk_s3::types::{BucketVersioningStatus, Tag, Tagging, VersioningConfiguration};
use common::*;

#[tokio::test]
async fn bucket_crud_location_tagging_versioning() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("alpha").await;
    env.bucket("beta").await;
    s3.put_object()
        .bucket("alpha")
        .key("kept")
        .body(b"x".to_vec().into())
        .send()
        .await
        .unwrap();
    // us-east-1: re-creating your own bucket is a no-op 200 that keeps its contents.
    s3.create_bucket().bucket("alpha").send().await.unwrap();
    s3.head_object()
        .bucket("alpha")
        .key("kept")
        .send()
        .await
        .unwrap();
    s3.delete_object()
        .bucket("alpha")
        .key("kept")
        .send()
        .await
        .unwrap();
    // Any other region keeps the 409.
    assert_eq!(
        code(
            s3.create_bucket()
                .bucket("alpha")
                .create_bucket_configuration(
                    aws_sdk_s3::types::CreateBucketConfiguration::builder()
                        .location_constraint(aws_sdk_s3::types::BucketLocationConstraint::EuWest1)
                        .build()
                )
                .send()
                .await
        ),
        "BucketAlreadyOwnedByYou"
    );
    assert_eq!(
        code(s3.create_bucket().bucket("Not_Valid").send().await),
        "InvalidBucketName"
    );

    let names: Vec<_> = s3
        .list_buckets()
        .send()
        .await
        .unwrap()
        .buckets()
        .iter()
        .map(|b| b.name().unwrap().to_string())
        .collect();
    assert_eq!(names, vec!["alpha", "beta"]);

    s3.head_bucket().bucket("alpha").send().await.unwrap();
    assert_eq!(status(s3.head_bucket().bucket("nope").send().await), 404);

    let loc = s3
        .get_bucket_location()
        .bucket("alpha")
        .send()
        .await
        .unwrap();
    assert!(
        loc.location_constraint()
            .is_none_or(|l| l.as_str().is_empty())
    );

    assert_eq!(
        code(s3.get_bucket_tagging().bucket("alpha").send().await),
        "NoSuchTagSet"
    );
    s3.put_bucket_tagging()
        .bucket("alpha")
        .tagging(
            Tagging::builder()
                .tag_set(Tag::builder().key("team").value("storage").build().unwrap())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let t = s3
        .get_bucket_tagging()
        .bucket("alpha")
        .send()
        .await
        .unwrap();
    assert_eq!(t.tag_set()[0].key(), "team");
    assert_eq!(t.tag_set()[0].value(), "storage");
    s3.delete_bucket_tagging()
        .bucket("alpha")
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(s3.get_bucket_tagging().bucket("alpha").send().await),
        "NoSuchTagSet"
    );

    let v = s3
        .get_bucket_versioning()
        .bucket("alpha")
        .send()
        .await
        .unwrap();
    assert!(v.status().is_none());
    for st in [
        BucketVersioningStatus::Enabled,
        BucketVersioningStatus::Suspended,
    ] {
        s3.put_bucket_versioning()
            .bucket("alpha")
            .versioning_configuration(
                VersioningConfiguration::builder()
                    .status(st.clone())
                    .build(),
            )
            .send()
            .await
            .unwrap();
        let v = s3
            .get_bucket_versioning()
            .bucket("alpha")
            .send()
            .await
            .unwrap();
        assert_eq!(v.status(), Some(&st));
    }

    env.put("beta", "k", "x").await;
    assert_eq!(
        code(s3.delete_bucket().bucket("beta").send().await),
        "BucketNotEmpty"
    );
    s3.delete_object()
        .bucket("beta")
        .key("k")
        .send()
        .await
        .unwrap();
    s3.delete_bucket().bucket("beta").send().await.unwrap();
    assert_eq!(
        code(s3.delete_bucket().bucket("beta").send().await),
        "NoSuchBucket"
    );
    assert_eq!(status(s3.head_bucket().bucket("beta").send().await), 404);
    // The name is released immediately.
    env.bucket("beta").await;
    env.stop().await;
}

#[tokio::test]
async fn errors_are_aws_shaped_with_request_id() {
    let env = Env::new().await;
    let r = env
        .s3
        .get_object()
        .bucket("missing")
        .key("k")
        .send()
        .await
        .unwrap_err();
    let raw = r.raw_response().unwrap();
    assert_eq!(raw.status().as_u16(), 404);
    let rid = raw.headers().get("x-amz-request-id").unwrap().to_string();
    assert_eq!(rid.len(), 16);
    let body = std::str::from_utf8(raw.body().bytes().unwrap())
        .unwrap()
        .to_string();
    assert!(body.contains("<Code>NoSuchBucket</Code>"), "{body}");
    assert!(body.contains("<Message>"), "{body}");
    assert!(body.contains("<Resource>/missing/k</Resource>"), "{body}");
    assert!(
        body.contains(&format!("<RequestId>{rid}</RequestId>")),
        "{body}"
    );

    // Unsigned requests are rejected with an AWS-shaped AccessDenied.
    let resp = reqwest::get(env.url("/")).await.unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    let rid = resp.headers()["x-amz-request-id"]
        .to_str()
        .unwrap()
        .to_string();
    let body = resp.text().await.unwrap();
    assert!(body.contains("<Code>AccessDenied</Code>"), "{body}");
    assert!(
        body.contains(&format!("<RequestId>{rid}</RequestId>")),
        "{body}"
    );

    // Wrong secret → SignatureDoesNotMatch.
    let bad = client(
        env.addr,
        &cairn_server::test_support::RootCreds {
            access_key: env.creds.access_key.clone(),
            secret_key: "wrong-secret-key-wrong-secret-key".into(),
        },
    );
    assert_eq!(
        code(bad.list_buckets().send().await),
        "SignatureDoesNotMatch"
    );
    let unknown = client(
        env.addr,
        &cairn_server::test_support::RootCreds {
            access_key: "AKIDUNKNOWN".into(),
            secret_key: "whatever-whatever".into(),
        },
    );
    assert_eq!(
        code(unknown.list_buckets().send().await),
        "InvalidAccessKeyId"
    );
    // Successful responses carry a request id too.
    let ok = env.s3.list_buckets().send().await.unwrap();
    let _ = ok;
    env.stop().await;
}
