//! Bucket configuration round trips: policy (+ status), PublicAccessBlock, lifecycle.

mod common;
use aws_sdk_s3::types::{
    BucketLifecycleConfiguration, ExpirationStatus, LifecycleExpiration, LifecycleRule,
    LifecycleRuleFilter, PublicAccessBlockConfiguration,
};
use common::*;

#[tokio::test]
async fn policy_public_access_block_and_lifecycle_round_trip() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("cfg").await;

    // Bucket policy and its status.
    assert_eq!(
        code(s3.get_bucket_policy().bucket("cfg").send().await),
        "NoSuchBucketPolicy"
    );
    let public = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::cfg/*"}]}"#;
    s3.put_bucket_policy()
        .bucket("cfg")
        .policy(public)
        .send()
        .await
        .unwrap();
    let got = s3.get_bucket_policy().bucket("cfg").send().await.unwrap();
    assert!(got.policy().unwrap().contains("s3:GetObject"));
    let st = s3
        .get_bucket_policy_status()
        .bucket("cfg")
        .send()
        .await
        .unwrap();
    assert_eq!(st.policy_status().unwrap().is_public(), Some(true));
    s3.delete_bucket_policy()
        .bucket("cfg")
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(s3.get_bucket_policy().bucket("cfg").send().await),
        "NoSuchBucketPolicy"
    );
    assert_eq!(
        code(s3.get_bucket_policy_status().bucket("cfg").send().await),
        "NoSuchBucketPolicy"
    );

    // PublicAccessBlock.
    s3.put_public_access_block()
        .bucket("cfg")
        .public_access_block_configuration(
            PublicAccessBlockConfiguration::builder()
                .block_public_policy(true)
                .restrict_public_buckets(true)
                .build(),
        )
        .send()
        .await
        .unwrap();
    let pab = s3
        .get_public_access_block()
        .bucket("cfg")
        .send()
        .await
        .unwrap();
    let c = pab.public_access_block_configuration().unwrap();
    assert_eq!(c.block_public_policy(), Some(true));
    assert_eq!(c.restrict_public_buckets(), Some(true));
    s3.delete_public_access_block()
        .bucket("cfg")
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(s3.get_public_access_block().bucket("cfg").send().await),
        "NoSuchPublicAccessBlockConfiguration"
    );

    // Lifecycle: round trip, validation, delete.
    let rule = |status: ExpirationStatus| {
        LifecycleRule::builder()
            .id("tmp")
            .filter(LifecycleRuleFilter::builder().prefix("tmp/").build())
            .expiration(LifecycleExpiration::builder().days(7).build())
            .status(status)
            .build()
            .unwrap()
    };
    s3.put_bucket_lifecycle_configuration()
        .bucket("cfg")
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(rule(ExpirationStatus::Enabled))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let lc = s3
        .get_bucket_lifecycle_configuration()
        .bucket("cfg")
        .send()
        .await
        .unwrap();
    assert_eq!(lc.rules()[0].id(), Some("tmp"));
    assert_eq!(lc.rules()[0].expiration().unwrap().days(), Some(7));
    assert_eq!(
        code(
            s3.put_bucket_lifecycle_configuration()
                .bucket("cfg")
                .lifecycle_configuration(
                    BucketLifecycleConfiguration::builder()
                        .rules(rule(ExpirationStatus::from("enabled")))
                        .build()
                        .unwrap(),
                )
                .send()
                .await
        ),
        "MalformedXML"
    );
    let not_midnight = LifecycleRule::builder()
        .id("d")
        .filter(LifecycleRuleFilter::builder().prefix("d/").build())
        .expiration(
            LifecycleExpiration::builder()
                .date(aws_sdk_s3::primitives::DateTime::from_secs(1_000_000_001))
                .build(),
        )
        .status(ExpirationStatus::Enabled)
        .build()
        .unwrap();
    assert_eq!(
        code(
            s3.put_bucket_lifecycle_configuration()
                .bucket("cfg")
                .lifecycle_configuration(
                    BucketLifecycleConfiguration::builder()
                        .rules(not_midnight)
                        .build()
                        .unwrap(),
                )
                .send()
                .await
        ),
        "InvalidArgument"
    );
    s3.delete_bucket_lifecycle()
        .bucket("cfg")
        .send()
        .await
        .unwrap();
    assert_eq!(
        code(
            s3.get_bucket_lifecycle_configuration()
                .bucket("cfg")
                .send()
                .await
        ),
        "NoSuchLifecycleConfiguration"
    );
}

/// `x-amz-expiration` on PUT, HEAD and GET names the matching rule and the expiry instant
/// (creation + Days, rounded up to midnight UTC); rules sent without an ID get one.
#[tokio::test]
async fn lifecycle_expiration_header_and_generated_ids() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("exp").await;
    let rule = |id: Option<&str>, prefix: &str, days: i32| {
        LifecycleRule::builder()
            .set_id(id.map(str::to_string))
            .filter(LifecycleRuleFilter::builder().prefix(prefix).build())
            .expiration(LifecycleExpiration::builder().days(days).build())
            .status(ExpirationStatus::Enabled)
            .build()
            .unwrap()
    };
    s3.put_bucket_lifecycle_configuration()
        .bucket("exp")
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(rule(Some("one-day"), "d1/", 1))
                .rules(rule(None, "d3/", 3))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let got = s3
        .get_bucket_lifecycle_configuration()
        .bucket("exp")
        .send()
        .await
        .unwrap();
    let ids: Vec<_> = got.rules().iter().map(|r| r.id().unwrap_or("")).collect();
    assert_eq!(ids[0], "one-day");
    assert!(!ids[1].is_empty(), "rule sent without an ID got none");

    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let put = s3
        .put_object()
        .bucket("exp")
        .key("d1/a")
        .body(b"x".to_vec().into())
        .send()
        .await
        .unwrap();
    let hdr = put.expiration().expect("PUT carries x-amz-expiration");
    assert!(hdr.ends_with("rule-id=\"one-day\""), "{hdr}");
    let date = hdr
        .strip_prefix("expiry-date=\"")
        .and_then(|s| s.split('"').next())
        .unwrap();
    let at = aws_sdk_s3::primitives::DateTime::from_str(
        date,
        aws_sdk_s3::primitives::DateTimeFormat::HttpDate,
    )
    .unwrap()
    .secs() as u64;
    assert_eq!(at % 86_400, 0, "expiry is at midnight UTC: {date}");
    assert!(at > before + 86_400 && at <= before + 2 * 86_400, "{date}");

    let head = s3
        .head_object()
        .bucket("exp")
        .key("d1/a")
        .send()
        .await
        .unwrap();
    assert_eq!(head.expiration(), Some(hdr));
    let get = s3
        .get_object()
        .bucket("exp")
        .key("d1/a")
        .send()
        .await
        .unwrap();
    assert_eq!(get.expiration(), Some(hdr));
    let other = s3
        .put_object()
        .bucket("exp")
        .key("elsewhere")
        .body(b"x".to_vec().into())
        .send()
        .await
        .unwrap();
    assert_eq!(other.expiration(), None);
    let three = s3
        .put_object()
        .bucket("exp")
        .key("d3/a")
        .body(b"x".to_vec().into())
        .send()
        .await
        .unwrap();
    assert!(
        three
            .expiration()
            .unwrap()
            .contains(&format!("rule-id=\"{}\"", ids[1])),
        "generated id reported"
    );
}

/// A rule sent with the legacy top-level `<Prefix>` comes back in that shape (not as a
/// `<Filter>`), so read-modify-write clients see what they sent.
#[tokio::test]
#[allow(deprecated)]
async fn lifecycle_legacy_prefix_round_trips_in_the_same_shape() {
    let env = Env::new().await;
    let s3 = &env.s3;
    env.bucket("legacy").await;
    let legacy = LifecycleRule::builder()
        .id("old")
        .prefix("logs/")
        .expiration(LifecycleExpiration::builder().days(31).build())
        .status(ExpirationStatus::Enabled)
        .build()
        .unwrap();
    let modern = LifecycleRule::builder()
        .id("new")
        .filter(LifecycleRuleFilter::builder().prefix("tmp/").build())
        .expiration(LifecycleExpiration::builder().days(7).build())
        .status(ExpirationStatus::Enabled)
        .build()
        .unwrap();
    s3.put_bucket_lifecycle_configuration()
        .bucket("legacy")
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(legacy)
                .rules(modern)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let lc = s3
        .get_bucket_lifecycle_configuration()
        .bucket("legacy")
        .send()
        .await
        .unwrap();
    let old = &lc.rules()[0];
    assert_eq!(old.prefix(), Some("logs/"));
    assert!(old.filter().is_none());
    let new = &lc.rules()[1];
    assert_eq!(new.prefix(), None);
    assert_eq!(new.filter().and_then(|f| f.prefix()), Some("tmp/"));
}
