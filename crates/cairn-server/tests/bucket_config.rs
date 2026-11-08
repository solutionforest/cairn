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
