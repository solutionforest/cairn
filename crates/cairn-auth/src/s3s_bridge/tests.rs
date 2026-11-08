use super::*;
use crate::bucket_policy::MemoryBucketAuthz;
use crate::eval::PublicAccessBlock;
use crate::store::MemoryBackend;
use crate::types::ManualClock;
use crate::{MasterKey, SecretString};
use std::time::Duration;

struct Fx {
    store: Arc<CredentialStore>,
    buckets: Arc<MemoryBucketAuthz>,
    access: CairnS3Access,
    clock: Arc<ManualClock>,
    n: std::sync::atomic::AtomicUsize,
}

const NOW: i64 = 1_790_000_000;

async fn fx() -> Fx {
    let clock = Arc::new(ManualClock::new(NOW));
    let store = Arc::new(
        CredentialStore::new(Arc::new(MemoryBackend::new()), MasterKey::new([9; 32]))
            .with_clock(clock.clone()),
    );
    store
        .ensure_root("ROOTAK", &SecretString::new("rootsecret"))
        .await
        .unwrap();
    let buckets = Arc::new(MemoryBucketAuthz::new());
    let access = CairnS3Access::new(store.clone(), buckets.clone())
        .with_engine(AuthzEngine::with_clock(clock.clone()));
    Fx {
        store,
        buckets,
        access,
        clock,
        n: Default::default(),
    }
}

fn stmt(effect: &str, action: &str, resource: &str) -> String {
    format!(r#"{{"Effect":"{effect}","Action":"{action}","Resource":"{resource}"}}"#)
}

fn doc(stmts: &[String]) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{}]}}"#,
        stmts.join(",")
    )
}

impl Fx {
    /// New user with an inline policy; returns its access key id.
    async fn user(&self, policy: Option<String>) -> (String, String) {
        let i = self.n.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let name = format!("u{i}");
        self.store.create_user(&name).await.unwrap();
        if let Some(p) = policy {
            self.store.put_user_policy(&name, "p", &p).await.unwrap();
        }
        let k = self
            .store
            .create_access_key(&name, Default::default())
            .await
            .unwrap();
        (name, k.access_key_id)
    }

    async fn check(
        &self,
        ak: Option<&str>,
        op: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Result<AuthenticatedCaller, S3Error> {
        self.check_meta(ak, op, path, headers, None).await
    }

    async fn check_meta(
        &self,
        ak: Option<&str>,
        op: &str,
        path: &str,
        headers: &[(&str, &str)],
        meta: Option<&RequestMeta>,
    ) -> Result<AuthenticatedCaller, S3Error> {
        let uri: Uri = path.parse().unwrap();
        let mut h = HeaderMap::new();
        for (k, v) in headers {
            h.append(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        let p = uri.path().trim_start_matches('/');
        let (bucket, key) = match p.split_once('/') {
            Some((b, k)) => (Some(b), Some(k)),
            None if p.is_empty() => (None, None),
            None => (Some(p), None),
        };
        self.access
            .authorize(&S3RequestView {
                op,
                access_key: ak,
                bucket,
                key,
                uri: &uri,
                headers: &h,
                meta,
            })
            .await
    }
}

fn code(r: Result<AuthenticatedCaller, S3Error>) -> String {
    match r {
        Ok(_) => "OK".into(),
        Err(e) => e.code().as_str().to_string(),
    }
}

/// (s3s op, request path incl. query, expected IAM action, expected resource ARN)
const OP_CASES: &[(&str, &str, &str, &str)] = &[
    ("ListBuckets", "/", "s3:ListAllMyBuckets", "arn:aws:s3:::*"),
    ("CreateBucket", "/b1", "s3:CreateBucket", "arn:aws:s3:::b1"),
    ("DeleteBucket", "/b1", "s3:DeleteBucket", "arn:aws:s3:::b1"),
    ("HeadBucket", "/b1", "s3:ListBucket", "arn:aws:s3:::b1"),
    (
        "GetBucketLocation",
        "/b1?location",
        "s3:GetBucketLocation",
        "arn:aws:s3:::b1",
    ),
    ("ListObjects", "/b1", "s3:ListBucket", "arn:aws:s3:::b1"),
    (
        "ListObjectsV2",
        "/b1?list-type=2",
        "s3:ListBucket",
        "arn:aws:s3:::b1",
    ),
    (
        "ListObjectVersions",
        "/b1?versions",
        "s3:ListBucketVersions",
        "arn:aws:s3:::b1",
    ),
    (
        "ListMultipartUploads",
        "/b1?uploads",
        "s3:ListBucketMultipartUploads",
        "arn:aws:s3:::b1",
    ),
    (
        "GetBucketVersioning",
        "/b1?versioning",
        "s3:GetBucketVersioning",
        "arn:aws:s3:::b1",
    ),
    (
        "PutBucketVersioning",
        "/b1?versioning",
        "s3:PutBucketVersioning",
        "arn:aws:s3:::b1",
    ),
    (
        "GetBucketPolicy",
        "/b1?policy",
        "s3:GetBucketPolicy",
        "arn:aws:s3:::b1",
    ),
    (
        "PutBucketPolicy",
        "/b1?policy",
        "s3:PutBucketPolicy",
        "arn:aws:s3:::b1",
    ),
    (
        "DeleteBucketPolicy",
        "/b1?policy",
        "s3:DeleteBucketPolicy",
        "arn:aws:s3:::b1",
    ),
    (
        "GetBucketPolicyStatus",
        "/b1?policyStatus",
        "s3:GetBucketPolicyStatus",
        "arn:aws:s3:::b1",
    ),
    (
        "GetBucketTagging",
        "/b1?tagging",
        "s3:GetBucketTagging",
        "arn:aws:s3:::b1",
    ),
    (
        "DeleteBucketTagging",
        "/b1?tagging",
        "s3:PutBucketTagging",
        "arn:aws:s3:::b1",
    ),
    (
        "GetBucketCors",
        "/b1?cors",
        "s3:GetBucketCORS",
        "arn:aws:s3:::b1",
    ),
    (
        "PutBucketLifecycleConfiguration",
        "/b1?lifecycle",
        "s3:PutLifecycleConfiguration",
        "arn:aws:s3:::b1",
    ),
    (
        "PutBucketEncryption",
        "/b1?encryption",
        "s3:PutEncryptionConfiguration",
        "arn:aws:s3:::b1",
    ),
    (
        "PutPublicAccessBlock",
        "/b1?publicAccessBlock",
        "s3:PutBucketPublicAccessBlock",
        "arn:aws:s3:::b1",
    ),
    (
        "GetObjectLockConfiguration",
        "/b1?object-lock",
        "s3:GetBucketObjectLockConfiguration",
        "arn:aws:s3:::b1",
    ),
    (
        "PutBucketNotificationConfiguration",
        "/b1?notification",
        "s3:PutBucketNotification",
        "arn:aws:s3:::b1",
    ),
    (
        "GetBucketReplication",
        "/b1?replication",
        "s3:GetReplicationConfiguration",
        "arn:aws:s3:::b1",
    ),
    (
        "PutObject",
        "/b1/dir/k.txt",
        "s3:PutObject",
        "arn:aws:s3:::b1/dir/k.txt",
    ),
    (
        "GetObject",
        "/b1/dir/k.txt",
        "s3:GetObject",
        "arn:aws:s3:::b1/dir/k.txt",
    ),
    (
        "GetObject",
        "/b1/k?versionId=abc",
        "s3:GetObjectVersion",
        "arn:aws:s3:::b1/k",
    ),
    ("HeadObject", "/b1/k", "s3:GetObject", "arn:aws:s3:::b1/k"),
    (
        "HeadObject",
        "/b1/k?versionId=abc",
        "s3:GetObjectVersion",
        "arn:aws:s3:::b1/k",
    ),
    (
        "DeleteObject",
        "/b1/k",
        "s3:DeleteObject",
        "arn:aws:s3:::b1/k",
    ),
    (
        "DeleteObject",
        "/b1/k?versionId=abc",
        "s3:DeleteObjectVersion",
        "arn:aws:s3:::b1/k",
    ),
    (
        "GetObjectTagging",
        "/b1/k?tagging",
        "s3:GetObjectTagging",
        "arn:aws:s3:::b1/k",
    ),
    (
        "PutObjectTagging",
        "/b1/k?tagging&versionId=v",
        "s3:PutObjectVersionTagging",
        "arn:aws:s3:::b1/k",
    ),
    (
        "DeleteObjectTagging",
        "/b1/k?tagging",
        "s3:DeleteObjectTagging",
        "arn:aws:s3:::b1/k",
    ),
    (
        "GetObjectAttributes",
        "/b1/k?attributes",
        "s3:GetObjectAttributes",
        "arn:aws:s3:::b1/k",
    ),
    (
        "GetObjectAcl",
        "/b1/k?acl",
        "s3:GetObjectAcl",
        "arn:aws:s3:::b1/k",
    ),
    (
        "PutObjectRetention",
        "/b1/k?retention",
        "s3:PutObjectRetention",
        "arn:aws:s3:::b1/k",
    ),
    (
        "GetObjectLegalHold",
        "/b1/k?legal-hold",
        "s3:GetObjectLegalHold",
        "arn:aws:s3:::b1/k",
    ),
    (
        "CreateMultipartUpload",
        "/b1/k?uploads",
        "s3:PutObject",
        "arn:aws:s3:::b1/k",
    ),
    (
        "UploadPart",
        "/b1/k?partNumber=1&uploadId=u",
        "s3:PutObject",
        "arn:aws:s3:::b1/k",
    ),
    (
        "CompleteMultipartUpload",
        "/b1/k?uploadId=u",
        "s3:PutObject",
        "arn:aws:s3:::b1/k",
    ),
    (
        "AbortMultipartUpload",
        "/b1/k?uploadId=u",
        "s3:AbortMultipartUpload",
        "arn:aws:s3:::b1/k",
    ),
    (
        "ListParts",
        "/b1/k?uploadId=u",
        "s3:ListMultipartUploadParts",
        "arn:aws:s3:::b1/k",
    ),
    (
        "RestoreObject",
        "/b1/k?restore",
        "s3:RestoreObject",
        "arn:aws:s3:::b1/k",
    ),
    (
        "GetBucketWebsite",
        "/b1?website",
        "s3:GetBucketWebsite",
        "arn:aws:s3:::b1",
    ),
];

#[tokio::test]
async fn operation_to_action_mapping_table() {
    assert!(OP_CASES.len() >= 30);
    let f = fx().await;
    for (op, path, action, resource) in OP_CASES {
        let (_, exact) = f.user(Some(doc(&[stmt("Allow", action, resource)]))).await;
        assert_eq!(
            code(f.check(Some(&exact), op, path, &[]).await),
            "OK",
            "{op} {path} should need {action} on {resource}"
        );
        let (_, other_res) = f
            .user(Some(doc(&[stmt(
                "Allow",
                action,
                "arn:aws:s3:::zz-other/*",
            )])))
            .await;
        assert_eq!(
            code(f.check(Some(&other_res), op, path, &[]).await),
            "AccessDenied",
            "{op} wrong resource"
        );
        let (_, deny) = f
            .user(Some(doc(&[
                stmt("Allow", "s3:*", "*"),
                stmt("Deny", action, resource),
            ])))
            .await;
        assert_eq!(
            code(f.check(Some(&deny), op, path, &[]).await),
            "AccessDenied",
            "{op} explicit deny"
        );
    }
}

#[tokio::test]
async fn root_allowed_everything_and_unmapped_ops_denied_for_users() {
    let f = fx().await;
    assert_eq!(
        code(
            f.check(Some("ROOTAK"), "SelectObjectContent", "/b/k", &[])
                .await
        ),
        "OK"
    );
    assert_eq!(
        code(f.check(Some("ROOTAK"), "PutObject", "/b/k", &[]).await),
        "OK"
    );
    let (_, ak) = f.user(Some(doc(&[stmt("Allow", "*", "*")]))).await;
    assert_eq!(
        code(f.check(Some(&ak), "SelectObjectContent", "/b/k", &[]).await),
        "AccessDenied"
    );
    let caller = f
        .check(Some("ROOTAK"), "GetObject", "/b/k", &[])
        .await
        .unwrap();
    assert!(caller.principal.unwrap().is_root);
}

#[tokio::test]
async fn user_without_policy_is_implicitly_denied() {
    let f = fx().await;
    let (_, ak) = f.user(None).await;
    assert_eq!(
        code(f.check(Some(&ak), "GetObject", "/b/k", &[]).await),
        "AccessDenied"
    );
}

#[tokio::test]
async fn group_policies_apply() {
    let f = fx().await;
    let (name, ak) = f.user(None).await;
    f.store.create_group("readers").await.unwrap();
    f.store
        .put_group_policy(
            "readers",
            "r",
            &doc(&[stmt("Allow", "s3:GetObject", "arn:aws:s3:::b/*")]),
        )
        .await
        .unwrap();
    assert_eq!(
        code(f.check(Some(&ak), "GetObject", "/b/k", &[]).await),
        "AccessDenied"
    );
    f.store.add_user_to_group(&name, "readers").await.unwrap();
    assert_eq!(
        code(f.check(Some(&ak), "GetObject", "/b/k", &[]).await),
        "OK"
    );
    assert_eq!(
        code(f.check(Some(&ak), "PutObject", "/b/k", &[]).await),
        "AccessDenied"
    );
}

const PUBLIC_READ: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::pub/*"}]}"#;

fn bucket_policy(text: &str, pab: PublicAccessBlock) -> BucketAuthz {
    BucketAuthz {
        policy: Some(text.parse().unwrap()),
        public_access_block: pab,
    }
}

#[tokio::test]
async fn anonymous_only_via_bucket_policy() {
    let f = fx().await;
    assert_eq!(
        code(f.check(None, "GetObject", "/pub/k", &[]).await),
        "AccessDenied"
    );
    assert_eq!(
        code(f.check(None, "ListBuckets", "/", &[]).await),
        "AccessDenied"
    );
    f.buckets
        .set("pub", bucket_policy(PUBLIC_READ, Default::default()));
    let c = f.check(None, "GetObject", "/pub/k", &[]).await.unwrap();
    assert!(c.principal.is_none());
    assert_eq!(
        code(f.check(None, "PutObject", "/pub/k", &[]).await),
        "AccessDenied"
    );
    assert_eq!(
        code(f.check(None, "ListObjectsV2", "/pub", &[]).await),
        "AccessDenied"
    );
    // A user with no identity policy is allowed by the `*` grant too.
    let (_, ak) = f.user(None).await;
    assert_eq!(
        code(f.check(Some(&ak), "GetObject", "/pub/k", &[]).await),
        "OK"
    );
}

#[tokio::test]
async fn restrict_public_buckets_blocks_anonymous() {
    let f = fx().await;
    let pab = PublicAccessBlock {
        restrict_public_buckets: true,
        ..Default::default()
    };
    f.buckets.set("pub", bucket_policy(PUBLIC_READ, pab));
    assert_eq!(
        code(f.check(None, "GetObject", "/pub/k", &[]).await),
        "AccessDenied"
    );
}

#[tokio::test]
async fn bucket_policy_grants_named_user_without_identity_policy() {
    let f = fx().await;
    let (name, ak) = f.user(None).await;
    let p = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{}"}},"Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::shared/*"}}]}}"#,
        arn::user(&name)
    );
    f.buckets
        .set("shared", bucket_policy(&p, Default::default()));
    assert_eq!(
        code(f.check(Some(&ak), "PutObject", "/shared/x", &[]).await),
        "OK"
    );
    assert_eq!(
        code(f.check(Some(&ak), "DeleteObject", "/shared/x", &[]).await),
        "AccessDenied"
    );
    let (_, other) = f.user(None).await;
    assert_eq!(
        code(f.check(Some(&other), "PutObject", "/shared/x", &[]).await),
        "AccessDenied"
    );
}

#[tokio::test]
async fn explicit_deny_wins_across_policy_sources() {
    let f = fx().await;
    let (_, ak) = f.user(Some(doc(&[stmt("Allow", "s3:*", "*")]))).await;
    let deny = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::locked/*"}]}"#;
    f.buckets
        .set("locked", bucket_policy(deny, Default::default()));
    assert_eq!(
        code(f.check(Some(&ak), "DeleteObject", "/locked/k", &[]).await),
        "AccessDenied"
    );
    assert_eq!(
        code(f.check(Some(&ak), "GetObject", "/locked/k", &[]).await),
        "OK"
    );
    // identity deny beats bucket-policy allow
    let (_, ak2) = f
        .user(Some(doc(&[stmt(
            "Deny",
            "s3:GetObject",
            "arn:aws:s3:::pub/*",
        )])))
        .await;
    f.buckets
        .set("pub", bucket_policy(PUBLIC_READ, Default::default()));
    assert_eq!(
        code(f.check(Some(&ak2), "GetObject", "/pub/k", &[]).await),
        "AccessDenied"
    );
    // root is never denied
    assert_eq!(
        code(
            f.check(Some("ROOTAK"), "DeleteObject", "/locked/k", &[])
                .await
        ),
        "OK"
    );
}

#[tokio::test]
async fn block_public_acls() {
    let f = fx().await;
    let (_, ak) = f.user(Some(doc(&[stmt("Allow", "s3:*", "*")]))).await;
    f.buckets.set(
        "b",
        BucketAuthz {
            policy: None,
            public_access_block: PublicAccessBlock {
                block_public_acls: true,
                ..Default::default()
            },
        },
    );
    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "PutObject",
                "/b/k",
                &[("x-amz-acl", "public-read")]
            )
            .await
        ),
        "AccessDenied"
    );
    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "PutObjectAcl",
                "/b/k?acl",
                &[(
                    "x-amz-grant-read",
                    "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\""
                )]
            )
            .await
        ),
        "AccessDenied"
    );
    assert_eq!(
        code(
            f.check(Some(&ak), "PutObject", "/b/k", &[("x-amz-acl", "private")])
                .await
        ),
        "OK"
    );
    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "PutObject",
                "/c/k",
                &[("x-amz-acl", "public-read")]
            )
            .await
        ),
        "OK"
    );
}

#[tokio::test]
async fn conditions_source_ip_secure_transport_prefix_acl() {
    let f = fx().await;
    let p = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b","Condition":{"StringLike":{"s3:prefix":"home/${aws:username}/*"}}},
        {"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"},"Bool":{"aws:SecureTransport":"true"}}},
        {"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}}
    ]}"#;
    let (name, ak) = f.user(Some(p.to_string())).await;
    let ok_list = format!("/b?list-type=2&prefix=home%2F{name}%2Fdocs");
    assert_eq!(
        code(f.check(Some(&ak), "ListObjectsV2", &ok_list, &[]).await),
        "OK"
    );
    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "ListObjectsV2",
                "/b?list-type=2&prefix=home%2Fother%2F",
                &[]
            )
            .await
        ),
        "AccessDenied"
    );
    assert_eq!(
        code(
            f.check(Some(&ak), "ListObjectsV2", "/b?list-type=2", &[])
                .await
        ),
        "AccessDenied"
    );

    let inside = RequestMeta {
        source_ip: Some("10.1.2.3".parse().unwrap()),
        secure: true,
    };
    let outside = RequestMeta {
        source_ip: Some("192.168.0.1".parse().unwrap()),
        secure: true,
    };
    let plain = RequestMeta {
        source_ip: Some("10.1.2.3".parse().unwrap()),
        secure: false,
    };
    assert_eq!(
        code(
            f.check_meta(Some(&ak), "GetObject", "/b/k", &[], Some(&inside))
                .await
        ),
        "OK"
    );
    assert_eq!(
        code(
            f.check_meta(Some(&ak), "GetObject", "/b/k", &[], Some(&outside))
                .await
        ),
        "AccessDenied"
    );
    assert_eq!(
        code(
            f.check_meta(Some(&ak), "GetObject", "/b/k", &[], Some(&plain))
                .await
        ),
        "AccessDenied"
    );
    assert_eq!(
        code(f.check(Some(&ak), "GetObject", "/b/k", &[]).await),
        "AccessDenied"
    );

    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "PutObject",
                "/b/k",
                &[("x-amz-acl", "bucket-owner-full-control")]
            )
            .await
        ),
        "OK"
    );
    assert_eq!(
        code(f.check(Some(&ak), "PutObject", "/b/k", &[]).await),
        "AccessDenied"
    );
}

#[tokio::test]
async fn current_time_condition_uses_engine_clock() {
    let f = fx().await;
    let p = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"DateLessThan":{"aws:CurrentTime":"2026-09-20T00:00:00Z"}}}]}"#;
    let (_, ak) = f.user(Some(p.to_string())).await;
    // NOW = 2026-09-21T13:46:40Z
    assert_eq!(
        code(f.check(Some(&ak), "GetObject", "/b/k", &[]).await),
        "AccessDenied"
    );
    let p2 = p.replace("2026-09-20", "2026-09-22");
    let (_, ak2) = f.user(Some(p2)).await;
    assert_eq!(
        code(f.check(Some(&ak2), "GetObject", "/b/k", &[]).await),
        "OK"
    );
}

#[tokio::test]
async fn copy_requires_read_on_source() {
    let f = fx().await;
    let (_, ak) = f
        .user(Some(doc(&[
            stmt("Allow", "s3:PutObject", "arn:aws:s3:::dst/*"),
            stmt("Allow", "s3:GetObject", "arn:aws:s3:::src/ok/*"),
        ])))
        .await;
    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "CopyObject",
                "/dst/k",
                &[("x-amz-copy-source", "/src/ok/a.txt")]
            )
            .await
        ),
        "OK"
    );
    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "CopyObject",
                "/dst/k",
                &[("x-amz-copy-source", "src/secret/a.txt")]
            )
            .await
        ),
        "AccessDenied"
    );
    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "UploadPartCopy",
                "/dst/k?partNumber=1&uploadId=u",
                &[("x-amz-copy-source", "src/ok/a.txt?versionId=v1")]
            )
            .await
        ),
        "AccessDenied",
        "versioned copy source needs s3:GetObjectVersion"
    );
    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "CopyObject",
                "/dst/k",
                &[("x-amz-copy-source", "nobucket")]
            )
            .await
        ),
        "InvalidArgument"
    );
}

#[tokio::test]
async fn sts_session_token_and_expiry() {
    let f = fx().await;
    let (name, _) = f.user(Some(doc(&[stmt("Allow", "s3:*", "*")]))).await;
    let p = f.store.principal_for_user(&name).await.unwrap().unwrap();
    let sts = f
        .store
        .get_session_token(&p, Duration::from_secs(900))
        .await
        .unwrap();
    let ak = sts.access_key_id.clone();
    let tok = sts.session_token.expose().to_string();
    assert_eq!(
        code(f.check(Some(&ak), "GetObject", "/b/k", &[]).await),
        "InvalidToken"
    );
    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "GetObject",
                "/b/k",
                &[("x-amz-security-token", "wrong")]
            )
            .await
        ),
        "InvalidToken"
    );
    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "GetObject",
                "/b/k",
                &[("x-amz-security-token", &tok)]
            )
            .await
        ),
        "OK"
    );
    let q = format!("/b/k?X-Amz-Security-Token={}", tok.replace('-', "%2D"));
    assert_eq!(code(f.check(Some(&ak), "GetObject", &q, &[]).await), "OK");
    // long-lived key presenting a token is rejected
    let (_, lak) = f.user(Some(doc(&[stmt("Allow", "s3:*", "*")]))).await;
    assert_eq!(
        code(
            f.check(
                Some(&lak),
                "GetObject",
                "/b/k",
                &[("x-amz-security-token", &tok)]
            )
            .await
        ),
        "InvalidToken"
    );

    let auth = CairnS3Auth::new(f.store.clone());
    assert_eq!(
        auth.get_secret_key(&ak).await.unwrap().expose(),
        sts.secret_access_key.expose()
    );
    f.clock.advance(Duration::from_secs(901));
    assert_eq!(
        code(
            f.check(
                Some(&ak),
                "GetObject",
                "/b/k",
                &[("x-amz-security-token", &tok)]
            )
            .await
        ),
        "ExpiredToken"
    );
    let e = auth.get_secret_key(&ak).await.unwrap_err();
    assert_eq!(*e.code(), S3ErrorCode::InvalidAccessKeyId);
}

#[tokio::test]
async fn revoked_session_and_disabled_user_stop_working() {
    let f = fx().await;
    let (name, lak) = f.user(Some(doc(&[stmt("Allow", "s3:*", "*")]))).await;
    let p = f.store.principal_for_user(&name).await.unwrap().unwrap();
    let sts = f
        .store
        .get_session_token(&p, Duration::from_secs(900))
        .await
        .unwrap();
    let tok = sts.session_token.expose().to_string();
    let h = [("x-amz-security-token", tok.as_str())];
    assert_eq!(
        code(
            f.check(Some(&sts.access_key_id), "GetObject", "/b/k", &h)
                .await
        ),
        "OK"
    );
    assert_eq!(f.store.list_sessions().await.unwrap().len(), 1);
    f.store.revoke_session(&sts.access_key_id).await.unwrap();
    assert_eq!(
        code(
            f.check(Some(&sts.access_key_id), "GetObject", "/b/k", &h)
                .await
        ),
        "ExpiredToken"
    );
    f.store.set_user_disabled(&name, true).await.unwrap();
    assert_eq!(
        code(f.check(Some(&lak), "GetObject", "/b/k", &[]).await),
        "ExpiredToken"
    );
}

#[tokio::test]
async fn assumed_role_session_with_session_policy() {
    let f = fx().await;
    let (name, _) = f
        .user(Some(doc(&[stmt("Allow", "sts:AssumeRole", "*")])))
        .await;
    let trust = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"{}"}},"Action":"sts:AssumeRole"}}]}}"#,
        arn::user(&name)
    );
    f.store.create_role("writer", &trust, None).await.unwrap();
    f.store
        .put_role_policy(
            "writer",
            "w",
            &doc(&[stmt("Allow", "s3:*", "arn:aws:s3:::b/*")]),
        )
        .await
        .unwrap();
    let caller = f.store.principal_for_user(&name).await.unwrap().unwrap();
    let sp = doc(&[stmt("Allow", "s3:GetObject", "*")]);
    let ctx = ConditionContext::new();
    let creds = f
        .store
        .assume_role(
            &caller,
            crate::AssumeRoleRequest {
                role: "writer",
                session_name: "s1",
                duration: Duration::from_secs(900),
                session_policy: Some(&sp),
                context: &ctx,
            },
        )
        .await
        .unwrap();
    let tok = creds.session_token.expose().to_string();
    let h = [("x-amz-security-token", tok.as_str())];
    let c = f
        .check(Some(&creds.access_key_id), "GetObject", "/b/k", &h)
        .await
        .unwrap();
    assert_eq!(c.principal.unwrap().id.as_str(), "role:writer/s1");
    assert_eq!(
        code(
            f.check(Some(&creds.access_key_id), "PutObject", "/b/k", &h)
                .await
        ),
        "AccessDenied"
    );
    assert_eq!(
        code(
            f.check(Some(&creds.access_key_id), "GetObject", "/other/k", &h)
                .await
        ),
        "AccessDenied"
    );
}

#[tokio::test]
async fn delete_objects_checks_every_key() {
    use s3s::dto::{Delete, ObjectIdentifier};
    let f = fx().await;
    let (_, ak) = f
        .user(Some(doc(&[stmt(
            "Allow",
            "s3:DeleteObject",
            "arn:aws:s3:::b/tmp/*",
        )])))
        .await;
    assert_eq!(
        code(f.check(Some(&ak), "DeleteObjects", "/b?delete", &[]).await),
        "OK"
    );
    let mk = |keys: &[(&str, Option<&str>)]| {
        let objects = keys
            .iter()
            .map(|(k, v)| ObjectIdentifier {
                key: k.to_string(),
                version_id: v.map(str::to_string),
                ..Default::default()
            })
            .collect();
        let input = DeleteObjectsInput::builder()
            .bucket("b".into())
            .delete(Delete {
                objects,
                quiet: None,
            })
            .build()
            .unwrap();
        S3Request {
            input,
            method: http::Method::POST,
            uri: "/b?delete".parse().unwrap(),
            headers: HeaderMap::new(),
            extensions: Default::default(),
            credentials: Some(s3s::auth::Credentials {
                access_key: ak.clone(),
                secret_key: SecretKey::from("x"),
            }),
            region: None,
            service: None,
            trailing_headers: None,
        }
    };
    let mut ok = mk(&[("tmp/a", None), ("tmp/b", None)]);
    f.access.delete_objects(&mut ok).await.unwrap();
    let mut bad = mk(&[("tmp/a", None), ("keep/b", None)]);
    assert_eq!(
        *f.access.delete_objects(&mut bad).await.unwrap_err().code(),
        S3ErrorCode::AccessDenied
    );
    let mut ver = mk(&[("tmp/a", Some("v1"))]);
    assert_eq!(
        *f.access.delete_objects(&mut ver).await.unwrap_err().code(),
        S3ErrorCode::AccessDenied
    );
}

#[test]
fn condition_context_keys() {
    let uri: Uri = "https://h/b?list-type=2&prefix=a%2Fb&delimiter=%2F&max-keys=10"
        .parse()
        .unwrap();
    let mut h = HeaderMap::new();
    h.insert("user-agent", "aws-cli/2".parse().unwrap());
    h.insert("x-amz-acl", "private".parse().unwrap());
    h.insert("x-amz-tagging", "team=data&env=prod".parse().unwrap());
    h.insert("x-amz-server-side-encryption", "AES256".parse().unwrap());
    h.insert("x-cairn-as-of", "2026-01-01T00:00:00Z".parse().unwrap());
    h.insert(
        "authorization",
        "AWS4-HMAC-SHA256 Credential=x".parse().unwrap(),
    );
    let meta = RequestMeta {
        source_ip: Some("1.2.3.4".parse().unwrap()),
        secure: false,
    };
    let c = condition_context(&S3RequestView {
        op: "ListObjectsV2",
        access_key: Some("AK"),
        bucket: Some("b"),
        key: None,
        uri: &uri,
        headers: &h,
        meta: Some(&meta),
    });
    let one = |k: &str| c.get(k).map(|v| v.join(","));
    assert_eq!(one("aws:SourceIp").as_deref(), Some("1.2.3.4"));
    assert_eq!(one("aws:SecureTransport").as_deref(), Some("true"));
    assert_eq!(one("aws:UserAgent").as_deref(), Some("aws-cli/2"));
    assert_eq!(one("s3:prefix").as_deref(), Some("a/b"));
    assert_eq!(one("s3:delimiter").as_deref(), Some("/"));
    assert_eq!(one("s3:max-keys").as_deref(), Some("10"));
    assert_eq!(one("s3:x-amz-acl").as_deref(), Some("private"));
    assert_eq!(
        one("s3:x-amz-server-side-encryption").as_deref(),
        Some("AES256")
    );
    assert_eq!(one("s3:RequestObjectTag/team").as_deref(), Some("data"));
    assert_eq!(one("s3:RequestObjectTagKeys").as_deref(), Some("team,env"));
    assert_eq!(one("cairn:AsOf").as_deref(), Some("2026-01-01T00:00:00Z"));
    assert_eq!(one("s3:authType").as_deref(), Some("REST-HEADER"));
    assert_eq!(
        one("s3:signatureversion").as_deref(),
        Some("AWS4-HMAC-SHA256")
    );
    assert_eq!(resource_arn("ListBuckets", None, None), "arn:aws:s3:::*");
}
