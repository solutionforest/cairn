//! Bucket sub-resource operations backed by Cairn IAM, cairn-events and the lifecycle engine:
//! bucket policy + status, PublicAccessBlock, notification and lifecycle configurations.

use crate::CairnS3;
use crate::convert::*;
use cairn_auth::{AuthError, PublicAccessBlock};
use cairn_core::{S3Error as CError, S3ErrorCode as Code, S3Result as CResult};
use cairn_engine::lifecycle::{LifecycleConfiguration, LifecycleFilter, LifecycleRule};
use s3s::dto::*;
use s3s::{S3Request, S3Response};

type Res<T> = CResult<S3Response<T>>;

fn ok<T>(t: T) -> Res<T> {
    Ok(S3Response::new(t))
}

fn auth_err(e: AuthError) -> CError {
    match e {
        AuthError::Policy(p) => CError::new(Code::MalformedPolicy, p.to_string()),
        AuthError::AccessDenied(m) => CError::new(Code::AccessDenied, m),
        AuthError::Invalid(m) => CError::new(Code::InvalidArgument, m),
        other => CError::internal(other),
    }
}

fn xml_of<T: s3s::xml::Serialize>(v: &T) -> CResult<String> {
    let mut buf = Vec::new();
    let mut ser = s3s::xml::Serializer::new(&mut buf);
    v.serialize(&mut ser).map_err(CError::internal)?;
    String::from_utf8(buf).map_err(CError::internal)
}

fn from_xml<'a, T: s3s::xml::Deserialize<'a>>(xml: &'a str) -> CResult<T> {
    let mut de = s3s::xml::Deserializer::new(xml.as_bytes());
    T::deserialize(&mut de).map_err(|e| CError::new(Code::MalformedXML, e.to_string()))
}

fn days_in(d: Option<i32>, what: &str) -> CResult<Option<u32>> {
    d.map(|n| {
        u32::try_from(n)
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| CError::new(Code::InvalidArgument, format!("{what} must be positive")))
    })
    .transpose()
}

fn size_in(n: Option<i64>) -> Option<u64> {
    n.and_then(|n| u64::try_from(n).ok())
}

fn rule_in(r: LifecycleRule_) -> CResult<LifecycleRule> {
    let mut filter = LifecycleFilter {
        prefix: r.prefix.clone().unwrap_or_default(),
        ..Default::default()
    };
    if let Some(f) = &r.filter {
        if let Some(p) = &f.prefix {
            filter.prefix = p.clone();
        }
        if let Some(t) = &f.tag {
            filter.tags = tags_in(std::slice::from_ref(t))?;
        }
        filter.size_greater_than = size_in(f.object_size_greater_than);
        filter.size_less_than = size_in(f.object_size_less_than);
        if let Some(a) = &f.and {
            if let Some(p) = &a.prefix {
                filter.prefix = p.clone();
            }
            if let Some(t) = &a.tags {
                filter.tags = tags_in(t)?;
            }
            filter.size_greater_than = size_in(a.object_size_greater_than);
            filter.size_less_than = size_in(a.object_size_less_than);
        }
    }
    if r.transitions.as_ref().is_some_and(|t| !t.is_empty())
        || r.noncurrent_version_transitions
            .as_ref()
            .is_some_and(|t| !t.is_empty())
    {
        return Err(CError::new(
            Code::NotImplemented,
            "lifecycle transitions are not supported (single storage class)",
        ));
    }
    let enabled = match r.status.as_str() {
        ExpirationStatus::ENABLED => true,
        ExpirationStatus::DISABLED => false,
        _ => {
            return Err(CError::new(
                Code::MalformedXML,
                "Rule Status must be Enabled or Disabled",
            ));
        }
    };
    let exp = r.expiration.as_ref();
    let expiration_date = match exp.and_then(|e| e.date.as_ref()) {
        None => None,
        Some(d) => Some(
            ts_in(d)
                .filter(|t| t.nanos().rem_euclid(86_400 * 1_000_000_000) == 0)
                .ok_or_else(|| {
                    CError::new(
                        Code::InvalidArgument,
                        "'Date' must be at midnight GMT in ISO 8601 format",
                    )
                })?,
        ),
    };
    Ok(LifecycleRule {
        id: r.id.clone(),
        enabled,
        filter,
        expiration_days: days_in(exp.and_then(|e| e.days), "Expiration Days")?,
        expiration_date,
        expired_object_delete_marker: exp
            .and_then(|e| e.expired_object_delete_marker)
            .unwrap_or(false),
        noncurrent_days: days_in(
            r.noncurrent_version_expiration
                .as_ref()
                .and_then(|n| n.noncurrent_days),
            "NoncurrentDays",
        )?,
        newer_noncurrent_versions: r
            .noncurrent_version_expiration
            .as_ref()
            .and_then(|n| n.newer_noncurrent_versions)
            .and_then(|n| u32::try_from(n).ok()),
        abort_incomplete_multipart_days: days_in(
            r.abort_incomplete_multipart_upload
                .as_ref()
                .and_then(|a| a.days_after_initiation),
            "DaysAfterInitiation",
        )?,
    })
}

type LifecycleRule_ = s3s::dto::LifecycleRule;

fn rule_out(r: &LifecycleRule) -> LifecycleRule_ {
    let f = &r.filter;
    let multi = usize::from(!f.prefix.is_empty())
        + f.tags.len()
        + usize::from(f.size_greater_than.is_some())
        + usize::from(f.size_less_than.is_some());
    let gt = f.size_greater_than.map(|n| n as i64);
    let lt = f.size_less_than.map(|n| n as i64);
    let filter = if multi > 1 {
        LifecycleRuleFilter {
            and: Some(LifecycleRuleAndOperator {
                prefix: Some(f.prefix.clone()),
                tags: (!f.tags.is_empty()).then(|| tags_out(&f.tags)),
                object_size_greater_than: gt,
                object_size_less_than: lt,
            }),
            ..Default::default()
        }
    } else {
        LifecycleRuleFilter {
            prefix: Some(f.prefix.clone()),
            tag: tags_out(&f.tags).into_iter().next(),
            object_size_greater_than: gt,
            object_size_less_than: lt,
            ..Default::default()
        }
    };
    let expiration = (r.expiration_days.is_some()
        || r.expiration_date.is_some()
        || r.expired_object_delete_marker)
        .then(|| LifecycleExpiration {
            days: r.expiration_days.map(|d| d as i32),
            date: r.expiration_date.map(ts_out),
            expired_object_delete_marker: r.expired_object_delete_marker.then_some(true),
        });
    LifecycleRule_ {
        id: r.id.clone(),
        status: ExpirationStatus::from_static(if r.enabled {
            ExpirationStatus::ENABLED
        } else {
            ExpirationStatus::DISABLED
        }),
        filter: Some(filter),
        expiration,
        noncurrent_version_expiration: r.noncurrent_days.map(|d| NoncurrentVersionExpiration {
            noncurrent_days: Some(d as i32),
            newer_noncurrent_versions: r.newer_noncurrent_versions.map(|n| n as i32),
        }),
        abort_incomplete_multipart_upload: r.abort_incomplete_multipart_days.map(|d| {
            AbortIncompleteMultipartUpload {
                days_after_initiation: Some(d as i32),
            }
        }),
        noncurrent_version_transitions: None,
        prefix: None,
        transitions: None,
    }
}

const ENCRYPTION: &str = "encryption";

impl CairnS3 {
    fn policies(&self) -> CResult<&cairn_auth::BucketPolicyStore> {
        self.policies
            .as_deref()
            .ok_or_else(|| CError::new(Code::NotImplemented, "bucket policies are not enabled"))
    }

    pub(crate) async fn do_put_bucket_policy(
        &self,
        req: S3Request<PutBucketPolicyInput>,
    ) -> Res<PutBucketPolicyOutput> {
        let i = req.input;
        self.engine.bucket(&i.bucket)?;
        self.policies()?
            .put_policy(&i.bucket, &i.policy)
            .await
            .map_err(auth_err)?;
        let mut r = S3Response::new(PutBucketPolicyOutput::default());
        r.status = Some(http::StatusCode::NO_CONTENT);
        Ok(r)
    }

    pub(crate) async fn do_get_bucket_policy(
        &self,
        req: S3Request<GetBucketPolicyInput>,
    ) -> Res<GetBucketPolicyOutput> {
        let b = req.input.bucket;
        self.engine.bucket(&b)?;
        let doc = self.policies()?.get_policy(&b).await.map_err(auth_err)?;
        match doc {
            Some(d) => ok(GetBucketPolicyOutput {
                policy: Some(d.to_string()),
            }),
            None => Err(CError::code(Code::NoSuchBucketPolicy).with_resource(b)),
        }
    }

    pub(crate) async fn do_delete_bucket_policy(
        &self,
        req: S3Request<DeleteBucketPolicyInput>,
    ) -> Res<DeleteBucketPolicyOutput> {
        let b = req.input.bucket;
        self.engine.bucket(&b)?;
        self.policies()?.delete_policy(&b).await.map_err(auth_err)?;
        ok(DeleteBucketPolicyOutput::default())
    }

    pub(crate) async fn do_get_bucket_policy_status(
        &self,
        req: S3Request<GetBucketPolicyStatusInput>,
    ) -> Res<GetBucketPolicyStatusOutput> {
        let b = req.input.bucket;
        self.engine.bucket(&b)?;
        match self
            .policies()?
            .policy_is_public(&b)
            .await
            .map_err(auth_err)?
        {
            Some(public) => ok(GetBucketPolicyStatusOutput {
                policy_status: Some(PolicyStatus {
                    is_public: Some(public),
                }),
            }),
            None => Err(CError::code(Code::NoSuchBucketPolicy).with_resource(b)),
        }
    }

    pub(crate) async fn do_put_public_access_block(
        &self,
        req: S3Request<PutPublicAccessBlockInput>,
    ) -> Res<PutPublicAccessBlockOutput> {
        let i = req.input;
        self.engine.bucket(&i.bucket)?;
        let c = i.public_access_block_configuration;
        let pab = PublicAccessBlock {
            block_public_acls: c.block_public_acls.unwrap_or(false),
            ignore_public_acls: c.ignore_public_acls.unwrap_or(false),
            block_public_policy: c.block_public_policy.unwrap_or(false),
            restrict_public_buckets: c.restrict_public_buckets.unwrap_or(false),
        };
        self.policies()?
            .put_public_access_block(&i.bucket, pab)
            .await
            .map_err(auth_err)?;
        ok(PutPublicAccessBlockOutput::default())
    }

    pub(crate) async fn do_get_public_access_block(
        &self,
        req: S3Request<GetPublicAccessBlockInput>,
    ) -> Res<GetPublicAccessBlockOutput> {
        let b = req.input.bucket;
        self.engine.bucket(&b)?;
        match self
            .policies()?
            .get_public_access_block(&b)
            .await
            .map_err(auth_err)?
        {
            Some(p) => ok(GetPublicAccessBlockOutput {
                public_access_block_configuration: Some(PublicAccessBlockConfiguration {
                    block_public_acls: Some(p.block_public_acls),
                    ignore_public_acls: Some(p.ignore_public_acls),
                    block_public_policy: Some(p.block_public_policy),
                    restrict_public_buckets: Some(p.restrict_public_buckets),
                }),
            }),
            None => Err(CError::code(Code::NoSuchPublicAccessBlockConfiguration).with_resource(b)),
        }
    }

    pub(crate) async fn do_delete_public_access_block(
        &self,
        req: S3Request<DeletePublicAccessBlockInput>,
    ) -> Res<DeletePublicAccessBlockOutput> {
        let b = req.input.bucket;
        self.engine.bucket(&b)?;
        self.policies()?
            .delete_public_access_block(&b)
            .await
            .map_err(auth_err)?;
        ok(DeletePublicAccessBlockOutput::default())
    }

    pub(crate) async fn do_put_bucket_notification_configuration(
        &self,
        req: S3Request<PutBucketNotificationConfigurationInput>,
    ) -> Res<PutBucketNotificationConfigurationOutput> {
        let i = req.input;
        let xml = xml_of(&i.notification_configuration)?;
        let cfg = cairn_engine::cairn_events::NotificationConfiguration::from_xml(&xml)?;
        if !i.skip_destination_validation.unwrap_or(false) {
            let known = &self.sink_arns;
            cfg.validate_destinations(|arn| known.iter().any(|k| k == arn))?;
        }
        self.engine.put_bucket_notification(&i.bucket, cfg).await?;
        ok(PutBucketNotificationConfigurationOutput::default())
    }

    pub(crate) async fn do_get_bucket_notification_configuration(
        &self,
        req: S3Request<GetBucketNotificationConfigurationInput>,
    ) -> Res<GetBucketNotificationConfigurationOutput> {
        let cfg = self.engine.get_bucket_notification(&req.input.bucket)?;
        let n: NotificationConfiguration = from_xml(&cfg.to_xml())?;
        ok(GetBucketNotificationConfigurationOutput {
            event_bridge_configuration: n.event_bridge_configuration,
            lambda_function_configurations: n.lambda_function_configurations,
            queue_configurations: n.queue_configurations,
            topic_configurations: n.topic_configurations,
        })
    }

    pub(crate) async fn do_put_bucket_lifecycle_configuration(
        &self,
        req: S3Request<PutBucketLifecycleConfigurationInput>,
    ) -> Res<PutBucketLifecycleConfigurationOutput> {
        let i = req.input;
        let rules = i
            .lifecycle_configuration
            .map(|c| c.rules)
            .unwrap_or_default()
            .into_iter()
            .map(rule_in)
            .collect::<CResult<Vec<_>>>()?;
        let mut rules = rules;
        let mut n = 0;
        // S3 assigns an ID to a rule sent without one; it appears in GET and x-amz-expiration.
        for i in 0..rules.len() {
            if rules[i].id.is_none() {
                let id = loop {
                    n += 1;
                    let id = format!("rule-{n}");
                    if !rules.iter().any(|r| r.id.as_deref() == Some(&id)) {
                        break id;
                    }
                };
                rules[i].id = Some(id);
            }
        }
        self.engine
            .put_bucket_lifecycle(&i.bucket, LifecycleConfiguration { rules })
            .await?;
        ok(PutBucketLifecycleConfigurationOutput::default())
    }

    pub(crate) async fn do_get_bucket_lifecycle_configuration(
        &self,
        req: S3Request<GetBucketLifecycleConfigurationInput>,
    ) -> Res<GetBucketLifecycleConfigurationOutput> {
        let b = req.input.bucket;
        match self.engine.get_bucket_lifecycle(&b)? {
            Some(c) => ok(GetBucketLifecycleConfigurationOutput {
                rules: Some(c.rules.iter().map(rule_out).collect()),
                ..Default::default()
            }),
            None => Err(CError::code(Code::NoSuchLifecycleConfiguration).with_resource(b)),
        }
    }

    pub(crate) async fn do_delete_bucket_lifecycle(
        &self,
        req: S3Request<DeleteBucketLifecycleInput>,
    ) -> Res<DeleteBucketLifecycleOutput> {
        self.engine
            .delete_bucket_lifecycle(&req.input.bucket)
            .await?;
        ok(DeleteBucketLifecycleOutput::default())
    }

    /// PutBucketEncryption: only SSE-S3 (`AES256`), and only when the store has a master key,
    /// because the key is store-wide: with one configured every blob is already encrypted, so the
    /// stored document describes what is true rather than switching anything on.
    pub(crate) async fn do_put_bucket_encryption(
        &self,
        req: S3Request<PutBucketEncryptionInput>,
    ) -> Res<PutBucketEncryptionOutput> {
        let i = req.input;
        self.engine.bucket(&i.bucket)?;
        let rules = &i.server_side_encryption_configuration.rules;
        let sse_s3 = !rules.is_empty()
            && rules.iter().all(|r| {
                r.apply_server_side_encryption_by_default
                    .as_ref()
                    .is_some_and(|d| {
                        d.sse_algorithm.as_str() == "AES256" && d.kms_master_key_id.is_none()
                    })
            });
        if !sse_s3 {
            return Err(CError::new(
                Code::NotImplemented,
                "only SSE-S3 (AES256) bucket encryption is supported",
            ));
        }
        if self.engine.config().at_rest_key.is_none() {
            return Err(CError::new(
                Code::InvalidRequest,
                "SSE-S3 needs a store master key (storage.master_key_file); see OPERATIONS.md",
            ));
        }
        self.engine
            .put_bucket_config(&i.bucket, ENCRYPTION, Some(b"AES256".to_vec()))
            .await?;
        ok(PutBucketEncryptionOutput::default())
    }

    pub(crate) async fn do_get_bucket_encryption(
        &self,
        req: S3Request<GetBucketEncryptionInput>,
    ) -> Res<GetBucketEncryptionOutput> {
        let b = req.input.bucket;
        if !self.engine.bucket(&b)?.configs.contains_key(ENCRYPTION) {
            return Err(
                CError::code(Code::ServerSideEncryptionConfigurationNotFoundError).with_resource(b),
            );
        }
        ok(GetBucketEncryptionOutput {
            server_side_encryption_configuration: Some(ServerSideEncryptionConfiguration {
                rules: vec![ServerSideEncryptionRule {
                    apply_server_side_encryption_by_default: Some(ServerSideEncryptionByDefault {
                        sse_algorithm: ServerSideEncryption::from_static(
                            ServerSideEncryption::AES256,
                        ),
                        kms_master_key_id: None,
                    }),
                    bucket_key_enabled: Some(false),
                    ..Default::default()
                }],
            }),
        })
    }

    pub(crate) async fn do_delete_bucket_encryption(
        &self,
        req: S3Request<DeleteBucketEncryptionInput>,
    ) -> Res<DeleteBucketEncryptionOutput> {
        let b = req.input.bucket;
        self.engine.bucket(&b)?;
        self.engine.put_bucket_config(&b, ENCRYPTION, None).await?;
        let mut r = S3Response::new(DeleteBucketEncryptionOutput::default());
        r.status = Some(http::StatusCode::NO_CONTENT);
        Ok(r)
    }
}
