//! ACLs, the way S3 has defaulted to since April 2023: every bucket is `BucketOwnerEnforced`.
//! The bucket owner owns every object and holds FULL_CONTROL; access is granted by IAM and
//! bucket policies only. Reads return that single grant. Writes that ask for nothing more
//! (`private`, `bucket-owner-full-control`, or an explicit owner-only FULL_CONTROL policy)
//! succeed as no-ops; anything that would grant access to someone else is refused with
//! `AccessControlListNotSupported`, as S3 does on an enforced bucket. ACL headers sent along
//! with a write (CreateBucket, PutObject, CopyObject, CreateMultipartUpload) are ignored, as
//! MinIO does: apps such as Mastodon send `x-amz-acl: public-read` on every upload and grant
//! public reads with a bucket policy. See DECISIONS.md.

use crate::CairnS3;
use crate::convert::*;
use cairn_core::{PrincipalId, S3ErrorCode as Code, S3Result as CResult};
use cairn_engine::GetObjectReq;
use s3s::dto::*;
use s3s::{S3Request, S3Response};

type Res<T> = CResult<S3Response<T>>;

const ENFORCED: &str = "BucketOwnerEnforced";

fn not_supported() -> cairn_core::S3Error {
    err(
        Code::AccessControlListNotSupported,
        "The bucket does not allow ACLs",
    )
}

fn owner_of(p: &PrincipalId) -> Owner {
    Owner {
        display_name: Some(p.as_str().to_string()),
        id: Some(p.as_str().to_string()),
    }
}

fn owner_grants(p: &PrincipalId) -> Grants {
    vec![Grant {
        grantee: Some(Grantee {
            display_name: Some(p.as_str().to_string()),
            email_address: None,
            id: Some(p.as_str().to_string()),
            type_: Type::from_static(Type::CANONICAL_USER),
            uri: None,
        }),
        permission: Some(Permission::from_static(Permission::FULL_CONTROL)),
    }]
}

/// A canned ACL is acceptable when it grants nobody but the bucket owner.
pub(crate) fn canned_ok(acl: Option<&str>) -> bool {
    matches!(
        acl,
        None | Some("private") | Some("bucket-owner-full-control")
    )
}

/// `x-amz-grant-full-control` naming only the owner is a no-op; any other grant header is not.
fn grant_headers_ok(owner: &PrincipalId, full: Option<&str>, others: &[Option<&str>]) -> bool {
    if others.iter().any(Option::is_some) {
        return false;
    }
    full.is_none_or(|g| {
        g.split(',').all(|part| {
            let v = part.trim();
            v.strip_prefix("id=")
                .map(|id| id.trim_matches('"') == owner.as_str())
                .unwrap_or(false)
        })
    })
}

fn policy_ok(owner: &PrincipalId, p: Option<&AccessControlPolicy>) -> bool {
    let Some(p) = p else { return true };
    p.grants.as_deref().unwrap_or_default().iter().all(|g| {
        g.permission
            .as_ref()
            .is_some_and(|x| x.as_str() == Permission::FULL_CONTROL)
            && g.grantee.as_ref().is_some_and(|e| {
                e.type_.as_str() == Type::CANONICAL_USER && e.id.as_deref() == Some(owner.as_str())
            })
    })
}

fn ownership_rule() -> OwnershipControls {
    OwnershipControls {
        rules: vec![OwnershipControlsRule {
            object_ownership: ObjectOwnership::from_static(ENFORCED),
        }],
    }
}

impl CairnS3 {
    pub(crate) async fn do_get_bucket_acl(
        &self,
        req: S3Request<GetBucketAclInput>,
    ) -> Res<GetBucketAclOutput> {
        let b = self.engine.bucket(&req.input.bucket)?;
        Ok(S3Response::new(GetBucketAclOutput {
            grants: Some(owner_grants(&b.owner)),
            owner: Some(owner_of(&b.owner)),
        }))
    }

    pub(crate) async fn do_put_bucket_acl(
        &self,
        req: S3Request<PutBucketAclInput>,
    ) -> Res<PutBucketAclOutput> {
        let i = req.input;
        let b = self.engine.bucket(&i.bucket)?;
        let ok = canned_ok(i.acl.as_ref().map(|a| a.as_str()))
            && grant_headers_ok(
                &b.owner,
                i.grant_full_control.as_deref(),
                &[
                    i.grant_read.as_deref(),
                    i.grant_read_acp.as_deref(),
                    i.grant_write.as_deref(),
                    i.grant_write_acp.as_deref(),
                ],
            )
            && policy_ok(&b.owner, i.access_control_policy.as_ref());
        if !ok {
            return Err(not_supported());
        }
        Ok(S3Response::new(PutBucketAclOutput::default()))
    }

    pub(crate) async fn do_get_object_acl(
        &self,
        req: S3Request<GetObjectAclInput>,
    ) -> Res<GetObjectAclOutput> {
        let i = req.input;
        let b = self.engine.bucket(&i.bucket)?;
        self.engine
            .get_object(
                GetObjectReq {
                    bucket: i.bucket,
                    key: i.key,
                    version_id: i.version_id,
                    ..Default::default()
                },
                false,
            )
            .await?;
        Ok(S3Response::new(GetObjectAclOutput {
            grants: Some(owner_grants(&b.owner)),
            owner: Some(owner_of(&b.owner)),
            request_charged: None,
        }))
    }

    pub(crate) async fn do_put_object_acl(
        &self,
        req: S3Request<PutObjectAclInput>,
    ) -> Res<PutObjectAclOutput> {
        let i = req.input;
        let b = self.engine.bucket(&i.bucket)?;
        self.engine
            .get_object(
                GetObjectReq {
                    bucket: i.bucket,
                    key: i.key,
                    version_id: i.version_id,
                    ..Default::default()
                },
                false,
            )
            .await?;
        let ok = canned_ok(i.acl.as_ref().map(|a| a.as_str()))
            && grant_headers_ok(
                &b.owner,
                i.grant_full_control.as_deref(),
                &[
                    i.grant_read.as_deref(),
                    i.grant_read_acp.as_deref(),
                    i.grant_write.as_deref(),
                    i.grant_write_acp.as_deref(),
                ],
            )
            && policy_ok(&b.owner, i.access_control_policy.as_ref());
        if !ok {
            return Err(not_supported());
        }
        Ok(S3Response::new(PutObjectAclOutput::default()))
    }

    pub(crate) async fn do_get_bucket_ownership_controls(
        &self,
        req: S3Request<GetBucketOwnershipControlsInput>,
    ) -> Res<GetBucketOwnershipControlsOutput> {
        self.engine.bucket(&req.input.bucket)?;
        Ok(S3Response::new(GetBucketOwnershipControlsOutput {
            ownership_controls: Some(ownership_rule()),
        }))
    }

    pub(crate) async fn do_put_bucket_ownership_controls(
        &self,
        req: S3Request<PutBucketOwnershipControlsInput>,
    ) -> Res<PutBucketOwnershipControlsOutput> {
        let i = req.input;
        self.engine.bucket(&i.bucket)?;
        let enforced = !i.ownership_controls.rules.is_empty()
            && i.ownership_controls
                .rules
                .iter()
                .all(|r| r.object_ownership.as_str() == ENFORCED);
        if !enforced {
            return Err(err(
                Code::InvalidArgument,
                "Cairn buckets are always BucketOwnerEnforced; ACL-based ownership is not supported",
            ));
        }
        Ok(S3Response::new(PutBucketOwnershipControlsOutput::default()))
    }
}
