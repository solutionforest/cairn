//! Canonical IAM action names (`s3:*`, `sts:*`, `cairn:*`) and the s3s operation → action map.

/// Every `s3:` action Cairn understands (AWS names; unsupported features still validate).
pub const S3_ACTIONS: &[&str] = &[
    "s3:AbortMultipartUpload",
    "s3:BypassGovernanceRetention",
    "s3:CreateBucket",
    "s3:DeleteBucket",
    "s3:DeleteBucketOwnershipControls",
    "s3:DeleteBucketPolicy",
    "s3:DeleteBucketWebsite",
    "s3:DeleteObject",
    "s3:DeleteObjectTagging",
    "s3:DeleteObjectVersion",
    "s3:DeleteObjectVersionTagging",
    "s3:GetAccelerateConfiguration",
    "s3:GetAnalyticsConfiguration",
    "s3:GetBucketAcl",
    "s3:GetBucketCORS",
    "s3:GetBucketLocation",
    "s3:GetBucketLogging",
    "s3:GetBucketNotification",
    "s3:GetBucketObjectLockConfiguration",
    "s3:GetBucketOwnershipControls",
    "s3:GetBucketPolicy",
    "s3:GetBucketPolicyStatus",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketRequestPayment",
    "s3:GetBucketTagging",
    "s3:GetBucketVersioning",
    "s3:GetBucketWebsite",
    "s3:GetEncryptionConfiguration",
    "s3:GetInventoryConfiguration",
    "s3:GetLifecycleConfiguration",
    "s3:GetMetricsConfiguration",
    "s3:GetObject",
    "s3:GetObjectAcl",
    "s3:GetObjectAttributes",
    "s3:GetObjectLegalHold",
    "s3:GetObjectRetention",
    "s3:GetObjectTagging",
    "s3:GetObjectVersion",
    "s3:GetObjectVersionAcl",
    "s3:GetObjectVersionAttributes",
    "s3:GetObjectVersionTagging",
    "s3:GetReplicationConfiguration",
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "s3:ListBucketMultipartUploads",
    "s3:ListBucketVersions",
    "s3:ListMultipartUploadParts",
    "s3:PutAccelerateConfiguration",
    "s3:PutBucketAcl",
    "s3:PutBucketCORS",
    "s3:PutBucketLogging",
    "s3:PutBucketNotification",
    "s3:PutBucketObjectLockConfiguration",
    "s3:PutBucketOwnershipControls",
    "s3:PutBucketPolicy",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutBucketRequestPayment",
    "s3:PutBucketTagging",
    "s3:PutBucketVersioning",
    "s3:PutBucketWebsite",
    "s3:PutEncryptionConfiguration",
    "s3:PutLifecycleConfiguration",
    "s3:PutObject",
    "s3:PutObjectAcl",
    "s3:PutObjectLegalHold",
    "s3:PutObjectRetention",
    "s3:PutObjectTagging",
    "s3:PutObjectVersionAcl",
    "s3:PutObjectVersionTagging",
    "s3:PutReplicationConfiguration",
    "s3:ReplicateDelete",
    "s3:ReplicateObject",
    "s3:ReplicateTags",
    "s3:RestoreObject",
];

/// `sts:` actions.
pub const STS_ACTIONS: &[&str] = &[
    "sts:AssumeRole",
    "sts:AssumeRoleWithWebIdentity",
    "sts:GetCallerIdentity",
    "sts:GetSessionToken",
    "sts:TagSession",
];

/// `cairn:` admin / extension actions (DESIGN §7.3, §8.2, §11.1).
pub const CAIRN_ACTIONS: &[&str] = &[
    // IAM administration
    "cairn:CreateUser",
    "cairn:DeleteUser",
    "cairn:GetUser",
    "cairn:ListUsers",
    "cairn:UpdateUser",
    "cairn:CreateAccessKey",
    "cairn:DeleteAccessKey",
    "cairn:ListAccessKeys",
    "cairn:UpdateAccessKey",
    "cairn:RotateRootCredentials",
    "cairn:CreateGroup",
    "cairn:DeleteGroup",
    "cairn:GetGroup",
    "cairn:ListGroups",
    "cairn:AddUserToGroup",
    "cairn:RemoveUserFromGroup",
    "cairn:CreateRole",
    "cairn:DeleteRole",
    "cairn:GetRole",
    "cairn:ListRoles",
    "cairn:UpdateAssumeRolePolicy",
    "cairn:CreatePolicy",
    "cairn:DeletePolicy",
    "cairn:GetPolicy",
    "cairn:ListPolicies",
    "cairn:AttachUserPolicy",
    "cairn:DetachUserPolicy",
    "cairn:AttachGroupPolicy",
    "cairn:DetachGroupPolicy",
    "cairn:AttachRolePolicy",
    "cairn:DetachRolePolicy",
    "cairn:PutUserPolicy",
    "cairn:DeleteUserPolicy",
    "cairn:PutGroupPolicy",
    "cairn:DeleteGroupPolicy",
    "cairn:PutRolePolicy",
    "cairn:DeleteRolePolicy",
    "cairn:CreateServiceAccount",
    // Recovery / time travel (§7)
    "cairn:ListTrash",
    "cairn:Restore",
    "cairn:RestoreBucket",
    "cairn:Purge",
    "cairn:TimeTravel",
    "cairn:Pitr",
    "cairn:PitrDiff",
    "cairn:SetRetention",
    "cairn:GetRetention",
    // Operations
    "cairn:ManageReplication",
    "cairn:ManageQuota",
    "cairn:ManageKms",
    "cairn:ManageEvents",
    "cairn:Backup",
    "cairn:Fsck",
    "cairn:Scrub",
    "cairn:Gc",
    "cairn:GetServerInfo",
    "cairn:GetStorageStats",
    "cairn:ReadAuditLog",
    "cairn:SubscribeEvents",
    "cairn:Search",
];

/// Iterator over every canonical action.
pub fn all() -> impl Iterator<Item = &'static str> {
    S3_ACTIONS
        .iter()
        .chain(STS_ACTIONS)
        .chain(CAIRN_ACTIONS)
        .copied()
}

/// Case-insensitive exact lookup of a canonical action; returns its canonical spelling.
pub fn canonical(action: &str) -> Option<&'static str> {
    all().find(|a| a.eq_ignore_ascii_case(action))
}

/// Map an s3s operation name (e.g. "ListObjectsV2") to the IAM action it requires.
///
/// Returns `None` for operations Cairn does not authorise (they must be rejected).
/// Versioned variants (`s3:GetObjectVersion`, …) are chosen by [`for_s3_operation_versioned`].
/// `CopyObject`/`UploadPartCopy` additionally need `s3:GetObject` on the source; the caller
/// must authorise that separately.
pub fn for_s3_operation(op: &str) -> Option<&'static str> {
    Some(match op {
        // service / bucket
        "ListBuckets" => "s3:ListAllMyBuckets",
        "CreateBucket" => "s3:CreateBucket",
        "DeleteBucket" => "s3:DeleteBucket",
        "HeadBucket" => "s3:ListBucket",
        "GetBucketLocation" => "s3:GetBucketLocation",
        "GetBucketVersioning" => "s3:GetBucketVersioning",
        "PutBucketVersioning" => "s3:PutBucketVersioning",
        "GetBucketTagging" => "s3:GetBucketTagging",
        "PutBucketTagging" | "DeleteBucketTagging" => "s3:PutBucketTagging",
        "GetBucketPolicy" => "s3:GetBucketPolicy",
        "PutBucketPolicy" => "s3:PutBucketPolicy",
        "DeleteBucketPolicy" => "s3:DeleteBucketPolicy",
        "GetBucketPolicyStatus" => "s3:GetBucketPolicyStatus",
        "GetBucketLifecycleConfiguration" | "GetBucketLifecycle" => "s3:GetLifecycleConfiguration",
        "PutBucketLifecycleConfiguration" | "PutBucketLifecycle" | "DeleteBucketLifecycle" => {
            "s3:PutLifecycleConfiguration"
        }
        "GetBucketCors" => "s3:GetBucketCORS",
        "PutBucketCors" | "DeleteBucketCors" => "s3:PutBucketCORS",
        "GetBucketEncryption" => "s3:GetEncryptionConfiguration",
        "PutBucketEncryption" | "DeleteBucketEncryption" => "s3:PutEncryptionConfiguration",
        "GetBucketOwnershipControls" => "s3:GetBucketOwnershipControls",
        "PutBucketOwnershipControls" => "s3:PutBucketOwnershipControls",
        "DeleteBucketOwnershipControls" => "s3:DeleteBucketOwnershipControls",
        "GetPublicAccessBlock" => "s3:GetBucketPublicAccessBlock",
        "PutPublicAccessBlock" | "DeletePublicAccessBlock" => "s3:PutBucketPublicAccessBlock",
        "GetBucketAcl" => "s3:GetBucketAcl",
        "PutBucketAcl" => "s3:PutBucketAcl",
        "GetBucketNotificationConfiguration" => "s3:GetBucketNotification",
        "PutBucketNotificationConfiguration" => "s3:PutBucketNotification",
        "GetBucketReplication" => "s3:GetReplicationConfiguration",
        "PutBucketReplication" | "DeleteBucketReplication" => "s3:PutReplicationConfiguration",
        "GetObjectLockConfiguration" => "s3:GetBucketObjectLockConfiguration",
        "PutObjectLockConfiguration" => "s3:PutBucketObjectLockConfiguration",
        // object
        "PutObject" | "PostObject" | "CopyObject" => "s3:PutObject",
        "GetObject" | "HeadObject" => "s3:GetObject",
        "DeleteObject" | "DeleteObjects" => "s3:DeleteObject",
        "ListObjects" | "ListObjectsV2" => "s3:ListBucket",
        "ListObjectVersions" => "s3:ListBucketVersions",
        "GetObjectTagging" => "s3:GetObjectTagging",
        "PutObjectTagging" => "s3:PutObjectTagging",
        "DeleteObjectTagging" => "s3:DeleteObjectTagging",
        "GetObjectAttributes" => "s3:GetObjectAttributes",
        "GetObjectAcl" => "s3:GetObjectAcl",
        "PutObjectAcl" => "s3:PutObjectAcl",
        "GetObjectRetention" => "s3:GetObjectRetention",
        "PutObjectRetention" => "s3:PutObjectRetention",
        "GetObjectLegalHold" => "s3:GetObjectLegalHold",
        "PutObjectLegalHold" => "s3:PutObjectLegalHold",
        // multipart
        "CreateMultipartUpload" | "UploadPart" | "UploadPartCopy" | "CompleteMultipartUpload" => {
            "s3:PutObject"
        }
        "AbortMultipartUpload" => "s3:AbortMultipartUpload",
        "ListParts" => "s3:ListMultipartUploadParts",
        "ListMultipartUploads" => "s3:ListBucketMultipartUploads",
        // sts
        "AssumeRole" => "sts:AssumeRole",
        "GetSessionToken" => "sts:GetSessionToken",
        "AssumeRoleWithWebIdentity" => "sts:AssumeRoleWithWebIdentity",
        "GetCallerIdentity" => "sts:GetCallerIdentity",
        _ => return None,
    })
}

/// Like [`for_s3_operation`] but selects the `*Version*` action when a `versionId` is present.
pub fn for_s3_operation_versioned(op: &str, has_version_id: bool) -> Option<&'static str> {
    if has_version_id {
        let v = match op {
            "GetObject" | "HeadObject" => Some("s3:GetObjectVersion"),
            "DeleteObject" => Some("s3:DeleteObjectVersion"),
            "GetObjectTagging" => Some("s3:GetObjectVersionTagging"),
            "PutObjectTagging" => Some("s3:PutObjectVersionTagging"),
            "DeleteObjectTagging" => Some("s3:DeleteObjectVersionTagging"),
            "GetObjectAcl" => Some("s3:GetObjectVersionAcl"),
            "PutObjectAcl" => Some("s3:PutObjectVersionAcl"),
            "GetObjectAttributes" => Some("s3:GetObjectVersionAttributes"),
            _ => None,
        };
        if v.is_some() {
            return v;
        }
    }
    for_s3_operation(op)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every operation marked ✅ or 🟡 in DESIGN §6.
    const DESIGN_OPS: &[&str] = &[
        "ListBuckets",
        "CreateBucket",
        "DeleteBucket",
        "HeadBucket",
        "GetBucketLocation",
        "GetBucketVersioning",
        "PutBucketVersioning",
        "GetBucketTagging",
        "PutBucketTagging",
        "DeleteBucketTagging",
        "GetBucketPolicy",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "GetBucketPolicyStatus",
        "GetBucketLifecycleConfiguration",
        "PutBucketLifecycleConfiguration",
        "DeleteBucketLifecycle",
        "GetBucketCors",
        "PutBucketCors",
        "DeleteBucketCors",
        "GetBucketEncryption",
        "PutBucketEncryption",
        "DeleteBucketEncryption",
        "GetPublicAccessBlock",
        "PutPublicAccessBlock",
        "DeletePublicAccessBlock",
        "GetBucketNotificationConfiguration",
        "PutBucketNotificationConfiguration",
        "GetBucketReplication",
        "PutBucketReplication",
        "DeleteBucketReplication",
        "GetObjectLockConfiguration",
        "PutObjectLockConfiguration",
        "PutObject",
        "GetObject",
        "HeadObject",
        "DeleteObject",
        "DeleteObjects",
        "CopyObject",
        "ListObjects",
        "ListObjectsV2",
        "ListObjectVersions",
        "GetObjectTagging",
        "PutObjectTagging",
        "DeleteObjectTagging",
        "GetObjectAttributes",
        "GetObjectRetention",
        "PutObjectRetention",
        "GetObjectLegalHold",
        "PutObjectLegalHold",
        "PostObject",
        "CreateMultipartUpload",
        "UploadPart",
        "UploadPartCopy",
        "CompleteMultipartUpload",
        "AbortMultipartUpload",
        "ListParts",
        "ListMultipartUploads",
        "AssumeRole",
        "GetSessionToken",
        "AssumeRoleWithWebIdentity",
        // ⚪ (accepted, stored)
        "GetBucketOwnershipControls",
        "PutBucketOwnershipControls",
        "DeleteBucketOwnershipControls",
        "GetBucketAcl",
        "PutBucketAcl",
        "GetObjectAcl",
        "PutObjectAcl",
    ];

    #[test]
    fn every_design_op_maps_to_a_canonical_action() {
        for op in DESIGN_OPS {
            let a = for_s3_operation(op).unwrap_or_else(|| panic!("{op} unmapped"));
            assert_eq!(canonical(a), Some(a), "{op} -> {a} not canonical");
        }
    }

    #[test]
    fn spot_checks() {
        assert_eq!(for_s3_operation("PutObject"), Some("s3:PutObject"));
        assert_eq!(for_s3_operation("ListObjectsV2"), Some("s3:ListBucket"));
        assert_eq!(
            for_s3_operation("GetBucketLocation"),
            Some("s3:GetBucketLocation")
        );
        assert_eq!(
            for_s3_operation("CompleteMultipartUpload"),
            Some("s3:PutObject")
        );
        assert_eq!(for_s3_operation("DeleteObjects"), Some("s3:DeleteObject"));
        assert_eq!(
            for_s3_operation("GetObjectTagging"),
            Some("s3:GetObjectTagging")
        );
        assert_eq!(for_s3_operation("SelectObjectContent"), None);
        assert_eq!(
            for_s3_operation_versioned("GetObject", true),
            Some("s3:GetObjectVersion")
        );
        assert_eq!(
            for_s3_operation_versioned("PutObject", true),
            Some("s3:PutObject")
        );
    }

    #[test]
    fn canonical_lists_are_unique_and_namespaced() {
        let mut v: Vec<String> = all().map(|a| a.to_ascii_lowercase()).collect();
        let n = v.len();
        v.sort();
        v.dedup();
        assert_eq!(v.len(), n);
        assert!(
            all().all(|a| a.starts_with("s3:") || a.starts_with("sts:") || a.starts_with("cairn:"))
        );
        assert_eq!(canonical("S3:getobject"), Some("s3:GetObject"));
    }
}
