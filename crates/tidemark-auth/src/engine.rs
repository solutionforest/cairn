//! `AuthzEngine`: the facade tidemark-s3 / tidemark-admin / tidemark-mcp call per request.

use crate::actions;
use crate::arn;
use crate::eval::{AuthzRequest, ConditionContext, Decision, PolicySet, PublicAccessBlock};
use crate::policy::PolicyDocument;
use crate::principal::Principal;
use crate::types::{Clock, SystemClock};
use std::net::IpAddr;
use std::sync::Arc;

/// Bucket-level authorisation inputs (owned by the engine's bucket record).
#[derive(Debug, Clone, Default)]
pub struct BucketAuthz {
    /// Bucket policy, if any.
    pub policy: Option<PolicyDocument>,
    /// PublicAccessBlock settings.
    pub public_access_block: PublicAccessBlock,
}

/// Stateless authoriser; fills principal- and time-derived condition keys, enforces
/// access-key source CIDRs, then evaluates the [`PolicySet`].
#[derive(Clone)]
pub struct AuthzEngine {
    clock: Arc<dyn Clock>,
}

impl Default for AuthzEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AuthzEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthzEngine")
    }
}

impl AuthzEngine {
    /// Engine using the system clock.
    pub fn new() -> Self {
        Self {
            clock: Arc::new(SystemClock),
        }
    }

    /// Engine with an injected clock (tests).
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self { clock }
    }

    /// Context with `aws:username`, `aws:userid`, `aws:PrincipalArn`, `aws:PrincipalType`,
    /// `aws:PrincipalTag/<k>`, `aws:CurrentTime`, `aws:EpochTime` added when absent. Principal keys always overwrite
    /// caller-supplied values so they cannot be spoofed.
    pub fn enrich(
        &self,
        principal: Option<&Principal>,
        ctx: &ConditionContext,
    ) -> ConditionContext {
        let mut c = ctx.clone();
        for k in [
            "aws:username",
            "aws:userid",
            "aws:principalarn",
            "aws:principaltype",
            "aws:principalaccount",
        ] {
            c.remove(k);
        }
        c.remove_prefix("aws:PrincipalTag/");
        match principal {
            Some(p) => {
                for (k, v) in &p.tags {
                    c.insert(&format!("aws:PrincipalTag/{k}"), v.clone());
                }
                if let Some(u) = p.username() {
                    c.insert("aws:username", u);
                }
                c.insert("aws:userid", p.user_id.clone());
                c.insert("aws:PrincipalArn", p.arn.clone());
                c.insert("aws:PrincipalAccount", crate::types::ACCOUNT_ID);
                let ty = match p.kind {
                    crate::principal::PrincipalKind::Root => "Account",
                    crate::principal::PrincipalKind::User { .. } => "User",
                    crate::principal::PrincipalKind::AssumedRole { .. } => "AssumedRole",
                };
                c.insert("aws:PrincipalType", ty);
            }
            None => {
                c.insert("aws:PrincipalType", "Anonymous");
            }
        }
        let now = self.clock.now();
        if !c.contains("aws:CurrentTime") {
            c.insert("aws:CurrentTime", now.to_rfc3339());
        }
        if !c.contains("aws:EpochTime") {
            c.insert("aws:EpochTime", now.as_secs().to_string());
        }
        c
    }

    /// Authorise `action` on `resource` (ARN). `principal = None` means anonymous.
    pub fn authorize(
        &self,
        principal: Option<&Principal>,
        action: &str,
        resource: &str,
        ctx: &ConditionContext,
        bucket: Option<&BucketAuthz>,
    ) -> Decision {
        if let Some(p) = principal
            && !p.allowed_source_cidrs.is_empty()
        {
            let ok = ctx
                .get("aws:SourceIp")
                .and_then(|v| v.first())
                .and_then(|ip| ip.parse::<IpAddr>().ok())
                .is_some_and(|ip| p.allowed_source_cidrs.iter().any(|n| n.contains(&ip)));
            if !ok {
                return Decision::Deny;
            }
        }
        let ctx = self.enrich(principal, ctx);
        let set = PolicySet::for_principal(
            principal,
            bucket.and_then(|b| b.policy.clone()),
            bucket.map(|b| b.public_access_block).unwrap_or_default(),
        );
        set.evaluate(&AuthzRequest {
            principal,
            action,
            resource,
            context: &ctx,
        })
    }

    /// Convenience: authorise an s3s operation by name on `bucket`/`key`.
    /// Unknown operations are denied.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize_s3(
        &self,
        principal: Option<&Principal>,
        op: &str,
        bucket_name: Option<&str>,
        key: Option<&str>,
        has_version_id: bool,
        ctx: &ConditionContext,
        bucket: Option<&BucketAuthz>,
    ) -> Decision {
        let Some(action) = actions::for_s3_operation_versioned(op, has_version_id) else {
            return Decision::Deny;
        };
        let resource = match (bucket_name, key) {
            (Some(b), Some(k)) => arn::object(b, k),
            (Some(b), None) => arn::bucket(b),
            _ => "*".to_string(),
        };
        self.authorize(principal, action, &resource, ctx, bucket)
    }
}
