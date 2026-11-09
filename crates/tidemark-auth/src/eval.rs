//! Policy evaluation (AWS semantics, single account).

use crate::pattern::{VarResolver, normalize_key};
use crate::policy::{Effect, PolicyDocument, PrincipalMatch, Statement};
use crate::principal::Principal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Authorisation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Explicitly or effectively allowed.
    Allow,
    /// Explicit Deny matched.
    Deny,
    /// Nothing allowed it (implicit deny).
    Implicit,
}

impl Decision {
    /// True only for `Allow`.
    pub fn is_allowed(self) -> bool {
        self == Decision::Allow
    }
}

/// Request condition context: key (case-insensitive namespace) → values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConditionContext {
    map: HashMap<String, Vec<String>>,
}

impl ConditionContext {
    /// Empty context.
    pub fn new() -> Self {
        Self::default()
    }
    /// Append a value to `key`.
    pub fn insert(&mut self, key: &str, value: impl Into<String>) -> &mut Self {
        self.map
            .entry(normalize_key(key))
            .or_default()
            .push(value.into());
        self
    }
    /// Replace all values of `key`.
    pub fn set(&mut self, key: &str, values: Vec<String>) -> &mut Self {
        self.map.insert(normalize_key(key), values);
        self
    }
    /// Builder form of [`insert`](Self::insert).
    pub fn with(mut self, key: &str, value: impl Into<String>) -> Self {
        self.insert(key, value);
        self
    }
    /// Values of `key`.
    pub fn get(&self, key: &str) -> Option<&[String]> {
        self.map.get(&normalize_key(key)).map(Vec::as_slice)
    }
    /// True if `key` is present.
    pub fn contains(&self, key: &str) -> bool {
        self.map.contains_key(&normalize_key(key))
    }
    /// Remove `key`.
    pub fn remove(&mut self, key: &str) -> Option<Vec<String>> {
        self.map.remove(&normalize_key(key))
    }
    /// Remove every key whose normalised form starts with `prefix` (e.g. `aws:principaltag/`).
    pub fn remove_prefix(&mut self, prefix: &str) {
        let p = normalize_key(prefix);
        self.map.retain(|k, _| !k.starts_with(&p));
    }
}

impl VarResolver for ConditionContext {
    fn var(&self, key: &str) -> Option<String> {
        match self.map.get(key).map(Vec::as_slice) {
            Some([v]) => Some(v.clone()),
            _ => None,
        }
    }
}

/// S3 PublicAccessBlock configuration of a bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAccessBlock {
    /// Reject PUTs of public ACLs (ACLs are canned-only in Tidemark; enforced by tidemark-s3).
    pub block_public_acls: bool,
    /// Ignore public ACLs.
    pub ignore_public_acls: bool,
    /// Reject PutBucketPolicy of a public policy (check with `PolicyDocument::is_public`).
    pub block_public_policy: bool,
    /// Ignore public grants of the bucket policy for anonymous callers.
    pub restrict_public_buckets: bool,
}

/// Outcome of matching a resource policy alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceVerdict {
    /// A Deny statement applies.
    Deny,
    /// Best-matching Allow statement and how the principal matched.
    Allow(PrincipalMatch),
    /// No statement applies.
    NoMatch,
}

/// One authorisation request.
#[derive(Debug, Clone, Copy)]
pub struct AuthzRequest<'a> {
    /// Caller; `None` for anonymous.
    pub principal: Option<&'a Principal>,
    /// IAM action, e.g. `s3:GetObject`.
    pub action: &'a str,
    /// Resource ARN.
    pub resource: &'a str,
    /// Condition context (should already contain principal-derived keys; see `AuthzEngine`).
    pub context: &'a ConditionContext,
}

/// Every policy relevant to one request.
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    /// Identity policies (user + groups, or role).
    pub identity: Vec<PolicyDocument>,
    /// Session policy (intersects identity and wide resource-policy grants).
    pub session: Option<PolicyDocument>,
    /// Resource (bucket or trust) policy.
    pub resource: Option<PolicyDocument>,
    /// Bucket PublicAccessBlock.
    pub public_access_block: PublicAccessBlock,
}

#[derive(Default)]
struct Tally {
    allow: bool,
    deny: bool,
}

fn scan<'s>(stmts: impl Iterator<Item = &'s Statement>, req: &AuthzRequest<'_>, t: &mut Tally) {
    for st in stmts {
        if t.deny {
            return;
        }
        if st.matches_action(req.action)
            && st.matches_resource(req.resource, req.context)
            && st.matches_conditions(req.context, req.context)
        {
            match st.effect {
                Effect::Deny => t.deny = true,
                Effect::Allow => t.allow = true,
            }
        }
    }
}

impl PolicySet {
    /// Policy set from a principal's own policies plus optional resource policy.
    pub fn for_principal(
        p: Option<&Principal>,
        resource: Option<PolicyDocument>,
        pab: PublicAccessBlock,
    ) -> Self {
        PolicySet {
            identity: p.map(|p| p.policies.clone()).unwrap_or_default(),
            session: p.and_then(|p| p.session_policy.clone()),
            resource,
            public_access_block: pab,
        }
    }

    /// Best principal match among Allow statements of the resource policy that apply to
    /// `req` (`Err` if a resource-policy Deny applies). Honours `RestrictPublicBuckets`.
    pub fn resource_match(&self, req: &AuthzRequest<'_>) -> ResourceVerdict {
        let Some(rp) = &self.resource else {
            return ResourceVerdict::NoMatch;
        };
        let mut best: Option<PrincipalMatch> = None;
        for st in rp.statements() {
            let Some(pm) = st.match_principal(req.principal) else {
                continue;
            };
            if st.matches_action(req.action)
                && st.matches_resource(req.resource, req.context)
                && st.matches_conditions(req.context, req.context)
            {
                match st.effect {
                    Effect::Deny => return ResourceVerdict::Deny,
                    Effect::Allow => best = best.max(Some(pm)),
                }
            }
        }
        if req.principal.is_none()
            && self.public_access_block.restrict_public_buckets
            && rp.is_public()
        {
            best = None;
        }
        best.map_or(ResourceVerdict::NoMatch, ResourceVerdict::Allow)
    }

    /// Evaluate per AWS rules:
    /// 1. root ⇒ Allow (root cannot be denied);
    /// 2. any matching explicit Deny (identity, session or resource policy) ⇒ Deny;
    /// 3. Allow if (identity allows ∧ session allows) ∨ resource policy allows the caller's
    ///    exact ARN ∨ (resource policy allows via `*`/role ARN ∧ session allows);
    ///    with `RestrictPublicBuckets` on a public bucket policy, anonymous gets no Allow;
    /// 4. otherwise Implicit.
    pub fn evaluate(&self, req: &AuthzRequest<'_>) -> Decision {
        if req.principal.is_some_and(|p| p.is_root) {
            return Decision::Allow;
        }
        let mut id = Tally::default();
        let mut sess = Tally::default();
        if req.principal.is_some() {
            scan(
                self.identity.iter().flat_map(|d| d.statements()),
                req,
                &mut id,
            );
            if id.deny {
                return Decision::Deny;
            }
            if let Some(s) = &self.session {
                scan(s.statements().iter(), req, &mut sess);
                if sess.deny {
                    return Decision::Deny;
                }
            }
        }
        let sess_ok = self.session.is_none() || sess.allow;
        let res_best = match self.resource_match(req) {
            ResourceVerdict::Deny => return Decision::Deny,
            ResourceVerdict::Allow(m) => Some(m),
            ResourceVerdict::NoMatch => None,
        };
        let allowed = (req.principal.is_some() && id.allow && sess_ok)
            || match res_best {
                Some(PrincipalMatch::Exact) => true,
                Some(PrincipalMatch::Wide) => sess_ok,
                Some(PrincipalMatch::Account) | None => false,
            };
        if allowed {
            Decision::Allow
        } else {
            Decision::Implicit
        }
    }
}
