//! Authenticated principals as seen by the authoriser.

use crate::arn;
use crate::policy::PolicyDocument;
use crate::types::PrincipalId;
use ipnet::IpNet;
use std::collections::BTreeMap;

/// What kind of principal this is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalKind {
    /// The root credential.
    Root,
    /// A long-lived IAM user (possibly via a GetSessionToken session).
    User {
        /// User name.
        name: String,
    },
    /// An STS AssumeRole session.
    AssumedRole {
        /// Role name.
        role: String,
        /// Session name.
        session: String,
    },
}

/// A resolved principal with its effective identity policies.
#[derive(Debug, Clone)]
pub struct Principal {
    /// Stable id ("root", "user:alice", "role:r/s").
    pub id: PrincipalId,
    /// ARN (`aws:PrincipalArn`).
    pub arn: String,
    /// Group names (users only).
    pub groups: Vec<String>,
    /// True for the root credential (always allowed).
    pub is_root: bool,
    /// Kind and names.
    pub kind: PrincipalKind,
    /// Unique id (`aws:userid`): user id, or `<role-id>:<session>` for role sessions.
    pub user_id: String,
    /// Identity policies: user inline + attached + group policies, or role policies.
    pub policies: Vec<PolicyDocument>,
    /// Inline STS session policy; intersects with `policies`.
    pub session_policy: Option<PolicyDocument>,
    /// If non-empty, requests must come from one of these networks (`aws:SourceIp`).
    pub allowed_source_cidrs: Vec<IpNet>,
    /// Session tags (`aws:PrincipalTag/<key>`), e.g. mapped from OIDC claims.
    pub tags: BTreeMap<String, String>,
}

impl Principal {
    /// The root principal.
    pub fn root() -> Self {
        Principal {
            id: PrincipalId::root(),
            arn: arn::root(),
            groups: Vec::new(),
            is_root: true,
            kind: PrincipalKind::Root,
            user_id: crate::types::ACCOUNT_ID.to_string(),
            policies: Vec::new(),
            session_policy: None,
            allowed_source_cidrs: Vec::new(),
            tags: BTreeMap::new(),
        }
    }

    /// A user principal with the given identity policies.
    pub fn user(name: &str, user_id: &str, policies: Vec<PolicyDocument>) -> Self {
        Principal {
            id: PrincipalId::user(name),
            arn: arn::user(name),
            groups: Vec::new(),
            is_root: false,
            kind: PrincipalKind::User {
                name: name.to_string(),
            },
            user_id: user_id.to_string(),
            policies,
            session_policy: None,
            allowed_source_cidrs: Vec::new(),
            tags: BTreeMap::new(),
        }
    }

    /// An assumed-role session principal.
    pub fn assumed_role(
        role: &str,
        role_id: &str,
        session: &str,
        policies: Vec<PolicyDocument>,
        session_policy: Option<PolicyDocument>,
    ) -> Self {
        Principal {
            id: PrincipalId::role_session(role, session),
            arn: arn::assumed_role(role, session),
            groups: Vec::new(),
            is_root: false,
            kind: PrincipalKind::AssumedRole {
                role: role.to_string(),
                session: session.to_string(),
            },
            user_id: format!("{role_id}:{session}"),
            policies,
            session_policy,
            allowed_source_cidrs: Vec::new(),
            tags: BTreeMap::new(),
        }
    }

    /// `aws:username` (users only).
    pub fn username(&self) -> Option<&str> {
        match &self.kind {
            PrincipalKind::User { name } => Some(name),
            _ => None,
        }
    }
}
