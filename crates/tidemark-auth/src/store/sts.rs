//! STS: AssumeRole and GetSessionToken.

use super::records::{SessionKind, SessionRecord};
use super::{CredentialStore, validate_name};
use crate::arn;
use crate::engine::{AuthzEngine, BucketAuthz};
use crate::error::AuthError;
use crate::eval::{AuthzRequest, ConditionContext, Decision, PolicySet, ResourceVerdict};
use crate::oidc::WebIdentity;
use crate::policy::{Effect, PolicyKind, PrincipalSpec, Statement};
use crate::principal::{Principal, PrincipalKind};
use crate::secret::{self, SecretString};
use crate::types::Ts;
use std::time::Duration;

/// Minimum STS session duration (15 min).
pub const MIN_SESSION: Duration = Duration::from_secs(15 * 60);
/// Maximum STS session duration (12 h).
pub const MAX_SESSION: Duration = Duration::from_secs(12 * 3600);
/// Maximum duration for role chaining (a role session assuming a role), as in AWS.
pub const MAX_CHAINED_SESSION: Duration = Duration::from_secs(3600);

/// Temporary credentials returned by STS.
#[derive(Debug, Clone)]
pub struct StsCredentials {
    /// Access key id (`TDMK…`).
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: SecretString,
    /// Session token (`X-Amz-Security-Token`).
    pub session_token: SecretString,
    /// Expiry.
    pub expiration: Ts,
    /// `arn:aws:sts::<acct>:assumed-role/<role>/<session>` for AssumeRole.
    pub assumed_role_arn: Option<String>,
    /// `<role-id>:<session>` for AssumeRole.
    pub assumed_role_id: Option<String>,
}

/// Parameters of an AssumeRole call.
#[derive(Debug, Clone, Copy)]
pub struct AssumeRoleRequest<'a> {
    /// Role name (or role ARN).
    pub role: &'a str,
    /// RoleSessionName (2–64 chars `[\w+=,.@-]`).
    pub session_name: &'a str,
    /// Requested duration (15 min – min(12 h, role max); ≤ 1 h when chaining).
    pub duration: Duration,
    /// Optional inline session policy; effective permissions are the intersection.
    pub session_policy: Option<&'a str>,
    /// Request context (aws:SourceIp etc.) for trust-policy conditions.
    pub context: &'a ConditionContext,
}

impl CredentialStore {
    fn new_session(
        &self,
        kind: SessionKind,
        duration: Duration,
        session_policy: Option<String>,
        cidrs: Vec<String>,
    ) -> Result<(SessionRecord, SecretString, SecretString), AuthError> {
        let akid = secret::generate_access_key_id();
        let sk = secret::generate_secret_key();
        let token = secret::generate_session_token();
        let (s, t) = self.seal_session(&akid, &sk, &token)?;
        let now = self.now();
        let rec = SessionRecord {
            access_key_id: akid,
            secret: s,
            token: t,
            kind,
            created_at: now,
            expires_at: now.plus(duration),
            session_policy,
            allowed_source_cidrs: cidrs,
        };
        self.store_session(&rec)?;
        Ok((rec, sk, token))
    }

    /// AssumeRole: checks the trust policy (and caller's identity policies) for
    /// `sts:AssumeRole` on the role ARN, then issues temporary credentials.
    pub async fn assume_role(
        &self,
        caller: &Principal,
        req: AssumeRoleRequest<'_>,
    ) -> Result<StsCredentials, AuthError> {
        let role_name = req
            .role
            .strip_prefix(&format!("arn:aws:iam::{}:role/", crate::types::ACCOUNT_ID))
            .unwrap_or(req.role);
        let sn = req.session_name;
        if sn.len() < 2
            || sn.len() > 64
            || !sn
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_+=,.@-".contains(c))
        {
            return Err(AuthError::Invalid(
                "RoleSessionName must be 2..=64 chars of [\\w+=,.@-]".into(),
            ));
        }
        validate_name("role", role_name)?;
        let role = self.role_record(role_name)?;
        let chained = matches!(caller.kind, PrincipalKind::AssumedRole { .. });
        let max = Duration::from_secs(role.max_session_secs).min(if chained {
            MAX_CHAINED_SESSION
        } else {
            MAX_SESSION
        });
        if req.duration < MIN_SESSION || req.duration > max {
            return Err(AuthError::Invalid(format!(
                "DurationSeconds must be between {} and {}",
                MIN_SESSION.as_secs(),
                max.as_secs()
            )));
        }
        let session_policy = match req.session_policy {
            Some(t) => {
                self.compile_policy(t, PolicyKind::Session)?;
                Some(t.to_string())
            }
            None => None,
        };
        let trust = self.compile_policy(&role.trust_policy, PolicyKind::Trust)?;
        let engine = AuthzEngine::with_clock(self.clock());
        let role_arn = arn::role(role_name);
        let ctx = engine.enrich(Some(caller), req.context);
        let set = PolicySet {
            resource: Some(trust.clone()),
            ..Default::default()
        };
        let trusted = caller.is_root
            || matches!(
                set.resource_match(&AuthzRequest {
                    principal: Some(caller),
                    action: "sts:AssumeRole",
                    resource: &role_arn,
                    context: &ctx
                }),
                ResourceVerdict::Allow(_)
            );
        let bucket = BucketAuthz {
            policy: Some(trust),
            ..Default::default()
        };
        let d = engine.authorize(
            Some(caller),
            "sts:AssumeRole",
            &role_arn,
            req.context,
            Some(&bucket),
        );
        if !trusted || d != Decision::Allow {
            return Err(AuthError::AccessDenied(format!(
                "{} is not allowed to assume role {role_name}",
                caller.arn
            )));
        }
        let (rec, sk, token) = self.new_session(
            SessionKind::Role {
                role: role_name.into(),
                session_name: sn.into(),
                source: caller.id.clone(),
            },
            req.duration,
            session_policy,
            Vec::new(),
        )?;
        tracing::info!(role = role_name, session = sn, caller = %caller.id, access_key_id = %rec.access_key_id, "sts assume-role");
        Ok(StsCredentials {
            access_key_id: rec.access_key_id,
            secret_access_key: sk,
            session_token: token,
            expiration: rec.expires_at,
            assumed_role_arn: Some(arn::assumed_role(role_name, sn)),
            assumed_role_id: Some(format!("{}:{sn}", role.role_id)),
        })
    }

    /// AssumeRoleWithWebIdentity: `identity` is an already verified OIDC token (see
    /// [`crate::oidc::OidcVerifier`]). The role's trust policy must allow
    /// `sts:AssumeRoleWithWebIdentity` to `Principal: {"Federated": <issuer | provider id |
    /// oidc-provider ARN>}`; conditions see `<provider>:sub`, `<provider>:aud`,
    /// `<provider>:iss`, `aws:FederatedProvider` and `aws:RequestTag/<k>` for mapped tags. An
    /// explicit Deny (federated match or `*`) wins; `Principal: "*"` never grants.
    pub async fn assume_role_with_web_identity(
        &self,
        identity: &WebIdentity,
        req: AssumeRoleRequest<'_>,
    ) -> Result<StsCredentials, AuthError> {
        let role_name = req
            .role
            .strip_prefix(&format!("arn:aws:iam::{}:role/", crate::types::ACCOUNT_ID))
            .unwrap_or(req.role);
        let sn = req.session_name;
        if sn.len() < 2
            || sn.len() > 64
            || !sn
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "_+=,.@-".contains(c))
        {
            return Err(AuthError::Invalid(
                "RoleSessionName must be 2..=64 chars of [\\w+=,.@-]".into(),
            ));
        }
        validate_name("role", role_name)?;
        let role = self.role_record(role_name)?;
        let max = Duration::from_secs(role.max_session_secs).min(MAX_SESSION);
        if req.duration < MIN_SESSION || req.duration > max {
            return Err(AuthError::Invalid(format!(
                "DurationSeconds must be between {} and {}",
                MIN_SESSION.as_secs(),
                max.as_secs()
            )));
        }
        let session_policy = match req.session_policy {
            Some(t) => {
                self.compile_policy(t, PolicyKind::Session)?;
                Some(t.to_string())
            }
            None => None,
        };
        let trust = self.compile_policy(&role.trust_policy, PolicyKind::Trust)?;
        let ctx = web_identity_context(identity, req.context, self.now());
        let role_arn = arn::role(role_name);
        if !federated_trust_allows(trust.statements(), identity, &role_arn, &ctx) {
            return Err(AuthError::AccessDenied(format!(
                "web identity {}/{} is not allowed to assume role {role_name}",
                identity.provider, identity.subject
            )));
        }
        let (rec, sk, token) = self.new_session(
            SessionKind::WebIdentity {
                role: role_name.into(),
                session_name: sn.into(),
                provider: identity.provider.clone(),
                subject: identity.subject.clone(),
                tags: identity.tags.clone(),
            },
            req.duration,
            session_policy,
            Vec::new(),
        )?;
        tracing::info!(role = role_name, session = sn, provider = %identity.provider, subject = %identity.subject, access_key_id = %rec.access_key_id, "sts assume-role-with-web-identity");
        Ok(StsCredentials {
            access_key_id: rec.access_key_id,
            secret_access_key: sk,
            session_token: token,
            expiration: rec.expires_at,
            assumed_role_arn: Some(arn::assumed_role(role_name, sn)),
            assumed_role_id: Some(format!("{}:{sn}", role.role_id)),
        })
    }

    /// GetSessionToken: temporary credentials with the caller's own permissions.
    /// Only users and root may call it (not role sessions); 15 min – 12 h.
    pub async fn get_session_token(
        &self,
        caller: &Principal,
        duration: Duration,
    ) -> Result<StsCredentials, AuthError> {
        if duration < MIN_SESSION || duration > MAX_SESSION {
            return Err(AuthError::Invalid(format!(
                "DurationSeconds must be between {} and {}",
                MIN_SESSION.as_secs(),
                MAX_SESSION.as_secs()
            )));
        }
        let kind = match &caller.kind {
            PrincipalKind::Root => SessionKind::Root,
            PrincipalKind::User { name } => SessionKind::User(name.clone()),
            PrincipalKind::AssumedRole { .. } => {
                return Err(AuthError::AccessDenied(
                    "role sessions cannot call GetSessionToken".into(),
                ));
            }
        };
        let cidrs = caller
            .allowed_source_cidrs
            .iter()
            .map(|n| n.to_string())
            .collect();
        let (rec, sk, token) = self.new_session(kind, duration, None, cidrs)?;
        Ok(StsCredentials {
            access_key_id: rec.access_key_id,
            secret_access_key: sk,
            session_token: token,
            expiration: rec.expires_at,
            assumed_role_arn: None,
            assumed_role_id: None,
        })
    }
}

/// Condition context for a web-identity trust evaluation.
fn web_identity_context(id: &WebIdentity, base: &ConditionContext, now: Ts) -> ConditionContext {
    let mut c = base.clone();
    for k in [
        "aws:username",
        "aws:userid",
        "aws:principalarn",
        "aws:principaltype",
        "aws:principalaccount",
        "aws:federatedprovider",
    ] {
        c.remove(k);
    }
    c.remove_prefix("aws:PrincipalTag/");
    c.remove_prefix("aws:RequestTag/");
    let p = &id.provider;
    for k in ["sub", "aud", "iss", "azp", "amr", "email"] {
        c.remove(&format!("{p}:{k}"));
    }
    c.insert(&format!("{p}:sub"), id.subject.clone());
    c.insert(&format!("{p}:iss"), id.issuer.clone());
    c.set(&format!("{p}:aud"), id.audience.clone());
    for k in ["azp", "email"] {
        if let Some(v) = id.claims.get(k).and_then(|v| v.as_str()) {
            c.insert(&format!("{p}:{k}"), v);
        }
    }
    if let Some(a) = id.claims.get("amr").and_then(|v| v.as_array()) {
        c.set(
            &format!("{p}:amr"),
            a.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect(),
        );
    }
    c.insert("aws:FederatedProvider", p.clone());
    c.insert("aws:PrincipalType", "WebIdentity");
    for (k, v) in &id.tags {
        c.insert(&format!("aws:RequestTag/{k}"), v.clone());
    }
    if !id.tags.is_empty() {
        c.set("aws:TagKeys", id.tags.keys().cloned().collect());
    }
    c.insert("aws:CurrentTime", now.to_rfc3339());
    c.insert("aws:EpochTime", now.as_secs().to_string());
    c
}

fn federated_value_matches(v: &str, id: &WebIdentity) -> bool {
    let v = v.trim_end_matches('/');
    v == id.issuer.trim_end_matches('/')
        || v == id.provider
        || v == format!(
            "arn:aws:iam::{}:oidc-provider/{}",
            crate::types::ACCOUNT_ID,
            id.provider
        )
}

/// `Some(true)` if the statement names this federated provider, `Some(false)` for `*`.
fn federated_principal(st: &Statement, id: &WebIdentity) -> Option<bool> {
    let m = match st.principal.as_ref()? {
        PrincipalSpec::Any => Some(false),
        PrincipalSpec::Typed(t) => t
            .iter()
            .any(|(ty, vals)| {
                ty == "Federated" && vals.iter().any(|v| federated_value_matches(v, id))
            })
            .then_some(true),
    };
    if st.not_principal {
        if m.is_some() { None } else { Some(false) }
    } else {
        m
    }
}

/// Trust decision for a web identity: explicit Deny wins; Allow needs an explicit
/// `Federated` principal match.
fn federated_trust_allows(
    stmts: &[Statement],
    id: &WebIdentity,
    role_arn: &str,
    ctx: &ConditionContext,
) -> bool {
    let mut allow = false;
    for st in stmts {
        let Some(explicit) = federated_principal(st, id) else {
            continue;
        };
        if !(st.matches_action("sts:AssumeRoleWithWebIdentity")
            && st.matches_resource(role_arn, ctx)
            && st.matches_conditions(ctx, ctx))
        {
            continue;
        }
        match st.effect {
            Effect::Deny => return false,
            Effect::Allow => allow |= explicit,
        }
    }
    allow
}
