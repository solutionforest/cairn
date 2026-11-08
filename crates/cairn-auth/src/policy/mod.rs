//! AWS IAM JSON policy documents: parsing, validation and compiled statement matching.

pub mod condition;

use crate::actions;
use crate::arn;
use crate::error::PolicyError;
use crate::eval::ConditionContext;
use crate::pattern::{PatternSet, VarResolver};
use crate::principal::{Principal, PrincipalKind};
use crate::types::ACCOUNT_ID;
use condition::Condition;
use serde_json::{Map, Value};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

pub use condition::{OpKind, SetQualifier};

/// Maximum policy document size in bytes (20 KiB).
pub const MAX_POLICY_BYTES: usize = 20 * 1024;

/// Statement effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Allow.
    Allow,
    /// Deny.
    Deny,
}

/// `Principal` / `NotPrincipal` contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalSpec {
    /// `"*"` or `{"AWS": "*"}` — everyone, including anonymous.
    Any,
    /// Typed principal lists, e.g. `("AWS", ["arn:aws:iam::0:user/alice"])`.
    Typed(Vec<(String, Vec<String>)>),
}

/// How a principal matched a `Principal` element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrincipalMatch {
    /// Matched via the account (root ARN / account id): delegates to identity policies.
    Account,
    /// Matched via `*` or the parent role ARN of a session: limited by session policies.
    Wide,
    /// Matched the principal's own ARN exactly.
    Exact,
}

/// What a policy is used as; selects element requirements in [`PolicyDocument::validate_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind<'a> {
    /// Identity policy attached to a user, group or role (no Principal).
    Identity,
    /// Inline STS session policy (same rules as identity).
    Session,
    /// Bucket policy (Principal required; resources must be within the bucket).
    Bucket(&'a str),
    /// Role trust policy (Principal required; only `sts:` actions; Resource optional).
    Trust,
}

/// One compiled statement.
#[derive(Debug, Clone)]
pub struct Statement {
    /// Sid.
    pub sid: Option<String>,
    /// Effect.
    pub effect: Effect,
    /// Principal or NotPrincipal (see `not_principal`).
    pub principal: Option<PrincipalSpec>,
    /// True when the principal came from `NotPrincipal`.
    pub not_principal: bool,
    /// Raw action patterns.
    pub actions: Vec<String>,
    /// True when the actions came from `NotAction`.
    pub not_action: bool,
    /// Raw resource patterns (`None` when absent, e.g. trust policies).
    pub resources: Option<Vec<String>>,
    /// True when the resources came from `NotResource`.
    pub not_resource: bool,
    /// Conditions (all must hold).
    pub conditions: Vec<Condition>,
    action_set: PatternSet,
    resource_set: Option<PatternSet>,
}

#[derive(Debug)]
struct Inner {
    source: String,
    version: Option<String>,
    id: Option<String>,
    statements: Vec<Statement>,
}

/// A parsed and compiled policy document. Cheap to clone (shared).
#[derive(Clone)]
pub struct PolicyDocument(Arc<Inner>);

impl fmt::Debug for PolicyDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyDocument")
            .field("id", &self.0.id)
            .field("statements", &self.0.statements.len())
            .finish()
    }
}

impl fmt::Display for PolicyDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.source)
    }
}

impl PartialEq for PolicyDocument {
    fn eq(&self, o: &Self) -> bool {
        self.0.source == o.0.source
    }
}

impl serde::Serialize for PolicyDocument {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0.source)
    }
}

impl<'de> serde::Deserialize<'de> for PolicyDocument {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

fn malformed(m: impl Into<String>) -> PolicyError {
    PolicyError::Malformed(m.into())
}

fn str_or_vec(v: &Value, field: &str) -> Result<Vec<String>, PolicyError> {
    match v {
        Value::String(s) => Ok(vec![s.clone()]),
        Value::Array(a) if !a.is_empty() => a
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| malformed(format!("{field}: array items must be strings")))
            })
            .collect(),
        _ => Err(malformed(format!(
            "{field}: expected a string or non-empty array of strings"
        ))),
    }
}

fn parse_principal(v: &Value) -> Result<PrincipalSpec, PolicyError> {
    match v {
        Value::String(s) if s == "*" => Ok(PrincipalSpec::Any),
        Value::Object(m) if !m.is_empty() => {
            let mut typed = Vec::new();
            for (k, v) in m {
                if !matches!(
                    k.as_str(),
                    "AWS" | "Service" | "Federated" | "CanonicalUser"
                ) {
                    return Err(PolicyError::InvalidPrincipal(format!(
                        "unknown principal type {k}"
                    )));
                }
                let vals = str_or_vec(v, k)?;
                if k == "AWS" && vals.iter().any(|x| x == "*") {
                    return Ok(PrincipalSpec::Any);
                }
                typed.push((k.clone(), vals));
            }
            Ok(PrincipalSpec::Typed(typed))
        }
        _ => Err(PolicyError::InvalidPrincipal(
            "Principal must be \"*\" or an object like {\"AWS\": [...]}".into(),
        )),
    }
}

fn take_exclusive<'a>(
    m: &'a Map<String, Value>,
    a: &str,
    b: &str,
) -> Result<Option<(&'a Value, bool)>, PolicyError> {
    match (m.get(a), m.get(b)) {
        (Some(_), Some(_)) => Err(malformed(format!("statement has both {a} and {b}"))),
        (Some(v), None) => Ok(Some((v, false))),
        (None, Some(v)) => Ok(Some((v, true))),
        (None, None) => Ok(None),
    }
}

fn parse_statement(v: &Value, vars: bool) -> Result<Statement, PolicyError> {
    let m = v
        .as_object()
        .ok_or_else(|| malformed("Statement entries must be objects"))?;
    for k in m.keys() {
        if !matches!(
            k.as_str(),
            "Sid"
                | "Effect"
                | "Principal"
                | "NotPrincipal"
                | "Action"
                | "NotAction"
                | "Resource"
                | "NotResource"
                | "Condition"
        ) {
            return Err(malformed(format!("unknown statement element {k}")));
        }
    }
    let sid = match m.get("Sid") {
        None => None,
        Some(Value::String(s)) => Some(s.clone()),
        Some(_) => return Err(malformed("Sid must be a string")),
    };
    let effect = match m.get("Effect").and_then(Value::as_str) {
        Some("Allow") => Effect::Allow,
        Some("Deny") => Effect::Deny,
        _ => return Err(malformed("Effect must be \"Allow\" or \"Deny\"")),
    };
    let (principal, not_principal) = match take_exclusive(m, "Principal", "NotPrincipal")? {
        Some((v, n)) => (Some(parse_principal(v)?), n),
        None => (None, false),
    };
    let (actions, not_action) = match take_exclusive(m, "Action", "NotAction")? {
        Some((v, n)) => (str_or_vec(v, "Action")?, n),
        None => return Err(malformed("statement needs Action or NotAction")),
    };
    let (resources, not_resource) = match take_exclusive(m, "Resource", "NotResource")? {
        Some((v, n)) => (Some(str_or_vec(v, "Resource")?), n),
        None => (None, false),
    };
    let conditions = match m.get("Condition") {
        Some(c) => condition::parse_block(c, vars)?,
        None => Vec::new(),
    };
    let action_set = PatternSet::compile(actions.iter().map(String::as_str), true, false)
        .map_err(PolicyError::UnknownAction)?;
    let resource_set = match &resources {
        Some(r) => Some(
            PatternSet::compile(r.iter().map(String::as_str), false, vars)
                .map_err(PolicyError::InvalidResource)?,
        ),
        None => None,
    };
    Ok(Statement {
        sid,
        effect,
        principal,
        not_principal,
        actions,
        not_action,
        resources,
        not_resource,
        conditions,
        action_set,
        resource_set,
    })
}

impl FromStr for PolicyDocument {
    type Err = PolicyError;

    /// Parse and compile. Does not run [`PolicyDocument::validate`] (size limit excepted at 4×).
    fn from_str(s: &str) -> Result<Self, PolicyError> {
        if s.len() > 4 * MAX_POLICY_BYTES {
            return Err(PolicyError::TooLarge(s.len(), MAX_POLICY_BYTES));
        }
        let v: Value = serde_json::from_str(s).map_err(|e| malformed(e.to_string()))?;
        let m = v
            .as_object()
            .ok_or_else(|| malformed("policy must be a JSON object"))?;
        for k in m.keys() {
            if !matches!(k.as_str(), "Version" | "Id" | "Statement") {
                return Err(malformed(format!("unknown top-level element {k}")));
            }
        }
        let version = match m.get("Version") {
            None => None,
            Some(Value::String(v)) if v == "2012-10-17" || v == "2008-10-17" => Some(v.clone()),
            Some(v) => return Err(PolicyError::UnsupportedVersion(v.to_string())),
        };
        let vars = version.as_deref() == Some("2012-10-17");
        let id = match m.get("Id") {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err(malformed("Id must be a string")),
        };
        let statements = match m.get("Statement") {
            Some(Value::Array(a)) => a
                .iter()
                .map(|s| parse_statement(s, vars))
                .collect::<Result<_, _>>()?,
            Some(o @ Value::Object(_)) => vec![parse_statement(o, vars)?],
            _ => return Err(malformed("Statement must be an object or array")),
        };
        Ok(PolicyDocument(Arc::new(Inner {
            source: s.to_string(),
            version,
            id,
            statements,
        })))
    }
}

fn validate_action(a: &str) -> Result<(), PolicyError> {
    if a == "*" {
        return Ok(());
    }
    let unknown = || PolicyError::UnknownAction(a.to_string());
    let (ns, name) = a.split_once(':').ok_or_else(unknown)?;
    let ns = ns.to_ascii_lowercase();
    if !matches!(ns.as_str(), "s3" | "sts" | "cairn") || name.is_empty() {
        return Err(unknown());
    }
    if !a.contains(['*', '?']) {
        return actions::canonical(a).map(|_| ()).ok_or_else(unknown);
    }
    let set = PatternSet::compile([a], true, false).map_err(|_| unknown())?;
    if actions::all().any(|c| set.is_match(c, &crate::pattern::NoVars)) {
        Ok(())
    } else {
        Err(unknown())
    }
}

fn validate_principal_value(ty: &str, v: &str) -> Result<(), PolicyError> {
    if ty != "AWS" {
        return Ok(());
    }
    let bad = || PolicyError::InvalidPrincipal(v.to_string());
    if v.len() == 12 && v.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(());
    }
    let a = arn::parse(v).ok_or_else(bad)?;
    let ok = match a.service {
        "iam" => {
            a.resource == "root"
                || a.resource.starts_with("user/")
                || a.resource.starts_with("role/")
        }
        "sts" => a.resource.starts_with("assumed-role/"),
        _ => false,
    };
    if ok && !a.account.is_empty() {
        Ok(())
    } else {
        Err(bad())
    }
}

impl PolicyDocument {
    /// Parse then [`validate`](Self::validate).
    pub fn parse_validated(s: &str) -> Result<Self, PolicyError> {
        let d: Self = s.parse()?;
        d.validate()?;
        Ok(d)
    }

    /// Original JSON text.
    pub fn as_json(&self) -> &str {
        &self.0.source
    }

    /// `Version`, if given.
    pub fn version(&self) -> Option<&str> {
        self.0.version.as_deref()
    }

    /// `Id`, if given.
    pub fn id(&self) -> Option<&str> {
        self.0.id.as_deref()
    }

    /// The compiled statements.
    pub fn statements(&self) -> &[Statement] {
        &self.0.statements
    }

    /// Generic validation: size ≤ 20 KiB, known actions, well-formed ARNs and principals,
    /// unique Sids.
    pub fn validate(&self) -> Result<(), PolicyError> {
        let len = self.0.source.len();
        if len > MAX_POLICY_BYTES {
            return Err(PolicyError::TooLarge(len, MAX_POLICY_BYTES));
        }
        if self.0.statements.is_empty() {
            return Err(malformed("policy has no statements"));
        }
        let mut sids = std::collections::HashSet::new();
        for st in &self.0.statements {
            if let Some(s) = &st.sid
                && !sids.insert(s.clone())
            {
                return Err(malformed(format!("duplicate Sid {s}")));
            }
            for a in &st.actions {
                validate_action(a)?;
            }
            if let Some(rs) = &st.resources {
                for r in rs {
                    arn::validate_resource_pattern(r).map_err(PolicyError::InvalidResource)?;
                }
            }
            if let Some(PrincipalSpec::Typed(t)) = &st.principal {
                for (ty, vals) in t {
                    for v in vals {
                        validate_principal_value(ty, v)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// [`validate`](Self::validate) plus the element rules for `kind`.
    pub fn validate_for(&self, kind: PolicyKind<'_>) -> Result<(), PolicyError> {
        self.validate()?;
        let k = |m: &str| Err(PolicyError::Kind(m.to_string()));
        for st in &self.0.statements {
            match kind {
                PolicyKind::Identity | PolicyKind::Session => {
                    if st.principal.is_some() {
                        return k("identity policies must not contain Principal/NotPrincipal");
                    }
                    if st.resources.is_none() {
                        return k("identity policy statements need Resource or NotResource");
                    }
                }
                PolicyKind::Bucket(bucket) => {
                    if st.principal.is_none() {
                        return k("bucket policy statements need Principal or NotPrincipal");
                    }
                    let Some(rs) = &st.resources else {
                        return k("bucket policy statements need Resource or NotResource");
                    };
                    let base = arn::bucket(bucket);
                    for r in rs {
                        let inside = *r == base || r.starts_with(&format!("{base}/"));
                        if !inside {
                            return Err(PolicyError::InvalidResource(format!(
                                "{r}: bucket policy resources must be within {base}"
                            )));
                        }
                    }
                }
                PolicyKind::Trust => {
                    if st.principal.is_none() {
                        return k("trust policy statements need Principal");
                    }
                    if st
                        .actions
                        .iter()
                        .any(|a| !a.to_ascii_lowercase().starts_with("sts:"))
                    {
                        return k("trust policies may only use sts: actions");
                    }
                }
            }
        }
        Ok(())
    }

    /// True if any Allow statement grants access to everyone (`*`) without a condition that
    /// pins the caller (source IP narrower than /8, principal ARN/account/user id). Used for
    /// `BlockPublicPolicy` and `RestrictPublicBuckets`.
    pub fn is_public(&self) -> bool {
        const PINNING: &[&str] = &[
            "aws:principalarn",
            "aws:principalaccount",
            "aws:sourceaccount",
            "aws:sourcearn",
            "aws:sourcevpc",
            "aws:sourcevpce",
            "aws:userid",
            "aws:username",
            "aws:principalorgid",
        ];
        self.0.statements.iter().any(|st| {
            if st.effect != Effect::Allow {
                return false;
            }
            let everyone = st.not_principal || st.principal == Some(PrincipalSpec::Any);
            if !everyone {
                return false;
            }
            let pinned = st.conditions.iter().any(|c| {
                if c.op.is_negated() || c.if_exists {
                    return false;
                }
                if c.key == "aws:sourceip" && c.op == OpKind::IpAddress {
                    return c.narrow_ip(8, 32);
                }
                PINNING.contains(&c.key.as_str())
                    && matches!(c.op, OpKind::StringEquals | OpKind::ArnEquals)
            });
            !pinned
        })
    }
}

impl Statement {
    /// True if the statement's action list covers `action`.
    pub fn matches_action(&self, action: &str) -> bool {
        self.action_set.is_match(action, &crate::pattern::NoVars) != self.not_action
    }

    /// True if the statement's resource list covers `resource` (absent ⇒ any).
    pub fn matches_resource(&self, resource: &str, vars: &dyn VarResolver) -> bool {
        match &self.resource_set {
            None => true,
            Some(s) => s.is_match(resource, vars) != self.not_resource,
        }
    }

    /// How the principal matches this statement's Principal/NotPrincipal (None = no match).
    pub fn match_principal(&self, p: Option<&Principal>) -> Option<PrincipalMatch> {
        let spec = self.principal.as_ref()?;
        let m = match_spec(spec, p);
        if self.not_principal {
            if m.is_some() {
                None
            } else {
                Some(PrincipalMatch::Wide)
            }
        } else {
            m
        }
    }

    /// All conditions hold.
    pub fn matches_conditions(&self, ctx: &ConditionContext, vars: &dyn VarResolver) -> bool {
        self.conditions.iter().all(|c| c.evaluate(ctx, vars))
    }
}

fn match_spec(spec: &PrincipalSpec, p: Option<&Principal>) -> Option<PrincipalMatch> {
    let typed = match spec {
        PrincipalSpec::Any => return Some(PrincipalMatch::Wide),
        PrincipalSpec::Typed(t) => t,
    };
    let p = p?;
    let root_arn = arn::root();
    let mut best: Option<PrincipalMatch> = None;
    for (ty, vals) in typed {
        if ty != "AWS" {
            continue;
        }
        for v in vals {
            let m = if *v == p.arn {
                Some(PrincipalMatch::Exact)
            } else if matches!(&p.kind, PrincipalKind::AssumedRole { role, .. } if *v == arn::role(role))
            {
                Some(PrincipalMatch::Wide)
            } else if *v == root_arn || v == ACCOUNT_ID {
                Some(if p.is_root {
                    PrincipalMatch::Exact
                } else {
                    PrincipalMatch::Account
                })
            } else {
                None
            };
            best = best.max(m);
        }
    }
    best
}

impl Condition {
    fn narrow_ip(&self, v4: u8, v6: u8) -> bool {
        self.ip_nets().is_some_and(|nets| {
            nets.iter().all(|n| match n {
                ipnet::IpNet::V4(n) => n.prefix_len() >= v4,
                ipnet::IpNet::V6(n) => n.prefix_len() >= v6,
            })
        })
    }
}

#[cfg(test)]
mod tests;
