//! Credential store: root, users, groups, roles, managed policies, access keys, STS sessions.

pub mod backend;
mod records;
mod sts;

pub use backend::{BackendError, BackendOp, CredentialBackend, MemoryBackend};
pub use sts::{AssumeRoleRequest, MAX_SESSION, MIN_SESSION, StsCredentials};

use crate::arn;
use crate::error::AuthError;
use crate::policy::{PolicyDocument, PolicyKind};
use crate::principal::Principal;
use crate::secret::{self, MasterKey, SecretString};
use crate::types::{Clock, SystemClock, Ts};
use ipnet::IpNet;
use records::*;
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Default maximum number of access keys per user.
pub const DEFAULT_MAX_KEYS_PER_USER: usize = 10;

/// STS session attached to a temporary credential.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    /// Session token the client must present as `X-Amz-Security-Token`.
    pub token: SecretString,
    /// Expiry.
    pub expires_at: Ts,
}

impl SessionInfo {
    /// Constant-time token check.
    pub fn verify_token(&self, presented: &str) -> bool {
        self.token.ct_eq(presented)
    }
}

/// A looked-up credential: the secret for SigV4 verification plus the resolved principal.
#[derive(Debug, Clone)]
pub struct Credential {
    /// Access key id.
    pub access_key_id: String,
    /// Secret access key.
    pub secret_key: SecretString,
    /// Resolved principal with effective policies.
    pub principal: Principal,
    /// Present for STS temporary credentials.
    pub session: Option<SessionInfo>,
    /// Expiry of a long-lived key or a session.
    pub expires_at: Option<Ts>,
}

impl Credential {
    /// The request's `X-Amz-Security-Token` must be present iff this is a session, and match.
    pub fn verify_session_token(&self, presented: Option<&str>) -> bool {
        match (&self.session, presented) {
            (None, None) => true,
            (Some(s), Some(t)) => s.verify_token(t),
            _ => false,
        }
    }
}

/// Public view of a user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInfo {
    /// Name.
    pub name: String,
    /// Unique id (`aws:userid`).
    pub user_id: String,
    /// ARN.
    pub arn: String,
    /// Creation time.
    pub created_at: Ts,
    /// Groups.
    pub groups: Vec<String>,
    /// Attached managed policies.
    pub attached_policies: Vec<String>,
    /// Inline policy names.
    pub inline_policies: Vec<String>,
    /// Disabled users cannot authenticate.
    pub disabled: bool,
}

/// Public view of a group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    /// Name.
    pub name: String,
    /// Members.
    pub members: Vec<String>,
    /// Attached managed policies.
    pub attached_policies: Vec<String>,
    /// Inline policy names.
    pub inline_policies: Vec<String>,
}

/// Public view of a role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleInfo {
    /// Name.
    pub name: String,
    /// Unique id.
    pub role_id: String,
    /// ARN.
    pub arn: String,
    /// Trust policy JSON.
    pub trust_policy: String,
    /// Attached managed policies.
    pub attached_policies: Vec<String>,
    /// Inline policy names.
    pub inline_policies: Vec<String>,
    /// Maximum session duration.
    pub max_session: Duration,
}

/// Public view of a managed policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedPolicyInfo {
    /// Name.
    pub name: String,
    /// ARN.
    pub arn: String,
    /// JSON document.
    pub document: String,
    /// Bumped on every update.
    pub version: u64,
}

/// Public view of an access key (never contains the secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessKeyInfo {
    /// Id.
    pub access_key_id: String,
    /// Owning user (`None` = root).
    pub user: Option<String>,
    /// Active flag.
    pub active: bool,
    /// Creation time.
    pub created_at: Ts,
    /// Optional expiry.
    pub expires_at: Option<Ts>,
    /// Allowed source networks.
    pub allowed_source_cidrs: Vec<String>,
}

/// Public view of an STS session (never includes the secret or token).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
    /// Temporary access key id.
    pub access_key_id: String,
    /// Principal id the session acts as (`root`, `user:alice`, `role:r/session`).
    pub principal: String,
    /// For role sessions, the principal that called AssumeRole.
    pub source: Option<String>,
    /// Issue time.
    pub created_at: Ts,
    /// Expiry.
    pub expires_at: Ts,
    /// True if already expired (not yet purged).
    pub expired: bool,
}

fn session_principal(k: &SessionKind) -> String {
    match k {
        SessionKind::Root => "root".into(),
        SessionKind::User(u) => format!("user:{u}"),
        SessionKind::Role {
            role, session_name, ..
        }
        | SessionKind::WebIdentity {
            role, session_name, ..
        } => format!("role:{role}/{session_name}"),
    }
}

/// A newly created access key; the only time the secret is returned.
#[derive(Debug, Clone)]
pub struct NewAccessKey {
    /// Id.
    pub access_key_id: String,
    /// Secret.
    pub secret_key: SecretString,
}

/// Options for creating an access key.
#[derive(Debug, Clone, Default)]
pub struct AccessKeyOptions {
    /// Optional expiry.
    pub expires_at: Option<Ts>,
    /// If non-empty, requests must originate from these CIDRs.
    pub allowed_source_cidrs: Vec<String>,
}

/// IAM credential store over a [`CredentialBackend`].
///
/// All methods are `async` per the crate contract but do short synchronous backend calls;
/// writes are serialised by an internal mutex (read-modify-write safety).
pub struct CredentialStore {
    backend: Arc<dyn CredentialBackend>,
    key: MasterKey,
    clock: Arc<dyn Clock>,
    write: Mutex<()>,
    cache: Mutex<HashMap<[u8; 32], PolicyDocument>>,
    max_keys_per_user: usize,
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore").finish_non_exhaustive()
    }
}

const K_USER: &str = "u/";
const K_GROUP: &str = "g/";
const K_ROLE: &str = "r/";
const K_POLICY: &str = "p/";
const K_KEY: &str = "k/";
const K_SESSION: &str = "s/";
const K_ROOT: &[u8] = b"x/root";

fn key(prefix: &str, name: &str) -> Vec<u8> {
    let mut k = prefix.as_bytes().to_vec();
    k.extend_from_slice(name.as_bytes());
    k
}

fn be(e: BackendError) -> AuthError {
    AuthError::Backend(e.0)
}

/// IAM names: 1–64 chars of `[A-Za-z0-9+=,.@_-]`.
pub fn validate_name(kind: &str, n: &str) -> Result<(), AuthError> {
    let ok = !n.is_empty()
        && n.len() <= 64
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || "+=,.@_-".contains(c));
    if ok {
        Ok(())
    } else {
        Err(AuthError::Invalid(format!("invalid {kind} name {n:?}")))
    }
}

fn parse_cidrs(v: &[String]) -> Result<Vec<IpNet>, AuthError> {
    v.iter()
        .map(|s| {
            s.parse::<IpNet>()
                .or_else(|_| s.parse::<std::net::IpAddr>().map(IpNet::from))
                .map_err(|_| AuthError::Invalid(format!("invalid CIDR {s:?}")))
        })
        .collect()
}

impl CredentialStore {
    /// New store over `backend`, encrypting secrets with `master_key`.
    pub fn new(backend: Arc<dyn CredentialBackend>, master_key: MasterKey) -> Self {
        Self {
            backend,
            key: master_key,
            clock: Arc::new(SystemClock),
            write: Mutex::new(()),
            cache: Mutex::new(HashMap::new()),
            max_keys_per_user: DEFAULT_MAX_KEYS_PER_USER,
        }
    }

    /// Replace the clock (tests).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Set the per-user access key limit.
    pub fn with_max_keys_per_user(mut self, n: usize) -> Self {
        self.max_keys_per_user = n;
        self
    }

    /// Current time from the store clock.
    pub fn now(&self) -> Ts {
        self.clock.now()
    }

    pub(crate) fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.write.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn get<T: serde::de::DeserializeOwned>(&self, k: &[u8]) -> Result<Option<T>, AuthError> {
        self.backend
            .get(k)
            .map_err(be)?
            .map(|b| decode(&b))
            .transpose()
    }

    fn put<T: serde::Serialize>(&self, k: &[u8], v: &T) -> Result<(), AuthError> {
        self.backend.put(k, &encode(v)?).map_err(be)
    }

    fn list<T: serde::de::DeserializeOwned>(&self, prefix: &str) -> Result<Vec<T>, AuthError> {
        self.backend
            .list_prefix(prefix.as_bytes())
            .map_err(be)?
            .into_iter()
            .map(|(_, v)| decode(&v))
            .collect()
    }

    fn must<T: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
        kind: &'static str,
        name: &str,
    ) -> Result<T, AuthError> {
        self.get(&key(prefix, name))?
            .ok_or_else(|| AuthError::NotFound {
                kind,
                name: name.to_string(),
            })
    }

    /// Parse a stored policy text, memoised by SHA-256 of the text.
    fn compiled(&self, text: &str) -> Result<PolicyDocument, AuthError> {
        let h: [u8; 32] = sha2::Sha256::digest(text.as_bytes()).into();
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = c.get(&h) {
            return Ok(d.clone());
        }
        let d: PolicyDocument = text.parse()?;
        if c.len() >= 4096 {
            c.clear();
        }
        c.insert(h, d.clone());
        Ok(d)
    }

    fn check_policy(&self, text: &str, kind: PolicyKind<'_>) -> Result<PolicyDocument, AuthError> {
        let d = self.compiled(text)?;
        d.validate_for(kind)?;
        Ok(d)
    }

    // ---------------------------------------------------------------- lookup

    /// Look up an access key id (long-lived or STS). Returns `None` for unknown, inactive,
    /// expired, or orphaned (owner deleted/disabled) credentials.
    pub async fn lookup(&self, access_key_id: &str) -> Result<Option<Credential>, AuthError> {
        let now = self.now();
        if let Some(rec) = self.get::<AccessKeyRecord>(&key(K_KEY, access_key_id))? {
            if !rec.active || rec.expires_at.is_some_and(|e| e <= now) {
                return Ok(None);
            }
            let mut principal = match &rec.owner {
                KeyOwner::Root => {
                    if self.root_access_key_id_sync()?.as_deref() != Some(access_key_id) {
                        return Ok(None);
                    }
                    Principal::root()
                }
                KeyOwner::User(u) => match self.resolve_user(u)? {
                    Some(p) => p,
                    None => return Ok(None),
                },
            };
            principal.allowed_source_cidrs = parse_cidrs(&rec.allowed_source_cidrs)?;
            let secret_key = self
                .key
                .open_secret(&rec.secret, &key(K_KEY, access_key_id))?;
            return Ok(Some(Credential {
                access_key_id: rec.access_key_id,
                secret_key,
                principal,
                session: None,
                expires_at: rec.expires_at,
            }));
        }
        let Some(s) = self.get::<SessionRecord>(&key(K_SESSION, access_key_id))? else {
            return Ok(None);
        };
        if s.expires_at <= now {
            return Ok(None);
        }
        let mut principal = match &s.kind {
            SessionKind::Root => Principal::root(),
            SessionKind::User(u) => match self.resolve_user(u)? {
                Some(p) => p,
                None => return Ok(None),
            },
            SessionKind::Role {
                role, session_name, ..
            }
            | SessionKind::WebIdentity {
                role, session_name, ..
            } => {
                let Some(r) = self.get::<RoleRecord>(&key(K_ROLE, role))? else {
                    return Ok(None);
                };
                let policies = self.policies_of(&r.inline, &r.attached)?;
                let sp = s
                    .session_policy
                    .as_deref()
                    .map(|t| self.compiled(t))
                    .transpose()?;
                let mut p = Principal::assumed_role(role, &r.role_id, session_name, policies, sp);
                if let SessionKind::WebIdentity { tags, .. } = &s.kind {
                    p.tags = tags.clone();
                }
                p
            }
        };
        principal.allowed_source_cidrs = parse_cidrs(&s.allowed_source_cidrs)?;
        let aad = key(K_SESSION, access_key_id);
        let secret_key = self.key.open_secret(&s.secret, &aad)?;
        let mut taad = aad;
        taad.extend_from_slice(b"#token");
        let token = self.key.open_secret(&s.token, &taad)?;
        Ok(Some(Credential {
            access_key_id: s.access_key_id,
            secret_key,
            principal,
            session: Some(SessionInfo {
                token,
                expires_at: s.expires_at,
            }),
            expires_at: Some(s.expires_at),
        }))
    }

    /// Authenticate by presenting the secret itself (MCP `Authorization: Bearer ak:sk[:token]`,
    /// stdio env credentials): the key must resolve (see [`lookup`](Self::lookup)), the secret
    /// match in constant time, and the session token be present iff the key is an STS session.
    /// `None` on any mismatch; never says which part failed.
    pub async fn authenticate_secret(
        &self,
        access_key_id: &str,
        secret: &str,
        session_token: Option<&str>,
    ) -> Result<Option<Credential>, AuthError> {
        let Some(c) = self.lookup(access_key_id).await? else {
            return Ok(None);
        };
        let secret_ok = c.secret_key.ct_eq(secret);
        let token_ok = c.verify_session_token(session_token);
        Ok((secret_ok & token_ok).then_some(c))
    }

    fn policies_of(
        &self,
        inline: &BTreeMap<String, String>,
        attached: &BTreeSet<String>,
    ) -> Result<Vec<PolicyDocument>, AuthError> {
        let mut out = Vec::new();
        for t in inline.values() {
            out.push(self.compiled(t)?);
        }
        for name in attached {
            if let Some(p) = self.get::<PolicyRecord>(&key(K_POLICY, name))? {
                out.push(self.compiled(&p.document)?);
            }
        }
        Ok(out)
    }

    fn resolve_user(&self, name: &str) -> Result<Option<Principal>, AuthError> {
        let Some(u) = self.get::<UserRecord>(&key(K_USER, name))? else {
            return Ok(None);
        };
        if u.disabled {
            return Ok(None);
        }
        let mut policies = self.policies_of(&u.inline, &u.attached)?;
        for g in &u.groups {
            if let Some(gr) = self.get::<GroupRecord>(&key(K_GROUP, g))? {
                policies.extend(self.policies_of(&gr.inline, &gr.attached)?);
            }
        }
        let mut p = Principal::user(&u.name, &u.user_id, policies);
        p.groups = u.groups.into_iter().collect();
        Ok(Some(p))
    }

    /// Resolve a user principal by name (admin tooling, MCP stdio).
    pub async fn principal_for_user(&self, name: &str) -> Result<Option<Principal>, AuthError> {
        self.resolve_user(name)
    }

    // ---------------------------------------------------------------- root

    fn root_access_key_id_sync(&self) -> Result<Option<String>, AuthError> {
        self.get::<String>(K_ROOT)
    }

    /// Current root access key id.
    pub async fn root_access_key_id(&self) -> Result<Option<String>, AuthError> {
        self.root_access_key_id_sync()
    }

    fn install_root(&self, akid: &str, secret: &SecretString) -> Result<(), AuthError> {
        let k = key(K_KEY, akid);
        if let Some(existing) = self.get::<AccessKeyRecord>(&k)?
            && existing.owner != KeyOwner::Root
        {
            return Err(AuthError::AlreadyExists {
                kind: "access key",
                name: akid.into(),
            });
        }
        let rec = AccessKeyRecord {
            access_key_id: akid.to_string(),
            owner: KeyOwner::Root,
            secret: self.key.seal_secret(secret, &k)?,
            active: true,
            created_at: self.now(),
            expires_at: None,
            allowed_source_cidrs: Vec::new(),
        };
        let mut ops = vec![
            BackendOp::Put(k, encode(&rec)?),
            BackendOp::Put(K_ROOT.to_vec(), encode(&akid.to_string())?),
        ];
        if let Some(old) = self.root_access_key_id_sync()?
            && old != akid
        {
            ops.push(BackendOp::Delete(key(K_KEY, &old)));
        }
        self.backend.apply(ops).map_err(be)
    }

    /// Install the root credential from config (first boot or when config changes it).
    /// Any previous root key is removed. Accepts any id format (e.g. `AKIA…`).
    pub async fn ensure_root(
        &self,
        access_key_id: &str,
        secret: &SecretString,
    ) -> Result<(), AuthError> {
        if access_key_id.len() < 3 || access_key_id.len() > 128 || secret.expose().len() < 8 {
            return Err(AuthError::Invalid(
                "root access key id 3..=128 chars, secret ≥ 8 chars".into(),
            ));
        }
        let _g = self.lock();
        if self.root_access_key_id_sync()?.as_deref() == Some(access_key_id)
            && let Some(rec) = self.get::<AccessKeyRecord>(&key(K_KEY, access_key_id))?
            && self
                .key
                .open_secret(&rec.secret, &key(K_KEY, access_key_id))?
                == *secret
        {
            return Ok(());
        }
        self.install_root(access_key_id, secret)
    }

    /// Generate a new root key pair, replacing the old one. Returns the new credentials.
    pub async fn rotate_root(&self) -> Result<NewAccessKey, AuthError> {
        let _g = self.lock();
        let akid = secret::generate_access_key_id();
        let sk = secret::generate_secret_key();
        self.install_root(&akid, &sk)?;
        tracing::warn!(access_key_id = %akid, "root credentials rotated");
        Ok(NewAccessKey {
            access_key_id: akid,
            secret_key: sk,
        })
    }

    // ---------------------------------------------------------------- users

    fn user_info(u: UserRecord) -> UserInfo {
        UserInfo {
            arn: arn::user(&u.name),
            name: u.name,
            user_id: u.user_id,
            created_at: u.created_at,
            groups: u.groups.into_iter().collect(),
            attached_policies: u.attached.into_iter().collect(),
            inline_policies: u.inline.into_keys().collect(),
            disabled: u.disabled,
        }
    }

    /// Create a user.
    pub async fn create_user(&self, name: &str) -> Result<UserInfo, AuthError> {
        validate_name("user", name)?;
        let _g = self.lock();
        let k = key(K_USER, name);
        if self.get::<UserRecord>(&k)?.is_some() {
            return Err(AuthError::AlreadyExists {
                kind: "user",
                name: name.into(),
            });
        }
        let u = UserRecord {
            name: name.to_string(),
            user_id: secret::generate_unique_id("AIDA"),
            created_at: self.now(),
            groups: BTreeSet::new(),
            attached: BTreeSet::new(),
            inline: BTreeMap::new(),
            disabled: false,
        };
        self.put(&k, &u)?;
        Ok(Self::user_info(u))
    }

    /// Get a user.
    pub async fn get_user(&self, name: &str) -> Result<UserInfo, AuthError> {
        self.must::<UserRecord>(K_USER, "user", name)
            .map(Self::user_info)
    }

    /// List users.
    pub async fn list_users(&self) -> Result<Vec<UserInfo>, AuthError> {
        Ok(self
            .list::<UserRecord>(K_USER)?
            .into_iter()
            .map(Self::user_info)
            .collect())
    }

    /// Delete a user together with its access keys and sessions.
    pub async fn delete_user(&self, name: &str) -> Result<(), AuthError> {
        let _g = self.lock();
        self.must::<UserRecord>(K_USER, "user", name)?;
        let mut ops = vec![BackendOp::Delete(key(K_USER, name))];
        for r in self.list::<AccessKeyRecord>(K_KEY)? {
            if r.owner == KeyOwner::User(name.to_string()) {
                ops.push(BackendOp::Delete(key(K_KEY, &r.access_key_id)));
            }
        }
        for s in self.list::<SessionRecord>(K_SESSION)? {
            let mine = match &s.kind {
                SessionKind::User(u) => u == name,
                SessionKind::Role { source, .. } => {
                    *source == crate::types::PrincipalId::user(name)
                }
                SessionKind::Root | SessionKind::WebIdentity { .. } => false,
            };
            if mine {
                ops.push(BackendOp::Delete(key(K_SESSION, &s.access_key_id)));
            }
        }
        self.backend.apply(ops).map_err(be)
    }

    fn update_user(
        &self,
        name: &str,
        f: impl FnOnce(&mut UserRecord) -> Result<(), AuthError>,
    ) -> Result<(), AuthError> {
        let _g = self.lock();
        let mut u = self.must::<UserRecord>(K_USER, "user", name)?;
        f(&mut u)?;
        self.put(&key(K_USER, name), &u)
    }

    /// Enable or disable a user (disabled users' keys and sessions stop working).
    pub async fn set_user_disabled(&self, name: &str, disabled: bool) -> Result<(), AuthError> {
        self.update_user(name, |u| {
            u.disabled = disabled;
            Ok(())
        })
    }

    /// Set an inline user policy.
    pub async fn put_user_policy(
        &self,
        user: &str,
        policy_name: &str,
        document: &str,
    ) -> Result<(), AuthError> {
        validate_name("policy", policy_name)?;
        self.check_policy(document, PolicyKind::Identity)?;
        self.update_user(user, |u| {
            u.inline.insert(policy_name.into(), document.into());
            Ok(())
        })
    }

    /// Remove an inline user policy.
    pub async fn delete_user_policy(&self, user: &str, policy_name: &str) -> Result<(), AuthError> {
        self.update_user(user, |u| {
            u.inline
                .remove(policy_name)
                .map(|_| ())
                .ok_or_else(|| AuthError::NotFound {
                    kind: "policy",
                    name: policy_name.into(),
                })
        })
    }

    /// Attach a managed policy to a user.
    pub async fn attach_user_policy(&self, user: &str, policy: &str) -> Result<(), AuthError> {
        self.must::<PolicyRecord>(K_POLICY, "policy", policy)?;
        self.update_user(user, |u| {
            u.attached.insert(policy.into());
            Ok(())
        })
    }

    /// Detach a managed policy from a user.
    pub async fn detach_user_policy(&self, user: &str, policy: &str) -> Result<(), AuthError> {
        self.update_user(user, |u| {
            u.attached.remove(policy);
            Ok(())
        })
    }

    // ---------------------------------------------------------------- groups

    fn group_info(&self, g: GroupRecord) -> Result<GroupInfo, AuthError> {
        let members = self
            .list::<UserRecord>(K_USER)?
            .into_iter()
            .filter(|u| u.groups.contains(&g.name))
            .map(|u| u.name)
            .collect();
        Ok(GroupInfo {
            name: g.name,
            members,
            attached_policies: g.attached.into_iter().collect(),
            inline_policies: g.inline.into_keys().collect(),
        })
    }

    /// Create a group.
    pub async fn create_group(&self, name: &str) -> Result<(), AuthError> {
        validate_name("group", name)?;
        let _g = self.lock();
        let k = key(K_GROUP, name);
        if self.get::<GroupRecord>(&k)?.is_some() {
            return Err(AuthError::AlreadyExists {
                kind: "group",
                name: name.into(),
            });
        }
        self.put(
            &k,
            &GroupRecord {
                name: name.into(),
                created_at: self.now(),
                attached: BTreeSet::new(),
                inline: BTreeMap::new(),
            },
        )
    }

    /// Get a group with its members.
    pub async fn get_group(&self, name: &str) -> Result<GroupInfo, AuthError> {
        let g = self.must::<GroupRecord>(K_GROUP, "group", name)?;
        self.group_info(g)
    }

    /// List groups.
    pub async fn list_groups(&self) -> Result<Vec<GroupInfo>, AuthError> {
        self.list::<GroupRecord>(K_GROUP)?
            .into_iter()
            .map(|g| self.group_info(g))
            .collect()
    }

    /// Delete a group, removing it from all members.
    pub async fn delete_group(&self, name: &str) -> Result<(), AuthError> {
        let _g = self.lock();
        self.must::<GroupRecord>(K_GROUP, "group", name)?;
        let mut ops = vec![BackendOp::Delete(key(K_GROUP, name))];
        for mut u in self.list::<UserRecord>(K_USER)? {
            if u.groups.remove(name) {
                ops.push(BackendOp::Put(key(K_USER, &u.name), encode(&u)?));
            }
        }
        self.backend.apply(ops).map_err(be)
    }

    /// Add a user to a group.
    pub async fn add_user_to_group(&self, user: &str, group: &str) -> Result<(), AuthError> {
        self.must::<GroupRecord>(K_GROUP, "group", group)?;
        self.update_user(user, |u| {
            u.groups.insert(group.into());
            Ok(())
        })
    }

    /// Remove a user from a group.
    pub async fn remove_user_from_group(&self, user: &str, group: &str) -> Result<(), AuthError> {
        self.update_user(user, |u| {
            u.groups.remove(group);
            Ok(())
        })
    }

    fn update_group(&self, name: &str, f: impl FnOnce(&mut GroupRecord)) -> Result<(), AuthError> {
        let _g = self.lock();
        let mut g = self.must::<GroupRecord>(K_GROUP, "group", name)?;
        f(&mut g);
        self.put(&key(K_GROUP, name), &g)
    }

    /// Set an inline group policy.
    pub async fn put_group_policy(
        &self,
        group: &str,
        policy_name: &str,
        document: &str,
    ) -> Result<(), AuthError> {
        validate_name("policy", policy_name)?;
        self.check_policy(document, PolicyKind::Identity)?;
        self.update_group(group, |g| {
            g.inline.insert(policy_name.into(), document.into());
        })
    }

    /// Remove an inline group policy.
    pub async fn delete_group_policy(
        &self,
        group: &str,
        policy_name: &str,
    ) -> Result<(), AuthError> {
        self.update_group(group, |g| {
            g.inline.remove(policy_name);
        })
    }

    /// Attach a managed policy to a group.
    pub async fn attach_group_policy(&self, group: &str, policy: &str) -> Result<(), AuthError> {
        self.must::<PolicyRecord>(K_POLICY, "policy", policy)?;
        self.update_group(group, |g| {
            g.attached.insert(policy.into());
        })
    }

    /// Detach a managed policy from a group.
    pub async fn detach_group_policy(&self, group: &str, policy: &str) -> Result<(), AuthError> {
        self.update_group(group, |g| {
            g.attached.remove(policy);
        })
    }

    // ---------------------------------------------------------------- managed policies

    fn policy_info(p: PolicyRecord) -> ManagedPolicyInfo {
        ManagedPolicyInfo {
            arn: arn::policy(&p.name),
            name: p.name,
            document: p.document,
            version: p.version,
        }
    }

    /// Create a managed policy.
    pub async fn create_policy(
        &self,
        name: &str,
        document: &str,
    ) -> Result<ManagedPolicyInfo, AuthError> {
        validate_name("policy", name)?;
        self.check_policy(document, PolicyKind::Identity)?;
        let _g = self.lock();
        let k = key(K_POLICY, name);
        if self.get::<PolicyRecord>(&k)?.is_some() {
            return Err(AuthError::AlreadyExists {
                kind: "policy",
                name: name.into(),
            });
        }
        let now = self.now();
        let p = PolicyRecord {
            name: name.into(),
            document: document.into(),
            created_at: now,
            updated_at: now,
            version: 1,
        };
        self.put(&k, &p)?;
        Ok(Self::policy_info(p))
    }

    /// Replace a managed policy's document (takes effect on the next lookup).
    pub async fn update_policy(
        &self,
        name: &str,
        document: &str,
    ) -> Result<ManagedPolicyInfo, AuthError> {
        self.check_policy(document, PolicyKind::Identity)?;
        let _g = self.lock();
        let mut p = self.must::<PolicyRecord>(K_POLICY, "policy", name)?;
        p.document = document.into();
        p.version += 1;
        p.updated_at = self.now();
        self.put(&key(K_POLICY, name), &p)?;
        Ok(Self::policy_info(p))
    }

    /// Get a managed policy.
    pub async fn get_policy(&self, name: &str) -> Result<ManagedPolicyInfo, AuthError> {
        self.must::<PolicyRecord>(K_POLICY, "policy", name)
            .map(Self::policy_info)
    }

    /// List managed policies.
    pub async fn list_policies(&self) -> Result<Vec<ManagedPolicyInfo>, AuthError> {
        Ok(self
            .list::<PolicyRecord>(K_POLICY)?
            .into_iter()
            .map(Self::policy_info)
            .collect())
    }

    /// Delete a managed policy; refused while attached anywhere (as in AWS).
    pub async fn delete_policy(&self, name: &str) -> Result<(), AuthError> {
        let _g = self.lock();
        self.must::<PolicyRecord>(K_POLICY, "policy", name)?;
        let attached = self
            .list::<UserRecord>(K_USER)?
            .iter()
            .any(|u| u.attached.contains(name))
            || self
                .list::<GroupRecord>(K_GROUP)?
                .iter()
                .any(|g| g.attached.contains(name))
            || self
                .list::<RoleRecord>(K_ROLE)?
                .iter()
                .any(|r| r.attached.contains(name));
        if attached {
            return Err(AuthError::Invalid(format!(
                "policy {name} is still attached"
            )));
        }
        self.backend
            .delete(&key(K_POLICY, name))
            .map_err(be)
            .map(|_| ())
    }

    // ---------------------------------------------------------------- roles

    fn role_info(r: RoleRecord) -> RoleInfo {
        RoleInfo {
            arn: arn::role(&r.name),
            name: r.name,
            role_id: r.role_id,
            trust_policy: r.trust_policy,
            attached_policies: r.attached.into_iter().collect(),
            inline_policies: r.inline.into_keys().collect(),
            max_session: Duration::from_secs(r.max_session_secs),
        }
    }

    /// Create a role with a trust policy. `max_session` defaults to 12 h (range 1 h–12 h).
    pub async fn create_role(
        &self,
        name: &str,
        trust_policy: &str,
        max_session: Option<Duration>,
    ) -> Result<RoleInfo, AuthError> {
        validate_name("role", name)?;
        self.check_policy(trust_policy, PolicyKind::Trust)?;
        let max = max_session.unwrap_or(MAX_SESSION);
        if max < Duration::from_secs(3600) || max > MAX_SESSION {
            return Err(AuthError::Invalid(
                "max session duration must be 1h..=12h".into(),
            ));
        }
        let _g = self.lock();
        let k = key(K_ROLE, name);
        if self.get::<RoleRecord>(&k)?.is_some() {
            return Err(AuthError::AlreadyExists {
                kind: "role",
                name: name.into(),
            });
        }
        let r = RoleRecord {
            name: name.into(),
            role_id: secret::generate_unique_id("AROA"),
            created_at: self.now(),
            trust_policy: trust_policy.into(),
            attached: BTreeSet::new(),
            inline: BTreeMap::new(),
            max_session_secs: max.as_secs(),
        };
        self.put(&k, &r)?;
        Ok(Self::role_info(r))
    }

    /// Get a role.
    pub async fn get_role(&self, name: &str) -> Result<RoleInfo, AuthError> {
        self.must::<RoleRecord>(K_ROLE, "role", name)
            .map(Self::role_info)
    }

    pub(crate) fn role_record(&self, name: &str) -> Result<RoleRecord, AuthError> {
        self.must::<RoleRecord>(K_ROLE, "role", name)
    }

    /// List roles.
    pub async fn list_roles(&self) -> Result<Vec<RoleInfo>, AuthError> {
        Ok(self
            .list::<RoleRecord>(K_ROLE)?
            .into_iter()
            .map(Self::role_info)
            .collect())
    }

    /// Delete a role and its sessions.
    pub async fn delete_role(&self, name: &str) -> Result<(), AuthError> {
        let _g = self.lock();
        self.must::<RoleRecord>(K_ROLE, "role", name)?;
        let mut ops = vec![BackendOp::Delete(key(K_ROLE, name))];
        for s in self.list::<SessionRecord>(K_SESSION)? {
            if matches!(&s.kind, SessionKind::Role { role, .. } | SessionKind::WebIdentity { role, .. } if role == name)
            {
                ops.push(BackendOp::Delete(key(K_SESSION, &s.access_key_id)));
            }
        }
        self.backend.apply(ops).map_err(be)
    }

    fn update_role(&self, name: &str, f: impl FnOnce(&mut RoleRecord)) -> Result<(), AuthError> {
        let _g = self.lock();
        let mut r = self.must::<RoleRecord>(K_ROLE, "role", name)?;
        f(&mut r);
        self.put(&key(K_ROLE, name), &r)
    }

    /// Replace a role's trust policy.
    pub async fn update_assume_role_policy(
        &self,
        name: &str,
        trust_policy: &str,
    ) -> Result<(), AuthError> {
        self.check_policy(trust_policy, PolicyKind::Trust)?;
        self.update_role(name, |r| r.trust_policy = trust_policy.into())
    }

    /// Set an inline role policy.
    pub async fn put_role_policy(
        &self,
        role: &str,
        policy_name: &str,
        document: &str,
    ) -> Result<(), AuthError> {
        validate_name("policy", policy_name)?;
        self.check_policy(document, PolicyKind::Identity)?;
        self.update_role(role, |r| {
            r.inline.insert(policy_name.into(), document.into());
        })
    }

    /// Remove an inline role policy.
    pub async fn delete_role_policy(&self, role: &str, policy_name: &str) -> Result<(), AuthError> {
        self.update_role(role, |r| {
            r.inline.remove(policy_name);
        })
    }

    /// Attach a managed policy to a role.
    pub async fn attach_role_policy(&self, role: &str, policy: &str) -> Result<(), AuthError> {
        self.must::<PolicyRecord>(K_POLICY, "policy", policy)?;
        self.update_role(role, |r| {
            r.attached.insert(policy.into());
        })
    }

    /// Detach a managed policy from a role.
    pub async fn detach_role_policy(&self, role: &str, policy: &str) -> Result<(), AuthError> {
        self.update_role(role, |r| {
            r.attached.remove(policy);
        })
    }

    // ---------------------------------------------------------------- access keys

    fn key_info(r: AccessKeyRecord) -> AccessKeyInfo {
        AccessKeyInfo {
            access_key_id: r.access_key_id,
            user: match r.owner {
                KeyOwner::Root => None,
                KeyOwner::User(u) => Some(u),
            },
            active: r.active,
            created_at: r.created_at,
            expires_at: r.expires_at,
            allowed_source_cidrs: r.allowed_source_cidrs,
        }
    }

    /// Create an access key for `user` (`CAIRN…`, 20 chars; secret 40 chars base64url).
    pub async fn create_access_key(
        &self,
        user: &str,
        opts: AccessKeyOptions,
    ) -> Result<NewAccessKey, AuthError> {
        let akid = secret::generate_access_key_id();
        let sk = secret::generate_secret_key();
        self.import_access_key(user, &akid, &sk, opts).await?;
        Ok(NewAccessKey {
            access_key_id: akid,
            secret_key: sk,
        })
    }

    /// Store an externally supplied key pair (migration from AWS/MinIO: any id format).
    pub async fn import_access_key(
        &self,
        user: &str,
        access_key_id: &str,
        secret: &SecretString,
        opts: AccessKeyOptions,
    ) -> Result<(), AuthError> {
        if access_key_id.len() < 3
            || access_key_id.len() > 128
            || !access_key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(AuthError::Invalid(
                "access key id must be 3..=128 chars [A-Za-z0-9_-]".into(),
            ));
        }
        parse_cidrs(&opts.allowed_source_cidrs)?;
        let now = self.now();
        if opts.expires_at.is_some_and(|e| e <= now) {
            return Err(AuthError::Invalid("expiry is in the past".into()));
        }
        let _g = self.lock();
        self.must::<UserRecord>(K_USER, "user", user)?;
        let k = key(K_KEY, access_key_id);
        if self.get::<AccessKeyRecord>(&k)?.is_some()
            || self
                .get::<SessionRecord>(&key(K_SESSION, access_key_id))?
                .is_some()
        {
            return Err(AuthError::AlreadyExists {
                kind: "access key",
                name: access_key_id.into(),
            });
        }
        let owner = KeyOwner::User(user.into());
        let count = self
            .list::<AccessKeyRecord>(K_KEY)?
            .iter()
            .filter(|r| r.owner == owner)
            .count();
        if count >= self.max_keys_per_user {
            return Err(AuthError::LimitExceeded(format!(
                "user {user} already has {count} access keys"
            )));
        }
        let rec = AccessKeyRecord {
            access_key_id: access_key_id.into(),
            owner,
            secret: self.key.seal_secret(secret, &k)?,
            active: true,
            created_at: now,
            expires_at: opts.expires_at,
            allowed_source_cidrs: opts.allowed_source_cidrs,
        };
        self.put(&k, &rec)
    }

    /// Permanently revoke (delete) a user access key. Root keys are replaced via `rotate_root`.
    pub async fn revoke_access_key(&self, access_key_id: &str) -> Result<(), AuthError> {
        let _g = self.lock();
        let r = self.must::<AccessKeyRecord>(K_KEY, "access key", access_key_id)?;
        if r.owner == KeyOwner::Root {
            return Err(AuthError::Invalid(
                "use rotate_root to replace the root key".into(),
            ));
        }
        self.backend
            .delete(&key(K_KEY, access_key_id))
            .map_err(be)
            .map(|_| ())
    }

    /// Activate or deactivate a user access key.
    pub async fn set_access_key_active(
        &self,
        access_key_id: &str,
        active: bool,
    ) -> Result<(), AuthError> {
        let _g = self.lock();
        let mut r = self.must::<AccessKeyRecord>(K_KEY, "access key", access_key_id)?;
        if r.owner == KeyOwner::Root {
            return Err(AuthError::Invalid(
                "the root key cannot be deactivated".into(),
            ));
        }
        r.active = active;
        self.put(&key(K_KEY, access_key_id), &r)
    }

    /// List a user's access keys (`None` = all keys including root).
    pub async fn list_access_keys(
        &self,
        user: Option<&str>,
    ) -> Result<Vec<AccessKeyInfo>, AuthError> {
        Ok(self
            .list::<AccessKeyRecord>(K_KEY)?
            .into_iter()
            .filter(|r| user.is_none_or(|u| r.owner == KeyOwner::User(u.into())))
            .map(Self::key_info)
            .collect())
    }

    // ---------------------------------------------------------------- sessions (see sts.rs)

    pub(crate) fn store_session(&self, rec: &SessionRecord) -> Result<(), AuthError> {
        let _g = self.lock();
        self.put(&key(K_SESSION, &rec.access_key_id), rec)
    }

    pub(crate) fn seal_session(
        &self,
        akid: &str,
        secret: &SecretString,
        token: &SecretString,
    ) -> Result<(crate::secret::Sealed, crate::secret::Sealed), AuthError> {
        let aad = key(K_SESSION, akid);
        let s = self.key.seal_secret(secret, &aad)?;
        let mut taad = aad;
        taad.extend_from_slice(b"#token");
        let t = self.key.seal_secret(token, &taad)?;
        Ok((s, t))
    }

    pub(crate) fn compile_policy(
        &self,
        text: &str,
        kind: PolicyKind<'_>,
    ) -> Result<PolicyDocument, AuthError> {
        self.check_policy(text, kind)
    }

    /// Delete all expired STS sessions; returns how many were removed.
    pub async fn purge_expired_sessions(&self) -> Result<usize, AuthError> {
        let _g = self.lock();
        let now = self.now();
        let ops: Vec<BackendOp> = self
            .list::<SessionRecord>(K_SESSION)?
            .into_iter()
            .filter(|s| s.expires_at <= now)
            .map(|s| BackendOp::Delete(key(K_SESSION, &s.access_key_id)))
            .collect();
        let n = ops.len();
        if n > 0 {
            self.backend.apply(ops).map_err(be)?;
        }
        Ok(n)
    }

    /// Revoke an STS session immediately (its access key id stops resolving).
    pub async fn revoke_session(&self, access_key_id: &str) -> Result<(), AuthError> {
        let _g = self.lock();
        let k = key(K_SESSION, access_key_id);
        if self.get::<SessionRecord>(&k)?.is_none() {
            return Err(AuthError::NotFound {
                kind: "session",
                name: access_key_id.into(),
            });
        }
        self.backend.delete(&k).map_err(be).map(|_| ())
    }

    /// Revoke every session issued for `principal_id` (e.g. `user:alice`, or `role:r/` for
    /// all sessions of role `r`); returns how many were removed.
    pub async fn revoke_sessions_for(&self, principal_id: &str) -> Result<usize, AuthError> {
        let _g = self.lock();
        let ops: Vec<BackendOp> = self
            .list::<SessionRecord>(K_SESSION)?
            .into_iter()
            .filter(|s| session_principal(&s.kind).starts_with(principal_id))
            .map(|s| BackendOp::Delete(key(K_SESSION, &s.access_key_id)))
            .collect();
        let n = ops.len();
        if n > 0 {
            self.backend.apply(ops).map_err(be)?;
        }
        Ok(n)
    }

    /// List STS sessions (no secrets).
    pub async fn list_sessions(&self) -> Result<Vec<SessionSummary>, AuthError> {
        let now = self.now();
        Ok(self
            .list::<SessionRecord>(K_SESSION)?
            .into_iter()
            .map(|s| SessionSummary {
                principal: session_principal(&s.kind),
                source: match &s.kind {
                    SessionKind::Role { source, .. } => Some(source.to_string()),
                    SessionKind::WebIdentity {
                        provider, subject, ..
                    } => Some(format!("oidc:{provider}/{subject}")),
                    _ => None,
                },
                expired: s.expires_at <= now,
                access_key_id: s.access_key_id,
                created_at: s.created_at,
                expires_at: s.expires_at,
            })
            .collect())
    }

    /// Number of stored sessions (including expired, not yet purged).
    pub async fn session_count(&self) -> Result<usize, AuthError> {
        Ok(self
            .backend
            .list_prefix(K_SESSION.as_bytes())
            .map_err(be)?
            .len())
    }
}

#[cfg(test)]
mod tests;
