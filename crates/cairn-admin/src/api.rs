//! The admin REST API under `/_cairn/v1` (DESIGN §9, §7.3). JSON in and out, SigV4
//! authentication with any Cairn credential, then authorisation of a `cairn:*` action
//! (root is always allowed). Secrets are returned only when a key is created or rotated.

use crate::engine::{
    AdminEngine, PitrDiffQuery, PitrRequest, PurgeRequest, RestoreBucketRequest, RestoreRequest,
    RetentionSettings, TrashQuery,
};
use crate::error::{AdminError, REQUEST_ID, REQUEST_ID_HEADER};
use axum::extract::{FromRequest, FromRequestParts, Path, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use cairn_auth::arn;
use cairn_auth::store::{GroupInfo, ManagedPolicyInfo, RoleInfo, UserInfo};
use cairn_auth::{
    AccessKeyInfo, AccessKeyOptions, AuthzEngine, ConditionContext, CredentialStore, Decision,
    NewAccessKey, Principal, RequestMeta, SessionSummary, Ts,
};
use http::StatusCode;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

/// URL prefix of the admin API.
pub const PREFIX: &str = "/_cairn/v1";
/// Maximum admin request body.
pub const MAX_BODY: usize = 1 << 20;

/// Shared state of the admin router.
#[derive(Clone)]
pub struct AdminState {
    store: Arc<CredentialStore>,
    engine: Arc<dyn AdminEngine>,
    authz: AuthzEngine,
}

impl std::fmt::Debug for AdminState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdminState")
    }
}

impl AdminState {
    /// State over the credential store and a storage engine.
    pub fn new(store: Arc<CredentialStore>, engine: Arc<dyn AdminEngine>) -> Self {
        Self {
            store,
            engine,
            authz: AuthzEngine::new(),
        }
    }
    /// Replace the authoriser (tests inject a clock).
    pub fn with_authz(mut self, authz: AuthzEngine) -> Self {
        self.authz = authz;
        self
    }
}

/// The authenticated admin caller (request extension).
#[derive(Debug, Clone)]
pub struct Caller {
    /// Resolved principal.
    pub principal: Principal,
    /// Condition context of the request (source IP, TLS).
    pub context: ConditionContext,
}

type R<T> = Result<T, AdminError>;

/// JSON body extractor whose rejection uses the admin error envelope.
pub struct JsonBody<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for JsonBody<T> {
    type Rejection = AdminError;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(v)| JsonBody(v))
            .map_err(|e| AdminError::invalid(e.body_text()))
    }
}

/// Query extractor whose rejection uses the admin error envelope.
pub struct QueryArgs<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequestParts<S> for QueryArgs<T> {
    type Rejection = AdminError;
    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        axum::extract::Query::<T>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Query(v)| QueryArgs(v))
            .map_err(|e| AdminError::invalid(e.body_text()))
    }
}

impl AdminState {
    fn allow(&self, c: &Caller, action: &str, resource: Option<&str>) -> R<()> {
        let server = arn::server();
        let res = resource.unwrap_or(&server);
        match self
            .authz
            .authorize(Some(&c.principal), action, res, &c.context, None)
        {
            Decision::Allow => Ok(()),
            _ => {
                tracing::info!(principal = %c.principal.id, action, resource = res, "admin access denied");
                Err(AdminError::denied(format!(
                    "{} is not allowed to perform {action}",
                    c.principal.arn
                )))
            }
        }
    }
}

fn rfc(t: Ts) -> String {
    t.to_rfc3339()
}

fn user_json(u: UserInfo) -> Value {
    json!({
        "name": u.name, "user_id": u.user_id, "arn": u.arn, "created_at": rfc(u.created_at),
        "groups": u.groups, "attached_policies": u.attached_policies,
        "inline_policies": u.inline_policies, "disabled": u.disabled,
    })
}

fn group_json(g: GroupInfo) -> Value {
    json!({
        "name": g.name, "arn": arn::group(&g.name), "members": g.members,
        "attached_policies": g.attached_policies, "inline_policies": g.inline_policies,
    })
}

fn role_json(r: RoleInfo) -> Value {
    json!({
        "name": r.name, "role_id": r.role_id, "arn": r.arn, "trust_policy": r.trust_policy,
        "attached_policies": r.attached_policies, "inline_policies": r.inline_policies,
        "max_session_secs": r.max_session.as_secs(),
    })
}

fn policy_json(p: ManagedPolicyInfo) -> Value {
    json!({ "name": p.name, "arn": p.arn, "document": p.document, "version": p.version })
}

fn key_json(k: AccessKeyInfo) -> Value {
    json!({
        "access_key_id": k.access_key_id, "user": k.user, "active": k.active,
        "created_at": rfc(k.created_at), "expires_at": k.expires_at.map(rfc),
        "allowed_source_cidrs": k.allowed_source_cidrs,
    })
}

fn new_key_json(k: NewAccessKey, user: Option<&str>) -> Value {
    json!({
        "access_key_id": k.access_key_id,
        "secret_access_key": k.secret_key.expose(),
        "user": user,
    })
}

fn session_json(s: SessionSummary) -> Value {
    json!({
        "access_key_id": s.access_key_id, "principal": s.principal, "source": s.source,
        "created_at": rfc(s.created_at), "expires_at": rfc(s.expires_at), "expired": s.expired,
    })
}

fn parse_ts(s: &str) -> R<Ts> {
    s.parse::<jiff::Timestamp>()
        .map(Ts::from_jiff)
        .map_err(|_| AdminError::invalid(format!("invalid RFC 3339 timestamp {s:?}")))
}

fn ok() -> Json<Value> {
    Json(json!({ "ok": true }))
}

fn list<T>(items: Vec<T>, f: impl Fn(T) -> Value) -> Json<Value> {
    Json(json!({ "items": items.into_iter().map(f).collect::<Vec<_>>() }))
}

// ---------------------------------------------------------------- bodies

#[derive(Deserialize)]
struct NameBody {
    name: String,
}

#[derive(Deserialize)]
struct DocBody {
    document: Value,
}

#[derive(Deserialize)]
struct NamedDocBody {
    name: String,
    document: Value,
}

#[derive(Deserialize)]
struct RoleBody {
    name: String,
    trust_policy: Value,
    max_session_secs: Option<u64>,
}

#[derive(Deserialize, Default)]
struct KeyBody {
    expires_at: Option<String>,
    #[serde(default)]
    allowed_source_cidrs: Vec<String>,
}

#[derive(Deserialize)]
struct ServiceAccountBody {
    name: String,
    bucket: String,
    #[serde(default)]
    read_only: bool,
}

#[derive(Deserialize, Serialize)]
struct QuotaBody {
    quota_bytes: Option<u64>,
}

#[derive(Deserialize)]
struct KeyFilter {
    user: Option<String>,
}

/// Policy documents may be sent as a JSON object or as a JSON string.
fn doc_text(v: Value) -> R<String> {
    match v {
        Value::String(s) => Ok(s),
        Value::Object(_) => Ok(v.to_string()),
        _ => Err(AdminError::invalid(
            "document must be a JSON object or string",
        )),
    }
}

// ---------------------------------------------------------------- handlers

type S = State<AdminState>;
type C = Extension<Caller>;

async fn whoami(Extension(c): C) -> Json<Value> {
    Json(json!({
        "id": c.principal.id.as_str(), "arn": c.principal.arn, "user_id": c.principal.user_id,
        "is_root": c.principal.is_root, "groups": c.principal.groups,
    }))
}

async fn server_info(State(s): S, Extension(c): C) -> R<Json<Value>> {
    s.allow(&c, "cairn:GetServerInfo", None)?;
    Ok(Json(json!(s.engine.server_info().await?)))
}

async fn list_users(State(s): S, Extension(c): C) -> R<Json<Value>> {
    s.allow(&c, "cairn:ListUsers", None)?;
    Ok(list(s.store.list_users().await?, user_json))
}

async fn create_user(State(s): S, Extension(c): C, JsonBody(b): JsonBody<NameBody>) -> R<Response> {
    s.allow(&c, "cairn:CreateUser", None)?;
    let u = s.store.create_user(&b.name).await?;
    Ok((StatusCode::CREATED, Json(user_json(u))).into_response())
}

async fn get_user(State(s): S, Extension(c): C, Path(u): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:GetUser", None)?;
    Ok(Json(user_json(s.store.get_user(&u).await?)))
}

async fn delete_user(State(s): S, Extension(c): C, Path(u): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:DeleteUser", None)?;
    s.store.delete_user(&u).await?;
    s.store.revoke_sessions_for(&format!("user:{u}")).await?;
    Ok(ok())
}

async fn enable_user(State(s): S, Extension(c): C, Path(u): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:UpdateUser", None)?;
    s.store.set_user_disabled(&u, false).await?;
    Ok(ok())
}

async fn disable_user(State(s): S, Extension(c): C, Path(u): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:UpdateUser", None)?;
    s.store.set_user_disabled(&u, true).await?;
    Ok(ok())
}

async fn put_user_policy(
    State(s): S,
    Extension(c): C,
    Path((u, p)): Path<(String, String)>,
    JsonBody(b): JsonBody<DocBody>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:PutUserPolicy", None)?;
    s.store
        .put_user_policy(&u, &p, &doc_text(b.document)?)
        .await?;
    Ok(ok())
}

async fn delete_user_policy(
    State(s): S,
    Extension(c): C,
    Path((u, p)): Path<(String, String)>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:DeleteUserPolicy", None)?;
    s.store.delete_user_policy(&u, &p).await?;
    Ok(ok())
}

async fn attach_user_policy(
    State(s): S,
    Extension(c): C,
    Path((u, p)): Path<(String, String)>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:AttachUserPolicy", None)?;
    s.store.attach_user_policy(&u, &p).await?;
    Ok(ok())
}

async fn detach_user_policy(
    State(s): S,
    Extension(c): C,
    Path((u, p)): Path<(String, String)>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:DetachUserPolicy", None)?;
    s.store.detach_user_policy(&u, &p).await?;
    Ok(ok())
}

async fn list_user_keys(State(s): S, Extension(c): C, Path(u): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:ListAccessKeys", None)?;
    s.store.get_user(&u).await?;
    Ok(list(s.store.list_access_keys(Some(&u)).await?, key_json))
}

async fn create_key(
    State(s): S,
    Extension(c): C,
    Path(u): Path<String>,
    body: axum::body::Bytes,
) -> R<Response> {
    s.allow(&c, "cairn:CreateAccessKey", None)?;
    let b: KeyBody = if body.is_empty() {
        KeyBody::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| AdminError::invalid(e.to_string()))?
    };
    let opts = AccessKeyOptions {
        expires_at: b.expires_at.as_deref().map(parse_ts).transpose()?,
        allowed_source_cidrs: b.allowed_source_cidrs,
    };
    let k = s.store.create_access_key(&u, opts).await?;
    tracing::info!(user = %u, access_key_id = %k.access_key_id, by = %c.principal.id, "access key created");
    Ok((StatusCode::CREATED, Json(new_key_json(k, Some(&u)))).into_response())
}

async fn list_keys(
    State(s): S,
    Extension(c): C,
    QueryArgs(f): QueryArgs<KeyFilter>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:ListAccessKeys", None)?;
    Ok(list(
        s.store.list_access_keys(f.user.as_deref()).await?,
        key_json,
    ))
}

async fn delete_key(State(s): S, Extension(c): C, Path(k): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:DeleteAccessKey", None)?;
    s.store.revoke_access_key(&k).await?;
    Ok(ok())
}

async fn activate_key(State(s): S, Extension(c): C, Path(k): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:UpdateAccessKey", None)?;
    s.store.set_access_key_active(&k, true).await?;
    Ok(ok())
}

async fn deactivate_key(State(s): S, Extension(c): C, Path(k): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:UpdateAccessKey", None)?;
    s.store.set_access_key_active(&k, false).await?;
    Ok(ok())
}

async fn rotate_root(State(s): S, Extension(c): C) -> R<Response> {
    s.allow(&c, "cairn:RotateRootCredentials", None)?;
    let k = s.store.rotate_root().await?;
    Ok((StatusCode::CREATED, Json(new_key_json(k, None))).into_response())
}

async fn create_service_account(
    State(s): S,
    Extension(c): C,
    JsonBody(b): JsonBody<ServiceAccountBody>,
) -> R<Response> {
    s.allow(&c, "cairn:CreateServiceAccount", None)?;
    let actions = if b.read_only {
        json!([
            "s3:GetObject",
            "s3:GetObjectVersion",
            "s3:GetObjectTagging",
            "s3:ListBucket",
            "s3:ListBucketVersions",
            "s3:GetBucketLocation"
        ])
    } else {
        json!([
            "s3:GetObject",
            "s3:GetObjectVersion",
            "s3:GetObjectTagging",
            "s3:PutObject",
            "s3:PutObjectTagging",
            "s3:DeleteObject",
            "s3:DeleteObjectVersion",
            "s3:AbortMultipartUpload",
            "s3:ListMultipartUploadParts",
            "s3:ListBucket",
            "s3:ListBucketVersions",
            "s3:ListBucketMultipartUploads",
            "s3:GetBucketLocation"
        ])
    };
    let doc = json!({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": actions,
            "Resource": [arn::bucket(&b.bucket), format!("{}/*", arn::bucket(&b.bucket))],
        }]
    });
    let u = s.store.create_user(&b.name).await?;
    let res = async {
        s.store
            .put_user_policy(&b.name, "service-account", &doc.to_string())
            .await?;
        s.store
            .create_access_key(&b.name, AccessKeyOptions::default())
            .await
    }
    .await;
    let k = match res {
        Ok(k) => k,
        Err(e) => {
            let _ = s.store.delete_user(&b.name).await;
            return Err(e.into());
        }
    };
    let mut v = new_key_json(k, Some(&b.name));
    v["user_arn"] = json!(u.arn);
    v["bucket"] = json!(b.bucket);
    v["read_only"] = json!(b.read_only);
    Ok((StatusCode::CREATED, Json(v)).into_response())
}

async fn list_groups(State(s): S, Extension(c): C) -> R<Json<Value>> {
    s.allow(&c, "cairn:ListGroups", None)?;
    Ok(list(s.store.list_groups().await?, group_json))
}

async fn create_group(
    State(s): S,
    Extension(c): C,
    JsonBody(b): JsonBody<NameBody>,
) -> R<Response> {
    s.allow(&c, "cairn:CreateGroup", None)?;
    s.store.create_group(&b.name).await?;
    let g = s.store.get_group(&b.name).await?;
    Ok((StatusCode::CREATED, Json(group_json(g))).into_response())
}

async fn get_group(State(s): S, Extension(c): C, Path(g): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:GetGroup", None)?;
    Ok(Json(group_json(s.store.get_group(&g).await?)))
}

async fn delete_group(State(s): S, Extension(c): C, Path(g): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:DeleteGroup", None)?;
    s.store.delete_group(&g).await?;
    Ok(ok())
}

async fn add_member(
    State(s): S,
    Extension(c): C,
    Path((g, u)): Path<(String, String)>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:AddUserToGroup", None)?;
    s.store.add_user_to_group(&u, &g).await?;
    Ok(ok())
}

async fn remove_member(
    State(s): S,
    Extension(c): C,
    Path((g, u)): Path<(String, String)>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:RemoveUserFromGroup", None)?;
    s.store.remove_user_from_group(&u, &g).await?;
    Ok(ok())
}

async fn put_group_policy(
    State(s): S,
    Extension(c): C,
    Path((g, p)): Path<(String, String)>,
    JsonBody(b): JsonBody<DocBody>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:PutGroupPolicy", None)?;
    s.store
        .put_group_policy(&g, &p, &doc_text(b.document)?)
        .await?;
    Ok(ok())
}

async fn delete_group_policy(
    State(s): S,
    Extension(c): C,
    Path((g, p)): Path<(String, String)>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:DeleteGroupPolicy", None)?;
    s.store.delete_group_policy(&g, &p).await?;
    Ok(ok())
}

async fn attach_group_policy(
    State(s): S,
    Extension(c): C,
    Path((g, p)): Path<(String, String)>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:AttachGroupPolicy", None)?;
    s.store.attach_group_policy(&g, &p).await?;
    Ok(ok())
}

async fn detach_group_policy(
    State(s): S,
    Extension(c): C,
    Path((g, p)): Path<(String, String)>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:DetachGroupPolicy", None)?;
    s.store.detach_group_policy(&g, &p).await?;
    Ok(ok())
}

async fn list_policies(State(s): S, Extension(c): C) -> R<Json<Value>> {
    s.allow(&c, "cairn:ListPolicies", None)?;
    Ok(list(s.store.list_policies().await?, policy_json))
}

async fn create_policy(
    State(s): S,
    Extension(c): C,
    JsonBody(b): JsonBody<NamedDocBody>,
) -> R<Response> {
    s.allow(&c, "cairn:CreatePolicy", None)?;
    let p = s
        .store
        .create_policy(&b.name, &doc_text(b.document)?)
        .await?;
    Ok((StatusCode::CREATED, Json(policy_json(p))).into_response())
}

async fn get_policy(State(s): S, Extension(c): C, Path(p): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:GetPolicy", None)?;
    Ok(Json(policy_json(s.store.get_policy(&p).await?)))
}

async fn update_policy(
    State(s): S,
    Extension(c): C,
    Path(p): Path<String>,
    JsonBody(b): JsonBody<DocBody>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:UpdatePolicy", None)?;
    let p = s.store.update_policy(&p, &doc_text(b.document)?).await?;
    Ok(Json(policy_json(p)))
}

async fn delete_policy(State(s): S, Extension(c): C, Path(p): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:DeletePolicy", None)?;
    s.store.delete_policy(&p).await?;
    Ok(ok())
}

async fn list_roles(State(s): S, Extension(c): C) -> R<Json<Value>> {
    s.allow(&c, "cairn:ListRoles", None)?;
    Ok(list(s.store.list_roles().await?, role_json))
}

async fn create_role(State(s): S, Extension(c): C, JsonBody(b): JsonBody<RoleBody>) -> R<Response> {
    s.allow(&c, "cairn:CreateRole", None)?;
    let r = s
        .store
        .create_role(
            &b.name,
            &doc_text(b.trust_policy)?,
            b.max_session_secs.map(Duration::from_secs),
        )
        .await?;
    Ok((StatusCode::CREATED, Json(role_json(r))).into_response())
}

async fn get_role(State(s): S, Extension(c): C, Path(r): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:GetRole", None)?;
    Ok(Json(role_json(s.store.get_role(&r).await?)))
}

async fn delete_role(State(s): S, Extension(c): C, Path(r): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:DeleteRole", None)?;
    s.store.delete_role(&r).await?;
    s.store.revoke_sessions_for(&format!("role:{r}/")).await?;
    Ok(ok())
}

async fn update_trust(
    State(s): S,
    Extension(c): C,
    Path(r): Path<String>,
    JsonBody(b): JsonBody<DocBody>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:UpdateAssumeRolePolicy", None)?;
    s.store
        .update_assume_role_policy(&r, &doc_text(b.document)?)
        .await?;
    Ok(ok())
}

async fn put_role_policy(
    State(s): S,
    Extension(c): C,
    Path((r, p)): Path<(String, String)>,
    JsonBody(b): JsonBody<DocBody>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:PutRolePolicy", None)?;
    s.store
        .put_role_policy(&r, &p, &doc_text(b.document)?)
        .await?;
    Ok(ok())
}

async fn delete_role_policy(
    State(s): S,
    Extension(c): C,
    Path((r, p)): Path<(String, String)>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:DeleteRolePolicy", None)?;
    s.store.delete_role_policy(&r, &p).await?;
    Ok(ok())
}

async fn attach_role_policy(
    State(s): S,
    Extension(c): C,
    Path((r, p)): Path<(String, String)>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:AttachRolePolicy", None)?;
    s.store.attach_role_policy(&r, &p).await?;
    Ok(ok())
}

async fn detach_role_policy(
    State(s): S,
    Extension(c): C,
    Path((r, p)): Path<(String, String)>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:DetachRolePolicy", None)?;
    s.store.detach_role_policy(&r, &p).await?;
    Ok(ok())
}

async fn list_sessions(State(s): S, Extension(c): C) -> R<Json<Value>> {
    s.allow(&c, "cairn:ListSessions", None)?;
    Ok(list(s.store.list_sessions().await?, session_json))
}

async fn revoke_session(State(s): S, Extension(c): C, Path(k): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:RevokeSession", None)?;
    s.store.revoke_session(&k).await?;
    Ok(ok())
}

async fn purge_sessions(State(s): S, Extension(c): C) -> R<Json<Value>> {
    s.allow(&c, "cairn:RevokeSession", None)?;
    let n = s.store.purge_expired_sessions().await?;
    Ok(Json(json!({ "purged": n })))
}

async fn list_buckets(State(s): S, Extension(c): C) -> R<Json<Value>> {
    s.allow(&c, "cairn:GetStorageStats", None)?;
    Ok(Json(json!({ "items": s.engine.list_buckets().await? })))
}

async fn get_bucket(State(s): S, Extension(c): C, Path(b): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:GetStorageStats", Some(&arn::bucket(&b)))?;
    Ok(Json(json!(s.engine.get_bucket(&b).await?)))
}

async fn set_quota(
    State(s): S,
    Extension(c): C,
    Path(b): Path<String>,
    JsonBody(q): JsonBody<QuotaBody>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:ManageQuota", Some(&arn::bucket(&b)))?;
    s.engine.set_quota(&b, q.quota_bytes).await?;
    Ok(ok())
}

async fn get_retention(State(s): S, Extension(c): C, Path(b): Path<String>) -> R<Json<Value>> {
    s.allow(&c, "cairn:GetRetention", Some(&arn::bucket(&b)))?;
    Ok(Json(json!(s.engine.get_bucket(&b).await?.retention)))
}

async fn set_retention(
    State(s): S,
    Extension(c): C,
    Path(b): Path<String>,
    JsonBody(r): JsonBody<RetentionSettings>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:SetRetention", Some(&arn::bucket(&b)))?;
    s.engine.set_retention(&b, r).await?;
    Ok(ok())
}

fn bucket_res(b: Option<&str>) -> Option<String> {
    b.map(arn::bucket)
}

async fn list_trash(
    State(s): S,
    Extension(c): C,
    QueryArgs(q): QueryArgs<TrashQuery>,
) -> R<Json<Value>> {
    s.allow(
        &c,
        "cairn:ListTrash",
        bucket_res(q.bucket.as_deref()).as_deref(),
    )?;
    for t in [&q.deleted_after, &q.deleted_before].into_iter().flatten() {
        parse_ts(t)?;
    }
    Ok(Json(json!(s.engine.list_trash(q).await?)))
}

async fn restore(
    State(s): S,
    Extension(c): C,
    JsonBody(r): JsonBody<RestoreRequest>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:Restore", Some(&arn::object(&r.bucket, &r.key)))?;
    Ok(Json(json!(s.engine.restore(r).await?)))
}

async fn restore_bucket(
    State(s): S,
    Extension(c): C,
    JsonBody(r): JsonBody<RestoreBucketRequest>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:RestoreBucket", None)?;
    Ok(Json(json!(s.engine.restore_bucket(r).await?)))
}

async fn purge(
    State(s): S,
    Extension(c): C,
    JsonBody(r): JsonBody<PurgeRequest>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:Purge", Some(&arn::bucket(&r.bucket)))?;
    if !r.confirm {
        return Err(AdminError::invalid(
            "purge is irreversible; set \"confirm\": true (CLI: --yes)",
        ));
    }
    if let Some(t) = &r.older_than {
        parse_ts(t)?;
    }
    Ok(Json(json!(s.engine.purge(r).await?)))
}

async fn pitr_restore(
    State(s): S,
    Extension(c): C,
    JsonBody(r): JsonBody<PitrRequest>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:Pitr", Some(&arn::bucket(&r.bucket)))?;
    if let Some(t) = &r.target_bucket {
        s.allow(&c, "cairn:Pitr", Some(&arn::bucket(t)))?;
    }
    parse_ts(&r.as_of)?;
    Ok(Json(json!(s.engine.pitr_restore(r).await?)))
}

async fn pitr_diff(
    State(s): S,
    Extension(c): C,
    QueryArgs(q): QueryArgs<PitrDiffQuery>,
) -> R<Json<Value>> {
    s.allow(&c, "cairn:PitrDiff", Some(&arn::bucket(&q.bucket)))?;
    parse_ts(&q.from)?;
    if let Some(t) = &q.to {
        parse_ts(t)?;
    }
    Ok(Json(json!({ "items": s.engine.pitr_diff(q).await? })))
}

async fn not_found() -> AdminError {
    AdminError::not_found("no such admin endpoint")
}

// ---------------------------------------------------------------- middleware

fn new_request_id() -> String {
    uuid::Uuid::now_v7().simple().to_string()
}

async fn authenticate(State(s): S, req: Request, next: Next) -> Response {
    let rid = new_request_id();
    let mut resp = REQUEST_ID
        .scope(rid.clone(), async move {
            match auth_inner(&s, req).await {
                Ok(req) => next.run(req).await,
                Err(e) => e.into_response(),
            }
        })
        .await;
    if let Ok(v) = rid.parse() {
        resp.headers_mut().insert(REQUEST_ID_HEADER, v);
    }
    resp
}

async fn auth_inner(s: &AdminState, req: Request) -> R<Request> {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_BODY).await.map_err(|_| {
        AdminError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "PayloadTooLarge",
            format!("request body exceeds {MAX_BODY} bytes"),
        )
    })?;
    let (principal, _ak) =
        cairn_auth::sts::authenticate(&s.store, &parts.method, &parts.uri, &parts.headers, &bytes)
            .await
            .map_err(|e| {
                let status = if e.status.is_server_error() {
                    e.status
                } else {
                    StatusCode::UNAUTHORIZED
                };
                AdminError::new(status, e.code, e.message)
            })?;
    let mut context = ConditionContext::new();
    let meta = parts.extensions.get::<RequestMeta>();
    if let Some(ip) = meta.and_then(|m| m.source_ip) {
        context.insert("aws:SourceIp", ip.to_string());
    }
    context.insert(
        "aws:SecureTransport",
        meta.is_some_and(|m| m.secure).to_string(),
    );
    let mut req = Request::from_parts(parts, axum::body::Body::from(bytes));
    req.extensions_mut().insert(Caller { principal, context });
    Ok(req)
}

async fn authorize_extra(
    State((s, action)): State<(AdminState, &'static str)>,
    req: Request,
    next: Next,
) -> Response {
    let Some(c) = req.extensions().get::<Caller>().cloned() else {
        return AdminError::new(
            StatusCode::UNAUTHORIZED,
            "AccessDenied",
            "not authenticated",
        )
        .into_response();
    };
    match s.allow(&c, action, None) {
        Ok(()) => next.run(req).await,
        Err(e) => e.into_response(),
    }
}

/// The admin router; mount at the server root (paths already start with `/_cairn/v1`).
pub fn router(state: AdminState) -> Router {
    router_with_extra(state, None, "cairn:GetServerInfo")
}

/// [`router`] plus `extra` routes (paths relative to `/_cairn/v1`, e.g. `/events`) behind the
/// same SigV4 authentication, each request authorised for `action` on the server ARN. Used by
/// the server to mount the SSE event stream (`cairn:SubscribeEvents`).
pub fn router_with_extra(state: AdminState, extra: Option<Router>, action: &'static str) -> Router {
    let extra = extra
        .map(|r| {
            r.route_layer(axum::middleware::from_fn_with_state(
                (state.clone(), action),
                authorize_extra,
            ))
        })
        .unwrap_or_default();
    let v1 = Router::new()
        .route("/whoami", get(whoami))
        .route("/info", get(server_info))
        .route("/users", get(list_users).post(create_user))
        .route("/users/{user}", get(get_user).delete(delete_user))
        .route("/users/{user}/enable", post(enable_user))
        .route("/users/{user}/disable", post(disable_user))
        .route(
            "/users/{user}/policies/{policy}",
            put(put_user_policy).delete(delete_user_policy),
        )
        .route(
            "/users/{user}/attached-policies/{policy}",
            put(attach_user_policy).delete(detach_user_policy),
        )
        .route(
            "/users/{user}/access-keys",
            get(list_user_keys).post(create_key),
        )
        .route("/access-keys", get(list_keys))
        .route("/access-keys/{id}", axum::routing::delete(delete_key))
        .route("/access-keys/{id}/activate", post(activate_key))
        .route("/access-keys/{id}/deactivate", post(deactivate_key))
        .route("/root/rotate", post(rotate_root))
        .route("/service-accounts", post(create_service_account))
        .route("/groups", get(list_groups).post(create_group))
        .route("/groups/{group}", get(get_group).delete(delete_group))
        .route(
            "/groups/{group}/members/{user}",
            put(add_member).delete(remove_member),
        )
        .route(
            "/groups/{group}/policies/{policy}",
            put(put_group_policy).delete(delete_group_policy),
        )
        .route(
            "/groups/{group}/attached-policies/{policy}",
            put(attach_group_policy).delete(detach_group_policy),
        )
        .route("/policies", get(list_policies).post(create_policy))
        .route(
            "/policies/{policy}",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
        .route("/roles", get(list_roles).post(create_role))
        .route("/roles/{role}", get(get_role).delete(delete_role))
        .route("/roles/{role}/trust-policy", put(update_trust))
        .route(
            "/roles/{role}/policies/{policy}",
            put(put_role_policy).delete(delete_role_policy),
        )
        .route(
            "/roles/{role}/attached-policies/{policy}",
            put(attach_role_policy).delete(detach_role_policy),
        )
        .route("/sessions", get(list_sessions))
        .route("/sessions/purge-expired", post(purge_sessions))
        .route("/sessions/{id}", axum::routing::delete(revoke_session))
        .route("/buckets", get(list_buckets))
        .route("/buckets/{bucket}", get(get_bucket))
        .route("/buckets/{bucket}/quota", put(set_quota))
        .route(
            "/buckets/{bucket}/retention",
            get(get_retention).put(set_retention),
        )
        .route("/trash", get(list_trash))
        .route("/trash/restore", post(restore))
        .route("/trash/restore-bucket", post(restore_bucket))
        .route("/trash/purge", post(purge))
        .route("/pitr/restore", post(pitr_restore))
        .route("/pitr/diff", get(pitr_diff))
        .fallback(not_found)
        .method_not_allowed_fallback(|| async {
            AdminError::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "method not allowed",
            )
        })
        .with_state(state.clone())
        .merge(extra);
    // The auth layer sits outside `nest` so it sees the full path that the client signed.
    Router::new()
        .nest(PREFIX, v1)
        .layer(axum::middleware::from_fn_with_state(state, authenticate))
}
