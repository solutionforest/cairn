//! Bridge from `s3s` to Tidemark IAM: [`TidemarkS3Auth`] (secret lookup for SigV4 verification) and
//! [`TidemarkS3Access`] (per-request policy evaluation).
//!
//! Wiring: `builder.set_auth(TidemarkS3Auth::new(store.clone()))` and
//! `builder.set_access(TidemarkS3Access::new(store, bucket_policies))`. Insert a [`RequestMeta`]
//! into each HTTP request's extensions (source IP, TLS) before it reaches s3s; after the check
//! the resolved [`AuthenticatedCaller`] is available in `S3Request::extensions`.

use crate::actions;
use crate::arn;
use crate::bucket_policy::BucketAuthzSource;
use crate::engine::{AuthzEngine, BucketAuthz};
use crate::eval::{ConditionContext, Decision};
use crate::principal::Principal;
use crate::sigv4::percent_decode;
use crate::store::CredentialStore;
use http::{HeaderMap, Uri};
use s3s::access::{S3Access, S3AccessContext};
use s3s::auth::{S3Auth, SecretKey};
use s3s::dto::{CopySource, DeleteObjectsInput};
use s3s::{S3Error, S3ErrorCode, S3Request, S3Result};
use std::net::IpAddr;
use std::sync::Arc;

/// Connection facts the HTTP layer knows and s3s does not; put it in request extensions.
#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    /// Client address (after trusted-proxy resolution).
    pub source_ip: Option<IpAddr>,
    /// True if the request arrived over TLS (or from a trusted TLS-terminating proxy).
    pub secure: bool,
}

/// The authenticated caller, stored in request extensions by [`TidemarkS3Access`].
#[derive(Debug, Clone)]
pub struct AuthenticatedCaller {
    /// `None` for anonymous requests.
    pub principal: Option<Principal>,
    /// Access key id used to sign, if any.
    pub access_key_id: Option<String>,
}

fn err(code: S3ErrorCode, msg: &str) -> S3Error {
    S3Error::with_message(code, msg.to_string())
}

fn denied() -> S3Error {
    err(S3ErrorCode::AccessDenied, "Access Denied")
}

fn internal(e: impl std::fmt::Display) -> S3Error {
    tracing::error!(error = %e, "auth backend failure");
    err(S3ErrorCode::InternalError, "internal error")
}

/// `S3Auth` over the [`CredentialStore`]: long-lived keys and STS sessions; unknown, inactive,
/// expired or orphaned keys are `InvalidAccessKeyId`.
#[derive(Debug, Clone)]
pub struct TidemarkS3Auth {
    store: Arc<CredentialStore>,
}

impl TidemarkS3Auth {
    /// New provider.
    pub fn new(store: Arc<CredentialStore>) -> Self {
        Self { store }
    }
}

#[async_trait::async_trait]
impl S3Auth for TidemarkS3Auth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        match self.store.lookup(access_key).await.map_err(internal)? {
            Some(c) => Ok(SecretKey::from(c.secret_key.expose())),
            None => Err(err(
                S3ErrorCode::InvalidAccessKeyId,
                "The AWS Access Key Id you provided does not exist in our records.",
            )),
        }
    }
}

/// Everything about one request the authoriser looks at (independent of s3s internals).
#[derive(Debug, Clone, Copy)]
pub struct S3RequestView<'a> {
    /// s3s operation name, e.g. `GetObject`.
    pub op: &'a str,
    /// Access key id of the verified signature (`None` = anonymous).
    pub access_key: Option<&'a str>,
    /// Bucket from the path.
    pub bucket: Option<&'a str>,
    /// Key from the path.
    pub key: Option<&'a str>,
    /// Request URI (query string is read for condition keys).
    pub uri: &'a Uri,
    /// Request headers.
    pub headers: &'a HeaderMap,
    /// Connection facts.
    pub meta: Option<&'a RequestMeta>,
}

fn query_pairs(uri: &Uri) -> Vec<(String, String)> {
    parse_qs(uri.query().unwrap_or(""))
}

fn parse_qs(qs: &str) -> Vec<(String, String)> {
    qs.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let d = |s: &str| {
                String::from_utf8_lossy(&percent_decode(&s.replace('+', " "))).into_owned()
            };
            (d(k), d(v))
        })
        .collect()
}

fn header<'h>(h: &'h HeaderMap, name: &str) -> Option<&'h str> {
    h.get(name).and_then(|v| v.to_str().ok())
}

fn query<'q>(q: &'q [(String, String)], name: &str) -> Option<&'q str> {
    q.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Canned ACLs that grant access beyond the owner.
const PUBLIC_ACLS: &[&str] = &["public-read", "public-read-write", "authenticated-read"];
const ALL_USERS: &str = "http://acs.amazonaws.com/groups/global/AllUsers";
const AUTH_USERS: &str = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";

/// True if the request headers try to set a public ACL (`BlockPublicAcls`).
fn sets_public_acl(h: &HeaderMap) -> bool {
    if header(h, "x-amz-acl").is_some_and(|a| PUBLIC_ACLS.contains(&a.trim())) {
        return true;
    }
    h.iter().any(|(n, v)| {
        n.as_str().starts_with("x-amz-grant-")
            && v.to_str()
                .is_ok_and(|v| v.contains(ALL_USERS) || v.contains(AUTH_USERS))
    })
}

const ACL_OPS: &[&str] = &[
    "PutObject",
    "CopyObject",
    "CreateMultipartUpload",
    "PutObjectAcl",
    "PutBucketAcl",
    "CreateBucket",
    "PostObject",
];

/// Build the request condition context (principal and time keys are added by the engine).
pub fn condition_context(v: &S3RequestView<'_>) -> ConditionContext {
    let mut c = ConditionContext::new();
    let q = query_pairs(v.uri);
    let h = v.headers;
    if let Some(ip) = v.meta.and_then(|m| m.source_ip) {
        c.insert("aws:SourceIp", ip.to_string());
    }
    let secure = v.meta.map(|m| m.secure).unwrap_or(false) || v.uri.scheme_str() == Some("https");
    c.insert("aws:SecureTransport", secure.to_string());
    if let Some(ua) = header(h, "user-agent") {
        c.insert("aws:UserAgent", ua);
    }
    if let Some(r) = header(h, "referer") {
        c.insert("aws:Referer", r);
    }
    for (cond, qname) in [
        ("s3:prefix", "prefix"),
        ("s3:delimiter", "delimiter"),
        ("s3:max-keys", "max-keys"),
        ("s3:VersionId", "versionId"),
    ] {
        if let Some(val) = query(&q, qname) {
            c.insert(cond, val);
        }
    }
    if matches!(v.op, "ListObjects" | "ListObjectsV2" | "ListObjectVersions")
        && !c.contains("s3:prefix")
    {
        c.insert("s3:prefix", "");
    }
    for (cond, hname) in [
        ("s3:x-amz-acl", "x-amz-acl"),
        (
            "s3:x-amz-server-side-encryption",
            "x-amz-server-side-encryption",
        ),
        (
            "s3:x-amz-server-side-encryption-aws-kms-key-id",
            "x-amz-server-side-encryption-aws-kms-key-id",
        ),
        ("s3:x-amz-copy-source", "x-amz-copy-source"),
        ("s3:x-amz-metadata-directive", "x-amz-metadata-directive"),
        ("s3:x-amz-storage-class", "x-amz-storage-class"),
        ("s3:x-amz-content-sha256", "x-amz-content-sha256"),
        ("s3:object-lock-mode", "x-amz-object-lock-mode"),
        (
            "s3:object-lock-retain-until-date",
            "x-amz-object-lock-retain-until-date",
        ),
        ("s3:object-lock-legal-hold", "x-amz-object-lock-legal-hold"),
        ("tidemark:AsOf", "x-tidemark-as-of"),
    ] {
        if let Some(val) = header(h, hname) {
            c.insert(cond, val.trim());
        }
    }
    if let Some(t) = header(h, "x-amz-tagging") {
        let tags = parse_qs(t);
        for (k, val) in &tags {
            c.insert(&format!("s3:RequestObjectTag/{k}"), val.as_str());
        }
        let keys: Vec<String> = tags.into_iter().map(|(k, _)| k).collect();
        if !keys.is_empty() {
            c.set("s3:RequestObjectTagKeys", keys);
        }
    }
    if v.access_key.is_some() {
        let presigned = query(&q, "X-Amz-Signature").is_some();
        c.insert(
            "s3:authType",
            if presigned {
                "REST-QUERY-STRING"
            } else {
                "REST-HEADER"
            },
        );
        let alg = query(&q, "X-Amz-Algorithm")
            .or_else(|| header(h, "authorization").and_then(|a| a.split_whitespace().next()));
        if let Some(a) = alg {
            c.insert(
                "s3:signatureversion",
                if a.starts_with("AWS4") {
                    "AWS4-HMAC-SHA256"
                } else {
                    "AWS"
                },
            );
        }
        let date = query(&q, "X-Amz-Date").or_else(|| header(h, "x-amz-date"));
        if let Some(ts) = date.and_then(|d| crate::sigv4::parse_amz_date(d).ok()) {
            let age = (jiff::Timestamp::now().as_millisecond() as i128) - ts.0 / 1_000_000;
            c.insert("s3:signatureAge", age.max(0).to_string());
        }
    }
    c
}

/// Resource ARN for an operation on `bucket`/`key`.
pub fn resource_arn(op: &str, bucket: Option<&str>, key: Option<&str>) -> String {
    match (bucket, key) {
        (Some(b), Some(k)) if !k.is_empty() => arn::object(b, k),
        (Some(b), _) => arn::bucket(b),
        _ if op == "ListBuckets" => "arn:aws:s3:::*".to_string(),
        _ => "*".to_string(),
    }
}

/// `S3Access` that evaluates identity ∪ group ∪ bucket policy ∪ PublicAccessBlock for every
/// request, explicit deny winning; anonymous callers are allowed only by bucket policy.
#[derive(Clone)]
pub struct TidemarkS3Access {
    store: Arc<CredentialStore>,
    buckets: Arc<dyn BucketAuthzSource>,
    engine: AuthzEngine,
}

impl std::fmt::Debug for TidemarkS3Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TidemarkS3Access")
    }
}

impl TidemarkS3Access {
    /// New access checker.
    pub fn new(store: Arc<CredentialStore>, buckets: Arc<dyn BucketAuthzSource>) -> Self {
        Self {
            store,
            buckets,
            engine: AuthzEngine::new(),
        }
    }

    /// Replace the authoriser (tests inject a clock).
    pub fn with_engine(mut self, engine: AuthzEngine) -> Self {
        self.engine = engine;
        self
    }

    /// Resolve the principal behind `access_key` and check the session token, if any.
    pub async fn resolve(
        &self,
        access_key: Option<&str>,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedCaller, S3Error> {
        let Some(ak) = access_key else {
            return Ok(AuthenticatedCaller {
                principal: None,
                access_key_id: None,
            });
        };
        let Some(cred) = self.store.lookup(ak).await.map_err(internal)? else {
            return Err(err(
                S3ErrorCode::ExpiredToken,
                "The provided token has expired or the access key is no longer valid.",
            ));
        };
        let q = query_pairs(uri);
        let presented =
            header(headers, "x-amz-security-token").or_else(|| query(&q, "X-Amz-Security-Token"));
        if !cred.verify_session_token(presented) {
            return Err(err(
                S3ErrorCode::InvalidToken,
                "The provided token is malformed or otherwise invalid.",
            ));
        }
        Ok(AuthenticatedCaller {
            principal: Some(cred.principal),
            access_key_id: Some(cred.access_key_id),
        })
    }

    async fn bucket_authz(&self, bucket: Option<&str>) -> Result<Option<BucketAuthz>, S3Error> {
        match bucket {
            Some(b) => self.buckets.bucket_authz(b).await.map_err(internal),
            None => Ok(None),
        }
    }

    /// Authorise one IAM `action` on `resource` for an already resolved caller.
    pub async fn authorize_action(
        &self,
        caller: &AuthenticatedCaller,
        action: &str,
        bucket: Option<&str>,
        resource: &str,
        ctx: &ConditionContext,
    ) -> Result<(), S3Error> {
        let ba = self.bucket_authz(bucket).await?;
        let d = self.engine.authorize(
            caller.principal.as_ref(),
            action,
            resource,
            ctx,
            ba.as_ref(),
        );
        if d == Decision::Allow {
            Ok(())
        } else {
            tracing::debug!(
                principal = caller.principal.as_ref().map(|p| p.id.as_str()).unwrap_or("anonymous"),
                action, resource, decision = ?d, "access denied"
            );
            Err(denied())
        }
    }

    /// Full check for one request: resolve the caller, map the operation to an IAM action and
    /// resource, apply PublicAccessBlock, evaluate, require `tidemark:TimeTravel` on the same
    /// resource for `x-tidemark-as-of` reads, and authorise the copy source if present.
    /// `DeleteObjects` is only resolved here; its keys are checked in the per-operation hook.
    pub async fn authorize(&self, v: &S3RequestView<'_>) -> Result<AuthenticatedCaller, S3Error> {
        let caller = self.resolve(v.access_key, v.uri, v.headers).await?;
        if v.op == "DeleteObjects" {
            return Ok(caller);
        }
        let q = query_pairs(v.uri);
        let has_version = query(&q, "versionId").is_some();
        let Some(action) = actions::for_s3_operation_versioned(v.op, has_version) else {
            if caller.principal.as_ref().is_some_and(|p| p.is_root) {
                return Ok(caller);
            }
            return Err(denied());
        };
        let ctx = condition_context(v);
        let ba = self.bucket_authz(v.bucket).await?;
        if ACL_OPS.contains(&v.op)
            && ba
                .as_ref()
                .is_some_and(|b| b.public_access_block.block_public_acls)
            && sets_public_acl(v.headers)
        {
            return Err(denied());
        }
        let resource = resource_arn(v.op, v.bucket, v.key);
        let d = self.engine.authorize(
            caller.principal.as_ref(),
            action,
            &resource,
            &ctx,
            ba.as_ref(),
        );
        if d != Decision::Allow {
            tracing::debug!(
                principal = caller.principal.as_ref().map(|p| p.id.as_str()).unwrap_or("anonymous"),
                action, resource, decision = ?d, "access denied"
            );
            return Err(denied());
        }
        if matches!(
            v.op,
            "GetObject" | "HeadObject" | "ListObjects" | "ListObjectsV2"
        ) && !has_version
            && header(v.headers, "x-tidemark-as-of").is_some()
        {
            self.authorize_action(&caller, "tidemark:TimeTravel", v.bucket, &resource, &ctx)
                .await?;
        }
        if matches!(v.op, "CopyObject" | "UploadPartCopy")
            && let Some(src) = header(v.headers, "x-amz-copy-source")
        {
            let Ok(CopySource::Bucket {
                bucket,
                key,
                version_id,
            }) = CopySource::parse(src)
            else {
                return Err(err(
                    S3ErrorCode::InvalidArgument,
                    "invalid x-amz-copy-source",
                ));
            };
            let act = if version_id.is_some() {
                "s3:GetObjectVersion"
            } else {
                "s3:GetObject"
            };
            self.authorize_action(
                &caller,
                act,
                Some(&bucket),
                &arn::object(&bucket, &key),
                &ctx,
            )
            .await?;
        }
        Ok(caller)
    }
}

#[async_trait::async_trait]
impl S3Access for TidemarkS3Access {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        let meta = cx.extensions_mut().get::<RequestMeta>().cloned();
        let path = cx.s3_path();
        let view = S3RequestView {
            op: cx.s3_op().name(),
            access_key: cx.credentials().map(|c| c.access_key.as_str()),
            bucket: path.get_bucket_name(),
            key: path.get_object_key(),
            uri: cx.uri(),
            headers: cx.headers(),
            meta: meta.as_ref(),
        };
        let caller = self.authorize(&view).await?;
        cx.extensions_mut().insert(caller);
        Ok(())
    }

    async fn delete_objects(&self, req: &mut S3Request<DeleteObjectsInput>) -> S3Result<()> {
        let caller = match req.extensions.get::<AuthenticatedCaller>() {
            Some(c) => c.clone(),
            None => {
                self.resolve(
                    req.credentials.as_ref().map(|c| c.access_key.as_str()),
                    &req.uri,
                    &req.headers,
                )
                .await?
            }
        };
        let meta = req.extensions.get::<RequestMeta>();
        let bucket = req.input.bucket.as_str();
        let view = S3RequestView {
            op: "DeleteObjects",
            access_key: caller.access_key_id.as_deref(),
            bucket: Some(bucket),
            key: None,
            uri: &req.uri,
            headers: &req.headers,
            meta,
        };
        let ctx = condition_context(&view);
        for o in &req.input.delete.objects {
            let act = if o.version_id.is_some() {
                "s3:DeleteObjectVersion"
            } else {
                "s3:DeleteObject"
            };
            self.authorize_action(
                &caller,
                act,
                Some(bucket),
                &arn::object(bucket, &o.key),
                &ctx,
            )
            .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
