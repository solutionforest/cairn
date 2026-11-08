//! STS HTTP endpoint: `AssumeRole`, `GetSessionToken`, `GetCallerIdentity` (query API,
//! `Version=2011-06-15`) over `POST /` (form body) and `GET /?Action=…`, SigV4-authenticated;
//! plus the unsigned `AssumeRoleWithWebIdentity` (OIDC federation, enabled with
//! [`StsState::with_oidc`]).
//!
//! Mount with `cairn_auth::sts::router(StsState::new(store))`; route requests for which
//! [`is_sts_request`] is true to it before they reach s3s.

use crate::error::AuthError;
use crate::eval::ConditionContext;
use crate::oidc::{OidcError, OidcVerifier};
use crate::principal::Principal;
use crate::s3s_bridge::RequestMeta;
use crate::sigv4::{self, HttpParts, SigV4Error};
use crate::store::{AssumeRoleRequest, CredentialStore, StsCredentials};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, Method, StatusCode, Uri, header};
use std::sync::Arc;
use std::time::Duration;

/// STS API version accepted.
pub const STS_VERSION: &str = "2011-06-15";
const XMLNS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";
/// Largest accepted STS request body (session policies are ≤ 2 KiB in AWS; we allow 64 KiB).
pub const MAX_BODY: usize = 64 * 1024;

/// Shared state of the STS router.
#[derive(Clone)]
pub struct StsState {
    store: Arc<CredentialStore>,
    oidc: Option<Arc<OidcVerifier>>,
}

impl std::fmt::Debug for StsState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StsState")
    }
}

impl StsState {
    /// State over a credential store.
    pub fn new(store: Arc<CredentialStore>) -> Self {
        Self { store, oidc: None }
    }

    /// Enable `AssumeRoleWithWebIdentity` with these trusted identity providers.
    pub fn with_oidc(mut self, verifier: Arc<OidcVerifier>) -> Self {
        self.oidc = Some(verifier);
        self
    }
}

/// The STS router (`GET /` and `POST /`).
pub fn router(state: StsState) -> Router {
    Router::new()
        .route("/", axum::routing::get(handle).post(handle))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .with_state(state)
}

fn form_pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let d = |x: &str| {
                String::from_utf8_lossy(&sigv4::percent_decode(&x.replace('+', " "))).into_owned()
            };
            (d(k), d(v))
        })
        .collect()
}

fn is_form(h: &HeaderMap) -> bool {
    h.get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/x-www-form-urlencoded"))
}

/// True if this request is an STS query-API call: `GET /?Action=…` or a form-encoded
/// `POST /` (S3 has no operation on those).
pub fn is_sts_request(method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
    if uri.path() != "/" {
        return false;
    }
    let has_action = form_pairs(uri.query().unwrap_or(""))
        .iter()
        .any(|(k, _)| k == "Action");
    match *method {
        Method::GET => has_action,
        Method::POST => has_action || is_form(headers),
        _ => false,
    }
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&apos;"),
            c => o.push(c),
        }
    }
    o
}

fn request_id() -> String {
    crate::secret::generate_unique_id("REQ")
}

/// An STS error response (AWS query-API error shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StsError {
    /// HTTP status.
    pub status: StatusCode,
    /// AWS error code.
    pub code: &'static str,
    /// Message (never contains secrets).
    pub message: String,
}

impl StsError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
    fn render(&self, rid: &str) -> Response {
        let ty = if self.status.is_server_error() {
            "Receiver"
        } else {
            "Sender"
        };
        let body = format!(
            "<ErrorResponse xmlns=\"{XMLNS}\"><Error><Type>{ty}</Type><Code>{}</Code><Message>{}</Message></Error><RequestId>{rid}</RequestId></ErrorResponse>",
            self.code,
            esc(&self.message)
        );
        xml(self.status, rid, body)
    }
}

fn xml(status: StatusCode, rid: &str, body: String) -> Response {
    let mut r = (status, body).into_response();
    let h = r.headers_mut();
    h.insert(header::CONTENT_TYPE, "text/xml".parse().expect("static"));
    if let Ok(v) = rid.parse() {
        h.insert("x-amzn-requestid", v);
    }
    r
}

fn auth_error(e: AuthError) -> StsError {
    match e {
        AuthError::AccessDenied(m) => StsError::new(StatusCode::FORBIDDEN, "AccessDenied", m),
        AuthError::NotFound { kind: "role", name } => StsError::new(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            format!("not authorized to perform sts:AssumeRole on role {name}"),
        ),
        AuthError::Invalid(m) => StsError::new(StatusCode::BAD_REQUEST, "ValidationError", m),
        AuthError::Policy(p) => StsError::new(
            StatusCode::BAD_REQUEST,
            "MalformedPolicyDocument",
            p.to_string(),
        ),
        other => {
            tracing::error!(error = %other, "sts backend failure");
            StsError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalFailure",
                "internal error",
            )
        }
    }
}

fn sig_error(e: SigV4Error) -> StsError {
    match e {
        SigV4Error::Missing => StsError::new(
            StatusCode::FORBIDDEN,
            "MissingAuthenticationToken",
            "Request is missing Authentication Token",
        ),
        SigV4Error::Malformed(m) => {
            StsError::new(StatusCode::BAD_REQUEST, "IncompleteSignature", m)
        }
        SigV4Error::Skewed | SigV4Error::Expired => {
            StsError::new(StatusCode::FORBIDDEN, "RequestExpired", e.to_string())
        }
        SigV4Error::Mismatch => StsError::new(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match the signature you provided.",
        ),
    }
}

/// Authenticate a SigV4-signed HTTP request against the credential store: signature, clock
/// skew / presign expiry and session token. Shared by the STS and admin endpoints.
pub async fn authenticate(
    store: &CredentialStore,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(Principal, String), StsError> {
    let hs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect();
    let body_sha = sigv4::sha256_hex(body);
    let parts = HttpParts {
        method: method.as_str(),
        raw_path: uri.path(),
        raw_query: uri.query().unwrap_or(""),
        headers: &hs,
        body_sha256: &body_sha,
    };
    let auth = sigv4::parse(&parts).map_err(sig_error)?;
    let invalid = || {
        StsError::new(
            StatusCode::FORBIDDEN,
            "InvalidClientTokenId",
            "The security token included in the request is invalid.",
        )
    };
    let cred = store
        .lookup(&auth.access_key_id)
        .await
        .map_err(auth_error)?
        .ok_or_else(invalid)?;
    sigv4::verify(&parts, &auth, &cred.secret_key, store.now()).map_err(sig_error)?;
    if !cred.verify_session_token(auth.security_token.as_deref()) {
        return Err(invalid());
    }
    Ok((cred.principal, cred.access_key_id))
}

fn creds_xml(c: &StsCredentials) -> String {
    format!(
        "<Credentials><AccessKeyId>{}</AccessKeyId><SecretAccessKey>{}</SecretAccessKey><SessionToken>{}</SessionToken><Expiration>{}</Expiration></Credentials>",
        esc(&c.access_key_id),
        esc(c.secret_access_key.expose()),
        esc(c.session_token.expose()),
        c.expiration.to_rfc3339()
    )
}

fn duration(params: &[(String, String)], default: u64) -> Result<Duration, StsError> {
    match params.iter().find(|(k, _)| k == "DurationSeconds") {
        None => Ok(Duration::from_secs(default)),
        Some((_, v)) => v.parse::<u64>().map(Duration::from_secs).map_err(|_| {
            StsError::new(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                "DurationSeconds must be an integer",
            )
        }),
    }
}

async fn dispatch(
    st: &StsState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    meta: Option<&RequestMeta>,
    body: &Bytes,
    rid: &str,
) -> Result<String, StsError> {
    let mut params = form_pairs(uri.query().unwrap_or(""));
    if *method == Method::POST && is_form(headers) {
        let b = std::str::from_utf8(body).map_err(|_| {
            StsError::new(
                StatusCode::BAD_REQUEST,
                "MalformedInput",
                "body is not UTF-8",
            )
        })?;
        params.extend(form_pairs(b));
    }
    let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let action = get("Action").ok_or_else(|| {
        StsError::new(
            StatusCode::BAD_REQUEST,
            "MissingAction",
            "Action is required",
        )
    })?;
    if let Some(v) = get("Version")
        && v != STS_VERSION
    {
        return Err(StsError::new(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            format!("unsupported Version {v}"),
        ));
    }
    if action == "AssumeRoleWithWebIdentity" {
        return assume_role_with_web_identity(st, &params, meta, rid).await;
    }
    let (caller, _akid) = authenticate(&st.store, method, uri, headers, body).await?;
    let meta_xml = format!("<ResponseMetadata><RequestId>{rid}</RequestId></ResponseMetadata>");
    match action {
        "AssumeRole" => {
            let missing = |n: &str| {
                StsError::new(
                    StatusCode::BAD_REQUEST,
                    "MissingParameter",
                    format!("{n} is required"),
                )
            };
            let role = get("RoleArn").ok_or_else(|| missing("RoleArn"))?;
            let session_name = get("RoleSessionName").ok_or_else(|| missing("RoleSessionName"))?;
            let mut ctx = ConditionContext::new();
            if let Some(m) = meta {
                if let Some(ip) = m.source_ip {
                    ctx.insert("aws:SourceIp", ip.to_string());
                }
                ctx.insert("aws:SecureTransport", m.secure.to_string());
            }
            let c = st
                .store
                .assume_role(
                    &caller,
                    AssumeRoleRequest {
                        role,
                        session_name,
                        duration: duration(&params, 3600)?,
                        session_policy: get("Policy"),
                        context: &ctx,
                    },
                )
                .await
                .map_err(auth_error)?;
            Ok(format!(
                "<AssumeRoleResponse xmlns=\"{XMLNS}\"><AssumeRoleResult>{}<AssumedRoleUser><Arn>{}</Arn><AssumedRoleId>{}</AssumedRoleId></AssumedRoleUser><PackedPolicySize>0</PackedPolicySize></AssumeRoleResult>{meta_xml}</AssumeRoleResponse>",
                creds_xml(&c),
                esc(c.assumed_role_arn.as_deref().unwrap_or_default()),
                esc(c.assumed_role_id.as_deref().unwrap_or_default()),
            ))
        }
        "GetSessionToken" => {
            let c = st
                .store
                .get_session_token(&caller, duration(&params, 43200)?)
                .await
                .map_err(auth_error)?;
            Ok(format!(
                "<GetSessionTokenResponse xmlns=\"{XMLNS}\"><GetSessionTokenResult>{}</GetSessionTokenResult>{meta_xml}</GetSessionTokenResponse>",
                creds_xml(&c)
            ))
        }
        "GetCallerIdentity" => Ok(format!(
            "<GetCallerIdentityResponse xmlns=\"{XMLNS}\"><GetCallerIdentityResult><Arn>{}</Arn><UserId>{}</UserId><Account>{}</Account></GetCallerIdentityResult>{meta_xml}</GetCallerIdentityResponse>",
            esc(&caller.arn),
            esc(&caller.user_id),
            crate::types::ACCOUNT_ID
        )),
        other => Err(StsError::new(
            StatusCode::BAD_REQUEST,
            "InvalidAction",
            format!("unsupported action {other}"),
        )),
    }
}

fn oidc_error(e: OidcError) -> StsError {
    match e {
        OidcError::Expired => StsError::new(
            StatusCode::BAD_REQUEST,
            "ExpiredTokenException",
            e.to_string(),
        ),
        OidcError::Jwks(_) => StsError::new(
            StatusCode::BAD_REQUEST,
            "IDPCommunicationError",
            e.to_string(),
        ),
        OidcError::Config(_) => {
            tracing::error!(error = %e, "oidc configuration error");
            StsError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalFailure",
                "internal error",
            )
        }
        _ => StsError::new(
            StatusCode::BAD_REQUEST,
            "InvalidIdentityToken",
            e.to_string(),
        ),
    }
}

async fn assume_role_with_web_identity(
    st: &StsState,
    params: &[(String, String)],
    meta: Option<&RequestMeta>,
    rid: &str,
) -> Result<String, StsError> {
    let get = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    let missing = |n: &str| {
        StsError::new(
            StatusCode::BAD_REQUEST,
            "MissingParameter",
            format!("{n} is required"),
        )
    };
    let role = get("RoleArn").ok_or_else(|| missing("RoleArn"))?;
    let session_name = get("RoleSessionName").ok_or_else(|| missing("RoleSessionName"))?;
    let token = get("WebIdentityToken").ok_or_else(|| missing("WebIdentityToken"))?;
    let verifier = st
        .oidc
        .as_ref()
        .ok_or_else(|| oidc_error(OidcError::NotConfigured))?;
    let identity = verifier.verify(token).await.map_err(oidc_error)?;
    let mut ctx = ConditionContext::new();
    if let Some(m) = meta {
        if let Some(ip) = m.source_ip {
            ctx.insert("aws:SourceIp", ip.to_string());
        }
        ctx.insert("aws:SecureTransport", m.secure.to_string());
    }
    let c = st
        .store
        .assume_role_with_web_identity(
            &identity,
            AssumeRoleRequest {
                role,
                session_name,
                duration: duration(params, 3600)?,
                session_policy: get("Policy"),
                context: &ctx,
            },
        )
        .await
        .map_err(auth_error)?;
    let meta_xml = format!("<ResponseMetadata><RequestId>{rid}</RequestId></ResponseMetadata>");
    Ok(format!(
        "<AssumeRoleWithWebIdentityResponse xmlns=\"{XMLNS}\"><AssumeRoleWithWebIdentityResult>{}<SubjectFromWebIdentityToken>{}</SubjectFromWebIdentityToken><AssumedRoleUser><Arn>{}</Arn><AssumedRoleId>{}</AssumedRoleId></AssumedRoleUser><Provider>{}</Provider><Audience>{}</Audience><PackedPolicySize>0</PackedPolicySize></AssumeRoleWithWebIdentityResult>{meta_xml}</AssumeRoleWithWebIdentityResponse>",
        creds_xml(&c),
        esc(&identity.subject),
        esc(c.assumed_role_arn.as_deref().unwrap_or_default()),
        esc(c.assumed_role_id.as_deref().unwrap_or_default()),
        esc(&identity.provider),
        esc(identity.primary_audience()),
    ))
}

async fn handle(
    State(st): State<StsState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    ext: http::Extensions,
    body: Bytes,
) -> Response {
    let rid = request_id();
    let meta = ext.get::<RequestMeta>();
    match dispatch(&st, &method, &uri, &headers, meta, &body, &rid).await {
        Ok(b) => xml(StatusCode::OK, &rid, b),
        Err(e) => {
            tracing::info!(code = e.code, request_id = %rid, "sts request rejected");
            e.render(&rid)
        }
    }
}

#[cfg(test)]
mod tests;
