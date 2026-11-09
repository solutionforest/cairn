//! Binding MCP sessions to Tidemark credentials: fixed credentials (stdio) re-verified per call,
//! and per-request HTTP authentication (bearer `ak:secret[:token]` or SigV4).

use crate::{MCP_PATH, McpError, McpState, tools::TidemarkMcp};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http::{HeaderValue, StatusCode, header};
use http_body_util::BodyExt;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
use std::sync::Arc;
use tidemark_auth::{Principal, RequestMeta, SecretString};

/// The authenticated caller of one MCP request.
#[derive(Debug, Clone)]
pub struct McpCaller {
    /// Resolved principal with its effective policies.
    pub principal: Principal,
    /// Access key id used.
    pub access_key_id: String,
    /// Connection facts (source IP, TLS).
    pub meta: RequestMeta,
}

/// Fixed credentials for a stdio session (zeroized on drop, never logged).
#[derive(Clone)]
pub struct StaticCredentials {
    /// Access key id.
    pub access_key_id: String,
    /// Secret access key.
    pub secret: SecretString,
    /// STS session token, for temporary credentials.
    pub session_token: Option<SecretString>,
}

impl std::fmt::Debug for StaticCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticCredentials")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

impl StaticCredentials {
    /// Credentials from values.
    pub fn new(access_key_id: &str, secret: &str, session_token: Option<&str>) -> Self {
        Self {
            access_key_id: access_key_id.to_string(),
            secret: SecretString::new(secret),
            session_token: session_token.map(SecretString::new),
        }
    }

    /// `TIDEMARK_ACCESS_KEY_ID`, `TIDEMARK_SECRET_ACCESS_KEY`, optional `TIDEMARK_SESSION_TOKEN`.
    pub fn from_env() -> Result<Self, McpError> {
        let get = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let ak = get("TIDEMARK_ACCESS_KEY_ID")
            .ok_or_else(|| McpError::Credentials("TIDEMARK_ACCESS_KEY_ID is not set".into()))?;
        let sk = get("TIDEMARK_SECRET_ACCESS_KEY")
            .ok_or_else(|| McpError::Credentials("TIDEMARK_SECRET_ACCESS_KEY is not set".into()))?;
        let sk = SecretString::new(sk);
        let tok = get("TIDEMARK_SESSION_TOKEN").map(SecretString::new);
        Ok(Self {
            access_key_id: ak,
            secret: sk,
            session_token: tok,
        })
    }

    /// Resolve to a caller, or `None` if the key is unknown/expired/revoked or a secret or
    /// token does not match.
    pub(crate) async fn resolve(&self, st: &McpState) -> Result<Option<McpCaller>, McpError> {
        let c = st
            .store
            .authenticate_secret(
                &self.access_key_id,
                self.secret.expose(),
                self.session_token.as_ref().map(SecretString::expose),
            )
            .await?;
        Ok(c.map(|c| McpCaller {
            principal: c.principal,
            access_key_id: c.access_key_id,
            meta: RequestMeta {
                source_ip: None,
                secure: true,
            },
        }))
    }
}

fn unauthorized(msg: &str) -> Response {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": null,
        "error": { "code": -32001, "message": msg },
    });
    let mut r = (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response();
    r.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer realm=\"tidemark-mcp\""),
    );
    r
}

async fn authenticate(State(st): State<McpState>, req: Request, next: Next) -> Response {
    let meta = req
        .extensions()
        .get::<RequestMeta>()
        .cloned()
        .unwrap_or_default();
    let authz = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let (req, caller) = match authz.as_deref() {
        Some(a) if a.len() > 7 && a[..7].eq_ignore_ascii_case("bearer ") => {
            let mut it = a[7..].trim().splitn(3, ':');
            let (Some(ak), Some(sk)) = (it.next(), it.next()) else {
                return unauthorized(
                    "malformed bearer credentials; expected <access-key-id>:<secret>[:<session-token>]",
                );
            };
            let sk = SecretString::new(sk);
            let tok = it.next().map(SecretString::new);
            match st
                .store
                .authenticate_secret(ak, sk.expose(), tok.as_ref().map(SecretString::expose))
                .await
            {
                Ok(Some(c)) => (req, (c.principal, c.access_key_id)),
                Ok(None) => return unauthorized("invalid credentials"),
                Err(e) => {
                    tracing::error!(error = %e, "mcp auth backend failure");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response();
                }
            }
        }
        Some(a) if a.starts_with("AWS4-HMAC-SHA256") => {
            let (parts, body) = req.into_parts();
            let bytes = match http_body_util::Limited::new(body, st.config.max_http_body)
                .collect()
                .await
            {
                Ok(b) => b.to_bytes(),
                Err(_) => {
                    return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large")
                        .into_response();
                }
            };
            match tidemark_auth::sts::authenticate(
                &st.store,
                &parts.method,
                &parts.uri,
                &parts.headers,
                &bytes,
            )
            .await
            {
                Ok((p, ak)) => (Request::from_parts(parts, Body::from(bytes)), (p, ak)),
                Err(e) => {
                    tracing::info!(code = e.code, "mcp sigv4 authentication failed");
                    return unauthorized(&e.message);
                }
            }
        }
        _ => return unauthorized("authentication required"),
    };
    let mut req = req;
    req.extensions_mut().insert(McpCaller {
        principal: caller.0,
        access_key_id: caller.1,
        meta,
    });
    next.run(req).await
}

pub(crate) fn http_router(state: McpState) -> axum::Router {
    let mut cfg = StreamableHttpServerConfig::default()
        .with_max_request_body_bytes(state.config.max_http_body);
    cfg = if state.config.allowed_hosts.is_empty() {
        cfg.disable_allowed_hosts()
    } else {
        cfg.with_allowed_hosts(state.config.allowed_hosts.clone())
    };
    let st = state.clone();
    let svc = StreamableHttpService::new(
        move || Ok(TidemarkMcp::http(st.clone())),
        Arc::new(LocalSessionManager::default()),
        cfg,
    );
    axum::Router::new()
        .route_service(MCP_PATH, svc)
        .layer(axum::middleware::from_fn_with_state(state, authenticate))
}
