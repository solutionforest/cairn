#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Tidemark MCP server (DESIGN §11.1): object-store tools for AI agents over the Model Context
//! Protocol, built on `rmcp`.
//!
//! Every tool call is authorised through `tidemark-auth` exactly like the equivalent S3 request
//! (same IAM action and resource ARN, bucket policy and PublicAccessBlock included) with the
//! extra condition key `tidemark:McpTool` = tool name, so ordinary policies can restrict tools.
//!
//! Transports:
//! - stdio: [`serve_stdio`] (credentials from `TIDEMARK_ACCESS_KEY_ID` /
//!   `TIDEMARK_SECRET_ACCESS_KEY` / optional `TIDEMARK_SESSION_TOKEN`);
//! - streamable HTTP: [`http_router`], an axum router serving [`MCP_PATH`]; every HTTP request
//!   carries `Authorization: Bearer <ak>:<secret>[:<session-token>]` or an AWS SigV4
//!   signature (see `docs/MCP.md`).

mod auth;
mod tools;

pub use auth::{McpCaller, StaticCredentials};
pub use tools::TidemarkMcp;

use rmcp::ServiceExt;
use std::sync::Arc;
use tidemark_auth::{BucketAuthzSource, CredentialStore, TidemarkS3Access};
use tidemark_engine::TidemarkEngine;

/// Path [`http_router`] serves (merge the router at the server root).
pub const MCP_PATH: &str = "/_tidemark/mcp";

/// Limits and transport options.
#[derive(Debug, Clone)]
pub struct McpConfig {
    /// Largest object body `get_object` returns inline; larger objects are truncated.
    pub max_get_bytes: u64,
    /// Largest body `put_object` accepts (decoded bytes).
    pub max_put_bytes: usize,
    /// Most keys `search` examines per call.
    pub max_search_scan: usize,
    /// Most changes `pitr_restore` applies per call.
    pub max_pitr_changes: usize,
    /// Largest HTTP request body (JSON-RPC message).
    pub max_http_body: usize,
    /// If non-empty, the HTTP transport only accepts these `Host` values (DNS-rebinding
    /// guard). Empty by default: every request must carry credentials anyway.
    pub allowed_hosts: Vec<String>,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            max_get_bytes: 1024 * 1024,
            max_put_bytes: 4 * 1024 * 1024,
            max_search_scan: 10_000,
            max_pitr_changes: 1_000,
            max_http_body: 8 * 1024 * 1024,
            allowed_hosts: Vec::new(),
        }
    }
}

/// Shared state: the engine, the credential store and the bucket-policy source.
#[derive(Clone)]
pub struct McpState {
    pub(crate) engine: TidemarkEngine,
    pub(crate) store: Arc<CredentialStore>,
    pub(crate) access: TidemarkS3Access,
    pub(crate) config: Arc<McpConfig>,
}

impl std::fmt::Debug for McpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpState")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl McpState {
    /// State over an engine, the credential store and bucket policies (pass the server's
    /// `BucketPolicyStore`).
    pub fn new(
        engine: TidemarkEngine,
        store: Arc<CredentialStore>,
        buckets: Arc<dyn BucketAuthzSource>,
    ) -> Self {
        Self {
            access: TidemarkS3Access::new(store.clone(), buckets),
            engine,
            store,
            config: Arc::new(McpConfig::default()),
        }
    }

    /// Replace the limits.
    pub fn with_config(mut self, config: McpConfig) -> Self {
        self.config = Arc::new(config);
        self
    }
}

/// Errors starting an MCP transport.
#[derive(Debug, thiserror::Error)]
pub enum McpError {
    /// Missing or invalid credentials for the stdio transport.
    #[error("{0}")]
    Credentials(String),
    /// Credential store failure.
    #[error("credential store: {0}")]
    Auth(#[from] tidemark_auth::AuthError),
    /// MCP protocol / transport failure.
    #[error("mcp transport: {0}")]
    Transport(String),
}

/// Serve MCP over stdin/stdout until the client disconnects. Credentials come from
/// `TIDEMARK_ACCESS_KEY_ID`, `TIDEMARK_SECRET_ACCESS_KEY` and (for STS credentials)
/// `TIDEMARK_SESSION_TOKEN`; they are verified at startup and again on every tool call.
pub async fn serve_stdio(state: McpState) -> Result<(), McpError> {
    let creds = StaticCredentials::from_env()?;
    serve_transport(state, creds, rmcp::transport::stdio()).await
}

/// Serve MCP with fixed credentials over any rmcp transport (stdio, a duplex pipe in tests).
pub async fn serve_transport<T, E, A>(
    state: McpState,
    creds: StaticCredentials,
    transport: T,
) -> Result<(), McpError>
where
    T: rmcp::transport::IntoTransport<rmcp::RoleServer, E, A>,
    E: std::error::Error + Send + Sync + 'static,
{
    let server = TidemarkMcp::with_credentials(state, creds).await?;
    let running = server
        .serve(transport)
        .await
        .map_err(|e| McpError::Transport(e.to_string()))?;
    running
        .waiting()
        .await
        .map_err(|e| McpError::Transport(e.to_string()))?;
    Ok(())
}

/// Streamable-HTTP MCP endpoint at [`MCP_PATH`] (POST/GET/DELETE), authenticating every
/// request. Merge into the server router: `app.merge(tidemark_mcp::http_router(state))`. Insert
/// `tidemark_auth::RequestMeta` into request extensions upstream for `aws:SourceIp` /
/// `aws:SecureTransport`.
pub fn http_router(state: McpState) -> axum::Router {
    auth::http_router(state)
}
