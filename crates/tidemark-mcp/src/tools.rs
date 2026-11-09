//! The MCP tool set (DESIGN §11.1). Each tool authorises the same IAM action and resource as
//! the equivalent S3 / admin operation, with `tidemark:McpTool` = tool name in the context.

use crate::auth::{McpCaller, StaticCredentials};
use crate::{McpError, McpState};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use futures::StreamExt;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, Implementation, ServerCapabilities, ServerConfig};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use tidemark_auth::{AuthenticatedCaller, ConditionContext, arn};
use tidemark_core::{PrincipalId, S3Error, Ts, VersionId};
use tidemark_engine::types::{
    CopyObjectReq, DiffKind, GetObjectReq, ListReq, ObjectMeta, PutObjectReq, RangeSpec,
    body_from_bytes,
};
use tidemark_meta::{VersionRecord, VersionState, Versioning};

type ToolResult = Result<CallToolResult, ErrorData>;

/// A tool-level failure, reported to the model as `isError: true` with a structured body.
struct Fail {
    code: &'static str,
    message: String,
}

impl Fail {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn denied() -> Self {
        Self::new("AccessDenied", "Access Denied")
    }
    fn invalid(m: impl Into<String>) -> Self {
        Self::new("InvalidArgument", m)
    }
}

impl From<S3Error> for Fail {
    fn from(e: S3Error) -> Self {
        Self {
            code: e.code.as_str(),
            message: e.message,
        }
    }
}

impl From<McpError> for Fail {
    fn from(e: McpError) -> Self {
        tracing::error!(error = %e, "mcp backend failure");
        Self::new("InternalError", "internal error")
    }
}

fn finish(r: Result<Value, Fail>) -> ToolResult {
    Ok(match r {
        Ok(v) => CallToolResult::structured(v),
        Err(f) => CallToolResult::structured_error(json!({"error": f.code, "message": f.message})),
    })
}

fn ts(s: &str, field: &str) -> Result<Ts, Fail> {
    Ts::parse(s).ok_or_else(|| Fail::invalid(format!("{field}: expected an RFC 3339 timestamp")))
}

fn vid(s: &str) -> Result<VersionId, Fail> {
    s.parse()
        .map_err(|_| Fail::invalid("version_id: expected a 40-hex Tidemark version id"))
}

fn display_vid(v: &VersionRecord) -> String {
    if v.is_null {
        "null".into()
    } else {
        v.version_id.to_string()
    }
}

fn version_json(v: &VersionRecord) -> Value {
    let mut o = json!({
        "key": v.key,
        "version_id": display_vid(v),
        "last_modified": v.created_at.to_rfc3339(),
        "delete_marker": v.is_delete_marker(),
    });
    if let Some(b) = v.body() {
        o["size"] = json!(b.size);
        o["etag"] = json!(format!("\"{}\"", b.etag));
        o["content_type"] = json!(b.content_type);
    }
    if let Some(at) = v.state.hidden_since() {
        o["hidden_at"] = json!(at.to_rfc3339());
        o["state"] = json!(match v.state {
            VersionState::Superseded { .. } => "superseded",
            _ => "soft_deleted",
        });
    }
    o
}

fn principal_id(c: &McpCaller) -> PrincipalId {
    PrincipalId(c.principal.id.as_str().to_string())
}

// ------------------------------------------------------------------ parameters

/// `list_buckets` takes no arguments.
#[derive(Debug, Deserialize, JsonSchema, Default)]
pub struct NoArgs {}

/// Arguments of `list_objects`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListObjectsArgs {
    /// Bucket name.
    pub bucket: String,
    /// Only keys starting with this prefix.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Group keys by this delimiter (usually `/`) into common prefixes.
    #[serde(default)]
    pub delimiter: Option<String>,
    /// Keys strictly after this one (pagination: pass the previous `next_start_after`).
    #[serde(default)]
    pub start_after: Option<String>,
    /// Page size, 1..=1000 (default 100).
    #[serde(default)]
    pub max_keys: Option<usize>,
    /// Time travel: list the bucket as it was at this RFC 3339 instant.
    #[serde(default)]
    pub as_of: Option<String>,
}

/// Arguments of `get_object`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetObjectArgs {
    /// Bucket name.
    pub bucket: String,
    /// Object key.
    pub key: String,
    /// Specific version id.
    #[serde(default)]
    pub version_id: Option<String>,
    /// Time travel: the object as it was at this RFC 3339 instant.
    #[serde(default)]
    pub as_of: Option<String>,
    /// Byte range `first-last` (inclusive) or `-N` (last N bytes).
    #[serde(default)]
    pub range: Option<String>,
    /// `text` (UTF-8, fails on binary), `base64`, or `auto` (default: text when valid UTF-8).
    #[serde(default)]
    pub mode: Option<String>,
}

/// Arguments of `head_object`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct HeadObjectArgs {
    /// Bucket name.
    pub bucket: String,
    /// Object key.
    pub key: String,
    /// Specific version id.
    #[serde(default)]
    pub version_id: Option<String>,
    /// Time travel instant (RFC 3339).
    #[serde(default)]
    pub as_of: Option<String>,
}

/// Arguments of `put_object`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PutObjectArgs {
    /// Bucket name.
    pub bucket: String,
    /// Object key.
    pub key: String,
    /// Body as UTF-8 text (exactly one of `content` / `content_base64`).
    #[serde(default)]
    pub content: Option<String>,
    /// Body as standard base64.
    #[serde(default)]
    pub content_base64: Option<String>,
    /// Content-Type (default `text/plain; charset=utf-8` for `content`,
    /// `application/octet-stream` for `content_base64`).
    #[serde(default)]
    pub content_type: Option<String>,
    /// User metadata (`x-amz-meta-*`).
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Object tags.
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
}

/// Arguments of `delete_object`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteObjectArgs {
    /// Bucket name.
    pub bucket: String,
    /// Object key.
    pub key: String,
    /// Delete this version (versioned buckets) instead of adding a delete marker.
    #[serde(default)]
    pub version_id: Option<String>,
}

/// Arguments of `copy_object`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CopyObjectArgs {
    /// Source bucket.
    pub source_bucket: String,
    /// Source key.
    pub source_key: String,
    /// Source version id.
    #[serde(default)]
    pub source_version_id: Option<String>,
    /// Destination bucket.
    pub bucket: String,
    /// Destination key.
    pub key: String,
}

/// Arguments of `search`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchArgs {
    /// Bucket name.
    pub bucket: String,
    /// Case-insensitive substring the key must contain.
    #[serde(default)]
    pub query: Option<String>,
    /// Only keys under this prefix.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Content-Type prefix, e.g. `text/` or `application/pdf`.
    #[serde(default)]
    pub content_type: Option<String>,
    /// Minimum size in bytes.
    #[serde(default)]
    pub min_size: Option<u64>,
    /// Maximum size in bytes.
    #[serde(default)]
    pub max_size: Option<u64>,
    /// Modified at or after this RFC 3339 instant.
    #[serde(default)]
    pub modified_after: Option<String>,
    /// Modified before this RFC 3339 instant.
    #[serde(default)]
    pub modified_before: Option<String>,
    /// Most results, 1..=500 (default 50).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Arguments of `trash_list`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TrashListArgs {
    /// Bucket name.
    pub bucket: String,
    /// Only keys under this prefix.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Most entries, 1..=1000 (default 100).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Arguments of `trash_restore`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TrashRestoreArgs {
    /// Bucket name.
    pub bucket: String,
    /// Object key.
    pub key: String,
    /// Hidden version to restore (default: the newest hidden version).
    #[serde(default)]
    pub version_id: Option<String>,
}

/// Arguments of `pitr_head_at`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PitrHeadAtArgs {
    /// Bucket name.
    pub bucket: String,
    /// Object key.
    pub key: String,
    /// RFC 3339 instant.
    pub at: String,
}

/// Arguments of `pitr_diff`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PitrDiffArgs {
    /// Bucket name.
    pub bucket: String,
    /// RFC 3339 instant to compare the current state with.
    pub at: String,
    /// Only keys under this prefix.
    #[serde(default)]
    pub prefix: Option<String>,
}

/// Arguments of `pitr_restore`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PitrRestoreArgs {
    /// Bucket name.
    pub bucket: String,
    /// RFC 3339 instant to restore to.
    pub at: String,
    /// Only keys under this prefix.
    #[serde(default)]
    pub prefix: Option<String>,
    /// Report the changes without applying them (default true).
    #[serde(default)]
    pub dry_run: Option<bool>,
    /// Must be true to apply (`dry_run: false`).
    #[serde(default)]
    pub confirm: bool,
}

/// Arguments of `bucket_info`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BucketArgs {
    /// Bucket name.
    pub bucket: String,
}

// ------------------------------------------------------------------ server

#[derive(Clone)]
enum Binding {
    /// HTTP: the caller is authenticated per request by the router middleware.
    PerRequest,
    /// stdio / in-process: fixed credentials, re-verified on every call.
    Fixed(Arc<StaticCredentials>),
}

/// The Tidemark MCP server handler.
#[derive(Clone)]
pub struct TidemarkMcp {
    state: McpState,
    binding: Binding,
    tool_router: ToolRouter<Self>,
}

impl std::fmt::Debug for TidemarkMcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TidemarkMcp")
    }
}

impl TidemarkMcp {
    /// Handler for the HTTP transport (caller from request extensions).
    pub(crate) fn http(state: McpState) -> Self {
        Self {
            state,
            binding: Binding::PerRequest,
            tool_router: Self::tool_router(),
        }
    }

    /// Handler bound to fixed credentials; fails if they do not authenticate now.
    pub async fn with_credentials(
        state: McpState,
        creds: StaticCredentials,
    ) -> Result<Self, McpError> {
        if creds.resolve(&state).await?.is_none() {
            return Err(McpError::Credentials(
                "the configured Tidemark credentials are invalid, expired or revoked".into(),
            ));
        }
        Ok(Self {
            state,
            binding: Binding::Fixed(Arc::new(creds)),
            tool_router: Self::tool_router(),
        })
    }

    /// Names of every tool this server exposes.
    pub fn tool_names() -> Vec<String> {
        Self::tool_router()
            .list_all()
            .into_iter()
            .map(|t| t.name.to_string())
            .collect()
    }

    async fn caller(&self, ctx: &RequestContext<RoleServer>) -> Result<McpCaller, Fail> {
        match &self.binding {
            Binding::Fixed(c) => c.resolve(&self.state).await?.ok_or_else(|| {
                Fail::new(
                    "InvalidAccessKeyId",
                    "the session's credentials are no longer valid",
                )
            }),
            Binding::PerRequest => ctx
                .extensions
                .get::<http::request::Parts>()
                .and_then(|p| p.extensions.get::<McpCaller>())
                .cloned()
                .ok_or_else(|| Fail::new("AccessDenied", "unauthenticated request")),
        }
    }

    /// Authorise `action` on `resource` for `tool`, like the equivalent S3 request.
    async fn allow(
        &self,
        c: &McpCaller,
        tool: &str,
        action: &str,
        bucket: Option<&str>,
        resource: &str,
        extra: &[(&str, String)],
    ) -> Result<(), Fail> {
        let mut ctx = ConditionContext::new();
        ctx.insert("tidemark:McpTool", tool);
        if let Some(ip) = c.meta.source_ip {
            ctx.insert("aws:SourceIp", ip.to_string());
        }
        ctx.insert("aws:SecureTransport", c.meta.secure.to_string());
        for (k, v) in extra {
            ctx.insert(k, v.clone());
        }
        let ac = AuthenticatedCaller {
            principal: Some(c.principal.clone()),
            access_key_id: Some(c.access_key_id.clone()),
        };
        self.state
            .access
            .authorize_action(&ac, action, bucket, resource, &ctx)
            .await
            .map_err(|_| {
                tracing::debug!(principal = %c.principal.id, tool, action, resource, "mcp tool denied");
                Fail::denied()
            })
    }

    async fn run<F, Fut>(&self, ctx: &RequestContext<RoleServer>, f: F) -> ToolResult
    where
        F: FnOnce(McpCaller) -> Fut,
        Fut: Future<Output = Result<Value, Fail>>,
    {
        let r = match self.caller(ctx).await {
            Ok(c) => f(c).await,
            Err(e) => Err(e),
        };
        finish(r)
    }
}

async fn read_body(res: tidemark_engine::types::GetObjectRes) -> Result<Vec<u8>, Fail> {
    let mut out = Vec::with_capacity(res.content_length as usize);
    if let Some(mut s) = res.body {
        while let Some(chunk) = s.next().await {
            let chunk = chunk.map_err(|e| Fail::new("InternalError", e.to_string()))?;
            out.extend_from_slice(&chunk);
        }
    }
    Ok(out)
}

fn parse_range(s: &str) -> Result<RangeSpec, Fail> {
    let s = s.trim().trim_start_matches("bytes=");
    let bad = || Fail::invalid("range: expected `first-last`, `first-` or `-N`");
    let (a, b) = s.split_once('-').ok_or_else(bad)?;
    if a.is_empty() {
        return Ok(RangeSpec::Suffix(b.parse().map_err(|_| bad())?));
    }
    let first = a.parse().map_err(|_| bad())?;
    let last = if b.is_empty() {
        None
    } else {
        Some(b.parse().map_err(|_| bad())?)
    };
    Ok(RangeSpec::Int { first, last })
}

#[tool_router]
impl TidemarkMcp {
    #[tool(
        description = "List the buckets you can browse (s3:ListAllMyBuckets; only buckets on which list_objects would be allowed are returned)."
    )]
    async fn list_buckets(
        &self,
        Parameters(_a): Parameters<NoArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            self.allow(
                &c,
                "list_buckets",
                "s3:ListAllMyBuckets",
                None,
                "arn:aws:s3:::*",
                &[],
            )
            .await?;
            let mut out = Vec::new();
            for b in self.state.engine.list_buckets()? {
                let visible = self
                    .allow(
                        &c,
                        "list_objects",
                        "s3:ListBucket",
                        Some(&b.name),
                        &arn::bucket(&b.name),
                        &[("s3:prefix", String::new())],
                    )
                    .await
                    .is_ok();
                if visible {
                    out.push(json!({"name": b.name, "created_at": b.created_at.to_rfc3339()}));
                }
            }
            Ok(json!({ "buckets": out }))
        })
        .await
    }

    #[tool(
        description = "List objects in a bucket (s3:ListBucket; as_of also needs tidemark:TimeTravel). Supports prefix, delimiter, pagination via start_after, and time travel via as_of."
    )]
    async fn list_objects(
        &self,
        Parameters(a): Parameters<ListObjectsArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let max = a.max_keys.unwrap_or(100).clamp(1, 1000);
            let prefix = a.prefix.unwrap_or_default();
            let as_of = a.as_of.as_deref().map(|s| ts(s, "as_of")).transpose()?;
            let mut extra = vec![
                ("s3:prefix", prefix.clone()),
                ("s3:max-keys", max.to_string()),
            ];
            if let Some(d) = &a.delimiter {
                extra.push(("s3:delimiter", d.clone()));
            }
            if let Some(t) = &a.as_of {
                extra.push(("tidemark:AsOf", t.clone()));
            }
            self.allow(
                &c,
                "list_objects",
                "s3:ListBucket",
                Some(&a.bucket),
                &arn::bucket(&a.bucket),
                &extra,
            )
            .await?;
            if a.as_of.is_some() {
                self.allow(
                    &c,
                    "list_objects",
                    "tidemark:TimeTravel",
                    Some(&a.bucket),
                    &arn::bucket(&a.bucket),
                    &extra,
                )
                .await?;
            }
            let res = self.state.engine.list_objects(
                &a.bucket,
                &ListReq {
                    prefix,
                    delimiter: a.delimiter,
                    after: a.start_after,
                    max,
                    as_of,
                },
            )?;
            let next = if res.truncated {
                res.next_key
                    .clone()
                    .or_else(|| res.objects.last().map(|o| o.version.key.clone()))
            } else {
                None
            };
            Ok(json!({
                "bucket": a.bucket,
                "objects": res.objects.iter().map(|o| version_json(&o.version)).collect::<Vec<_>>(),
                "common_prefixes": res.prefixes,
                "truncated": res.truncated,
                "next_start_after": next,
            }))
        })
        .await
    }

    #[tool(
        description = "Read an object (s3:GetObject / s3:GetObjectVersion). Returns UTF-8 text or base64; bodies larger than the server cap are truncated (use range to page)."
    )]
    async fn get_object(
        &self,
        Parameters(a): Parameters<GetObjectArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let mode = a.mode.as_deref().unwrap_or("auto");
            if !matches!(mode, "auto" | "text" | "base64") {
                return Err(Fail::invalid("mode: expected text, base64 or auto"));
            }
            let as_of = a.as_of.as_deref().map(|s| ts(s, "as_of")).transpose()?;
            let range = a.range.as_deref().map(parse_range).transpose()?;
            self.authorize_read(
                &c,
                "get_object",
                &a.bucket,
                &a.key,
                a.version_id.as_deref(),
                a.as_of.as_deref(),
            )
            .await?;
            let mut req = GetObjectReq {
                bucket: a.bucket.clone(),
                key: a.key.clone(),
                version_id: a.version_id,
                as_of,
                ..Default::default()
            };
            let head = self.state.engine.get_object(req.clone(), false).await?;
            let cap = self.state.config.max_get_bytes;
            let (range, truncated) = match range {
                Some(r) => (Some(r), false),
                None if head.size > cap => (
                    Some(RangeSpec::Int {
                        first: 0,
                        last: Some(cap - 1),
                    }),
                    true,
                ),
                None => (None, false),
            };
            req.range = range;
            let res = self.state.engine.get_object(req, true).await?;
            if res.content_length > cap {
                return Err(Fail::invalid(format!(
                    "requested range is larger than the {cap}-byte cap"
                )));
            }
            let mut out = version_json(&res.version);
            out["version_id"] = json!(res.version_id);
            out["size"] = json!(res.size);
            out["truncated"] = json!(truncated);
            if let Some((s, e)) = res.range {
                out["range"] = json!({"start": s, "end_exclusive": e});
            }
            let body = read_body(res).await?;
            out["returned_bytes"] = json!(body.len());
            match (mode, String::from_utf8(body)) {
                ("base64", Ok(t)) => {
                    out["encoding"] = json!("base64");
                    out["content_base64"] = json!(B64.encode(t.as_bytes()));
                }
                (_, Ok(t)) => {
                    out["encoding"] = json!("text");
                    out["content"] = json!(t);
                }
                ("text", Err(_)) => {
                    return Err(Fail::invalid("object is not valid UTF-8; use mode base64"));
                }
                (_, Err(e)) => {
                    out["encoding"] = json!("base64");
                    out["content_base64"] = json!(B64.encode(e.into_bytes()));
                }
            }
            Ok(out)
        })
        .await
    }

    #[tool(description = "Object metadata without the body (s3:GetObject, like HeadObject).")]
    async fn head_object(
        &self,
        Parameters(a): Parameters<HeadObjectArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let as_of = a.as_of.as_deref().map(|s| ts(s, "as_of")).transpose()?;
            self.authorize_read(
                &c,
                "head_object",
                &a.bucket,
                &a.key,
                a.version_id.as_deref(),
                a.as_of.as_deref(),
            )
            .await?;
            let res = self
                .state
                .engine
                .get_object(
                    GetObjectReq {
                        bucket: a.bucket,
                        key: a.key,
                        version_id: a.version_id,
                        as_of,
                        ..Default::default()
                    },
                    false,
                )
                .await?;
            let mut out = version_json(&res.version);
            out["version_id"] = json!(res.version_id);
            if let Some(b) = res.version.body() {
                out["metadata"] = json!(b.user_metadata);
                out["tag_count"] = json!(b.tags.len());
                out["cache_control"] = json!(b.cache_control);
                out["content_encoding"] = json!(b.content_encoding);
                out["parts"] = json!(b.parts.len());
            }
            Ok(out)
        })
        .await
    }

    #[tool(
        description = "Write an object (s3:PutObject) from text or base64, with optional content type, metadata and tags."
    )]
    async fn put_object(
        &self,
        Parameters(a): Parameters<PutObjectArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let (bytes, default_ct) = match (a.content, a.content_base64) {
                (Some(t), None) => (t.into_bytes(), "text/plain; charset=utf-8"),
                (None, Some(b)) => (
                    B64.decode(b.trim())
                        .map_err(|_| Fail::invalid("content_base64 is not valid base64"))?,
                    "application/octet-stream",
                ),
                _ => {
                    return Err(Fail::invalid(
                        "exactly one of content / content_base64 is required",
                    ));
                }
            };
            if bytes.len() > self.state.config.max_put_bytes {
                return Err(Fail::new(
                    "EntityTooLarge",
                    format!(
                        "body is larger than the {}-byte MCP cap; use S3 for large uploads",
                        self.state.config.max_put_bytes
                    ),
                ));
            }
            let mut extra: Vec<(&str, String)> = Vec::new();
            let tag_keys: Vec<String> = a.tags.keys().cloned().collect();
            let tag_conds: Vec<(String, String)> = a
                .tags
                .iter()
                .map(|(k, v)| (format!("s3:RequestObjectTag/{k}"), v.clone()))
                .collect();
            for (k, v) in &tag_conds {
                extra.push((k.as_str(), v.clone()));
            }
            for k in &tag_keys {
                extra.push(("s3:RequestObjectTagKeys", k.clone()));
            }
            self.allow(
                &c,
                "put_object",
                "s3:PutObject",
                Some(&a.bucket),
                &arn::object(&a.bucket, &a.key),
                &extra,
            )
            .await?;
            let len = bytes.len() as u64;
            let res = self
                .state
                .engine
                .put_object(PutObjectReq {
                    bucket: a.bucket.clone(),
                    key: a.key.clone(),
                    body: body_from_bytes(bytes),
                    content_length: Some(len),
                    content_md5: None,
                    checksum: Default::default(),
                    meta: ObjectMeta {
                        content_type: Some(a.content_type.unwrap_or_else(|| default_ct.into())),
                        user_metadata: a.metadata,
                        ..Default::default()
                    },
                    tags: a.tags,
                    conditions: Default::default(),
                    owner: principal_id(&c),
                })
                .await?;
            Ok(json!({
                "bucket": a.bucket, "key": a.key, "etag": format!("\"{}\"", res.etag),
                "version_id": res.version_id, "size": res.size,
            }))
        })
        .await
    }

    #[tool(
        description = "Delete an object (s3:DeleteObject) or one version (s3:DeleteObjectVersion). Deleted data stays restorable from the trash until its retention expires."
    )]
    async fn delete_object(
        &self,
        Parameters(a): Parameters<DeleteObjectArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let (action, extra) = match &a.version_id {
                Some(v) => ("s3:DeleteObjectVersion", vec![("s3:VersionId", v.clone())]),
                None => ("s3:DeleteObject", Vec::new()),
            };
            self.allow(
                &c,
                "delete_object",
                action,
                Some(&a.bucket),
                &arn::object(&a.bucket, &a.key),
                &extra,
            )
            .await?;
            let r = self
                .state
                .engine
                .delete_object(&a.bucket, &a.key, a.version_id, &principal_id(&c))
                .await?;
            Ok(json!({
                "bucket": a.bucket, "key": a.key,
                "delete_marker": r.delete_marker, "version_id": r.version_id,
            }))
        })
        .await
    }

    #[tool(
        description = "Server-side copy (s3:PutObject on the destination, s3:GetObject / s3:GetObjectVersion on the source). Metadata and tags are copied."
    )]
    async fn copy_object(
        &self,
        Parameters(a): Parameters<CopyObjectArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let src = format!("{}/{}", a.source_bucket, a.source_key);
            self.allow(
                &c,
                "copy_object",
                "s3:PutObject",
                Some(&a.bucket),
                &arn::object(&a.bucket, &a.key),
                &[("s3:x-amz-copy-source", src)],
            )
            .await?;
            self.authorize_read(
                &c,
                "copy_object",
                &a.source_bucket,
                &a.source_key,
                a.source_version_id.as_deref(),
                None,
            )
            .await?;
            let r = self
                .state
                .engine
                .copy_object(CopyObjectReq {
                    src_bucket: a.source_bucket,
                    src_key: a.source_key,
                    src_version: a.source_version_id,
                    bucket: a.bucket.clone(),
                    key: a.key.clone(),
                    owner: principal_id(&c),
                    ..Default::default()
                })
                .await?;
            Ok(json!({
                "bucket": a.bucket, "key": a.key, "etag": format!("\"{}\"", r.put.etag),
                "version_id": r.put.version_id, "size": r.put.size,
                "source_version_id": r.src_version_id,
            }))
        })
        .await
    }

    #[tool(
        description = "Search object metadata in one bucket (s3:ListBucket): key substring, prefix, content type, size and modification-time filters."
    )]
    async fn search(
        &self,
        Parameters(a): Parameters<SearchArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let prefix = a.prefix.clone().unwrap_or_default();
            let after = a
                .modified_after
                .as_deref()
                .map(|s| ts(s, "modified_after"))
                .transpose()?;
            let before = a
                .modified_before
                .as_deref()
                .map(|s| ts(s, "modified_before"))
                .transpose()?;
            let limit = a.limit.unwrap_or(50).clamp(1, 500);
            self.allow(
                &c,
                "search",
                "s3:ListBucket",
                Some(&a.bucket),
                &arn::bucket(&a.bucket),
                &[("s3:prefix", prefix.clone())],
            )
            .await?;
            let q = a.query.as_deref().map(str::to_lowercase);
            let (mut hits, mut scanned, mut cursor) = (Vec::new(), 0usize, None::<String>);
            let budget = self.state.config.max_search_scan;
            let mut exhausted = true;
            loop {
                let page = self.state.engine.list_objects(
                    &a.bucket,
                    &ListReq {
                        prefix: prefix.clone(),
                        after: cursor.clone(),
                        max: 1000.min(budget - scanned).max(1),
                        ..Default::default()
                    },
                )?;
                for o in &page.objects {
                    scanned += 1;
                    let v = &o.version;
                    let Some(b) = v.body() else { continue };
                    let ok = q.as_ref().is_none_or(|q| v.key.to_lowercase().contains(q))
                        && a.content_type.as_ref().is_none_or(|ct| {
                            b.content_type
                                .as_deref()
                                .is_some_and(|x| x.starts_with(ct.as_str()))
                        })
                        && a.min_size.is_none_or(|m| b.size >= m)
                        && a.max_size.is_none_or(|m| b.size <= m)
                        && after.is_none_or(|t| v.created_at >= t)
                        && before.is_none_or(|t| v.created_at < t);
                    if ok {
                        hits.push(version_json(v));
                        if hits.len() >= limit {
                            break;
                        }
                    }
                }
                cursor = page.objects.last().map(|o| o.version.key.clone());
                if hits.len() >= limit || scanned >= budget {
                    exhausted = !page.truncated && hits.len() < limit;
                    break;
                }
                if !page.truncated || cursor.is_none() {
                    break;
                }
            }
            Ok(json!({
                "bucket": a.bucket, "results": hits, "scanned": scanned,
                "complete": exhausted,
            }))
        })
        .await
    }

    #[tool(
        description = "List soft-deleted and superseded versions that can still be restored (tidemark:ListTrash on the bucket)."
    )]
    async fn trash_list(
        &self,
        Parameters(a): Parameters<TrashListArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let prefix = a.prefix.unwrap_or_default();
            let limit = a.limit.unwrap_or(100).clamp(1, 1000);
            self.allow(
                &c,
                "trash_list",
                "tidemark:ListTrash",
                Some(&a.bucket),
                &arn::bucket(&a.bucket),
                &[("s3:prefix", prefix.clone())],
            )
            .await?;
            let entries = self.state.engine.trash_list(&a.bucket, &prefix, limit)?;
            let items: Vec<Value> = entries
                .iter()
                .map(|e| {
                    let mut o = version_json(&e.version);
                    o["version_id"] = json!(e.version.version_id.to_string());
                    o["hidden_at"] = json!(e.hidden_at.to_rfc3339());
                    o["expires_at"] = json!(e.expires_at.to_rfc3339());
                    o
                })
                .collect();
            Ok(json!({"bucket": a.bucket, "items": items}))
        })
        .await
    }

    #[tool(
        description = "Restore a version from the trash as a new live version (tidemark:Restore on the object). History is never rewritten."
    )]
    async fn trash_restore(
        &self,
        Parameters(a): Parameters<TrashRestoreArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let v = a.version_id.as_deref().map(vid).transpose()?;
            self.allow(
                &c,
                "trash_restore",
                "tidemark:Restore",
                Some(&a.bucket),
                &arn::object(&a.bucket, &a.key),
                &[],
            )
            .await?;
            let r = self
                .state
                .engine
                .trash_restore(&a.bucket, &a.key, v, &principal_id(&c))
                .await?;
            Ok(json!({
                "bucket": a.bucket, "key": a.key, "etag": format!("\"{}\"", r.etag),
                "version_id": r.version_id, "size": r.size,
            }))
        })
        .await
    }

    #[tool(
        description = "The version that was current for a key at an instant (s3:GetObject + tidemark:TimeTravel with tidemark:AsOf, like a time-travel HEAD)."
    )]
    async fn pitr_head_at(
        &self,
        Parameters(a): Parameters<PitrHeadAtArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let at = ts(&a.at, "at")?;
            self.authorize_read(&c, "pitr_head_at", &a.bucket, &a.key, None, Some(&a.at))
                .await?;
            let v = self.state.engine.pitr_head_at(&a.bucket, &a.key, at)?;
            Ok(json!({
                "bucket": a.bucket, "key": a.key, "at": at.to_rfc3339(),
                "exists": v.is_some(), "version": v.as_ref().map(version_json),
            }))
        })
        .await
    }

    #[tool(
        description = "Keys whose state differs between now and an instant: recreate / revert / remove (tidemark:PitrDiff on the bucket)."
    )]
    async fn pitr_diff(
        &self,
        Parameters(a): Parameters<PitrDiffArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let at = ts(&a.at, "at")?;
            let prefix = a.prefix.unwrap_or_default();
            self.allow(
                &c,
                "pitr_diff",
                "tidemark:PitrDiff",
                Some(&a.bucket),
                &arn::bucket(&a.bucket),
                &[
                    ("s3:prefix", prefix.clone()),
                    ("tidemark:AsOf", a.at.clone()),
                ],
            )
            .await?;
            let d = self.state.engine.pitr_diff(&a.bucket, &prefix, at)?;
            Ok(json!({"bucket": a.bucket, "at": at.to_rfc3339(), "changes": diff_json(&d)}))
        })
        .await
    }

    #[tool(
        description = "Restore a bucket (or prefix) to its state at an instant by writing new versions (tidemark:Pitr on the bucket). dry_run defaults to true; applying requires confirm: true. Fully reversible."
    )]
    async fn pitr_restore(
        &self,
        Parameters(a): Parameters<PitrRestoreArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let at = ts(&a.at, "at")?;
            let prefix = a.prefix.unwrap_or_default();
            let dry = a.dry_run.unwrap_or(true);
            if !dry && !a.confirm {
                return Err(Fail::invalid(
                    "pitr_restore rewrites the bucket; set confirm: true to apply",
                ));
            }
            self.allow(
                &c,
                "pitr_restore",
                "tidemark:Pitr",
                Some(&a.bucket),
                &arn::bucket(&a.bucket),
                &[("s3:prefix", prefix.clone()), ("tidemark:AsOf", a.at.clone())],
            )
            .await?;
            let diff = self.state.engine.pitr_diff(&a.bucket, &prefix, at)?;
            let cap = self.state.config.max_pitr_changes;
            let truncated = diff.len() > cap;
            let diff = &diff[..diff.len().min(cap)];
            if dry {
                return Ok(json!({
                    "bucket": a.bucket, "at": at.to_rfc3339(), "dry_run": true,
                    "changes": diff_json(diff), "truncated": truncated,
                }));
            }
            let by = principal_id(&c);
            let eng = &self.state.engine;
            let mut applied = Vec::new();
            for e in diff {
                let r: Result<Option<String>, S3Error> = match e.kind {
                    DiffKind::Remove => eng
                        .delete_object(&a.bucket, &e.key, None, &by)
                        .await
                        .map(|r| r.version_id),
                    DiffKind::Recreate | DiffKind::Revert => {
                        match eng.pitr_head_at(&a.bucket, &e.key, at)? {
                            None => Ok(None),
                            Some(v) if v.is_live() => eng
                                .copy_object(CopyObjectReq {
                                    src_bucket: a.bucket.clone(),
                                    src_key: e.key.clone(),
                                    src_version: Some(display_vid(&v)),
                                    bucket: a.bucket.clone(),
                                    key: e.key.clone(),
                                    owner: by.clone(),
                                    ..Default::default()
                                })
                                .await
                                .map(|r| r.put.version_id),
                            Some(v) => eng
                                .trash_restore(&a.bucket, &e.key, Some(v.version_id), &by)
                                .await
                                .map(|r| r.version_id),
                        }
                    }
                };
                applied.push(match r {
                    Ok(v) => json!({"key": e.key, "action": kind_str(e.kind), "ok": true, "version_id": v}),
                    Err(err) => json!({"key": e.key, "action": kind_str(e.kind), "ok": false, "error": err.code.as_str(), "message": err.message}),
                });
            }
            Ok(json!({
                "bucket": a.bucket, "at": at.to_rfc3339(), "dry_run": false,
                "applied": applied, "truncated": truncated,
            }))
        })
        .await
    }

    #[tool(
        description = "Bucket configuration summary: creation time, versioning, object lock, retention (s3:ListBucket, like HeadBucket; tags only with s3:GetBucketTagging)."
    )]
    async fn bucket_info(
        &self,
        Parameters(a): Parameters<BucketArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> ToolResult {
        self.run(&ctx, |c| async move {
            let res = arn::bucket(&a.bucket);
            self.allow(
                &c,
                "bucket_info",
                "s3:ListBucket",
                Some(&a.bucket),
                &res,
                &[],
            )
            .await?;
            let b = self.state.engine.head_bucket(&a.bucket)?;
            let mut out = json!({
                "name": b.name,
                "created_at": b.created_at.to_rfc3339(),
                "versioning": match b.versioning {
                    Versioning::Off => "Off",
                    Versioning::Enabled => "Enabled",
                    Versioning::Suspended => "Suspended",
                },
                "object_lock_enabled": b.object_lock_enabled,
                "location": b.location,
                "retention": {
                    "soft_delete_secs": b.retention.soft_delete_secs,
                    "shadow_history_secs": b.retention.shadow_history_secs,
                    "min_versions_kept": b.retention.min_versions_kept,
                },
            });
            if self
                .allow(
                    &c,
                    "bucket_info",
                    "s3:GetBucketTagging",
                    Some(&a.bucket),
                    &res,
                    &[],
                )
                .await
                .is_ok()
            {
                out["tags"] = json!(b.tags);
            }
            Ok(out)
        })
        .await
    }
}

impl TidemarkMcp {
    /// `s3:GetObject` (or `s3:GetObjectVersion` with a version id) on the object, with
    /// `s3:VersionId` / `tidemark:AsOf` in the context; time travel (`as_of` without a version id)
    /// also needs `tidemark:TimeTravel` on the object, as `x-tidemark-as-of` does over S3.
    async fn authorize_read(
        &self,
        c: &McpCaller,
        tool: &str,
        bucket: &str,
        key: &str,
        version: Option<&str>,
        as_of: Option<&str>,
    ) -> Result<(), Fail> {
        let mut extra = Vec::new();
        let action = match version {
            Some(v) => {
                extra.push(("s3:VersionId", v.to_string()));
                "s3:GetObjectVersion"
            }
            None => "s3:GetObject",
        };
        if let Some(t) = as_of {
            extra.push(("tidemark:AsOf", t.to_string()));
        }
        let res = arn::object(bucket, key);
        self.allow(c, tool, action, Some(bucket), &res, &extra)
            .await?;
        if as_of.is_some() && version.is_none() {
            self.allow(c, tool, "tidemark:TimeTravel", Some(bucket), &res, &extra)
                .await?;
        }
        Ok(())
    }
}

fn kind_str(k: DiffKind) -> &'static str {
    match k {
        DiffKind::Recreate => "recreate",
        DiffKind::Revert => "revert",
        DiffKind::Remove => "remove",
    }
}

fn diff_json(d: &[tidemark_engine::types::DiffEntry]) -> Vec<Value> {
    d.iter()
        .map(|e| {
            json!({
                "key": e.key,
                "action": kind_str(e.kind),
                "then_version_id": e.then.map(|v| v.to_string()),
                "current_version_id": e.now.map(|v| v.to_string()),
            })
        })
        .collect()
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for TidemarkMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("tidemark", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Tidemark object storage. Tools act with the permissions of the Tidemark credential \
                 this session is bound to; denied calls return AccessDenied. Deletes are \
                 soft: use trash_list / trash_restore and pitr_* to recover data.",
            )
    }
}
