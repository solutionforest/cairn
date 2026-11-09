//! Per-connection request handling: request ids, tracing, health routes, error XML decoration.

use crate::State;
use axum::routing::get;
use bytes::Bytes;
use cairn_s3::RequestId;
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::Service as _;
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// Response body used by the server.
pub(crate) type BoxBody = UnsyncBoxBody<Bytes, BoxError>;

/// Facts about the connection, available to later layers via request extensions.
#[derive(Debug, Clone, Copy)]
pub struct ConnInfo {
    /// Remote address.
    pub peer: SocketAddr,
    /// Arrived over TLS.
    pub secure: bool,
}

fn full(b: impl Into<Bytes>) -> BoxBody {
    Full::new(b.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

fn box_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> BoxError {
    Box::new(e)
}

fn new_request_id() -> String {
    format!("{:016X}", rand::random::<u64>())
}

/// Serve one accepted connection (plain or TLS) until it closes or graceful shutdown ends it.
pub(crate) async fn serve<IO>(
    st: Arc<State>,
    io: IO,
    peer: SocketAddr,
    secure: bool,
    watcher: hyper_util::server::graceful::Watcher,
) where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let health = axum::Router::new()
        .route("/healthz", get(|| async { (StatusCode::OK, "ok\n") }))
        .route(
            "/readyz",
            get(
                |axum::extract::State(st): axum::extract::State<Arc<State>>| async move {
                    if st.ready() {
                        (StatusCode::OK, "ready\n")
                    } else {
                        (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
                    }
                },
            ),
        )
        .with_state(st.clone());
    let trace = TraceLayer::new_for_http()
        .make_span_with(|req: &Request<Incoming>| {
            let id = req
                .extensions()
                .get::<RequestId>()
                .map(|r| r.0.as_str())
                .unwrap_or("-");
            tracing::info_span!(
                "request",
                id = %id,
                method = %req.method(),
                path = %req.uri().path(),
            )
        })
        .on_request(DefaultOnRequest::new().level(Level::DEBUG))
        .on_response(DefaultOnResponse::new().level(Level::INFO));
    let inner =
        tower::ServiceBuilder::new()
            .layer(trace)
            .service_fn(move |req: Request<Incoming>| {
                let st = st.clone();
                let health = health.clone();
                let fut: std::pin::Pin<
                    Box<dyn Future<Output = Result<Response<BoxBody>, Infallible>> + Send>,
                > = Box::pin(async move { Ok::<_, Infallible>(handle(st, health, req).await) });
                fut
            });
    let svc = hyper::service::service_fn(move |mut req: Request<Incoming>| {
        let rid = new_request_id();
        req.extensions_mut().insert(RequestId(rid.clone()));
        req.extensions_mut().insert(ConnInfo { peer, secure });
        let mut svc = inner.clone();
        async move {
            let resp = match svc.call(req).await {
                Ok(r) => r.map(|b| b.boxed_unsync()),
                Err(never) => match never {},
            };
            Ok::<_, Infallible>(stamp(resp, &rid))
        }
    });
    let builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let conn = builder
        .serve_connection(hyper_util::rt::TokioIo::new(io), svc)
        .into_owned();
    if let Err(e) = watcher.watch(conn).await {
        tracing::debug!(%peer, error = %e, "connection ended with error");
    }
}

fn is_health(req: &Request<Incoming>) -> bool {
    matches!(*req.method(), Method::GET | Method::HEAD)
        && matches!(req.uri().path(), "/healthz" | "/readyz")
        && req.uri().query().is_none()
        && !req.headers().contains_key(http::header::AUTHORIZATION)
}

fn is_metrics(req: &Request<Incoming>) -> bool {
    *req.method() == Method::GET
        && req.uri().path() == "/metrics"
        && req.uri().query().is_none()
        && !req.headers().contains_key(http::header::AUTHORIZATION)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Api {
    S3,
    Sts,
    Admin,
    Mcp,
}

impl Api {
    fn name(self) -> &'static str {
        match self {
            Api::S3 => "s3",
            Api::Sts => "sts",
            Api::Admin => "admin",
            Api::Mcp => "mcp",
        }
    }
}

fn header_u64(h: &http::HeaderMap, name: &str) -> Option<u64> {
    h.get(name)?.to_str().ok()?.parse().ok()
}

/// Access key id from a SigV4 `Authorization` header or `X-Amz-Credential` query (not secret).
fn signing_key_id(req: &Request<Incoming>) -> Option<String> {
    let from_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|a| a.split("Credential=").nth(1))
        .and_then(|c| c.split('/').next())
        .map(str::to_string);
    from_header.or_else(|| {
        req.uri().query().and_then(|q| {
            q.split('&')
                .find_map(|p| p.strip_prefix("X-Amz-Credential="))
                .and_then(|c| c.split("%2F").next().or_else(|| c.split('/').next()))
                .map(str::to_string)
        })
    })
}

async fn call_router(mut r: axum::Router, req: Request<Incoming>) -> Response<BoxBody> {
    match r.call(req.map(axum::body::Body::new)).await {
        Ok(r) => r.map(|b| b.map_err(box_err).boxed_unsync()),
        Err(never) => match never {},
    }
}

async fn handle(
    st: Arc<State>,
    mut health: axum::Router,
    mut req: Request<Incoming>,
) -> Response<BoxBody> {
    let started = std::time::Instant::now();
    let rid = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0.clone())
        .unwrap_or_default();
    let path = req.uri().path().to_string();
    if is_health(&req) {
        return match health.call(req).await {
            Ok(r) => r.map(|b| b.map_err(box_err).boxed_unsync()),
            Err(never) => match never {},
        };
    }
    if st.metrics_enabled && is_metrics(&req) {
        st.metrics
            .outbox_depth
            .set(crate::workers::outbox_depth(&st) as i64);
        let mut r = Response::new(full(st.metrics.render()));
        r.headers_mut().insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4"),
        );
        return r;
    }
    if let Some(c) = req.extensions().get::<ConnInfo>().copied() {
        let meta = st.proxies.resolve(c.peer, c.secure, req.headers());
        req.extensions_mut().insert(meta);
    }
    let source_ip = req
        .extensions()
        .get::<cairn_auth::RequestMeta>()
        .and_then(|m| m.source_ip)
        .map(|ip| ip.to_string());
    let method = req.method().clone();
    let bytes_in = header_u64(req.headers(), "x-amz-decoded-content-length")
        .or_else(|| header_u64(req.headers(), "content-length"))
        .unwrap_or(0);
    let akid = signing_key_id(&req);
    let slot = cairn_s3::OpSlot::default();
    let api = if path.starts_with("/_cairn/mcp") {
        Api::Mcp
    } else if path.starts_with("/_cairn/") {
        Api::Admin
    } else if cairn_auth::sts::is_sts_request(req.method(), req.uri(), req.headers()) {
        Api::Sts
    } else {
        Api::S3
    };
    let resp = match api {
        Api::Admin | Api::Mcp => call_router(st.cairn.clone(), req).await,
        Api::Sts => call_router(st.sts.clone(), req).await,
        Api::S3 if req.method() == Method::OPTIONS => s3_preflight(req.headers(), &path, &rid),
        Api::S3 => {
            req.extensions_mut().insert(slot.clone());
            match st.s3.call(req.map(s3s::Body::from)).await {
                Ok(r) => r.map(|b| b.boxed_unsync()),
                Err(e) => {
                    tracing::error!(error = %e, "request failed");
                    let mut r = Response::new(full(error_xml(
                        "InternalError",
                        "We encountered an internal error. Please try again.",
                        &path,
                        &rid,
                    )));
                    *r.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                    r.headers_mut().insert(
                        http::header::CONTENT_TYPE,
                        HeaderValue::from_static("application/xml"),
                    );
                    r
                }
            }
        }
    };
    let resp =
        if api == Api::S3 && (resp.status().is_client_error() || resp.status().is_server_error()) {
            decorate_error(resp, rid.clone(), path.clone()).await
        } else {
            resp
        };
    let status = resp.status().as_u16();
    let info = slot.get();
    let op = match api {
        Api::S3 => info.op.clone().unwrap_or_else(|| "Unknown".into()),
        other => other.name().to_string(),
    };
    let bytes_out = header_u64(resp.headers(), "content-length").unwrap_or(0);
    let elapsed = started.elapsed();
    st.metrics
        .observe_request(&op, status, elapsed.as_secs_f64(), bytes_in, bytes_out);
    if let Some(audit) = &st.audit {
        let mutating = !matches!(method, Method::GET | Method::HEAD | Method::OPTIONS);
        let denied = matches!(status, 401 | 403) || info.denied;
        if st.audit_all || mutating || denied || api == Api::Sts {
            let principal = match (&info.principal, &akid) {
                (Some(p), _) => Some(p.clone()),
                (None, Some(ak)) if api != Api::S3 || status != 403 => st
                    .store
                    .lookup(ak)
                    .await
                    .ok()
                    .flatten()
                    .map(|c| c.principal.id.as_str().to_string()),
                _ => None,
            };
            let resource = match (api, &info.bucket, &info.key) {
                (Api::S3, Some(b), Some(k)) => format!("arn:aws:s3:::{b}/{k}"),
                (Api::S3, Some(b), None) => format!("arn:aws:s3:::{b}"),
                _ => path.clone(),
            };
            let action = match api {
                Api::S3 => op.clone(),
                _ => format!("{method} {path}"),
            };
            let ok = audit.record(crate::audit::AuditRecord {
                time: cairn_core::Ts::now().to_rfc3339(),
                request_id: rid.clone(),
                api: api.name(),
                principal,
                access_key: akid,
                action,
                resource,
                status,
                source_ip,
                latency_ms: elapsed.as_millis() as u64,
            });
            if !ok {
                st.metrics.audit_dropped.inc();
            }
        }
    }
    resp
}

/// S3 CORS preflight. Bucket CORS is shelved for v0.1, so no origin is ever allowed; answer the
/// way S3 does for a bucket without a CORS configuration: 400 when the request is not a
/// well-formed preflight, otherwise 403.
fn s3_preflight(h: &http::HeaderMap, path: &str, rid: &str) -> Response<BoxBody> {
    let (status, code, msg) = if !h.contains_key(http::header::ORIGIN) {
        (
            StatusCode::BAD_REQUEST,
            "BadRequest",
            "Insufficient information. Origin request header needed.",
        )
    } else if !h.contains_key(http::header::ACCESS_CONTROL_REQUEST_METHOD) {
        (
            StatusCode::BAD_REQUEST,
            "BadRequest",
            "Insufficient information. Access-Control-Request-Method header needed.",
        )
    } else {
        (
            StatusCode::FORBIDDEN,
            "AccessForbidden",
            "CORSResponse: CORS is not enabled for this bucket.",
        )
    };
    let mut r = Response::new(full(error_xml(code, msg, path, rid)));
    *r.status_mut() = status;
    r.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    r
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn error_xml(code: &str, msg: &str, resource: &str, rid: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{}</Message><Resource>{}</Resource><RequestId>{rid}</RequestId></Error>",
        xml_escape(msg),
        xml_escape(resource)
    )
}

/// Ensure an AWS-shaped error body carries `Resource` and `RequestId`.
async fn decorate_error(resp: Response<BoxBody>, rid: String, path: String) -> Response<BoxBody> {
    let (mut parts, body) = resp.into_parts();
    let bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            tracing::warn!(error = %e, "could not buffer error body");
            Bytes::new()
        }
    };
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if let Some(end) = text.rfind("</Error>") {
        let mut extra = String::new();
        if !text.contains("<Resource>") {
            extra.push_str(&format!("<Resource>{}</Resource>", xml_escape(&path)));
        }
        if !text.contains("<RequestId>") {
            extra.push_str(&format!("<RequestId>{rid}</RequestId>"));
        }
        text.insert_str(end, &extra);
        parts
            .headers
            .insert(http::header::CONTENT_LENGTH, HeaderValue::from(text.len()));
        return Response::from_parts(parts, full(text));
    }
    Response::from_parts(parts, full(bytes))
}

fn stamp(mut resp: Response<BoxBody>, rid: &str) -> Response<BoxBody> {
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(rid) {
        h.insert("x-amz-request-id", v.clone());
        h.insert("x-amz-id-2", v);
    }
    h.insert(http::header::SERVER, HeaderValue::from_static("Cairn"));
    resp
}
