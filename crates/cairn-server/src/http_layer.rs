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

async fn handle(
    st: Arc<State>,
    mut health: axum::Router,
    req: Request<Incoming>,
) -> Response<BoxBody> {
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
    let resp = match st.s3.call(req.map(s3s::Body::from)).await {
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
    };
    if resp.status().is_client_error() || resp.status().is_server_error() {
        decorate_error(resp, rid, path).await
    } else {
        resp
    }
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
