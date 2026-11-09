//! Sinks: the [`Sink`] trait, sink configuration, and the HTTP [`WebhookSink`] with its auth
//! modes (`hmac`, `bearer`, `sigv4-lambda`, `cf-access`, `none`).

use crate::EventsError;
use crate::event::{envelope, idempotency_key};
use crate::matcher::tidemark_sink_id;
use crate::outbox::{OutboxRecord, valid_sink_id};
use crate::secret::Secret;
use crate::sigv4;
use futures::future::BoxFuture;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::time::Duration;

/// Delivery failure classification.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SinkError {
    /// Worth retrying (network error, timeout, 408/429/5xx).
    #[error("retryable: {0}")]
    Retryable(String),
    /// Retrying will not help (other 4xx, bad config); goes straight to the DLQ.
    #[error("permanent: {0}")]
    Permanent(String),
}

/// One event handed to a sink.
#[derive(Debug, Clone)]
pub struct Delivery {
    /// Outbox sequence (idempotency key source).
    pub seq: u64,
    /// The outbox record.
    pub record: OutboxRecord,
    /// `configurationId` of the rule that routed it here (empty for broadcast sinks).
    pub configuration_id: String,
}

impl Delivery {
    /// The S3 event-message record for this delivery.
    pub fn to_record(&self) -> serde_json::Value {
        self.record
            .event
            .to_record(self.seq, &self.configuration_id)
    }

    /// Stable idempotency key (`tidemark.id` in the record).
    pub fn idempotency_key(&self) -> String {
        idempotency_key(self.seq)
    }
}

/// A delivery destination driven by a [`crate::DeliveryWorker`].
pub trait Sink: Send + Sync {
    /// Stable sink id (cursor and DLQ key).
    fn id(&self) -> &str;

    /// If this sink should receive `rec`, the `configurationId` to stamp on it.
    fn accepts(&self, rec: &OutboxRecord) -> Option<String>;

    /// Max events per [`Sink::deliver`] call.
    fn batch_size(&self) -> usize {
        1
    }

    /// Deliver a batch; `Ok` means every event in it was accepted by the destination.
    fn deliver<'a>(&'a self, batch: &'a [Delivery]) -> BoxFuture<'a, Result<(), SinkError>>;
}

/// Default routing: honour `only_sink`, else pick the first target whose ARN is
/// `arn:tidemark:sink::<id>` or one of `aliases`.
pub fn route(id: &str, aliases: &[String], rec: &OutboxRecord) -> Option<String> {
    if let Some(only) = &rec.only_sink {
        if only != id {
            return None;
        }
        return Some(
            rec.targets
                .first()
                .map(|t| t.configuration_id.clone())
                .unwrap_or_default(),
        );
    }
    rec.targets
        .iter()
        .find(|t| tidemark_sink_id(&t.arn) == Some(id) || aliases.iter().any(|a| a == &t.arn))
        .map(|t| t.configuration_id.clone())
}

/// How an HTTP sink authenticates (DESIGN §10).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SinkAuth {
    /// No authentication (only sensible on a private network).
    #[default]
    None,
    /// `x-tidemark-signature: v1=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>` plus
    /// `x-tidemark-timestamp: <unix seconds>`.
    Hmac {
        /// Shared secret.
        secret: Secret,
    },
    /// `Authorization: Bearer <token>`.
    Bearer {
        /// Static token.
        token: Secret,
    },
    /// AWS Lambda `Invoke` signed with SigV4 (`lambda` service).
    Sigv4Lambda {
        /// AWS access key id.
        access_key_id: String,
        /// AWS secret access key.
        secret_access_key: Secret,
        /// Optional STS session token.
        #[serde(default)]
        session_token: Option<Secret>,
        /// AWS region of the function.
        region: String,
        /// Function name, ARN or partial ARN.
        function: String,
        /// `Event` (async, default) or `RequestResponse`.
        #[serde(default)]
        invocation_type: Option<String>,
    },
    /// Cloudflare Access service token (`CF-Access-Client-Id` / `CF-Access-Client-Secret`).
    CfAccess {
        /// Service token client id.
        client_id: String,
        /// Service token client secret.
        client_secret: Secret,
    },
}

impl SinkAuth {
    /// The `mode` name.
    pub fn mode(&self) -> &'static str {
        match self {
            SinkAuth::None => "none",
            SinkAuth::Hmac { .. } => "hmac",
            SinkAuth::Bearer { .. } => "bearer",
            SinkAuth::Sigv4Lambda { .. } => "sigv4-lambda",
            SinkAuth::CfAccess { .. } => "cf-access",
        }
    }
}

/// A sink definition (one `[[events.sinks]]` entry).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkConfig {
    /// Sink id; destination ARN is `arn:tidemark:sink::<id>`.
    pub id: String,
    /// Target URL. For `sigv4-lambda` this is an optional endpoint override
    /// (default `https://lambda.<region>.amazonaws.com`).
    #[serde(default)]
    pub url: Option<String>,
    /// Extra ARNs that route to this sink (e.g. an AWS `LambdaFunctionArn`).
    #[serde(default)]
    pub arns: Vec<String>,
    /// Authentication mode.
    #[serde(default)]
    pub auth: SinkAuth,
    /// Events per request (default 10 for webhooks, 1 for function sinks).
    #[serde(default)]
    pub batch_size: Option<usize>,
    /// Per-request timeout in seconds (default 10).
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

/// HTTP POST sink. With `bearer`/`sigv4-lambda`/`cf-access` auth it is a "function sink".
pub struct WebhookSink {
    id: String,
    url: url::Url,
    aliases: Vec<String>,
    auth: SinkAuth,
    batch_size: usize,
    client: reqwest::Client,
}

impl std::fmt::Debug for WebhookSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSink")
            .field("id", &self.id)
            .field("host", &self.url.host_str())
            .field("auth", &self.auth.mode())
            .finish()
    }
}

/// Max batch size accepted from config.
pub const MAX_BATCH: usize = 100;

impl WebhookSink {
    /// Build from configuration, validating the id, URL and auth parameters.
    pub fn from_config(cfg: SinkConfig) -> Result<WebhookSink, EventsError> {
        let bad = |m: String| EventsError::Sink(format!("sink {:?}: {m}", cfg.id));
        if !valid_sink_id(&cfg.id) {
            return Err(bad("id must be 1..=128 of [A-Za-z0-9._-]".into()));
        }
        let url = match &cfg.auth {
            SinkAuth::Sigv4Lambda {
                region, function, ..
            } => {
                if function.is_empty() || region.is_empty() {
                    return Err(bad("sigv4-lambda needs region and function".into()));
                }
                let base = cfg
                    .url
                    .clone()
                    .unwrap_or_else(|| format!("https://lambda.{region}.amazonaws.com"));
                format!(
                    "{}/2015-03-31/functions/{}/invocations",
                    base.trim_end_matches('/'),
                    sigv4::uri_encode(function, true)
                )
            }
            _ => cfg
                .url
                .clone()
                .ok_or_else(|| bad("url is required".into()))?,
        };
        let url = url::Url::parse(&url).map_err(|e| bad(format!("invalid url: {e}")))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(bad("url must be http or https".into()));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(bad("put credentials in auth, not in the url".into()));
        }
        match &cfg.auth {
            SinkAuth::Hmac { secret } if secret.is_empty() => {
                return Err(bad("hmac secret is empty".into()));
            }
            SinkAuth::Bearer { token } if token.is_empty() => {
                return Err(bad("bearer token is empty".into()));
            }
            SinkAuth::CfAccess {
                client_id,
                client_secret,
            } if client_id.is_empty() || client_secret.is_empty() => {
                return Err(bad("cf-access needs client_id and client_secret".into()));
            }
            _ => {}
        }
        let default_batch = match cfg.auth {
            SinkAuth::None | SinkAuth::Hmac { .. } => 10,
            _ => 1,
        };
        let batch_size = cfg.batch_size.unwrap_or(default_batch).clamp(1, MAX_BATCH);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_secs.unwrap_or(10).max(1)))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("tidemark/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| bad(format!("http client: {e}")))?;
        Ok(WebhookSink {
            id: cfg.id,
            url,
            aliases: cfg.arns,
            auth: cfg.auth,
            batch_size,
            client,
        })
    }

    /// The ARNs that route to this sink.
    pub fn arns(&self) -> Vec<String> {
        let mut v = vec![format!("arn:tidemark:sink::{}", self.id)];
        v.extend(self.aliases.iter().cloned());
        v
    }

    /// Target URL.
    pub fn url(&self) -> &url::Url {
        &self.url
    }

    fn host_header(&self) -> String {
        let host = self.url.host_str().unwrap_or_default();
        match self.url.port() {
            Some(p) => format!("{host}:{p}"),
            None => host.to_string(),
        }
    }

    /// Headers (besides `content-type`) for a request with `body`, sent at `now`.
    pub fn auth_headers(
        &self,
        body: &[u8],
        ids: &str,
        now: jiff::Timestamp,
    ) -> Vec<(String, String)> {
        let mut h = vec![
            ("content-type".to_string(), "application/json".to_string()),
            ("x-tidemark-sink".to_string(), self.id.clone()),
            ("x-tidemark-idempotency-key".to_string(), ids.to_string()),
        ];
        match &self.auth {
            SinkAuth::None => {}
            SinkAuth::Hmac { secret } => {
                let ts = now.as_second().to_string();
                h.push(("x-tidemark-timestamp".into(), ts.clone()));
                h.push((
                    "x-tidemark-signature".into(),
                    format!("v1={}", hmac_signature(secret.expose(), &ts, body)),
                ));
            }
            SinkAuth::Bearer { token } => {
                h.push(("authorization".into(), format!("Bearer {}", token.expose())));
            }
            SinkAuth::CfAccess {
                client_id,
                client_secret,
            } => {
                h.push(("cf-access-client-id".into(), client_id.clone()));
                h.push((
                    "cf-access-client-secret".into(),
                    client_secret.expose().to_string(),
                ));
            }
            SinkAuth::Sigv4Lambda {
                access_key_id,
                secret_access_key,
                session_token,
                region,
                invocation_type,
                ..
            } => {
                let date = sigv4::amz_date(now);
                let mut signed = vec![
                    ("content-type".to_string(), "application/json".to_string()),
                    ("host".to_string(), self.host_header()),
                    ("x-amz-date".to_string(), date.clone()),
                    (
                        "x-amz-invocation-type".to_string(),
                        invocation_type.clone().unwrap_or_else(|| "Event".into()),
                    ),
                ];
                if let Some(t) = session_token {
                    signed.push(("x-amz-security-token".into(), t.expose().to_string()));
                }
                let req = sigv4::SignableRequest {
                    method: "POST",
                    path: self.url.path(),
                    query: self.url.query().unwrap_or(""),
                    headers: &signed,
                    payload: body,
                };
                let scope = sigv4::Scope {
                    amz_date: &date,
                    region,
                    service: "lambda",
                };
                let auth =
                    sigv4::authorization(&req, &scope, access_key_id, secret_access_key.expose());
                for (k, v) in signed {
                    if k != "host" && k != "content-type" {
                        h.push((k, v));
                    }
                }
                h.push(("authorization".into(), auth));
            }
        }
        h
    }
}

/// Lowercase hex HMAC-SHA256 over `"<timestamp>.<body>"`; receivers recompute and compare in
/// constant time, and reject timestamps older than their tolerance (5 minutes suggested).
pub fn hmac_signature(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let mut m = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("any key length");
    m.update(timestamp.as_bytes());
    m.update(b".");
    m.update(body);
    hex::encode(m.finalize().into_bytes())
}

/// Headers whose values are credentials and must never be logged.
pub fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "cf-access-client-secret" | "x-amz-security-token"
    )
}

fn classify(status: reqwest::StatusCode) -> Result<(), SinkError> {
    if status.is_success() {
        Ok(())
    } else if status.is_server_error()
        || status == reqwest::StatusCode::REQUEST_TIMEOUT
        || status == reqwest::StatusCode::TOO_MANY_REQUESTS
    {
        Err(SinkError::Retryable(format!("HTTP {status}")))
    } else {
        Err(SinkError::Permanent(format!("HTTP {status}")))
    }
}

impl Sink for WebhookSink {
    fn id(&self) -> &str {
        &self.id
    }

    fn accepts(&self, rec: &OutboxRecord) -> Option<String> {
        route(&self.id, &self.aliases, rec)
    }

    fn batch_size(&self) -> usize {
        self.batch_size
    }

    fn deliver<'a>(&'a self, batch: &'a [Delivery]) -> BoxFuture<'a, Result<(), SinkError>> {
        Box::pin(async move {
            let records = batch.iter().map(Delivery::to_record).collect();
            let body = serde_json::to_vec(&envelope(records))
                .map_err(|e| SinkError::Permanent(e.to_string()))?;
            let ids = batch
                .iter()
                .map(Delivery::idempotency_key)
                .collect::<Vec<_>>()
                .join(",");
            let mut req = self.client.post(self.url.clone());
            for (k, v) in self.auth_headers(&body, &ids, jiff::Timestamp::now()) {
                let mut hv = reqwest::header::HeaderValue::from_str(&v)
                    .map_err(|_| SinkError::Permanent(format!("invalid value for header {k}")))?;
                hv.set_sensitive(is_sensitive_header(&k));
                req = req.header(k, hv);
            }
            let resp = req
                .body(body)
                .send()
                .await
                .map_err(|e| SinkError::Retryable(e.without_url().to_string()))?;
            classify(resp.status())?;
            if resp.headers().contains_key("x-amz-function-error") {
                return Err(SinkError::Retryable("function returned an error".into()));
            }
            Ok(())
        })
    }
}
