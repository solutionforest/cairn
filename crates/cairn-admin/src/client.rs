//! HTTP client for the admin API (reqwest + rustls), signing every request with SigV4.

use cairn_auth::{SecretString, Ts, sigv4};
use serde_json::Value;
use url::Url;

/// Client-side failure.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The server returned an error envelope.
    #[error("{code}: {message} (HTTP {status}, request id {request_id})")]
    Api {
        /// HTTP status.
        status: u16,
        /// Error code.
        code: String,
        /// Message.
        message: String,
        /// Server request id.
        request_id: String,
    },
    /// Transport failure.
    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Bad configuration (endpoint, credentials).
    #[error("{0}")]
    Config(String),
}

/// Admin API client.
#[derive(Clone)]
pub struct AdminClient {
    http: reqwest::Client,
    endpoint: Url,
    access_key: String,
    secret_key: SecretString,
    session_token: Option<SecretString>,
    region: String,
}

impl std::fmt::Debug for AdminClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminClient")
            .field("endpoint", &self.endpoint.as_str())
            .field("access_key", &self.access_key)
            .finish_non_exhaustive()
    }
}

impl AdminClient {
    /// Client for `endpoint` (e.g. `http://127.0.0.1:9000`) with the given credentials.
    pub fn new(
        endpoint: &str,
        access_key: &str,
        secret_key: SecretString,
        session_token: Option<SecretString>,
        region: &str,
    ) -> Result<Self, ClientError> {
        let endpoint = Url::parse(endpoint)
            .map_err(|e| ClientError::Config(format!("invalid endpoint {endpoint:?}: {e}")))?;
        if endpoint.host_str().is_none() {
            return Err(ClientError::Config("endpoint has no host".into()));
        }
        let http = reqwest::Client::builder()
            .user_agent(concat!("cairn-admin/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            endpoint,
            access_key: access_key.to_string(),
            secret_key,
            session_token,
            region: region.to_string(),
        })
    }

    /// Send `method` to `/_cairn/v1{path}` with optional query pairs and JSON body; returns
    /// the decoded JSON response.
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        query: &[(&str, String)],
        body: Option<&Value>,
    ) -> Result<Value, ClientError> {
        let base = self.endpoint.path().trim_end_matches('/');
        let raw_path = format!("{base}{}{path}", crate::api::PREFIX);
        let raw_query = query
            .iter()
            .map(|(k, v)| {
                format!(
                    "{}={}",
                    sigv4::uri_encode(k.as_bytes(), false),
                    sigv4::uri_encode(v.as_bytes(), false)
                )
            })
            .collect::<Vec<_>>()
            .join("&");
        let mut url = self.endpoint.clone();
        url.set_path(&raw_path);
        url.set_query(if raw_query.is_empty() {
            None
        } else {
            Some(&raw_query)
        });
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().to_string(),
        };
        let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
        let mut headers = vec![("host".to_string(), host)];
        if body.is_some() {
            headers.push(("content-type".into(), "application/json".into()));
        }
        let signed = sigv4::sign_headers(
            method,
            url.path(),
            url.query().unwrap_or(""),
            &headers,
            &bytes,
            &self.access_key,
            &self.secret_key,
            self.session_token.as_ref().map(|t| t.expose()),
            Ts::now(),
            &self.region,
            "s3",
        );
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| ClientError::Config(format!("bad method {method}")))?;
        let mut rb = self.http.request(m, url);
        for (k, v) in headers.iter().skip(1).chain(signed.iter()) {
            rb = rb.header(k.as_str(), v.as_str());
        }
        let resp = rb.body(bytes).send().await?;
        let status = resp.status();
        let rid = resp
            .headers()
            .get(crate::error::REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let text = resp.text().await?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
        if status.is_success() {
            return Ok(v);
        }
        let e = &v["error"];
        Err(ClientError::Api {
            status: status.as_u16(),
            code: e["code"].as_str().unwrap_or("Unknown").to_string(),
            message: e["message"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| v.to_string()),
            request_id: e["request_id"].as_str().unwrap_or(&rid).to_string(),
        })
    }
}
