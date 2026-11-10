//! Malware scanner clients for `[scan] endpoint` (the engine side is `tidemark_engine::scan`).
//!
//! - `clamd://host:port` / `clamd:///path/to/clamd.sock`: ClamAV's `INSTREAM` command.
//! - `http://host:port/path`: the object is POSTed as the request body; the endpoint answers
//!   `200` with `{"infected": false}` or `{"infected": true, "signature": "<name>"}`. Anything
//!   else (other status, bad JSON, timeout) counts as "no verdict". Wrap VirusTotal, a
//!   commercial engine or your own rules behind such an endpoint.

use bytes::Bytes;
use futures::StreamExt;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use std::sync::Arc;
use std::time::Duration;
use tidemark_core::config::{ScanConfig, ScanFailMode};
use tidemark_engine::scan::{OnError, ScanGate, ScanRequest, Scanner, Verdict};
use tidemark_engine::types::BodyStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest clamd reply read.
const MAX_REPLY: u64 = 4096;

/// Build the engine scan gate from `[scan]`; `None` when no endpoint is configured.
pub fn scan_gate(cfg: &ScanConfig) -> anyhow::Result<Option<ScanGate>> {
    let Some(ep) = cfg.endpoint() else {
        return Ok(None);
    };
    let scanner: Arc<dyn Scanner> = if let Some(rest) = ep.strip_prefix("clamd://") {
        let addr = if let Some(path) = rest.strip_prefix('/') {
            ClamdAddr::Unix(format!("/{path}").into())
        } else {
            ClamdAddr::Tcp(rest.trim_end_matches('/').to_string())
        };
        Arc::new(Clamd {
            addr,
            timeout: cfg.timeout,
        })
    } else if ep.starts_with("http://") {
        let uri: hyper::Uri = ep
            .parse()
            .map_err(|e| anyhow::anyhow!("scan.endpoint {ep:?}: {e}"))?;
        Arc::new(HttpScanner::new(uri, cfg.timeout))
    } else {
        anyhow::bail!("scan.endpoint {ep:?}: expected clamd:// or http://");
    };
    let mode = |m: ScanFailMode| match m {
        ScanFailMode::Reject => OnError::Reject,
        ScanFailMode::Allow => OnError::Allow,
    };
    Ok(Some(ScanGate {
        scanner,
        quarantine_bucket: cfg.quarantine_bucket.clone(),
        max_size: cfg.max_size,
        on_error: mode(cfg.on_error),
        on_oversize: mode(cfg.on_oversize),
    }))
}

enum ClamdAddr {
    Tcp(String),
    Unix(std::path::PathBuf),
}

/// ClamAV daemon client (`zINSTREAM`).
struct Clamd {
    addr: ClamdAddr,
    timeout: Duration,
}

#[async_trait::async_trait]
impl Scanner for Clamd {
    async fn scan(&self, _req: ScanRequest, body: BodyStream) -> Result<Verdict, String> {
        let run = async {
            match &self.addr {
                ClamdAddr::Tcp(a) => {
                    let s = tokio::net::TcpStream::connect(a)
                        .await
                        .map_err(|e| format!("clamd connect {a}: {e}"))?;
                    instream(s, body).await
                }
                ClamdAddr::Unix(p) => {
                    let s = tokio::net::UnixStream::connect(p)
                        .await
                        .map_err(|e| format!("clamd connect {}: {e}", p.display()))?;
                    instream(s, body).await
                }
            }
        };
        tokio::time::timeout(self.timeout, run)
            .await
            .map_err(|_| "clamd timed out".to_string())?
    }
}

/// Send the body with `INSTREAM` framing (u32 BE length + bytes, zero length ends) and parse
/// the reply. If clamd hangs up mid-stream (size limit), its reply still says why.
async fn instream<S: AsyncRead + AsyncWrite + Unpin>(
    mut s: S,
    mut body: BodyStream,
) -> Result<Verdict, String> {
    let sent = async {
        s.write_all(b"zINSTREAM\0").await?;
        while let Some(chunk) = body.next().await {
            let chunk = chunk?;
            if chunk.is_empty() {
                continue;
            }
            for piece in chunk.chunks(u32::MAX as usize) {
                s.write_all(&(piece.len() as u32).to_be_bytes()).await?;
                s.write_all(piece).await?;
            }
        }
        s.write_all(&0u32.to_be_bytes()).await?;
        s.flush().await
    }
    .await;
    let mut reply = Vec::new();
    let read = (&mut s).take(MAX_REPLY).read_to_end(&mut reply).await;
    match (parse_clamd_reply(&reply), sent, read) {
        (Some(v), _, _) => v,
        (None, Err(e), _) | (None, Ok(()), Err(e)) => Err(format!("clamd: {e}")),
        (None, Ok(()), Ok(_)) => Err("clamd closed the connection without a reply".into()),
    }
}

/// `stream: OK` → clean, `stream: <sig> FOUND` → infected, `… ERROR` → error.
fn parse_clamd_reply(raw: &[u8]) -> Option<Result<Verdict, String>> {
    let text = String::from_utf8_lossy(raw);
    let line = text.trim_end_matches(['\0', '\n', '\r']).trim();
    if line.is_empty() {
        return None;
    }
    let body = line.strip_prefix("stream:").map(str::trim).unwrap_or(line);
    Some(if body == "OK" {
        Ok(Verdict::Clean)
    } else if let Some(sig) = body.strip_suffix(" FOUND") {
        Ok(Verdict::Infected(sig.trim().to_string()))
    } else {
        Err(format!("clamd: {body}"))
    })
}

/// Generic HTTP endpoint.
struct HttpScanner {
    uri: hyper::Uri,
    timeout: Duration,
    client: hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        ScanBody,
    >,
}

type ScanBody = http_body_util::combinators::BoxBody<Bytes, std::io::Error>;

impl HttpScanner {
    fn new(uri: hyper::Uri, timeout: Duration) -> HttpScanner {
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        HttpScanner {
            uri,
            timeout,
            client,
        }
    }
}

#[derive(serde::Deserialize)]
struct HttpVerdict {
    infected: bool,
    #[serde(default)]
    signature: Option<String>,
}

#[async_trait::async_trait]
impl Scanner for HttpScanner {
    async fn scan(&self, req: ScanRequest, body: BodyStream) -> Result<Verdict, String> {
        let stream = body.map(|r| r.map(Frame::data));
        let body: ScanBody = BodyExt::boxed(StreamBody::new(stream));
        let request = hyper::Request::post(self.uri.clone())
            .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
            .header(hyper::header::CONTENT_LENGTH, req.size)
            .header("x-tidemark-bucket", &req.bucket)
            .header(
                "x-tidemark-key",
                tidemark_auth::sigv4::uri_encode(req.key.as_bytes(), true),
            )
            .body(body)
            .map_err(|e| format!("scan request: {e}"))?;
        let run = async {
            let resp = self
                .client
                .request(request)
                .await
                .map_err(|e| format!("scan endpoint: {e}"))?;
            let status = resp.status();
            let raw = http_body_util::Limited::new(resp.into_body(), 64 * 1024)
                .collect()
                .await
                .map_err(|e| format!("scan endpoint body: {e}"))?
                .to_bytes();
            if status != hyper::StatusCode::OK {
                return Err(format!("scan endpoint answered {status}"));
            }
            let v: HttpVerdict = serde_json::from_slice(&raw)
                .map_err(|e| format!("scan endpoint reply is not a verdict: {e}"))?;
            Ok(if v.infected {
                Verdict::Infected(v.signature.unwrap_or_else(|| "unnamed".into()))
            } else {
                Verdict::Clean
            })
        };
        tokio::time::timeout(self.timeout, run)
            .await
            .map_err(|_| "scan endpoint timed out".to_string())?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamd_replies() {
        assert_eq!(parse_clamd_reply(b"stream: OK\0"), Some(Ok(Verdict::Clean)));
        assert_eq!(
            parse_clamd_reply(b"stream: Eicar-Test-Signature FOUND\0"),
            Some(Ok(Verdict::Infected("Eicar-Test-Signature".into())))
        );
        assert!(matches!(
            parse_clamd_reply(b"INSTREAM size limit exceeded. ERROR\0"),
            Some(Err(e)) if e.contains("size limit")
        ));
        assert_eq!(parse_clamd_reply(b""), None);
    }

    #[test]
    fn endpoints() {
        let mut c = ScanConfig::default();
        assert!(scan_gate(&c).unwrap().is_none());
        c.endpoint = Some("  ".into());
        assert!(scan_gate(&c).unwrap().is_none(), "blank endpoint means off");
        for ep in [
            "clamd://127.0.0.1:3310",
            "clamd:///run/clamd.sock",
            "http://127.0.0.1:8080/scan",
        ] {
            c.endpoint = Some(ep.into());
            assert!(scan_gate(&c).unwrap().is_some(), "{ep}");
        }
        c.endpoint = Some("ftp://x".into());
        assert!(scan_gate(&c).is_err());
    }
}
