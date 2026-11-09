//! rustls server configuration from PEM files.

use anyhow::Context as _;
use std::path::Path;
use std::sync::Arc;

/// Build a TLS acceptor from a PEM certificate chain and private key.
pub(crate) fn acceptor(cert: &Path, key: &Path) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert).with_context(|| format!("opening {}", cert.display()))?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .with_context(|| format!("parsing certificates in {}", cert.display()))?;
    anyhow::ensure!(!certs.is_empty(), "no certificates in {}", cert.display());
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key).with_context(|| format!("opening {}", key.display()))?,
    ))
    .with_context(|| format!("parsing private key in {}", key.display()))?
    .ok_or_else(|| anyhow::anyhow!("no private key in {}", key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building TLS configuration")?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}

/// Reload the certificate and key on SIGHUP (B6); a failed reload keeps the old acceptor.
pub(crate) async fn reload_on_sighup(
    acc: Arc<std::sync::RwLock<tokio_rustls::TlsAcceptor>>,
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    #[cfg(unix)]
    {
        let Ok(mut hup) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        else {
            return;
        };
        loop {
            tokio::select! {
                _ = stop.changed() => return,
                _ = hup.recv() => match acceptor(&cert, &key) {
                    Ok(a) => {
                        *acc.write().unwrap_or_else(|e| e.into_inner()) = a;
                        tracing::info!("TLS certificate reloaded");
                    }
                    Err(e) => tracing::error!(error = %e, "TLS reload failed; keeping the old certificate"),
                },
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (acc, cert, key);
        let _ = stop.changed().await;
    }
}
