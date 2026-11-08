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
