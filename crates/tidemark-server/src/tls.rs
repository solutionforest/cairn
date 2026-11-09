//! rustls server configuration from PEM files.

use anyhow::Context as _;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::path::Path;
use std::sync::Arc;

/// Build a TLS acceptor from a PEM certificate chain and private key.
pub(crate) fn acceptor(cert: &Path, key: &Path) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    let certs = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("opening {}", cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parsing certificates in {}", cert.display()))?;
    anyhow::ensure!(!certs.is_empty(), "no certificates in {}", cert.display());
    let key = match PrivateKeyDer::from_pem_file(key) {
        Ok(k) => k,
        Err(pem::Error::NoItemsFound) => anyhow::bail!("no private key in {}", key.display()),
        Err(e) => {
            return Err(anyhow::Error::new(e))
                .with_context(|| format!("reading private key from {}", key.display()));
        }
    };
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

#[cfg(test)]
mod tests {
    use super::acceptor;
    use std::path::PathBuf;

    // Fixtures: a test-only self-signed P-256 pair, made with
    // `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 36500`
    // (key.pem is PKCS#8; key-sec1.pem is the same key via `openssl pkey -traditional`).
    fn fx(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls")
            .join(name)
    }

    #[test]
    fn loads_pkcs8_and_sec1_keys() {
        acceptor(&fx("cert.pem"), &fx("key.pem")).expect("pkcs8 key");
        acceptor(&fx("cert.pem"), &fx("key-sec1.pem")).expect("sec1 key");
    }

    #[test]
    fn errors_name_the_file_and_the_problem() {
        let msg = |r: anyhow::Result<_>| format!("{:#}", r.err().expect("must fail"));
        let e = msg(acceptor(&fx("cert.pem"), &fx("cert.pem")));
        assert!(
            e.contains("no private key in") && e.contains("cert.pem"),
            "{e}"
        );
        let e = msg(acceptor(&fx("key.pem"), &fx("key.pem")));
        assert!(
            e.contains("no certificates in") && e.contains("key.pem"),
            "{e}"
        );
        let e = msg(acceptor(&fx("missing.pem"), &fx("key.pem")));
        assert!(e.contains("opening") && e.contains("missing.pem"), "{e}");
        let e = msg(acceptor(&fx("cert.pem"), &fx("missing.pem")));
        assert!(e.contains("missing.pem"), "{e}");
    }

    #[test]
    fn key_must_match_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let other = dir.path().join("other.pem");
        let st = std::process::Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "EC",
                "-pkeyopt",
                "ec_paramgen_curve:prime256v1",
                "-out",
            ])
            .arg(&other)
            .status();
        if !matches!(st, Ok(s) if s.success()) {
            eprintln!("openssl not available; skipping");
            return;
        }
        let e = format!(
            "{:#}",
            acceptor(&fx("cert.pem"), &other).err().expect("mismatch")
        );
        assert!(e.contains("building TLS configuration"), "{e}");
    }
}
