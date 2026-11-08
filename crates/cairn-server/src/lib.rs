#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Cairn server: wires the engine, the `s3s` service and the health endpoints into a hyper 1
//! server with optional rustls TLS, request ids, tracing and graceful shutdown (DESIGN §3, §12).

mod http_layer;
pub use http_layer::ConnInfo;
pub mod test_support;
mod tls;

use anyhow::Context as _;
use cairn_core::{Config, Ts};
use cairn_engine::{CairnEngine, EngineConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

pub use cairn_engine;

/// Shared per-process state handed to every connection.
pub(crate) struct State {
    pub(crate) s3: s3s::service::S3Service,
    pub(crate) engine: CairnEngine,
    pub(crate) shutting_down: AtomicBool,
}

impl State {
    pub(crate) fn ready(&self) -> bool {
        !self.shutting_down.load(Ordering::SeqCst) && self.engine.ready()
    }
}

/// Asks a running [`Server`] to shut down gracefully.
#[derive(Clone)]
pub struct ShutdownTrigger(watch::Sender<bool>);

impl ShutdownTrigger {
    /// Begin graceful shutdown.
    pub fn trigger(&self) {
        let _ = self.0.send(true);
    }
}

/// A bound, not yet running server.
pub struct Server {
    listener: TcpListener,
    addr: SocketAddr,
    state: Arc<State>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    grace: Duration,
    gc_interval: Duration,
    stop_tx: watch::Sender<bool>,
}

/// Engine settings derived from the server configuration.
pub fn engine_config(cfg: &Config) -> anyhow::Result<EngineConfig> {
    let at_rest_key = if cfg.storage.encrypt_at_rest {
        Some(load_or_create_master_key(&cfg.master_key_path())?)
    } else {
        None
    };
    Ok(EngineConfig {
        retention: cfg.retention.clone(),
        limits: cfg.limits.clone(),
        at_rest_key,
        fsync: cfg.storage.fsync,
    })
}

/// Read the 32-byte master key, creating it (mode 0600) on first use.
pub fn load_or_create_master_key(path: &std::path::Path) -> anyhow::Result<cairn_blob::DataKey> {
    if let Ok(b) = std::fs::read(path) {
        let k: [u8; 32] = b
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} must contain exactly 32 bytes", path.display()))?;
        return Ok(cairn_blob::DataKey::new(k));
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let k: [u8; 32] = rand::random();
    write_private(path, &k)?;
    Ok(cairn_blob::DataKey::new(k))
}

/// Write a file readable only by the owner.
pub fn write_private(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

impl Server {
    /// Open the data directory, run startup recovery, build the S3 service and bind the listener.
    pub async fn bind(config: Config) -> anyhow::Result<Server> {
        let problems = config.validate();
        if !problems.is_empty() {
            anyhow::bail!("invalid configuration:\n  - {}", problems.join("\n  - "));
        }
        let ecfg = engine_config(&config)?;
        let engine = CairnEngine::open(&config.storage.data_dir, ecfg).with_context(|| {
            format!("opening data directory {}", config.storage.data_dir.display())
        })?;
        let report = engine.recover(false).await.context("startup recovery")?;
        if report.unclean_shutdown {
            tracing::warn!(?report, "recovered from an unclean shutdown");
        }
        let (ak, sk) = (
            config.auth.root_access_key.clone().unwrap_or_default(),
            config.auth.root_secret_key.clone().unwrap_or_default(),
        );
        let s3 = cairn_s3::CairnS3Builder::new(engine.clone(), config.server.region.clone())
            .with_root_credentials(&ak, &sk)
            .with_domain(config.server.domain.clone())
            .build()?;
        let tls = match (&config.server.tls_cert, &config.server.tls_key) {
            (Some(c), Some(k)) => Some(tls::acceptor(c, k)?),
            _ => None,
        };
        let listener = TcpListener::bind(&config.server.listen)
            .await
            .with_context(|| format!("binding {}", config.server.listen))?;
        let addr = listener.local_addr()?;
        let (stop_tx, _) = watch::channel(false);
        tracing::info!(%addr, tls = tls.is_some(), data_dir = %config.storage.data_dir.display(), "cairn listening");
        Ok(Server {
            listener,
            addr,
            state: Arc::new(State {
                s3,
                engine,
                shutting_down: AtomicBool::new(false),
            }),
            tls,
            grace: config.server.shutdown_grace,
            gc_interval: config.retention.gc_interval,
            stop_tx,
        })
    }

    /// The bound address (useful with port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The engine behind the server.
    pub fn engine(&self) -> &CairnEngine {
        &self.state.engine
    }

    /// Handle that starts a graceful shutdown when triggered.
    pub fn shutdown_trigger(&self) -> ShutdownTrigger {
        ShutdownTrigger(self.stop_tx.clone())
    }

    /// Serve until SIGTERM / ctrl-c or a [`ShutdownTrigger`], then drain in-flight requests for
    /// up to `server.shutdown_grace`, stop background work and close the metadata store.
    pub async fn run(self) -> anyhow::Result<()> {
        let mut stop_rx = self.stop_tx.subscribe();
        let signal = async move {
            tokio::select! {
                _ = os_signal() => tracing::info!("shutdown signal received"),
                _ = async { let _ = stop_rx.wait_for(|v| *v).await.map(|_| ()); } => tracing::info!("shutdown requested"),
            }
        };
        self.run_until(signal).await
    }

    /// Like [`Server::run`] but stops when `signal` completes.
    pub async fn run_until(self, signal: impl Future<Output = ()>) -> anyhow::Result<()> {
        let Server {
            listener,
            state,
            tls,
            grace,
            gc_interval,
            ..
        } = self;
        let (bg_stop, bg_rx) = watch::channel(false);
        let gc = tokio::spawn(gc_loop(state.engine.clone(), gc_interval, bg_rx));
        let graceful = hyper_util::server::graceful::GracefulShutdown::new();
        let mut conns = JoinSet::new();
        tokio::pin!(signal);
        loop {
            tokio::select! {
                _ = &mut signal => break,
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!(error = %e, "accept failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);
                    let watcher = graceful.watcher();
                    let st = state.clone();
                    let tls = tls.clone();
                    conns.spawn(async move {
                        match tls {
                            None => http_layer::serve(st, stream, peer, false, watcher).await,
                            Some(acc) => {
                                let hs = tokio::time::timeout(Duration::from_secs(10), acc.accept(stream)).await;
                                let Ok(Ok(tls_stream)) = hs else {
                                    tracing::debug!(%peer, "TLS handshake failed");
                                    return;
                                };
                                http_layer::serve(st, tls_stream, peer, true, watcher).await;
                            }
                        }
                    });
                }
            }
        }
        state.shutting_down.store(true, Ordering::SeqCst);
        drop(listener);
        tracing::info!(in_flight = graceful.count(), ?grace, "draining connections");
        if tokio::time::timeout(grace, graceful.shutdown()).await.is_err() {
            tracing::warn!("drain timeout elapsed; aborting remaining connections");
        }
        conns.abort_all();
        while conns.join_next().await.is_some() {}
        let _ = bg_stop.send(true);
        let _ = gc.await;
        state.engine.shutdown();
        tracing::info!("shutdown complete");
        Ok(())
    }
}

async fn gc_loop(engine: CairnEngine, every: Duration, mut stop: watch::Receiver<bool>) {
    let every = every.max(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = stop.changed() => return,
            _ = tokio::time::sleep(every) => {
                if let Err(e) = engine.gc_tick(Ts::now()).await {
                    tracing::warn!(error = %e, "gc tick failed");
                }
            }
        }
    }
}

async fn os_signal() {
    #[cfg(unix)]
    {
        let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
