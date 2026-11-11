#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Tidemark server: wires the engine, IAM (`tidemark-auth`), the `s3s` service, STS, the admin API,
//! MCP, events, metrics and audit into a hyper 1 server with optional rustls TLS, request ids,
//! trusted-proxy handling, background workers and graceful shutdown (DESIGN §3, §8–§12).

pub mod admin_engine;
pub mod audit;
mod backup;
pub mod clock;
mod http_layer;
pub mod metrics;
pub mod proxy;
pub mod scan;
pub use http_layer::ConnInfo;
pub mod test_support;
mod tls;
mod workers;

use anyhow::Context as _;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tidemark_auth::{
    BucketPolicyStore, CredentialStore, MasterKey, MetaCredentialBackend, SecretString,
    TidemarkS3Access, TidemarkS3Auth,
};
use tidemark_core::Config;
use tidemark_engine::{EngineConfig, EngineExtras, TidemarkEngine};
use tidemark_events::{Outbox, SinkConfig, SseBroadcast, WebhookSink};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;

pub use clock::{Clock, OffsetClock, SystemClock};
pub use metrics::Metrics;
pub use tidemark_engine;

/// Shared per-process state handed to every connection.
pub(crate) struct State {
    pub(crate) s3: s3s::service::S3Service,
    pub(crate) engine: TidemarkEngine,
    pub(crate) shutting_down: AtomicBool,
    /// `/_tidemark/...`: admin API, SSE stream, MCP.
    pub(crate) tidemark: axum::Router,
    pub(crate) sts: axum::Router,
    pub(crate) store: Arc<CredentialStore>,
    pub(crate) proxies: proxy::TrustedProxies,
    pub(crate) metrics: Arc<Metrics>,
    pub(crate) metrics_enabled: bool,
    pub(crate) audit: Option<audit::AuditLog>,
    pub(crate) audit_all: bool,
    /// Sink ids whose cursors bound the outbox (depth gauge, compaction).
    pub(crate) sink_ids: Vec<String>,
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
        // `send` drops the value when no receiver exists yet (a trigger before `run_until`).
        self.0.send_replace(true);
    }
}

/// A bound, not yet running server.
pub struct Server {
    listener: TcpListener,
    addr: SocketAddr,
    state: Arc<State>,
    tls: Option<Arc<RwLock<tokio_rustls::TlsAcceptor>>>,
    tls_files: Option<(std::path::PathBuf, std::path::PathBuf)>,
    grace: Duration,
    stop_tx: watch::Sender<bool>,
    workers: workers::Workers,
}

/// Engine settings derived from the server configuration.
pub fn engine_config(cfg: &Config) -> anyhow::Result<EngineConfig> {
    let at_rest_key = if cfg.storage.encrypt_at_rest {
        Some(tidemark_blob::DataKey::new(master_key_bytes(cfg)?))
    } else {
        None
    };
    Ok(EngineConfig {
        retention: cfg.retention.clone(),
        limits: cfg.limits.clone(),
        at_rest_key,
        fsync: cfg.storage.fsync,
        meta_cache: Some(cfg.storage.meta_cache_bytes()),
    })
}

fn read_or_create_key_bytes(path: &std::path::Path) -> anyhow::Result<[u8; 32]> {
    if let Ok(b) = std::fs::read(path) {
        return b
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("{} must contain exactly 32 bytes", path.display()));
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let k: [u8; 32] = rand::random();
    write_private(path, &k)?;
    Ok(k)
}

/// The 32-byte master key: `storage.master_key` / `storage.master_key_file` when configured
/// (never generated), else `keys/master.key`, created on first use.
pub fn master_key_bytes(cfg: &Config) -> anyhow::Result<[u8; 32]> {
    match cfg.configured_master_key().context("master key")? {
        Some(k) => Ok(k),
        None => read_or_create_key_bytes(&cfg.master_key_path()),
    }
}

/// Read the 32-byte master key, creating it (mode 0600) on first use.
pub fn load_or_create_master_key(path: &std::path::Path) -> anyhow::Result<tidemark_blob::DataKey> {
    Ok(tidemark_blob::DataKey::new(read_or_create_key_bytes(path)?))
}

/// Key sealing IAM secrets at rest, derived from the master key file.
pub fn iam_master_key(cfg: &Config) -> anyhow::Result<MasterKey> {
    let mk = master_key_bytes(cfg)?;
    Ok(MasterKey::new(blake3::derive_key(
        "tidemark iam secrets v1",
        &mk,
    )))
}

fn replication_key(cfg: &Config) -> anyhow::Result<[u8; 32]> {
    let mk = master_key_bytes(cfg)?;
    Ok(blake3::derive_key("tidemark replication targets", &mk))
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

/// Run pending metadata migrations (pre-upgrade snapshot included) before the store is opened.
pub async fn run_migrations(
    cfg: &Config,
) -> anyhow::Result<tidemark_meta::migrate::MigrationReport> {
    let path = cfg.meta_path();
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p)?;
    }
    let rep = tidemark_meta::migrate::migrate(&path, false)
        .await
        .context("metadata migration")?;
    if !rep.steps.is_empty() {
        tracing::warn!(from = ?rep.from, to = rep.to, steps = ?rep.steps, backup = ?rep.backup, "metadata migrated");
    }
    Ok(rep)
}

/// Open the engine the way `serve` does (migrations, events outbox, free-space guard, recovery).
pub async fn open_engine(cfg: &Config, outbox: Outbox) -> anyhow::Result<TidemarkEngine> {
    run_migrations(cfg).await?;
    let ecfg = engine_config(cfg)?;
    tracing::info!(
        meta_cache_mib = ecfg.meta_cache.unwrap_or_default() >> 20,
        auto = cfg.storage.meta_cache == 0,
        "metadata cache"
    );
    let space = (cfg.storage.min_free > 0).then(|| {
        tidemark_blob::space::SpaceGuard::new(&cfg.storage.data_dir, cfg.storage.min_free)
    });
    let engine = TidemarkEngine::open_with(
        &cfg.storage.data_dir,
        ecfg,
        EngineExtras {
            outbox,
            region: Some(cfg.server.region.clone()),
            space,
            scan: scan::scan_gate(&cfg.scan)?,
        },
    )
    .with_context(|| format!("opening data directory {}", cfg.storage.data_dir.display()))?;
    let report = engine.recover(false).await.context("startup recovery")?;
    if report.unclean_shutdown {
        tracing::warn!(?report, "recovered from an unclean shutdown");
    }
    Ok(engine)
}

/// The credential store over the engine's metadata, with the root credential bootstrapped
/// from config/env when given (`auth.root_access_key` / `auth.root_secret_key`, aliases
/// `TIDEMARK_ROOT_ACCESS_KEY` / `TIDEMARK_ROOT_SECRET`). Fails if no root credential exists at all.
pub async fn credential_store(
    cfg: &Config,
    engine: &TidemarkEngine,
) -> anyhow::Result<Arc<CredentialStore>> {
    credential_store_with_clock(cfg, engine, None).await
}

/// Adapts a server [`Clock`] to the IAM store's clock.
struct AuthClock(Arc<dyn Clock>);

impl tidemark_auth::Clock for AuthClock {
    fn now(&self) -> tidemark_auth::Ts {
        tidemark_auth::Ts(self.0.now().0)
    }
}

/// Closes the engine if [`Server::bind_with_clocks`] fails after opening it, so the metadata
/// database lock is released for a retry in the same process.
struct ShutdownOnDrop(Option<TidemarkEngine>);

impl Drop for ShutdownOnDrop {
    fn drop(&mut self) {
        if let Some(e) = self.0.take() {
            e.shutdown();
        }
    }
}

/// Startup error when the configured master key cannot unseal the credential store.
fn wrong_master_key(cfg: &Config) -> String {
    let source = match (&cfg.storage.master_key, &cfg.storage.master_key_file) {
        (Some(_), _) => "storage.master_key".to_string(),
        (None, Some(f)) => f.display().to_string(),
        (None, None) => cfg.master_key_path().display().to_string(),
    };
    format!(
        "the master key ({source}) cannot unseal this data dir's credential store: it is not the key the data dir was initialised with (check storage.master_key, storage.master_key_file and TIDEMARK_STORAGE_MASTER_KEY*)"
    )
}

async fn credential_store_with_clock(
    cfg: &Config,
    engine: &TidemarkEngine,
    clock: Option<Arc<dyn Clock>>,
) -> anyhow::Result<Arc<CredentialStore>> {
    let mut store = CredentialStore::new(
        Arc::new(MetaCredentialBackend::new(engine.meta().clone())),
        iam_master_key(cfg)?,
    );
    if let Some(c) = clock {
        store = store.with_clock(Arc::new(AuthClock(c)));
    }
    let store = Arc::new(store);
    match (&cfg.auth.root_access_key, &cfg.auth.root_secret_key) {
        (Some(ak), Some(sk)) => match store.ensure_root(ak, &SecretString::new(sk.clone())).await {
            Err(tidemark_auth::AuthError::Crypto) => anyhow::bail!(wrong_master_key(cfg)),
            r => r.context("installing root credentials from configuration")?,
        },
        _ => {
            let Some(root) = store.root_access_key_id().await? else {
                anyhow::bail!(
                    "no root credentials: run `tidemark init`, or set TIDEMARK_ROOT_ACCESS_KEY and TIDEMARK_ROOT_SECRET once to bootstrap them"
                );
            };
            // Unseal once now, so a master key other than the one this data dir was initialised
            // with stops startup instead of failing every authenticated request with a 500.
            if let Err(tidemark_auth::AuthError::Crypto) = store.lookup(&root).await {
                anyhow::bail!(wrong_master_key(cfg));
            }
        }
    }
    Ok(store)
}

fn sinks(cfg: &Config) -> anyhow::Result<Vec<WebhookSink>> {
    cfg.events
        .sinks
        .iter()
        .map(|t| {
            let sc: SinkConfig = toml::Value::Table(t.clone())
                .try_into()
                .context("parsing [[events.sinks]]")?;
            Ok(WebhookSink::from_config(sc)?)
        })
        .collect()
}

impl Server {
    /// Open the data directory (after migrations), run startup recovery, bootstrap IAM, build
    /// the S3 / STS / admin / MCP services and bind the listener.
    pub async fn bind(config: Config) -> anyhow::Result<Server> {
        Server::bind_with_clock(config, Arc::new(SystemClock)).await
    }

    /// [`Server::bind`] with an explicit clock for the GC and lifecycle workers.
    pub async fn bind_with_clock(config: Config, clock: Arc<dyn Clock>) -> anyhow::Result<Server> {
        Server::bind_with_clocks(config, clock, None).await
    }

    /// [`Server::bind_with_clock`] plus a clock for IAM (signature time checks, session and
    /// presign expiry). Tests only: production always uses the system clock for IAM.
    pub async fn bind_with_clocks(
        config: Config,
        clock: Arc<dyn Clock>,
        auth_clock: Option<Arc<dyn Clock>>,
    ) -> anyhow::Result<Server> {
        let problems = config.validate();
        if !problems.is_empty() {
            anyhow::bail!("invalid configuration:\n  - {}", problems.join("\n  - "));
        }
        let sinks = sinks(&config)?;
        let outbox = Outbox::new(config.events.sse);
        let engine = open_engine(&config, outbox.clone()).await?;
        let mut engine_guard = ShutdownOnDrop(Some(engine.clone()));
        let store = credential_store_with_clock(&config, &engine, auth_clock).await?;
        engine
            .ensure_quarantine_bucket(&tidemark_core::PrincipalId::root())
            .await
            .with_context(|| {
                format!(
                    "creating the scan quarantine bucket {:?}",
                    config.scan.quarantine_bucket
                )
            })?;
        if let Some(ep) = config.scan.endpoint() {
            tracing::info!(endpoint = %ep, quarantine = %config.scan.quarantine_bucket, "malware scanning enabled");
        }
        let policies = Arc::new(BucketPolicyStore::new(engine.meta().clone()));
        let access = TidemarkS3Access::new(store.clone(), policies.clone());
        let mut sink_arns = Vec::new();
        for s in &sinks {
            sink_arns.extend(s.arns());
        }
        let s3 = tidemark_s3::TidemarkS3Builder::new(engine.clone(), config.server.region.clone())
            .with_auth(Arc::new(TidemarkS3Auth::new(store.clone())))
            .with_access(tidemark_s3::ObservedAccess(access.clone()))
            .with_access_checker(access)
            .with_policies(policies.clone())
            .with_sink_arns(sink_arns)
            .with_domain(config.server.domain.clone())
            .build()?;
        let sse = config
            .events
            .sse
            .then(|| SseBroadcast::new(config.events.sse_buffer));
        let metrics = Arc::new(Metrics::new());
        metrics.gc_last_success.set(tidemark_core::Ts::now().secs());
        let backups = backup::BackupRunner::new(engine.clone(), &config.backup, metrics.clone());
        if let Some(b) = &backups {
            b.load_last_success().await;
        }
        let admin_state = tidemark_admin::AdminState::new(
            store.clone(),
            Arc::new(
                admin_engine::EngineAdmin::new(engine.clone(), config.server.region.clone())
                    .with_backup(backups),
            ),
        );
        let extra = sse.as_ref().map(|b| workers::sse_routes(b.clone()));
        let mut tidemark =
            tidemark_admin::router_with_extra(admin_state, extra, "tidemark:SubscribeEvents");
        if config.mcp.enabled {
            let mcp = tidemark_mcp::McpState::new(engine.clone(), store.clone(), policies.clone());
            tidemark = tidemark.merge(tidemark_mcp::http_router(mcp));
        }
        // OIDC federation is shelved for v0.1 (BUILD-PLAN): AssumeRoleWithWebIdentity is never
        // given a verifier, so it answers "not configured" whatever the config says.
        if !config.auth.oidc_providers.is_empty() {
            tracing::warn!(
                "auth.oidc_providers is set but OIDC federation is not part of v0.1; ignoring it"
            );
        }
        let sts = tidemark_auth::sts::router(tidemark_auth::sts::StsState::new(store.clone()));
        let audit = if config.audit.enabled {
            let path = config
                .audit
                .path
                .clone()
                .unwrap_or_else(|| config.storage.data_dir.join("audit").join("audit.jsonl"));
            Some(
                audit::AuditLog::start(&path, config.audit.max_bytes, config.audit.keep)
                    .with_context(|| format!("opening audit log {}", path.display()))?,
            )
        } else {
            None
        };
        let tls_files = match (&config.server.tls_cert, &config.server.tls_key) {
            (Some(c), Some(k)) => Some((c.clone(), k.clone())),
            _ => None,
        };
        let tls = match &tls_files {
            Some((c, k)) => Some(Arc::new(RwLock::new(tls::acceptor(c, k)?))),
            None => None,
        };
        let listener = TcpListener::bind(&config.server.listen)
            .await
            .with_context(|| format!("binding {}", config.server.listen))?;
        let addr = listener.local_addr()?;
        let (stop_tx, _) = watch::channel(false);
        let mut sink_ids: Vec<String> = sinks
            .iter()
            .map(|s| tidemark_events::Sink::id(s).to_string())
            .collect();
        if let Some(b) = &sse {
            sink_ids.push(tidemark_events::Sink::id(b).to_string());
        }
        let workers = workers::Workers {
            clock,
            gc_interval: config.retention.gc_interval,
            lifecycle_interval: config.retention.lifecycle_interval,
            stats_interval: config.metrics.stats_interval,
            events_enabled: config.events.enabled,
            max_attempts: config.events.max_attempts,
            sinks,
            sse,
            outbox,
            replication_key: replication_key(&config)?,
            scrub: config
                .storage
                .scrub
                .then(|| tidemark_engine::scrub::ScrubConfig {
                    bytes_per_sec: config.storage.scrub_bytes_per_sec,
                    ..Default::default()
                }),
            scrub_idle: config.storage.scrub_idle,
            targets: Arc::new(tidemark_engine::replication::TargetRegistry::new(
                &engine,
                replication_key(&config)?,
            )),
        };
        tracing::info!(%addr, tls = tls.is_some(), data_dir = %config.storage.data_dir.display(), "tidemark listening");
        engine_guard.0 = None;
        Ok(Server {
            listener,
            addr,
            state: Arc::new(State {
                s3,
                engine,
                shutting_down: AtomicBool::new(false),
                tidemark,
                sts,
                store,
                proxies: proxy::TrustedProxies::new(&config.server.trusted_proxies),
                metrics,
                metrics_enabled: config.metrics.enabled,
                audit,
                audit_all: config.audit.all_requests,
                sink_ids,
            }),
            tls,
            tls_files,
            grace: config.server.shutdown_grace,
            stop_tx,
            workers,
        })
    }

    /// The bound address (useful with port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The engine behind the server.
    pub fn engine(&self) -> &TidemarkEngine {
        &self.state.engine
    }

    /// The IAM credential store.
    pub fn credential_store(&self) -> &Arc<CredentialStore> {
        &self.state.store
    }

    /// Server metrics.
    pub fn metrics(&self) -> &Arc<Metrics> {
        &self.state.metrics
    }

    /// Replication target registry (remote endpoints referenced by replication rules).
    pub fn replication_targets(&self) -> &Arc<tidemark_engine::replication::TargetRegistry> {
        &self.workers.targets
    }

    /// Handle that starts a graceful shutdown when triggered.
    pub fn shutdown_trigger(&self) -> ShutdownTrigger {
        ShutdownTrigger(self.stop_tx.clone())
    }

    /// Serve until SIGTERM / ctrl-c or a [`ShutdownTrigger`], then drain in-flight requests for
    /// up to `server.shutdown_grace`, stop background work and close the metadata store.
    pub async fn run(self) -> anyhow::Result<()> {
        self.run_until(async {
            os_signal().await;
            tracing::info!("shutdown signal received");
        })
        .await
    }

    /// Like [`Server::run`] but stops when `signal` completes (a [`ShutdownTrigger`] also
    /// always works).
    pub async fn run_until(self, signal: impl Future<Output = ()>) -> anyhow::Result<()> {
        let Server {
            listener,
            state,
            tls,
            tls_files,
            grace,
            stop_tx,
            workers,
            ..
        } = self;
        let mut stop_rx = stop_tx.subscribe();
        let signal = async move {
            tokio::select! {
                _ = signal => {}
                _ = async { let _ = stop_rx.wait_for(|v| *v).await.map(|_| ()); } => {
                    tracing::info!("shutdown requested");
                }
            }
        };
        let (bg_stop, bg_rx) = watch::channel(false);
        let mut bg = workers.spawn(state.clone(), bg_rx.clone());
        if let (Some(acc), Some((c, k))) = (&tls, tls_files) {
            bg.spawn(tls::reload_on_sighup(acc.clone(), c, k, bg_rx));
        }
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
                    let acc = tls.as_ref().map(|t| t.read().unwrap_or_else(|e| e.into_inner()).clone());
                    conns.spawn(async move {
                        match acc {
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
        if tokio::time::timeout(grace, graceful.shutdown())
            .await
            .is_err()
        {
            tracing::warn!("drain timeout elapsed; aborting remaining connections");
        }
        conns.abort_all();
        while conns.join_next().await.is_some() {}
        let _ = bg_stop.send(true);
        if tokio::time::timeout(Duration::from_secs(10), async {
            while bg.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            tracing::warn!("background workers did not stop in time; aborting them");
            bg.abort_all();
        }
        state.engine.shutdown();
        tracing::info!("shutdown complete");
        Ok(())
    }
}

async fn os_signal() {
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
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
