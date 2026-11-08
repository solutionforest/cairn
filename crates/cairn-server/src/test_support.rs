//! Helpers for integration tests: an in-process server on `127.0.0.1:0` over a temp dir.

use crate::Server;
use cairn_core::Config;
use std::net::SocketAddr;
use std::path::Path;

/// Root access key used by [`spawn`].
pub const TEST_ACCESS_KEY: &str = "CAIRNTESTROOT0000000";
/// Root secret key used by [`spawn`].
pub const TEST_SECRET_KEY: &str = "cairn-test-root-secret-key-0000000000000";

/// Root credentials of a test server.
#[derive(Debug, Clone)]
pub struct RootCreds {
    /// Access key id.
    pub access_key: String,
    /// Secret key.
    pub secret_key: String,
}

/// Stops a spawned server and waits until it has fully shut down (database closed).
pub struct ShutdownHandle {
    trigger: crate::ShutdownTrigger,
    join: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl ShutdownHandle {
    /// Trigger graceful shutdown and wait for it to complete.
    pub async fn shutdown(self) -> anyhow::Result<()> {
        self.trigger.trigger();
        self.join.await?
    }
}

/// Test configuration over `dir` (no fsync, ephemeral port, fixed root credentials).
pub fn test_config(dir: &Path) -> Config {
    let mut c = Config::default();
    c.server.listen = "127.0.0.1:0".into();
    c.server.shutdown_grace = std::time::Duration::from_secs(5);
    c.storage.data_dir = dir.to_path_buf();
    c.storage.fsync = false;
    c.auth.root_access_key = Some(TEST_ACCESS_KEY.into());
    c.auth.root_secret_key = Some(TEST_SECRET_KEY.into());
    c
}

/// Start a server over `dir` with [`test_config`].
pub async fn spawn(dir: &Path) -> (SocketAddr, RootCreds, ShutdownHandle) {
    spawn_with(test_config(dir)).await
}

/// Start a server with an explicit configuration.
pub async fn spawn_with(config: Config) -> (SocketAddr, RootCreds, ShutdownHandle) {
    let creds = RootCreds {
        access_key: config.auth.root_access_key.clone().unwrap_or_default(),
        secret_key: config.auth.root_secret_key.clone().unwrap_or_default(),
    };
    let server = Server::bind(config).await.expect("bind test server");
    let addr = server.local_addr();
    let trigger = server.shutdown_trigger();
    let join = tokio::spawn(server.run_until(async move {
        std::future::pending::<()>().await;
    }));
    let _ = &join;
    (addr, creds, ShutdownHandle { trigger, join })
}
