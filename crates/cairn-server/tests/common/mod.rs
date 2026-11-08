//! Shared helpers for integration tests: in-process server + aws-sdk-s3 client.
#![allow(dead_code)]

use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::{BehaviorVersion, Region};
use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::primitives::ByteStream;
use cairn_server::test_support::{RootCreds, ShutdownHandle, spawn};
use std::net::SocketAddr;

pub struct Env {
    pub dir: tempfile::TempDir,
    pub addr: SocketAddr,
    pub creds: RootCreds,
    pub handle: Option<ShutdownHandle>,
    pub s3: Client,
}

impl Env {
    pub async fn new() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let (addr, creds, handle) = spawn(dir.path()).await;
        let s3 = client(addr, &creds);
        Env {
            dir,
            addr,
            creds,
            handle: Some(handle),
            s3,
        }
    }

    /// Stop the server and start a fresh one over the same data directory.
    pub async fn restart(&mut self) {
        self.handle.take().unwrap().shutdown().await.unwrap();
        let (addr, creds, handle) = spawn(self.dir.path()).await;
        self.addr = addr;
        self.s3 = client(addr, &creds);
        self.creds = creds;
        self.handle = Some(handle);
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub async fn bucket(&self, name: &str) {
        self.s3.create_bucket().bucket(name).send().await.unwrap();
    }

    pub async fn put(&self, bucket: &str, key: &str, data: impl Into<Vec<u8>>) -> String {
        self.s3
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(data.into()))
            .send()
            .await
            .unwrap()
            .e_tag
            .unwrap()
    }

    pub async fn get(&self, bucket: &str, key: &str) -> Vec<u8> {
        self.s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .unwrap()
            .body
            .collect()
            .await
            .unwrap()
            .into_bytes()
            .to_vec()
    }

    pub async fn stop(mut self) {
        if let Some(h) = self.handle.take() {
            h.shutdown().await.unwrap();
        }
    }
}

pub fn client(addr: SocketAddr, creds: &RootCreds) -> Client {
    let conf = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(format!("http://{addr}"))
        .force_path_style(true)
        .credentials_provider(Credentials::new(
            &creds.access_key,
            &creds.secret_key,
            None,
            None,
            "cairn-test",
        ))
        .http_client(aws_smithy_http_client::Builder::new().build_http())
        .build();
    Client::from_conf(conf)
}

/// Error code of a failed SDK call.
pub fn code<E: ProvideErrorMetadata, R>(r: Result<R, E>) -> String {
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.code().unwrap_or("<none>").to_string(),
    }
}

/// HTTP status of a failed SDK call.
pub fn status<E, R>(
    r: Result<R, aws_sdk_s3::error::SdkError<E, aws_sdk_s3::config::http::HttpResponse>>,
) -> u16
where
    E: std::fmt::Debug,
{
    match r {
        Ok(_) => panic!("expected an error"),
        Err(e) => e.raw_response().map(|r| r.status().as_u16()).unwrap_or(0),
    }
}

/// A server that also exposes its engine, an admin client and the clock its workers use.
pub struct Node {
    pub addr: SocketAddr,
    pub s3: Client,
    pub admin: cairn_admin::client::AdminClient,
    pub engine: Option<cairn_server::cairn_engine::CairnEngine>,
    trigger: Option<cairn_server::ShutdownTrigger>,
    join: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

impl Node {
    /// Start a server with `config` and the given worker clock.
    pub async fn start_with_clock(
        config: cairn_core::Config,
        clock: std::sync::Arc<dyn cairn_server::Clock>,
    ) -> Node {
        let creds = RootCreds {
            access_key: config.auth.root_access_key.clone().unwrap_or_default(),
            secret_key: config.auth.root_secret_key.clone().unwrap_or_default(),
        };
        let server = cairn_server::Server::bind_with_clock(config, clock)
            .await
            .expect("bind test server");
        let addr = server.local_addr();
        let engine = server.engine().clone();
        let trigger = server.shutdown_trigger();
        let join = tokio::spawn(server.run_until(std::future::pending::<()>()));
        let admin = cairn_admin::client::AdminClient::new(
            &format!("http://{addr}"),
            &creds.access_key,
            cairn_auth::SecretString::from(creds.secret_key.as_str()),
            None,
            "us-east-1",
        )
        .unwrap();
        Node {
            addr,
            s3: client(addr, &creds),
            admin,
            engine: Some(engine),
            trigger: Some(trigger),
            join: Some(join),
        }
    }

    /// Start a server with `config` and the system clock.
    pub async fn start(config: cairn_core::Config) -> Node {
        Node::start_with_clock(config, std::sync::Arc::new(cairn_server::SystemClock)).await
    }

    /// Start a server over `dir` with the default test configuration.
    pub async fn open(dir: &std::path::Path) -> Node {
        Node::start(cairn_server::test_support::test_config(dir)).await
    }

    pub fn engine(&self) -> &cairn_server::cairn_engine::CairnEngine {
        self.engine.as_ref().unwrap()
    }

    /// Graceful shutdown; the database is closed when this returns.
    pub async fn stop(mut self) {
        self.engine.take();
        self.trigger.take().unwrap().trigger();
        self.join.take().unwrap().await.unwrap().unwrap();
    }

    pub async fn admin(
        &self,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> serde_json::Value {
        self.admin
            .call(method, path, &[], body.as_ref())
            .await
            .unwrap_or_else(|e| panic!("{method} {path}: {e}"))
    }

    /// Create IAM user `name` with an inline policy; returns an S3 client signed with its key
    /// and the key pair.
    pub async fn user_with_policy(
        &self,
        name: &str,
        policy: serde_json::Value,
    ) -> (Client, RootCreds) {
        self.admin("POST", "/users", Some(serde_json::json!({ "name": name })))
            .await;
        self.admin(
            "PUT",
            &format!("/users/{name}/policies/inline"),
            Some(serde_json::json!({ "document": policy })),
        )
        .await;
        let k = self
            .admin("POST", &format!("/users/{name}/access-keys"), None)
            .await;
        let creds = RootCreds {
            access_key: k["access_key_id"].as_str().unwrap().into(),
            secret_key: k["secret_access_key"].as_str().unwrap().into(),
        };
        (client(self.addr, &creds), creds)
    }

    pub async fn bucket(&self, name: &str) {
        self.s3.create_bucket().bucket(name).send().await.unwrap();
    }

    pub async fn put(&self, bucket: &str, key: &str, data: impl Into<Vec<u8>>) -> String {
        self.s3
            .put_object()
            .bucket(bucket)
            .key(key)
            .body(ByteStream::from(data.into()))
            .send()
            .await
            .unwrap()
            .e_tag
            .unwrap()
    }

    pub async fn get(&self, bucket: &str, key: &str) -> Vec<u8> {
        self.s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .unwrap()
            .body
            .collect()
            .await
            .unwrap()
            .into_bytes()
            .to_vec()
    }

    /// GET `key` as of `at` (`x-cairn-as-of`, nanoseconds or RFC 3339).
    pub async fn get_as_of(&self, bucket: &str, key: &str, at: &str) -> Result<Vec<u8>, String> {
        let at = at.to_string();
        match self
            .s3
            .get_object()
            .bucket(bucket)
            .key(key)
            .customize()
            .mutate_request(move |r| {
                r.headers_mut().insert("x-cairn-as-of", at.clone());
            })
            .send()
            .await
        {
            Ok(o) => Ok(o.body.collect().await.unwrap().into_bytes().to_vec()),
            Err(e) => Err(e.code().unwrap_or("<none>").to_string()),
        }
    }
}

/// Current wall time as an RFC 3339 string with nanoseconds, after a small sleep on both sides
/// so it lies strictly between surrounding writes.
pub async fn instant() -> String {
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let t = jiff::Timestamp::now().to_string();
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    t
}

/// Files and total bytes under `dir/blobs` (recursive).
pub fn blob_files(dir: &std::path::Path) -> (usize, u64) {
    fn walk(p: &std::path::Path, acc: &mut (usize, u64)) {
        let Ok(rd) = std::fs::read_dir(p) else {
            return;
        };
        for e in rd.flatten() {
            let m = e.metadata().unwrap();
            if m.is_dir() {
                walk(&e.path(), acc);
            } else {
                acc.0 += 1;
                acc.1 += m.len();
            }
        }
    }
    let mut acc = (0, 0);
    walk(&dir.join("blobs"), &mut acc);
    acc
}

/// Whether any file under `dir` contains `needle`.
pub fn tree_contains(dir: &std::path::Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir).unwrap().flatten().any(|e| {
        let p = e.path();
        if p.is_dir() {
            tree_contains(&p, needle)
        } else {
            std::fs::read(&p)
                .unwrap()
                .windows(needle.len())
                .any(|w| w == needle)
        }
    })
}
