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
