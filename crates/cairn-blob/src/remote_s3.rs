//! Minimal S3 client wrapper (aws-sdk-s3 over rustls/ring) shared by the cold blob tier
//! ([`crate::tiered::RemoteBlobStore`]), backups and replication targets in `cairn-engine`.

use crate::{BlobError, BlobReader};
use aws_credential_types::Credentials;
use aws_sdk_s3::Client;
use aws_sdk_s3::config::http::HttpResponse;
use aws_sdk_s3::config::{BehaviorVersion, Region};
use aws_sdk_s3::error::{DisplayErrorContext, SdkError};
use aws_sdk_s3::primitives::ByteStream;
use bytes::Bytes;
use std::fmt;
use std::io;
use std::ops::Range;
use std::path::Path;

pub use aws_sdk_s3;

/// Where and how to reach a remote S3 bucket.
#[derive(Clone, Default)]
pub struct S3Endpoint {
    /// Endpoint URL (`https://s3.example.com`); `None` uses the AWS endpoint for `region`.
    pub endpoint: Option<String>,
    /// Signing region.
    pub region: String,
    /// Bucket name.
    pub bucket: String,
    /// Key prefix inside the bucket (e.g. `cairn-cold/`); may be empty.
    pub prefix: String,
    /// Access key id.
    pub access_key: String,
    /// Secret access key (never logged).
    pub secret_key: String,
    /// Path-style addressing (required by most non-AWS endpoints, including Cairn).
    pub path_style: bool,
}

impl fmt::Debug for S3Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Endpoint")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("access_key", &self.access_key)
            .field("secret_key", &"<redacted>")
            .field("path_style", &self.path_style)
            .finish()
    }
}

/// Build an aws-sdk-s3 client for an endpoint (rustls with the ring provider, no OpenSSL).
pub fn build_client(ep: &S3Endpoint) -> Client {
    let region = if ep.region.is_empty() {
        "us-east-1".to_string()
    } else {
        ep.region.clone()
    };
    let plain_http = ep
        .endpoint
        .as_deref()
        .is_some_and(|u| u.starts_with("http://"));
    let http = if plain_http {
        aws_smithy_http_client::Builder::new().build_http()
    } else {
        aws_smithy_http_client::Builder::new()
            .tls_provider(aws_smithy_http_client::tls::Provider::Rustls(
                aws_smithy_http_client::tls::rustls_provider::CryptoMode::Ring,
            ))
            .build_https()
    };
    let mut b = aws_sdk_s3::Config::builder()
        .behavior_version(BehaviorVersion::latest())
        .region(Region::new(region))
        .force_path_style(ep.path_style)
        .credentials_provider(Credentials::new(
            &ep.access_key,
            &ep.secret_key,
            None,
            None,
            "cairn",
        ))
        .http_client(http);
    if let Some(url) = &ep.endpoint {
        b = b.endpoint_url(url);
    }
    Client::from_conf(b.build())
}

/// Map an SDK error to a [`BlobError`] (404 becomes `io::ErrorKind::NotFound`).
pub fn sdk_err<E>(e: SdkError<E, HttpResponse>) -> BlobError
where
    E: std::error::Error + Send + Sync + 'static,
{
    let not_found = e.raw_response().is_some_and(|r| r.status().as_u16() == 404);
    let msg = format!("s3: {}", DisplayErrorContext(&e));
    if not_found {
        BlobError::Io(io::Error::new(io::ErrorKind::NotFound, msg))
    } else {
        BlobError::Io(io::Error::other(msg))
    }
}

/// Whether a [`BlobError`] means "object not found".
pub fn is_not_found(e: &BlobError) -> bool {
    match e {
        BlobError::NotFound(_) => true,
        BlobError::Io(io) => io.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}

/// A bucket + prefix on a remote S3 endpoint with whole-file and ranged helpers.
#[derive(Clone)]
pub struct RemoteS3 {
    client: Client,
    bucket: String,
    prefix: String,
}

impl fmt::Debug for RemoteS3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteS3")
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .finish()
    }
}

impl RemoteS3 {
    /// Connect to `ep` (no network I/O happens until the first request).
    pub fn new(ep: &S3Endpoint) -> RemoteS3 {
        RemoteS3::with_client(build_client(ep), &ep.bucket, &ep.prefix)
    }

    /// Wrap an existing client.
    pub fn with_client(client: Client, bucket: &str, prefix: &str) -> RemoteS3 {
        RemoteS3 {
            client,
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
        }
    }

    /// The underlying SDK client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Bucket name.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Full object key for a relative name.
    pub fn key(&self, name: &str) -> String {
        format!("{}{}", self.prefix, name)
    }

    /// Upload a local file as `name`.
    pub async fn put_path(&self, name: &str, path: &Path) -> Result<(), BlobError> {
        let body = ByteStream::from_path(path)
            .await
            .map_err(|e| BlobError::Io(io::Error::other(e)))?;
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key(name))
            .body(body)
            .send()
            .await
            .map_err(sdk_err)?;
        Ok(())
    }

    /// Upload bytes as `name`.
    pub async fn put_bytes(&self, name: &str, data: Bytes) -> Result<(), BlobError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key(name))
            .body(ByteStream::from(data))
            .send()
            .await
            .map_err(sdk_err)?;
        Ok(())
    }

    /// Download `name` fully into memory (`None` if absent). For small documents only.
    pub async fn get_bytes(&self, name: &str) -> Result<Option<Bytes>, BlobError> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(name))
            .send()
            .await
        {
            Ok(r) => Ok(Some(
                r.body
                    .collect()
                    .await
                    .map_err(|e| BlobError::Io(io::Error::other(e)))?
                    .into_bytes(),
            )),
            Err(e) => {
                let e = sdk_err(e);
                if is_not_found(&e) { Ok(None) } else { Err(e) }
            }
        }
    }

    /// Download `name` into a local file (created or truncated).
    pub async fn get_to_path(&self, name: &str, path: &Path) -> Result<(), BlobError> {
        use tokio::io::AsyncWriteExt;
        let r = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(name))
            .send()
            .await
            .map_err(sdk_err)?;
        let mut body = r.body;
        let mut f = tokio::fs::File::create(path).await?;
        while let Some(chunk) = body
            .try_next()
            .await
            .map_err(|e| BlobError::Io(io::Error::other(e)))?
        {
            f.write_all(&chunk).await?;
        }
        f.flush().await?;
        f.sync_all().await?;
        Ok(())
    }

    /// Stream a byte range of `name`.
    pub async fn get_range(&self, name: &str, range: Range<u64>) -> Result<BlobReader, BlobError> {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        if range.start == range.end {
            return Ok(BlobReader { rx });
        }
        let r = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(name))
            .range(format!("bytes={}-{}", range.start, range.end - 1))
            .send()
            .await
            .map_err(sdk_err)?;
        let mut body = r.body;
        tokio::spawn(async move {
            loop {
                match body.try_next().await {
                    Ok(Some(b)) => {
                        if tx.send(Ok(b)).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => return,
                    Err(e) => {
                        let _ = tx.send(Err(io::Error::other(e))).await;
                        return;
                    }
                }
            }
        });
        Ok(BlobReader { rx })
    }

    /// Object size (`None` if absent).
    pub async fn head_size(&self, name: &str) -> Result<Option<u64>, BlobError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.key(name))
            .send()
            .await
        {
            Ok(r) => Ok(Some(r.content_length.unwrap_or(0).max(0) as u64)),
            Err(e) => {
                let e = sdk_err(e);
                if is_not_found(&e) { Ok(None) } else { Err(e) }
            }
        }
    }

    /// Delete `name` (idempotent).
    pub async fn delete(&self, name: &str) -> Result<(), BlobError> {
        match self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.key(name))
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => {
                let e = sdk_err(e);
                if is_not_found(&e) { Ok(()) } else { Err(e) }
            }
        }
    }

    /// Relative names under `sub` (prefix-relative), in key order.
    pub async fn list(&self, sub: &str) -> Result<Vec<String>, BlobError> {
        let mut out = Vec::new();
        let full = self.key(sub);
        let mut token: Option<String> = None;
        loop {
            let r = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&full)
                .set_continuation_token(token.take())
                .send()
                .await
                .map_err(sdk_err)?;
            for o in r.contents() {
                if let Some(k) = o.key()
                    && let Some(rel) = k.strip_prefix(&self.prefix)
                {
                    out.push(rel.to_string());
                }
            }
            match r.next_continuation_token() {
                Some(t) if r.is_truncated() == Some(true) => token = Some(t.to_string()),
                _ => return Ok(out),
            }
        }
    }
}
