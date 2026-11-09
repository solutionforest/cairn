//! Plain description of a remote S3 location. Always built; the client that talks to it
//! (`remote_s3`) is behind the `remote` feature.

use crate::BlobError;
use std::fmt;
use std::io;

/// Where and how to reach a remote S3 bucket.
#[derive(Clone, Default)]
pub struct S3Endpoint {
    /// Endpoint URL (`https://s3.example.com`); `None` uses the AWS endpoint for `region`.
    pub endpoint: Option<String>,
    /// Signing region.
    pub region: String,
    /// Bucket name.
    pub bucket: String,
    /// Key prefix inside the bucket (e.g. `tidemark-cold/`); may be empty.
    pub prefix: String,
    /// Access key id.
    pub access_key: String,
    /// Secret access key (never logged).
    pub secret_key: String,
    /// Path-style addressing (required by most non-AWS endpoints, including Tidemark).
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

/// Whether a [`BlobError`] means "object not found".
pub fn is_not_found(e: &BlobError) -> bool {
    match e {
        BlobError::NotFound(_) => true,
        BlobError::Io(io) => io.kind() == io::ErrorKind::NotFound,
        _ => false,
    }
}
