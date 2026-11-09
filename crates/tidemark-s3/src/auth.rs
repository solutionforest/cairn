//! Root-only SigV4 secret lookup. Agent B's `tidemark_auth::s3s_bridge` replaces this in phase 2b
//! via [`crate::TidemarkS3Builder::with_auth`].

use s3s::auth::{S3Auth, SecretKey};
use s3s::{S3Result, s3_error};
use std::sync::Arc;
use subtle::ConstantTimeEq;

/// Accepts exactly one access key (the root credential from config / env).
pub struct RootAuth {
    access_key: String,
    secret: SecretKey,
}

impl RootAuth {
    /// Root credential pair.
    pub fn new(access_key: impl Into<String>, secret: impl Into<String>) -> RootAuth {
        RootAuth {
            access_key: access_key.into(),
            secret: SecretKey::from(secret.into()),
        }
    }

    /// The root access key id.
    pub fn access_key(&self) -> &str {
        &self.access_key
    }
}

impl std::fmt::Debug for RootAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RootAuth")
            .field("access_key", &self.access_key)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

#[async_trait::async_trait]
impl S3Auth for RootAuth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        if bool::from(access_key.as_bytes().ct_eq(self.access_key.as_bytes())) {
            Ok(self.secret.clone())
        } else {
            Err(s3_error!(
                InvalidAccessKeyId,
                "The AWS access key Id you provided does not exist in our records."
            ))
        }
    }
}

/// Adapter so a shared `Arc<dyn S3Auth>` can be installed on the s3s builder.
pub(crate) struct SharedAuth(pub Arc<dyn S3Auth>);

#[async_trait::async_trait]
impl S3Auth for SharedAuth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        self.0.get_secret_key(access_key).await
    }
}
