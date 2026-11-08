#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Cairn S3 protocol layer: implements [`s3s::S3`] for [`CairnEngine`] as a thin mapping from
//! `s3s` DTOs to engine calls (DESIGN §5–§6). Unimplemented operations return `NotImplemented`.

mod auth;
mod convert;
mod ops;

pub use auth::RootAuth;
pub use convert::RequestId;

use cairn_core::PrincipalId;
use cairn_engine::CairnEngine;
use s3s::auth::S3Auth;
use s3s::service::{S3Service, S3ServiceBuilder};
use std::sync::Arc;

/// The `s3s::S3` implementation.
#[derive(Clone)]
pub struct CairnS3 {
    engine: CairnEngine,
    region: String,
    root_access_key: Option<String>,
}

impl CairnS3 {
    /// Wrap an engine; `region` is reported by GetBucketLocation and HeadBucket.
    pub fn new(engine: CairnEngine, region: impl Into<String>) -> CairnS3 {
        CairnS3 {
            engine,
            region: region.into(),
            root_access_key: None,
        }
    }

    /// The engine.
    pub fn engine(&self) -> &CairnEngine {
        &self.engine
    }

    /// Principal for a request: a `PrincipalId` placed in the request extensions by an
    /// `S3Access` implementation wins; otherwise the root key maps to `root`, any other signed key
    /// to `user:<access key>`, and unsigned requests to `anonymous`.
    pub(crate) fn principal<T>(&self, req: &s3s::S3Request<T>) -> PrincipalId {
        if let Some(p) = req.extensions.get::<PrincipalId>() {
            return p.clone();
        }
        match &req.credentials {
            Some(c) if self.root_access_key.as_deref() == Some(c.access_key.as_str()) => {
                PrincipalId::root()
            }
            Some(c) => PrincipalId::user(&c.access_key),
            None => PrincipalId::anonymous(),
        }
    }
}

type Customize = Box<dyn FnOnce(&mut S3ServiceBuilder) + Send>;

/// Builds the `s3s` service around [`CairnS3`]: authentication, access control, virtual hosts.
pub struct CairnS3Builder {
    s3: CairnS3,
    auth: Option<Arc<dyn S3Auth>>,
    access: Option<Customize>,
    domain: Option<String>,
    max_object_size: u64,
}

/// Errors building the service.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// The virtual-host base domain is invalid.
    #[error("invalid server.domain: {0}")]
    Domain(String),
    /// No authentication configured and anonymous access not allowed.
    #[error("no root credentials configured (set auth.root_access_key / auth.root_secret_key)")]
    NoAuth,
}

impl CairnS3Builder {
    /// Start from an engine.
    pub fn new(engine: CairnEngine, region: impl Into<String>) -> CairnS3Builder {
        let max_object_size = engine.config().limits.max_object_size;
        CairnS3Builder {
            s3: CairnS3::new(engine, region),
            auth: None,
            access: None,
            domain: None,
            max_object_size,
        }
    }

    /// Root-only authentication (phase 1).
    pub fn with_root_credentials(mut self, access_key: &str, secret: &str) -> CairnS3Builder {
        self.s3.root_access_key = Some(access_key.to_string());
        self.auth = Some(Arc::new(RootAuth::new(access_key, secret)));
        self
    }

    /// Replace secret lookup (e.g. `cairn_auth::s3s_bridge::CairnS3Auth`). The root access key
    /// set by [`Self::with_root_credentials`] still maps to the `root` principal.
    pub fn with_auth(mut self, auth: Arc<dyn S3Auth>) -> CairnS3Builder {
        self.auth = Some(auth);
        self
    }

    /// Install an `S3Access` policy check (e.g. `cairn_auth::s3s_bridge::CairnS3Access`). It may
    /// insert a `cairn_core::PrincipalId` into the request extensions to name the caller.
    pub fn with_access<A: s3s::access::S3Access>(mut self, access: A) -> CairnS3Builder {
        self.access = Some(Box::new(move |b| b.set_access(access)));
        self
    }

    /// Base domain for virtual-host-style requests (`bucket.<domain>`).
    pub fn with_domain(mut self, domain: Option<String>) -> CairnS3Builder {
        self.domain = domain;
        self
    }

    /// Build the hyper/tower service.
    pub fn build(self) -> Result<S3Service, BuildError> {
        let auth = self.auth.ok_or(BuildError::NoAuth)?;
        let mut b = S3ServiceBuilder::new(self.s3);
        b.set_auth(auth::SharedAuth(auth));
        if let Some(f) = self.access {
            f(&mut b);
        }
        if let Some(d) = &self.domain {
            let host =
                s3s::host::SingleDomain::new(d).map_err(|e| BuildError::Domain(e.to_string()))?;
            b.set_host(host);
        }
        let mut cfg = s3s::config::S3Config::default();
        cfg.put_object_max_size = Some(self.max_object_size);
        b.set_config(Arc::new(s3s::config::StaticConfigProvider::new(Arc::new(
            cfg,
        ))));
        Ok(b.build())
    }
}
