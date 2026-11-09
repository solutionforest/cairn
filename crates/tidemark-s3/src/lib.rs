#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Tidemark S3 protocol layer: implements [`s3s::S3`] for [`TidemarkEngine`] as a thin mapping from
//! `s3s` DTOs to engine calls (DESIGN §5–§6). Unimplemented operations return `NotImplemented`.

mod acl;
mod auth;
mod config_ops;
mod convert;
mod observe;
mod ops;

pub use auth::RootAuth;
pub use convert::RequestId;

/// Header parsers exposed to `fuzz/` only.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzzing {
    pub use crate::convert::{as_of, copy_range, parse_tagging};
}
pub use observe::{ObservedAccess, OpInfo, OpSlot};

use s3s::auth::S3Auth;
use s3s::service::{S3Service, S3ServiceBuilder};
use std::sync::Arc;
use tidemark_core::PrincipalId;
use tidemark_engine::TidemarkEngine;

/// The `s3s::S3` implementation.
#[derive(Clone)]
pub struct TidemarkS3 {
    engine: TidemarkEngine,
    region: String,
    root_access_key: Option<String>,
    policies: Option<Arc<tidemark_auth::BucketPolicyStore>>,
    access: Option<tidemark_auth::TidemarkS3Access>,
    sink_arns: Arc<Vec<String>>,
}

impl TidemarkS3 {
    /// Wrap an engine; `region` is reported by GetBucketLocation and HeadBucket.
    pub fn new(engine: TidemarkEngine, region: impl Into<String>) -> TidemarkS3 {
        TidemarkS3 {
            engine,
            region: region.into(),
            root_access_key: None,
            policies: None,
            access: None,
            sink_arns: Arc::new(Vec::new()),
        }
    }

    /// The engine.
    pub fn engine(&self) -> &TidemarkEngine {
        &self.engine
    }

    /// Principal for a request: a `PrincipalId` placed in the request extensions by an
    /// `S3Access` implementation wins; otherwise the root key maps to `root`, any other signed key
    /// to `user:<access key>`, and unsigned requests to `anonymous`.
    pub(crate) fn principal<T>(&self, req: &s3s::S3Request<T>) -> PrincipalId {
        if let Some(p) = req.extensions.get::<PrincipalId>() {
            return p.clone();
        }
        if let Some(c) = req.extensions.get::<tidemark_auth::AuthenticatedCaller>() {
            return match &c.principal {
                Some(p) => PrincipalId(p.id.as_str().to_string()),
                None => PrincipalId::anonymous(),
            };
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

/// Builds the `s3s` service around [`TidemarkS3`]: authentication, access control, virtual hosts.
pub struct TidemarkS3Builder {
    s3: TidemarkS3,
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

impl TidemarkS3Builder {
    /// Start from an engine.
    pub fn new(engine: TidemarkEngine, region: impl Into<String>) -> TidemarkS3Builder {
        let max_object_size = engine.config().limits.max_object_size;
        TidemarkS3Builder {
            s3: TidemarkS3::new(engine, region),
            auth: None,
            access: None,
            domain: None,
            max_object_size,
        }
    }

    /// Root-only authentication (phase 1).
    pub fn with_root_credentials(mut self, access_key: &str, secret: &str) -> TidemarkS3Builder {
        self.s3.root_access_key = Some(access_key.to_string());
        self.auth = Some(Arc::new(RootAuth::new(access_key, secret)));
        self
    }

    /// Replace secret lookup (e.g. `tidemark_auth::s3s_bridge::TidemarkS3Auth`). The root access key
    /// set by [`Self::with_root_credentials`] still maps to the `root` principal.
    pub fn with_auth(mut self, auth: Arc<dyn S3Auth>) -> TidemarkS3Builder {
        self.auth = Some(auth);
        self
    }

    /// Install an `S3Access` policy check (e.g. `tidemark_auth::s3s_bridge::TidemarkS3Access`). It may
    /// insert a `tidemark_core::PrincipalId` into the request extensions to name the caller.
    pub fn with_access<A: s3s::access::S3Access>(mut self, access: A) -> TidemarkS3Builder {
        self.access = Some(Box::new(move |b| b.set_access(access)));
        self
    }

    /// Bucket policy / PublicAccessBlock store behind the policy S3 operations.
    pub fn with_policies(mut self, p: Arc<tidemark_auth::BucketPolicyStore>) -> TidemarkS3Builder {
        self.s3.policies = Some(p);
        self
    }

    /// Access checker used for in-handler checks (`tidemark:ReplicateObject`).
    pub fn with_access_checker(mut self, a: tidemark_auth::TidemarkS3Access) -> TidemarkS3Builder {
        self.s3.access = Some(a);
        self
    }

    /// Destination ARNs notification configurations may name (configured sinks).
    pub fn with_sink_arns(mut self, arns: Vec<String>) -> TidemarkS3Builder {
        self.s3.sink_arns = Arc::new(arns);
        self
    }

    /// Base domain for virtual-host-style requests (`bucket.<domain>`).
    pub fn with_domain(mut self, domain: Option<String>) -> TidemarkS3Builder {
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
