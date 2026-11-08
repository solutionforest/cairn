#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Cairn `auth` crate: IAM policy language and evaluator, credential store, STS sessions and
//! SigV4 presigning and verification, the s3s auth/access bridge and the STS endpoint.
//! See DESIGN §8.

pub mod actions;
pub mod arn;
pub mod bucket_policy;
pub mod engine;
pub mod error;
pub mod eval;
pub mod meta_backend;
mod pattern;
pub mod policy;
pub mod principal;
pub mod s3s_bridge;
pub mod secret;
pub mod sigv4;
pub mod store;
pub mod sts;
pub mod types;

pub use bucket_policy::{BucketAuthzSource, BucketPolicyStore, MemoryBucketAuthz};
pub use engine::{AuthzEngine, BucketAuthz};
pub use error::{AuthError, PolicyError, PresignError};
pub use eval::{
    AuthzRequest, ConditionContext, Decision, PolicySet, PublicAccessBlock, ResourceVerdict,
};
pub use meta_backend::MetaCredentialBackend;
pub use pattern::VarResolver;
pub use policy::{PolicyDocument, PolicyKind};
pub use principal::{Principal, PrincipalKind};
pub use s3s_bridge::{AuthenticatedCaller, CairnS3Access, CairnS3Auth, RequestMeta};
pub use secret::{MasterKey, SecretString};
pub use sigv4::{MAX_PRESIGN_EXPIRY, presign};
pub use store::{
    AccessKeyInfo, AccessKeyOptions, AssumeRoleRequest, Credential, CredentialBackend,
    CredentialStore, MemoryBackend, NewAccessKey, SessionInfo, SessionSummary, StsCredentials,
};
pub use types::{Clock, ManualClock, PrincipalId, SystemClock, Ts};

#[cfg(test)]
mod eval_tests;
