#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! Cairn `auth` crate: IAM policy language and evaluator, credential store, STS sessions and
//! SigV4 presigning. See `docs/AUTH.md` and DESIGN §8.

pub mod actions;
pub mod arn;
pub mod engine;
pub mod error;
pub mod eval;
mod pattern;
pub mod policy;
pub mod principal;
pub mod secret;
pub mod sigv4;
pub mod store;
pub mod types;

pub use engine::{AuthzEngine, BucketAuthz};
pub use error::{AuthError, PolicyError, PresignError};
pub use eval::{
    AuthzRequest, ConditionContext, Decision, PolicySet, PublicAccessBlock, ResourceVerdict,
};
pub use pattern::VarResolver;
pub use policy::{PolicyDocument, PolicyKind};
pub use principal::{Principal, PrincipalKind};
pub use secret::{MasterKey, SecretString};
pub use sigv4::{MAX_PRESIGN_EXPIRY, presign};
pub use store::{
    AccessKeyInfo, AccessKeyOptions, AssumeRoleRequest, Credential, CredentialBackend,
    CredentialStore, MemoryBackend, NewAccessKey, SessionInfo, StsCredentials,
};
pub use types::{Clock, ManualClock, PrincipalId, SystemClock, Ts};

#[cfg(test)]
mod eval_tests;
