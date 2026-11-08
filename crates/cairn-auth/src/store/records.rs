//! Persisted record types (postcard, leading schema-version byte).

use crate::error::AuthError;
use crate::secret::Sealed;
use crate::types::{PrincipalId, Ts};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, BTreeSet};

/// Current schema version of every record in this module.
pub const SCHEMA_V1: u8 = 1;

pub(crate) fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, AuthError> {
    let mut out = vec![SCHEMA_V1];
    out.extend(postcard::to_allocvec(v).map_err(|e| AuthError::Corrupt(e.to_string()))?);
    Ok(out)
}

pub(crate) fn decode<T: DeserializeOwned>(b: &[u8]) -> Result<T, AuthError> {
    match b.split_first() {
        Some((&SCHEMA_V1, rest)) => {
            postcard::from_bytes(rest).map_err(|e| AuthError::Corrupt(e.to_string()))
        }
        Some((v, _)) => Err(AuthError::Corrupt(format!("unknown schema version {v}"))),
        None => Err(AuthError::Corrupt("empty record".into())),
    }
}

/// IAM user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    pub name: String,
    pub user_id: String,
    pub created_at: Ts,
    pub groups: BTreeSet<String>,
    pub attached: BTreeSet<String>,
    pub inline: BTreeMap<String, String>,
    pub disabled: bool,
}

/// IAM group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupRecord {
    pub name: String,
    pub created_at: Ts,
    pub attached: BTreeSet<String>,
    pub inline: BTreeMap<String, String>,
}

/// IAM role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleRecord {
    pub name: String,
    pub role_id: String,
    pub created_at: Ts,
    pub trust_policy: String,
    pub attached: BTreeSet<String>,
    pub inline: BTreeMap<String, String>,
    pub max_session_secs: u64,
}

/// Managed policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub name: String,
    pub document: String,
    pub created_at: Ts,
    pub updated_at: Ts,
    pub version: u64,
}

/// Owner of a long-lived access key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyOwner {
    Root,
    User(String),
}

/// Long-lived access key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessKeyRecord {
    pub access_key_id: String,
    pub owner: KeyOwner,
    pub secret: Sealed,
    pub active: bool,
    pub created_at: Ts,
    pub expires_at: Option<Ts>,
    pub allowed_source_cidrs: Vec<String>,
}

/// What an STS session stands for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionKind {
    Role {
        role: String,
        session_name: String,
        source: PrincipalId,
    },
    User(String),
    Root,
    /// `AssumeRoleWithWebIdentity` (phase 3c). Appended variant: existing encodings are
    /// unchanged, so no migration is needed (older binaries cannot read these records).
    WebIdentity {
        role: String,
        session_name: String,
        /// OIDC provider id (issuer without scheme).
        provider: String,
        /// Token `sub`.
        subject: String,
        /// Session tags mapped from claims.
        tags: BTreeMap<String, String>,
    },
}

/// STS temporary credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub access_key_id: String,
    pub secret: Sealed,
    pub token: Sealed,
    pub kind: SessionKind,
    pub created_at: Ts,
    pub expires_at: Ts,
    pub session_policy: Option<String>,
    pub allowed_source_cidrs: Vec<String>,
}
