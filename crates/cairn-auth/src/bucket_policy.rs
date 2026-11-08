//! Bucket policies and PublicAccessBlock settings, stored in the `policies` table under
//! `b/<bucket>` (managed IAM policies use `p/<name>` in the same table).

use crate::engine::BucketAuthz;
use crate::error::AuthError;
use crate::eval::PublicAccessBlock;
use crate::policy::{PolicyDocument, PolicyKind};
use crate::types::Ts;
use cairn_meta::{MetaError, MetaStore, Reader, RedbMetaStore, Table};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Mutex;

/// Per-bucket authorisation inputs, as the S3 access bridge needs them.
#[async_trait::async_trait]
pub trait BucketAuthzSource: Send + Sync {
    /// Bucket policy and PublicAccessBlock of `bucket` (`None` if nothing is configured).
    async fn bucket_authz(&self, bucket: &str) -> Result<Option<BucketAuthz>, AuthError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct BucketAuthzRecord {
    policy: Option<String>,
    public_access_block: Option<PublicAccessBlock>,
    updated_at: Option<Ts>,
}

impl BucketAuthzRecord {
    fn is_empty(&self) -> bool {
        self.policy.is_none() && self.public_access_block.is_none()
    }
}

/// Persistent store of bucket policies and PublicAccessBlock configurations.
pub struct BucketPolicyStore {
    meta: RedbMetaStore,
    cache: Mutex<HashMap<[u8; 32], PolicyDocument>>,
}

impl std::fmt::Debug for BucketPolicyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BucketPolicyStore")
    }
}

fn key(bucket: &str) -> Vec<u8> {
    let mut k = b"b/".to_vec();
    k.extend_from_slice(bucket.as_bytes());
    k
}

fn me(e: MetaError) -> AuthError {
    AuthError::Backend(e.to_string())
}

impl BucketPolicyStore {
    /// Store over an open metadata database.
    pub fn new(meta: RedbMetaStore) -> Self {
        Self {
            meta,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn record(&self, bucket: &str) -> Result<BucketAuthzRecord, AuthError> {
        let r = self.meta.read().map_err(me)?;
        match r.get(Table::Policies, &key(bucket)).map_err(me)? {
            Some(b) => cairn_meta::records::decode(&b).map_err(me),
            None => Ok(BucketAuthzRecord::default()),
        }
    }

    async fn update(
        &self,
        bucket: &str,
        f: impl Fn(&mut BucketAuthzRecord) + Send + 'static,
    ) -> Result<(), AuthError> {
        let k = key(bucket);
        let now = Ts::now();
        self.meta
            .write(move |txn| -> Result<(), MetaError> {
                let mut rec: BucketAuthzRecord = match txn.get(Table::Policies, &k)? {
                    Some(b) => cairn_meta::records::decode(&b)?,
                    None => BucketAuthzRecord::default(),
                };
                f(&mut rec);
                rec.updated_at = Some(now);
                if rec.is_empty() {
                    txn.del(Table::Policies, &k)?;
                } else {
                    txn.put(Table::Policies, &k, &cairn_meta::records::encode(&rec))?;
                }
                Ok(())
            })
            .await
            .map_err(me)
    }

    fn compiled(&self, text: &str) -> Result<PolicyDocument, AuthError> {
        let h: [u8; 32] = sha2::Sha256::digest(text.as_bytes()).into();
        let mut c = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = c.get(&h) {
            return Ok(d.clone());
        }
        let d: PolicyDocument = text.parse()?;
        if c.len() >= 4096 {
            c.clear();
        }
        c.insert(h, d.clone());
        Ok(d)
    }

    /// The bucket policy (`GetBucketPolicy`), if any.
    pub async fn get_policy(&self, bucket: &str) -> Result<Option<PolicyDocument>, AuthError> {
        self.record(bucket)?
            .policy
            .map(|t| self.compiled(&t))
            .transpose()
    }

    /// Validate and store a bucket policy (`PutBucketPolicy`). Rejects a public policy with
    /// `AccessDenied` when the bucket's `BlockPublicPolicy` is set.
    pub async fn put_policy(&self, bucket: &str, text: &str) -> Result<PolicyDocument, AuthError> {
        let doc = self.compiled(text)?;
        doc.validate_for(PolicyKind::Bucket(bucket))?;
        let pab = self.record(bucket)?.public_access_block.unwrap_or_default();
        if pab.block_public_policy && doc.is_public() {
            return Err(AuthError::AccessDenied(
                "BlockPublicPolicy is enabled and the policy grants public access".into(),
            ));
        }
        let t = text.to_string();
        self.update(bucket, move |r| r.policy = Some(t.clone()))
            .await?;
        Ok(doc)
    }

    /// Remove the bucket policy (`DeleteBucketPolicy`); returns whether one existed.
    pub async fn delete_policy(&self, bucket: &str) -> Result<bool, AuthError> {
        let existed = self.record(bucket)?.policy.is_some();
        self.update(bucket, |r| r.policy = None).await?;
        Ok(existed)
    }

    /// `GetBucketPolicyStatus`: true if the stored policy is public.
    pub async fn policy_is_public(&self, bucket: &str) -> Result<Option<bool>, AuthError> {
        Ok(self.get_policy(bucket).await?.map(|d| d.is_public()))
    }

    /// The PublicAccessBlock configuration (`GetPublicAccessBlock`), if any.
    pub async fn get_public_access_block(
        &self,
        bucket: &str,
    ) -> Result<Option<PublicAccessBlock>, AuthError> {
        Ok(self.record(bucket)?.public_access_block)
    }

    /// Store the PublicAccessBlock configuration (`PutPublicAccessBlock`).
    pub async fn put_public_access_block(
        &self,
        bucket: &str,
        pab: PublicAccessBlock,
    ) -> Result<(), AuthError> {
        self.update(bucket, move |r| r.public_access_block = Some(pab))
            .await
    }

    /// Remove the PublicAccessBlock configuration (`DeletePublicAccessBlock`).
    pub async fn delete_public_access_block(&self, bucket: &str) -> Result<bool, AuthError> {
        let existed = self.record(bucket)?.public_access_block.is_some();
        self.update(bucket, |r| r.public_access_block = None)
            .await?;
        Ok(existed)
    }

    /// Drop everything stored for `bucket` (call on DeleteBucket / purge).
    pub async fn forget_bucket(&self, bucket: &str) -> Result<(), AuthError> {
        self.update(bucket, |r| *r = BucketAuthzRecord::default())
            .await
    }
}

#[async_trait::async_trait]
impl BucketAuthzSource for BucketPolicyStore {
    async fn bucket_authz(&self, bucket: &str) -> Result<Option<BucketAuthz>, AuthError> {
        let rec = self.record(bucket)?;
        if rec.is_empty() {
            return Ok(None);
        }
        Ok(Some(BucketAuthz {
            policy: rec.policy.map(|t| self.compiled(&t)).transpose()?,
            public_access_block: rec.public_access_block.unwrap_or_default(),
        }))
    }
}

/// In-memory [`BucketAuthzSource`] for tests and embedding.
#[derive(Debug, Default)]
pub struct MemoryBucketAuthz {
    map: Mutex<HashMap<String, BucketAuthz>>,
}

impl MemoryBucketAuthz {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the inputs for `bucket`.
    pub fn set(&self, bucket: &str, authz: BucketAuthz) {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(bucket.to_string(), authz);
    }
}

#[async_trait::async_trait]
impl BucketAuthzSource for MemoryBucketAuthz {
    async fn bucket_authz(&self, bucket: &str) -> Result<Option<BucketAuthz>, AuthError> {
        Ok(self
            .map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(bucket)
            .cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC_READ: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::photos/*"}]}"#;

    #[tokio::test]
    async fn put_get_delete_and_block_public_policy() {
        let dir = tempfile::tempdir().unwrap();
        let meta = RedbMetaStore::open(&dir.path().join("m.redb")).unwrap();
        let s = BucketPolicyStore::new(meta.clone());
        assert!(s.get_policy("photos").await.unwrap().is_none());
        assert!(s.bucket_authz("photos").await.unwrap().is_none());
        s.put_policy("photos", PUBLIC_READ).await.unwrap();
        assert_eq!(s.policy_is_public("photos").await.unwrap(), Some(true));
        let other = PUBLIC_READ.replace("photos", "other");
        assert!(s.put_policy("photos", &other).await.is_err());
        assert!(s.put_policy("photos", "{nope").await.is_err());

        let pab = PublicAccessBlock {
            block_public_policy: true,
            ..Default::default()
        };
        s.put_public_access_block("photos", pab).await.unwrap();
        assert!(matches!(
            s.put_policy("photos", PUBLIC_READ).await,
            Err(AuthError::AccessDenied(_))
        ));
        let a = s.bucket_authz("photos").await.unwrap().unwrap();
        assert!(a.policy.is_some() && a.public_access_block.block_public_policy);

        assert!(s.delete_policy("photos").await.unwrap());
        assert!(!s.delete_policy("photos").await.unwrap());
        assert!(s.delete_public_access_block("photos").await.unwrap());
        assert!(
            meta.read()
                .unwrap()
                .get(Table::Policies, b"b/photos")
                .unwrap()
                .is_none()
        );
        meta.shutdown();
    }
}
